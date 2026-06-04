"""Background task: gap detection after a device is assigned to a group.

Moved from in-process (blocking assign_device endpoint) to a Huey task so
the device assignment completes immediately and gap detection runs async.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.tasks import huey

log = logging.getLogger(__name__)


def _run(coro: Any) -> Any:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            pending = asyncio.all_tasks(loop)
            for t in pending:
                t.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        loop.close()
        asyncio.set_event_loop(None)


@huey.task(retries=1, retry_delay=15, context=True)
def run_gap_detection(group_id: int, vendor: str, task: Any = None) -> dict:
    """Detect translation gaps for a vendor within a group and create proposals."""
    log.info(
        "gap_detection started task=%s group=%d vendor=%s",
        task.id if task else "?",
        group_id,
        vendor,
    )
    result = _run(_async_detect(group_id, vendor))
    log.info(
        "gap_detection done task=%s proposals_created=%d",
        task.id if task else "?",
        result.get("proposals_created", 0),
    )
    return result


async def _async_detect(group_id: int, vendor: str) -> dict:
    from src.api.routes.translations import detect_gaps
    result = await detect_gaps(
        group_id=group_id,
        target_vendor=vendor,
        triggered_by="device_onboard",
    )
    return {
        "group_id": group_id,
        "vendor": vendor,
        "proposals_created": result.proposals_created,
        "missing_object_translations": len(result.missing_object_translations),
        "missing_rule_translations": len(result.missing_rule_translations),
    }
