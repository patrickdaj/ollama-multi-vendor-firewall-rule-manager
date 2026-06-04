"""Background task: AI-assisted policy import preview.

Runs the full normalization pipeline (fast-path + LLM) for a device's latest
snapshot and stores the candidate list as the Huey task result.  The API
layer enqueues this task and returns the task_id immediately; the frontend
polls /api/v1/tasks/{task_id} until status == "complete".
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.tasks import huey

log = logging.getLogger(__name__)


def _run(coro: Any) -> Any:
    """Run a coroutine in a fresh event loop with proper pending-task cleanup."""
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


@huey.task(retries=1, retry_delay=10, context=True)
def run_import_preview(
    group_id: int,
    device_name: str,
    limit: int = 50,
    task: Any = None,
) -> dict:
    """Normalize up to `limit` policy objects from the device's latest snapshot.

    Returns the full ImportPreviewOut payload as a dict so the task status
    endpoint can pass it straight through to the frontend.
    """
    log.info(
        "import_preview started task=%s group=%d device=%s limit=%d",
        task.id if task else "?",
        group_id,
        device_name,
        limit,
    )
    result = _run(_async_preview(group_id, device_name, limit))
    log.info(
        "import_preview done task=%s total=%d ai_failed=%d",
        task.id if task else "?",
        result.get("total", 0),
        result.get("ai_failed", 0),
    )
    return result


async def _async_preview(group_id: int, device_name: str, limit: int) -> dict:
    from sqlalchemy import select

    from src.ai.import_policy import normalize_object, normalize_rule
    from src.api.routes.groups import IMPORTABLE_OBJECT_TYPES, RULE_TYPES
    from src.db.models import Device, PolicyObject, Snapshot
    from src.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        device = (await session.execute(
            select(Device).where(Device.name == device_name)
        )).scalar_one_or_none()
        if not device:
            raise ValueError(f"Device {device_name!r} not found")

        snap = (await session.execute(
            select(Snapshot)
            .where(Snapshot.device_id == device.id, Snapshot.status == "complete")
            .order_by(Snapshot.created_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        if not snap:
            raise ValueError(f"No completed snapshot for {device_name!r}")

        rows = (await session.execute(
            select(PolicyObject)
            .where(
                PolicyObject.snapshot_id == snap.id,
                PolicyObject.object_type.in_(IMPORTABLE_OBJECT_TYPES),
            )
            .order_by(PolicyObject.object_type, PolicyObject.object_name)
            .limit(limit)
        )).scalars().all()

        objects = [
            {"object_type": o.object_type, "object_name": o.object_name, "data": dict(o.data or {})}
            for o in rows
        ]
        vendor = device.vendor
        snapshot_id = snap.id

    candidates = []
    for obj in objects:
        try:
            if obj["object_type"] in RULE_TYPES:
                result = await normalize_rule(
                    vendor=vendor,
                    rule_type=obj["object_type"],
                    rule_name=obj["object_name"],
                    vendor_data=obj["data"],
                )
                proposed_base = result.get("base_rule", {})
            else:
                result = await normalize_object(
                    vendor=vendor,
                    object_type=obj["object_type"],
                    object_name=obj["object_name"],
                    vendor_data=obj["data"],
                )
                proposed_base = result.get("base_data", {})
            reasoning = result.get("reasoning", "")
        except Exception as exc:
            log.warning("Normalization failed %s/%s: %s", obj["object_type"], obj["object_name"], exc)
            proposed_base = {}
            reasoning = f"AI normalization failed: {exc}"

        candidates.append({
            "object_type": obj["object_type"],
            "object_name": obj["object_name"],
            "vendor_data": obj["data"],
            "proposed_base": proposed_base,
            "reasoning": reasoning,
            "selected": bool(proposed_base),
        })

    ai_processed = sum(1 for c in candidates if "failed" not in c["reasoning"].lower())
    ai_failed = len(candidates) - ai_processed

    return {
        "device_name": device_name,
        "vendor": vendor,
        "snapshot_id": snapshot_id,
        "candidates": candidates,
        "total": len(candidates),
        "ai_processed": ai_processed,
        "ai_failed": ai_failed,
    }
