"""Huey background task for executing push jobs."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from src.tasks import huey

log = logging.getLogger(__name__)


def _run(coro):
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


@huey.task(retries=0, context=True)
def run_push_job(job_id: int, task=None):
    """Execute a push job: iterate items and call vendor connectors."""
    return _run(_async_push(job_id))


async def _async_push(job_id: int) -> dict:
    from sqlalchemy import select
    from src.db.models import Device, PushJob, PushJobItem
    from src.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        job = await session.get(PushJob, job_id)
        if not job:
            log.error("Push job %d not found", job_id)
            return {"error": f"Job {job_id} not found"}

        device = await session.get(Device, job.device_id)
        if not device:
            job.status = "failed"
            job.error_summary = f"Device #{job.device_id} not found"
            job.completed_at = datetime.now(timezone.utc)
            await session.commit()
            return {"error": "Device not found"}

        items = (await session.execute(
            select(PushJobItem)
            .where(PushJobItem.job_id == job_id, PushJobItem.status == "pending")
            .order_by(PushJobItem.sequence)
        )).scalars().all()

        # Try to get a vendor connector
        try:
            from src.firewall.connectors import get_connector
            connector = await get_connector(device)
        except Exception as exc:
            log.warning("No connector available for vendor %s: %s", device.vendor, exc)
            connector = None

        pushed_rules = 0
        pushed_objects = 0
        any_failed = False

        for item in items:
            if connector is None:
                # No connector implemented — mark as skipped with note
                item.status = "skipped"
                item.error = f"No push connector for vendor {device.vendor!r} yet"
                continue

            try:
                ok = await connector.push_item(
                    item_type=item.item_type,
                    object_type=item.object_type,
                    name=item.item_name,
                    action=item.action,
                    payload=item.vendor_payload,
                )
                item.status = "success" if ok else "failed"
                if ok:
                    if item.item_type == "rule":
                        pushed_rules += 1
                    else:
                        pushed_objects += 1
                else:
                    any_failed = True
            except Exception as exc:
                item.status = "failed"
                item.error = str(exc)
                any_failed = True
                log.error("Push item %s/%s failed: %s", item.object_type, item.item_name, exc)

        job.pushed_rules = pushed_rules
        job.pushed_objects = pushed_objects
        job.completed_at = datetime.now(timezone.utc)

        if connector is None:
            job.status = "pending"
            job.error_summary = f"Push connector for {device.vendor!r} not yet implemented — items compiled but not sent."
        elif any_failed:
            job.status = "partial"
        else:
            job.status = "complete"

        await session.commit()

    return {
        "job_id": job_id,
        "status": job.status,
        "pushed_rules": pushed_rules,
        "pushed_objects": pushed_objects,
    }
