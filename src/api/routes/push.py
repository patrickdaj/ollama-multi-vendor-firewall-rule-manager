"""Push engine API — compile, preview, and execute policy pushes to devices."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select

from src.db.models import Device, DeviceGroup, PushJob, PushJobItem
from src.db.session import AsyncSessionLocal
from src.push.compiler import compile_push

router = APIRouter(prefix="/push", tags=["push"])
log = logging.getLogger(__name__)


# ── Schemas ───────────────────────────────────────────────────────────────────


class PushItemOut(BaseModel):
    id: int
    item_type: str
    object_type: str
    item_name: str
    action: str
    vendor_payload: dict[str, Any]
    status: str
    error: str | None
    sequence: int


class PushJobOut(BaseModel):
    id: int
    device_name: str
    vendor: str
    group_id: int
    triggered_by: str
    status: str
    dry_run: bool
    started_at: datetime | None
    completed_at: datetime | None
    pushed_rules: int
    pushed_objects: int
    error_summary: str | None
    created_at: datetime
    # Summary counts (not full item list — use separate endpoint)
    creates: int = 0
    updates: int = 0
    no_changes: int = 0
    failed: int = 0


class CreatePushJobRequest(BaseModel):
    device_name: str
    group_id: int | None = None  # defaults to device's assigned group
    dry_run: bool = True
    triggered_by: str = "manual"


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _job_out(session: Any, job: PushJob) -> PushJobOut:
    device = await session.get(Device, job.device_id)
    items = (await session.execute(
        select(PushJobItem).where(PushJobItem.job_id == job.id)
    )).scalars().all()

    creates = sum(1 for i in items if i.action == "create")
    updates = sum(1 for i in items if i.action == "update")
    no_changes = sum(1 for i in items if i.action == "no-change")
    failed = sum(1 for i in items if i.status == "failed")

    return PushJobOut(
        id=job.id,
        device_name=device.name if device else f"#{job.device_id}",
        vendor=device.vendor if device else "unknown",
        group_id=job.group_id,
        triggered_by=job.triggered_by,
        status=job.status,
        dry_run=job.dry_run,
        started_at=job.started_at,
        completed_at=job.completed_at,
        pushed_rules=job.pushed_rules,
        pushed_objects=job.pushed_objects,
        error_summary=job.error_summary,
        created_at=job.created_at,
        creates=creates,
        updates=updates,
        no_changes=no_changes,
        failed=failed,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/jobs", response_model=list[PushJobOut])
async def list_push_jobs(
    device_name: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
) -> list[PushJobOut]:
    async with AsyncSessionLocal() as session:
        q = select(PushJob).order_by(PushJob.created_at.desc()).limit(limit)
        if device_name:
            dev = (await session.execute(
                select(Device).where(Device.name == device_name)
            )).scalar_one_or_none()
            if dev:
                q = q.where(PushJob.device_id == dev.id)
        jobs = (await session.execute(q)).scalars().all()
        return [await _job_out(session, j) for j in jobs]


@router.get("/jobs/{job_id}", response_model=PushJobOut)
async def get_push_job(job_id: int) -> PushJobOut:
    async with AsyncSessionLocal() as session:
        job = await session.get(PushJob, job_id)
        if not job:
            raise HTTPException(404, f"Push job {job_id} not found")
        return await _job_out(session, job)


@router.get("/jobs/{job_id}/items", response_model=list[PushItemOut])
async def list_push_job_items(
    job_id: int,
    action: str | None = Query(None, description="create|update|no-change|delete"),
) -> list[PushItemOut]:
    async with AsyncSessionLocal() as session:
        job = await session.get(PushJob, job_id)
        if not job:
            raise HTTPException(404, f"Push job {job_id} not found")
        q = select(PushJobItem).where(PushJobItem.job_id == job_id).order_by(PushJobItem.sequence)
        if action:
            q = q.where(PushJobItem.action == action)
        items = (await session.execute(q)).scalars().all()
    return [
        PushItemOut(
            id=i.id, item_type=i.item_type, object_type=i.object_type,
            item_name=i.item_name, action=i.action, vendor_payload=i.vendor_payload,
            status=i.status, error=i.error, sequence=i.sequence,
        )
        for i in items
    ]


@router.post("/jobs", response_model=PushJobOut, status_code=201)
async def create_push_job(body: CreatePushJobRequest) -> PushJobOut:
    """Compile a push job (dry-run by default).

    Compiles the device's effective policy into vendor-specific items, diffs
    against the latest snapshot, and stores the job. No traffic is sent to the
    device unless you call /execute on the job.
    """
    async with AsyncSessionLocal() as session:
        dev_result = await session.execute(
            select(Device).where(Device.name == body.device_name)
        )
        device = dev_result.scalar_one_or_none()
        if not device:
            raise HTTPException(404, f"Device {body.device_name!r} not found")

        group_id = body.group_id or device.device_group_id
        if not group_id:
            raise HTTPException(400, f"Device {body.device_name!r} is not assigned to a group")

        group = await session.get(DeviceGroup, group_id)
        if not group:
            raise HTTPException(404, f"Group {group_id} not found")

        try:
            compile_result = await compile_push(session, group_id, body.device_name)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

        job = PushJob(
            device_id=device.id,
            group_id=group_id,
            triggered_by=body.triggered_by,
            status="pending",
            dry_run=body.dry_run,
            started_at=datetime.now(timezone.utc) if not body.dry_run else None,
        )
        session.add(job)
        await session.flush()  # get job.id

        for item in compile_result.items:
            session.add(PushJobItem(
                job_id=job.id,
                item_type=item.item_type,
                object_type=item.object_type,
                item_name=item.item_name,
                action=item.action,
                vendor_payload=item.vendor_payload,
                status="pending" if item.action != "no-change" else "skipped",
                sequence=item.sequence,
            ))

        if body.dry_run:
            job.status = "pending"
        await session.commit()
        await session.refresh(job)
        return await _job_out(session, job)


@router.post("/jobs/{job_id}/execute", response_model=PushJobOut)
async def execute_push_job(job_id: int) -> PushJobOut:
    """Promote a dry-run job to a live push.

    Currently stores the intent to push and marks status = 'running'.
    Actual device communication is vendor-connector dependent and will be
    implemented per vendor (PAN-OS first).  For now this marks the job as
    running and returns it — the Huey worker picks it up.
    """
    async with AsyncSessionLocal() as session:
        job = await session.get(PushJob, job_id)
        if not job:
            raise HTTPException(404, f"Push job {job_id} not found")
        if job.status not in ("pending",):
            raise HTTPException(409, f"Job {job_id} is already in status {job.status!r}")
        job.dry_run = False
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        await session.commit()

        # Enqueue push execution as background task
        try:
            from src.tasks.push_tasks import run_push_job
            run_push_job(job_id)
            log.info("Push job %d enqueued for execution", job_id)
        except Exception as exc:
            log.warning("Could not enqueue push job (non-fatal): %s", exc)

        await session.refresh(job)
        return await _job_out(session, job)


@router.post("/jobs/{job_id}/rollback", response_model=PushJobOut)
async def rollback_push_job(job_id: int) -> PushJobOut:
    """Mark a job for rollback (placeholder — vendor connectors implement revert logic)."""
    async with AsyncSessionLocal() as session:
        job = await session.get(PushJob, job_id)
        if not job:
            raise HTTPException(404, f"Push job {job_id} not found")
        if job.status not in ("complete", "partial", "failed"):
            raise HTTPException(409, f"Cannot rollback job in status {job.status!r}")
        job.status = "rolled_back"
        job.error_summary = (job.error_summary or "") + "\n[Rollback requested by operator]"
        await session.commit()
        await session.refresh(job)
        return await _job_out(session, job)
