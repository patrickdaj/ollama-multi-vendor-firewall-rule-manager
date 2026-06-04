"""Snapshot history, diffs, and policy object CRUD for the SoT frontend."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func

from src.db.models import Device, PolicyDiff, PolicyObject, Snapshot
from src.db.session import AsyncSessionLocal

router = APIRouter(prefix="/snapshots", tags=["snapshots"])


# ── Response schemas ──────────────────────────────────────────────────────────


class SnapshotOut(BaseModel):
    id: int
    device_name: str
    vendor: str
    status: str
    triggered_by: str
    object_count: int | None
    created_at: datetime
    completed_at: datetime | None


class DiffOut(BaseModel):
    id: int
    object_type: str
    object_name: str
    change_type: str
    before: dict | None
    after: dict | None
    created_at: datetime


class PolicyObjectOut(BaseModel):
    id: int
    object_type: str
    object_name: str
    vendor: str
    data: dict
    content_hash: str


# ── Snapshot endpoints ────────────────────────────────────────────────────────


@router.get("", response_model=list[SnapshotOut])
async def list_snapshots(
    device: str | None = None,
    limit: int = Query(50, le=200),
) -> list[SnapshotOut]:
    """List snapshots, optionally filtered by device."""
    async with AsyncSessionLocal() as session:
        q = (
            select(Snapshot, Device)
            .join(Device, Snapshot.device_id == Device.id)
            .where(Snapshot.status == "complete")
            .order_by(Snapshot.created_at.desc())
            .limit(limit)
        )
        if device:
            q = q.where(Device.name == device)
        rows = (await session.execute(q)).all()
    return [
        SnapshotOut(
            id=s.id, device_name=d.name, vendor=d.vendor,
            status=s.status, triggered_by=s.triggered_by,
            object_count=s.object_count,
            created_at=s.created_at, completed_at=s.completed_at,
        )
        for s, d in rows
    ]


@router.get("/{snapshot_id}/objects", response_model=list[PolicyObjectOut])
async def get_snapshot_objects(
    snapshot_id: int,
    object_type: str | None = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
) -> list[PolicyObjectOut]:
    """List all policy objects in a snapshot."""
    async with AsyncSessionLocal() as session:
        q = (
            select(PolicyObject)
            .where(PolicyObject.snapshot_id == snapshot_id)
            .order_by(PolicyObject.object_type, PolicyObject.object_name)
            .limit(limit).offset(offset)
        )
        if object_type:
            q = q.where(PolicyObject.object_type == object_type)
        rows = (await session.execute(q)).scalars().all()
    return [
        PolicyObjectOut(
            id=r.id, object_type=r.object_type, object_name=r.object_name,
            vendor=r.vendor, data=r.data, content_hash=r.content_hash,
        )
        for r in rows
    ]


@router.get("/{snapshot_id}/diffs", response_model=list[DiffOut])
async def get_snapshot_diffs(snapshot_id: int) -> list[DiffOut]:
    """Return all diffs that were computed FOR this snapshot (vs its predecessor)."""
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(
            select(PolicyDiff)
            .where(PolicyDiff.to_snapshot_id == snapshot_id)
            .order_by(PolicyDiff.object_type, PolicyDiff.object_name)
        )).scalars().all()
    return [
        DiffOut(
            id=r.id, object_type=r.object_type, object_name=r.object_name,
            change_type=r.change_type, before=r.before, after=r.after,
            created_at=r.created_at,
        )
        for r in rows
    ]


# ── Policy object CRUD (SoT write surface) ────────────────────────────────────


@router.get("/objects/{object_id}", response_model=PolicyObjectOut)
async def get_policy_object(object_id: int) -> PolicyObjectOut:
    async with AsyncSessionLocal() as session:
        obj = await session.get(PolicyObject, object_id)
        if not obj:
            raise HTTPException(404, "Object not found")
    return PolicyObjectOut(
        id=obj.id, object_type=obj.object_type, object_name=obj.object_name,
        vendor=obj.vendor, data=obj.data, content_hash=obj.content_hash,
    )


@router.patch("/objects/{object_id}", response_model=PolicyObjectOut)
async def update_policy_object(object_id: int, data: dict) -> PolicyObjectOut:
    """Update a policy object in the Postgres SOT.

    This modifies the stored JSONB data and recomputes the content hash.
    Call POST /firewall/devices/{name}/reindex after edits to sync ChromaDB.
    """
    import hashlib, json
    async with AsyncSessionLocal() as session:
        obj = await session.get(PolicyObject, object_id)
        if not obj:
            raise HTTPException(404, "Object not found")
        obj.data = data
        obj.content_hash = hashlib.sha256(
            json.dumps(data, sort_keys=True, default=str).encode()
        ).hexdigest()
        await session.commit()
        await session.refresh(obj)
    return PolicyObjectOut(
        id=obj.id, object_type=obj.object_type, object_name=obj.object_name,
        vendor=obj.vendor, data=obj.data, content_hash=obj.content_hash,
    )


# ── Object type summary ───────────────────────────────────────────────────────


@router.get("/{snapshot_id}/summary")
async def snapshot_summary(snapshot_id: int) -> dict:
    """Return object type counts for a snapshot — used by the policy browser."""
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(
            select(PolicyObject.object_type, func.count().label("count"))
            .where(PolicyObject.snapshot_id == snapshot_id)
            .group_by(PolicyObject.object_type)
            .order_by(PolicyObject.object_type)
        )).all()
    return {"snapshot_id": snapshot_id, "types": {r[0]: r[1] for r in rows}}
