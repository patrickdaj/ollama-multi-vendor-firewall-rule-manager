"""Database operations: snapshot creation, diff computation, history queries."""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Device, PolicyDiff, PolicyObject, Snapshot
from src.firewall.models import FirewallPolicy

logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _hash(obj: dict) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, default=str).encode()
    ).hexdigest()


def _policy_objects(policy: FirewallPolicy) -> list[tuple[str, str, dict]]:
    """Return (object_type, name, data) tuples for every object in policy."""
    rows: list[tuple[str, str, dict]] = []

    for r in policy.rules:
        rows.append(("security_rule", r.name, r.model_dump()))
    for r in policy.nat_rules:
        rows.append(("nat_rule", r.name, r.model_dump()))
    for r in policy.decryption_rules:
        rows.append(("decryption_rule", r.name, r.model_dump()))
    for r in policy.dos_policies:
        rows.append(("dos_policy", r.name, r.model_dump()))
    for r in policy.auth_policies:
        rows.append(("auth_policy", r.name, r.model_dump()))
    for o in policy.address_objects:
        rows.append(("address_object", o.name, o.model_dump()))
    for o in policy.service_objects:
        rows.append(("service_object", o.name, o.model_dump()))
    for o in policy.service_groups:
        rows.append(("service_group", o.name, o.model_dump()))
    for o in policy.application_objects:
        rows.append(("application", o.name, o.model_dump()))
    for o in policy.application_groups:
        rows.append(("app_group", o.name, o.model_dump()))
    for o in policy.url_categories:
        rows.append(("url_category", o.name, o.model_dump()))
    for o in policy.security_profiles:
        rows.append(("security_profile", o.name, o.model_dump()))
    for o in policy.decryption_profiles:
        rows.append(("decryption_profile", o.name, o.model_dump()))
    for o in policy.edls:
        rows.append(("edl", o.name, o.model_dump()))
    for o in policy.zones:
        rows.append(("zone", o.name, o.model_dump()))

    return rows


# ── Device upsert ─────────────────────────────────────────────────────────────


async def _upsert_device(
    session: AsyncSession, name: str, vendor: str, host: str | None
) -> Device:
    result = await session.execute(select(Device).where(Device.name == name))
    device = result.scalar_one_or_none()
    if device is None:
        device = Device(name=name, vendor=vendor, host=host)
        session.add(device)
        await session.flush()
    return device


# ── Diff computation ──────────────────────────────────────────────────────────


async def _compute_and_store_diffs(
    session: AsyncSession,
    device: Device,
    prev_snapshot_id: int,
    new_snapshot_id: int,
) -> int:
    """Compare two snapshots and write PolicyDiff rows. Returns change count."""
    prev_rows = (
        await session.execute(
            select(PolicyObject).where(PolicyObject.snapshot_id == prev_snapshot_id)
        )
    ).scalars().all()
    new_rows = (
        await session.execute(
            select(PolicyObject).where(PolicyObject.snapshot_id == new_snapshot_id)
        )
    ).scalars().all()

    prev_index = {(r.object_type, r.object_name): r for r in prev_rows}
    new_index = {(r.object_type, r.object_name): r for r in new_rows}

    diffs: list[PolicyDiff] = []

    for key, new_obj in new_index.items():
        prev_obj = prev_index.get(key)
        if prev_obj is None:
            diffs.append(PolicyDiff(
                device_id=device.id,
                from_snapshot_id=prev_snapshot_id,
                to_snapshot_id=new_snapshot_id,
                object_type=key[0],
                object_name=key[1],
                change_type="added",
                before=None,
                after=new_obj.data,
            ))
        elif prev_obj.content_hash != new_obj.content_hash:
            diffs.append(PolicyDiff(
                device_id=device.id,
                from_snapshot_id=prev_snapshot_id,
                to_snapshot_id=new_snapshot_id,
                object_type=key[0],
                object_name=key[1],
                change_type="modified",
                before=prev_obj.data,
                after=new_obj.data,
            ))

    for key, prev_obj in prev_index.items():
        if key not in new_index:
            diffs.append(PolicyDiff(
                device_id=device.id,
                from_snapshot_id=prev_snapshot_id,
                to_snapshot_id=new_snapshot_id,
                object_type=key[0],
                object_name=key[1],
                change_type="removed",
                before=prev_obj.data,
                after=None,
            ))

    for diff in diffs:
        session.add(diff)

    return len(diffs)


# ── Public API ────────────────────────────────────────────────────────────────


async def save_snapshot(
    session: AsyncSession,
    policy: FirewallPolicy,
    triggered_by: str = "manual",
) -> Snapshot:
    """Persist a full policy snapshot and compute diffs vs previous.

    Returns the completed Snapshot row.
    """
    device = await _upsert_device(
        session, policy.device, policy.vendor, getattr(policy, "host", None)
    )

    # Find previous completed snapshot for diff
    prev_result = await session.execute(
        select(Snapshot)
        .where(Snapshot.device_id == device.id, Snapshot.status == "complete")
        .order_by(Snapshot.created_at.desc())
        .limit(1)
    )
    prev_snapshot = prev_result.scalar_one_or_none()

    snapshot = Snapshot(
        device_id=device.id,
        status="in_progress",
        triggered_by=triggered_by,
    )
    session.add(snapshot)
    await session.flush()  # get snapshot.id

    objects = _policy_objects(policy)
    for obj_type, obj_name, data in objects:
        session.add(PolicyObject(
            snapshot_id=snapshot.id,
            device_id=device.id,
            object_type=obj_type,
            object_name=obj_name,
            vendor=policy.vendor,
            data=data,
            content_hash=_hash(data),
        ))

    snapshot.status = "complete"
    snapshot.object_count = len(objects)
    snapshot.completed_at = datetime.now(timezone.utc)

    device.last_synced_at = snapshot.completed_at

    if prev_snapshot:
        await session.flush()
        diff_count = await _compute_and_store_diffs(
            session, device, prev_snapshot.id, snapshot.id
        )
        logger.info(
            "Snapshot %d for %s: %d objects, %d changes vs snapshot %d",
            snapshot.id, policy.device, len(objects), diff_count, prev_snapshot.id,
        )
    else:
        logger.info(
            "Snapshot %d for %s: %d objects (first snapshot, no diff)",
            snapshot.id, policy.device, len(objects),
        )

    await session.commit()
    return snapshot


async def get_latest_snapshot(session: AsyncSession, device_name: str) -> Snapshot | None:
    result = await session.execute(
        select(Snapshot)
        .join(Device)
        .where(Device.name == device_name, Snapshot.status == "complete")
        .order_by(Snapshot.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def get_recent_diffs(
    session: AsyncSession, device_name: str, limit: int = 50
) -> list[PolicyDiff]:
    """Return the most recent diff records for a device."""
    result = await session.execute(
        select(PolicyDiff)
        .join(Device, PolicyDiff.device_id == Device.id)
        .where(Device.name == device_name)
        .order_by(PolicyDiff.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def list_devices(session: AsyncSession) -> list[Device]:
    result = await session.execute(select(Device).order_by(Device.name))
    return list(result.scalars().all())
