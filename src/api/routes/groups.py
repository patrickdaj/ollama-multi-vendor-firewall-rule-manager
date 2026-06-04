"""Group hierarchy and group policy rule CRUD."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from src.db.models import (
    Device, DeviceGroup, DeviceZoneMapping, GroupPolicyObject, GroupPolicyRule,
    PolicyObject, Snapshot, TranslationProposal,
)
from typing import Any
from src.db.session import AsyncSessionLocal

router = APIRouter(prefix="/groups", tags=["groups"])
log = logging.getLogger(__name__)


# ── Schemas ───────────────────────────────────────────────────────────────────


class DeviceGroupCreate(BaseModel):
    name: str
    parent_id: int | None = None
    description: str | None = None


class DeviceGroupOut(BaseModel):
    id: int
    name: str
    parent_id: int | None
    description: str | None
    created_at: datetime
    device_count: int = 0
    child_count: int = 0


class DeviceGroupTree(DeviceGroupOut):
    children: list[DeviceGroupTree] = []


class ZoneMappingIn(BaseModel):
    logical_zone: str
    vendor_zone: str


class ZoneMappingOut(BaseModel):
    id: int
    device_id: int
    logical_zone: str
    vendor_zone: str


class GroupRuleCreate(BaseModel):
    rule_type: str = "security"
    rulebase: str = "pre"
    position: int = 0
    name: str
    description: str | None = None
    enabled: bool = True
    base_rule: dict[str, Any] = {}


class GroupRuleOut(BaseModel):
    id: int
    device_group_id: int
    rule_type: str
    rulebase: str
    position: int
    name: str
    description: str | None
    enabled: bool
    base_rule: dict[str, Any]
    created_at: datetime
    updated_at: datetime | None


class EffectivePolicyOut(BaseModel):
    device_group_id: int
    device_group_name: str
    ancestor_chain: list[str]
    pre_rules: list[GroupRuleOut]
    post_rules: list[GroupRuleOut]


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _get_group_or_404(session: Any, group_id: int) -> DeviceGroup:
    """Fetch a group by id — does NOT load relationships."""
    group = await session.get(DeviceGroup, group_id)
    if not group:
        raise HTTPException(404, f"Device group {group_id} not found")
    return group


async def _get_group_with_counts(session: Any, group_id: int) -> DeviceGroup:
    """Fetch a group with devices + children eagerly loaded so counts are safe."""
    result = await session.execute(
        select(DeviceGroup)
        .where(DeviceGroup.id == group_id)
        .options(selectinload(DeviceGroup.devices), selectinload(DeviceGroup.children))
    )
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(404, f"Device group {group_id} not found")
    return group


def _group_out(g: DeviceGroup) -> DeviceGroupOut:
    return DeviceGroupOut(
        id=g.id, name=g.name, parent_id=g.parent_id,
        description=g.description, created_at=g.created_at,
        device_count=len(g.devices), child_count=len(g.children),
    )


async def _ancestor_chain(session: Any, group: DeviceGroup) -> list[DeviceGroup]:
    """Return [root, ..., parent] for a group — closest ancestor last."""
    chain: list[DeviceGroup] = []
    current = group
    while current.parent_id is not None:
        parent = await session.get(DeviceGroup, current.parent_id)
        if not parent:
            break
        chain.append(parent)
        current = parent
    chain.reverse()
    return chain


def _rule_out(r: GroupPolicyRule) -> GroupRuleOut:
    return GroupRuleOut(
        id=r.id, device_group_id=r.device_group_id,
        rule_type=r.rule_type, rulebase=r.rulebase,
        position=r.position, name=r.name,
        description=r.description, enabled=r.enabled,
        base_rule=r.base_rule,
        created_at=r.created_at, updated_at=r.updated_at,
    )


# ── Device group CRUD ─────────────────────────────────────────────────────────


@router.get("", response_model=list[DeviceGroupOut])
async def list_groups() -> list[DeviceGroupOut]:
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(
            select(DeviceGroup)
            .options(selectinload(DeviceGroup.devices), selectinload(DeviceGroup.children))
            .order_by(DeviceGroup.name)
        )).scalars().all()
        return [_group_out(g) for g in rows]


@router.get("/tree", response_model=list[DeviceGroupTree])
async def group_tree() -> list[DeviceGroupTree]:
    """Return the full hierarchy as a nested tree (roots only at top level)."""
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(
            select(DeviceGroup)
            .options(selectinload(DeviceGroup.devices), selectinload(DeviceGroup.children))
            .order_by(DeviceGroup.name)
        )).scalars().all()

        index = {g.id: DeviceGroupTree(
            id=g.id, name=g.name, parent_id=g.parent_id,
            description=g.description, created_at=g.created_at,
            device_count=len(g.devices), child_count=len(g.children),
        ) for g in rows}

    roots: list[DeviceGroupTree] = []
    for node in index.values():
        if node.parent_id is None:
            roots.append(node)
        elif node.parent_id in index:
            index[node.parent_id].children.append(node)
    return roots


@router.post("", response_model=DeviceGroupOut, status_code=201)
async def create_group(body: DeviceGroupCreate) -> DeviceGroupOut:
    async with AsyncSessionLocal() as session:
        if body.parent_id is not None:
            parent = await session.get(DeviceGroup, body.parent_id)
            if not parent:
                raise HTTPException(404, f"Parent group {body.parent_id} not found")
        group = DeviceGroup(
            name=body.name, parent_id=body.parent_id, description=body.description
        )
        session.add(group)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            raise HTTPException(409, f"A group named {body.name!r} already exists")
        await session.refresh(group)
    return DeviceGroupOut(
        id=group.id, name=group.name, parent_id=group.parent_id,
        description=group.description, created_at=group.created_at,
        device_count=0, child_count=0,
    )


@router.get("/{group_id}", response_model=DeviceGroupOut)
async def get_group(group_id: int) -> DeviceGroupOut:
    async with AsyncSessionLocal() as session:
        g = await _get_group_with_counts(session, group_id)
        return _group_out(g)


@router.patch("/{group_id}", response_model=DeviceGroupOut)
async def update_group(group_id: int, body: dict) -> DeviceGroupOut:
    async with AsyncSessionLocal() as session:
        g = await _get_group_with_counts(session, group_id)
        for field in ("name", "description", "parent_id"):
            if field in body:
                setattr(g, field, body[field])
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            raise HTTPException(409, f"A group with that name already exists")
        await session.refresh(g)
        # Re-fetch with counts after refresh (refresh expires relationships)
        g = await _get_group_with_counts(session, group_id)
        return _group_out(g)


@router.delete("/{group_id}", status_code=204)
async def delete_group(group_id: int) -> None:
    async with AsyncSessionLocal() as session:
        g = await _get_group_or_404(session, group_id)
        child_count = (await session.execute(
            select(DeviceGroup).where(DeviceGroup.parent_id == group_id)
        )).scalars().first()
        if child_count is not None:
            raise HTTPException(409, "Remove child groups before deleting this group")
        device_count = (await session.execute(
            select(Device).where(Device.device_group_id == group_id)
        )).scalars().first()
        if device_count is not None:
            raise HTTPException(409, "Reassign devices before deleting this group")
        await session.delete(g)
        await session.commit()


# ── Device ↔ group assignment ─────────────────────────────────────────────────


@router.post("/{group_id}/devices/{device_name}", status_code=204)
async def assign_device(group_id: int, device_name: str) -> None:
    """Assign a device to this group.

    After assignment, automatically runs gap detection for the device's vendor
    against the group's effective policy and creates TranslationProposal records
    for any missing translations.
    """
    async with AsyncSessionLocal() as session:
        await _get_group_or_404(session, group_id)
        result = await session.execute(
            select(Device).where(Device.name == device_name)
        )
        device = result.scalar_one_or_none()
        if not device:
            raise HTTPException(404, f"Device {device_name!r} not found")
        vendor = device.vendor
        device.device_group_id = group_id
        await session.commit()

    # Enqueue gap detection as a background task (Phase 3.5).
    try:
        from src.tasks.gap_tasks import run_gap_detection
        run_gap_detection(group_id, vendor)
        log.info("Gap detection enqueued for group=%d vendor=%s", group_id, vendor)
    except Exception as exc:
        log.warning("Could not enqueue gap detection (non-fatal): %s", exc)


@router.delete("/{group_id}/devices/{device_name}", status_code=204)
async def unassign_device(group_id: int, device_name: str) -> None:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Device).where(Device.name == device_name)
        )
        device = result.scalar_one_or_none()
        if not device:
            raise HTTPException(404, f"Device {device_name!r} not found")
        if device.device_group_id != group_id:
            raise HTTPException(409, f"Device {device_name!r} is not in group {group_id}")
        device.device_group_id = None
        await session.commit()


# ── Zone mappings ─────────────────────────────────────────────────────────────


@router.get("/devices/{device_name}/zones", response_model=list[ZoneMappingOut])
async def list_zone_mappings(device_name: str) -> list[ZoneMappingOut]:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Device).where(Device.name == device_name)
        )
        device = result.scalar_one_or_none()
        if not device:
            raise HTTPException(404, f"Device {device_name!r} not found")
        rows = (await session.execute(
            select(DeviceZoneMapping).where(DeviceZoneMapping.device_id == device.id)
        )).scalars().all()
    return [ZoneMappingOut(
        id=r.id, device_id=r.device_id,
        logical_zone=r.logical_zone, vendor_zone=r.vendor_zone,
    ) for r in rows]


@router.put("/devices/{device_name}/zones", response_model=list[ZoneMappingOut])
async def set_zone_mappings(
    device_name: str, mappings: list[ZoneMappingIn]
) -> list[ZoneMappingOut]:
    """Replace all zone mappings for a device."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Device).where(Device.name == device_name)
        )
        device = result.scalar_one_or_none()
        if not device:
            raise HTTPException(404, f"Device {device_name!r} not found")

        existing = (await session.execute(
            select(DeviceZoneMapping).where(DeviceZoneMapping.device_id == device.id)
        )).scalars().all()
        for row in existing:
            await session.delete(row)

        new_rows = []
        for m in mappings:
            row = DeviceZoneMapping(
                device_id=device.id,
                logical_zone=m.logical_zone,
                vendor_zone=m.vendor_zone,
            )
            session.add(row)
            new_rows.append(row)

        await session.commit()
        for row in new_rows:
            await session.refresh(row)

    return [ZoneMappingOut(
        id=r.id, device_id=r.device_id,
        logical_zone=r.logical_zone, vendor_zone=r.vendor_zone,
    ) for r in new_rows]


# ── Group policy rules ────────────────────────────────────────────────────────


@router.get("/{group_id}/rules", response_model=list[GroupRuleOut])
async def list_rules(
    group_id: int,
    rulebase: str | None = Query(None, description="pre | post | local"),
    rule_type: str | None = Query(None, description="security | nat | decryption | dos | auth"),
) -> list[GroupRuleOut]:
    async with AsyncSessionLocal() as session:
        await _get_group_or_404(session, group_id)
        q = (
            select(GroupPolicyRule)
            .where(GroupPolicyRule.device_group_id == group_id)
            .order_by(GroupPolicyRule.rulebase, GroupPolicyRule.position)
        )
        if rulebase:
            q = q.where(GroupPolicyRule.rulebase == rulebase)
        if rule_type:
            q = q.where(GroupPolicyRule.rule_type == rule_type)
        rows = (await session.execute(q)).scalars().all()
    return [_rule_out(r) for r in rows]


@router.post("/{group_id}/rules", response_model=GroupRuleOut, status_code=201)
async def create_rule(group_id: int, body: GroupRuleCreate) -> GroupRuleOut:
    async with AsyncSessionLocal() as session:
        await _get_group_or_404(session, group_id)
        rule = GroupPolicyRule(
            device_group_id=group_id,
            rule_type=body.rule_type,
            rulebase=body.rulebase,
            position=body.position,
            name=body.name,
            description=body.description,
            enabled=body.enabled,
            base_rule=body.base_rule,
        )
        session.add(rule)
        await session.commit()
        await session.refresh(rule)
    return _rule_out(rule)


@router.patch("/rules/{rule_id}", response_model=GroupRuleOut)
async def update_rule(rule_id: int, body: dict) -> GroupRuleOut:
    async with AsyncSessionLocal() as session:
        rule = await session.get(GroupPolicyRule, rule_id)
        if not rule:
            raise HTTPException(404, f"Rule {rule_id} not found")
        for field in ("name", "description", "enabled", "position",
                      "rulebase", "rule_type", "base_rule"):
            if field in body:
                setattr(rule, field, body[field])
        rule.updated_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(rule)
    return _rule_out(rule)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: int) -> None:
    async with AsyncSessionLocal() as session:
        rule = await session.get(GroupPolicyRule, rule_id)
        if not rule:
            raise HTTPException(404, f"Rule {rule_id} not found")
        await session.delete(rule)
        await session.commit()


# ── Effective policy ──────────────────────────────────────────────────────────


@router.get("/{group_id}/effective-policy", response_model=EffectivePolicyOut)
async def effective_policy(
    group_id: int,
    rule_type: str = Query("security", description="security | nat | decryption | dos | auth"),
) -> EffectivePolicyOut:
    """Compute the full ordered rulebase a device in this group would see.

    Returns pre-rules (root→group) + post-rules (group→root).
    Device-local rules are ingested separately and not included here.
    """
    async with AsyncSessionLocal() as session:
        group = await _get_group_or_404(session, group_id)
        ancestors = await _ancestor_chain(session, group)
        all_groups = ancestors + [group]

        pre_rules: list[GroupRuleOut] = []
        post_rules: list[GroupRuleOut] = []

        for g in all_groups:
            rows = (await session.execute(
                select(GroupPolicyRule)
                .where(
                    GroupPolicyRule.device_group_id == g.id,
                    GroupPolicyRule.rule_type == rule_type,
                    GroupPolicyRule.rulebase == "pre",
                )
                .order_by(GroupPolicyRule.position)
            )).scalars().all()
            pre_rules.extend(_rule_out(r) for r in rows)

        for g in reversed(all_groups):
            rows = (await session.execute(
                select(GroupPolicyRule)
                .where(
                    GroupPolicyRule.device_group_id == g.id,
                    GroupPolicyRule.rule_type == rule_type,
                    GroupPolicyRule.rulebase == "post",
                )
                .order_by(GroupPolicyRule.position)
            )).scalars().all()
            post_rules.extend(_rule_out(r) for r in rows)

    return EffectivePolicyOut(
        device_group_id=group.id,
        device_group_name=group.name,
        ancestor_chain=[g.name for g in ancestors],
        pre_rules=pre_rules,
        post_rules=post_rules,
    )


# ── Devices in group ──────────────────────────────────────────────────────────


class DeviceInGroupOut(BaseModel):
    id: int
    name: str
    vendor: str
    host: str | None
    last_synced_at: datetime | None


@router.get("/{group_id}/devices", response_model=list[DeviceInGroupOut])
async def list_group_devices(group_id: int) -> list[DeviceInGroupOut]:
    async with AsyncSessionLocal() as session:
        await _get_group_or_404(session, group_id)
        rows = (await session.execute(
            select(Device).where(Device.device_group_id == group_id).order_by(Device.name)
        )).scalars().all()
    return [DeviceInGroupOut(
        id=d.id, name=d.name, vendor=d.vendor,
        host=d.host, last_synced_at=d.last_synced_at,
    ) for d in rows]


# ── Group policy objects CRUD ─────────────────────────────────────────────────


class GroupObjectCreate(BaseModel):
    object_type: str
    object_name: str
    description: str | None = None
    base_data: dict[str, Any] = {}


class GroupObjectOut(BaseModel):
    id: int
    device_group_id: int | None
    object_type: str
    object_name: str
    description: str | None
    base_data: dict[str, Any]
    created_at: datetime
    updated_at: datetime | None


def _obj_out(o: GroupPolicyObject) -> GroupObjectOut:
    return GroupObjectOut(
        id=o.id, device_group_id=o.device_group_id,
        object_type=o.object_type, object_name=o.object_name,
        description=o.description, base_data=o.base_data,
        created_at=o.created_at, updated_at=o.updated_at,
    )


@router.get("/{group_id}/objects", response_model=list[GroupObjectOut])
async def list_group_objects(group_id: int) -> list[GroupObjectOut]:
    async with AsyncSessionLocal() as session:
        await _get_group_or_404(session, group_id)
        rows = (await session.execute(
            select(GroupPolicyObject)
            .where(GroupPolicyObject.device_group_id == group_id)
            .order_by(GroupPolicyObject.object_type, GroupPolicyObject.object_name)
        )).scalars().all()
    return [_obj_out(o) for o in rows]


@router.post("/{group_id}/objects", response_model=GroupObjectOut, status_code=201)
async def create_group_object(group_id: int, body: GroupObjectCreate) -> GroupObjectOut:
    async with AsyncSessionLocal() as session:
        await _get_group_or_404(session, group_id)
        obj = GroupPolicyObject(
            device_group_id=group_id,
            object_type=body.object_type,
            object_name=body.object_name,
            description=body.description,
            base_data=body.base_data,
        )
        session.add(obj)
        await session.commit()
        await session.refresh(obj)
    return _obj_out(obj)


@router.patch("/objects/{object_id}", response_model=GroupObjectOut)
async def update_group_object(object_id: int, body: dict) -> GroupObjectOut:
    async with AsyncSessionLocal() as session:
        obj = await session.get(GroupPolicyObject, object_id)
        if not obj:
            raise HTTPException(404, f"Object {object_id} not found")
        for field in ("object_name", "description", "base_data"):
            if field in body:
                setattr(obj, field, body[field])
        obj.updated_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(obj)
    return _obj_out(obj)


@router.delete("/objects/{object_id}", status_code=204)
async def delete_group_object(object_id: int) -> None:
    async with AsyncSessionLocal() as session:
        obj = await session.get(GroupPolicyObject, object_id)
        if not obj:
            raise HTTPException(404, f"Object {object_id} not found")
        await session.delete(obj)
        await session.commit()


# ── Import policy from device ─────────────────────────────────────────────────


IMPORTABLE_OBJECT_TYPES = {
    "security_rule", "nat_rule",
    "address_object", "service_object", "service_group",
    "application", "url_category", "edl",
}

RULE_TYPES = {"security_rule", "nat_rule"}


class ImportCandidate(BaseModel):
    """A single candidate for import review."""
    object_type: str
    object_name: str
    vendor_data: dict[str, Any]
    proposed_base: dict[str, Any]  # base_rule or base_data depending on type
    reasoning: str
    selected: bool = True


class ImportPreviewOut(BaseModel):
    device_name: str
    vendor: str
    snapshot_id: int
    candidates: list[ImportCandidate]
    total: int
    ai_processed: int
    ai_failed: int


class ImportConfirmIn(BaseModel):
    snapshot_id: int
    candidates: list[ImportCandidate]
    rulebase: str = "pre"


class ImportConfirmOut(BaseModel):
    rules_created: int
    objects_created: int


class ImportStartOut(BaseModel):
    task_id: str
    status: str = "queued"


@router.post("/{group_id}/import/{device_name}/start", response_model=ImportStartOut, status_code=202)
async def import_policy_start(
    group_id: int,
    device_name: str,
    limit: int = Query(50, description="Max objects to preview"),
) -> ImportStartOut:
    """Enqueue a background import preview and return the task_id immediately.

    The client polls GET /api/v1/tasks/{task_id} until status == "complete",
    then reads result.candidates to show the review dialog.
    """
    await _get_group_or_404_simple(group_id)
    from src.tasks.import_tasks import run_import_preview
    task = run_import_preview(group_id, device_name, limit)
    return ImportStartOut(task_id=task.id)


async def _get_group_or_404_simple(group_id: int) -> None:
    async with AsyncSessionLocal() as session:
        await _get_group_or_404(session, group_id)


@router.post("/{group_id}/import/{device_name}/preview", response_model=ImportPreviewOut)
async def import_policy_preview(
    group_id: int,
    device_name: str,
    limit: int = Query(50, description="Max objects to preview (keeps LLM calls manageable)"),
) -> ImportPreviewOut:
    """Preview AI-normalized policy objects from a device's latest snapshot.

    Reads the device's most recent complete snapshot and runs each importable
    policy object through the AI normalization pipeline, producing vendor-agnostic
    candidates for review. The human then selects/edits candidates and calls
    /confirm to commit them to the group.

    This is intentionally synchronous — for large configs consider lowering `limit`
    and calling in batches. Phase 3.5 moves this to the task queue.
    """
    from src.ai.import_policy import normalize_object, normalize_rule

    async with AsyncSessionLocal() as session:
        await _get_group_or_404(session, group_id)

        device = (await session.execute(
            select(Device).where(Device.name == device_name)
        )).scalar_one_or_none()
        if not device:
            raise HTTPException(404, f"Device {device_name!r} not found")

        # Get latest completed snapshot
        snap = (await session.execute(
            select(Snapshot)
            .where(Snapshot.device_id == device.id, Snapshot.status == "complete")
            .order_by(Snapshot.created_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        if not snap:
            raise HTTPException(404, f"No completed snapshot found for {device_name!r}. Run onboard first.")

        # Fetch importable objects — extract to plain dicts while session is open
        # to avoid DetachedInstanceError after the session closes.
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

    async def _normalize_one(obj: dict[str, Any]) -> ImportCandidate:
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
            log.warning("AI normalization failed for %s/%s: %s", obj["object_type"], obj["object_name"], exc)
            proposed_base = {}
            reasoning = f"AI normalization failed: {exc}"

        return ImportCandidate(
            object_type=obj["object_type"],
            object_name=obj["object_name"],
            vendor_data=obj["data"],
            proposed_base=proposed_base,
            reasoning=reasoning,
            selected=bool(proposed_base),
        )

    candidates: list[ImportCandidate] = []
    for obj in objects:
        candidates.append(await _normalize_one(obj))
    ai_processed = sum(1 for c in candidates if "failed" not in c.reasoning.lower())
    ai_failed = sum(1 for c in candidates if "failed" in c.reasoning.lower())

    return ImportPreviewOut(
        device_name=device_name,
        vendor=vendor,
        snapshot_id=snap.id,
        candidates=list(candidates),
        total=len(candidates),
        ai_processed=ai_processed,
        ai_failed=ai_failed,
    )


@router.post("/{group_id}/import/{device_name}/confirm", response_model=ImportConfirmOut)
async def import_policy_confirm(
    group_id: int,
    device_name: str,
    body: ImportConfirmIn,
) -> ImportConfirmOut:
    """Commit reviewed import candidates to the group's desired-state policy.

    Only candidates with selected=True are written. Rules land in group_policy_rules;
    objects land in group_policy_objects. Duplicate names within the same group are
    skipped silently (the existing record wins).
    """
    async with AsyncSessionLocal() as session:
        await _get_group_or_404(session, group_id)

        rules_created = 0
        objects_created = 0
        position = 0

        for c in body.candidates:
            if not c.selected:
                continue

            if c.object_type in RULE_TYPES:
                # Check for duplicate
                existing = (await session.execute(
                    select(GroupPolicyRule).where(
                        GroupPolicyRule.device_group_id == group_id,
                        GroupPolicyRule.name == c.object_name,
                    )
                )).scalar_one_or_none()
                if existing:
                    continue

                rule_type = "security" if c.object_type == "security_rule" else "nat"
                session.add(GroupPolicyRule(
                    device_group_id=group_id,
                    rule_type=rule_type,
                    rulebase=body.rulebase,
                    position=position,
                    name=c.object_name,
                    description=f"Imported from {device_name}",
                    enabled=True,
                    base_rule=c.proposed_base,
                ))
                position += 1
                rules_created += 1

            else:
                existing = (await session.execute(
                    select(GroupPolicyObject).where(
                        GroupPolicyObject.device_group_id == group_id,
                        GroupPolicyObject.object_type == c.object_type,
                        GroupPolicyObject.object_name == c.object_name,
                    )
                )).scalar_one_or_none()
                if existing:
                    continue

                session.add(GroupPolicyObject(
                    device_group_id=group_id,
                    object_type=c.object_type,
                    object_name=c.object_name,
                    description=f"Imported from {device_name}",
                    base_data=c.proposed_base,
                ))
                objects_created += 1

        await session.commit()

    return ImportConfirmOut(rules_created=rules_created, objects_created=objects_created)


# ── Compliance / drift view ───────────────────────────────────────────────────


class ComplianceItem(BaseModel):
    object_type: str
    object_name: str
    # compliant | drifted | orphan | missing
    status: str
    intent_data: dict[str, Any] | None = None
    live_data: dict[str, Any] | None = None


class ComplianceResult(BaseModel):
    device_name: str
    group_name: str
    compliant: list[ComplianceItem]
    drifted: list[ComplianceItem]
    orphan: list[ComplianceItem]
    missing: list[ComplianceItem]
    score: int  # 0-100 percent compliant+drifted vs all intent items


@router.get("/{group_id}/compliance/{device_name}", response_model=ComplianceResult)
async def get_compliance(group_id: int, device_name: str) -> ComplianceResult:
    """Compare the device's latest snapshot against the group's effective policy.

    Returns four buckets:
      compliant — object/rule exists in both, data matches (same content_hash or equal JSON)
      drifted   — exists in both, but data differs
      orphan    — on device but not in intent (extra, unmanaged)
      missing   — in intent but not on device (not pushed yet)
    """
    from sqlalchemy import select as sel

    async with AsyncSessionLocal() as session:
        group = await session.get(DeviceGroup, group_id)
        if not group:
            raise HTTPException(404, f"Group {group_id} not found")

        device_result = await session.execute(
            sel(Device).where(Device.name == device_name)
        )
        device = device_result.scalar_one_or_none()
        if not device:
            raise HTTPException(404, f"Device {device_name!r} not found")

        # Latest complete snapshot for this device
        snap_result = await session.execute(
            sel(Snapshot)
            .where(Snapshot.device_id == device.id, Snapshot.status == "complete")
            .order_by(Snapshot.created_at.desc())
            .limit(1)
        )
        snapshot = snap_result.scalar_one_or_none()

        # Live objects from latest snapshot
        live_objects: dict[tuple[str, str], PolicyObject] = {}
        if snapshot:
            live_rows = (await session.execute(
                sel(PolicyObject).where(PolicyObject.snapshot_id == snapshot.id)
            )).scalars().all()
            for obj in live_rows:
                live_objects[(obj.object_type, obj.object_name)] = obj

        # Intent objects from group ancestor chain
        chain: list[DeviceGroup] = []
        current = group
        while current is not None:
            chain.append(current)
            current = await session.get(DeviceGroup, current.parent_id) if current.parent_id else None
        chain.reverse()
        all_group_ids = [g.id for g in chain]

        intent_objects = (await session.execute(
            sel(GroupPolicyObject).where(
                GroupPolicyObject.device_group_id.in_(all_group_ids + [None])  # type: ignore[list-item]
            )
        )).scalars().all()

        intent_rules = (await session.execute(
            sel(GroupPolicyRule).where(
                GroupPolicyRule.device_group_id.in_(all_group_ids)
            ).order_by(GroupPolicyRule.rulebase, GroupPolicyRule.position)
        )).scalars().all()

    # Build intent lookup: (object_type, object_name) → data
    intent_lookup: dict[tuple[str, str], dict[str, Any]] = {}
    for obj in intent_objects:
        intent_lookup[(obj.object_type, obj.object_name)] = dict(obj.base_data or {})
    for rule in intent_rules:
        intent_lookup[(rule.rule_type, rule.name)] = dict(rule.base_rule or {})

    compliant: list[ComplianceItem] = []
    drifted: list[ComplianceItem] = []
    orphan: list[ComplianceItem] = []
    missing: list[ComplianceItem] = []

    # Compare intent vs live
    for (otype, oname), intent_data in intent_lookup.items():
        live_obj = live_objects.get((otype, oname))
        if live_obj is None:
            missing.append(ComplianceItem(
                object_type=otype, object_name=oname,
                status="missing", intent_data=intent_data,
            ))
        else:
            live_data = dict(live_obj.data or {})
            # Simple equality check on the JSON structure
            if live_data == intent_data:
                compliant.append(ComplianceItem(
                    object_type=otype, object_name=oname,
                    status="compliant", intent_data=intent_data, live_data=live_data,
                ))
            else:
                drifted.append(ComplianceItem(
                    object_type=otype, object_name=oname,
                    status="drifted", intent_data=intent_data, live_data=live_data,
                ))

    # Orphans: on device but not in intent
    for (otype, oname), live_obj in live_objects.items():
        if (otype, oname) not in intent_lookup:
            orphan.append(ComplianceItem(
                object_type=otype, object_name=oname,
                status="orphan", live_data=dict(live_obj.data or {}),
            ))

    total_intent = len(intent_lookup)
    score = int(len(compliant) / total_intent * 100) if total_intent > 0 else 100

    return ComplianceResult(
        device_name=device_name,
        group_name=group.name,
        compliant=compliant,
        drifted=drifted,
        orphan=orphan,
        missing=missing,
        score=score,
    )
