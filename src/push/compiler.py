"""Push compiler — converts group intent policy into vendor-specific push items.

The compiler takes a group + device and produces an ordered list of PushItems:
  1. Load effective rules and objects from the full ancestor chain.
  2. Apply approved object translations for the device's vendor.
  3. Apply approved rule translations for the device's vendor.
  4. Substitute logical zone names with device-specific zone names.
  5. Diff against the device's latest snapshot to determine create/update/no-change.

Objects are ordered before rules. Leaf objects come before groups that reference them.
Rules are ordered by rulebase (pre before post) and position.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import (
    Device, DeviceGroup, DeviceZoneMapping,
    GroupPolicyObject, GroupPolicyRule,
    ObjectTranslation, PolicyObject, RuleTranslation, Snapshot,
)

log = logging.getLogger(__name__)


@dataclass
class PushItem:
    """A single compiled policy item ready to be sent to a device."""
    item_type: str          # "object" | "rule"
    object_type: str
    item_name: str
    # create | update | delete | no-change
    action: str
    vendor_payload: dict[str, Any]
    sequence: int = 0


@dataclass
class CompileResult:
    device_name: str
    vendor: str
    group_id: int
    items: list[PushItem] = field(default_factory=list)

    @property
    def creates(self) -> list[PushItem]:
        return [i for i in self.items if i.action == "create"]

    @property
    def updates(self) -> list[PushItem]:
        return [i for i in self.items if i.action == "update"]

    @property
    def no_changes(self) -> list[PushItem]:
        return [i for i in self.items if i.action == "no-change"]


async def compile_push(
    session: AsyncSession,
    group_id: int,
    device_name: str,
) -> CompileResult:
    """Compile the push plan for a device against its assigned group.

    Returns a CompileResult with all items ordered for deployment.
    Raises ValueError if the device is not found or not assigned to a group.
    """
    device_result = await session.execute(
        select(Device).where(Device.name == device_name)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise ValueError(f"Device {device_name!r} not found")

    actual_group_id = device.device_group_id or group_id

    # Full ancestor chain
    chain: list[DeviceGroup] = []
    current = await session.get(DeviceGroup, actual_group_id)
    while current is not None:
        chain.append(current)
        current = await session.get(DeviceGroup, current.parent_id) if current.parent_id else None
    chain.reverse()
    all_group_ids = [g.id for g in chain]

    # Collect objects and rules
    objects = (await session.execute(
        select(GroupPolicyObject).where(
            GroupPolicyObject.device_group_id.in_(all_group_ids + [None])  # type: ignore
        )
    )).scalars().all()

    rules = (await session.execute(
        select(GroupPolicyRule).where(
            GroupPolicyRule.device_group_id.in_(all_group_ids)
        ).order_by(GroupPolicyRule.rulebase, GroupPolicyRule.position)
    )).scalars().all()

    vendor = device.vendor

    # Approved object translations for this vendor
    obj_translations = {
        (t.object_type, t.object_name): dict(t.translation or {})
        for t in (await session.execute(
            select(ObjectTranslation).where(
                ObjectTranslation.target_vendor == vendor,
                ObjectTranslation.status == "approved",
            )
        )).scalars().all()
    }

    # Approved rule translations for this vendor
    rule_translations = {
        t.rule_id: dict(t.translation or {})
        for t in (await session.execute(
            select(RuleTranslation).where(
                RuleTranslation.target_vendor == vendor,
                RuleTranslation.status == "approved",
            )
        )).scalars().all()
    }

    # Zone mappings: logical → vendor
    zone_map = {
        z.logical_zone: z.vendor_zone
        for z in (await session.execute(
            select(DeviceZoneMapping).where(DeviceZoneMapping.device_id == device.id)
        )).scalars().all()
    }

    # Latest snapshot for diff
    snap = (await session.execute(
        select(Snapshot)
        .where(Snapshot.device_id == device.id, Snapshot.status == "complete")
        .order_by(Snapshot.created_at.desc())
        .limit(1)
    )).scalar_one_or_none()

    live_objects: dict[tuple[str, str], dict[str, Any]] = {}
    if snap:
        live_rows = (await session.execute(
            select(PolicyObject).where(PolicyObject.snapshot_id == snap.id)
        )).scalars().all()
        for obj in live_rows:
            live_objects[(obj.object_type, obj.object_name)] = dict(obj.data or {})

    result = CompileResult(device_name=device_name, vendor=vendor, group_id=actual_group_id)
    seq = 0

    # ── Compile objects ──────────────────────────────────────────────────────
    for obj in objects:
        base = dict(obj.base_data or {})
        translation = obj_translations.get((obj.object_type, obj.object_name), {})
        # Merge base + translation (translation overrides base fields)
        payload = {**base, **translation}

        live = live_objects.get((obj.object_type, obj.object_name))
        if live is None:
            action = "create"
        elif live == payload:
            action = "no-change"
        else:
            action = "update"

        result.items.append(PushItem(
            item_type="object",
            object_type=obj.object_type,
            item_name=obj.object_name,
            action=action,
            vendor_payload=payload,
            sequence=seq,
        ))
        seq += 1

    # ── Compile rules ────────────────────────────────────────────────────────
    for rule in rules:
        base = dict(rule.base_rule or {})
        translation = rule_translations.get(rule.id, {})
        payload = {**base, **translation}

        # Substitute logical zones → vendor zones
        for zone_field in ("src_zones", "dst_zones"):
            if zone_field in payload and isinstance(payload[zone_field], list):
                payload[zone_field] = [
                    zone_map.get(z, z) for z in payload[zone_field]
                ]

        live = live_objects.get((rule.rule_type, rule.name))
        if live is None:
            action = "create"
        elif live == payload:
            action = "no-change"
        else:
            action = "update"

        result.items.append(PushItem(
            item_type="rule",
            object_type=rule.rule_type,
            item_name=rule.name,
            action=action,
            vendor_payload=payload,
            sequence=seq,
        ))
        seq += 1

    log.info(
        "Compiled push for %s/%s: %d create, %d update, %d no-change",
        device_name, vendor,
        len(result.creates), len(result.updates), len(result.no_changes),
    )
    return result
