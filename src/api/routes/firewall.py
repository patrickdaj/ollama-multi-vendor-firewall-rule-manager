"""Firewall live-device endpoints (connect + pull from device)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from src.config import settings
from src.firewall.vendors import get_connector
from src.rag.ingest import onboard_device, reindex_device

router = APIRouter(prefix="/firewall", tags=["firewall"])


@router.get("/devices/{device_name}/rules")
async def get_device_rules(device_name: str, rulebase: str = "security") -> dict:
    device = await settings.get_device_async(device_name)
    if not device:
        raise HTTPException(404, f"Device '{device_name}' not found")
    connector = get_connector(device)
    async with connector:
        rules = await connector.get_rules(rulebase)
    return {"device": device_name, "rulebase": rulebase, "count": len(rules),
            "rules": [r.model_dump() for r in rules]}


@router.get("/devices/{device_name}/objects/addresses")
async def get_address_objects(device_name: str) -> dict:
    device = await settings.get_device_async(device_name)
    if not device:
        raise HTTPException(404, f"Device '{device_name}' not found")
    connector = get_connector(device)
    async with connector:
        objects = await connector.get_address_objects()
    return {"device": device_name, "count": len(objects),
            "objects": [o.model_dump() for o in objects]}


@router.post("/devices/{device_name}/onboard")
async def onboard(device_name: str) -> dict:
    """Pull full policy from a live device → Postgres SOT → ChromaDB index."""
    device = await settings.get_device_async(device_name)
    if not device:
        raise HTTPException(404, f"Device '{device_name}' not found")
    connector = get_connector(device)
    async with connector:
        policy = await connector.get_policy()
    result = await onboard_device(policy, triggered_by="api")
    return {"device": device_name, "vendor": device.vendor,
            "rules_ingested": policy.rule_count(), **result}


@router.post("/devices/{device_name}/reindex")
async def reindex(device_name: str) -> dict:
    """Rebuild ChromaDB from latest Postgres SOT snapshot — no device contact."""
    try:
        result = await reindex_device(device_name)
    except ValueError as e:
        raise HTTPException(404, str(e))
    return {"device": device_name, **result}
