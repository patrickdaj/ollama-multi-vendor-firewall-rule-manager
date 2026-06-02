"""Firewall device management endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from src.config import settings
from src.firewall.models import FirewallPolicy
from src.firewall.vendors import get_connector
from src.rag.loader import ingest_policy

router = APIRouter(prefix="/firewall", tags=["firewall"])


@router.get("/devices")
async def list_devices() -> list[dict]:
    return [
        {"name": d.name, "vendor": d.vendor, "host": d.host}
        for d in settings.firewall_devices
    ]


@router.get("/devices/{device_name}/rules")
async def get_device_rules(device_name: str, rulebase: str = "security") -> dict:
    device = settings.get_device(device_name)
    if not device:
        raise HTTPException(404, f"Device '{device_name}' not found")
    connector = get_connector(device)
    async with connector:
        rules = await connector.get_rules(rulebase)
    return {"device": device_name, "rulebase": rulebase, "count": len(rules), "rules": [r.model_dump() for r in rules]}


@router.get("/devices/{device_name}/objects/addresses")
async def get_address_objects(device_name: str) -> dict:
    device = settings.get_device(device_name)
    if not device:
        raise HTTPException(404, f"Device '{device_name}' not found")
    connector = get_connector(device)
    async with connector:
        objects = await connector.get_address_objects()
    return {"device": device_name, "count": len(objects), "objects": [o.model_dump() for o in objects]}


@router.post("/devices/{device_name}/ingest")
async def ingest_device(device_name: str) -> dict:
    """Connect to a device, pull its policy, and ingest into the RAG store."""
    device = settings.get_device(device_name)
    if not device:
        raise HTTPException(404, f"Device '{device_name}' not found")
    connector = get_connector(device)
    async with connector:
        policy = await connector.get_policy()
    count = ingest_policy(policy)
    return {
        "device": device_name,
        "vendor": device.vendor,
        "rules_ingested": policy.rule_count(),
        "documents_created": count,
    }
