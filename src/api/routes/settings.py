"""System settings — operator-configurable key/value pairs."""
from __future__ import annotations

import json
import logging
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from src.db.models import SystemSetting
from src.db.session import AsyncSessionLocal

router = APIRouter(prefix="/settings", tags=["settings"])
log = logging.getLogger(__name__)

# Keys that are allowed and their human labels
ALLOWED_KEYS = {
    "default_username",
    "default_password",
    "default_verify_ssl",
    "default_port_paloalto",
    "default_port_fortinet",
    "default_port_cisco_asa",
    "default_port_cisco_ftd",
}


class SettingOut(BaseModel):
    key: str
    value: str | int | float | bool | None
    updated_at: datetime | None = None


class SettingIn(BaseModel):
    value: str | int | float | bool | None


@router.get("", response_model=list[SettingOut])
async def list_settings() -> list[SettingOut]:
    """Return all system settings (omits sensitive values — password is returned masked)."""
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(select(SystemSetting))).scalars().all()
        result = {r.key: r for r in rows}

    out: list[SettingOut] = []
    for key in sorted(ALLOWED_KEYS):
        row = result.get(key)
        if row is None:
            out.append(SettingOut(key=key, value=None))
        else:
            raw = json.loads(row.value) if row.value != "null" else None
            out.append(SettingOut(key=key, value=raw, updated_at=row.updated_at))
    return out


@router.put("/{key}", response_model=SettingOut)
async def upsert_setting(key: str, body: SettingIn) -> SettingOut:
    if key not in ALLOWED_KEYS:
        raise HTTPException(400, f"Unknown setting key {key!r}")
    async with AsyncSessionLocal() as session:
        row = await session.get(SystemSetting, key)
        if row is None:
            row = SystemSetting(key=key, value="null")
            session.add(row)
        row.value = json.dumps(body.value)
        await session.commit()
        await session.refresh(row)

    raw = json.loads(row.value) if row.value != "null" else None
    return SettingOut(key=key, value=raw, updated_at=row.updated_at)


@router.delete("/{key}", status_code=204)
async def delete_setting(key: str) -> None:
    if key not in ALLOWED_KEYS:
        raise HTTPException(400, f"Unknown setting key {key!r}")
    async with AsyncSessionLocal() as session:
        row = await session.get(SystemSetting, key)
        if row:
            await session.delete(row)
            await session.commit()


async def get_setting(key: str) -> str | int | float | bool | None:
    """Internal helper for reading a single setting (e.g. to pre-fill device creation)."""
    async with AsyncSessionLocal() as session:
        row = await session.get(SystemSetting, key)
        if row is None or row.value == "null":
            return None
        return json.loads(row.value)
