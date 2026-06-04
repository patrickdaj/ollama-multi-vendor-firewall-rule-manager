"""Device registry API — CRUD for managed firewall devices.

Credentials are accepted in request bodies but stored Fernet-encrypted.
They are never returned in API responses (only a `has_credentials` bool).
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from src.db.models import Device, DeviceGroup, PolicyObject, Snapshot
from src.db.session import AsyncSessionLocal
from src.security.credentials import decrypt_credentials, encrypt_credentials

router = APIRouter(prefix="/devices", tags=["devices"])


# ── Request / response schemas ────────────────────────────────────────────────


class DeviceCreate(BaseModel):
    name: str
    vendor: str
    host: str
    port: int | None = None
    verify_ssl: bool = True
    username: str = ""
    password: str = ""
    api_key: str = ""
    notes: str = ""


class DeviceUpdate(BaseModel):
    host: str | None = None
    port: int | None = None
    verify_ssl: bool | None = None
    username: str | None = None
    password: str | None = None
    api_key: str | None = None
    notes: str | None = None


class DeviceOut(BaseModel):
    id: int
    name: str
    vendor: str
    host: str | None
    port: int | None
    verify_ssl: bool
    has_credentials: bool
    notes: str | None
    created_at: datetime
    last_synced_at: datetime | None
    snapshot_count: int = 0
    latest_object_count: int | None = None
    device_group_id: int | None = None
    device_group_name: str | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _creds_dict(req: DeviceCreate | DeviceUpdate) -> dict:
    return {k: v for k, v in {
        "username": getattr(req, "username", None),
        "password": getattr(req, "password", None),
        "api_key": getattr(req, "api_key", None),
    }.items() if v}


async def _device_out(session, device: Device) -> DeviceOut:
    snap_count = (await session.execute(
        select(Snapshot).where(Snapshot.device_id == device.id, Snapshot.status == "complete")
    )).scalars().all()

    latest_count: int | None = None
    if snap_count:
        latest = max(snap_count, key=lambda s: s.created_at)
        latest_count = latest.object_count

    group_id = device.device_group_id
    group_name: str | None = None
    if group_id is not None:
        grp = await session.get(DeviceGroup, group_id)
        if grp:
            group_name = grp.name

    return DeviceOut(
        id=device.id,
        name=device.name,
        vendor=device.vendor,
        host=device.host,
        port=device.port,
        verify_ssl=device.verify_ssl,
        has_credentials=bool(device.credentials_enc),
        notes=device.notes,
        created_at=device.created_at,
        last_synced_at=device.last_synced_at,
        snapshot_count=len(snap_count),
        latest_object_count=latest_count,
        device_group_id=group_id,
        device_group_name=group_name,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("", response_model=list[DeviceOut])
async def list_devices() -> list[DeviceOut]:
    """List all registered devices from Postgres."""
    async with AsyncSessionLocal() as session:
        devices = (await session.execute(
            select(Device).order_by(Device.name)
        )).scalars().all()
        return [await _device_out(session, d) for d in devices]


@router.post("", response_model=DeviceOut, status_code=201)
async def create_device(req: DeviceCreate) -> DeviceOut:
    """Register a new device. Credentials are encrypted at rest."""
    async with AsyncSessionLocal() as session:
        existing = (await session.execute(
            select(Device).where(Device.name == req.name)
        )).scalar_one_or_none()
        if existing:
            raise HTTPException(409, f"Device '{req.name}' already exists")

        creds = _creds_dict(req)
        device = Device(
            name=req.name,
            vendor=req.vendor,
            host=req.host,
            port=req.port,
            verify_ssl=req.verify_ssl,
            credentials_enc=encrypt_credentials(creds) if creds else None,
            notes=req.notes or None,
        )
        session.add(device)
        await session.commit()
        await session.refresh(device)
        return await _device_out(session, device)


@router.get("/{name}", response_model=DeviceOut)
async def get_device(name: str) -> DeviceOut:
    async with AsyncSessionLocal() as session:
        device = (await session.execute(
            select(Device).where(Device.name == name)
        )).scalar_one_or_none()
        if not device:
            raise HTTPException(404, f"Device '{name}' not found")
        return await _device_out(session, device)


@router.patch("/{name}", response_model=DeviceOut)
async def update_device(name: str, req: DeviceUpdate) -> DeviceOut:
    """Update device connection details or credentials."""
    async with AsyncSessionLocal() as session:
        device = (await session.execute(
            select(Device).where(Device.name == name)
        )).scalar_one_or_none()
        if not device:
            raise HTTPException(404, f"Device '{name}' not found")

        if req.host is not None:
            device.host = req.host
        if req.port is not None:
            device.port = req.port
        if req.verify_ssl is not None:
            device.verify_ssl = req.verify_ssl
        if req.notes is not None:
            device.notes = req.notes

        # Merge updated credentials into existing
        new_creds = {k: v for k, v in {
            "username": req.username,
            "password": req.password,
            "api_key": req.api_key,
        }.items() if v is not None}
        if new_creds:
            existing_creds = decrypt_credentials(device.credentials_enc) if device.credentials_enc else {}
            existing_creds.update(new_creds)
            device.credentials_enc = encrypt_credentials(existing_creds)

        await session.commit()
        await session.refresh(device)
        return await _device_out(session, device)


@router.delete("/{name}", status_code=204)
async def delete_device(name: str) -> None:
    """Remove a device and all its snapshots from the registry."""
    async with AsyncSessionLocal() as session:
        device = (await session.execute(
            select(Device).where(Device.name == name)
        )).scalar_one_or_none()
        if not device:
            raise HTTPException(404, f"Device '{name}' not found")
        await session.delete(device)
        await session.commit()
