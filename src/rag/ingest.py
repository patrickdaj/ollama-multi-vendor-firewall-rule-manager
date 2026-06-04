"""Ingest pipeline — two distinct stages, always in this order:

  1. sync_to_postgres(policy)   — saves to Postgres (source of truth)
  2. index_to_chroma(policy)    — builds ChromaDB from the saved SOT data

Call onboard_device() to run both for initial device onboarding.
Call reindex_from_snapshot() to rebuild ChromaDB from an existing Postgres
snapshot without hitting the live device again.

ChromaDB is always a *derived* index of what is in Postgres.
It is never the primary record and can be fully rebuilt at any time.
"""
from __future__ import annotations

import json
import logging

from langchain_core.documents import Document

from src.db.models import PolicyObject, Snapshot
from src.db.repository import get_latest_snapshot, save_snapshot
from src.db.session import AsyncSessionLocal
from src.firewall.models import FirewallPolicy
from src.rag.loader import ingest_policy
from sqlalchemy import select

logger = logging.getLogger(__name__)


# ── Stage 1: device → Postgres (SOT) ─────────────────────────────────────────

async def sync_to_postgres(
    policy: FirewallPolicy,
    triggered_by: str = "manual",
) -> Snapshot:
    """Save a full policy snapshot to Postgres.

    This is the source-of-truth write. Returns the completed Snapshot row.
    Does NOT touch ChromaDB.
    """
    async with AsyncSessionLocal() as session:
        snapshot = await save_snapshot(session, policy, triggered_by=triggered_by)
    logger.info(
        "Postgres SOT updated: device=%s snapshot_id=%d objects=%d",
        policy.device, snapshot.id, snapshot.object_count,
    )
    return snapshot


# ── Stage 2: Postgres snapshot → ChromaDB ────────────────────────────────────

async def index_to_chroma(snapshot_id: int) -> int:
    """Build ChromaDB index from an existing Postgres snapshot.

    Reads the JSONB objects stored in Postgres and reconstructs Documents
    for the vector store. ChromaDB is fully rebuildable this way.
    """
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PolicyObject, Snapshot)
            .join(Snapshot, PolicyObject.snapshot_id == Snapshot.id)
            .where(PolicyObject.snapshot_id == snapshot_id)
        )
        rows = result.all()

    if not rows:
        logger.warning("No objects found for snapshot_id=%d", snapshot_id)
        return 0

    from src.rag.loader import (
        _doc, _id,
        _rule_docs, _nat_docs, _decrypt_docs, _dos_docs, _auth_docs,
        _address_docs, _service_docs, _app_docs, _profile_docs,
        _edl_docs, _zone_docs,
    )
    from src.rag.vectorstore import get_vectorstore
    from langchain_text_splitters import RecursiveCharacterTextSplitter

    # Rebuild a minimal FirewallPolicy from the stored JSONB, then use the
    # existing document builders so formatting stays consistent.
    from src.firewall.models import (
        FirewallPolicy, FirewallRule, NATRule, DecryptionRule, DoSPolicy,
        AuthPolicy, AddressObject, ServiceObject, ServiceGroup, ApplicationObject,
        ApplicationGroup, URLCategory, SecurityProfile, DecryptionProfile,
        EDL, ZoneDefinition,
    )

    snapshot = rows[0][1]
    device = snapshot.device_id  # we only need name + vendor from first row
    first_obj = rows[0][0]

    # Group objects by type
    by_type: dict[str, list[dict]] = {}
    for obj, _ in rows:
        by_type.setdefault(obj.object_type, []).append(obj.data)

    _MODEL_MAP = {
        "security_rule": FirewallRule,
        "nat_rule": NATRule,
        "decryption_rule": DecryptionRule,
        "dos_policy": DoSPolicy,
        "auth_policy": AuthPolicy,
        "address_object": AddressObject,
        "service_object": ServiceObject,
        "service_group": ServiceGroup,
        "application": ApplicationObject,
        "app_group": ApplicationGroup,
        "url_category": URLCategory,
        "security_profile": SecurityProfile,
        "decryption_profile": DecryptionProfile,
        "edl": EDL,
        "zone": ZoneDefinition,
    }

    async with AsyncSessionLocal() as session:
        from src.db.models import Device as DeviceModel
        dev_row = await session.get(DeviceModel, first_obj.device_id)

    policy = FirewallPolicy(device=dev_row.name, vendor=dev_row.vendor)
    for obj_type, model_class in _MODEL_MAP.items():
        for data in by_type.get(obj_type, []):
            try:
                obj = model_class(**data)
                _ATTR_MAP = {
                    "security_rule": "rules",
                    "nat_rule": "nat_rules",
                    "decryption_rule": "decryption_rules",
                    "dos_policy": "dos_policies",
                    "auth_policy": "auth_policies",
                    "address_object": "address_objects",
                    "service_object": "service_objects",
                    "service_group": "service_groups",
                    "application": "application_objects",
                    "app_group": "application_groups",
                    "url_category": "url_categories",
                    "security_profile": "security_profiles",
                    "decryption_profile": "decryption_profiles",
                    "edl": "edls",
                    "zone": "zones",
                }
                getattr(policy, _ATTR_MAP[obj_type]).append(obj)
            except Exception as e:
                logger.debug("Skipping %s object during reindex: %s", obj_type, e)

    count = ingest_policy(policy)
    logger.info(
        "ChromaDB indexed from Postgres snapshot_id=%d: %d documents",
        snapshot_id, count,
    )
    return count


# ── Combined: onboard a device for the first time ────────────────────────────

async def onboard_device(
    policy: FirewallPolicy,
    triggered_by: str = "onboard",
) -> dict:
    """Initial device onboarding: Postgres SOT first, then ChromaDB index.

    This is the only path that writes to Postgres from a live device pull.
    After onboarding, policy changes flow through Postgres → ChromaDB,
    not device → Postgres.
    """
    snapshot = await sync_to_postgres(policy, triggered_by=triggered_by)
    chroma_count = await index_to_chroma(snapshot.id)
    return {
        "snapshot_id": snapshot.id,
        "object_count": snapshot.object_count,
        "chroma_documents": chroma_count,
    }


# ── Rebuild ChromaDB from latest Postgres snapshot ───────────────────────────

async def reindex_device(device_name: str) -> dict:
    """Rebuild ChromaDB for a device from its latest Postgres snapshot.

    Use this to recover ChromaDB or apply SOT changes without hitting the
    live device.
    """
    async with AsyncSessionLocal() as session:
        snapshot = await get_latest_snapshot(session, device_name)
    if not snapshot:
        raise ValueError(f"No completed snapshot found for device '{device_name}'")

    chroma_count = await index_to_chroma(snapshot.id)
    return {"snapshot_id": snapshot.id, "chroma_documents": chroma_count}
