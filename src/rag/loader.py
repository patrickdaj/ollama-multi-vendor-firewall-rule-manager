"""Ingest firewall policy data into the vector store.

Every policy object type gets its own document with structured metadata
so that search results can be filtered by type, vendor, device, etc.

Document types:
  security_rule     nat_rule       decryption_rule   dos_policy     auth_policy
  address_object    service_object application       app_group      url_category
  security_profile  decryption_profile  edl          zone
"""
from __future__ import annotations

import hashlib
import logging

from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

from src.firewall.models import FirewallPolicy
from src.rag.vectorstore import get_vectorstore

logger = logging.getLogger(__name__)

_splitter = RecursiveCharacterTextSplitter(
    chunk_size=800,
    chunk_overlap=100,
    separators=["\n\n", "\n", ". ", " "],
)


def _id(*parts: str) -> str:
    return hashlib.md5(":".join(parts).encode()).hexdigest()


def _doc(content: str, meta: dict) -> Document:
    return Document(page_content=content, metadata=meta)


# ── Document builders ──────────────────────────────────────────────────────────


def _rule_docs(policy: FirewallPolicy) -> list[Document]:
    docs = []
    for r in policy.rules:
        docs.append(_doc(r.to_text(), {
            "type": "security_rule", "rule_name": r.name,
            "device": policy.device, "vendor": policy.vendor,
            "rulebase": r.rulebase, "action": str(r.action),
            "enabled": str(r.enabled),
            "doc_id": _id(policy.device, "rule", r.name),
        }))
    return docs


def _nat_docs(policy: FirewallPolicy) -> list[Document]:
    docs = []
    for r in policy.nat_rules:
        docs.append(_doc(r.to_text(), {
            "type": "nat_rule", "rule_name": r.name,
            "nat_type": str(r.nat_type),
            "device": policy.device, "vendor": policy.vendor,
            "rulebase": r.rulebase, "enabled": str(r.enabled),
            "doc_id": _id(policy.device, "nat", r.name),
        }))
    return docs


def _decrypt_docs(policy: FirewallPolicy) -> list[Document]:
    docs = []
    for r in policy.decryption_rules:
        docs.append(_doc(r.to_text(), {
            "type": "decryption_rule", "rule_name": r.name,
            "device": policy.device, "vendor": policy.vendor,
            "decrypt_type": str(r.decrypt_type), "action": str(r.action),
            "enabled": str(r.enabled),
            "doc_id": _id(policy.device, "decrypt", r.name),
        }))
    return docs


def _dos_docs(policy: FirewallPolicy) -> list[Document]:
    docs = []
    for r in policy.dos_policies:
        docs.append(_doc(r.to_text(), {
            "type": "dos_policy", "rule_name": r.name,
            "device": policy.device, "vendor": policy.vendor,
            "enabled": str(r.enabled),
            "doc_id": _id(policy.device, "dos", r.name),
        }))
    return docs


def _auth_docs(policy: FirewallPolicy) -> list[Document]:
    docs = []
    for r in policy.auth_policies:
        docs.append(_doc(r.to_text(), {
            "type": "auth_policy", "rule_name": r.name,
            "device": policy.device, "vendor": policy.vendor,
            "doc_id": _id(policy.device, "auth", r.name),
        }))
    return docs


def _address_docs(policy: FirewallPolicy) -> list[Document]:
    docs = []
    for a in policy.address_objects:
        docs.append(_doc(a.to_text(), {
            "type": "address_object", "name": a.name,
            "addr_type": str(a.type),
            "device": policy.device, "vendor": policy.vendor,
            "doc_id": _id(policy.device, "addr", a.name),
        }))
    return docs


def _service_docs(policy: FirewallPolicy) -> list[Document]:
    docs = []
    for s in policy.service_objects:
        docs.append(_doc(s.to_text(), {
            "type": "service_object", "name": s.name,
            "device": policy.device, "vendor": policy.vendor,
            "doc_id": _id(policy.device, "svc", s.name),
        }))
    return docs


def _app_docs(policy: FirewallPolicy) -> list[Document]:
    docs = []
    for a in policy.application_objects:
        docs.append(_doc(a.to_text(), {
            "type": "application", "name": a.name,
            "category": a.category, "risk": str(a.risk),
            "is_custom": str(a.is_custom),
            "device": policy.device, "vendor": policy.vendor,
            "doc_id": _id(policy.device, "app", a.name),
        }))
    for g in policy.application_groups:
        docs.append(_doc(g.to_text(), {
            "type": "app_group", "name": g.name,
            "is_filter": str(g.is_filter),
            "device": policy.device, "vendor": policy.vendor,
            "doc_id": _id(policy.device, "appgrp", g.name),
        }))
    for c in policy.url_categories:
        docs.append(_doc(c.to_text(), {
            "type": "url_category", "name": c.name,
            "device": policy.device, "vendor": policy.vendor,
            "doc_id": _id(policy.device, "urlcat", c.name),
        }))
    return docs


def _profile_docs(policy: FirewallPolicy) -> list[Document]:
    docs = []
    for p in policy.security_profiles:
        docs.append(_doc(p.to_text(), {
            "type": "security_profile", "name": p.name,
            "profile_type": p.profile_type,
            "device": policy.device, "vendor": policy.vendor,
            "doc_id": _id(policy.device, "profile", p.name),
        }))
    for p in policy.decryption_profiles:
        docs.append(_doc(p.to_text(), {
            "type": "decryption_profile", "name": p.name,
            "device": policy.device, "vendor": policy.vendor,
            "doc_id": _id(policy.device, "dprofile", p.name),
        }))
    return docs


def _edl_docs(policy: FirewallPolicy) -> list[Document]:
    docs = []
    for e in policy.edls:
        docs.append(_doc(e.to_text(), {
            "type": "edl", "name": e.name,
            "edl_type": str(e.edl_type),
            "is_predefined": str(e.is_predefined),
            "device": policy.device, "vendor": policy.vendor,
            "doc_id": _id(policy.device, "edl", e.name),
        }))
    return docs


def _zone_docs(policy: FirewallPolicy) -> list[Document]:
    docs = []
    for z in policy.zones:
        docs.append(_doc(z.to_text(), {
            "type": "zone", "name": z.name,
            "zone_type": z.zone_type,
            "device": policy.device, "vendor": policy.vendor,
            "doc_id": _id(policy.device, "zone", z.name),
        }))
    return docs


# ── Public API ────────────────────────────────────────────────────────────────


def ingest_policy(policy: FirewallPolicy) -> int:
    """Embed and store the complete policy snapshot. Returns document count.

    Idempotent — documents are keyed by stable hash(device+type+name),
    so re-ingesting after a policy change updates existing entries.
    """
    all_docs: list[Document] = []
    all_docs.extend(_rule_docs(policy))
    all_docs.extend(_nat_docs(policy))
    all_docs.extend(_decrypt_docs(policy))
    all_docs.extend(_dos_docs(policy))
    all_docs.extend(_auth_docs(policy))
    all_docs.extend(_address_docs(policy))
    all_docs.extend(_service_docs(policy))
    all_docs.extend(_app_docs(policy))
    all_docs.extend(_profile_docs(policy))
    all_docs.extend(_edl_docs(policy))
    all_docs.extend(_zone_docs(policy))

    if not all_docs:
        logger.warning("No documents to ingest from %s", policy.device)
        return 0

    split_docs = _splitter.split_documents(all_docs)
    ids = [d.metadata["doc_id"] for d in split_docs]

    get_vectorstore().add_documents(split_docs, ids=ids)
    logger.info(policy.summary() + f" → {len(split_docs)} documents ingested")
    return len(split_docs)


def ingest_raw_text(text: str, metadata: dict | None = None) -> int:
    """Ingest a raw config file or text blob.

    Use for bootstrapping from exported configs before live device access.
    The preferred workflow is always: live device → connector.get_policy() → ingest_policy().
    """
    doc = Document(page_content=text, metadata=metadata or {})
    chunks = _splitter.split_documents([doc])
    get_vectorstore().add_documents(chunks)
    logger.info("Ingested %d chunks from raw text (%s)", len(chunks), metadata)
    return len(chunks)
