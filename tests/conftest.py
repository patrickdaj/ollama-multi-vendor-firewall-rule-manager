"""Shared fixtures for all tests.

Connector tests use mock connectors — no live devices needed.
RAG tests use an in-memory ChromaDB instance.
MCP / prompt tests use an ephemeral vectorstore pre-loaded with all four
enterprise sample configs (no live Ollama unless marked @pytest.mark.llm).
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

SAMPLES_DIR = Path(__file__).parent.parent / "data" / "configs" / "samples"

# ── LLM client cache invalidation ────────────────────────────────────────────
# ChatOllama holds an httpx async client whose connection pool is bound to the
# event loop that first used it.  pytest-asyncio creates a new event loop per
# test function, so the cached client from the previous test becomes invalid.
# Clearing the cache before each LLM-marked test forces a fresh client.


@pytest.fixture(autouse=True)
def _reset_llm_cache(request):
    if request.node.get_closest_marker("llm"):
        from src.llm.factory import invalidate_cache
        invalidate_cache()


# ── pytest markers ────────────────────────────────────────────────────────────


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "llm: requires a running Ollama instance (skipped in CI by default)",
    )

from src.firewall.models import (
    AddressObject,
    AddressType,
    FirewallPolicy,
    FirewallRule,
    NATRule,
    NATType,
    RuleAction,
    SecurityProfile,
    ServiceObject,
)


# ── Sample policy data ────────────────────────────────────────────────────────


@pytest.fixture
def sample_rules() -> list[FirewallRule]:
    return [
        FirewallRule(
            name="allow-web-out",
            action=RuleAction.ALLOW,
            src_zones=["trust"],
            dst_zones=["untrust"],
            src_addresses=["10.0.0.0/8"],
            dst_addresses=["any"],
            services=["HTTP", "HTTPS"],
            applications=["web-browsing", "ssl"],
            log=True,
            vendor="paloalto",
            device="pa-fw01",
            position=0,
        ),
        FirewallRule(
            name="allow-any-any",
            action=RuleAction.ALLOW,
            src_zones=["any"],
            dst_zones=["any"],
            src_addresses=["any"],
            dst_addresses=["any"],
            services=["any"],
            vendor="paloalto",
            device="pa-fw01",
            position=1,
        ),
        FirewallRule(
            name="block-smb",
            action=RuleAction.DENY,
            src_zones=["untrust"],
            dst_zones=["trust"],
            src_addresses=["any"],
            dst_addresses=["any"],
            services=["SMB"],
            vendor="paloalto",
            device="pa-fw01",
            position=2,
            description="Block inbound SMB — this is shadowed by allow-any-any above",
        ),
        FirewallRule(
            name="deny-all",
            action=RuleAction.DENY,
            src_zones=["any"],
            dst_zones=["any"],
            src_addresses=["any"],
            dst_addresses=["any"],
            services=["any"],
            vendor="fortinet",
            device="fg-fw01",
            position=0,
        ),
    ]


@pytest.fixture
def sample_nat_rules() -> list[NATRule]:
    return [
        NATRule(
            name="outbound-pat",
            nat_type=NATType.PAT,
            src_zones=["trust"],
            dst_zones=["untrust"],
            src_addresses=["10.0.0.0/8"],
            dst_addresses=["any"],
            translated_src="203.0.113.1",
            vendor="paloalto",
            device="pa-fw01",
            position=0,
        ),
        NATRule(
            name="webserver-dnat",
            nat_type=NATType.DNAT,
            dst_zones=["untrust"],
            dst_addresses=["203.0.113.10"],
            translated_dst="192.168.10.50",
            translated_port="443",
            services=["HTTPS"],
            vendor="paloalto",
            device="pa-fw01",
            position=1,
        ),
        NATRule(
            name="vip-web-forti",
            nat_type=NATType.DNAT,
            dst_addresses=["198.51.100.5"],
            translated_dst="10.10.10.100",
            translated_port="80",
            vendor="fortinet",
            device="fg-fw01",
            rulebase="vip",
            position=0,
        ),
    ]


@pytest.fixture
def sample_addresses() -> list[AddressObject]:
    return [
        AddressObject(name="web-server-01", type=AddressType.HOST, value="10.0.1.100",
                      description="Primary web server"),
        AddressObject(name="web-proxy", type=AddressType.HOST, value="10.0.1.100",
                      description="Web proxy — DUPLICATE of web-server-01"),
        AddressObject(name="internal-net", type=AddressType.NETWORK, value="10.0.0.0/8"),
        AddressObject(name="dmz-servers", type=AddressType.RANGE, value="192.168.10.1-192.168.10.50"),
        AddressObject(name="web-group", type=AddressType.GROUP,
                      members=["web-server-01", "web-proxy"]),
    ]


@pytest.fixture
def sample_services() -> list[ServiceObject]:
    return [
        ServiceObject(name="custom-https", protocol="tcp", port="8443"),
        ServiceObject(name="syslog-udp", protocol="udp", port="514"),
    ]


@pytest.fixture
def sample_profiles() -> list[SecurityProfile]:
    return [
        SecurityProfile(name="strict-av", profile_type="antivirus", vendor="paloalto", device="pa-fw01"),
        SecurityProfile(name="default-ips", profile_type="ips", vendor="fortinet", device="fg-fw01"),
    ]


@pytest.fixture
def paloalto_policy(sample_rules, sample_nat_rules, sample_addresses, sample_services, sample_profiles) -> FirewallPolicy:
    return FirewallPolicy(
        vendor="paloalto",
        device="pa-fw01",
        rules=[r for r in sample_rules if r.device == "pa-fw01"],
        nat_rules=[r for r in sample_nat_rules if r.device == "pa-fw01"],
        address_objects=sample_addresses,
        service_objects=sample_services,
        security_profiles=[p for p in sample_profiles if p.device == "pa-fw01"],
    )


@pytest.fixture
def fortinet_policy(sample_rules, sample_nat_rules, sample_profiles) -> FirewallPolicy:
    return FirewallPolicy(
        vendor="fortinet",
        device="fg-fw01",
        rules=[r for r in sample_rules if r.device == "fg-fw01"],
        nat_rules=[r for r in sample_nat_rules if r.device == "fg-fw01"],
        address_objects=[],
        service_objects=[],
        security_profiles=[p for p in sample_profiles if p.device == "fg-fw01"],
    )


# ── Mock connector ────────────────────────────────────────────────────────────


class MockConnector:
    """A connector that returns fixture data without any network calls."""

    def __init__(self, policy: FirewallPolicy) -> None:
        self._policy = policy

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass

    async def get_policy(self) -> FirewallPolicy:
        return self._policy

    async def get_rules(self, rulebase: str = "security") -> list[FirewallRule]:
        return self._policy.rules

    async def get_nat_rules(self) -> list[NATRule]:
        return self._policy.nat_rules

    async def get_address_objects(self) -> list[AddressObject]:
        return self._policy.address_objects

    async def get_service_objects(self) -> list[ServiceObject]:
        return self._policy.service_objects


# ── In-memory ChromaDB fixture ────────────────────────────────────────────────


@pytest.fixture
def in_memory_vectorstore(monkeypatch):
    """Patch get_vectorstore to return an ephemeral in-memory Chroma instance."""
    import chromadb
    from langchain_chroma import Chroma
    from langchain_core.embeddings import FakeEmbeddings

    client = chromadb.EphemeralClient()
    store = Chroma(
        client=client,
        collection_name="test_collection",
        embedding_function=FakeEmbeddings(size=768),
    )
    monkeypatch.setattr("src.rag.vectorstore.get_vectorstore", lambda: store)
    monkeypatch.setattr("src.rag.loader.get_vectorstore", lambda: store)
    monkeypatch.setattr("src.mcp.server.get_vectorstore", lambda: store)
    return store


@pytest.fixture
def enterprise_vectorstore(monkeypatch):
    """Ephemeral vectorstore pre-loaded with all four enterprise sample configs.

    Uses FakeEmbeddings so no Ollama is required. Metadata-based filtering
    works normally; semantic ranking is not meaningful with fake embeddings.
    """
    import chromadb
    from langchain_chroma import Chroma
    from langchain_core.embeddings import FakeEmbeddings

    from src.firewall.loaders import load_from_file
    from src.rag.loader import ingest_policy

    client = chromadb.EphemeralClient()
    store = Chroma(
        client=client,
        collection_name="test_enterprise",
        embedding_function=FakeEmbeddings(size=768),
    )

    monkeypatch.setattr("src.rag.loader.get_vectorstore", lambda: store)
    monkeypatch.setattr("src.mcp.server.get_vectorstore", lambda: store)

    configs = [
        ("paloalto_enterprise.xml",  "paloalto",  "pa-fw01"),
        ("fortinet_enterprise.json", "fortinet",  "fg-fw01"),
        ("cisco_asa_enterprise.txt", "cisco_asa", "asa-fw01"),
        ("cisco_ftd_enterprise.json","cisco_ftd",  "ftd-fw01"),
    ]
    for filename, vendor, device in configs:
        policy = load_from_file(SAMPLES_DIR / filename, vendor, device)
        ingest_policy(policy)

    return store


@pytest.fixture
def mock_chain(monkeypatch):
    """Replace build_rag_chain with a mock that returns a fixed string.

    Use this for MCP analysis/translation tool tests that would otherwise
    require a running LLM.
    """
    chain = MagicMock()
    chain.invoke.return_value = "Mock analysis: no issues found."
    monkeypatch.setattr("src.mcp.server.build_rag_chain", lambda: chain)
    return chain
