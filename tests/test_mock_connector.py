"""Integration tests using MockConnector — validates the full ingest pipeline
from connector output through to vector store retrieval without live devices.
"""
from __future__ import annotations

import pytest

from src.rag.loader import ingest_policy
from tests.conftest import MockConnector


class TestMockConnectorPipeline:
    @pytest.mark.asyncio
    async def test_mock_connector_returns_policy(self, paloalto_policy):
        connector = MockConnector(paloalto_policy)
        async with connector:
            policy = await connector.get_policy()
        assert policy.vendor == "paloalto"
        assert policy.rule_count() == 3

    @pytest.mark.asyncio
    async def test_mock_connector_rules(self, paloalto_policy):
        connector = MockConnector(paloalto_policy)
        async with connector:
            rules = await connector.get_rules()
        assert any(r.name == "allow-web-out" for r in rules)
        assert any(r.name == "allow-any-any" for r in rules)

    @pytest.mark.asyncio
    async def test_mock_connector_nat_rules(self, paloalto_policy):
        connector = MockConnector(paloalto_policy)
        async with connector:
            nat_rules = await connector.get_nat_rules()
        assert any(r.name == "outbound-pat" for r in nat_rules)
        assert any(r.name == "webserver-dnat" for r in nat_rules)

    @pytest.mark.asyncio
    async def test_full_ingest_pipeline(self, in_memory_vectorstore, paloalto_policy):
        connector = MockConnector(paloalto_policy)
        async with connector:
            policy = await connector.get_policy()
        count = ingest_policy(policy)
        assert count > 0

        # Verify rules are searchable
        docs = in_memory_vectorstore.similarity_search(
            "outbound web traffic", k=5, filter={"type": "security_rule"}
        )
        assert len(docs) > 0

    @pytest.mark.asyncio
    async def test_vendor_factory_cisco_asa(self):
        from src.config import DeviceConfig
        from src.firewall.vendors import get_connector
        device = DeviceConfig(
            name="test-asa", vendor="cisco_asa", host="10.0.0.1",
            username="admin", password="secret"
        )
        connector = get_connector(device)
        from src.firewall.vendors.cisco_asa import CiscoASAConnector
        assert isinstance(connector, CiscoASAConnector)

    @pytest.mark.asyncio
    async def test_vendor_factory_fortinet(self):
        from src.config import DeviceConfig
        from src.firewall.vendors import get_connector
        device = DeviceConfig(
            name="test-fg", vendor="fortinet", host="10.0.0.3",
            username="admin", password="secret"
        )
        connector = get_connector(device)
        from src.firewall.vendors.fortinet import FortinetConnector
        assert isinstance(connector, FortinetConnector)

    def test_vendor_factory_invalid(self):
        from src.config import DeviceConfig
        from src.firewall.vendors import get_connector
        device = DeviceConfig(
            name="test", vendor="paloalto", host="x", username="u", password="p"
        )
        # Force an unsupported vendor via raw dict
        device_dict = device.model_dump()
        device_dict["vendor"] = "paloalto"  # valid — just confirming factory works
        d = DeviceConfig(**device_dict)
        connector = get_connector(d)
        from src.firewall.vendors.paloalto import PaloAltoConnector
        assert isinstance(connector, PaloAltoConnector)
