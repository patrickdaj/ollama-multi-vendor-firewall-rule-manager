"""Tests for vendor connectors using mock network responses.

Each test class patches the underlying transport (httpx, pan-os-python)
so no live device is needed.  The goal is to verify that each connector
correctly maps vendor-specific API responses to our vendor-agnostic models.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config import DeviceConfig
from src.firewall.models import NATType, RuleAction


def _asa_device() -> DeviceConfig:
    return DeviceConfig(
        name="asa-test",
        vendor="cisco_asa",
        host="10.0.0.1",
        username="admin",
        password="secret",
        verify_ssl=False,
    )


def _ftd_device() -> DeviceConfig:
    return DeviceConfig(
        name="ftd-test",
        vendor="cisco_ftd",
        host="10.0.0.2",
        username="admin",
        password="secret",
        verify_ssl=False,
    )


def _forti_device() -> DeviceConfig:
    return DeviceConfig(
        name="fg-test",
        vendor="fortinet",
        host="10.0.0.3",
        username="admin",
        password="secret",
        verify_ssl=False,
    )


# ── Cisco ASA REST ────────────────────────────────────────────────────────────


class TestCiscoASAConnector:
    @pytest.fixture
    def connector(self):
        from src.firewall.vendors.cisco_asa import CiscoASAConnector
        return CiscoASAConnector(_asa_device())

    @pytest.fixture
    def mock_client(self, connector):
        mock = AsyncMock()
        connector._client = mock
        return mock

    def _make_response(self, items: list[dict]):
        resp = AsyncMock()
        resp.json.return_value = {"items": items}
        resp.raise_for_status = MagicMock()
        return resp

    @pytest.mark.asyncio
    async def test_get_rules_permit(self, connector, mock_client):
        ace = {
            "permit": "permit",
            "aclName": "OUTSIDE_IN",
            "remark": "allow-https",
            "inactive": False,
            "sourceAddress": {"kind": "AnyIPAddress"},
            "destinationAddress": {"value": "10.0.1.0/24"},
            "destinationService": {"protocol": "tcp", "destinationPort": {"value": "443"}},
        }
        mock_client.get.return_value = self._make_response([ace])
        rules = await connector.get_rules()
        assert len(rules) == 1
        assert rules[0].action == RuleAction.ALLOW
        assert rules[0].src_addresses == ["any"]
        assert "10.0.1.0/24" in rules[0].dst_addresses
        assert rules[0].vendor == "cisco_asa"

    @pytest.mark.asyncio
    async def test_get_rules_deny(self, connector, mock_client):
        ace = {
            "permit": "deny",
            "aclName": "OUTSIDE_IN",
            "inactive": False,
            "sourceAddress": {"value": "192.168.0.0/16"},
            "destinationAddress": {"kind": "AnyIPAddress"},
            "destinationService": {},
        }
        mock_client.get.return_value = self._make_response([ace])
        rules = await connector.get_rules()
        assert rules[0].action == RuleAction.DENY

    @pytest.mark.asyncio
    async def test_get_nat_rules(self, connector, mock_client):
        nat_entry = {
            "natType": "static",
            "description": "web-vip",
            "inactive": False,
            "originalSource": {"value": "10.0.1.50"},
            "translatedSource": {"value": "203.0.113.50"},
            "originalDestination": {},
            "translatedDestination": {},
        }
        mock_client.get.return_value = self._make_response([nat_entry])
        nat_rules = await connector.get_nat_rules()
        assert len(nat_rules) >= 1
        assert nat_rules[0].nat_type == NATType.STATIC
        assert nat_rules[0].translated_src == "203.0.113.50"

    @pytest.mark.asyncio
    async def test_get_address_objects(self, connector, mock_client):
        obj = {"name": "web-server", "host": {"value": "10.0.1.100"}}
        mock_client.get.return_value = self._make_response([obj])
        objects = await connector.get_address_objects()
        assert any(o.name == "web-server" and o.value == "10.0.1.100" for o in objects)

    @pytest.mark.asyncio
    async def test_get_policy_structure(self, connector, mock_client):
        mock_client.get.return_value = self._make_response([])
        policy = await connector.get_policy()
        assert policy.vendor == "cisco_asa"
        assert policy.device == "asa-test"
        assert isinstance(policy.rules, list)
        assert isinstance(policy.nat_rules, list)


# ── Cisco FTD ─────────────────────────────────────────────────────────────────


class TestCiscoFTDConnector:
    @pytest.fixture
    def connector(self):
        from src.firewall.vendors.cisco_ftd import CiscoFTDConnector
        c = CiscoFTDConnector(_ftd_device())
        c._token = "fake-token"
        c._domain_uuid = "default"
        return c

    def _make_response(self, items: list[dict], count: int | None = None):
        resp = AsyncMock()
        resp.json.return_value = {
            "items": items,
            "paging": {"count": count or len(items)},
        }
        resp.raise_for_status = MagicMock()
        return resp

    @pytest.mark.asyncio
    async def test_get_rules_maps_action(self, connector):
        acp = {"id": "acp-1", "name": "MainPolicy"}
        rule = {
            "id": "rule-1", "name": "allow-web", "enabled": True,
            "action": "ALLOW",
            "sourceZones": {"objects": [{"name": "inside"}]},
            "destinationZones": {"objects": [{"name": "outside"}]},
            "sourceNetworks": {"objects": []},
            "destinationNetworks": {"objects": []},
            "destinationPorts": {"objects": [{"name": "HTTPS"}]},
            "logEnd": True,
        }
        mock_client = AsyncMock()
        connector._client = mock_client

        call_count = 0
        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:  # ACPs
                r = AsyncMock()
                r.json.return_value = {"items": [acp], "paging": {"count": 1}}
                r.raise_for_status = MagicMock()
                return r
            else:  # rules
                r = AsyncMock()
                r.json.return_value = {"items": [rule], "paging": {"count": 1}}
                r.raise_for_status = MagicMock()
                return r

        mock_client.get.side_effect = side_effect
        rules = await connector.get_rules()
        assert len(rules) == 1
        assert rules[0].action == RuleAction.ALLOW
        assert rules[0].src_zones == ["inside"]
        assert rules[0].vendor == "cisco_ftd"

    @pytest.mark.asyncio
    async def test_get_address_objects(self, connector):
        mock_client = AsyncMock()
        connector._client = mock_client
        net_obj = {"name": "dmz-net", "value": "172.16.1.0/24", "description": "DMZ"}
        grp = {"name": "server-group", "objects": [{"name": "dmz-net"}], "literals": []}

        call_count = 0
        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            r = AsyncMock()
            r.raise_for_status = MagicMock()
            if call_count == 1:
                r.json.return_value = {"items": [net_obj], "paging": {"count": 1}}
            else:
                r.json.return_value = {"items": [grp], "paging": {"count": 1}}
            return r

        mock_client.get.side_effect = side_effect
        objects = await connector.get_address_objects()
        names = [o.name for o in objects]
        assert "dmz-net" in names
        assert "server-group" in names


# ── Fortinet ──────────────────────────────────────────────────────────────────


class TestFortinetConnector:
    @pytest.fixture
    def connector(self):
        from src.firewall.vendors.fortinet import FortinetConnector
        c = FortinetConnector(_forti_device())
        c._client = AsyncMock()
        return c

    def _api_response(self, connector, results: list[dict]):
        resp = AsyncMock()
        resp.json.return_value = {"results": results, "status": "success"}
        resp.raise_for_status = MagicMock()
        connector._client.get.return_value = resp

    @pytest.mark.asyncio
    async def test_get_rules_accept(self, connector):
        self._api_response(connector, [{
            "policyid": 1, "name": "allow-web", "status": "enable",
            "action": "accept",
            "srcintf": [{"name": "internal"}],
            "dstintf": [{"name": "wan1"}],
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "HTTP"}],
            "logtraffic": "all",
            "comments": "",
        }])
        rules = await connector.get_rules()
        assert len(rules) == 1
        assert rules[0].action == RuleAction.ALLOW
        assert rules[0].src_zones == ["internal"]
        assert rules[0].log is True

    @pytest.mark.asyncio
    async def test_get_rules_deny(self, connector):
        self._api_response(connector, [{
            "policyid": 99, "name": "deny-all", "status": "enable",
            "action": "deny",
            "srcintf": [], "dstintf": [], "srcaddr": [], "dstaddr": [],
            "service": [], "logtraffic": "disable", "comments": "",
        }])
        rules = await connector.get_rules()
        assert rules[0].action == RuleAction.DENY

    @pytest.mark.asyncio
    async def test_get_nat_vip(self, connector):
        self._api_response(connector, [{
            "name": "web-vip",
            "extip": "203.0.113.10",
            "mappedip": [{"range": "10.10.10.100"}],
            "mappedport": "8080",
            "protocol": "tcp",
            "status": "enable",
            "comment": "",
        }])
        nat_rules = await connector.get_nat_rules()
        vips = [r for r in nat_rules if r.rulebase == "vip"]
        assert len(vips) == 1
        assert vips[0].nat_type == NATType.DNAT
        assert vips[0].translated_dst == "10.10.10.100"
        assert vips[0].translated_port == "8080"

    @pytest.mark.asyncio
    async def test_get_address_objects(self, connector):
        call_count = 0
        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            r = AsyncMock()
            r.raise_for_status = MagicMock()
            if call_count == 1:  # /cmdb/firewall/address
                r.json.return_value = {"results": [
                    {"name": "web-host", "type": "ipmask", "subnet": "10.0.1.100/32", "comment": ""},
                    {"name": "corp-fqdn", "type": "fqdn", "fqdn": "corp.example.com", "comment": ""},
                ]}
            else:  # /cmdb/firewall/addrgrp
                r.json.return_value = {"results": [
                    {"name": "web-servers", "member": [{"name": "web-host"}], "comment": ""}
                ]}
            return r

        connector._client.get.side_effect = side_effect
        objects = await connector.get_address_objects()
        names = [o.name for o in objects]
        assert "web-host" in names
        assert "corp-fqdn" in names
        assert "web-servers" in names

    @pytest.mark.asyncio
    async def test_get_rules_profiles(self, connector):
        self._api_response(connector, [{
            "policyid": 1, "name": "secure-web", "status": "enable",
            "action": "accept",
            "srcintf": [], "dstintf": [], "srcaddr": [], "dstaddr": [], "service": [],
            "logtraffic": "all",
            "av-profile": "strict-av",
            "ips-sensor": "default-ips",
            "webfilter-profile": "",
            "comments": "",
        }])
        rules = await connector.get_rules()
        assert rules[0].profiles.get("antivirus") == "strict-av"
        assert rules[0].profiles.get("ips") == "default-ips"
        assert "url-filtering" not in rules[0].profiles
