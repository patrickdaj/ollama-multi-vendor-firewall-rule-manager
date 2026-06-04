"""Tests for the AI dock agent tool functions.

Each agent tool is called directly (not through the LangChain agent executor).
The database is mocked with AsyncMock so no Postgres is required.
The vectorstore is mocked for search_policy tests.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.chat.agent import (
    add_device,
    assign_device,
    create_group,
    list_devices,
    list_groups,
    search_policy,
)


# ── DB session mock helpers ───────────────────────────────────────────────────


def _mock_session(scalar_result=None, scalars_result=None):
    """Build a minimal async SQLAlchemy session mock."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = scalar_result
    result.scalars.return_value.all.return_value = scalars_result or []

    session = AsyncMock()
    session.execute.return_value = result
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.add = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)
    return session


def _parse(result: str) -> dict:
    return json.loads(result)


# ── add_device ────────────────────────────────────────────────────────────────


class TestAddDevice:
    async def test_add_new_device_succeeds(self):
        session = _mock_session(scalar_result=None)  # device doesn't exist yet
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session):
            result = _parse(await add_device.ainvoke({
                "name": "test-pa", "vendor": "paloalto", "host": "10.0.0.1",
            }))
        assert result["status"] == "ok"
        assert "test-pa" in result["message"]
        assert "devices" in result["invalidate"]

    async def test_duplicate_device_returns_error(self):
        from src.db.models import Device
        existing = MagicMock(spec=Device)
        existing.name = "existing-fw"
        session = _mock_session(scalar_result=existing)  # device already exists
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session):
            result = _parse(await add_device.ainvoke({
                "name": "existing-fw", "vendor": "fortinet", "host": "10.0.0.2",
            }))
        assert result["status"] == "error"
        assert "already exists" in result["message"]

    async def test_vendor_in_success_message(self):
        session = _mock_session(scalar_result=None)
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session):
            result = _parse(await add_device.ainvoke({
                "name": "ftd-test", "vendor": "cisco_ftd", "host": "192.168.1.1",
            }))
        assert result["status"] == "ok"
        assert "cisco_ftd" in result["message"]

    async def test_credentials_encrypted_when_provided(self):
        session = _mock_session(scalar_result=None)
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session), \
             patch("src.security.credentials.encrypt_credentials", return_value="enc-blob") as enc:
            await add_device.ainvoke({
                "name": "secure-fw", "vendor": "paloalto", "host": "10.0.0.3",
                "username": "admin", "password": "secret",
            })
            enc.assert_called_once()


# ── list_devices ──────────────────────────────────────────────────────────────


class TestListDevices:
    async def test_empty_returns_no_devices_message(self):
        session = _mock_session(scalars_result=[])
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session):
            result = await list_devices.ainvoke({})
        assert "No devices" in result

    async def test_lists_devices(self):
        from src.db.models import Device
        dev = MagicMock(spec=Device)
        dev.name = "pa-edge"
        dev.vendor = "paloalto"
        dev.host = "10.1.1.1"
        dev.device_group_id = None
        dev.last_synced_at = None
        session = _mock_session(scalars_result=[dev])
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session):
            result = await list_devices.ainvoke({})
        assert "pa-edge" in result
        assert "paloalto" in result
        assert "10.1.1.1" in result

    async def test_vendor_filter_passed(self):
        session = _mock_session(scalars_result=[])
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session):
            result = await list_devices.ainvoke({"vendor": "fortinet"})
        assert "No fortinet devices" in result or "No devices" in result


# ── create_group ──────────────────────────────────────────────────────────────


class TestCreateGroup:
    async def test_creates_root_group(self):
        session = _mock_session()
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session):
            result = _parse(await create_group.ainvoke({"name": "DC-East"}))
        assert result["status"] == "ok"
        assert "DC-East" in result["message"]
        assert "groups" in result["invalidate"]
        assert "groups-tree" in result["invalidate"]

    async def test_creates_child_group(self):
        from src.db.models import DeviceGroup
        parent = MagicMock(spec=DeviceGroup)
        parent.id = 42
        parent.name = "US-East"
        session = _mock_session(scalar_result=parent)
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session):
            result = _parse(await create_group.ainvoke({
                "name": "DC-East", "parent_name": "US-East",
            }))
        assert result["status"] == "ok"
        assert "US-East" in result["message"]

    async def test_parent_not_found_returns_error(self):
        session = _mock_session(scalar_result=None)
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session):
            result = _parse(await create_group.ainvoke({
                "name": "Child", "parent_name": "NonExistentParent",
            }))
        assert result["status"] == "error"
        assert "not found" in result["message"]


# ── list_groups ───────────────────────────────────────────────────────────────


class TestListGroups:
    async def test_empty_returns_no_groups_message(self):
        session = _mock_session(scalars_result=[])
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session):
            result = await list_groups.ainvoke({})
        assert "No groups" in result

    async def test_lists_groups(self):
        from src.db.models import DeviceGroup
        grp = MagicMock(spec=DeviceGroup)
        grp.id = 1
        grp.name = "HQ"
        grp.parent_id = None
        grp.description = "Headquarters"
        grp.devices = []
        grp.children = []
        session = _mock_session(scalars_result=[grp])
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session):
            result = await list_groups.ainvoke({})
        assert "HQ" in result
        assert "Headquarters" in result


# ── assign_device ─────────────────────────────────────────────────────────────


class TestAssignDevice:
    async def _make_session(self, device_name, group_name):
        from src.db.models import Device, DeviceGroup
        dev = MagicMock(spec=Device)
        dev.name = device_name
        dev.device_group_id = None
        grp = MagicMock(spec=DeviceGroup)
        grp.id = 7
        grp.name = group_name

        call_count = 0

        async def fake_execute(query):
            nonlocal call_count
            result = MagicMock()
            call_count += 1
            result.scalar_one_or_none.return_value = dev if call_count == 1 else grp
            return result

        session = AsyncMock()
        session.execute.side_effect = fake_execute
        session.commit = AsyncMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)
        return session

    async def test_assigns_device_to_group(self):
        session = await self._make_session("pa-fw01", "HQ")
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session):
            result = _parse(await assign_device.ainvoke({
                "device_name": "pa-fw01", "group_name": "HQ",
            }))
        assert result["status"] == "ok"
        assert "pa-fw01" in result["message"]
        assert "HQ" in result["message"]
        assert "devices" in result["invalidate"]

    async def test_device_not_found_returns_error(self):
        session = _mock_session(scalar_result=None)  # first execute returns None (device missing)
        with patch("src.chat.agent.AsyncSessionLocal", return_value=session):
            result = _parse(await assign_device.ainvoke({
                "device_name": "ghost-fw", "group_name": "HQ",
            }))
        assert result["status"] == "error"
        assert "not found" in result["message"].lower()


# ── search_policy ─────────────────────────────────────────────────────────────


class TestSearchPolicy:
    async def test_returns_results_from_vectorstore(self, enterprise_vectorstore):
        result = await search_policy.ainvoke({"query": "allow web traffic"})
        assert isinstance(result, str)
        assert len(result) > 10
        assert "No matching" not in result

    async def test_device_filter_applied(self, enterprise_vectorstore):
        result = await search_policy.ainvoke({
            "query": "security rules",
            "device": "pa-fw01",
        })
        assert "pa-fw01" in result

    async def test_vendor_filter_applied(self, enterprise_vectorstore):
        result = await search_policy.ainvoke({
            "query": "outbound allow",
            "vendor": "fortinet",
        })
        assert "fortinet" in result

    async def test_no_results_message(self, enterprise_vectorstore):
        result = await search_policy.ainvoke({
            "query": "quantum firewall rules for IPv9",
            "device": "no-such-device",
        })
        assert "No matching" in result
