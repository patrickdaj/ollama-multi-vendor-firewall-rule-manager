"""Cisco ASA SSH/CLI fallback connector for firmware predating REST API support (pre-9.3).

Use this instead of cisco_asa.py by setting vendor="cisco_asa_ssh" in the device config,
or swap the factory entry in vendors/__init__.py.
"""
from __future__ import annotations

import asyncio
import re
from functools import partial

from netmiko import ConnectHandler

from src.config import DeviceConfig
from src.firewall.base import FirewallConnector
from src.firewall.models import (
    AddressObject,
    AddressType,
    FirewallPolicy,
    FirewallRule,
    NATRule,
    NATType,
    RuleAction,
    ServiceObject,
)

_ACL_RE = re.compile(
    r"access-list\s+(?P<acl>\S+)\s+extended\s+(?P<action>permit|deny)\s+"
    r"(?P<proto>\S+)\s+(?P<src>\S+(?:\s+\S+)?)\s+(?P<dst>\S+(?:\s+\S+)?)"
    r"(?:\s+eq\s+(?P<port>\S+))?",
    re.IGNORECASE,
)
_OBJ_NET_RE = re.compile(
    r"object network\s+(?P<name>\S+)\n"
    r"(?:\s+description\s+(?P<desc>[^\n]+)\n)?"
    r"\s+(?:host\s+(?P<host>\S+)|subnet\s+(?P<net>\S+)\s+(?P<mask>\S+)|range\s+(?P<r1>\S+)\s+(?P<r2>\S+))",
    re.MULTILINE,
)
_STATIC_NAT_RE = re.compile(
    r"nat\s+\((?P<real_if>\S+),(?P<mapped_if>\S+)\)\s+static\s+(?P<mapped_ip>\S+)",
    re.IGNORECASE,
)
_PAT_RE = re.compile(
    r"nat\s+\((?P<real_if>\S+),(?P<mapped_if>\S+)\)\s+dynamic\s+(?:pat-pool\s+)?(?P<pool>\S+)",
    re.IGNORECASE,
)


class CiscoASASSHConnector(FirewallConnector):
    """CLI-based fallback for ASA firmware without REST API support."""

    def __init__(self, device: DeviceConfig) -> None:
        super().__init__(device)
        self._conn: ConnectHandler | None = None

    async def connect(self) -> None:
        loop = asyncio.get_event_loop()
        self._conn = await loop.run_in_executor(
            None,
            partial(
                ConnectHandler,
                device_type="cisco_asa",
                host=self.device.host,
                username=self.device.username,
                password=self.device.password,
                port=self.device.port,
                timeout=self.device.timeout,
            ),
        )

    async def disconnect(self) -> None:
        if self._conn:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._conn.disconnect)
            self._conn = None

    async def _cmd(self, command: str) -> str:
        if self._conn is None:
            raise RuntimeError("Not connected")
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, partial(self._conn.send_command, command)
        )

    async def get_rules(self, rulebase: str = "security") -> list[FirewallRule]:
        output = await self._cmd("show running-config access-list")
        rules: list[FirewallRule] = []
        for i, line in enumerate(output.splitlines()):
            m = _ACL_RE.match(line.strip())
            if not m:
                continue
            rules.append(FirewallRule(
                name=f"{m.group('acl')}_{i}",
                action=RuleAction.ALLOW if m.group("action").lower() == "permit" else RuleAction.DENY,
                src_addresses=[m.group("src").split()[0]],
                dst_addresses=[m.group("dst").split()[0]],
                services=[f"{m.group('proto')}/{m.group('port') or 'any'}"],
                vendor="cisco_asa",
                device=self.device.name,
                rulebase=m.group("acl"),
                position=i,
            ))
        return rules

    async def get_nat_rules(self) -> list[NATRule]:
        output = await self._cmd("show running-config nat")
        nat_rules: list[NATRule] = []

        for i, m in enumerate(_STATIC_NAT_RE.finditer(output)):
            nat_rules.append(NATRule(
                name=f"static-nat-{i}",
                nat_type=NATType.STATIC,
                src_zones=[m.group("real_if")],
                dst_zones=[m.group("mapped_if")],
                translated_src=m.group("mapped_ip"),
                vendor="cisco_asa",
                device=self.device.name,
                rulebase="nat",
                position=i,
            ))

        offset = len(nat_rules)
        for i, m in enumerate(_PAT_RE.finditer(output)):
            nat_rules.append(NATRule(
                name=f"pat-nat-{i}",
                nat_type=NATType.PAT,
                src_zones=[m.group("real_if")],
                dst_zones=[m.group("mapped_if")],
                translated_src=m.group("pool"),
                vendor="cisco_asa",
                device=self.device.name,
                rulebase="nat",
                position=offset + i,
            ))

        return nat_rules

    async def get_address_objects(self) -> list[AddressObject]:
        output = await self._cmd("show running-config object network")
        objects: list[AddressObject] = []
        for m in _OBJ_NET_RE.finditer(output):
            name = m.group("name")
            desc = m.group("desc") or ""
            if m.group("host"):
                objects.append(AddressObject(name=name, type=AddressType.HOST,
                                             value=m.group("host"), description=desc))
            elif m.group("net"):
                objects.append(AddressObject(name=name, type=AddressType.NETWORK,
                                             value=f"{m.group('net')}/{m.group('mask')}", description=desc))
            elif m.group("r1"):
                objects.append(AddressObject(name=name, type=AddressType.RANGE,
                                             value=f"{m.group('r1')}-{m.group('r2')}", description=desc))
        return objects

    async def get_service_objects(self) -> list[ServiceObject]:
        output = await self._cmd("show running-config object service")
        pattern = re.compile(
            r"object service\s+(?P<name>\S+).*?service\s+(?P<proto>\S+).*?(?:destination\s+eq\s+(?P<port>\S+))?",
            re.DOTALL,
        )
        return [
            ServiceObject(name=m.group("name"), protocol=m.group("proto"), port=m.group("port") or "")
            for m in pattern.finditer(output)
        ]

    async def get_policy(self) -> FirewallPolicy:
        rules, nat_rules, addresses, services = await asyncio.gather(
            self.get_rules(),
            self.get_nat_rules(),
            self.get_address_objects(),
            self.get_service_objects(),
        )
        return FirewallPolicy(
            vendor="cisco_asa",
            device=self.device.name,
            rules=rules,
            nat_rules=nat_rules,
            address_objects=addresses,
            service_objects=services,
        )
