"""Cisco ASA connector via ASA REST API (requires ASDM 7.3+).

API base: https://<host>/api/
Docs: https://www.cisco.com/c/en/us/td/docs/security/asa/api/

If your ASA firmware predates REST support (pre-9.3), see cisco_asa_ssh.py
for a netmiko/CLI fallback.
"""
from __future__ import annotations

import asyncio
import logging

import httpx

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
    SecurityProfile,
)

logger = logging.getLogger(__name__)

_ACTION_MAP = {"permit": RuleAction.ALLOW, "deny": RuleAction.DENY}
_NAT_TYPE_MAP = {
    "static": NATType.STATIC,
    "dynamic": NATType.DYNAMIC,
    "dynamic-pat": NATType.PAT,
}


class CiscoASAConnector(FirewallConnector):
    """Cisco ASA REST API connector.

    All policy data comes from the REST API, not CLI parsing.
    The API returns JSON; we map it to vendor-agnostic models.
    """

    def __init__(self, device: DeviceConfig) -> None:
        super().__init__(device)
        self._base = f"https://{device.host}/api"
        self._client: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self._base,
            auth=(self.device.username, self.device.password),
            verify=self.device.verify_ssl,
            timeout=self.device.timeout,
            headers={"Content-Type": "application/json", "User-Agent": "fw-rag-manager/0.1"},
        )
        # Verify connectivity
        resp = await self._client.get("/")
        resp.raise_for_status()

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _get_all(self, path: str) -> list[dict]:
        """Paginate through all items (ASA REST uses offset/limit)."""
        if self._client is None:
            raise RuntimeError("Not connected")
        items: list[dict] = []
        offset = 0
        limit = 100
        while True:
            resp = await self._client.get(path, params={"offset": offset, "limit": limit})
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("items", [])
            items.extend(batch)
            if len(batch) < limit:
                break
            offset += limit
        return items

    async def get_rules(self, rulebase: str = "security") -> list[FirewallRule]:
        """Retrieve all extended ACLs and flatten them into rules."""
        # ASA returns ACEs grouped by ACL name
        raw = await self._get_all("/acl/extended")
        rules: list[FirewallRule] = []
        for i, ace in enumerate(raw):
            action = _ACTION_MAP.get(ace.get("permit", "deny"), RuleAction.DENY)
            src = ace.get("sourceAddress", {})
            dst = ace.get("destinationAddress", {})
            svc = ace.get("destinationService", {})
            rules.append(
                FirewallRule(
                    rule_id=ace.get("objectId", ""),
                    name=ace.get("remark") or f"{ace.get('aclName', 'acl')}_{i}",
                    enabled=not ace.get("inactive", False),
                    action=action,
                    src_addresses=[_addr_value(src)],
                    dst_addresses=[_addr_value(dst)],
                    services=[_svc_value(svc)],
                    log=ace.get("logInterval") is not None,
                    vendor="cisco_asa",
                    device=self.device.name,
                    rulebase=ace.get("aclName", rulebase),
                    position=i,
                )
            )
        return rules

    async def get_nat_rules(self) -> list[NATRule]:
        """Retrieve both object NAT and manual NAT rules."""
        nat_rules: list[NATRule] = []

        # Object NAT (auto NAT — tied to a network object)
        object_nat = await self._get_all("/nat/auto")
        for i, r in enumerate(object_nat):
            nat_rules.append(_parse_asa_nat(r, i, "object-nat", self.device.name))

        # Manual NAT (twice NAT — policy-based)
        manual_nat = await self._get_all("/nat/manual")
        for i, r in enumerate(manual_nat):
            nat_rules.append(_parse_asa_nat(r, i, "manual-nat", self.device.name))

        return nat_rules

    async def get_address_objects(self) -> list[AddressObject]:
        objects: list[AddressObject] = []

        # Individual network objects
        raw_objects = await self._get_all("/objects/networkobjects")
        for o in raw_objects:
            host = o.get("host", {})
            net = o.get("network", {})
            rng = o.get("range", {})
            if host:
                objects.append(AddressObject(name=o["name"], type=AddressType.HOST, value=host.get("value", "")))
            elif net:
                objects.append(AddressObject(name=o["name"], type=AddressType.NETWORK,
                                             value=f"{net.get('address', '')}/{net.get('netMask', '')}"))
            elif rng:
                objects.append(AddressObject(name=o["name"], type=AddressType.RANGE,
                                             value=f"{rng.get('fStart', '')}-{rng.get('fEnd', '')}"))

        # Network object groups
        raw_groups = await self._get_all("/objects/networkgroups")
        for g in raw_groups:
            members = [m.get("value", m.get("name", "")) for m in g.get("members", [])]
            objects.append(AddressObject(name=g["name"], type=AddressType.GROUP, members=members,
                                         description=g.get("description", "")))

        return objects

    async def get_service_objects(self) -> list[ServiceObject]:
        raw = await self._get_all("/objects/serviceobjects")
        services: list[ServiceObject] = []
        for s in raw:
            svc = s.get("service", {})
            proto = svc.get("protocol", "tcp").lower()
            port = svc.get("destinationPort", {}).get("value", "")
            services.append(ServiceObject(name=s["name"], protocol=proto, port=port,
                                          description=s.get("description", "")))
        return services

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


# ── Helpers ────────────────────────────────────────────────────────────────


def _addr_value(addr: dict) -> str:
    if not addr:
        return "any"
    if addr.get("kind") == "AnyIPAddress":
        return "any"
    return addr.get("value", addr.get("objectId", "any"))


def _svc_value(svc: dict) -> str:
    if not svc:
        return "any"
    proto = svc.get("protocol", "")
    port = svc.get("destinationPort", {}).get("value", "")
    return f"{proto}/{port}" if port else (proto or "any")


def _parse_asa_nat(r: dict, i: int, rulebase: str, device: str) -> NATRule:
    nat_type_str = r.get("natType", "dynamic-pat")
    nat_type = _NAT_TYPE_MAP.get(nat_type_str, NATType.PAT)

    original_src = r.get("originalSource", {})
    original_dst = r.get("originalDestination", {})
    translated_src = r.get("translatedSource", {})
    translated_dst = r.get("translatedDestination", {})

    return NATRule(
        rule_id=r.get("objectId", ""),
        name=r.get("description") or f"{rulebase}_{i}",
        description=r.get("description", ""),
        enabled=not r.get("inactive", False),
        nat_type=nat_type,
        src_addresses=[_addr_value(original_src)],
        dst_addresses=[_addr_value(original_dst)],
        translated_src=_addr_value(translated_src),
        translated_dst=_addr_value(translated_dst),
        translated_port=r.get("translatedService", {}).get("destinationPort", {}).get("value", ""),
        vendor="cisco_asa",
        device=device,
        rulebase=rulebase,
        position=i,
    )
