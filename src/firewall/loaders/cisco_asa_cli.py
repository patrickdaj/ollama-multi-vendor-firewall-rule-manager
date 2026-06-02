"""Parse Cisco ASA CLI config text into a FirewallPolicy."""
from __future__ import annotations

import re
from pathlib import Path

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

_OBJ_NET = re.compile(
    r"^object network (\S+)\s*\n(?:\s+description ([^\n]+)\n)?"
    r"\s+(?:host (\S+)|subnet (\S+) (\S+)|range (\S+) (\S+))",
    re.MULTILINE,
)
_OBJ_GRP_NET = re.compile(
    r"^object-group network (\S+)\s*\n((?:\s+(?:network-object|description)[^\n]+\n)*)",
    re.MULTILINE,
)
_OBJ_SVC = re.compile(
    r"^object service (\S+)\s*\n\s+service (tcp|udp) destination eq (\S+)",
    re.MULTILINE,
)
_ACL_LINE = re.compile(
    r"^access-list (\S+) extended (permit|deny)\s+(tcp|udp|ip|icmp)\s+"
    r"(object-group \S+|object \S+|any|host \S+|\S+ \S+)\s+"
    r"(object-group \S+|object \S+|any|host \S+|\S+ \S+)"
    r"(?:\s+(?:eq|gt|lt|neq) (\S+))?",
    re.MULTILINE | re.IGNORECASE,
)
_OBJECT_NAT_STATIC = re.compile(
    r"nat \((\S+),(\S+)\) static (\S+)(?: service tcp (\S+) (\S+))?",
    re.MULTILINE | re.IGNORECASE,
)
_DYNAMIC_NAT = re.compile(
    r"nat \((\S+),(\S+)\) source dynamic (\S+) (\S+)",
    re.MULTILINE | re.IGNORECASE,
)


def _cidr_from_mask(ip: str, mask: str) -> str:
    """Convert dotted-decimal mask to prefix length."""
    bits = sum(bin(int(x)).count("1") for x in mask.split("."))
    return f"{ip}/{bits}"


def load_cisco_asa_cli(path: Path, device: str) -> FirewallPolicy:
    text = path.read_text()

    # ── Address objects ────────────────────────────────────────────────────
    address_objects: list[AddressObject] = []
    for m in _OBJ_NET.finditer(text):
        name, desc = m.group(1), m.group(2) or ""
        if m.group(3):
            address_objects.append(AddressObject(name=name, type=AddressType.HOST,
                                                  value=m.group(3), description=desc))
        elif m.group(4):
            address_objects.append(AddressObject(name=name, type=AddressType.NETWORK,
                                                  value=_cidr_from_mask(m.group(4), m.group(5)), description=desc))
        elif m.group(6):
            address_objects.append(AddressObject(name=name, type=AddressType.RANGE,
                                                  value=f"{m.group(6)}-{m.group(7)}", description=desc))

    for m in _OBJ_GRP_NET.finditer(text):
        grp_name = m.group(1)
        members = re.findall(r"network-object object (\S+)", m.group(2))
        if members:
            address_objects.append(AddressObject(name=grp_name, type=AddressType.GROUP,
                                                  members=members))

    # ── Service objects ────────────────────────────────────────────────────
    service_objects: list[ServiceObject] = []
    for m in _OBJ_SVC.finditer(text):
        service_objects.append(ServiceObject(
            name=m.group(1), protocol=m.group(2), port=m.group(3),
        ))

    # ── NAT rules ─────────────────────────────────────────────────────────
    nat_rules: list[NATRule] = []

    for i, m in enumerate(_DYNAMIC_NAT.finditer(text)):
        nat_rules.append(NATRule(
            name=f"pat-outbound-{i}",
            nat_type=NATType.PAT,
            src_zones=[m.group(1)],
            dst_zones=[m.group(2)],
            src_addresses=[m.group(3)],
            translated_src=m.group(4),
            vendor="cisco_asa", device=device, rulebase="nat", position=i,
        ))

    for i, m in enumerate(_OBJECT_NAT_STATIC.finditer(text)):
        nat_type = NATType.DNAT if m.group(4) else NATType.STATIC
        nat_rules.append(NATRule(
            name=f"static-nat-{i}",
            nat_type=nat_type,
            src_zones=[m.group(1)],
            dst_zones=[m.group(2)],
            translated_dst=m.group(3) if nat_type == NATType.DNAT else "",
            translated_src=m.group(3) if nat_type == NATType.STATIC else "",
            translated_port=m.group(4) or "",
            vendor="cisco_asa", device=device, rulebase="nat",
            position=len(nat_rules),
        ))

    # ── Security rules (from ACLs) ────────────────────────────────────────
    rules: list[FirewallRule] = []
    acl_positions: dict[str, int] = {}

    for m in _ACL_LINE.finditer(text):
        acl_name = m.group(1)
        pos = acl_positions.get(acl_name, 0)
        acl_positions[acl_name] = pos + 1

        action = RuleAction.ALLOW if m.group(2).lower() == "permit" else RuleAction.DENY
        src_raw = m.group(4).strip()
        dst_raw = m.group(5).strip()
        port = m.group(6) or ""
        proto = m.group(3).lower()

        rules.append(FirewallRule(
            name=f"{acl_name}_{pos}",
            action=action,
            src_addresses=[src_raw.replace("object ", "").replace("object-group ", "")],
            dst_addresses=[dst_raw.replace("object ", "").replace("object-group ", "")],
            services=[f"{proto}/{port}" if port else proto],
            log=True,
            vendor="cisco_asa", device=device, rulebase=acl_name, position=pos,
        ))

    return FirewallPolicy(
        vendor="cisco_asa", device=device,
        rules=rules, nat_rules=nat_rules,
        address_objects=address_objects, service_objects=service_objects,
    )
