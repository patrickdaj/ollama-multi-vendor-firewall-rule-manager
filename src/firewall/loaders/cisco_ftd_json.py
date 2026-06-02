"""Parse Cisco FTD/FMC JSON export into a FirewallPolicy."""
from __future__ import annotations

import json
from pathlib import Path

from src.firewall.models import (
    AddressObject,
    AddressType,
    ApplicationGroup,
    DecryptAction,
    DecryptionProfile,
    DecryptionRule,
    DecryptType,
    EDL,
    EDLType,
    FirewallPolicy,
    FirewallRule,
    NATRule,
    NATType,
    RuleAction,
    SecurityProfile,
    ServiceObject,
    ZoneDefinition,
)

_ACTION_MAP = {
    "ALLOW": RuleAction.ALLOW, "BLOCK": RuleAction.DENY,
    "BLOCK_RESET": RuleAction.REJECT, "TRUST": RuleAction.ALLOW, "MONITOR": RuleAction.ALLOW,
}
_NAT_MAP = {"STATIC": NATType.STATIC, "DYNAMIC": NATType.DYNAMIC}


def _items(data: dict, key: str) -> list[dict]:
    return data.get(key, {}).get("items", [])


def load_cisco_ftd_json(path: Path, device: str) -> FirewallPolicy:
    data = json.loads(path.read_text())

    # ── Zones ─────────────────────────────────────────────────────────────
    zones = [
        ZoneDefinition(
            name=z["name"], zone_type=z.get("interfaceMode", "ROUTED").lower(),
            description=z.get("description", ""), vendor="cisco_ftd", device=device,
        )
        for z in _items(data, "security_zones")
    ]

    # ── Address objects ────────────────────────────────────────────────────
    address_objects: list[AddressObject] = []
    for o in _items(data, "network_objects"):
        val = o.get("value", "")
        addr_type = AddressType.NETWORK if "/" in val else AddressType.HOST
        address_objects.append(AddressObject(
            name=o["name"], type=addr_type, value=val, description=o.get("description", ""),
        ))
    for g in _items(data, "network_groups"):
        members = [m.get("name", "") for m in g.get("objects", [])]
        address_objects.append(AddressObject(
            name=g["name"], type=AddressType.GROUP, members=members,
            description=g.get("description", ""),
        ))

    # ── Service objects ────────────────────────────────────────────────────
    service_objects = [
        ServiceObject(
            name=o["name"],
            protocol=o.get("protocol", "TCP").lower(),
            port=o.get("port", ""),
        )
        for o in _items(data, "port_objects")
    ]

    # ── Application groups / filters ──────────────────────────────────────
    application_groups = [
        ApplicationGroup(
            name=f["name"],
            is_filter=True,
            filter_category=[c["name"] for c in f.get("categories", [])],
            filter_risk=[r["id"] for r in f.get("risks", [])],
            members=[a["name"] for a in f.get("applications", [])],
            description=f.get("description", ""),
            vendor="cisco_ftd", device=device,
        )
        for f in _items(data, "application_filters")
    ]

    # ── Security profiles ──────────────────────────────────────────────────
    security_profiles: list[SecurityProfile] = []
    for p in _items(data, "intrusion_policies"):
        security_profiles.append(SecurityProfile(
            name=p["name"], profile_type="ips",
            vendor="cisco_ftd", device=device, description=p.get("description", ""),
        ))
    for p in _items(data, "file_policies"):
        security_profiles.append(SecurityProfile(
            name=p["name"], profile_type="file-policy",
            vendor="cisco_ftd", device=device, description=p.get("description", ""),
        ))

    # ── Decryption profiles (from SSL policies) ───────────────────────────
    decryption_profiles: list[DecryptionProfile] = []
    decryption_rules: list[DecryptionRule] = []

    for ssl_policy in _items(data, "ssl_policies"):
        decryption_profiles.append(DecryptionProfile(
            name=ssl_policy["name"], description=ssl_policy.get("description", ""),
            vendor="cisco_ftd", device=device,
        ))
        for i, r in enumerate(ssl_policy.get("rules", [])):
            action_str = r.get("action", "DECRYPT_KNOWN_KEY")
            action = DecryptAction.NO_DECRYPT if "NO" in action_str or "NOT" in action_str else DecryptAction.DECRYPT
            decryption_rules.append(DecryptionRule(
                rule_id=r.get("id", ""),
                name=r.get("name", f"ssl-rule-{i}"),
                enabled=r.get("enabled", True),
                action=action,
                decrypt_type=DecryptType.SSL_FORWARD_PROXY,
                src_zones=[z["name"] for z in r.get("sourceZones", {}).get("objects", [])],
                dst_zones=[z["name"] for z in r.get("destinationZones", {}).get("objects", [])],
                src_addresses=[a["name"] for a in r.get("sourceNetworks", {}).get("objects", [])],
                dst_addresses=[a["name"] for a in r.get("destinationNetworks", {}).get("objects", [])],
                url_categories=[c["name"] for c in r.get("urls", {}).get("urlCategoriesWithReputation", [])],
                profile=ssl_policy["name"],
                vendor="cisco_ftd", device=device, position=i,
            ))

    # ── EDLs (Security Intelligence feeds) ───────────────────────────────
    edls: list[EDL] = []
    for f in _items(data, "security_intelligence_feeds"):
        edls.append(EDL(
            name=f["name"], edl_type=EDLType.URL,
            description=f.get("description", ""),
            is_predefined=f.get("readOnly", False),
            vendor="cisco_ftd", device=device,
        ))

    # ── Security rules ────────────────────────────────────────────────────
    rules: list[FirewallRule] = []
    nat_rules: list[NATRule] = []

    for acp in _items(data, "access_control_policy"):
        for i, r in enumerate(acp.get("rules", [])):
            apps_obj = r.get("applications", {})
            apps = [a["name"] for a in apps_obj.get("applications", [])]
            app_filters = [f["name"] for f in apps_obj.get("applicationFilters", [])]
            url_cats = [c["name"] for c in r.get("urls", {}).get("urlCategoriesWithReputation", [])]
            ips = r.get("ipsPolicy", {}).get("name", "") if r.get("ipsPolicy") else ""
            fp = r.get("filePolicy", {}).get("name", "") if r.get("filePolicy") else ""
            rules.append(FirewallRule(
                rule_id=r.get("id", ""),
                name=r.get("name", f"rule-{i}"),
                enabled=r.get("enabled", True),
                action=_ACTION_MAP.get(r.get("action", "BLOCK"), RuleAction.DENY),
                src_zones=[z["name"] for z in r.get("sourceZones", {}).get("objects", [])],
                dst_zones=[z["name"] for z in r.get("destinationZones", {}).get("objects", [])],
                src_addresses=[a["name"] for a in r.get("sourceNetworks", {}).get("objects", [])],
                dst_addresses=[a["name"] for a in r.get("destinationNetworks", {}).get("objects", [])],
                services=[s["name"] for s in r.get("destinationPorts", {}).get("objects", [])],
                applications=apps + app_filters,
                url_categories=url_cats,
                profiles={k: v for k, v in {"ips": ips, "file": fp}.items() if v},
                log=r.get("logBegin", False) or r.get("logEnd", False),
                vendor="cisco_ftd", device=device, rulebase=acp.get("name", "ACP"), position=i,
            ))

    for nat_policy in _items(data, "nat_policies"):
        for i, r in enumerate(nat_policy.get("autonatrules", [])):
            nat_rules.append(NATRule(
                rule_id=r.get("id", ""),
                name=r.get("description") or f"auto-nat-{i}",
                description=r.get("description", ""),
                enabled=r.get("enabled", True),
                nat_type=_NAT_MAP.get(r.get("natType", "DYNAMIC"), NATType.DYNAMIC),
                src_addresses=[r["originalSource"]["name"]] if r.get("originalSource") else [],
                translated_src=r["translatedSource"]["name"] if r.get("translatedSource") else "",
                vendor="cisco_ftd", device=device, rulebase="auto-nat", position=i,
            ))
        for i, r in enumerate(nat_policy.get("manualnatrules", [])):
            nat_type = NATType.DNAT if r.get("translatedDestination") else NATType.STATIC
            nat_rules.append(NATRule(
                rule_id=r.get("id", ""),
                name=r.get("description") or f"manual-nat-{i}",
                description=r.get("description", ""),
                enabled=r.get("enabled", True),
                nat_type=nat_type,
                dst_addresses=[r["originalDestination"]["name"]] if r.get("originalDestination") else [],
                translated_dst=r["translatedDestination"]["name"] if r.get("translatedDestination") else "",
                translated_src=r["translatedSource"]["name"] if r.get("translatedSource") else "",
                vendor="cisco_ftd", device=device, rulebase="manual-nat",
                position=len(nat_rules),
            ))

    return FirewallPolicy(
        vendor="cisco_ftd", device=device,
        rules=rules, nat_rules=nat_rules,
        decryption_rules=decryption_rules,
        address_objects=address_objects,
        service_objects=service_objects,
        application_groups=application_groups,
        security_profiles=security_profiles,
        decryption_profiles=decryption_profiles,
        edls=edls, zones=zones,
    )
