"""Parse FortiGate JSON export (FortiOS REST API response format) into a FirewallPolicy."""
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
    DoSPolicy,
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

_ACTION_MAP = {"accept": RuleAction.ALLOW, "deny": RuleAction.DENY, "drop": RuleAction.DROP}


def _results(data: dict, key: str) -> list[dict]:
    section = data.get(key, {})
    return section.get("results", []) if isinstance(section, dict) else []


def load_fortinet_json(path: Path, device: str) -> FirewallPolicy:
    data = json.loads(path.read_text())

    # ── Zones ─────────────────────────────────────────────────────────────
    zones = [
        ZoneDefinition(
            name=z.get("name", ""),
            interfaces=[i.get("interface-name", "") for i in z.get("interface", [])],
            description=z.get("description", ""),
            vendor="fortinet", device=device,
        )
        for z in _results(data, "system_zone")
    ]

    # ── Address objects ────────────────────────────────────────────────────
    address_objects: list[AddressObject] = []
    for a in _results(data, "firewall_address"):
        ftype = a.get("type", "ipmask")
        addr_type = {"ipmask": AddressType.NETWORK, "iprange": AddressType.RANGE,
                     "fqdn": AddressType.FQDN}.get(ftype, AddressType.HOST)
        value = a.get("subnet", a.get("fqdn", ""))
        if ftype == "iprange":
            value = f"{a.get('start-ip','')}-{a.get('end-ip','')}"
        address_objects.append(AddressObject(
            name=a["name"], type=addr_type, value=value, description=a.get("comment", ""),
        ))
    for g in _results(data, "firewall_addrgrp"):
        address_objects.append(AddressObject(
            name=g["name"], type=AddressType.GROUP,
            members=[m["name"] for m in g.get("member", [])],
            description=g.get("comment", ""),
        ))

    # ── Service objects ────────────────────────────────────────────────────
    service_objects: list[ServiceObject] = []
    for s in _results(data, "firewall_service_custom"):
        proto = "tcp" if s.get("tcp-portrange") else ("udp" if s.get("udp-portrange") else "any")
        port = s.get("tcp-portrange") or s.get("udp-portrange") or ""
        service_objects.append(ServiceObject(
            name=s["name"], protocol=proto, port=port, description=s.get("comment", ""),
        ))

    # ── Application groups ────────────────────────────────────────────────
    application_groups: list[ApplicationGroup] = []
    for sensor in _results(data, "application_list"):
        for entry in sensor.get("entries", []):
            apps = [a["name"] for a in entry.get("application", [])]
            cats = [c["name"] if isinstance(c, dict) else c for c in entry.get("category", [])]
            if apps or cats:
                application_groups.append(ApplicationGroup(
                    name=f"{sensor['name']}-entry-{entry.get('id',0)}",
                    members=apps, filter_category=cats,
                    is_filter=bool(cats and not apps),
                    vendor="fortinet", device=device,
                ))

    # ── Security profiles ──────────────────────────────────────────────────
    security_profiles: list[SecurityProfile] = []
    for key, ptype in [("antivirus_profile", "antivirus"), ("ips_sensor", "ips"), ("webfilter_profile", "url-filtering")]:
        for p in _results(data, key):
            security_profiles.append(SecurityProfile(
                name=p["name"], profile_type=ptype,
                vendor="fortinet", device=device, description=p.get("comment", ""),
            ))

    # ── Decryption profiles ───────────────────────────────────────────────
    decryption_profiles: list[DecryptionProfile] = []
    for p in _results(data, "firewall_ssl_ssh_profile"):
        ssl = p.get("ssl", {})
        decryption_profiles.append(DecryptionProfile(
            name=p["name"],
            min_tls_version=ssl.get("min-version", "") if isinstance(ssl, dict) else "",
            description=p.get("comment", ""),
            vendor="fortinet", device=device,
        ))

    # ── VIPs (DNAT) ───────────────────────────────────────────────────────
    nat_rules: list[NATRule] = []
    for i, v in enumerate(_results(data, "firewall_vip")):
        nat_rules.append(NATRule(
            name=v.get("name", f"vip_{i}"),
            description=v.get("comment", ""),
            enabled=v.get("status", "enable") == "enable",
            nat_type=NATType.DNAT,
            dst_addresses=[v.get("extip", "")],
            translated_dst=(v.get("mappedip") or [{}])[0].get("range", ""),
            translated_port=str(v.get("mappedport", "") or ""),
            services=[v.get("protocol", "any")],
            vendor="fortinet", device=device, rulebase="vip", position=i,
        ))

    # ── Central SNAT ──────────────────────────────────────────────────────
    for i, s in enumerate(_results(data, "central_snat_map")):
        nat_rules.append(NATRule(
            rule_id=str(s.get("policyid", i)),
            name=f"snat_{s.get('policyid', i)}",
            description=s.get("comments", ""),
            enabled=s.get("status", "enable") == "enable",
            nat_type=NATType.PAT if s.get("type") == "ippool" else NATType.STATIC,
            src_zones=[z["name"] for z in s.get("srcintf", [])],
            dst_zones=[z["name"] for z in s.get("dstintf", [])],
            src_addresses=[a["name"] for a in s.get("orig-addr", [])],
            dst_addresses=[a["name"] for a in s.get("dst-addr", [])],
            translated_src=", ".join(p["name"] for p in s.get("nat-ippool", [])),
            vendor="fortinet", device=device, rulebase="central-snat",
            position=len(nat_rules),
        ))

    # ── EDLs / threat feeds ───────────────────────────────────────────────
    edls: list[EDL] = []
    edl_type_map = {"address": EDLType.IP, "domain": EDLType.DOMAIN, "url": EDLType.URL}
    for f in _results(data, "system_external_resource"):
        edls.append(EDL(
            name=f.get("name", ""),
            edl_type=edl_type_map.get(f.get("type", "address"), EDLType.IP),
            source_url=f.get("server-list", ""),
            description=f.get("comments", ""),
            recurring=f.get("refresh-rate", ""),
            vendor="fortinet", device=device,
        ))

    # ── Security rules (firewall policies) ────────────────────────────────
    rules: list[FirewallRule] = []
    decryption_rules: list[DecryptionRule] = []
    dos_policies: list[DoSPolicy] = []

    for i, r in enumerate(_results(data, "firewall_policy")):
        profiles: dict[str, str] = {}
        for pkey, pfield in [("antivirus","av-profile"),("ips","ips-sensor"),
                              ("url-filtering","webfilter-profile"),("dns-filter","dnsfilter-profile"),
                              ("app-control","application-list")]:
            v = r.get(pfield, "")
            if v:
                profiles[pkey] = v

        rules.append(FirewallRule(
            rule_id=str(r.get("policyid", i)),
            name=r.get("name", f"policy_{i}"),
            description=r.get("comments", ""),
            enabled=r.get("status", "enable") == "enable",
            action=_ACTION_MAP.get(r.get("action", "deny"), RuleAction.DENY),
            src_zones=[z["name"] for z in r.get("srcintf", [])],
            dst_zones=[z["name"] for z in r.get("dstintf", [])],
            src_addresses=[a["name"] for a in r.get("srcaddr", [])],
            dst_addresses=[a["name"] for a in r.get("dstaddr", [])],
            services=[s["name"] for s in r.get("service", [])],
            applications=[a["name"] for a in r.get("application", [])],
            url_categories=[c["name"] for c in r.get("url-category", [])],
            src_users=[u["name"] for u in r.get("groups", []) + r.get("users", [])],
            profiles=profiles,
            log=r.get("logtraffic", "disable") not in ("disable", ""),
            vendor="fortinet", device=device, rulebase="security", position=i,
        ))

        # Extract SSL inspection as a decryption rule if a non-trivial profile is set
        ssl_profile = r.get("ssl-ssh-profile", "")
        if ssl_profile and ssl_profile not in ("no-inspection", ""):
            decryption_rules.append(DecryptionRule(
                name=f"ssl-inspect_{r.get('name', i)}",
                enabled=r.get("status", "enable") == "enable",
                action=DecryptAction.DECRYPT,
                decrypt_type=DecryptType.SSL_FORWARD_PROXY,
                src_zones=[z["name"] for z in r.get("srcintf", [])],
                dst_zones=[z["name"] for z in r.get("dstintf", [])],
                src_addresses=[a["name"] for a in r.get("srcaddr", [])],
                dst_addresses=[a["name"] for a in r.get("dstaddr", [])],
                profile=ssl_profile,
                vendor="fortinet", device=device, position=i,
            ))

    for i, r in enumerate(_results(data, "firewall_DoS_policy") or []):
        dos_policies.append(DoSPolicy(
            rule_id=str(r.get("policyid", i)),
            name=r.get("name", f"dos_{i}"),
            description=r.get("comments", ""),
            enabled=r.get("status", "enable") == "enable",
            src_zones=[z["name"] for z in r.get("srcintf", [])],
            dst_zones=[z["name"] for z in r.get("dstintf", [])],
            src_addresses=[a["name"] for a in r.get("srcaddr", [])],
            dst_addresses=[a["name"] for a in r.get("dstaddr", [])],
            services=[s["name"] for s in r.get("service", [])],
            vendor="fortinet", device=device, position=i,
        ))

    return FirewallPolicy(
        vendor="fortinet", device=device,
        rules=rules, nat_rules=nat_rules,
        decryption_rules=decryption_rules, dos_policies=dos_policies,
        address_objects=address_objects, service_objects=service_objects,
        application_groups=application_groups,
        security_profiles=security_profiles,
        decryption_profiles=decryption_profiles,
        edls=edls, zones=zones,
    )
