"""Deterministic (no-LLM) translators for simple policy object types.

These cover object types whose structure is fully defined by syntax differences
between vendors — no semantic interpretation is needed. When a fast-path
translator exists, the proposal is auto-approved immediately (approved_by =
"system:fast-path") without human review.

Object types handled here:
  address_object   — IP, range, FQDN re-encoding per vendor
  address_group    — member list re-keying per vendor (trivially translatable)
  service_object   — protocol + port syntax per vendor
  service_group    — member list re-keying
  url_category     — category list re-keying (ASA: unsupported, returns note)
  edl              — feed URL + refresh interval per vendor (ASA: unsupported)

For security rules: APP_PORT_MAP provides deterministic App-ID → port mapping
for well-known applications. Rules whose application list resolves entirely to
known ports are fast-pathed; unknown apps fall through to the LLM.

Types that still require LLM (security_rule with unknown apps, nat_rule,
application, etc.) return None, signalling the caller to fall back to
generate_object_translation.
"""
from __future__ import annotations

import ipaddress
from typing import Any


# ── App-ID → port mapping ─────────────────────────────────────────────────────
# Maps PAN-OS application names to (protocol, port) tuples for port-based vendors.
# Only well-known, unambiguous mappings are listed here.

APP_PORT_MAP: dict[str, list[tuple[str, str]]] = {
    "web-browsing":      [("tcp", "80")],
    "ssl":               [("tcp", "443")],
    "http2":             [("tcp", "443")],
    "dns":               [("udp", "53"), ("tcp", "53")],
    "ssh":               [("tcp", "22")],
    "ftp":               [("tcp", "21")],
    "ftp-data":          [("tcp", "20")],
    "smtp":              [("tcp", "25")],
    "smtps":             [("tcp", "465")],
    "imap":              [("tcp", "143")],
    "imaps":             [("tcp", "993")],
    "pop3":              [("tcp", "110")],
    "pop3s":             [("tcp", "995")],
    "ntp":               [("udp", "123")],
    "snmp":              [("udp", "161")],
    "snmptrap":          [("udp", "162")],
    "ldap":              [("tcp", "389"), ("udp", "389")],
    "ldaps":             [("tcp", "636")],
    "kerberos":          [("tcp", "88"), ("udp", "88")],
    "rdp":               [("tcp", "3389")],
    "telnet":            [("tcp", "23")],
    "tftp":              [("udp", "69")],
    "syslog":            [("udp", "514")],
    "msrpc":             [("tcp", "135")],
    "netbios-ns":        [("udp", "137")],
    "netbios-dgm":       [("udp", "138")],
    "netbios-ss":        [("tcp", "139")],
    "ms-ds-replication": [("tcp", "389"), ("tcp", "636")],
    "smb":               [("tcp", "445")],
    "nfs":               [("tcp", "2049"), ("udp", "2049")],
    "mysql":             [("tcp", "3306")],
    "mssql":             [("tcp", "1433")],
    "oracle":            [("tcp", "1521")],
    "postgresql":        [("tcp", "5432")],
    "redis":             [("tcp", "6379")],
    "mongodb":           [("tcp", "27017")],
    "elasticsearch":     [("tcp", "9200"), ("tcp", "9300")],
    "kafka":             [("tcp", "9092")],
    "amqp":              [("tcp", "5672")],
    "mqtt":              [("tcp", "1883")],
    "sip":               [("tcp", "5060"), ("udp", "5060")],
    "sips":              [("tcp", "5061")],
    "rtsp":              [("tcp", "554")],
    "bgp":               [("tcp", "179")],
    "ospf":              [("tcp", "89")],
    "nfs-tcp":           [("tcp", "2049")],
    "http-proxy":        [("tcp", "8080")],
    "https-proxy":       [("tcp", "8443")],
    "icmp":              [("icmp", "any")],
    "ping":              [("icmp", "any")],
    "traceroute":        [("udp", "33434-33523")],
}

PORT_BASED_VENDORS = frozenset({"cisco_asa", "cisco_ftd"})


def resolve_apps_to_ports(apps: list[str]) -> tuple[list[tuple[str, str]], list[str]] | None:
    """Resolve an application list to (protocol, port) pairs.

    Returns (known_ports, unknown_apps) or None if the list is empty / contains
    'any'. The caller should use LLM when unknown_apps is non-empty.
    """
    if not apps or apps == ["any"]:
        return None
    known: list[tuple[str, str]] = []
    unknown: list[str] = []
    for app in apps:
        app_lower = app.lower()
        if app_lower in APP_PORT_MAP:
            known.extend(APP_PORT_MAP[app_lower])
        else:
            unknown.append(app)
    return known, unknown


# ── Entry point ───────────────────────────────────────────────────────────────

FAST_PATH_TYPES = frozenset({
    "address_object",
    "address_group",
    "service_object",
    "service_group",
    "url_category",
    "edl",
})


def fast_translate_object(
    object_type: str,
    object_name: str,
    base_data: dict[str, Any],
    target_vendor: str,
) -> tuple[dict[str, Any], str] | None:
    """Return (translation, reasoning) or None if type needs LLM."""
    if object_type not in FAST_PATH_TYPES:
        return None

    fn = {
        "address_object": _address_object,
        "address_group":  _address_group,
        "service_object": _service_object,
        "service_group":  _service_group,
        "url_category":   _url_category,
        "edl":            _edl,
    }.get(object_type)

    if fn is None:
        return None

    try:
        result = fn(object_name, base_data, target_vendor)
        return result
    except Exception:
        return None


# ── Address objects ───────────────────────────────────────────────────────────

def _address_object(
    name: str, base: dict[str, Any], vendor: str
) -> tuple[dict[str, Any], str]:
    addr_type = base.get("type", "ip-netmask")
    value = str(base.get("value", ""))
    desc = base.get("description", "")

    if addr_type in ("group", "address-group", "addrgrp"):
        return _address_group(name, base, vendor)
    if addr_type == "ip-range":
        return _addr_range(name, value, desc, vendor)
    if addr_type == "fqdn":
        return _addr_fqdn(name, value, desc, vendor)
    # default: ip-netmask (host or subnet)
    return _addr_netmask(name, value, desc, vendor)


def _addr_netmask(name: str, value: str, desc: str, vendor: str) -> tuple[dict, str]:
    try:
        net = ipaddress.ip_network(value, strict=False)
        is_host = net.num_addresses == 1
    except ValueError:
        net = None
        is_host = False

    if vendor == "paloalto":
        t = {"type": "ip-netmask", "ip-netmask": value}
        if desc:
            t["description"] = desc
        return t, "Direct ip-netmask mapping."

    if vendor == "fortinet":
        if net:
            mask = str(net.netmask)
            subnet = f"{net.network_address} {mask}"
        else:
            subnet = value
        t = {"type": "ipmask", "subnet": subnet}
        if desc:
            t["comment"] = desc
        return t, "ip-netmask → FortiGate ipmask (dotted-decimal mask)."

    if vendor == "cisco_asa":
        if net and is_host:
            t = {"type": "host", "ip": str(net.network_address)}
        elif net:
            t = {"type": "subnet", "ip": str(net.network_address), "mask": str(net.netmask)}
        else:
            t = {"type": "subnet", "ip": value, "mask": "255.255.255.255"}
        if desc:
            t["description"] = desc
        return t, "ip-netmask → ASA host/subnet object."

    if vendor == "cisco_ftd":
        t = {"type": "Network", "value": value}
        if desc:
            t["description"] = desc
        return t, "ip-netmask → FTD Network object."

    return {"value": value}, f"Generic mapping for unknown vendor {vendor!r}."


def _addr_range(name: str, value: str, desc: str, vendor: str) -> tuple[dict, str]:
    parts = value.split("-", 1)
    start = parts[0].strip() if parts else value
    end = parts[1].strip() if len(parts) > 1 else value

    if vendor == "paloalto":
        t = {"type": "ip-range", "ip-range": value}
        if desc:
            t["description"] = desc
        return t, "ip-range direct mapping."

    if vendor == "fortinet":
        t = {"type": "iprange", "start-ip": start, "end-ip": end}
        if desc:
            t["comment"] = desc
        return t, "ip-range → FortiGate iprange."

    if vendor == "cisco_asa":
        t = {"type": "range", "start": start, "end": end}
        if desc:
            t["description"] = desc
        return t, "ip-range → ASA range object."

    if vendor == "cisco_ftd":
        t = {"type": "Range", "value": value}
        if desc:
            t["description"] = desc
        return t, "ip-range → FTD Range object."

    return {"value": value}, f"Generic range for {vendor!r}."


def _addr_fqdn(name: str, value: str, desc: str, vendor: str) -> tuple[dict, str]:
    if vendor == "paloalto":
        t = {"type": "fqdn", "fqdn": value}
        if desc:
            t["description"] = desc
        return t, "FQDN direct mapping."

    if vendor == "fortinet":
        t = {"type": "fqdn", "fqdn": value}
        if desc:
            t["comment"] = desc
        return t, "FQDN direct mapping to FortiGate."

    if vendor == "cisco_asa":
        t = {"type": "fqdn", "fqdn": value, "version": "v4"}
        if desc:
            t["description"] = desc
        return t, "FQDN → ASA fqdn object."

    if vendor == "cisco_ftd":
        t = {"type": "FQDN", "value": value}
        if desc:
            t["description"] = desc
        return t, "FQDN → FTD FQDN object."

    return {"fqdn": value}, f"Generic FQDN for {vendor!r}."


# ── Address groups ────────────────────────────────────────────────────────────

def _address_group(
    name: str, base: dict[str, Any], vendor: str
) -> tuple[dict[str, Any], str]:
    """Translate an address group (member list) — trivially re-keyed per vendor."""
    members: list[str] = base.get("members", base.get("member", []))
    desc = base.get("description", "")

    if vendor == "paloalto":
        t: dict[str, Any] = {"members": members}
        if desc:
            t["description"] = desc
        return t, "Address group member list — PAN-OS format."

    if vendor == "fortinet":
        t = {"type": "group", "member": members}
        if desc:
            t["comment"] = desc
        return t, "Address group → FortiGate group with 'member' list."

    if vendor == "cisco_asa":
        t = {"type": "network-object-group", "network_objects": members}
        if desc:
            t["description"] = desc
        return t, "Address group → ASA network-object-group."

    if vendor == "cisco_ftd":
        t = {"type": "NetworkGroup", "objects": [{"name": m} for m in members]}
        if desc:
            t["description"] = desc
        return t, "Address group → FTD NetworkGroup."

    return {"members": members}, f"Generic address group for {vendor!r}."


# ── Service objects ───────────────────────────────────────────────────────────

def _service_object(
    name: str, base: dict[str, Any], vendor: str
) -> tuple[dict[str, Any], str]:
    proto = base.get("protocol", "tcp").lower()
    port = str(base.get("port", "any"))
    desc = base.get("description", "")

    if vendor == "paloalto":
        t: dict[str, Any] = {}
        if proto in ("tcp", "udp"):
            t["protocol"] = {proto: {"port": port}}
        elif proto == "icmp":
            t["protocol"] = {"icmp": {}}
        else:
            t["protocol"] = {proto: {}}
        if desc:
            t["description"] = desc
        return t, "Direct protocol/port mapping to PAN-OS service."

    if vendor == "fortinet":
        t = {"protocol": "TCP/UDP/SCTP"}
        if proto == "tcp":
            t["tcp-portrange"] = port
            t["udp-portrange"] = ""
        elif proto == "udp":
            t["tcp-portrange"] = ""
            t["udp-portrange"] = port
        elif proto == "icmp":
            t["protocol"] = "ICMP"
        if desc:
            t["comment"] = desc
        return t, "Protocol/port → FortiGate service syntax."

    if vendor == "cisco_asa":
        if proto in ("tcp", "udp"):
            if "-" in port:
                lo, hi = port.split("-", 1)
                dst = {"range": f"{lo.strip()} {hi.strip()}"}
            elif port == "any":
                dst = {}
            else:
                dst = {"eq": port}
            t = {"protocol": proto}
            if dst:
                t["destination"] = dst
        elif proto == "icmp":
            t = {"protocol": "icmp"}
        else:
            t = {"protocol": proto}
        if desc:
            t["description"] = desc
        return t, "Protocol/port → ASA service object syntax."

    if vendor == "cisco_ftd":
        proto_upper = proto.upper()
        if "-" in port:
            lo, hi = port.split("-", 1)
            t = {"protocol": proto_upper, "portRange": {"low": int(lo), "high": int(hi)}}
        elif port == "any":
            t = {"protocol": proto_upper}
        else:
            t = {"protocol": proto_upper, "port": port}
        if desc:
            t["description"] = desc
        return t, "Protocol/port → FTD port object syntax."

    return {"protocol": proto, "port": port}, f"Generic service for {vendor!r}."


# ── Service groups ────────────────────────────────────────────────────────────

def _service_group(
    name: str, base: dict[str, Any], vendor: str
) -> tuple[dict[str, Any], str]:
    members: list[str] = base.get("members", [])
    desc = base.get("description", "")

    if vendor == "paloalto":
        t: dict[str, Any] = {"members": members}
        if desc:
            t["description"] = desc
        return t, "Service group member list — PAN-OS format."

    if vendor == "fortinet":
        t = {"member": members}
        if desc:
            t["comment"] = desc
        return t, "Service group → FortiGate 'member' list."

    if vendor == "cisco_asa":
        t = {"type": "service-group", "members": members}
        if desc:
            t["description"] = desc
        return t, "Service group → ASA service-group."

    if vendor == "cisco_ftd":
        t = {"type": "PortObjectGroup", "objects": [{"name": m} for m in members]}
        if desc:
            t["description"] = desc
        return t, "Service group → FTD PortObjectGroup."

    return {"members": members}, f"Generic group for {vendor!r}."


# ── URL categories ────────────────────────────────────────────────────────────

def _url_category(
    name: str, base: dict[str, Any], vendor: str
) -> tuple[dict[str, Any], str]:
    cats: list[str] = base.get("categories", [])
    desc = base.get("description", "")

    if vendor == "paloalto":
        t: dict[str, Any] = {"type": "url-category", "members": cats}
        if desc:
            t["description"] = desc
        return t, "URL category direct mapping to PAN-OS."

    if vendor == "fortinet":
        t = {"type": "webfilter-category", "categories": cats}
        if desc:
            t["comment"] = desc
        return t, "URL category → FortiGate webfilter-category."

    if vendor == "cisco_ftd":
        t = {"type": "URLCategory", "categories": cats}
        if desc:
            t["description"] = desc
        return t, "URL category → FTD URLCategory."

    if vendor == "cisco_asa":
        return (
            {"note": "Cisco ASA has no native URL category support. Use WCCP/WSA or FirePOWER module.", "categories": cats},
            "ASA has no native URL category object — manual integration required.",
        )

    return {"categories": cats}, f"Generic url_category for {vendor!r}."


# ── External dynamic lists (EDL) ──────────────────────────────────────────────

def _edl(
    name: str, base: dict[str, Any], vendor: str
) -> tuple[dict[str, Any], str]:
    edl_type = base.get("type", "ip").lower()
    url = base.get("url", "")
    refresh_min = int(base.get("refresh_interval_minutes", 60))
    desc = base.get("description", "")

    if vendor == "paloalto":
        # PAN-OS uses hourly/five-minute/daily
        repeat: dict[str, Any]
        if refresh_min <= 5:
            repeat = {"five-minute": "+"}
        elif refresh_min <= 60:
            repeat = {"hourly": "+"}
        else:
            repeat = {"daily": {"at": "00"}}
        t: dict[str, Any] = {"type": edl_type, "url": url, "repeat": repeat}
        if desc:
            t["description"] = desc
        return t, "EDL → PAN-OS External Dynamic List."

    if vendor == "fortinet":
        t = {"type": edl_type, "url": url, "refresh-rate": refresh_min}
        if desc:
            t["comment"] = desc
        return t, "EDL → FortiGate threat-feed."

    if vendor == "cisco_ftd":
        t = {
            "type": "SecurityIntelligenceList",
            "feed_url": url,
            "update_interval": refresh_min * 60,  # FTD uses seconds
        }
        if desc:
            t["description"] = desc
        return t, "EDL → FTD Security Intelligence feed (interval in seconds)."

    if vendor == "cisco_asa":
        return (
            {"note": "Cisco ASA has no native EDL support. Use threat-feed via Firepower or dynamic ACL.", "url": url},
            "ASA has no native EDL — Firepower service policy or dynamic ACL required.",
        )

    return {"url": url, "type": edl_type}, f"Generic EDL for {vendor!r}."
