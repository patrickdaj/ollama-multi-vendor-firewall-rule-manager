"""Vendor-agnostic data models for firewall policies.

Ingestion map — what each vendor provides per tier:

  Tier 1 Policy:
    PAN-OS   : security rules, NAT, decryption policy, DoS policy, auth policy
    ASA      : extended ACLs, object/twice NAT (no App-ID, no decrypt in base ASA)
    FTD      : access control rules, NAT policy, SSL policy, identity policy
    FortiGate: firewall policy, central SNAT, VIPs, SSL/SSH inspection, DoS policy, auth policy

  Tier 2 Objects:
    PAN-OS   : address/group, service/group, App-ID (predefined+custom), app groups, app filters, URL categories, regions
    ASA      : network objects/groups, service objects (no App-ID)
    FTD      : network objects/groups, port objects, app filters, URL categories
    FortiGate: address/group, service/group, app signatures, app groups, app categories, URL categories, geography

  Tier 3 Profiles:
    PAN-OS   : antivirus, vulnerability, spyware, url-filtering, file-blocking, wildfire, dns-security, decryption
    FTD      : intrusion policy, file & malware policy, SSL policy
    FortiGate: av-profile, ips-sensor, webfilter, dns-filter, app-control, ssl-ssh-profile

  Tier 4 Dynamic:
    PAN-OS   : EDLs (ip/domain/url/predefined)
    FTD      : Security Intelligence feeds (IP/URL/DNS block lists)
    FortiGate: threat feeds (FortiGuard), custom threat lists

  Tier 5 Network:
    All      : zones, interfaces (zone membership)
"""
from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


# ── Enumerations ──────────────────────────────────────────────────────────────


class RuleAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    REJECT = "reject"


class NATType(StrEnum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    PAT = "pat"
    DNAT = "dnat"
    BIDIR = "bidir"


class AddressType(StrEnum):
    HOST = "host"
    NETWORK = "network"
    RANGE = "range"
    FQDN = "fqdn"
    GROUP = "group"
    ANY = "any"


class DecryptAction(StrEnum):
    DECRYPT = "decrypt"
    NO_DECRYPT = "no-decrypt"
    FORWARD = "forward"


class DecryptType(StrEnum):
    SSL_FORWARD_PROXY = "ssl-forward-proxy"
    SSL_INBOUND = "ssl-inbound-inspection"
    SSH_PROXY = "ssh-proxy"


class EDLType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    PREDEFINED_IP = "predefined-ip"
    PREDEFINED_URL = "predefined-url"


# ── Tier 2 Objects ────────────────────────────────────────────────────────────


class AddressObject(BaseModel):
    name: str
    type: AddressType
    value: str = ""
    members: list[str] = []
    description: str = ""
    tags: list[str] = []

    def to_text(self) -> str:
        parts = [f"Address Object: {self.name}", f"Type: {self.type}"]
        if self.value:
            parts.append(f"Value: {self.value}")
        if self.members:
            parts.append(f"Members: {', '.join(self.members)}")
        if self.description:
            parts.append(f"Description: {self.description}")
        return "\n".join(parts)


class ServiceObject(BaseModel):
    name: str
    protocol: Literal["tcp", "udp", "icmp", "any"] = "tcp"
    port: str = ""
    description: str = ""
    tags: list[str] = []

    def to_text(self) -> str:
        return (
            f"Service Object: {self.name}\n"
            f"Protocol: {self.protocol}\n"
            f"Port: {self.port or 'any'}"
        )


class ServiceGroup(BaseModel):
    name: str
    members: list[str] = []
    description: str = ""

    def to_text(self) -> str:
        return f"Service Group: {self.name}\nMembers: {', '.join(self.members)}"


class ApplicationObject(BaseModel):
    """A single application definition — predefined or custom.

    PAN-OS  : App-ID (predefined from content updates + user-defined)
    FTD     : Application detectors (OpenAppID + Talos-provided)
    FortiGate: FortiGuard application signatures + custom signatures
    ASA     : Not applicable (port-based only)
    """
    name: str
    vendor_id: str = ""         # vendor's internal signature ID
    category: str = ""          # e.g. "business-systems", "media", "networking"
    subcategory: str = ""       # e.g. "database", "file-sharing"
    technology: str = ""        # "client-server", "peer-to-peer", "browser-based"
    risk: int = 0               # 1-5 (vendor risk score)
    evasive: bool = False
    consumes_big_bandwidth: bool = False
    used_by_malware: bool = False
    transfers_files: bool = False
    tunnels_other_apps: bool = False
    default_ports: list[str] = []   # ["tcp/80", "tcp/443"]
    is_custom: bool = False
    description: str = ""
    vendor: str = ""
    device: str = ""
    tags: list[str] = []

    def to_text(self) -> str:
        parts = [
            f"Application: {self.name}",
            f"Category: {self.category} / {self.subcategory}",
            f"Technology: {self.technology}",
            f"Risk: {self.risk}/5",
        ]
        flags = [
            k for k, v in {
                "evasive": self.evasive,
                "consumes-big-bandwidth": self.consumes_big_bandwidth,
                "used-by-malware": self.used_by_malware,
                "transfers-files": self.transfers_files,
                "tunnels-other-apps": self.tunnels_other_apps,
            }.items() if v
        ]
        if flags:
            parts.append(f"Characteristics: {', '.join(flags)}")
        if self.default_ports:
            parts.append(f"Default Ports: {', '.join(self.default_ports)}")
        if self.description:
            parts.append(f"Description: {self.description}")
        if self.is_custom:
            parts.append("Type: custom (user-defined)")
        parts.append(f"Device: {self.device} ({self.vendor})")
        return "\n".join(parts)


class ApplicationGroup(BaseModel):
    """Static or dynamic application grouping.

    PAN-OS  : Application Group (static) or Application Filter (dynamic — risk/category/etc.)
    FTD     : Application Filter
    FortiGate: Application Group / Application Category
    """
    name: str
    members: list[str] = []         # for static groups
    is_filter: bool = False          # True = dynamic filter (risk/category criteria)
    filter_risk: list[int] = []      # [4, 5] = high + critical risk
    filter_category: list[str] = []  # ["collaboration", "media"]
    filter_subcategory: list[str] = []
    filter_technology: list[str] = []
    filter_characteristics: list[str] = []  # ["evasive", "used-by-malware"]
    description: str = ""
    vendor: str = ""
    device: str = ""

    def to_text(self) -> str:
        if self.is_filter:
            criteria = []
            if self.filter_risk:
                criteria.append(f"risk={self.filter_risk}")
            if self.filter_category:
                criteria.append(f"category={self.filter_category}")
            if self.filter_characteristics:
                criteria.append(f"characteristics={self.filter_characteristics}")
            return (
                f"Application Filter: {self.name}\n"
                f"Type: dynamic filter\n"
                f"Criteria: {', '.join(criteria)}\n"
                f"Device: {self.device} ({self.vendor})"
            )
        return (
            f"Application Group: {self.name}\n"
            f"Members: {', '.join(self.members)}\n"
            f"Device: {self.device} ({self.vendor})"
        )


class URLCategory(BaseModel):
    """Custom URL category definition.

    PAN-OS  : Custom URL categories (block/allow list of URLs)
    FTD     : URL objects / URL groups
    FortiGate: Web filter custom categories
    """
    name: str
    urls: list[str] = []
    description: str = ""
    vendor: str = ""
    device: str = ""

    def to_text(self) -> str:
        return (
            f"URL Category: {self.name}\n"
            f"URLs: {', '.join(self.urls[:10])}{'...' if len(self.urls) > 10 else ''}\n"
            f"Device: {self.device} ({self.vendor})"
        )


# ── Tier 3 Profiles ───────────────────────────────────────────────────────────


class SecurityProfile(BaseModel):
    """Vendor-agnostic security/UTM profile."""
    name: str
    profile_type: str   # "antivirus", "ips", "url-filtering", "dns-security", "file-blocking", "wildfire", "ssl"
    vendor: str = ""
    device: str = ""
    description: str = ""

    def to_text(self) -> str:
        return (
            f"Security Profile: {self.name}\n"
            f"Type: {self.profile_type}\n"
            f"Device: {self.device} ({self.vendor})"
            + (f"\nDescription: {self.description}" if self.description else "")
        )


class DecryptionProfile(BaseModel):
    """SSL/TLS inspection profile settings.

    Controls what is checked/enforced during decrypted traffic inspection.
    PAN-OS: Decryption Profile
    FTD: SSL policy settings
    FortiGate: SSL/SSH inspection profile
    """
    name: str
    check_certificate_expiry: bool = False
    check_certificate_revocation: bool = False
    block_untrusted_issuers: bool = False
    min_tls_version: str = ""   # "tls1-0", "tls1-1", "tls1-2", "tls1-3"
    block_expired_certs: bool = False
    block_self_signed: bool = False
    strip_alpn: bool = False     # disable HTTP/2 for inspection
    description: str = ""
    vendor: str = ""
    device: str = ""

    def to_text(self) -> str:
        settings = [
            k for k, v in {
                "check-certificate-expiry": self.check_certificate_expiry,
                "check-revocation": self.check_certificate_revocation,
                "block-untrusted-issuers": self.block_untrusted_issuers,
                "block-expired": self.block_expired_certs,
                "block-self-signed": self.block_self_signed,
                "strip-alpn": self.strip_alpn,
            }.items() if v
        ]
        parts = [
            f"Decryption Profile: {self.name}",
            f"Device: {self.device} ({self.vendor})",
        ]
        if self.min_tls_version:
            parts.append(f"Minimum TLS: {self.min_tls_version}")
        if settings:
            parts.append(f"Enforcement: {', '.join(settings)}")
        return "\n".join(parts)


# ── Tier 4 Dynamic / Threat Intelligence ─────────────────────────────────────


class EDL(BaseModel):
    """External Dynamic List or threat feed entry.

    PAN-OS  : External Dynamic List (ip/domain/url/predefined)
    FTD     : Security Intelligence feeds (IP Intelligence, URL Intelligence, DNS Intelligence)
    FortiGate: Threat feeds (FortiGuard + custom), address objects with ISDB type
    """
    name: str
    edl_type: EDLType
    source_url: str = ""
    description: str = ""
    recurring: str = ""         # "hourly", "five-minute", "daily", "weekly"
    last_updated: str = ""
    entry_count: int = 0        # number of entries in the list
    is_predefined: bool = False  # vendor-managed (PAN Alto predefined, FortiGuard)
    vendor: str = ""
    device: str = ""

    def to_text(self) -> str:
        parts = [
            f"External Dynamic List / Threat Feed: {self.name}",
            f"Type: {self.edl_type}",
            f"Device: {self.device} ({self.vendor})",
        ]
        if self.source_url:
            parts.append(f"Source: {self.source_url}")
        if self.recurring:
            parts.append(f"Update frequency: {self.recurring}")
        if self.entry_count:
            parts.append(f"Entry count: {self.entry_count}")
        if self.is_predefined:
            parts.append("Source: vendor-managed (predefined)")
        if self.description:
            parts.append(f"Description: {self.description}")
        return "\n".join(parts)


# ── Tier 5 Network Topology ───────────────────────────────────────────────────


class ZoneDefinition(BaseModel):
    """Security zone definition.

    Critical context for policy: rules reference zones, so knowing which
    interfaces belong to which zone is necessary to understand traffic paths.
    """
    name: str
    zone_type: str = "layer3"   # layer3, layer2, virtual-wire, tap, external, tunnel
    interfaces: list[str] = []
    description: str = ""
    log_setting: str = ""
    zone_protection_profile: str = ""
    enable_userid: bool = False
    vendor: str = ""
    device: str = ""

    def to_text(self) -> str:
        parts = [
            f"Zone: {self.name}",
            f"Type: {self.zone_type}",
            f"Device: {self.device} ({self.vendor})",
        ]
        if self.interfaces:
            parts.append(f"Interfaces: {', '.join(self.interfaces)}")
        if self.zone_protection_profile:
            parts.append(f"Zone Protection Profile: {self.zone_protection_profile}")
        if self.description:
            parts.append(f"Description: {self.description}")
        return "\n".join(parts)


# ── Tier 1 Policy Rules ───────────────────────────────────────────────────────


class FirewallRule(BaseModel):
    rule_id: str = ""
    name: str
    description: str = ""
    enabled: bool = True
    action: RuleAction

    src_zones: list[str] = Field(default_factory=list)
    dst_zones: list[str] = Field(default_factory=list)
    src_addresses: list[str] = Field(default_factory=list)
    dst_addresses: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    applications: list[str] = []   # App-ID (PAN-OS) / application filter (FTD/FortiGate)
    url_categories: list[str] = [] # URL category matching
    src_users: list[str] = []       # user/group identity
    profiles: dict[str, str] = {}   # {"antivirus": "default", "ips": "strict"}
    log: bool = True
    tags: list[str] = []

    vendor: str = ""
    device: str = ""
    rulebase: str = "security"
    position: int = 0

    def to_text(self) -> str:
        parts = [
            f"Security Rule: {self.name}",
            f"Device: {self.device} ({self.vendor})",
            f"Action: {self.action}",
            f"Enabled: {self.enabled}",
            f"Source Zones: {', '.join(self.src_zones) or 'any'}",
            f"Destination Zones: {', '.join(self.dst_zones) or 'any'}",
            f"Source Addresses: {', '.join(self.src_addresses) or 'any'}",
            f"Destination Addresses: {', '.join(self.dst_addresses) or 'any'}",
            f"Services: {', '.join(self.services) or 'any'}",
        ]
        if self.applications:
            parts.append(f"Applications: {', '.join(self.applications)}")
        if self.url_categories:
            parts.append(f"URL Categories: {', '.join(self.url_categories)}")
        if self.src_users:
            parts.append(f"Source Users/Groups: {', '.join(self.src_users)}")
        if self.profiles:
            parts.append(f"Security Profiles: {', '.join(f'{k}={v}' for k, v in self.profiles.items())}")
        if self.description:
            parts.append(f"Description: {self.description}")
        if self.tags:
            parts.append(f"Tags: {', '.join(self.tags)}")
        return "\n".join(parts)


class NATRule(BaseModel):
    """Vendor-agnostic NAT rule covering all types and all vendors."""
    rule_id: str = ""
    name: str
    description: str = ""
    enabled: bool = True
    nat_type: NATType

    src_zones: list[str] = []
    dst_zones: list[str] = []
    src_addresses: list[str] = []
    dst_addresses: list[str] = []
    services: list[str] = []

    translated_src: str = ""
    translated_dst: str = ""
    translated_port: str = ""

    vendor: str = ""
    device: str = ""
    rulebase: str = "nat"
    position: int = 0

    def to_text(self) -> str:
        parts = [
            f"NAT Rule: {self.name}",
            f"Device: {self.device} ({self.vendor})",
            f"Type: {self.nat_type}",
            f"Enabled: {self.enabled}",
            f"Source Zones: {', '.join(self.src_zones) or 'any'}",
            f"Destination Zones: {', '.join(self.dst_zones) or 'any'}",
            f"Original Source: {', '.join(self.src_addresses) or 'any'}",
            f"Original Destination: {', '.join(self.dst_addresses) or 'any'}",
            f"Services: {', '.join(self.services) or 'any'}",
        ]
        if self.translated_src:
            parts.append(f"Translated Source: {self.translated_src}")
        if self.translated_dst:
            parts.append(f"Translated Destination: {self.translated_dst}")
        if self.translated_port:
            parts.append(f"Translated Port: {self.translated_port}")
        if self.description:
            parts.append(f"Description: {self.description}")
        return "\n".join(parts)


class DecryptionRule(BaseModel):
    """SSL/TLS or SSH inspection policy rule.

    PAN-OS  : Decryption policy rules
    FTD     : SSL policy rules
    FortiGate: SSL/SSH inspection is set per-policy in firewall policy, not a separate rulebase;
               FortiGate deep-inspection profiles are referenced here
    """
    rule_id: str = ""
    name: str
    description: str = ""
    enabled: bool = True
    action: DecryptAction = DecryptAction.DECRYPT
    decrypt_type: DecryptType = DecryptType.SSL_FORWARD_PROXY

    src_zones: list[str] = []
    dst_zones: list[str] = []
    src_addresses: list[str] = []
    dst_addresses: list[str] = []
    services: list[str] = []
    url_categories: list[str] = []  # decrypt only these categories

    profile: str = ""   # decryption profile name
    log: bool = True

    vendor: str = ""
    device: str = ""
    position: int = 0

    def to_text(self) -> str:
        parts = [
            f"Decryption Rule: {self.name}",
            f"Device: {self.device} ({self.vendor})",
            f"Action: {self.action}",
            f"Type: {self.decrypt_type}",
            f"Enabled: {self.enabled}",
            f"Source Zones: {', '.join(self.src_zones) or 'any'}",
            f"Destination Zones: {', '.join(self.dst_zones) or 'any'}",
            f"Source Addresses: {', '.join(self.src_addresses) or 'any'}",
            f"Destination Addresses: {', '.join(self.dst_addresses) or 'any'}",
        ]
        if self.url_categories:
            parts.append(f"URL Categories: {', '.join(self.url_categories)}")
        if self.profile:
            parts.append(f"Decryption Profile: {self.profile}")
        if self.description:
            parts.append(f"Description: {self.description}")
        return "\n".join(parts)


class DoSPolicy(BaseModel):
    """DoS / zone protection policy rule.

    PAN-OS  : DoS Protection rules + Zone Protection profiles
    FTD     : Prefilter policy (fast-path / block)
    FortiGate: DoS policy
    """
    rule_id: str = ""
    name: str
    description: str = ""
    enabled: bool = True
    action: Literal["protect", "deny", "allow"] = "protect"

    src_zones: list[str] = []
    dst_zones: list[str] = []
    src_addresses: list[str] = []
    dst_addresses: list[str] = []
    services: list[str] = []

    profile: str = ""       # DoS/zone protection profile name
    aggregate_profile: str = ""
    classified_profile: str = ""

    vendor: str = ""
    device: str = ""
    position: int = 0

    def to_text(self) -> str:
        parts = [
            f"DoS Policy: {self.name}",
            f"Device: {self.device} ({self.vendor})",
            f"Action: {self.action}",
            f"Source Zones: {', '.join(self.src_zones) or 'any'}",
            f"Destination Zones: {', '.join(self.dst_zones) or 'any'}",
        ]
        if self.profile:
            parts.append(f"Protection Profile: {self.profile}")
        return "\n".join(parts)


class AuthPolicy(BaseModel):
    """Authentication / captive portal policy rule.

    PAN-OS  : Authentication policy
    FTD     : Identity policy
    FortiGate: Captive portal policy
    """
    rule_id: str = ""
    name: str
    description: str = ""
    enabled: bool = True

    src_zones: list[str] = []
    dst_zones: list[str] = []
    src_addresses: list[str] = []
    dst_addresses: list[str] = []
    services: list[str] = []

    authentication_profile: str = ""
    authentication_method: str = ""  # "web-form", "kerberos", "ntlm", "radius"
    timeout: int = 0                 # session timeout in seconds

    vendor: str = ""
    device: str = ""
    position: int = 0

    def to_text(self) -> str:
        parts = [
            f"Authentication Policy: {self.name}",
            f"Device: {self.device} ({self.vendor})",
            f"Method: {self.authentication_method or 'any'}",
            f"Source Zones: {', '.join(self.src_zones) or 'any'}",
            f"Destination Zones: {', '.join(self.dst_zones) or 'any'}",
        ]
        if self.authentication_profile:
            parts.append(f"Auth Profile: {self.authentication_profile}")
        return "\n".join(parts)


# ── Full policy snapshot ──────────────────────────────────────────────────────


class FirewallPolicy(BaseModel):
    """Complete policy snapshot from one device — everything the RAG ingests."""

    vendor: str
    device: str

    # Tier 1 — Rulebases
    rules: list[FirewallRule] = []
    nat_rules: list[NATRule] = []
    decryption_rules: list[DecryptionRule] = []
    dos_policies: list[DoSPolicy] = []
    auth_policies: list[AuthPolicy] = []

    # Tier 2 — Objects
    address_objects: list[AddressObject] = []
    service_objects: list[ServiceObject] = []
    service_groups: list[ServiceGroup] = []
    application_objects: list[ApplicationObject] = []
    application_groups: list[ApplicationGroup] = []
    url_categories: list[URLCategory] = []

    # Tier 3 — Profiles
    security_profiles: list[SecurityProfile] = []
    decryption_profiles: list[DecryptionProfile] = []

    # Tier 4 — Dynamic intelligence
    edls: list[EDL] = []

    # Tier 5 — Topology
    zones: list[ZoneDefinition] = []

    # ── Counts ───────────────────────────────────────────────────────────────

    def rule_count(self) -> int:
        return len(self.rules)

    def nat_count(self) -> int:
        return len(self.nat_rules)

    def object_count(self) -> int:
        return (len(self.address_objects) + len(self.service_objects) +
                len(self.application_objects) + len(self.application_groups))

    def summary(self) -> str:
        return (
            f"{self.device} ({self.vendor}): "
            f"{self.rule_count()} security rules, {self.nat_count()} NAT rules, "
            f"{len(self.decryption_rules)} decryption rules, "
            f"{len(self.application_objects)} apps, {len(self.application_groups)} app groups, "
            f"{len(self.edls)} EDLs, {len(self.zones)} zones"
        )

    # ── Lookups ───────────────────────────────────────────────────────────────

    def find_rule(self, name: str) -> FirewallRule | None:
        return next((r for r in self.rules if r.name == name), None)

    def find_nat_rule(self, name: str) -> NATRule | None:
        return next((r for r in self.nat_rules if r.name == name), None)

    def find_address(self, name: str) -> AddressObject | None:
        return next((a for a in self.address_objects if a.name == name), None)

    def find_application(self, name: str) -> ApplicationObject | None:
        return next((a for a in self.application_objects if a.name == name), None)

    def find_zone(self, name: str) -> ZoneDefinition | None:
        return next((z for z in self.zones if z.name == name), None)
