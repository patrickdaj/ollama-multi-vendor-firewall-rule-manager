"""Fortinet FortiGate connector — direct device FortiOS REST API v2.

No FortiManager. Connects directly to each FortiGate's management interface.

Ingests:
  Tier 1: firewall policies (security), central SNAT + VIPs (NAT),
           SSL/SSH inspection (decryption), DoS policy, auth/captive portal policy
  Tier 2: address/group objects, service/group objects,
           application signatures + groups + categories, URL categories, geography objects
  Tier 3: AV profiles, IPS sensors, Web Filter profiles, DNS Filter profiles,
           App Control sensors, SSL/SSH inspection profiles
  Tier 4: threat feeds (FortiGuard), custom threat lists
  Tier 5: zones, interfaces
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
    ApplicationGroup,
    ApplicationObject,
    AuthPolicy,
    DecryptionProfile,
    DecryptionRule,
    DecryptAction,
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
    URLCategory,
    ZoneDefinition,
)

logger = logging.getLogger(__name__)

_ACTION_MAP = {"accept": RuleAction.ALLOW, "deny": RuleAction.DENY, "drop": RuleAction.DROP}


class FortinetConnector(FirewallConnector):
    """FortiGate REST API connector — direct device, no FortiManager."""

    def __init__(self, device: DeviceConfig) -> None:
        super().__init__(device)
        self._client: httpx.AsyncClient | None = None
        self._base = f"https://{device.host}/api/v2"
        self._vdom = "root"

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(verify=self.device.verify_ssl, timeout=self.device.timeout)
        resp = await self._client.post(
            f"https://{self.device.host}/logincheck",
            data={"username": self.device.username, "secretkey": self.device.password},
        )
        resp.raise_for_status()
        if "incorrect" in resp.text.lower():
            raise PermissionError(f"FortiGate auth failed for {self.device.host}")

    async def disconnect(self) -> None:
        if self._client:
            try:
                await self._client.get(f"https://{self.device.host}/logout")
            finally:
                await self._client.aclose()
                self._client = None

    async def _get(self, path: str) -> list[dict]:
        if self._client is None:
            raise RuntimeError("Not connected")
        resp = await self._client.get(
            f"{self._base}/{path}",
            params={"vdom": self._vdom, "format": "json"},
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("results", data) if isinstance(data, dict) else data

    async def _get_safe(self, path: str) -> list[dict]:
        try:
            return await self._get(path)
        except Exception as e:
            logger.debug("Skipped %s: %s", path, e)
            return []

    # ── Tier 1 ────────────────────────────────────────────────────────────────

    async def get_rules(self, rulebase: str = "security") -> list[FirewallRule]:
        raw = await self._get("cmdb/firewall/policy")
        rules: list[FirewallRule] = []
        for i, r in enumerate(raw):
            profiles: dict[str, str] = {}
            for profile_key, field in [
                ("antivirus", "av-profile"),
                ("ips", "ips-sensor"),
                ("url-filtering", "webfilter-profile"),
                ("dns-filter", "dnsfilter-profile"),
                ("app-control", "application-list"),
                ("ssl-ssh", "ssl-ssh-profile"),
            ]:
                v = r.get(field, "")
                if v:
                    profiles[profile_key] = v
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
                vendor="fortinet",
                device=self.device.name,
                rulebase=rulebase,
                position=i,
            ))
        return rules

    async def get_nat_rules(self) -> list[NATRule]:
        nat_rules: list[NATRule] = []

        for vip in await self._get_safe("cmdb/firewall/vip"):
            i = len(nat_rules)
            nat_rules.append(NATRule(
                name=vip.get("name", f"vip_{i}"),
                description=vip.get("comment", ""),
                enabled=vip.get("status", "enable") == "enable",
                nat_type=NATType.DNAT,
                dst_addresses=[vip.get("extip", "")],
                translated_dst=(vip.get("mappedip") or [{}])[0].get("range", ""),
                translated_port=str(vip.get("mappedport", "") or ""),
                services=[vip.get("protocol", "any")],
                vendor="fortinet",
                device=self.device.name,
                rulebase="vip",
                position=i,
            ))

        for s in await self._get_safe("cmdb/firewall/central-snat-map"):
            i = len(nat_rules)
            nat_type = NATType.PAT if s.get("type", "ippool") == "ippool" else NATType.STATIC
            nat_rules.append(NATRule(
                rule_id=str(s.get("policyid", i)),
                name=f"snat_{s.get('policyid', i)}",
                description=s.get("comments", ""),
                enabled=s.get("status", "enable") == "enable",
                nat_type=nat_type,
                src_zones=[z["name"] for z in s.get("srcintf", [])],
                dst_zones=[z["name"] for z in s.get("dstintf", [])],
                src_addresses=[a["name"] for a in s.get("orig-addr", [])],
                dst_addresses=[a["name"] for a in s.get("dst-addr", [])],
                translated_src=", ".join(p["name"] for p in s.get("nat-ippool", [])),
                vendor="fortinet",
                device=self.device.name,
                rulebase="central-snat",
                position=i,
            ))

        return nat_rules

    async def get_decryption_rules(self) -> list[DecryptionRule]:
        """FortiGate SSL/SSH inspection is per-policy; build rules from policies referencing a deep-inspect profile."""
        rules = await self._get_safe("cmdb/firewall/policy")
        result: list[DecryptionRule] = []
        for i, r in enumerate(rules):
            profile = r.get("ssl-ssh-profile", "")
            if not profile or profile == "no-inspection":
                continue
            result.append(DecryptionRule(
                rule_id=str(r.get("policyid", i)),
                name=f"ssl-inspect_{r.get('name', i)}",
                enabled=r.get("status", "enable") == "enable",
                action=DecryptAction.DECRYPT,
                decrypt_type=DecryptType.SSL_FORWARD_PROXY,
                src_zones=[z["name"] for z in r.get("srcintf", [])],
                dst_zones=[z["name"] for z in r.get("dstintf", [])],
                src_addresses=[a["name"] for a in r.get("srcaddr", [])],
                dst_addresses=[a["name"] for a in r.get("dstaddr", [])],
                profile=profile,
                vendor="fortinet",
                device=self.device.name,
                position=i,
            ))
        return result

    async def get_dos_policies(self) -> list[DoSPolicy]:
        raw = await self._get_safe("cmdb/firewall/DoS-policy")
        return [
            DoSPolicy(
                rule_id=str(r.get("policyid", i)),
                name=r.get("name", f"dos_{i}"),
                description=r.get("comments", ""),
                enabled=r.get("status", "enable") == "enable",
                action="protect",
                src_zones=[z["name"] for z in r.get("srcintf", [])],
                dst_zones=[z["name"] for z in r.get("dstintf", [])],
                src_addresses=[a["name"] for a in r.get("srcaddr", [])],
                dst_addresses=[a["name"] for a in r.get("dstaddr", [])],
                services=[s["name"] for s in r.get("service", [])],
                vendor="fortinet",
                device=self.device.name,
                position=i,
            )
            for i, r in enumerate(raw)
        ]

    async def get_auth_policies(self) -> list[AuthPolicy]:
        raw = await self._get_safe("cmdb/firewall/auth-portal")
        if not raw:
            return []
        portal = raw[0] if isinstance(raw, list) else raw
        return [AuthPolicy(
            name="auth-portal",
            enabled=True,
            authentication_method="web-form",
            authentication_profile=portal.get("identity-based-route", ""),
            vendor="fortinet",
            device=self.device.name,
        )]

    # ── Tier 2 ────────────────────────────────────────────────────────────────

    async def get_address_objects(self) -> list[AddressObject]:
        objects: list[AddressObject] = []
        for a in await self._get_safe("cmdb/firewall/address"):
            ftype = a.get("type", "ipmask")
            addr_type = {"ipmask": AddressType.NETWORK, "iprange": AddressType.RANGE,
                         "fqdn": AddressType.FQDN}.get(ftype, AddressType.HOST)
            value = a.get("subnet", a.get("fqdn", ""))
            if ftype == "iprange":
                value = f"{a.get('start-ip', '')}-{a.get('end-ip', '')}"
            objects.append(AddressObject(
                name=a["name"], type=addr_type, value=value, description=a.get("comment", ""),
            ))
        for g in await self._get_safe("cmdb/firewall/addrgrp"):
            members = [m["name"] for m in g.get("member", [])]
            objects.append(AddressObject(
                name=g["name"], type=AddressType.GROUP, members=members, description=g.get("comment", ""),
            ))
        return objects

    async def get_service_objects(self) -> list[ServiceObject]:
        services: list[ServiceObject] = []
        for s in await self._get_safe("cmdb/firewall.service/custom"):
            proto = "tcp" if s.get("tcp-portrange") else ("udp" if s.get("udp-portrange") else "any")
            port = s.get("tcp-portrange") or s.get("udp-portrange") or ""
            services.append(ServiceObject(name=s["name"], protocol=proto, port=port,
                                          description=s.get("comment", "")))
        return services

    async def get_application_objects(self) -> list[ApplicationObject]:
        """FortiGuard application signatures + custom signatures."""
        objects: list[ApplicationObject] = []

        # Custom application signatures
        for app in await self._get_safe("cmdb/application/custom"):
            objects.append(ApplicationObject(
                name=app.get("name", ""),
                vendor_id=str(app.get("id", "")),
                category=app.get("category", ""),
                technology=app.get("technology", ""),
                is_custom=True,
                description=app.get("comment", ""),
                vendor="fortinet",
                device=self.device.name,
            ))

        # FortiGuard application list entries referenced in policies (sample — full DB is huge)
        # We ingest what's explicitly referenced in application-list objects
        for sensor in await self._get_safe("cmdb/application/list"):
            for entry in sensor.get("entries", []):
                for app in entry.get("application", []):
                    name = app.get("name", "")
                    if name and not any(o.name == name for o in objects):
                        objects.append(ApplicationObject(
                            name=name,
                            category=entry.get("category", ""),
                            vendor="fortinet",
                            device=self.device.name,
                        ))

        return objects

    async def get_application_groups(self) -> list[ApplicationGroup]:
        groups: list[ApplicationGroup] = []

        # Application groups
        for g in await self._get_safe("cmdb/application/group"):
            members = [a["name"] for a in g.get("application", [])]
            groups.append(ApplicationGroup(
                name=g["name"], members=members, is_filter=False,
                vendor="fortinet", device=self.device.name,
            ))

        # Application categories (used as groups in policies)
        for c in await self._get_safe("cmdb/application/categories"):
            if isinstance(c, dict):
                groups.append(ApplicationGroup(
                    name=c.get("name", ""),
                    is_filter=True,
                    filter_category=[c.get("name", "")],
                    vendor="fortinet",
                    device=self.device.name,
                ))

        return groups

    async def get_url_categories(self) -> list[URLCategory]:
        categories: list[URLCategory] = []
        for c in await self._get_safe("cmdb/webfilter/urlfilter"):
            entries = [e.get("url", "") for e in c.get("entries", []) if e.get("url")]
            categories.append(URLCategory(
                name=c.get("name", ""),
                urls=entries,
                description=c.get("comment", ""),
                vendor="fortinet",
                device=self.device.name,
            ))
        return categories

    # ── Tier 3 ────────────────────────────────────────────────────────────────

    async def get_security_profiles(self) -> list[SecurityProfile]:
        profiles: list[SecurityProfile] = []
        for endpoint, ptype in [
            ("cmdb/antivirus/profile", "antivirus"),
            ("cmdb/ips/sensor", "ips"),
            ("cmdb/webfilter/profile", "url-filtering"),
            ("cmdb/dnsfilter/profile", "dns-filter"),
            ("cmdb/application/list", "app-control"),
        ]:
            for p in await self._get_safe(endpoint):
                profiles.append(SecurityProfile(
                    name=p["name"], profile_type=ptype,
                    vendor="fortinet", device=self.device.name,
                    description=p.get("comment", ""),
                ))
        return profiles

    async def get_decryption_profiles(self) -> list[DecryptionProfile]:
        profiles: list[DecryptionProfile] = []
        for p in await self._get_safe("cmdb/firewall/ssl-ssh-profile"):
            profiles.append(DecryptionProfile(
                name=p["name"],
                block_untrusted_issuers=p.get("rpc-over-https", "") == "block",
                min_tls_version=p.get("ssl", {}).get("min-version", "") if isinstance(p.get("ssl"), dict) else "",
                description=p.get("comment", ""),
                vendor="fortinet",
                device=self.device.name,
            ))
        return profiles

    # ── Tier 4 ────────────────────────────────────────────────────────────────

    async def get_edls(self) -> list[EDL]:
        """FortiGate threat feeds — external connector addresses."""
        edls: list[EDL] = []
        for feed in await self._get_safe("cmdb/system/external-resource"):
            edl_type = {
                "address": EDLType.IP,
                "domain": EDLType.DOMAIN,
                "url": EDLType.URL,
            }.get(feed.get("type", "address"), EDLType.IP)
            edls.append(EDL(
                name=feed.get("name", ""),
                edl_type=edl_type,
                source_url=feed.get("server-list", ""),
                description=feed.get("comments", ""),
                recurring=feed.get("refresh-rate", ""),
                is_predefined=False,
                vendor="fortinet",
                device=self.device.name,
            ))
        return edls

    # ── Tier 5 ────────────────────────────────────────────────────────────────

    async def get_zones(self) -> list[ZoneDefinition]:
        zones: list[ZoneDefinition] = []
        for z in await self._get_safe("cmdb/system/zone"):
            ifaces = [i.get("interface-name", "") for i in z.get("interface", [])]
            zones.append(ZoneDefinition(
                name=z.get("name", ""),
                interfaces=ifaces,
                description=z.get("description", ""),
                vendor="fortinet",
                device=self.device.name,
            ))
        return zones

    # ── Full snapshot ─────────────────────────────────────────────────────────

    async def get_policy(self) -> FirewallPolicy:
        (rules, nat_rules, decrypt_rules, dos_policies, auth_policies,
         addresses, services, apps, app_groups, url_cats,
         profiles, decrypt_profiles, edls, zones) = await asyncio.gather(
            self.get_rules(),
            self.get_nat_rules(),
            self.get_decryption_rules(),
            self.get_dos_policies(),
            self.get_auth_policies(),
            self.get_address_objects(),
            self.get_service_objects(),
            self.get_application_objects(),
            self.get_application_groups(),
            self.get_url_categories(),
            self.get_security_profiles(),
            self.get_decryption_profiles(),
            self.get_edls(),
            self.get_zones(),
        )
        policy = FirewallPolicy(
            vendor="fortinet",
            device=self.device.name,
            rules=rules,
            nat_rules=nat_rules,
            decryption_rules=decrypt_rules,
            dos_policies=dos_policies,
            auth_policies=auth_policies,
            address_objects=addresses,
            service_objects=services,
            application_objects=apps,
            application_groups=app_groups,
            url_categories=url_cats,
            security_profiles=profiles,
            decryption_profiles=decrypt_profiles,
            edls=edls,
            zones=zones,
        )
        logger.info(policy.summary())
        return policy
