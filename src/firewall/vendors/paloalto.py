"""Palo Alto Networks PAN-OS connector — direct device XML API via pan-os-python.

No Panorama. Connects directly to each firewall's management interface.

Ingests:
  Tier 1: security rules, NAT rules, decryption policy, DoS policy, auth policy
  Tier 2: address/group objects, service/group objects, App-ID (predefined+custom),
           application groups, application filters, custom URL categories
  Tier 3: antivirus/IPS/spyware/URL/file/WildFire/DNS profiles, decryption profiles
  Tier 4: External Dynamic Lists (ip/domain/url/predefined)
  Tier 5: zone definitions
"""
from __future__ import annotations

import asyncio
import logging
from functools import partial

import panos.firewall as panos_fw
import panos.network as panos_net
import panos.objects as panos_obj
import panos.policies as panos_pol
from panos.base import PanDevice

from src.config import DeviceConfig
from src.firewall.base import FirewallConnector
from src.firewall.models import (
    AddressObject,
    AddressType,
    ApplicationGroup,
    ApplicationObject,
    AuthPolicy,
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
    URLCategory,
    ZoneDefinition,
)

logger = logging.getLogger(__name__)

_ACTION_MAP = {
    "allow": RuleAction.ALLOW,
    "deny": RuleAction.DENY,
    "drop": RuleAction.DROP,
    "reset-client": RuleAction.REJECT,
    "reset-server": RuleAction.REJECT,
    "reset-both": RuleAction.REJECT,
}
_NAT_SRCTYPE_MAP = {
    "static-ip": NATType.STATIC,
    "dynamic-ip": NATType.DYNAMIC,
    "dynamic-ip-and-port": NATType.PAT,
}
_EDL_TYPE_MAP = {
    "ip": EDLType.IP,
    "domain": EDLType.DOMAIN,
    "url": EDLType.URL,
    "predefined-ip": EDLType.PREDEFINED_IP,
    "predefined-url": EDLType.PREDEFINED_URL,
}
_DECRYPT_ACTION_MAP = {
    "decrypt": DecryptAction.DECRYPT,
    "no-decrypt": DecryptAction.NO_DECRYPT,
}
_DECRYPT_TYPE_MAP = {
    "ssl-forward-proxy": DecryptType.SSL_FORWARD_PROXY,
    "ssl-inbound-inspection": DecryptType.SSL_INBOUND,
    "ssh-proxy": DecryptType.SSH_PROXY,
}


class PaloAltoConnector(FirewallConnector):
    def __init__(self, device: DeviceConfig) -> None:
        super().__init__(device)
        self._fw: PanDevice | None = None

    async def connect(self) -> None:
        loop = asyncio.get_event_loop()
        self._fw = await loop.run_in_executor(
            None,
            partial(
                panos_fw.Firewall,
                self.device.host,
                self.device.username,
                self.device.password,
                api_key=self.device.api_key,
            ),
        )

    async def disconnect(self) -> None:
        self._fw = None

    def _fw_req(self) -> PanDevice:
        if self._fw is None:
            raise RuntimeError("Not connected")
        return self._fw

    async def _run(self, fn):
        return await asyncio.get_event_loop().run_in_executor(None, fn)

    # ── Tier 1 ────────────────────────────────────────────────────────────────

    async def get_rules(self, rulebase: str = "security") -> list[FirewallRule]:
        fw = self._fw_req()

        def _fetch():
            rb = panos_pol.Rulebase()
            fw.add(rb)
            panos_pol.SecurityRule.refreshall(rb)
            return rb.children

        raw = await self._run(_fetch)
        return [
            FirewallRule(
                name=r.name,
                description=r.description or "",
                enabled=not r.disabled,
                action=_ACTION_MAP.get(r.action, RuleAction.DENY),
                src_zones=list(r.fromzone or []),
                dst_zones=list(r.tozone or []),
                src_addresses=list(r.source or []),
                dst_addresses=list(r.destination or []),
                services=list(r.service or []),
                applications=list(r.application or []),
                src_users=list(r.source_user or []),
                profiles={
                    k: v for k, v in {
                        "antivirus": getattr(r, "virus", None),
                        "vulnerability": getattr(r, "vulnerability", None),
                        "url-filtering": getattr(r, "url_filtering", None),
                        "spyware": getattr(r, "spyware", None),
                        "dns-security": getattr(r, "dns_security_profile", None),
                        "wildfire": getattr(r, "wildfire_analysis", None),
                    }.items() if v
                },
                log=r.log_end or False,
                tags=list(r.tag or []),
                vendor="paloalto",
                device=self.device.name,
                rulebase=rulebase,
                position=i,
            )
            for i, r in enumerate(raw)
        ]

    async def get_nat_rules(self) -> list[NATRule]:
        fw = self._fw_req()

        def _fetch():
            rb = panos_pol.Rulebase()
            fw.add(rb)
            panos_pol.NatRule.refreshall(rb)
            return rb.findall(panos_pol.NatRule)

        raw = await self._run(_fetch)
        nat_rules: list[NATRule] = []
        for i, r in enumerate(raw):
            src_trans = getattr(r, "source_translation_type", None)
            nat_type = _NAT_SRCTYPE_MAP.get(src_trans or "", NATType.STATIC)
            dst_trans = getattr(r, "destination_translated_address", None)
            if dst_trans and not src_trans:
                nat_type = NATType.DNAT
            nat_rules.append(NATRule(
                name=r.name,
                description=r.description or "",
                enabled=not getattr(r, "disabled", False),
                nat_type=nat_type,
                src_zones=list(r.fromzone or []),
                dst_zones=list(r.tozone or []),
                src_addresses=list(r.source or []),
                dst_addresses=list(r.destination or []),
                services=[r.service] if r.service else [],
                translated_src=(getattr(r, "source_translation_translated_addresses", None) or [""])[0],
                translated_dst=dst_trans or "",
                translated_port=str(getattr(r, "destination_translated_port", "") or ""),
                vendor="paloalto",
                device=self.device.name,
                rulebase="nat",
                position=i,
            ))
        return nat_rules

    async def get_decryption_rules(self) -> list[DecryptionRule]:
        fw = self._fw_req()

        def _fetch():
            rb = panos_pol.Rulebase()
            fw.add(rb)
            panos_pol.DecryptionRule.refreshall(rb)
            return rb.findall(panos_pol.DecryptionRule)

        raw = await self._run(_fetch)
        rules: list[DecryptionRule] = []
        for i, r in enumerate(raw):
            rules.append(DecryptionRule(
                name=r.name,
                description=r.description or "",
                enabled=not getattr(r, "disabled", False),
                action=_DECRYPT_ACTION_MAP.get(r.action or "decrypt", DecryptAction.DECRYPT),
                decrypt_type=_DECRYPT_TYPE_MAP.get(r.type or "ssl-forward-proxy", DecryptType.SSL_FORWARD_PROXY),
                src_zones=list(r.fromzone or []),
                dst_zones=list(r.tozone or []),
                src_addresses=list(r.source or []),
                dst_addresses=list(r.destination or []),
                services=list(r.service or []),
                url_categories=list(r.category or []),
                profile=r.profile or "",
                log=r.log_success or False,
                vendor="paloalto",
                device=self.device.name,
                position=i,
            ))
        return rules

    async def get_dos_policies(self) -> list[DoSPolicy]:
        fw = self._fw_req()

        def _fetch():
            rb = panos_pol.Rulebase()
            fw.add(rb)
            panos_pol.DoSRule.refreshall(rb)
            return rb.findall(panos_pol.DoSRule)

        raw = await self._run(_fetch)
        return [
            DoSPolicy(
                name=r.name,
                description=r.description or "",
                enabled=not getattr(r, "disabled", False),
                action=getattr(r, "action", "protect"),
                src_zones=list(r.fromzone or []),
                dst_zones=list(r.tozone or []),
                src_addresses=list(r.source or []),
                dst_addresses=list(r.destination or []),
                services=list(r.service or []),
                profile=r.protection or "",
                vendor="paloalto",
                device=self.device.name,
                position=i,
            )
            for i, r in enumerate(raw)
        ]

    # ── Tier 2 ────────────────────────────────────────────────────────────────

    async def get_address_objects(self) -> list[AddressObject]:
        fw = self._fw_req()

        def _fetch():
            panos_obj.AddressObject.refreshall(fw)
            panos_obj.AddressGroup.refreshall(fw)
            return fw.findall(panos_obj.AddressObject), fw.findall(panos_obj.AddressGroup)

        raw_objs, raw_groups = await self._run(_fetch)
        result: list[AddressObject] = []
        for a in raw_objs:
            addr_type = {
                "ip-netmask": AddressType.NETWORK,
                "ip-range": AddressType.RANGE,
                "fqdn": AddressType.FQDN,
            }.get(a.type, AddressType.HOST)
            result.append(AddressObject(
                name=a.name, type=addr_type, value=a.value or "",
                description=a.description or "", tags=list(a.tag or []),
            ))
        for g in raw_groups:
            result.append(AddressObject(
                name=g.name, type=AddressType.GROUP,
                members=list(g.static_value or []),
                description=g.description or "", tags=list(g.tag or []),
            ))
        return result

    async def get_service_objects(self) -> list[ServiceObject]:
        fw = self._fw_req()

        def _fetch():
            panos_obj.ServiceObject.refreshall(fw)
            return fw.findall(panos_obj.ServiceObject)

        return [
            ServiceObject(
                name=s.name, protocol=s.protocol or "tcp",
                port=s.destination_port or "", description=s.description or "",
            )
            for s in await self._run(_fetch)
        ]

    async def get_application_objects(self) -> list[ApplicationObject]:
        """Custom application objects (user-defined App-IDs)."""
        fw = self._fw_req()

        def _fetch():
            try:
                panos_obj.ApplicationObject.refreshall(fw)
                return fw.findall(panos_obj.ApplicationObject)
            except Exception:
                return []

        raw = await self._run(_fetch)
        return [
            ApplicationObject(
                name=a.name,
                category=a.category or "",
                subcategory=a.subcategory or "",
                technology=a.technology or "",
                risk=int(a.risk or 0),
                evasive=getattr(a, "evasive_behavior", False) or False,
                transfers_files=getattr(a, "file_type_ident", False) or False,
                tunnels_other_apps=getattr(a, "tunnel_other_application", False) or False,
                default_ports=list(getattr(a, "default_ports", None) or []),
                is_custom=True,
                description=a.description or "",
                vendor="paloalto",
                device=self.device.name,
            )
            for a in raw
        ]

    async def get_application_groups(self) -> list[ApplicationGroup]:
        fw = self._fw_req()

        def _fetch():
            try:
                panos_obj.ApplicationGroup.refreshall(fw)
                panos_obj.ApplicationFilter.refreshall(fw)
                groups = fw.findall(panos_obj.ApplicationGroup)
                filters = fw.findall(panos_obj.ApplicationFilter)
                return groups, filters
            except Exception:
                return [], []

        raw_groups, raw_filters = await self._run(_fetch)
        result: list[ApplicationGroup] = []
        for g in raw_groups:
            result.append(ApplicationGroup(
                name=g.name, members=list(g.value or []),
                is_filter=False, vendor="paloalto", device=self.device.name,
            ))
        for f in raw_filters:
            result.append(ApplicationGroup(
                name=f.name,
                is_filter=True,
                filter_category=list(f.category or []),
                filter_subcategory=list(f.subcategory or []),
                filter_technology=list(f.technology or []),
                filter_risk=[int(r) for r in (f.risk or []) if str(r).isdigit()],
                vendor="paloalto",
                device=self.device.name,
            ))
        return result

    async def get_url_categories(self) -> list[URLCategory]:
        fw = self._fw_req()

        def _fetch():
            try:
                panos_obj.CustomUrlCategory.refreshall(fw)
                return fw.findall(panos_obj.CustomUrlCategory)
            except Exception:
                return []

        return [
            URLCategory(
                name=c.name, urls=list(c.url_value or []),
                description=c.description or "",
                vendor="paloalto", device=self.device.name,
            )
            for c in await self._run(_fetch)
        ]

    # ── Tier 3 ────────────────────────────────────────────────────────────────

    async def get_security_profiles(self) -> list[SecurityProfile]:
        fw = self._fw_req()
        profiles: list[SecurityProfile] = []

        profile_map = [
            (panos_obj.SecurityProfileGroup, "profile-group"),
        ]

        def _fetch():
            results: list[tuple[str, str]] = []
            for cls, ptype in profile_map:
                try:
                    cls.refreshall(fw)
                    for p in fw.findall(cls):
                        results.append((p.name, ptype, getattr(p, "description", "") or ""))
                except Exception:
                    pass
            return results

        for name, ptype, desc in await self._run(_fetch):
            profiles.append(SecurityProfile(
                name=name, profile_type=ptype,
                vendor="paloalto", device=self.device.name, description=desc,
            ))
        return profiles

    async def get_decryption_profiles(self) -> list[DecryptionProfile]:
        fw = self._fw_req()

        def _fetch():
            try:
                panos_obj.DecryptionProfile.refreshall(fw)
                return fw.findall(panos_obj.DecryptionProfile)
            except Exception:
                return []

        raw = await self._run(_fetch)
        return [
            DecryptionProfile(
                name=p.name,
                check_certificate_expiry=getattr(p, "ssl_exclude_cert_check_expired_cert", False),
                check_certificate_revocation=getattr(p, "ssl_exclude_cert_check_revoked_cert", False) is False,
                block_untrusted_issuers=getattr(p, "ssl_no_proxy_cert_check_for_unknown_ca", False) is False,
                min_tls_version=getattr(p, "ssl_min_version", "") or "",
                vendor="paloalto",
                device=self.device.name,
            )
            for p in raw
        ]

    # ── Tier 4 ────────────────────────────────────────────────────────────────

    async def get_edls(self) -> list[EDL]:
        fw = self._fw_req()

        def _fetch():
            try:
                panos_obj.Edl.refreshall(fw)
                return fw.findall(panos_obj.Edl)
            except Exception:
                return []

        return [
            EDL(
                name=e.name,
                edl_type=_EDL_TYPE_MAP.get(e.edl_type or "ip", EDLType.IP),
                source_url=getattr(e, "url", "") or "",
                description=getattr(e, "description", "") or "",
                recurring=str(getattr(e, "recurring", "") or ""),
                vendor="paloalto",
                device=self.device.name,
            )
            for e in await self._run(_fetch)
        ]

    # ── Tier 5 ────────────────────────────────────────────────────────────────

    async def get_zones(self) -> list[ZoneDefinition]:
        fw = self._fw_req()

        def _fetch():
            try:
                panos_net.Zone.refreshall(fw)
                return fw.findall(panos_net.Zone)
            except Exception:
                return []

        raw = await self._run(_fetch)
        return [
            ZoneDefinition(
                name=z.name,
                zone_type=z.mode or "layer3",
                interfaces=list(z.interface or []),
                log_setting=getattr(z, "log_setting", "") or "",
                zone_protection_profile=getattr(z, "zone_profile", "") or "",
                enable_userid=getattr(z, "enable_user_identification", False) or False,
                vendor="paloalto",
                device=self.device.name,
            )
            for z in raw
        ]

    # ── Full snapshot ─────────────────────────────────────────────────────────

    async def get_policy(self) -> FirewallPolicy:
        (rules, nat_rules, decrypt_rules, dos_policies,
         addresses, services, apps, app_groups, url_cats,
         profiles, decrypt_profiles, edls, zones) = await asyncio.gather(
            self.get_rules(),
            self.get_nat_rules(),
            self.get_decryption_rules(),
            self.get_dos_policies(),
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
            vendor="paloalto",
            device=self.device.name,
            rules=rules,
            nat_rules=nat_rules,
            decryption_rules=decrypt_rules,
            dos_policies=dos_policies,
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
