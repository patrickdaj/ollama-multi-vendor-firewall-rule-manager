"""Cisco FTD connector via Firepower Management Center (FMC) REST API.

FMC is the device's native management plane — it is not an external platform.
There is no way to manage FTD policy without FMC; it is the device API.

Ingests:
  Tier 1: access control rules, NAT policy, SSL policy (decryption), identity policy (auth)
  Tier 2: network objects/groups, port objects/groups, application filters, URL objects
  Tier 3: intrusion policies (IPS), file & malware policies
  Tier 4: Security Intelligence feeds (IP/URL/DNS block lists)
  Tier 5: security zones
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
    AuthPolicy,
    DecryptionProfile,
    DecryptionRule,
    DecryptAction,
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
    URLCategory,
    ZoneDefinition,
)

logger = logging.getLogger(__name__)

_ACTION_MAP = {
    "ALLOW": RuleAction.ALLOW,
    "BLOCK": RuleAction.DENY,
    "BLOCK_RESET": RuleAction.REJECT,
    "TRUST": RuleAction.ALLOW,
    "MONITOR": RuleAction.ALLOW,
}
_NAT_TYPE_MAP = {"STATIC": NATType.STATIC, "DYNAMIC": NATType.DYNAMIC}


class CiscoFTDConnector(FirewallConnector):
    def __init__(self, device: DeviceConfig) -> None:
        super().__init__(device)
        self._client: httpx.AsyncClient | None = None
        self._token: str = ""
        self._domain_uuid: str = ""
        self._base = f"https://{device.host}/api/fmc_config/v1"

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(verify=self.device.verify_ssl, timeout=self.device.timeout)
        resp = await self._client.post(
            f"https://{self.device.host}/api/fmc_platform/v1/auth/generatetoken",
            auth=(self.device.username, self.device.password),
        )
        resp.raise_for_status()
        self._token = resp.headers["X-auth-access-token"]
        self._domain_uuid = resp.headers.get("DOMAIN_UUID", "default")

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _hdrs(self) -> dict:
        return {"X-auth-access-token": self._token, "Content-Type": "application/json"}

    async def _get_all(self, path: str) -> list[dict]:
        if self._client is None:
            raise RuntimeError("Not connected")
        items: list[dict] = []
        offset, limit = 0, 1000
        while True:
            url = f"{self._base}/domain/{self._domain_uuid}/{path}"
            resp = await self._client.get(url, headers=self._hdrs(), params={"offset": offset, "limit": limit})
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("items", [])
            items.extend(batch)
            if len(items) >= data.get("paging", {}).get("count", len(items)):
                break
            offset += limit
        return items

    async def _get_safe(self, path: str) -> list[dict]:
        try:
            return await self._get_all(path)
        except Exception as e:
            logger.debug("Skipped %s: %s", path, e)
            return []

    async def _get_acp_ids(self) -> list[dict]:
        return await self._get_all("policy/accesspolicies")

    # ── Tier 1 ────────────────────────────────────────────────────────────────

    async def get_rules(self, rulebase: str = "security") -> list[FirewallRule]:
        acps = await self._get_acp_ids()
        rules: list[FirewallRule] = []
        for policy in acps:
            acp_id = policy["id"]
            for i, r in enumerate(await self._get_all(f"policy/accesspolicies/{acp_id}/accessrules")):
                ips_policy = r.get("ipsPolicy", {}).get("name", "")
                file_policy = r.get("filePolicy", {}).get("name", "")
                apps = [a["name"] for a in r.get("applications", {}).get("applications", [])]
                app_filters = [f["name"] for f in r.get("applications", {}).get("applicationFilters", [])]
                url_cats = [c["name"] for c in r.get("urls", {}).get("urlCategoriesWithReputation", [])]
                users = [u["name"] for u in r.get("users", {}).get("objects", [])]
                rules.append(FirewallRule(
                    rule_id=r["id"],
                    name=r["name"],
                    enabled=r.get("enabled", True),
                    action=_ACTION_MAP.get(r.get("action", "BLOCK"), RuleAction.DENY),
                    src_zones=[z["name"] for z in r.get("sourceZones", {}).get("objects", [])],
                    dst_zones=[z["name"] for z in r.get("destinationZones", {}).get("objects", [])],
                    src_addresses=[a["name"] for a in r.get("sourceNetworks", {}).get("objects", [])],
                    dst_addresses=[a["name"] for a in r.get("destinationNetworks", {}).get("objects", [])],
                    services=[s["name"] for s in r.get("destinationPorts", {}).get("objects", [])],
                    applications=apps + app_filters,
                    url_categories=url_cats,
                    src_users=users,
                    profiles={k: v for k, v in {"ips": ips_policy, "file": file_policy}.items() if v},
                    log=r.get("logBegin", False) or r.get("logEnd", False),
                    vendor="cisco_ftd",
                    device=self.device.name,
                    rulebase=policy["name"],
                    position=i,
                ))
        return rules

    async def get_nat_rules(self) -> list[NATRule]:
        nat_rules: list[NATRule] = []
        for policy in await self._get_safe("policy/ftdnatpolicies"):
            pid = policy["id"]
            for rulebase, suffix in [
                ("auto-nat", f"policy/ftdnatpolicies/{pid}/autonatrules"),
                ("manual-nat", f"policy/ftdnatpolicies/{pid}/manualnatrules"),
            ]:
                for i, r in enumerate(await self._get_safe(suffix)):
                    nat_type = _NAT_TYPE_MAP.get(r.get("natType", "STATIC"), NATType.STATIC)
                    if r.get("translatedDestination") or r.get("interfaceInOriginalDestination"):
                        nat_type = NATType.DNAT
                    nat_rules.append(NATRule(
                        rule_id=r.get("id", ""),
                        name=r.get("description") or f"{rulebase}_{i}",
                        description=r.get("description", ""),
                        enabled=r.get("enabled", True),
                        nat_type=nat_type,
                        src_zones=[z["name"] for z in r.get("sourceInterface", {}).get("objects", [])],
                        dst_zones=[z["name"] for z in r.get("destinationInterface", {}).get("objects", [])],
                        src_addresses=[r.get("originalSource", {}).get("name", "")] if r.get("originalSource") else [],
                        dst_addresses=[r.get("originalDestination", {}).get("name", "")] if r.get("originalDestination") else [],
                        translated_src=r.get("translatedSource", {}).get("name", "") if r.get("translatedSource") else "",
                        translated_dst=r.get("translatedDestination", {}).get("name", "") if r.get("translatedDestination") else "",
                        vendor="cisco_ftd",
                        device=self.device.name,
                        rulebase=rulebase,
                        position=i,
                    ))
        return nat_rules

    async def get_decryption_rules(self) -> list[DecryptionRule]:
        rules: list[DecryptionRule] = []
        for policy in await self._get_safe("policy/sslpolicies"):
            pid = policy["id"]
            for i, r in enumerate(await self._get_safe(f"policy/sslpolicies/{pid}/sslrules")):
                action_str = r.get("action", "DECRYPT")
                action = DecryptAction.NO_DECRYPT if "NO" in action_str or "BLOCK" in action_str else DecryptAction.DECRYPT
                rules.append(DecryptionRule(
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
                    vendor="cisco_ftd",
                    device=self.device.name,
                    position=i,
                ))
        return rules

    async def get_auth_policies(self) -> list[AuthPolicy]:
        policies: list[AuthPolicy] = []
        for policy in await self._get_safe("policy/identitypolicies"):
            pid = policy["id"]
            for i, r in enumerate(await self._get_safe(f"policy/identitypolicies/{pid}/identityrules")):
                policies.append(AuthPolicy(
                    rule_id=r.get("id", ""),
                    name=r.get("name", f"identity-rule-{i}"),
                    enabled=r.get("enabled", True),
                    src_zones=[z["name"] for z in r.get("sourceZones", {}).get("objects", [])],
                    src_addresses=[a["name"] for a in r.get("sourceNetworks", {}).get("objects", [])],
                    authentication_method=r.get("action", ""),
                    vendor="cisco_ftd",
                    device=self.device.name,
                    position=i,
                ))
        return policies

    # ── Tier 2 ────────────────────────────────────────────────────────────────

    async def get_address_objects(self) -> list[AddressObject]:
        objects: list[AddressObject] = []
        for o in await self._get_safe("object/networks"):
            val = o.get("value", "")
            addr_type = AddressType.NETWORK if "/" in val else AddressType.HOST
            objects.append(AddressObject(name=o["name"], type=addr_type, value=val,
                                         description=o.get("description", "")))
        for g in await self._get_safe("object/networkgroups"):
            members = [m.get("name", "") for m in g.get("objects", [])]
            objects.append(AddressObject(name=g["name"], type=AddressType.GROUP, members=members,
                                         description=g.get("description", "")))
        return objects

    async def get_service_objects(self) -> list[ServiceObject]:
        objects: list[ServiceObject] = []
        for o in await self._get_safe("object/protocolportobjects"):
            objects.append(ServiceObject(
                name=o["name"],
                protocol=o.get("protocol", "tcp").lower(),
                port=o.get("port", ""),
            ))
        return objects

    async def get_application_groups(self) -> list[ApplicationGroup]:
        groups: list[ApplicationGroup] = []
        for f in await self._get_safe("object/applicationfilters"):
            groups.append(ApplicationGroup(
                name=f["name"],
                is_filter=True,
                filter_category=[c["name"] for c in f.get("categories", [])],
                filter_risk=[r["id"] for r in f.get("risks", [])],
                vendor="cisco_ftd",
                device=self.device.name,
                description=f.get("description", ""),
            ))
        return groups

    async def get_url_categories(self) -> list[URLCategory]:
        categories: list[URLCategory] = []
        for o in await self._get_safe("object/urls"):
            categories.append(URLCategory(
                name=o["name"],
                urls=[o.get("url", "")],
                description=o.get("description", ""),
                vendor="cisco_ftd",
                device=self.device.name,
            ))
        return categories

    # ── Tier 3 ────────────────────────────────────────────────────────────────

    async def get_security_profiles(self) -> list[SecurityProfile]:
        profiles: list[SecurityProfile] = []
        for p in await self._get_safe("policy/intrusionpolicies"):
            profiles.append(SecurityProfile(name=p["name"], profile_type="ips",
                                            vendor="cisco_ftd", device=self.device.name,
                                            description=p.get("description", "")))
        for p in await self._get_safe("policy/filepolicies"):
            profiles.append(SecurityProfile(name=p["name"], profile_type="file-policy",
                                            vendor="cisco_ftd", device=self.device.name,
                                            description=p.get("description", "")))
        return profiles

    async def get_decryption_profiles(self) -> list[DecryptionProfile]:
        profiles: list[DecryptionProfile] = []
        for p in await self._get_safe("policy/sslpolicies"):
            profiles.append(DecryptionProfile(
                name=p["name"],
                description=p.get("description", ""),
                vendor="cisco_ftd",
                device=self.device.name,
            ))
        return profiles

    # ── Tier 4 ────────────────────────────────────────────────────────────────

    async def get_edls(self) -> list[EDL]:
        """FTD Security Intelligence feeds."""
        edls: list[EDL] = []
        for feed_type, edl_type in [
            ("object/siurllists", EDLType.URL),
            ("object/sifqdnlists", EDLType.DOMAIN),
        ]:
            for f in await self._get_safe(feed_type):
                edls.append(EDL(
                    name=f["name"],
                    edl_type=edl_type,
                    description=f.get("description", ""),
                    is_predefined=f.get("readOnly", False),
                    vendor="cisco_ftd",
                    device=self.device.name,
                ))
        return edls

    # ── Tier 5 ────────────────────────────────────────────────────────────────

    async def get_zones(self) -> list[ZoneDefinition]:
        return [
            ZoneDefinition(
                name=z["name"],
                zone_type=z.get("interfaceMode", "ROUTED").lower(),
                description=z.get("description", ""),
                vendor="cisco_ftd",
                device=self.device.name,
            )
            for z in await self._get_safe("object/securityzones")
        ]

    # ── Full snapshot ─────────────────────────────────────────────────────────

    async def get_policy(self) -> FirewallPolicy:
        (rules, nat_rules, decrypt_rules, auth_policies,
         addresses, services, app_groups, url_cats,
         profiles, decrypt_profiles, edls, zones) = await asyncio.gather(
            self.get_rules(),
            self.get_nat_rules(),
            self.get_decryption_rules(),
            self.get_auth_policies(),
            self.get_address_objects(),
            self.get_service_objects(),
            self.get_application_groups(),
            self.get_url_categories(),
            self.get_security_profiles(),
            self.get_decryption_profiles(),
            self.get_edls(),
            self.get_zones(),
        )
        policy = FirewallPolicy(
            vendor="cisco_ftd",
            device=self.device.name,
            rules=rules,
            nat_rules=nat_rules,
            decryption_rules=decrypt_rules,
            auth_policies=auth_policies,
            address_objects=addresses,
            service_objects=services,
            application_groups=app_groups,
            url_categories=url_cats,
            security_profiles=profiles,
            decryption_profiles=decrypt_profiles,
            edls=edls,
            zones=zones,
        )
        logger.info(policy.summary())
        return policy
