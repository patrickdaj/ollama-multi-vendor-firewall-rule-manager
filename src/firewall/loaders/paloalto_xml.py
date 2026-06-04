"""Parse PAN-OS XML config export into a FirewallPolicy."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from src.firewall.models import (
    AddressObject,
    AddressType,
    ApplicationGroup,
    ApplicationObject,
    AuthPolicy,
    DecryptionProfile,
    ServiceGroup,
    URLCategory,
    DecryptAction,
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
    ServiceObject,
    ZoneDefinition,
)

_ACTION_MAP = {
    "allow": RuleAction.ALLOW, "deny": RuleAction.DENY,
    "drop": RuleAction.DROP, "reset-client": RuleAction.REJECT,
    "reset-server": RuleAction.REJECT, "reset-both": RuleAction.REJECT,
}


def _members(el: ET.Element | None, tag: str) -> list[str]:
    if el is None:
        return []
    return [m.text for m in el.findall(f"{tag}/member") if m.text]


def _text(el: ET.Element | None, path: str, default: str = "") -> str:
    if el is None:
        return default
    node = el.find(path)
    return (node.text or default) if node is not None else default


def load_paloalto_xml(path: Path, device: str) -> FirewallPolicy:
    tree = ET.parse(path)
    root = tree.getroot()

    vsys = root.find(".//vsys/entry[@name='vsys1']") or root.find(".//vsys/entry")
    if vsys is None:
        vsys = root

    # ── Zones ─────────────────────────────────────────────────────────────
    zones: list[ZoneDefinition] = []
    for z in vsys.findall("zone/entry"):
        ifaces = [m.text for m in z.findall(".//layer3/member") + z.findall(".//layer2/member") if m.text]
        zones.append(ZoneDefinition(
            name=z.get("name", ""),
            zone_type="layer3" if z.find("network/layer3") is not None else "layer2",
            interfaces=ifaces,
            enable_userid=_text(z, "enable-user-identification") == "yes",
            vendor="paloalto", device=device,
        ))

    # ── Address objects ────────────────────────────────────────────────────
    address_objects: list[AddressObject] = []
    for a in vsys.findall("address/entry"):
        name = a.get("name", "")
        desc = _text(a, "description")
        tags = [m.text for m in a.findall("tag/member") if m.text]
        if a.find("ip-netmask") is not None:
            address_objects.append(AddressObject(name=name, type=AddressType.NETWORK,
                                                  value=_text(a, "ip-netmask"), description=desc, tags=tags))
        elif a.find("ip-range") is not None:
            address_objects.append(AddressObject(name=name, type=AddressType.RANGE,
                                                  value=_text(a, "ip-range"), description=desc, tags=tags))
        elif a.find("fqdn") is not None:
            address_objects.append(AddressObject(name=name, type=AddressType.FQDN,
                                                  value=_text(a, "fqdn"), description=desc, tags=tags))

    for g in vsys.findall("address-group/entry"):
        dynamic_node = g.find("dynamic/filter")
        if dynamic_node is not None:
            address_objects.append(AddressObject(
                name=g.get("name", ""), type=AddressType.GROUP,
                is_dynamic=True, dynamic_filter=dynamic_node.text or "",
                description=_text(g, "description"),
                tags=[m.text for m in g.findall("tag/member") if m.text],
            ))
        else:
            members = _members(g, "static")
            address_objects.append(AddressObject(
                name=g.get("name", ""), type=AddressType.GROUP, members=members,
                description=_text(g, "description"),
                tags=[m.text for m in g.findall("tag/member") if m.text],
            ))

    # ── Service objects ────────────────────────────────────────────────────
    service_objects: list[ServiceObject] = []
    for s in vsys.findall("service/entry"):
        if s.find("protocol/icmp") is not None or s.find("protocol/icmp6") is not None:
            proto, port = "icmp", ""
        elif s.find("protocol/tcp") is not None:
            proto, port = "tcp", _text(s, "protocol/tcp/port")
        else:
            proto, port = "udp", _text(s, "protocol/udp/port")
        service_objects.append(ServiceObject(
            name=s.get("name", ""), protocol=proto,
            port=port, description=_text(s, "description"),
        ))

    # ── Service groups ────────────────────────────────────────────────────
    service_groups: list[ServiceGroup] = []
    for g in vsys.findall("service-group/entry"):
        service_groups.append(ServiceGroup(
            name=g.get("name", ""),
            members=[m.text for m in g.findall("members/member") if m.text],
            description=_text(g, "description"),
        ))

    # ── Decryption profiles ───────────────────────────────────────────────
    decryption_profiles: list[DecryptionProfile] = []
    for p in vsys.findall("profiles/decryption/entry"):
        fp = p.find("ssl-forward-proxy")
        inbound = p.find("ssl-inbound-inspection")
        decryption_profiles.append(DecryptionProfile(
            name=p.get("name", ""),
            description=_text(p, "description"),
            block_expired_certs=(
                _text(fp, "block-expired-certificate") == "yes" if fp is not None else False
            ),
            block_untrusted_issuers=(
                _text(fp, "block-untrusted-issuer") == "yes" if fp is not None else False
            ),
            min_tls_version=_text(p, "ssl-version/min-version"),
            vendor="paloalto", device=device,
        ))

    # ── Custom URL categories ─────────────────────────────────────────────
    url_categories: list[URLCategory] = []
    for c in vsys.findall("profiles/custom-url-category/entry"):
        url_categories.append(URLCategory(
            name=c.get("name", ""),
            description=_text(c, "description"),
            urls=[m.text for m in c.findall("list/member") if m.text],
            vendor="paloalto", device=device,
        ))

    # ── Application objects (user-defined / custom App-IDs) ───────────────
    application_objects: list[ApplicationObject] = []
    for a in vsys.findall("application/entry"):
        ports = [m.text for m in a.findall("default/port/member") if m.text]
        application_objects.append(ApplicationObject(
            name=a.get("name", ""),
            description=_text(a, "description"),
            category=_text(a, "category"),
            subcategory=_text(a, "subcategory"),
            technology=_text(a, "technology"),
            risk=int(_text(a, "risk", "0") or "0"),
            default_ports=ports,
            is_custom=True,
            vendor="paloalto", device=device,
        ))

    # ── Auth policies ─────────────────────────────────────────────────────
    auth_policies: list[AuthPolicy] = []
    for i, r in enumerate(vsys.findall("authentication/rules/entry")):
        auth_policies.append(AuthPolicy(
            name=r.get("name", ""),
            description=_text(r, "description"),
            src_zones=_members(r, "from"),
            dst_zones=_members(r, "to"),
            src_addresses=_members(r, "source"),
            dst_addresses=_members(r, "destination"),
            services=_members(r, "service"),
            authentication_profile=_text(r, "authentication-profile"),
            authentication_method=_text(r, "method"),
            vendor="paloalto", device=device, position=i,
        ))

    # ── Application groups and filters ────────────────────────────────────
    application_groups: list[ApplicationGroup] = []
    for g in vsys.findall("application-group/entry"):
        application_groups.append(ApplicationGroup(
            name=g.get("name", ""),
            members=[m.text for m in g.findall("members/member") if m.text],
            vendor="paloalto", device=device,
        ))
    for f in vsys.findall("application-filter/entry"):
        application_groups.append(ApplicationGroup(
            name=f.get("name", ""),
            is_filter=True,
            filter_risk=[int(m.text) for m in f.findall("risk/member") if m.text and m.text.isdigit()],
            filter_category=[m.text for m in f.findall("category/member") if m.text],
            filter_subcategory=[m.text for m in f.findall("subcategory/member") if m.text],
            vendor="paloalto", device=device,
        ))

    # ── EDLs ──────────────────────────────────────────────────────────────
    edls: list[EDL] = []
    edl_type_map = {"ip": EDLType.IP, "domain": EDLType.DOMAIN, "url": EDLType.URL,
                    "predefined-ip": EDLType.PREDEFINED_IP, "predefined-url": EDLType.PREDEFINED_URL}
    for e in vsys.findall("external-list/entry"):
        # type is a child element whose tag is the edl type
        for type_node in e.find("type") or []:
            edl_type = edl_type_map.get(type_node.tag, EDLType.IP)
            url = _text(type_node, "url")
            desc = _text(type_node, "description")
            recurring = "daily"
            for rec_node in type_node.find("recurring") or []:
                recurring = rec_node.tag
            edls.append(EDL(
                name=e.get("name", ""), edl_type=edl_type,
                source_url=url, description=desc, recurring=recurring,
                vendor="paloalto", device=device,
            ))
            break

    # ── Security rules ────────────────────────────────────────────────────
    rules: list[FirewallRule] = []
    for i, r in enumerate(vsys.findall("rulebase/security/rules/entry")):
        profiles: dict[str, str] = {}
        for tag_name, model_key in [
            ("virus", "antivirus"), ("vulnerability", "vulnerability"),
            ("spyware", "spyware"), ("url-filtering", "url-filtering"),
            ("dns-security", "dns-security"), ("wildfire-analysis", "wildfire"),
        ]:
            val = _text(r, f"profile-setting/profiles/{tag_name}/member")
            if val:
                profiles[model_key] = val
        group_profile = _text(r, "profile-setting/group/member")
        if group_profile:
            profiles["group"] = group_profile

        rules.append(FirewallRule(
            name=r.get("name", ""),
            description=_text(r, "description"),
            enabled=_text(r, "disabled", "no") == "no",
            action=_ACTION_MAP.get(_text(r, "action"), RuleAction.DENY),
            src_zones=_members(r, "from"),
            dst_zones=_members(r, "to"),
            src_addresses=_members(r, "source"),
            dst_addresses=_members(r, "destination"),
            services=_members(r, "service"),
            applications=_members(r, "application"),
            src_users=_members(r, "source-user"),
            profiles=profiles,
            log=_text(r, "log-end") == "yes",
            tags=[m.text for m in r.findall("tag/member") if m.text],
            vendor="paloalto", device=device, rulebase="security", position=i,
        ))

    # ── NAT rules ─────────────────────────────────────────────────────────
    nat_rules: list[NATRule] = []
    for i, r in enumerate(vsys.findall("rulebase/nat/rules/entry")):
        src_trans = r.find("source-translation")
        nat_type = NATType.PAT
        translated_src = ""
        if src_trans is not None:
            if src_trans.find("static-ip") is not None:
                nat_type = NATType.STATIC
                translated_src = _text(src_trans, "static-ip/translated-address")
            elif src_trans.find("dynamic-ip") is not None:
                nat_type = NATType.DYNAMIC
                translated_src = _members(src_trans, "dynamic-ip/translated-address")[0] if _members(src_trans, "dynamic-ip/translated-address") else ""
            elif src_trans.find("dynamic-ip-and-port") is not None:
                nat_type = NATType.PAT
                translated_src = _members(src_trans, "dynamic-ip-and-port/translated-address")[0] if _members(src_trans, "dynamic-ip-and-port/translated-address") else ""

        dst_trans = r.find("destination-translation")
        translated_dst = ""
        translated_port = ""
        if dst_trans is not None:
            if not src_trans:
                nat_type = NATType.DNAT
            translated_dst = _text(dst_trans, "translated-address")
            translated_port = _text(dst_trans, "translated-port")

        nat_rules.append(NATRule(
            name=r.get("name", ""), description=_text(r, "description"),
            enabled=_text(r, "disabled", "no") == "no",
            nat_type=nat_type,
            src_zones=_members(r, "from"), dst_zones=_members(r, "to"),
            src_addresses=_members(r, "source"), dst_addresses=_members(r, "destination"),
            services=[_text(r, "service")] if _text(r, "service") else [],
            translated_src=translated_src, translated_dst=translated_dst, translated_port=translated_port,
            vendor="paloalto", device=device, rulebase="nat", position=i,
        ))

    # ── Decryption rules ──────────────────────────────────────────────────
    decryption_rules: list[DecryptionRule] = []
    for i, r in enumerate(vsys.findall("rulebase/decryption/rules/entry")):
        action_str = _text(r, "action", "decrypt")
        action = DecryptAction.NO_DECRYPT if "no" in action_str else DecryptAction.DECRYPT
        type_node = r.find("type")
        dtype = DecryptType.SSL_FORWARD_PROXY
        if type_node is not None:
            if type_node.find("ssl-inbound-inspection") is not None:
                dtype = DecryptType.SSL_INBOUND
            elif type_node.find("ssh-proxy") is not None:
                dtype = DecryptType.SSH_PROXY

        decryption_rules.append(DecryptionRule(
            name=r.get("name", ""), description=_text(r, "description"),
            enabled=_text(r, "disabled", "no") == "no",
            action=action, decrypt_type=dtype,
            src_zones=_members(r, "from"), dst_zones=_members(r, "to"),
            src_addresses=_members(r, "source"), dst_addresses=_members(r, "destination"),
            services=_members(r, "service"),
            url_categories=_members(r, "category"),
            profile=_text(r, "profile"),
            log=_text(r, "log-success") == "yes",
            vendor="paloalto", device=device, position=i,
        ))

    # ── DoS rules ─────────────────────────────────────────────────────────
    dos_policies: list[DoSPolicy] = []
    for i, r in enumerate(vsys.findall("rulebase/dos/rules/entry")):
        dos_policies.append(DoSPolicy(
            name=r.get("name", ""), description=_text(r, "description"),
            enabled=_text(r, "disabled", "no") == "no",
            action=_text(r, "action", "protect"),
            src_zones=_members(r, "from"), dst_zones=_members(r, "to"),
            src_addresses=_members(r, "source"), dst_addresses=_members(r, "destination"),
            services=_members(r, "service"),
            profile=_text(r, "protection"),
            vendor="paloalto", device=device, position=i,
        ))

    return FirewallPolicy(
        vendor="paloalto", device=device,
        rules=rules, nat_rules=nat_rules,
        decryption_rules=decryption_rules, decryption_profiles=decryption_profiles,
        dos_policies=dos_policies, auth_policies=auth_policies,
        address_objects=address_objects, service_objects=service_objects,
        service_groups=service_groups,
        application_objects=application_objects, application_groups=application_groups,
        url_categories=url_categories, edls=edls, zones=zones,
    )
