"""AI-assisted translation service.

Generates vendor-specific translations for group policy objects and rules.
Uses the configured LLM (Ollama, OpenAI, or Anthropic) to produce translations
that are then surfaced as TranslationProposal records for human review.

Translation workflow:
  1. Gap detection identifies objects/rules with no approved translation for a vendor
  2. TranslationProposal records are created with proposed_translation={}
  3. This module fills those proposals in by calling the LLM
  4. A human reviews, modifies if needed, and approves — creating ObjectTranslation
     or RuleTranslation records used at push time
"""
from __future__ import annotations

import json
import logging
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from src.llm.factory import get_chat_llm

logger = logging.getLogger(__name__)

# ── Vendor profiles ───────────────────────────────────────────────────────────

VENDOR_PROFILES: dict[str, str] = {
    "paloalto": (
        "Palo Alto Networks PAN-OS. Uses App-ID for application identification, "
        "security profiles (antivirus, vulnerability, URL filtering, file blocking, "
        "data filtering, wildfire), zones, address objects (ip-netmask, ip-range, fqdn), "
        "service objects (tcp/udp with port ranges). Security rules reference application "
        "and service objects by name. NAT uses source/destination translation with "
        "interface or pool addresses."
    ),
    "cisco_asa": (
        "Cisco ASA. Uses access-lists with extended entries, network objects and object-groups "
        "(host, subnet, range), service objects (tcp/udp/icmp with port specs), NAT with "
        "auto-NAT and manual-NAT. Applications are not natively inspected by name — service "
        "objects or protocol/port pairs are used instead. Zones map to named interfaces."
    ),
    "cisco_ftd": (
        "Cisco FTD (Firepower Threat Defense). Uses access control policies with rules that "
        "reference network objects, port objects, application filters (Firepower app-id), "
        "URL categories, intrusion policies, file policies, and security intelligence. "
        "Zones map to security zones. NAT uses FTD NAT policy with auto and manual rules."
    ),
    "fortinet": (
        "Fortinet FortiGate. Uses firewall policies with address objects (ipmask, iprange, fqdn), "
        "service objects (tcp/udp/icmp), application control lists (app-id categories), "
        "UTM profiles (antivirus, IPS, web filter, application control, SSL inspection). "
        "Zones map to interfaces or VDOMs. NAT is configured within the firewall policy "
        "or with VIP objects for destination NAT."
    ),
}

# ── Object type hints ─────────────────────────────────────────────────────────

OBJECT_TRANSLATION_HINTS: dict[str, dict[str, str]] = {
    "address_object": {
        "paloalto": '{"type": "ip-netmask", "value": "10.0.0.0/24", "description": "..."}',
        "cisco_asa": '{"type": "network-object", "ip": "10.0.0.0", "mask": "255.255.255.0"}  or  {"type": "host", "ip": "10.0.0.1"}',
        "cisco_ftd": '{"type": "Network", "value": "10.0.0.0/24", "description": "..."}',
        "fortinet": '{"type": "ipmask", "subnet": "10.0.0.0 255.255.255.0"}  or  {"type": "iprange", "start-ip": "...", "end-ip": "..."}',
    },
    "service_object": {
        "paloalto": '{"protocol": "tcp", "port": "443", "description": "HTTPS"}',
        "cisco_asa": '{"protocol": "tcp", "eq": "443"}  or  {"protocol": "tcp", "range": "8080 8090"}',
        "cisco_ftd": '{"protocol": "TCP", "port": "443"}',
        "fortinet": '{"protocol": "TCP/UDP/SCTP", "tcp-portrange": "443", "udp-portrange": ""}',
    },
    "application": {
        "paloalto": '{"type": "app-id", "name": "ssl"}  (native App-ID)',
        "cisco_asa": '{"type": "service", "protocol": "tcp", "port": "443"}  (ASA has no App-ID; map to protocol/port)',
        "cisco_ftd": '{"type": "application_filter", "app_name": "SSL", "categories": [...]}',
        "fortinet": '{"type": "application", "id": 16354, "name": "HTTPS"}  (FortiGate app-id)',
    },
    "service_group": {
        "paloalto": '{"members": ["service-https", "service-http"]}',
        "cisco_asa": '{"type": "service-group", "members": [...]}',
        "cisco_ftd": '{"type": "PortObjectGroup", "members": [...]}',
        "fortinet": '{"type": "group", "member": [...]}',
    },
    "url_category": {
        "paloalto": '{"type": "url-category", "members": ["social-networking"]}',
        "cisco_asa": '{"note": "ASA does not natively support URL categories without WCCP/WSA integration"}',
        "cisco_ftd": '{"type": "url_category", "categories": ["Social Networking"]}',
        "fortinet": '{"type": "webfilter-category", "categories": [96]}',
    },
    "security_profile": {
        "paloalto": '{"antivirus": "strict", "vulnerability": "strict", "url-filtering": "default"}',
        "cisco_asa": '{"note": "No direct equivalent — reference inspect policy-map or Firepower service policy"}',
        "cisco_ftd": '{"intrusion_policy": "Balanced Security and Connectivity", "file_policy": "Block Malware All"}',
        "fortinet": '{"av-profile": "default", "ips-sensor": "default", "webfilter-profile": "default"}',
    },
    "edl": {
        "paloalto": '{"type": "ip", "url": "https://...", "repeat": "hourly"}',
        "cisco_asa": '{"note": "No native EDL — configure via dynamic ACL download or threat feed"}',
        "cisco_ftd": '{"type": "network", "feed_url": "https://...", "update_interval": 3600}',
        "fortinet": '{"type": "ip", "url": "https://...", "refresh_rate": 60}',
    },
}

# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a firewall policy translation engine. Your job is to convert vendor-agnostic \
policy definitions to vendor-specific representations. You understand the syntax, \
feature sets, and limitations of Palo Alto PAN-OS, Cisco ASA, Cisco FTD, and Fortinet \
FortiGate. You produce concise, accurate translations that would be usable by a push engine.

Always return valid JSON. Never return explanations outside the JSON structure. \
When a concept has no direct equivalent on the target vendor, use the closest approximation \
and note the limitation in the reasoning field.\
"""

# ── Core translation functions ────────────────────────────────────────────────


async def generate_object_translation(
    object_type: str,
    object_name: str,
    base_data: dict[str, Any],
    target_vendor: str,
    model_name: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Generate a vendor-specific translation for a policy object.

    Returns (translation_dict, reasoning_str).
    Raises ValueError if the LLM response cannot be parsed.
    """
    vendor_profile = VENDOR_PROFILES.get(target_vendor, target_vendor)
    hints = OBJECT_TRANSLATION_HINTS.get(object_type, {})
    hint = hints.get(target_vendor, "No specific example available — use best judgment.")

    user_prompt = f"""\
Translate the following vendor-agnostic {object_type} to {target_vendor} syntax.

Object name: {object_name}
Vendor-agnostic definition:
{json.dumps(base_data, indent=2)}

Target vendor: {target_vendor}
Vendor description: {vendor_profile}

Example {target_vendor} representation for this object type:
{hint}

Return ONLY this JSON structure (no other text):
{{
  "translation": {{...vendor-specific fields...}},
  "reasoning": "brief explanation of the mapping choices"
}}

If the object type has no direct equivalent on {target_vendor}, return the closest approximation \
and explain the limitation in reasoning.\
"""

    llm = get_chat_llm()
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=user_prompt),
    ]
    response = await llm.ainvoke(messages)
    raw = response.content if hasattr(response, "content") else str(response)
    return _parse_translation_response(raw)


async def generate_rule_translation(
    rule_id: int,
    rule_name: str,
    rule_type: str,
    base_rule: dict[str, Any],
    target_vendor: str,
    model_name: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Generate vendor-specific override fields for a group policy rule.

    Returns only the fields that differ from the base_rule — these are merged
    on top of base_rule at push time.
    Returns (translation_dict, reasoning_str).
    """
    vendor_profile = VENDOR_PROFILES.get(target_vendor, target_vendor)

    user_prompt = f"""\
Generate vendor-specific override fields for this group policy rule targeting {target_vendor}.

Rule name: {rule_name}
Rule type: {rule_type}
Vendor-agnostic base rule:
{json.dumps(base_rule, indent=2)}

Target vendor: {target_vendor}
Vendor description: {vendor_profile}

Return ONLY the fields that need to be different or overridden for {target_vendor}. \
The push engine merges base_rule + translation, so only include fields that must change. \
Return an empty "translation" dict if the base rule maps cleanly without modification.

Common reasons to override:
- The rule references App-IDs that don't exist on the target vendor (map to protocol/port)
- The rule uses security profiles that have different names on the target vendor
- The target vendor requires vendor-specific action values
- Zone names differ (though these are handled by DeviceZoneMapping separately)

Return ONLY this JSON structure (no other text):
{{
  "translation": {{...override fields only, empty if none needed...}},
  "reasoning": "brief explanation of why these fields need overriding"
}}\
"""

    llm = get_chat_llm()
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=user_prompt),
    ]
    response = await llm.ainvoke(messages)
    raw = response.content if hasattr(response, "content") else str(response)
    return _parse_translation_response(raw)


def _parse_translation_response(raw: str) -> tuple[dict[str, Any], str]:
    """Extract translation + reasoning from LLM response."""
    # Strip markdown code fences if present
    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        # Try to extract JSON from within the response
        import re
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
            except json.JSONDecodeError:
                raise ValueError(f"LLM returned unparseable JSON: {text[:200]}") from exc
        else:
            raise ValueError(f"LLM returned no JSON: {text[:200]}") from exc

    translation = parsed.get("translation", {})
    reasoning = parsed.get("reasoning", "")
    if not isinstance(translation, dict):
        translation = {}
    return translation, str(reasoning)
