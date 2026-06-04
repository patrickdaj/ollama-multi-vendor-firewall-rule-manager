"""AI-assisted policy import: vendor-specific → vendor-agnostic conversion.

When a device is onboarded its policy is stored as observed state (PolicyObject rows
in vendor-specific form). This module converts that observed state into the
vendor-agnostic desired-state format (base_rule / base_data) so it can be
reviewed and then promoted to group policy.

Workflow:
  1. Read device's latest snapshot (PolicyObject rows)
  2. For each rule/object call the LLM to produce a vendor-agnostic form
  3. Return staged candidates with {vendor_data, proposed_base, reasoning}
  4. Human reviews, edits if needed, and confirms
  5. Confirmed items are written as GroupPolicyRule / GroupPolicyObject rows

Performance note: simple object types (address, service, url_category, edl,
service_group) are normalized by fast rule-based paths — no LLM call. Only
security_rule and nat_rule go to the LLM, and those run concurrently via
asyncio.gather with a semaphore to avoid saturating Ollama.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from src.llm.factory import get_chat_llm

logger = logging.getLogger(__name__)

# Local Ollama processes one request at a time — concurrent calls queue inside
# the server and responses can come back empty under load. Keep sequential.
_LLM_SEMAPHORE = asyncio.Semaphore(1)

SYSTEM_PROMPT = """\
You are a firewall policy normalization engine. Your job is to convert vendor-specific \
firewall configuration into a vendor-agnostic representation that can be applied across \
multiple vendors. You understand Palo Alto PAN-OS, Cisco ASA, Cisco FTD, and Fortinet \
FortiGate. Produce concise, accurate vendor-agnostic JSON.

Always return valid JSON. Never return explanations outside the JSON structure.\
"""

# ── Schema guidance ───────────────────────────────────────────────────────────

BASE_RULE_SCHEMAS: dict[str, str] = {
    "security_rule": """\
{
  "action": "allow | deny | drop | reset-client | reset-server",
  "src_zones": ["zone-name", ...],
  "dst_zones": ["zone-name", ...],
  "src_addresses": ["address-object-name-or-any", ...],
  "dst_addresses": ["address-object-name-or-any", ...],
  "services": ["service-object-name-or-application-default-or-any", ...],
  "applications": ["app-id-name", ...],
  "profiles": {"antivirus": "...", "vulnerability": "...", "url-filtering": "..."},
  "log": true,
  "description": "..."
}""",
    "nat_rule": """\
{
  "nat_type": "ipv4 | ipv6",
  "src_zones": ["zone-name", ...],
  "dst_zones": ["zone-name", ...],
  "src_addresses": ["address-object-name-or-any", ...],
  "dst_addresses": ["address-object-name-or-any", ...],
  "translated_src": "address-object-name or null",
  "translated_dst": "address-object-name or null",
  "translated_dst_port": "port or null",
  "description": "..."
}""",
    "address_object": """\
{
  "type": "ip-netmask | ip-range | fqdn",
  "value": "10.0.0.0/24  or  10.0.0.1-10.0.0.10  or  example.com",
  "description": "..."
}""",
    "service_object": """\
{
  "protocol": "tcp | udp | icmp | any",
  "port": "443  or  8080-8090  or  any",
  "description": "..."
}""",
    "service_group": """\
{
  "members": ["service-object-name", ...],
  "description": "..."
}""",
    "application": """\
{
  "vendor_app_id": "vendor-specific app identifier",
  "canonical_name": "common name like ssl, http, rdp, ssh",
  "protocol": "tcp | udp",
  "default_ports": ["443", ...],
  "description": "..."
}""",
    "url_category": """\
{
  "categories": ["category-name", ...],
  "description": "..."
}""",
    "edl": """\
{
  "type": "ip | url | domain",
  "url": "https://...",
  "refresh_interval_minutes": 60,
  "description": "..."
}""",
}


# ── Fast rule-based paths (no LLM) ───────────────────────────────────────────

def _fast_normalize_object(
    object_type: str,
    vendor_data: dict[str, Any],
) -> dict[str, Any] | None:
    """Rule-based normalization for deterministic object types.

    Returns {"base_data": {...}, "reasoning": "..."} or None when the type
    requires LLM assistance.
    """
    if object_type == "address_object":
        addr_type = vendor_data.get("type", vendor_data.get("addr_type", "")).lower()
        value = str(
            vendor_data.get("value")
            or vendor_data.get("ip_netmask")
            or vendor_data.get("ip_range")
            or vendor_data.get("fqdn")
            or vendor_data.get("subnet")
            or ""
        )
        # Wildcard addresses: no IP value, let LLM handle.
        if "wildcard" in addr_type:
            return None
        # Address groups: fast-path as group type (members list).
        if "group" in addr_type or "addrgrp" in addr_type:
            members = vendor_data.get("members", vendor_data.get("member", []))
            if isinstance(members, list):
                return {
                    "base_data": {
                        "type": "group",
                        "members": members,
                        "description": vendor_data.get("description", ""),
                    },
                    "reasoning": "Address group — member list preserved as-is.",
                }
            return None
        if not value:
            return None
        if "range" in addr_type or ("-" in value and "/" not in value):
            canonical_type = "ip-range"
        elif "fqdn" in addr_type or (
            value and not value.replace(".", "").replace("/", "").replace("-", "").isdigit()
        ):
            canonical_type = "fqdn"
        else:
            canonical_type = "ip-netmask"
        return {
            "base_data": {
                "type": canonical_type,
                "value": value,
                "description": vendor_data.get("description", ""),
            },
            "reasoning": "Direct field mapping — no LLM required.",
        }

    if object_type == "service_object":
        proto = vendor_data.get("protocol", vendor_data.get("proto", "tcp")).lower()
        port = str(
            vendor_data.get("destination_port")
            or vendor_data.get("dst_port")
            or vendor_data.get("port")
            or "any"
        )
        return {
            "base_data": {
                "protocol": proto if proto in ("tcp", "udp", "icmp") else "any",
                "port": port,
                "description": vendor_data.get("description", ""),
            },
            "reasoning": "Direct field mapping — no LLM required.",
        }

    if object_type == "service_group":
        members = vendor_data.get("members", vendor_data.get("member", []))
        if isinstance(members, str):
            members = [members]
        return {
            "base_data": {
                "members": list(members),
                "description": vendor_data.get("description", ""),
            },
            "reasoning": "Member list copy — no LLM required.",
        }

    if object_type == "url_category":
        cats = vendor_data.get("categories", vendor_data.get("category", []))
        if isinstance(cats, str):
            cats = [cats]
        return {
            "base_data": {
                "categories": list(cats),
                "description": vendor_data.get("description", ""),
            },
            "reasoning": "Category list copy — no LLM required.",
        }

    if object_type == "edl":
        return {
            "base_data": {
                "type": vendor_data.get("type", "ip").lower(),
                "url": str(vendor_data.get("url", vendor_data.get("location", ""))),
                "refresh_interval_minutes": int(vendor_data.get("refresh_interval", 60)),
                "description": vendor_data.get("description", ""),
            },
            "reasoning": "Direct field mapping — no LLM required.",
        }

    return None


# ── LLM-backed normalization ──────────────────────────────────────────────────

async def _invoke_with_retry(prompt: str, key: str, max_attempts: int = 2) -> dict[str, Any]:
    """Call the LLM and parse the response, retrying once if the result is empty."""
    for attempt in range(max_attempts):
        async with _LLM_SEMAPHORE:
            llm = get_chat_llm()
            response = await llm.ainvoke([
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ])
        raw = response.content if hasattr(response, "content") else str(response)
        result = _parse_normalization_response(raw, key=key)
        if result[key]:
            return result
        if attempt < max_attempts - 1:
            logger.warning("Empty %s on attempt %d, retrying…", key, attempt + 1)
    return result


async def normalize_object(
    vendor: str,
    object_type: str,
    object_name: str,
    vendor_data: dict[str, Any],
) -> dict[str, Any]:
    """Convert one vendor-specific PolicyObject to vendor-agnostic base_data.

    Returns {"base_data": {...}, "reasoning": "..."}.

    Simple types are handled by fast rule-based paths. Complex types use the LLM.
    """
    fast = _fast_normalize_object(object_type, vendor_data)
    if fast is not None:
        return fast

    schema = BASE_RULE_SCHEMAS.get(object_type, '{"key": "value", ...}')

    user_prompt = f"""\
Convert the following vendor-specific firewall {object_type} to a vendor-agnostic representation.

Source vendor: {vendor}
Object name: {object_name}
Vendor-specific data:
{json.dumps(vendor_data, indent=2)}

Target vendor-agnostic schema for {object_type}:
{schema}

Rules:
- Use the canonical zone names that appear in the vendor config (keep them as-is for zones).
- Use the object names that appear in the vendor config for address/service references.
- Normalize actions: "permit"→"allow", "deny"→"deny", "drop"→"drop".
- For applications: if the vendor uses port-based inspection, use the application name if \
  it can be inferred, otherwise use protocol/port and explain in reasoning.
- Keep the output minimal — only include fields that have meaningful values.

Return ONLY this JSON (no other text):
{{
  "base_data": {{...vendor-agnostic fields...}},
  "reasoning": "brief explanation of normalization choices"
}}\
"""

    result = await _invoke_with_retry(user_prompt, key="base_data")
    return result


async def normalize_rule(
    vendor: str,
    rule_type: str,
    rule_name: str,
    vendor_data: dict[str, Any],
) -> dict[str, Any]:
    """Convert one vendor-specific rule to vendor-agnostic base_rule.

    Returns {"base_rule": {...}, "reasoning": "..."}.
    """
    schema_key = "security_rule" if rule_type == "security_rule" else (
        "nat_rule" if rule_type == "nat_rule" else rule_type
    )
    schema = BASE_RULE_SCHEMAS.get(schema_key, '{"key": "value", ...}')

    user_prompt = f"""\
Convert the following vendor-specific firewall {rule_type} to a vendor-agnostic representation.

Source vendor: {vendor}
Rule name: {rule_name}
Vendor-specific data:
{json.dumps(vendor_data, indent=2)}

Target vendor-agnostic schema:
{schema}

Rules:
- Preserve zone names exactly as they appear — they will be mapped via DeviceZoneMapping.
- Preserve address/service object references by name.
- Normalize the action field (permit→allow, deny→deny).
- For applications: use logical app names (ssl, http, rdp, ssh) where possible.
- Include only fields with meaningful values.

Return ONLY this JSON (no other text):
{{
  "base_rule": {{...vendor-agnostic fields...}},
  "reasoning": "brief explanation of normalization choices"
}}\
"""

    return await _invoke_with_retry(user_prompt, key="base_rule")


def _parse_normalization_response(
    raw: str, key: str = "base_data"
) -> dict[str, Any]:
    """Parse LLM JSON response for normalization."""
    import re

    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
            except json.JSONDecodeError:
                logger.warning("Could not parse LLM response: %s", text[:200])
                return {key: {}, "reasoning": "LLM response parsing failed"}
        else:
            logger.warning("No JSON in LLM response: %s", text[:200])
            return {key: {}, "reasoning": "LLM returned no JSON"}

    result = parsed.get(key, {})
    reasoning = parsed.get("reasoning", "")
    if not isinstance(result, dict):
        result = {}

    # If the LLM skipped the wrapper and returned rule/object fields directly,
    # use the whole parsed dict as the base (excluding any "reasoning" key).
    if not result and isinstance(parsed, dict) and parsed:
        result = {k: v for k, v in parsed.items() if k not in ("reasoning",)}
        if not reasoning:
            reasoning = "Normalized (LLM omitted wrapper key)."

    return {key: result, "reasoning": str(reasoning)}
