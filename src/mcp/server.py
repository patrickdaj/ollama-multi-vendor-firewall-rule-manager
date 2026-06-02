"""MCP server — firewall management tools for Claude Desktop / other clients.

Tool groups:
  Search     — semantic search over ingested policy data
  Analysis   — shadow rules, redundant objects, permissive rules
  Optimization — policy cleanup recommendations, object consolidation
  Translation — cross-vendor rule/object generation
  Live       — connect to a device and ingest / query live
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict

from mcp.server.fastmcp import FastMCP

from src.config import settings
from src.firewall.vendors import get_connector
from src.rag.chain import build_rag_chain
from src.rag.loader import ingest_policy
from src.rag.vectorstore import get_vectorstore

logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="firewall-manager",
    instructions=(
        "Multi-vendor firewall policy management. Vendors: Palo Alto, Cisco ASA, "
        "Cisco FTD, Fortinet. Use search tools to find rules/objects, analysis tools "
        "to identify policy problems, translation tools to generate cross-vendor config."
    ),
)

# ── Search ───────────────────────────────────────────────────────────────────


@mcp.tool()
def search_firewall_rules(
    query: str,
    vendor: str | None = None,
    device: str | None = None,
    enabled_only: bool = False,
    limit: int = 10,
) -> str:
    """
    Semantic search across all ingested security rules.

    Args:
        query:        Natural language (e.g. "rules allowing RDP from untrusted zone")
        vendor:       Filter by vendor (paloalto, cisco_asa, cisco_ftd, fortinet)
        device:       Filter by device name
        enabled_only: Only return enabled rules
        limit:        Max results
    """
    where: dict = {"type": "security_rule"}
    if vendor:
        where["vendor"] = vendor
    if device:
        where["device"] = device
    if enabled_only:
        where["enabled"] = "True"

    docs = get_vectorstore().similarity_search(query, k=limit, filter=where)
    if not docs:
        return "No matching security rules found."

    lines = []
    for doc in docs:
        m = doc.metadata
        lines.append(
            f"[{m.get('device')} / {m.get('vendor')}] {m.get('rule_name')} "
            f"| action={m.get('action')} enabled={m.get('enabled')}\n{doc.page_content}"
        )
    return "\n\n---\n\n".join(lines)


@mcp.tool()
def search_nat_rules(
    query: str,
    nat_type: str | None = None,
    vendor: str | None = None,
    device: str | None = None,
    limit: int = 10,
) -> str:
    """
    Semantic search across all ingested NAT rules.

    Args:
        query:    Natural language (e.g. "DNAT rules forwarding port 443 to DMZ")
        nat_type: Filter by type (static, dynamic, pat, dnat, bidir)
        vendor:   Vendor filter
        device:   Device filter
        limit:    Max results
    """
    where: dict = {"type": "nat_rule"}
    if nat_type:
        where["nat_type"] = nat_type
    if vendor:
        where["vendor"] = vendor
    if device:
        where["device"] = device

    docs = get_vectorstore().similarity_search(query, k=limit, filter=where)
    if not docs:
        return "No matching NAT rules found."
    return "\n\n---\n\n".join(
        f"[{d.metadata.get('device')} / {d.metadata.get('vendor')}] "
        f"NAT:{d.metadata.get('nat_type')}\n{d.page_content}"
        for d in docs
    )


@mcp.tool()
def search_address_objects(
    query: str,
    vendor: str | None = None,
    device: str | None = None,
    limit: int = 10,
) -> str:
    """Search address objects and groups by name, IP, or description."""
    where: dict = {"type": "address_object"}
    if vendor:
        where["vendor"] = vendor
    if device:
        where["device"] = device

    docs = get_vectorstore().similarity_search(query, k=limit, filter=where)
    if not docs:
        return "No matching address objects found."
    return "\n\n---\n\n".join(
        f"[{d.metadata.get('device')} / {d.metadata.get('vendor')}]\n{d.page_content}"
        for d in docs
    )


@mcp.tool()
def ask_firewall_policy(question: str) -> str:
    """
    Ask a natural language question about firewall policies using RAG.
    Grounded in all ingested policy data across all vendors.

    Args:
        question: e.g. "Which rules allow traffic from the DMZ to the internet?"
    """
    chain = build_rag_chain()
    return chain.invoke({"input": question, "chat_history": []})


# ── Analysis ─────────────────────────────────────────────────────────────────


@mcp.tool()
def find_shadow_rules(device: str | None = None, vendor: str | None = None) -> str:
    """
    Identify rules that are likely shadowed by earlier broader rules.

    Shadow rule: a rule that can never be matched because a prior rule
    with broader criteria already handles all traffic it would match.

    This tool retrieves candidate rules and uses the LLM to reason about ordering.

    Args:
        device: Optional device filter
        vendor: Optional vendor filter
    """
    where: dict = {"type": "security_rule"}
    if device:
        where["device"] = device
    if vendor:
        where["vendor"] = vendor

    docs = get_vectorstore().similarity_search("any any allow all traffic deny", k=50, filter=where)
    if not docs:
        return "No rules found to analyze."

    rules_text = "\n\n".join(f"Position {i}: {d.page_content}" for i, d in enumerate(docs))
    chain = build_rag_chain()
    return chain.invoke({
        "input": (
            "Analyze the following firewall rules for shadow rule problems. "
            "A rule is shadowed when a prior rule with broader match criteria "
            "would catch all traffic before reaching it. "
            "List any shadowed rules, explain why they're shadowed, and suggest fixes.\n\n"
            f"{rules_text}"
        ),
        "chat_history": [],
    })


@mcp.tool()
def find_redundant_objects(device: str | None = None, vendor: str | None = None) -> str:
    """
    Find address objects with duplicate or overlapping values.

    Redundant objects waste admin time and create audit confusion
    (e.g., "web-server-01" and "proxy-host" both pointing to 10.0.1.100).

    Args:
        device: Optional device filter
        vendor: Optional vendor filter
    """
    where: dict = {"type": "address_object"}
    if device:
        where["device"] = device
    if vendor:
        where["vendor"] = vendor

    docs = get_vectorstore().similarity_search("host network address IP", k=200, filter=where)
    if not docs:
        return "No address objects found."

    # Group by value to find duplicates deterministically
    value_map: dict[str, list[str]] = defaultdict(list)
    for doc in docs:
        content = doc.page_content
        for line in content.splitlines():
            if line.startswith("Value:"):
                val = line.split(":", 1)[1].strip()
                if val:
                    name_line = next((l for l in content.splitlines() if l.startswith("Address Object:")), "")
                    obj_name = name_line.split(":", 1)[1].strip() if name_line else "unknown"
                    device_label = doc.metadata.get("device", "?")
                    value_map[val].append(f"{device_label}:{obj_name}")

    duplicates = {v: names for v, names in value_map.items() if len(names) > 1}
    if not duplicates:
        return "No redundant address objects found."

    lines = [f"Found {len(duplicates)} duplicate values:"]
    for val, names in sorted(duplicates.items()):
        lines.append(f"  {val} → {', '.join(names)}")
    return "\n".join(lines)


@mcp.tool()
def find_permissive_rules(device: str | None = None, vendor: str | None = None) -> str:
    """
    Find overly permissive rules (any/any, broad subnets, no application restriction).

    Args:
        device: Optional device filter
        vendor: Optional vendor filter
    """
    where: dict = {"type": "security_rule"}
    if device:
        where["device"] = device
    if vendor:
        where["vendor"] = vendor

    docs = get_vectorstore().similarity_search(
        "source any destination any permit all traffic unrestricted", k=30, filter=where
    )
    if not docs:
        return "No obviously permissive rules found."

    result_text = "\n\n".join(d.page_content for d in docs)
    chain = build_rag_chain()
    return chain.invoke({
        "input": (
            "Review these firewall rules and identify which ones are overly permissive. "
            "Look for: any/any source/destination, missing application restrictions (PAN-OS), "
            "broad subnets like /8 or /16 to the internet, rules with no logging. "
            "For each permissive rule, explain the risk and suggest a tighter replacement.\n\n"
            f"{result_text}"
        ),
        "chat_history": [],
    })


# ── Optimization ─────────────────────────────────────────────────────────────


@mcp.tool()
def optimize_policy(device: str, vendor: str | None = None) -> str:
    """
    Generate a prioritized list of optimization recommendations for a device's policy.

    Covers: shadow rules, redundant objects, permissive rules, consolidation
    opportunities, missing logging, disabled rules that could be removed.

    Args:
        device: Device name (required)
        vendor: Vendor hint (optional)
    """
    where: dict = {"device": device}
    if vendor:
        where["vendor"] = vendor

    rules_docs = get_vectorstore().similarity_search("rule policy", k=100, filter={**where, "type": "security_rule"})
    nat_docs = get_vectorstore().similarity_search("nat", k=50, filter={**where, "type": "nat_rule"})
    addr_docs = get_vectorstore().similarity_search("address", k=100, filter={**where, "type": "address_object"})

    context = (
        f"=== Security Rules ({len(rules_docs)}) ===\n"
        + "\n".join(d.page_content for d in rules_docs)
        + f"\n\n=== NAT Rules ({len(nat_docs)}) ===\n"
        + "\n".join(d.page_content for d in nat_docs)
        + f"\n\n=== Address Objects ({len(addr_docs)}) ===\n"
        + "\n".join(d.page_content for d in addr_docs)
    )

    chain = build_rag_chain()
    return chain.invoke({
        "input": (
            f"Analyze the full policy for device '{device}' and produce a prioritized "
            "optimization plan. Include:\n"
            "1. Shadow/unreachable rules\n"
            "2. Redundant or duplicate objects\n"
            "3. Overly permissive rules with recommended tightening\n"
            "4. Disabled rules that can be safely removed\n"
            "5. Missing logging\n"
            "6. Consolidation opportunities (rules that could be merged)\n"
            "Format as a numbered list with severity (High/Medium/Low) for each item.\n\n"
            + context
        ),
        "chat_history": [],
    })


# ── Cross-vendor translation ─────────────────────────────────────────────────


@mcp.tool()
def translate_rule_to_vendor(
    rule_name: str,
    source_device: str,
    target_vendor: str,
) -> str:
    """
    Generate the equivalent security rule config for a different vendor.

    This uses RAG to find the source rule and similar rules already on the
    target vendor, then asks the LLM to produce vendor-specific CLI/API syntax.

    Args:
        rule_name:     Name of the rule to translate
        source_device: Device the rule currently lives on
        target_vendor: Target vendor (paloalto, cisco_asa, cisco_ftd, fortinet)
    """
    vs = get_vectorstore()

    # Find source rule
    source_docs = vs.similarity_search(
        rule_name,
        k=3,
        filter={"type": "security_rule", "device": source_device},
    )
    if not source_docs:
        return f"Rule '{rule_name}' not found on device '{source_device}'. Ingest the policy first."

    source_text = source_docs[0].page_content

    # Find examples of similar rules on the target vendor for grounding
    example_docs = vs.similarity_search(source_text, k=5, filter={"type": "security_rule", "vendor": target_vendor})
    examples = "\n\n".join(d.page_content for d in example_docs) if example_docs else "No existing examples found."

    chain = build_rag_chain()
    return chain.invoke({
        "input": (
            f"Translate the following firewall rule to {target_vendor} syntax.\n\n"
            f"Source rule:\n{source_text}\n\n"
            f"Examples of existing {target_vendor} rules for context:\n{examples}\n\n"
            f"Generate the complete {target_vendor} CLI commands or API payload needed "
            "to implement an equivalent rule. Include any address or service objects "
            "that would need to be created. Explain any behavioral differences between "
            "the source and target vendor implementations."
        ),
        "chat_history": [],
    })


@mcp.tool()
def translate_nat_rule_to_vendor(
    rule_name: str,
    source_device: str,
    target_vendor: str,
) -> str:
    """
    Generate the equivalent NAT rule config for a different vendor.

    Args:
        rule_name:     Name of the NAT rule to translate
        source_device: Source device name
        target_vendor: Target vendor (paloalto, cisco_asa, cisco_ftd, fortinet)
    """
    vs = get_vectorstore()

    source_docs = vs.similarity_search(
        rule_name, k=3, filter={"type": "nat_rule", "device": source_device}
    )
    if not source_docs:
        return f"NAT rule '{rule_name}' not found on '{source_device}'."

    source_text = source_docs[0].page_content
    nat_type = source_docs[0].metadata.get("nat_type", "")

    example_docs = vs.similarity_search(
        source_text, k=5, filter={"type": "nat_rule", "vendor": target_vendor}
    )
    examples = "\n\n".join(d.page_content for d in example_docs) if example_docs else "No existing examples."

    chain = build_rag_chain()
    return chain.invoke({
        "input": (
            f"Translate this {nat_type} NAT rule to {target_vendor} syntax.\n\n"
            f"Source:\n{source_text}\n\n"
            f"Existing {target_vendor} NAT examples:\n{examples}\n\n"
            "Provide complete CLI commands or API payload. "
            "Note any vendor-specific NAT concepts (e.g. FortiGate VIP vs PAN-OS DNAT, "
            "ASA twice-NAT vs auto-NAT, FTD manual vs auto NAT)."
        ),
        "chat_history": [],
    })


@mcp.tool()
def compare_device_policies(device_a: str, device_b: str) -> str:
    """
    Compare the security policies of two devices and highlight differences.

    Useful for: identifying coverage gaps when migrating vendor A → vendor B,
    ensuring equivalent protection across redundant firewalls.

    Args:
        device_a: First device name
        device_b: Second device name
    """
    vs = get_vectorstore()
    docs_a = vs.similarity_search("rule", k=50, filter={"type": "security_rule", "device": device_a})
    docs_b = vs.similarity_search("rule", k=50, filter={"type": "security_rule", "device": device_b})

    if not docs_a and not docs_b:
        return f"No rules found for either device. Ingest policies first."

    text_a = "\n".join(d.page_content for d in docs_a)
    text_b = "\n".join(d.page_content for d in docs_b)

    chain = build_rag_chain()
    return chain.invoke({
        "input": (
            f"Compare the security policies of '{device_a}' and '{device_b}'.\n\n"
            f"--- {device_a} rules ---\n{text_a}\n\n"
            f"--- {device_b} rules ---\n{text_b}\n\n"
            "Identify: (1) rules present on A but missing on B, "
            "(2) rules present on B but missing on A, "
            "(3) rules that exist on both but differ in action/scope, "
            "(4) overall coverage assessment."
        ),
        "chat_history": [],
    })


# ── Live device ───────────────────────────────────────────────────────────────


@mcp.tool()
def list_configured_devices() -> str:
    """List all firewall devices registered in the environment."""
    if not settings.firewall_devices:
        return "No devices configured. Set FIREWALL_DEVICES in .env"
    return "\n".join(f"- {d.name} ({d.vendor}) @ {d.host}" for d in settings.firewall_devices)


@mcp.tool()
async def fetch_and_ingest_device(device_name: str) -> str:
    """
    Connect to a live device, retrieve its full policy (rules, NAT, objects, profiles),
    and ingest everything into the RAG knowledge base.

    Args:
        device_name: Name as configured in FIREWALL_DEVICES
    """
    device = settings.get_device(device_name)
    if not device:
        return f"Device '{device_name}' not in FIREWALL_DEVICES."

    connector = get_connector(device)
    try:
        async with connector:
            policy = await connector.get_policy()
        count = ingest_policy(policy)
        return (
            f"Ingested {device_name} ({device.vendor}): "
            f"{policy.rule_count()} security rules, {policy.nat_count()} NAT rules, "
            f"{len(policy.address_objects)} address objects, "
            f"{len(policy.service_objects)} service objects → {count} total documents."
        )
    except Exception as e:
        logger.exception("Failed to ingest %s", device_name)
        return f"Error: {e}"


@mcp.tool()
async def get_live_rules(device_name: str, rulebase: str = "security") -> str:
    """
    Pull current rules directly from a live device (bypasses RAG cache).

    Args:
        device_name: Device name from FIREWALL_DEVICES
        rulebase:    "security" or "nat"
    """
    device = settings.get_device(device_name)
    if not device:
        return f"Device '{device_name}' not found."

    connector = get_connector(device)
    try:
        async with connector:
            if rulebase == "nat":
                rules = await connector.get_nat_rules()
            else:
                rules = await connector.get_rules(rulebase)
        return json.dumps([r.model_dump() for r in rules], indent=2, default=str)
    except Exception as e:
        return f"Error: {e}"


def run() -> None:
    """Entry point — stdio for local use, SSE for Docker/network deployment."""
    import os
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "sse":
        mcp.settings.host = os.environ.get("MCP_HOST", "0.0.0.0")
        mcp.settings.port = int(os.environ.get("MCP_PORT", "8001"))
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    run()
