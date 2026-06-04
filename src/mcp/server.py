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
from src.rag.ingest import onboard_device
from src.rag.vectorstore import build_filter, get_vectorstore

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

    docs = get_vectorstore().similarity_search(query, k=limit, filter=build_filter(where))
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

    docs = get_vectorstore().similarity_search(query, k=limit, filter=build_filter(where))
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

    docs = get_vectorstore().similarity_search(query, k=limit, filter=build_filter(where))
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

    docs = get_vectorstore().similarity_search("any any allow all traffic deny", k=50, filter=build_filter(where))
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

    docs = get_vectorstore().similarity_search("host network address IP", k=200, filter=build_filter(where))
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
        "source any destination any permit all traffic unrestricted", k=30, filter=build_filter(where)
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

    rules_docs = get_vectorstore().similarity_search("rule policy", k=100, filter=build_filter({**where, "type": "security_rule"}))
    nat_docs = get_vectorstore().similarity_search("nat", k=50, filter=build_filter({**where, "type": "nat_rule"}))
    addr_docs = get_vectorstore().similarity_search("address", k=100, filter=build_filter({**where, "type": "address_object"}))

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
        filter=build_filter({"type": "security_rule", "device": source_device}),
    )
    if not source_docs:
        return f"Rule '{rule_name}' not found on device '{source_device}'. Ingest the policy first."

    source_text = source_docs[0].page_content

    # Find examples of similar rules on the target vendor for grounding
    example_docs = vs.similarity_search(source_text, k=5, filter=build_filter({"type": "security_rule", "vendor": target_vendor}))
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
        rule_name, k=3, filter=build_filter({"type": "nat_rule", "device": source_device})
    )
    if not source_docs:
        return f"NAT rule '{rule_name}' not found on '{source_device}'."

    source_text = source_docs[0].page_content
    nat_type = source_docs[0].metadata.get("nat_type", "")

    example_docs = vs.similarity_search(
        source_text, k=5, filter=build_filter({"type": "nat_rule", "vendor": target_vendor})
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
    docs_a = vs.similarity_search("rule", k=50, filter=build_filter({"type": "security_rule", "device": device_a}))
    docs_b = vs.similarity_search("rule", k=50, filter=build_filter({"type": "security_rule", "device": device_b}))

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
def search_service_objects(
    query: str,
    vendor: str | None = None,
    device: str | None = None,
    include_groups: bool = True,
    limit: int = 10,
) -> str:
    """Search service objects and service groups by name, port, or protocol."""
    vs = get_vectorstore()
    results = []
    for obj_type in (["service_object", "service_group"] if include_groups else ["service_object"]):
        where: dict = {"type": obj_type}
        if vendor:
            where["vendor"] = vendor
        if device:
            where["device"] = device
        results.extend(vs.similarity_search(query, k=limit, filter=build_filter(where)))
    if not results:
        return "No matching service objects or groups found."
    return "\n\n---\n\n".join(
        f"[{d.metadata.get('device')} / {d.metadata.get('vendor')}] "
        f"({d.metadata.get('type')})\n{d.page_content}"
        for d in results[:limit]
    )


@mcp.tool()
def search_decryption_rules(
    query: str,
    vendor: str | None = None,
    device: str | None = None,
    limit: int = 10,
) -> str:
    """Search SSL/TLS decryption rules and decryption profiles."""
    vs = get_vectorstore()
    results = []
    for obj_type in ["decryption_rule", "decryption_profile"]:
        where: dict = {"type": obj_type}
        if vendor:
            where["vendor"] = vendor
        if device:
            where["device"] = device
        results.extend(vs.similarity_search(query, k=limit, filter=build_filter(where)))
    if not results:
        return "No matching decryption rules or profiles found."
    return "\n\n---\n\n".join(
        f"[{d.metadata.get('device')} / {d.metadata.get('vendor')}] "
        f"({d.metadata.get('type')})\n{d.page_content}"
        for d in results[:limit]
    )


@mcp.tool()
def search_auth_policies(
    query: str,
    vendor: str | None = None,
    device: str | None = None,
    limit: int = 10,
) -> str:
    """Search authentication and captive portal policy rules."""
    where: dict = {"type": "auth_policy"}
    if vendor:
        where["vendor"] = vendor
    if device:
        where["device"] = device
    docs = get_vectorstore().similarity_search(query, k=limit, filter=build_filter(where))
    if not docs:
        return "No matching authentication policies found."
    return "\n\n---\n\n".join(
        f"[{d.metadata.get('device')} / {d.metadata.get('vendor')}]\n{d.page_content}"
        for d in docs
    )


@mcp.tool()
def search_url_categories(
    query: str,
    vendor: str | None = None,
    device: str | None = None,
    limit: int = 10,
) -> str:
    """Search custom URL categories and web filter lists."""
    where: dict = {"type": "url_category"}
    if vendor:
        where["vendor"] = vendor
    if device:
        where["device"] = device
    docs = get_vectorstore().similarity_search(query, k=limit, filter=build_filter(where))
    if not docs:
        return "No matching URL categories found."
    return "\n\n---\n\n".join(
        f"[{d.metadata.get('device')} / {d.metadata.get('vendor')}]\n{d.page_content}"
        for d in docs
    )


@mcp.tool()
def search_zones(
    query: str,
    vendor: str | None = None,
    device: str | None = None,
    limit: int = 10,
) -> str:
    """Search zone definitions and their interface assignments."""
    where: dict = {"type": "zone"}
    if vendor:
        where["vendor"] = vendor
    if device:
        where["device"] = device
    docs = get_vectorstore().similarity_search(query, k=limit, filter=build_filter(where))
    if not docs:
        return "No matching zones found."
    return "\n\n---\n\n".join(
        f"[{d.metadata.get('device')} / {d.metadata.get('vendor')}]\n{d.page_content}"
        for d in docs
    )


@mcp.tool()
def search_application_objects(
    query: str,
    vendor: str | None = None,
    device: str | None = None,
    include_groups: bool = True,
    limit: int = 10,
) -> str:
    """Search application objects (App-ID, custom apps) and application groups/filters."""
    vs = get_vectorstore()
    results = []
    for obj_type in (["application", "app_group"] if include_groups else ["application"]):
        where: dict = {"type": obj_type}
        if vendor:
            where["vendor"] = vendor
        if device:
            where["device"] = device
        results.extend(vs.similarity_search(query, k=limit, filter=build_filter(where)))
    if not results:
        return "No matching application objects or groups found."
    return "\n\n---\n\n".join(
        f"[{d.metadata.get('device')} / {d.metadata.get('vendor')}] "
        f"({d.metadata.get('type')})\n{d.page_content}"
        for d in results[:limit]
    )


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
        result = await onboard_device(policy, triggered_by="mcp")
        return (
            f"Onboarded {device_name} ({device.vendor}): "
            f"{policy.rule_count()} security rules, {policy.nat_count()} NAT rules, "
            f"{len(policy.address_objects)} address objects, "
            f"{len(policy.service_objects)} service objects → "
            f"{result['chroma_documents']} documents (snapshot #{result['snapshot_id']})."
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


# ── Group policy management ───────────────────────────────────────────────────


@mcp.tool()
async def list_groups() -> str:
    """List all policy groups in the hierarchy with device and rule counts.

    Groups are the desired-state containers: each group holds vendor-agnostic
    policy rules and shared objects that are inherited by its child groups and
    member devices.
    """
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from src.db.models import DeviceGroup
    from src.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        rows = (await session.execute(
            select(DeviceGroup)
            .options(selectinload(DeviceGroup.devices), selectinload(DeviceGroup.children))
            .order_by(DeviceGroup.name)
        )).scalars().all()

    if not rows:
        return "No groups defined. Create groups via the web UI or API."

    lines = []
    for g in rows:
        parent = f" (parent: #{g.parent_id})" if g.parent_id else " (root)"
        lines.append(
            f"- [{g.id}] {g.name}{parent} | {len(g.devices)} device(s), {len(g.children)} child group(s)"
            + (f" — {g.description}" if g.description else "")
        )
    return "\n".join(lines)


@mcp.tool()
async def get_group_effective_policy(
    group_name: str,
    rule_type: str = "security",
) -> str:
    """Get the full ordered rulebase that a device in this group would see.

    Includes pre-rules from all ancestor groups (root first) then this group,
    followed by post-rules (this group first, root last). Device-local rules
    are not included here.

    Args:
        group_name: Name of the group (exact match)
        rule_type:  security | nat | decryption | dos | auth
    """
    from sqlalchemy import select
    from src.db.models import DeviceGroup, GroupPolicyRule
    from src.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        group = (await session.execute(
            select(DeviceGroup).where(DeviceGroup.name == group_name)
        )).scalar_one_or_none()
        if not group:
            return f"Group '{group_name}' not found."

        # Build ancestor chain
        chain: list[DeviceGroup] = []
        current: DeviceGroup | None = group
        while current is not None:
            chain.append(current)
            current = await session.get(DeviceGroup, current.parent_id) if current.parent_id else None
        chain.reverse()

        pre_rules = []
        post_rules = []
        for g in chain:
            rows = (await session.execute(
                select(GroupPolicyRule).where(
                    GroupPolicyRule.device_group_id == g.id,
                    GroupPolicyRule.rule_type == rule_type,
                    GroupPolicyRule.rulebase == "pre",
                ).order_by(GroupPolicyRule.position)
            )).scalars().all()
            for r in rows:
                pre_rules.append(f"  [{g.name}/pre/{r.position}] {r.name} | {r.base_rule.get('action', '?')} {'enabled' if r.enabled else 'DISABLED'}")

        for g in reversed(chain):
            rows = (await session.execute(
                select(GroupPolicyRule).where(
                    GroupPolicyRule.device_group_id == g.id,
                    GroupPolicyRule.rule_type == rule_type,
                    GroupPolicyRule.rulebase == "post",
                ).order_by(GroupPolicyRule.position)
            )).scalars().all()
            for r in rows:
                post_rules.append(f"  [{g.name}/post/{r.position}] {r.name} | {r.base_rule.get('action', '?')} {'enabled' if r.enabled else 'DISABLED'}")

    ancestor_str = " → ".join(g.name for g in chain[:-1])
    header = f"Effective {rule_type} policy for group '{group_name}'"
    if ancestor_str:
        header += f"\nAncestor chain: {ancestor_str}"

    sections = [header]
    sections.append(f"\nPRE-RULES ({len(pre_rules)}):")
    sections.extend(pre_rules or ["  (none)"])
    sections.append(f"\nPOST-RULES ({len(post_rules)}):")
    sections.extend(post_rules or ["  (none)"])
    return "\n".join(sections)


@mcp.tool()
async def detect_translation_gaps(
    group_name: str,
    target_vendor: str,
) -> str:
    """Scan a group's effective policy for missing vendor translations.

    Creates TranslationProposal records for each gap found. The proposals
    start empty — use generate_ai_translations to fill them in, then review
    and approve via the web UI.

    Args:
        group_name:    Group name (exact match)
        target_vendor: paloalto | cisco_asa | cisco_ftd | fortinet
    """
    from sqlalchemy import select
    from src.db.models import DeviceGroup
    from src.db.session import AsyncSessionLocal
    from src.api.routes.translations import detect_gaps

    async with AsyncSessionLocal() as session:
        group = (await session.execute(
            select(DeviceGroup).where(DeviceGroup.name == group_name)
        )).scalar_one_or_none()
        if not group:
            return f"Group '{group_name}' not found."
        group_id = group.id

    result = await detect_gaps(
        group_id=group_id,
        target_vendor=target_vendor,
        triggered_by="mcp",
    )

    if result.proposals_created == 0:
        return (
            f"All translations are in place for group '{group_name}' → {target_vendor}. "
            "No gaps detected."
        )

    lines = [
        f"Gap detection complete for group '{group_name}' → {target_vendor}:",
        f"  {result.proposals_created} proposal(s) created",
    ]
    if result.missing_object_translations:
        lines.append(f"  Missing object translations ({len(result.missing_object_translations)}):")
        for o in result.missing_object_translations[:10]:
            lines.append(f"    - {o['object_type']}: {o['object_name']}")
        if len(result.missing_object_translations) > 10:
            lines.append(f"    … and {len(result.missing_object_translations) - 10} more")
    if result.missing_rule_translations:
        lines.append(f"  Missing rule translations ({len(result.missing_rule_translations)}):")
        for r in result.missing_rule_translations[:10]:
            lines.append(f"    - Rule #{r['rule_id']}: {r['rule_name']}")

    lines.append("\nRun generate_ai_translations to fill these proposals in.")
    return "\n".join(lines)


@mcp.tool()
async def list_pending_proposals(
    target_vendor: str | None = None,
    limit: int = 20,
) -> str:
    """List pending translation proposals awaiting review.

    Shows proposals that gap detection has created but that haven't been
    approved or rejected yet. Use generate_ai_translations to fill in any
    proposals that have empty proposed_translation fields.

    Args:
        target_vendor: Filter by vendor (optional)
        limit:         Max proposals to show
    """
    from sqlalchemy import select
    from src.db.models import TranslationProposal
    from src.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        q = select(TranslationProposal).where(
            TranslationProposal.status == "pending"
        ).order_by(TranslationProposal.created_at).limit(limit)
        if target_vendor:
            q = q.where(TranslationProposal.target_vendor == target_vendor)
        proposals = (await session.execute(q)).scalars().all()

    if not proposals:
        vendor_str = f" for {target_vendor}" if target_vendor else ""
        return f"No pending proposals{vendor_str}."

    empty = sum(1 for p in proposals if not p.proposed_translation)
    lines = [f"{len(proposals)} pending proposal(s) ({empty} need AI generation):"]
    for p in proposals:
        has_content = "✓" if p.proposed_translation else "○ awaiting AI"
        if p.proposal_type == "object":
            label = f"{p.object_type}: {p.object_name}"
        else:
            label = f"Rule #{p.rule_id}"
        lines.append(f"  [{p.id}] {p.proposal_type} | {label} → {p.target_vendor} | {has_content}")

    if empty > 0:
        lines.append(f"\nRun generate_ai_translations to fill the {empty} empty proposal(s).")
    return "\n".join(lines)


@mcp.tool()
async def generate_ai_translations(
    target_vendor: str | None = None,
    proposal_ids: list[int] | None = None,
) -> str:
    """Run AI generation for pending translation proposals with empty translations.

    Either pass specific proposal_ids, or leave None to generate for all
    empty pending proposals (optionally filtered by target_vendor).
    Proposals remain pending after generation — a human must review and
    approve them via the web UI before they take effect.

    Args:
        target_vendor:  Only generate for this vendor (optional, ignored if proposal_ids given)
        proposal_ids:   Specific proposal IDs to generate (optional)
    """
    from src.api.routes.translations import generate_proposal, generate_proposals_batch

    if proposal_ids:
        results = []
        for pid in proposal_ids:
            result = await generate_proposal(pid)
            results.append(result)
        succeeded = sum(1 for r in results if r.status == "generated")
        failed = [r for r in results if r.status == "error"]
        lines = [f"Generated {succeeded}/{len(results)} proposals."]
        for r in failed:
            lines.append(f"  [#{r.proposal_id}] Failed: {r.error}")
        return "\n".join(lines)

    batch = await generate_proposals_batch(target_vendor=target_vendor)
    if batch.processed == 0:
        vendor_str = f" for {target_vendor}" if target_vendor else ""
        return f"No empty pending proposals found{vendor_str}. Nothing to generate."

    return (
        f"Batch generation complete: {batch.succeeded}/{batch.processed} proposals generated"
        + (f", {batch.failed} failed" if batch.failed else "")
        + ".\nReview proposals via the web UI Translations page."
    )


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
