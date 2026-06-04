"""Ignis AI agent — task-executing chat backed by LangChain tool calling.

Unlike the RAG chain (which only answers questions), this agent can also
take actions. Each tool call surfaces in the frontend as a tracked task
with live status and query-cache invalidation on completion.

WebSocket message protocol (additions over the basic chat protocol):
  {"type": "task_start",  "task_id": "...", "tool": "...", "description": "..."}
  {"type": "task_done",   "task_id": "...", "result": "...",   "invalidate": [...]}
  {"type": "task_error",  "task_id": "...", "error": "..."}

The "invalidate" list contains react-query key prefixes that the frontend
should invalidate so the relevant pages refresh automatically.

Starter tools (more wired in as integration points are needed):
  add_device         — register a new firewall device
  list_devices       — list registered devices
  create_group       — create a policy group
  list_groups        — show the group hierarchy
  assign_device      — assign a device to a group
  search_policy      — semantic search over ingested policy data
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any, AsyncIterator

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from src.db.models import Device, DeviceGroup
from src.db.session import AsyncSessionLocal
from src.llm.factory import get_chat_llm

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are Ignis AI, the built-in assistant for Ignis — a multi-vendor firewall \
management platform supporting Palo Alto PAN-OS, Cisco ASA, Cisco FTD, and Fortinet FortiGate.

You can answer questions about firewall policy using the knowledge base, and you \
can take actions using the available tools.

## Tool usage
- When a user asks to add multiple devices, call add_device once per device.
- When searching policy, use search_policy to query the knowledge base.
- After taking actions, give a brief summary of what was done.
- Vendor values: paloalto | cisco_asa | cisco_ftd | fortinet

## Response formatting
Always respond using GitHub-flavored Markdown. The UI renders it fully.

- **Rules or objects**: present as a compact markdown table. Columns depend on context:
  - Security rules: Device | Rule Name | Action | Src Zone | Dst Zone | Service
  - Address objects: Device | Name | Type | Value
  - Omit columns that are all the same value (e.g. if Action is always "allow", skip it).
- **Short lists**: use bullet points, not numbered prose.
- **Findings**: lead with a one-line summary, then the table or bullets.
- **Actions taken**: use a short bullet list of what was created/changed.
- Avoid restating every field in prose — the table captures structure better.
- Keep responses concise. Skip filler phrases like "Here is the list of...".
"""

# ── Helpers ───────────────────────────────────────────────────────────────────


def _ok(message: str, invalidate: list[str] | None = None) -> str:
    return json.dumps({"status": "ok", "message": message, "invalidate": invalidate or []})


def _err(message: str) -> str:
    return json.dumps({"status": "error", "message": message, "invalidate": []})


# ── Tools ─────────────────────────────────────────────────────────────────────


@tool
async def add_device(
    name: str,
    vendor: str,
    host: str,
    username: str = "",
    password: str = "",
    notes: str = "",
) -> str:
    """Add a new firewall device to Ignis.

    Args:
        name:     Unique device name (e.g. pa-edge-01)
        vendor:   paloalto | cisco_asa | cisco_ftd | fortinet
        host:     IP address or FQDN
        username: Login username (optional — required to connect/ingest later)
        password: Login password (optional)
        notes:    Free-text notes
    """
    from src.security.credentials import encrypt_credentials

    async with AsyncSessionLocal() as session:
        if (await session.execute(select(Device).where(Device.name == name))).scalar_one_or_none():
            return _err(f"Device '{name}' already exists.")

        creds_enc = None
        if username or password:
            try:
                creds_enc = encrypt_credentials({"username": username, "password": password})
            except Exception:
                pass

        session.add(Device(name=name, vendor=vendor, host=host, credentials_enc=creds_enc, notes=notes or None))
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            return _err(f"Device '{name}' already exists.")

    return _ok(f"Device '{name}' ({vendor} @ {host}) added.", ["devices"])


@tool
async def list_devices(vendor: str = "") -> str:
    """List all registered firewall devices, optionally filtered by vendor.

    Args:
        vendor: paloalto | cisco_asa | cisco_ftd | fortinet | empty for all
    """
    async with AsyncSessionLocal() as session:
        q = select(Device).order_by(Device.name)
        if vendor:
            q = q.where(Device.vendor == vendor)
        rows = (await session.execute(q)).scalars().all()

    if not rows:
        return "No devices registered." if not vendor else f"No {vendor} devices registered."

    lines = []
    for d in rows:
        synced = d.last_synced_at.strftime("%Y-%m-%d") if d.last_synced_at else "never synced"
        group_info = f"group #{d.device_group_id}" if d.device_group_id else "unassigned"
        lines.append(f"- {d.name}  {d.vendor}  {d.host or '(no host)'}  {group_info}  {synced}")
    return "\n".join(lines)


@tool
async def create_group(
    name: str,
    description: str = "",
    parent_name: str = "",
) -> str:
    """Create a new policy group in the hierarchy.

    Args:
        name:        Unique group name (e.g. DC-East)
        description: Optional description
        parent_name: Parent group name — leave empty for a root group
    """
    async with AsyncSessionLocal() as session:
        parent_id = None
        if parent_name:
            parent = (await session.execute(
                select(DeviceGroup).where(DeviceGroup.name == parent_name)
            )).scalar_one_or_none()
            if not parent:
                return _err(f"Parent group '{parent_name}' not found.")
            parent_id = parent.id

        session.add(DeviceGroup(name=name, description=description or None, parent_id=parent_id))
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            return _err(f"Group '{name}' already exists.")

    loc = f" under '{parent_name}'" if parent_name else " (root)"
    return _ok(f"Group '{name}'{loc} created.", ["groups", "groups-tree"])


@tool
async def list_groups() -> str:
    """List all policy groups in the hierarchy."""
    from sqlalchemy.orm import selectinload

    async with AsyncSessionLocal() as session:
        rows = (await session.execute(
            select(DeviceGroup)
            .options(selectinload(DeviceGroup.devices), selectinload(DeviceGroup.children))
            .order_by(DeviceGroup.name)
        )).scalars().all()

    if not rows:
        return "No groups defined."

    lines = []
    for g in rows:
        indent = "  " if g.parent_id else ""
        lines.append(
            f"{indent}- [{g.id}] {g.name}  {len(g.devices)} device(s)"
            + (f"  — {g.description}" if g.description else "")
        )
    return "\n".join(lines)


@tool
async def assign_device(device_name: str, group_name: str) -> str:
    """Assign a device to a policy group.

    Args:
        device_name: Name of the device to assign
        group_name:  Name of the target group
    """
    async with AsyncSessionLocal() as session:
        device = (await session.execute(
            select(Device).where(Device.name == device_name)
        )).scalar_one_or_none()
        if not device:
            return _err(f"Device '{device_name}' not found.")

        group = (await session.execute(
            select(DeviceGroup).where(DeviceGroup.name == group_name)
        )).scalar_one_or_none()
        if not group:
            return _err(f"Group '{group_name}' not found.")

        device.device_group_id = group.id
        await session.commit()

    return _ok(
        f"Device '{device_name}' assigned to group '{group_name}'.",
        ["devices", "groups", "groups-tree", f"group-devices-{group.id}"],
    )


@tool
async def search_policy(query: str, device: str = "", vendor: str = "") -> str:
    """Search firewall rules and policy objects using natural language.

    Args:
        query:  What to look for (e.g. "rules allowing RDP from untrusted zones")
        device: Filter by device name (optional)
        vendor: Filter by vendor (optional)
    """
    from src.rag.vectorstore import build_filter, get_vectorstore

    where: dict[str, str] = {}
    if vendor:
        where["vendor"] = vendor
    if device:
        where["device"] = device

    vs = get_vectorstore()
    docs = vs.similarity_search(query, k=8, filter=build_filter(where))
    if not docs:
        return "No matching policy objects found in the knowledge base."

    lines = []
    for doc in docs:
        m = doc.metadata
        lines.append(
            f"[{m.get('device', '?')} / {m.get('vendor', '?')}] "
            f"({m.get('type', '?')}) {doc.page_content[:300]}"
        )
    return "\n\n".join(lines)


TOOLS = [add_device, list_devices, create_group, list_groups, assign_device, search_policy]

# Human-readable task descriptions derived from tool name + input
_TOOL_LABELS: dict[str, str] = {
    "add_device": "Adding device",
    "list_devices": "Listing devices",
    "create_group": "Creating group",
    "list_groups": "Listing groups",
    "assign_device": "Assigning device",
    "search_policy": "Searching policy",
}


def _describe_task(tool_name: str, tool_input: Any) -> str:
    """Build a concise human-readable task description."""
    if not isinstance(tool_input, dict):
        return _TOOL_LABELS.get(tool_name, tool_name)

    if tool_name == "add_device":
        return f"Adding device {tool_input.get('name', '')} ({tool_input.get('vendor', '')} @ {tool_input.get('host', '')})"
    if tool_name == "create_group":
        name = tool_input.get("name", "")
        parent = tool_input.get("parent_name", "")
        return f"Creating group '{name}'" + (f" under '{parent}'" if parent else "")
    if tool_name == "assign_device":
        return f"Assigning '{tool_input.get('device_name', '')}' → '{tool_input.get('group_name', '')}'"
    if tool_name == "search_policy":
        return f"Searching: {tool_input.get('query', '')[:50]}"

    return _TOOL_LABELS.get(tool_name, tool_name)


# ── Agent graph ───────────────────────────────────────────────────────────────


def _build_agent():
    from langchain.agents import create_agent

    llm = get_chat_llm()
    return create_agent(llm, TOOLS, system_prompt=SYSTEM_PROMPT)


# ── Streaming entrypoint ──────────────────────────────────────────────────────


async def stream_agent(
    message: str,
    history: list[dict],
) -> AsyncIterator[dict]:
    """Stream agent responses and tool events to the WebSocket handler.

    Yields typed event dicts consumed by agent_manager.py.
    """
    agent = _build_agent()

    lc_messages = []
    for msg in history:
        if msg["role"] == "user":
            lc_messages.append(HumanMessage(content=msg["content"]))
        else:
            lc_messages.append(AIMessage(content=msg["content"]))
    lc_messages.append(HumanMessage(content=message))

    task_ids: dict[str, str] = {}
    full_response = ""

    try:
        async for event in agent.astream_events(
            {"messages": lc_messages},
            version="v2",
        ):
            kind = event["event"]

            if kind == "on_chat_model_stream":
                chunk = event["data"].get("chunk")
                if chunk and hasattr(chunk, "content"):
                    content = chunk.content
                    if isinstance(content, str) and content:
                        full_response += content
                        yield {"type": "token", "content": content}
                    elif isinstance(content, list):
                        for part in content:
                            if isinstance(part, dict) and part.get("type") == "text":
                                text = part.get("text", "")
                                if text:
                                    full_response += text
                                    yield {"type": "token", "content": text}

            elif kind == "on_tool_start":
                run_id = event.get("run_id", str(uuid.uuid4()))
                tool_name = event.get("name", "tool")
                tool_input = event["data"].get("input", {})

                task_id = f"t-{uuid.uuid4().hex[:8]}"
                task_ids[run_id] = task_id

                yield {
                    "type": "task_start",
                    "task_id": task_id,
                    "tool": tool_name,
                    "description": _describe_task(tool_name, tool_input),
                }

            elif kind == "on_tool_end":
                run_id = event.get("run_id", "")
                task_id = task_ids.get(run_id, f"t-{uuid.uuid4().hex[:8]}")
                raw_output = event["data"].get("output", "")
                # LangChain 1.x returns a ToolMessage object; extract .content
                output = str(getattr(raw_output, "content", raw_output))

                invalidate: list[str] = []
                result_msg = output
                try:
                    parsed = json.loads(output)
                    if isinstance(parsed, dict):
                        result_msg = parsed.get("message", output)
                        invalidate = parsed.get("invalidate", [])
                        if parsed.get("status") == "error":
                            yield {"type": "task_error", "task_id": task_id, "error": result_msg}
                            continue
                except (json.JSONDecodeError, TypeError):
                    pass

                yield {
                    "type": "task_done",
                    "task_id": task_id,
                    "result": result_msg,
                    "invalidate": invalidate,
                }

    except Exception as exc:
        log.exception("Agent stream error: %s", exc)
        err_text = f"\n\n_(Agent error: {exc})_"
        full_response += err_text
        yield {"type": "token", "content": err_text}

    new_history = history + [
        {"role": "user", "content": message},
        {"role": "assistant", "content": full_response or "_(actions completed)_"},
    ]
    yield {"type": "end", "history": new_history[-20:]}  # cap at 10 turns
