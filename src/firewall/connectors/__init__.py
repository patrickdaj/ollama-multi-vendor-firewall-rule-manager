"""Vendor push connectors registry.

Each connector implements push_item(item_type, object_type, name, action, payload) → bool.
Returns True on success, False on failure (non-exception failure).
Raises on hard errors.

Connectors are registered here as they are implemented. Vendors without a connector
will get a None return from get_connector(), causing the push task to mark items as
skipped with an informational message.
"""
from __future__ import annotations

from typing import Any, Protocol


class PushConnector(Protocol):
    async def push_item(
        self,
        item_type: str,
        object_type: str,
        name: str,
        action: str,
        payload: dict[str, Any],
    ) -> bool: ...

    async def commit(self) -> bool: ...


async def get_connector(device: Any) -> PushConnector | None:
    """Return the appropriate push connector for a device, or None if not implemented."""
    vendor = device.vendor

    if vendor == "paloalto":
        try:
            from src.firewall.connectors.paloalto import PanOSConnector
            return PanOSConnector(device)
        except ImportError:
            pass

    # fortinet, cisco_asa, cisco_ftd — connectors not yet implemented
    return None
