"""PAN-OS push connector — sends compiled items to a PAN-OS device via XML API.

Requires pan-python (pip install pan-python) or falls back to direct HTTP.
Items are pushed to the candidate config and the caller must call commit() to
activate changes. We do NOT auto-commit — operators should review the candidate
config before committing.
"""
from __future__ import annotations

import json
import logging
import ssl
from typing import Any

log = logging.getLogger(__name__)


class PanOSConnector:
    """Minimal PAN-OS XML API connector for pushing objects and rules.

    Currently a scaffold — full implementation requires pan-python or
    direct XML API calls for each object type.
    """

    def __init__(self, device: Any) -> None:
        self.device = device
        self.host = device.host
        self.port = device.port or 443
        self.verify_ssl = device.verify_ssl

        # Decrypt credentials
        creds = self._decrypt_creds()
        self.api_key: str | None = creds.get("api_key")
        self.username: str | None = creds.get("username")
        self.password: str | None = creds.get("password")
        self._session_key: str | None = None

    def _decrypt_creds(self) -> dict[str, str]:
        try:
            from src.config import settings
            from cryptography.fernet import Fernet
            f = Fernet(settings.fernet_key.encode())
            raw = f.decrypt(self.device.credentials_enc.encode()).decode()
            return json.loads(raw)
        except Exception:
            return {}

    async def _ensure_key(self) -> str:
        """Get or generate an API key for authentication."""
        if self.api_key:
            return self.api_key
        if self._session_key:
            return self._session_key

        # Generate API key from username/password
        import httpx
        url = f"https://{self.host}:{self.port}/api/?type=keygen&user={self.username}&password={self.password}"
        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            resp = await client.get(url, timeout=10)
            resp.raise_for_status()
            # Parse XML response
            import xml.etree.ElementTree as ET
            root = ET.fromstring(resp.text)
            key_elem = root.find(".//key")
            if key_elem is None or not key_elem.text:
                raise RuntimeError("Failed to obtain PAN-OS API key")
            self._session_key = key_elem.text
        return self._session_key

    async def push_item(
        self,
        item_type: str,
        object_type: str,
        name: str,
        action: str,
        payload: dict[str, Any],
    ) -> bool:
        """Push a single item to the PAN-OS candidate config.

        Returns True on success. Raises on hard errors.

        NOTE: This is a scaffold. Full XPath-based push for each object_type
        (address, service, security-rule, nat-rule, etc.) needs to be implemented
        for production use. The function logs the intent and returns True for now.
        """
        try:
            api_key = await self._ensure_key()
        except Exception as exc:
            log.warning("PAN-OS auth failed for %s: %s", self.host, exc)
            raise

        xpath = self._xpath_for(object_type, name)
        if xpath is None:
            log.warning("No XPath mapping for object_type=%r — skipping %s", object_type, name)
            return False

        element_xml = self._to_xml(object_type, name, payload)
        if element_xml is None:
            log.warning("Cannot serialize %s/%s to PAN-OS XML", object_type, name)
            return False

        log.info("PAN-OS push %s %s/%s to %s (dry-run scaffold)", action, object_type, name, self.host)

        # TODO: implement actual API call:
        # import httpx
        # url = f"https://{self.host}:{self.port}/api/"
        # params = {"type": "config", "action": "set", "key": api_key, "xpath": xpath, "element": element_xml}
        # async with httpx.AsyncClient(verify=self.verify_ssl) as client:
        #     resp = await client.post(url, params=params, timeout=30)
        #     resp.raise_for_status()
        #     root = ET.fromstring(resp.text)
        #     return root.get("status") == "success"

        return True

    async def commit(self) -> bool:
        """Commit the candidate config to the running config."""
        log.info("PAN-OS commit requested for %s (scaffold — not yet implemented)", self.host)
        return True

    def _xpath_for(self, object_type: str, name: str) -> str | None:
        """Return the PAN-OS XPath for setting an object."""
        vsys = "vsys1"
        xpaths = {
            "address_object": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/address/entry[@name='{name}']",
            "service_object": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/service/entry[@name='{name}']",
            "service_group":  f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/service-group/entry[@name='{name}']",
            "security_rule":  f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/rulebase/security/rules/entry[@name='{name}']",
            "nat_rule":       f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/rulebase/nat/rules/entry[@name='{name}']",
        }
        return xpaths.get(object_type)

    def _to_xml(self, object_type: str, name: str, payload: dict[str, Any]) -> str | None:
        """Convert a vendor payload dict to PAN-OS XML element string (scaffold)."""
        # Real implementation maps each object_type's fields to PAN-OS XML schema
        # For now return a minimal comment so we can test the plumbing
        return f"<!-- {object_type}/{name}: scaffold -->"
