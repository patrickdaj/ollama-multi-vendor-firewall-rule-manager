"""Config file loaders — parse exported vendor configs into FirewallPolicy objects.

These loaders let you bootstrap the RAG from saved config files without
live device access.  The real-time workflow (connector → get_policy() →
ingest_policy()) is always preferred for production; use these for local
development and testing.
"""
from __future__ import annotations

import json
from pathlib import Path

from src.firewall.models import FirewallPolicy


def load_from_file(path: str | Path, vendor: str, device: str) -> FirewallPolicy:
    """Detect format from vendor and parse the file into a FirewallPolicy."""
    p = Path(path)
    match vendor:
        case "paloalto":
            from src.firewall.loaders.paloalto_xml import load_paloalto_xml
            return load_paloalto_xml(p, device)
        case "fortinet":
            from src.firewall.loaders.fortinet_json import load_fortinet_json
            return load_fortinet_json(p, device)
        case "cisco_asa" | "cisco_asa_ssh":
            from src.firewall.loaders.cisco_asa_cli import load_cisco_asa_cli
            return load_cisco_asa_cli(p, device)
        case "cisco_ftd":
            from src.firewall.loaders.cisco_ftd_json import load_cisco_ftd_json
            return load_cisco_ftd_json(p, device)
        case _:
            raise ValueError(f"No loader for vendor: {vendor}")
