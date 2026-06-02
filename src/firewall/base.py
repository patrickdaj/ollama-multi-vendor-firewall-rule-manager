"""Abstract base class for all firewall vendor connectors.

Each vendor subclass connects to the device's native API and maps the
vendor-specific response structures to the shared vendor-agnostic models.
No management platform intermediaries (Panorama, FortiManager, CDO) are used.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from src.config import DeviceConfig
from src.firewall.models import (
    AddressObject,
    ApplicationGroup,
    ApplicationObject,
    AuthPolicy,
    DecryptionProfile,
    DecryptionRule,
    DoSPolicy,
    EDL,
    FirewallPolicy,
    FirewallRule,
    NATRule,
    SecurityProfile,
    ServiceObject,
    URLCategory,
    ZoneDefinition,
)


class FirewallConnector(ABC):
    def __init__(self, device: DeviceConfig) -> None:
        self.device = device

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def disconnect(self) -> None: ...

    async def __aenter__(self) -> "FirewallConnector":
        await self.connect()
        return self

    async def __aexit__(self, *_) -> None:
        await self.disconnect()

    # ── Tier 1: Rulebases ─────────────────────────────────────────────────────

    @abstractmethod
    async def get_policy(self) -> FirewallPolicy:
        """Return the complete policy snapshot for this device."""

    @abstractmethod
    async def get_rules(self, rulebase: str = "security") -> list[FirewallRule]: ...

    @abstractmethod
    async def get_nat_rules(self) -> list[NATRule]: ...

    async def get_decryption_rules(self) -> list[DecryptionRule]:
        return []

    async def get_dos_policies(self) -> list[DoSPolicy]:
        return []

    async def get_auth_policies(self) -> list[AuthPolicy]:
        return []

    # ── Tier 2: Objects ───────────────────────────────────────────────────────

    @abstractmethod
    async def get_address_objects(self) -> list[AddressObject]: ...

    @abstractmethod
    async def get_service_objects(self) -> list[ServiceObject]: ...

    async def get_application_objects(self) -> list[ApplicationObject]:
        return []

    async def get_application_groups(self) -> list[ApplicationGroup]:
        return []

    async def get_url_categories(self) -> list[URLCategory]:
        return []

    # ── Tier 3: Profiles ──────────────────────────────────────────────────────

    async def get_security_profiles(self) -> list[SecurityProfile]:
        return []

    async def get_decryption_profiles(self) -> list[DecryptionProfile]:
        return []

    # ── Tier 4: Dynamic intelligence ─────────────────────────────────────────

    async def get_edls(self) -> list[EDL]:
        return []

    # ── Tier 5: Topology ──────────────────────────────────────────────────────

    async def get_zones(self) -> list[ZoneDefinition]:
        return []

    # ── Write operations (optional) ───────────────────────────────────────────

    async def push_rule(self, rule: FirewallRule) -> bool:
        raise NotImplementedError(f"{self.__class__.__name__} does not support rule push")

    async def delete_rule(self, rule_name: str) -> bool:
        raise NotImplementedError(f"{self.__class__.__name__} does not support rule delete")
