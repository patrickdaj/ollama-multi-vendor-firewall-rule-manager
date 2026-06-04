"""Tests for vendor config file loaders.

Each loader parses an exported vendor config file into a FirewallPolicy.
Tests use the enterprise sample files in data/configs/samples/ — no live
devices or LLM required.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from src.firewall.loaders import load_from_file
from src.firewall.models import AddressType, NATType, RuleAction

SAMPLES = Path(__file__).parent.parent / "data" / "configs" / "samples"


# ── Palo Alto PAN-OS XML ──────────────────────────────────────────────────────


class TestPaloAltoLoader:
    @pytest.fixture(autouse=True)
    def policy(self):
        self.p = load_from_file(SAMPLES / "paloalto_enterprise.xml", "paloalto", "pa-fw01")

    def test_vendor_and_device(self):
        assert self.p.vendor == "paloalto"
        assert self.p.device == "pa-fw01"

    def test_rule_count(self):
        assert len(self.p.rules) >= 10

    def test_nat_rule_count(self):
        assert len(self.p.nat_rules) >= 3

    def test_address_object_count(self):
        assert len(self.p.address_objects) >= 10

    def test_known_security_rules_present(self):
        names = {r.name for r in self.p.rules}
        assert "block-threat-intel" in names
        assert "allow-web-users" in names

    def test_known_nat_rules_present(self):
        names = {r.name for r in self.p.nat_rules}
        assert "nat-outbound-pat" in names
        assert "nat-inbound-https-web" in names

    def test_outbound_pat_is_pat_type(self):
        pat = next(r for r in self.p.nat_rules if r.name == "nat-outbound-pat")
        assert pat.nat_type == NATType.PAT

    def test_known_address_objects_present(self):
        names = {a.name for a in self.p.address_objects}
        assert "corp-network" in names
        assert "dc-01" in names

    def test_rules_have_vendor_device_tags(self):
        for rule in self.p.rules:
            assert rule.vendor == "paloalto"
            assert rule.device == "pa-fw01"

    def test_deny_rules_exist(self):
        deny_rules = [r for r in self.p.rules if r.action == RuleAction.DENY]
        assert len(deny_rules) >= 1

    def test_allow_rules_exist(self):
        allow_rules = [r for r in self.p.rules if r.action == RuleAction.ALLOW]
        assert len(allow_rules) >= 1

    def test_address_objects_have_names(self):
        for addr in self.p.address_objects:
            assert addr.name  # every object must have a non-empty name


# ── Fortinet FortiGate JSON ───────────────────────────────────────────────────


class TestFortinetLoader:
    @pytest.fixture(autouse=True)
    def policy(self):
        self.p = load_from_file(SAMPLES / "fortinet_enterprise.json", "fortinet", "fg-fw01")

    def test_vendor_and_device(self):
        assert self.p.vendor == "fortinet"
        assert self.p.device == "fg-fw01"

    def test_rule_count(self):
        assert len(self.p.rules) >= 10

    def test_address_object_count(self):
        assert len(self.p.address_objects) >= 10

    def test_known_security_rules_present(self):
        names = {r.name for r in self.p.rules}
        assert "block-threat-feeds" in names
        assert "allow-users-web" in names

    def test_rules_have_vendor_device_tags(self):
        for rule in self.p.rules:
            assert rule.vendor == "fortinet"
            assert rule.device == "fg-fw01"

    def test_allow_and_deny_rules(self):
        actions = {r.action for r in self.p.rules}
        assert RuleAction.ALLOW in actions
        assert RuleAction.DENY in actions


# ── Cisco ASA CLI ─────────────────────────────────────────────────────────────


class TestCiscoASACLILoader:
    @pytest.fixture(autouse=True)
    def policy(self):
        self.p = load_from_file(SAMPLES / "cisco_asa_enterprise.txt", "cisco_asa", "asa-fw01")

    def test_vendor_and_device(self):
        assert self.p.vendor == "cisco_asa"
        assert self.p.device == "asa-fw01"

    def test_rule_count(self):
        assert len(self.p.rules) >= 10

    def test_address_object_count(self):
        assert len(self.p.address_objects) >= 10

    def test_known_rules_present(self):
        names = {r.name for r in self.p.rules}
        # ACL entries parsed from the enterprise sample
        assert any("OUTSIDE_IN" in n or "INSIDE_OUT" in n for n in names)

    def test_known_address_objects_present(self):
        names = {a.name for a in self.p.address_objects}
        assert "web-server-prod" in names or "corp-users" in names

    def test_nat_rules_present(self):
        assert len(self.p.nat_rules) >= 1

    def test_rules_have_vendor_device_tags(self):
        for rule in self.p.rules:
            assert rule.vendor == "cisco_asa"
            assert rule.device == "asa-fw01"


# ── Cisco FTD JSON ────────────────────────────────────────────────────────────


class TestCiscoFTDLoader:
    @pytest.fixture(autouse=True)
    def policy(self):
        self.p = load_from_file(SAMPLES / "cisco_ftd_enterprise.json", "cisco_ftd", "ftd-fw01")

    def test_vendor_and_device(self):
        assert self.p.vendor == "cisco_ftd"
        assert self.p.device == "ftd-fw01"

    def test_rule_count(self):
        assert len(self.p.rules) >= 8

    def test_address_object_count(self):
        assert len(self.p.address_objects) >= 8

    def test_known_security_rules_present(self):
        names = {r.name for r in self.p.rules}
        assert "block-threat-intelligence" in names
        assert "allow-users-web-saas" in names

    def test_nat_rules_present(self):
        assert len(self.p.nat_rules) >= 2

    def test_rules_have_vendor_device_tags(self):
        for rule in self.p.rules:
            assert rule.vendor == "cisco_ftd"
            assert rule.device == "ftd-fw01"

    def test_allow_rules_have_action(self):
        allow_rules = [r for r in self.p.rules if r.action == RuleAction.ALLOW]
        assert len(allow_rules) >= 1


# ── Cross-loader ──────────────────────────────────────────────────────────────


class TestLoaderDispatch:
    def test_invalid_vendor_raises(self):
        with pytest.raises((ValueError, KeyError, Exception)):
            load_from_file(SAMPLES / "paloalto_enterprise.xml", "unknown_vendor", "dev1")

    def test_all_four_loaders_produce_non_empty_policy(self):
        configs = [
            ("paloalto_enterprise.xml",  "paloalto",  "pa-fw01"),
            ("fortinet_enterprise.json", "fortinet",  "fg-fw01"),
            ("cisco_asa_enterprise.txt", "cisco_asa", "asa-fw01"),
            ("cisco_ftd_enterprise.json","cisco_ftd",  "ftd-fw01"),
        ]
        for filename, vendor, device in configs:
            policy = load_from_file(SAMPLES / filename, vendor, device)
            assert len(policy.rules) > 0, f"{vendor}: no rules loaded"
            assert policy.vendor == vendor
            assert policy.device == device
