"""Unit tests for vendor-agnostic firewall data models."""
import pytest

from src.firewall.models import (
    AddressObject,
    AddressType,
    FirewallPolicy,
    FirewallRule,
    NATRule,
    NATType,
    RuleAction,
    ServiceObject,
)


class TestFirewallRule:
    def test_to_text_includes_all_fields(self):
        rule = FirewallRule(
            name="allow-web",
            action=RuleAction.ALLOW,
            src_zones=["trust"],
            dst_zones=["untrust"],
            src_addresses=["10.0.0.0/8"],
            dst_addresses=["any"],
            services=["HTTP", "HTTPS"],
            applications=["web-browsing"],
            profiles={"antivirus": "strict-av"},
            description="Outbound web",
            tags=["prod"],
            vendor="paloalto",
            device="fw01",
        )
        text = rule.to_text()
        assert "allow-web" in text
        assert "trust" in text
        assert "allow" in text
        assert "web-browsing" in text
        assert "antivirus=strict-av" in text
        assert "Outbound web" in text
        assert "prod" in text

    def test_disabled_rule_text(self):
        rule = FirewallRule(name="disabled-rule", action=RuleAction.DENY, enabled=False)
        assert "False" in rule.to_text()

    def test_default_rulebase(self):
        rule = FirewallRule(name="r", action=RuleAction.ALLOW)
        assert rule.rulebase == "security"


class TestNATRule:
    def test_dnat_to_text(self):
        rule = NATRule(
            name="webserver-vip",
            nat_type=NATType.DNAT,
            dst_addresses=["203.0.113.10"],
            translated_dst="192.168.1.50",
            translated_port="443",
            vendor="fortinet",
            device="fg01",
        )
        text = rule.to_text()
        assert "NAT Rule: webserver-vip" in text
        assert "dnat" in text
        assert "203.0.113.10" in text
        assert "192.168.1.50" in text
        assert "443" in text

    def test_pat_rule(self):
        rule = NATRule(
            name="outbound-pat",
            nat_type=NATType.PAT,
            src_addresses=["10.0.0.0/8"],
            translated_src="203.0.113.1",
            vendor="cisco_asa",
            device="asa01",
        )
        assert "pat" in rule.to_text()
        assert "203.0.113.1" in rule.to_text()

    def test_nat_rulebase_default(self):
        rule = NATRule(name="n", nat_type=NATType.STATIC)
        assert rule.rulebase == "nat"


class TestAddressObject:
    def test_host_to_text(self):
        obj = AddressObject(name="db-server", type=AddressType.HOST, value="10.0.2.5")
        text = obj.to_text()
        assert "db-server" in text
        assert "10.0.2.5" in text

    def test_group_to_text(self):
        obj = AddressObject(
            name="web-group",
            type=AddressType.GROUP,
            members=["web-01", "web-02", "web-03"],
        )
        text = obj.to_text()
        assert "web-group" in text
        assert "web-01" in text

    def test_fqdn(self):
        obj = AddressObject(name="example", type=AddressType.FQDN, value="example.com")
        assert "example.com" in obj.to_text()


class TestServiceObject:
    def test_tcp_service(self):
        svc = ServiceObject(name="custom-https", protocol="tcp", port="8443")
        text = svc.to_text()
        assert "custom-https" in text
        assert "tcp" in text
        assert "8443" in text

    def test_any_protocol_default(self):
        svc = ServiceObject(name="any-svc")
        assert svc.protocol == "tcp"


class TestFirewallPolicy:
    def test_rule_count(self, paloalto_policy):
        assert paloalto_policy.rule_count() > 0

    def test_nat_count(self, paloalto_policy):
        assert paloalto_policy.nat_count() > 0

    def test_find_rule_found(self, paloalto_policy):
        rule = paloalto_policy.find_rule("allow-web-out")
        assert rule is not None
        assert rule.action == RuleAction.ALLOW

    def test_find_rule_not_found(self, paloalto_policy):
        assert paloalto_policy.find_rule("nonexistent-rule") is None

    def test_find_nat_rule(self, paloalto_policy):
        rule = paloalto_policy.find_nat_rule("outbound-pat")
        assert rule is not None
        assert rule.nat_type == NATType.PAT

    def test_find_address(self, paloalto_policy):
        addr = paloalto_policy.find_address("web-server-01")
        assert addr is not None
        assert addr.value == "10.0.1.100"

    def test_policy_serialization(self, paloalto_policy):
        data = paloalto_policy.model_dump()
        restored = FirewallPolicy(**data)
        assert restored.rule_count() == paloalto_policy.rule_count()
        assert restored.vendor == "paloalto"
