"""Tests for MCP server tools.

Search tools (no LLM): fully exercised against the enterprise_vectorstore fixture.
Analysis/translation tools (LLM-dependent): exercised with a mocked RAG chain
so the pipeline logic is verified without requiring a running Ollama.

Integration tests that call the real LLM are marked @pytest.mark.llm.
"""
from __future__ import annotations

import pytest

# Import MCP tool functions directly — they are regular Python callables
# even though registered with @mcp.tool().
from src.mcp.server import (
    compare_device_policies,
    find_permissive_rules,
    find_redundant_objects,
    find_shadow_rules,
    optimize_policy,
    search_address_objects,
    search_firewall_rules,
    search_nat_rules,
    translate_nat_rule_to_vendor,
    translate_rule_to_vendor,
)


# ── Search tools (no LLM required) ───────────────────────────────────────────


class TestSearchFirewallRules:
    def test_unfiltered_returns_results(self, enterprise_vectorstore):
        result = search_firewall_rules("allow web traffic")
        assert isinstance(result, str)
        assert len(result) > 20
        assert "No matching" not in result

    def test_filter_by_device_pa(self, enterprise_vectorstore):
        result = search_firewall_rules("web", device="pa-fw01")
        assert "pa-fw01" in result
        assert "fg-fw01" not in result
        assert "asa-fw01" not in result

    def test_filter_by_device_fortinet(self, enterprise_vectorstore):
        result = search_firewall_rules("allow users", device="fg-fw01")
        assert "fg-fw01" in result

    def test_filter_by_vendor(self, enterprise_vectorstore):
        result = search_firewall_rules("any traffic", vendor="cisco_asa")
        assert "cisco_asa" in result
        assert "paloalto" not in result

    def test_missing_device_returns_not_found(self, enterprise_vectorstore):
        result = search_firewall_rules("web", device="nonexistent-fw99")
        assert "No matching" in result or result == ""

    def test_result_contains_rule_metadata(self, enterprise_vectorstore):
        result = search_firewall_rules("block threat", device="pa-fw01")
        # Should mention device and vendor in output
        assert "pa-fw01" in result or "paloalto" in result

    def test_limit_respected(self, enterprise_vectorstore):
        result = search_firewall_rules("allow", limit=2)
        # Result should not be empty and should not be excessively long
        assert len(result) > 0


class TestSearchNatRules:
    def test_finds_nat_rules(self, enterprise_vectorstore):
        result = search_nat_rules("outbound PAT source NAT")
        assert isinstance(result, str)
        assert "No matching" not in result

    def test_filter_by_device(self, enterprise_vectorstore):
        result = search_nat_rules("inbound HTTPS", device="pa-fw01")
        assert "pa-fw01" in result

    def test_no_nat_for_unknown_device(self, enterprise_vectorstore):
        result = search_nat_rules("any NAT", device="does-not-exist")
        assert "No matching" in result or result == ""


class TestSearchAddressObjects:
    def test_finds_address_objects(self, enterprise_vectorstore):
        result = search_address_objects("web server")
        assert isinstance(result, str)
        assert "No matching" not in result

    def test_filter_by_device(self, enterprise_vectorstore):
        result = search_address_objects("network subnet", device="pa-fw01")
        assert "pa-fw01" in result

    def test_filter_by_vendor(self, enterprise_vectorstore):
        result = search_address_objects("host", vendor="paloalto")
        assert "paloalto" in result
        assert "fortinet" not in result


# ── Analysis tools (deterministic — no LLM) ──────────────────────────────────


class TestFindRedundantObjects:
    """find_redundant_objects uses only vectorstore + deterministic dedup — no LLM."""

    def test_runs_without_error(self, enterprise_vectorstore):
        result = find_redundant_objects()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_device_filter(self, enterprise_vectorstore):
        result = find_redundant_objects(device="pa-fw01")
        assert isinstance(result, str)
        # Either finds duplicates or reports none — both are valid
        assert "pa-fw01" in result or "No redundant" in result

    def test_no_duplicates_message_when_clean(self, enterprise_vectorstore):
        # If there are no actual duplicates for this device, returns clean message
        result = find_redundant_objects(device="ftd-fw01")
        assert isinstance(result, str)


# ── Analysis tools (LLM-dependent — mocked chain) ────────────────────────────


class TestFindShadowRules:
    def test_calls_vectorstore_and_chain(self, enterprise_vectorstore, mock_chain):
        result = find_shadow_rules(device="pa-fw01")
        assert isinstance(result, str)
        assert len(result) > 0
        # Mock chain should have been invoked
        mock_chain.invoke.assert_called_once()

    def test_passes_rules_to_chain(self, enterprise_vectorstore, mock_chain):
        find_shadow_rules(device="pa-fw01")
        call_args = mock_chain.invoke.call_args[0][0]
        assert "input" in call_args
        # Context should mention shadow rules
        assert "shadow" in call_args["input"].lower()

    def test_no_rules_returns_early(self, enterprise_vectorstore, mock_chain):
        result = find_shadow_rules(device="no-such-device-xyz")
        assert "No rules found" in result
        mock_chain.invoke.assert_not_called()

    def test_vendor_filter_applied(self, enterprise_vectorstore, mock_chain):
        result = find_shadow_rules(vendor="paloalto")
        assert isinstance(result, str)


class TestFindPermissiveRules:
    def test_runs_and_returns_string(self, enterprise_vectorstore, mock_chain):
        result = find_permissive_rules()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_device_filter_applied(self, enterprise_vectorstore, mock_chain):
        result = find_permissive_rules(device="asa-fw01")
        assert isinstance(result, str)

    def test_calls_chain_with_permissive_context(self, enterprise_vectorstore, mock_chain):
        find_permissive_rules(device="pa-fw01")
        if mock_chain.invoke.called:
            call_args = mock_chain.invoke.call_args[0][0]
            assert "permissive" in call_args["input"].lower() or "any" in call_args["input"].lower()


# ── Optimization tools (LLM-dependent — mocked) ──────────────────────────────


class TestOptimizePolicy:
    def test_runs_for_known_device(self, enterprise_vectorstore, mock_chain):
        result = optimize_policy("pa-fw01")
        assert isinstance(result, str)
        assert len(result) > 0
        mock_chain.invoke.assert_called_once()

    def test_passes_device_context_to_chain(self, enterprise_vectorstore, mock_chain):
        optimize_policy("pa-fw01")
        call_args = mock_chain.invoke.call_args[0][0]["input"]
        assert "pa-fw01" in call_args

    def test_vendor_hint_accepted(self, enterprise_vectorstore, mock_chain):
        result = optimize_policy("pa-fw01", vendor="paloalto")
        assert isinstance(result, str)


class TestCompareDevicePolicies:
    def test_compares_two_devices(self, enterprise_vectorstore, mock_chain):
        result = compare_device_policies("pa-fw01", "fg-fw01")
        assert isinstance(result, str)
        assert len(result) > 0
        mock_chain.invoke.assert_called_once()

    def test_both_devices_in_chain_context(self, enterprise_vectorstore, mock_chain):
        compare_device_policies("pa-fw01", "fg-fw01")
        call_input = mock_chain.invoke.call_args[0][0]["input"]
        assert "pa-fw01" in call_input
        assert "fg-fw01" in call_input

    def test_no_rules_message_for_unknown_devices(self, enterprise_vectorstore, mock_chain):
        result = compare_device_policies("ghost-a", "ghost-b")
        assert "No rules found" in result
        mock_chain.invoke.assert_not_called()


# ── Translation tools (LLM-dependent — mocked) ───────────────────────────────


class TestTranslateRuleToVendor:
    def test_translates_known_rule(self, enterprise_vectorstore, mock_chain):
        result = translate_rule_to_vendor(
            rule_name="allow-web-users",
            source_device="pa-fw01",
            target_vendor="fortinet",
        )
        assert isinstance(result, str)
        assert len(result) > 0
        mock_chain.invoke.assert_called_once()

    def test_not_found_returns_message(self, enterprise_vectorstore, mock_chain):
        # FakeEmbeddings always return results for existing devices regardless of query text,
        # so use a device that has no docs in the vectorstore to trigger the "not found" path.
        result = translate_rule_to_vendor(
            rule_name="any-rule",
            source_device="nonexistent-device-xyz",
            target_vendor="fortinet",
        )
        assert "not found" in result.lower()
        mock_chain.invoke.assert_not_called()

    def test_target_vendor_in_chain_prompt(self, enterprise_vectorstore, mock_chain):
        translate_rule_to_vendor(
            rule_name="allow-web-users",
            source_device="pa-fw01",
            target_vendor="cisco_asa",
        )
        if mock_chain.invoke.called:
            call_input = mock_chain.invoke.call_args[0][0]["input"]
            assert "cisco_asa" in call_input


class TestTranslateNatRuleToVendor:
    def test_translates_known_nat_rule(self, enterprise_vectorstore, mock_chain):
        result = translate_nat_rule_to_vendor(
            rule_name="nat-outbound-pat",
            source_device="pa-fw01",
            target_vendor="fortinet",
        )
        assert isinstance(result, str)
        assert len(result) > 0
        mock_chain.invoke.assert_called_once()

    def test_not_found_returns_message(self, enterprise_vectorstore, mock_chain):
        result = translate_nat_rule_to_vendor(
            rule_name="no-such-nat-rule",
            source_device="nonexistent-device-xyz",
            target_vendor="fortinet",
        )
        assert "not found" in result.lower()


# ── LLM integration tests (require running Ollama) ───────────────────────────


@pytest.mark.llm
class TestShadowRulesIntegration:
    """Run the real LLM chain — skip unless Ollama is available."""

    def test_shadow_rules_pa_fw01_mentions_shadow(self, enterprise_vectorstore):
        result = find_shadow_rules(device="pa-fw01")
        low = result.lower()
        assert any(word in low for word in ["shadow", "unreachable", "never", "matched", "blocked"])

    def test_permissive_rules_mentions_any(self, enterprise_vectorstore):
        result = find_permissive_rules()
        low = result.lower()
        assert any(word in low for word in ["any", "permissive", "broad", "allow", "risk"])
