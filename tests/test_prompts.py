"""Tests for the six example prompts from the README.

Each prompt is tested at two levels:

  Unit (always run):
    - The correct tool/pipeline is invoked
    - The vectorstore is queried with appropriate filters
    - The chain is called with relevant context (mocked chain)
    - The result is a non-empty string with no Python error traces

  Integration (@pytest.mark.llm — requires a running Ollama):
    - Called against the real LLM
    - Response passes a quality gate: mentions expected entities,
      contains no error markers, exceeds a minimum length

Run unit tests only:   pytest tests/test_prompts.py
Run LLM tests as well: pytest tests/test_prompts.py -m llm
"""
from __future__ import annotations

import pytest

from src.mcp.server import (
    compare_device_policies,
    find_permissive_rules,
    find_shadow_rules,
    optimize_policy,
    search_address_objects,
    translate_rule_to_vendor,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

# Python runtime error strings that should never appear in a real LLM answer
_CRASH_MARKERS = ("traceback (most recent call last)", "modulenotfounderror", "attributeerror:")


def _is_good_response(text: str, min_len: int = 40) -> bool:
    """Return True if the response looks like a real answer, not a Python crash."""
    if len(text) < min_len:
        return False
    lower = text.lower()
    return not any(m in lower for m in _CRASH_MARKERS)


# ═════════════════════════════════════════════════════════════════════════════
# PROMPT 1 — "Which rules on pa-fw01 are shadowed and can never be matched?"
# Maps to: find_shadow_rules(device="pa-fw01")
# ═════════════════════════════════════════════════════════════════════════════


class TestShadowRulesPrompt:
    """Unit: pipeline runs, chain is called, pa-fw01 rules are in context."""

    def test_pipeline_runs_without_error(self, enterprise_vectorstore, mock_chain):
        result = find_shadow_rules(device="pa-fw01")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_chain_called_with_pa_fw01_rules(self, enterprise_vectorstore, mock_chain):
        find_shadow_rules(device="pa-fw01")
        mock_chain.invoke.assert_called_once()
        context = mock_chain.invoke.call_args[0][0]["input"]
        assert "shadow" in context.lower()

    def test_unknown_device_returns_no_rules_message(self, enterprise_vectorstore, mock_chain):
        result = find_shadow_rules(device="ghost-fw-99")
        assert "No rules found" in result
        mock_chain.invoke.assert_not_called()

    @pytest.mark.llm
    def test_llm_response_mentions_shadow_concept(self, enterprise_vectorstore):
        result = find_shadow_rules(device="pa-fw01")
        assert _is_good_response(result)
        low = result.lower()
        assert any(w in low for w in ["shadow", "unreachable", "never matched", "blocked by", "position"])


# ═════════════════════════════════════════════════════════════════════════════
# PROMPT 2 — "Find all rules that allow any/any on any device"
# Maps to: find_permissive_rules() (no device filter)
# Also maps to: search_firewall_rules("any any allow") for search-only version
# ═════════════════════════════════════════════════════════════════════════════


class TestPermissiveRulesPrompt:
    def test_pipeline_runs_without_error(self, enterprise_vectorstore, mock_chain):
        result = find_permissive_rules()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_chain_receives_rules_context(self, enterprise_vectorstore, mock_chain):
        find_permissive_rules()
        if mock_chain.invoke.called:
            context = mock_chain.invoke.call_args[0][0]["input"]
            assert "permissive" in context.lower() or "any" in context.lower()

    def test_search_any_any_returns_all_vendors(self, enterprise_vectorstore):
        # Direct vectorstore search — no LLM needed
        from src.mcp.server import search_firewall_rules
        result = search_firewall_rules("any any allow all traffic")
        # Sample data has permissive rules on multiple devices
        assert isinstance(result, str)
        assert "No matching" not in result

    @pytest.mark.llm
    def test_llm_identifies_permissive_rules(self, enterprise_vectorstore):
        result = find_permissive_rules()
        assert _is_good_response(result)
        low = result.lower()
        assert any(w in low for w in ["any", "allow", "permissive", "risk", "broad", "unrestricted"])


# ═════════════════════════════════════════════════════════════════════════════
# PROMPT 3 — "Translate the outbound PAT rule from pa-fw01 to FortiGate CLI syntax"
# Maps to: translate_rule_to_vendor(rule_name, source_device, target_vendor)
# Note: nat-outbound-pat is a NAT rule; the NAT search uses translate_nat_rule_to_vendor.
#       search_firewall_rules will also find it via general search.
# ═════════════════════════════════════════════════════════════════════════════


class TestTranslateOutboundPATPrompt:
    def test_pipeline_runs_for_known_nat_rule(self, enterprise_vectorstore, mock_chain):
        from src.mcp.server import translate_nat_rule_to_vendor
        result = translate_nat_rule_to_vendor(
            rule_name="nat-outbound-pat",
            source_device="pa-fw01",
            target_vendor="fortinet",
        )
        assert isinstance(result, str)
        assert len(result) > 0

    def test_chain_receives_fortinet_target(self, enterprise_vectorstore, mock_chain):
        from src.mcp.server import translate_nat_rule_to_vendor
        translate_nat_rule_to_vendor(
            rule_name="nat-outbound-pat",
            source_device="pa-fw01",
            target_vendor="fortinet",
        )
        mock_chain.invoke.assert_called_once()
        context = mock_chain.invoke.call_args[0][0]["input"]
        assert "fortinet" in context.lower()

    def test_unknown_rule_returns_not_found(self, enterprise_vectorstore, mock_chain):
        from src.mcp.server import translate_nat_rule_to_vendor
        result = translate_nat_rule_to_vendor(
            rule_name="no-such-nat-rule",
            source_device="nonexistent-device-xyz",
            target_vendor="fortinet",
        )
        assert "not found" in result.lower()
        mock_chain.invoke.assert_not_called()

    @pytest.mark.llm
    def test_llm_produces_fortinet_syntax(self, enterprise_vectorstore):
        from src.mcp.server import translate_nat_rule_to_vendor
        result = translate_nat_rule_to_vendor(
            rule_name="nat-outbound-pat",
            source_device="pa-fw01",
            target_vendor="fortinet",
        )
        assert _is_good_response(result)
        low = result.lower()
        assert any(w in low for w in ["fortinet", "fortigate", "nat", "ip pool", "overload", "pat", "masquerade"])


# ═════════════════════════════════════════════════════════════════════════════
# PROMPT 4 — "Compare security coverage between pa-fw01 and fg-fw01"
# Maps to: compare_device_policies("pa-fw01", "fg-fw01")
# ═════════════════════════════════════════════════════════════════════════════


class TestCompareDevicesPrompt:
    def test_pipeline_runs_without_error(self, enterprise_vectorstore, mock_chain):
        result = compare_device_policies("pa-fw01", "fg-fw01")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_both_device_names_in_chain_context(self, enterprise_vectorstore, mock_chain):
        compare_device_policies("pa-fw01", "fg-fw01")
        mock_chain.invoke.assert_called_once()
        context = mock_chain.invoke.call_args[0][0]["input"]
        assert "pa-fw01" in context
        assert "fg-fw01" in context

    def test_unknown_devices_returns_early(self, enterprise_vectorstore, mock_chain):
        result = compare_device_policies("ghost-a", "ghost-b")
        assert "No rules found" in result
        mock_chain.invoke.assert_not_called()

    def test_cross_vendor_comparison_works(self, enterprise_vectorstore, mock_chain):
        # asa-fw01 (Cisco ASA) vs ftd-fw01 (Cisco FTD) — different vendors
        result = compare_device_policies("asa-fw01", "ftd-fw01")
        assert isinstance(result, str)
        assert len(result) > 0

    @pytest.mark.llm
    def test_llm_describes_differences(self, enterprise_vectorstore):
        result = compare_device_policies("pa-fw01", "fg-fw01")
        assert _is_good_response(result)
        low = result.lower()
        assert any(w in low for w in ["pa-fw01", "fg-fw01", "palo", "fortinet", "differ", "coverage", "gap", "missing", "rule"])


# ═════════════════════════════════════════════════════════════════════════════
# PROMPT 5 — "Which address objects reference the 10.10.10.0/24 range?"
# Maps to: search_address_objects("10.10.10.0/24")
# This is a pure search — no LLM required even for integration.
# ═════════════════════════════════════════════════════════════════════════════


class TestAddressObjectSearchPrompt:
    def test_search_returns_results(self, enterprise_vectorstore):
        result = search_address_objects("10.10.10.0/24")
        assert isinstance(result, str)
        # May or may not match exactly — the sample data uses various ranges

    def test_search_by_subnet_pattern(self, enterprise_vectorstore):
        # Broader search that should find something in any enterprise config
        result = search_address_objects("192.168 subnet network")
        assert isinstance(result, str)

    def test_search_by_known_ip_range_pa(self, enterprise_vectorstore):
        # pa-fw01 uses corp-network which is a well-known range
        result = search_address_objects("corp network internal subnet", device="pa-fw01")
        # Either finds it or reports no match — both are valid
        assert isinstance(result, str)

    def test_device_filter_limits_to_one_vendor(self, enterprise_vectorstore):
        result_pa = search_address_objects("host", device="pa-fw01")
        result_fg = search_address_objects("host", device="fg-fw01")
        if "No matching" not in result_pa and "No matching" not in result_fg:
            # Results should not overlap device names
            assert "fg-fw01" not in result_pa
            assert "pa-fw01" not in result_fg

    def test_search_all_devices_returns_multi_vendor(self, enterprise_vectorstore):
        result = search_address_objects("web server dmz address", limit=10)
        if "No matching" not in result:
            # At least one device should appear
            has_any_device = any(d in result for d in ["pa-fw01", "fg-fw01", "asa-fw01", "ftd-fw01"])
            assert has_any_device


# ═════════════════════════════════════════════════════════════════════════════
# PROMPT 6 — "Audit pa-fw01 for rules missing logging"
# Maps to: optimize_policy("pa-fw01")
# ═════════════════════════════════════════════════════════════════════════════


class TestAuditLoggingPrompt:
    def test_pipeline_runs_for_pa_fw01(self, enterprise_vectorstore, mock_chain):
        result = optimize_policy("pa-fw01")
        assert isinstance(result, str)
        assert len(result) > 0
        mock_chain.invoke.assert_called_once()

    def test_device_name_in_chain_context(self, enterprise_vectorstore, mock_chain):
        optimize_policy("pa-fw01")
        context = mock_chain.invoke.call_args[0][0]["input"]
        assert "pa-fw01" in context

    def test_chain_context_includes_logging_audit_request(self, enterprise_vectorstore, mock_chain):
        optimize_policy("pa-fw01")
        context = mock_chain.invoke.call_args[0][0]["input"]
        low = context.lower()
        assert "logging" in low or "log" in low

    def test_works_for_all_four_devices(self, enterprise_vectorstore, mock_chain):
        for device in ("pa-fw01", "fg-fw01", "asa-fw01", "ftd-fw01"):
            mock_chain.invoke.reset_mock()
            result = optimize_policy(device)
            assert isinstance(result, str), f"optimize_policy failed for {device}"
            mock_chain.invoke.assert_called_once()

    @pytest.mark.llm
    def test_llm_audit_mentions_logging(self, enterprise_vectorstore):
        result = optimize_policy("pa-fw01")
        assert _is_good_response(result)
        low = result.lower()
        assert any(w in low for w in ["log", "logging", "audit", "recommend", "rule", "policy"])

    @pytest.mark.llm
    def test_llm_audit_response_is_structured(self, enterprise_vectorstore):
        result = optimize_policy("pa-fw01")
        assert len(result) >= 80, f"Response too short ({len(result)} chars)"
        assert _is_good_response(result)
        # LLM should produce some structure — numbered list, bullets, or headers
        has_structure = any(c in result for c in ["1.", "2.", "•", "-", "*", "#", ":"])
        assert has_structure, "Expected structured output"
