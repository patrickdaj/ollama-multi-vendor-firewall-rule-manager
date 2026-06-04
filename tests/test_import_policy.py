"""Tests for the AI-assisted policy import pipeline.

Coverage:
  - _fast_normalize_object: rule-based paths for all simple object types
  - _parse_normalization_response: edge cases for LLM output formats
  - normalize_rule / normalize_object: full LLM normalization (@pytest.mark.llm)
  - End-to-end: load each enterprise config → normalize a sample of objects

Fast-path and parser tests run without Ollama (CI-safe).
LLM tests require a running Ollama instance: pytest -m llm
"""
from __future__ import annotations

from pathlib import Path

import pytest

from src.ai.import_policy import (
    _fast_normalize_object,
    _parse_normalization_response,
    normalize_object,
    normalize_rule,
)
from src.firewall.loaders import load_from_file

SAMPLES_DIR = Path(__file__).parent.parent / "data" / "configs" / "samples"

ENTERPRISE_CONFIGS = [
    ("paloalto_enterprise.xml",   "paloalto",  "pa-fw01"),
    ("fortinet_enterprise.json",  "fortinet",  "fg-fw01"),
    ("cisco_asa_enterprise.txt",  "cisco_asa", "asa-fw01"),
    ("cisco_ftd_enterprise.json", "cisco_ftd", "ftd-fw01"),
]


# ── _parse_normalization_response edge cases ──────────────────────────────────


def test_parse_wrapped_base_rule():
    raw = '{"base_rule": {"action": "allow", "src_zones": ["trust"]}, "reasoning": "ok"}'
    result = _parse_normalization_response(raw, key="base_rule")
    assert result["base_rule"]["action"] == "allow"
    assert result["reasoning"] == "ok"


def test_parse_wrapped_base_data():
    raw = '{"base_data": {"type": "ip-netmask", "value": "10.0.0.0/8"}, "reasoning": "direct"}'
    result = _parse_normalization_response(raw, key="base_data")
    assert result["base_data"]["type"] == "ip-netmask"


def test_parse_backtick_wrapped():
    raw = '```json\n{"base_rule": {"action": "deny"}, "reasoning": "test"}\n```'
    result = _parse_normalization_response(raw, key="base_rule")
    assert result["base_rule"]["action"] == "deny"


def test_parse_backtick_no_lang():
    raw = '```\n{"base_rule": {"action": "allow"}}\n```'
    result = _parse_normalization_response(raw, key="base_rule")
    assert result["base_rule"]["action"] == "allow"


def test_parse_llm_omits_wrapper_key():
    """LLM returns fields directly without the base_rule wrapper."""
    raw = '{"action": "allow", "src_zones": ["trust"], "dst_zones": ["untrust"]}'
    result = _parse_normalization_response(raw, key="base_rule")
    assert result["base_rule"]["action"] == "allow"
    assert result["base_rule"]["src_zones"] == ["trust"]


def test_parse_llm_omits_wrapper_preserves_reasoning():
    raw = '{"action": "deny", "reasoning": "blocked"}'
    result = _parse_normalization_response(raw, key="base_rule")
    assert result["base_rule"]["action"] == "deny"
    assert "reasoning" not in result["base_rule"]
    assert result["reasoning"] == "blocked"


def test_parse_empty_response():
    result = _parse_normalization_response("", key="base_rule")
    assert result["base_rule"] == {}
    assert "no json" in result["reasoning"].lower() or result["reasoning"] == ""


def test_parse_invalid_json():
    result = _parse_normalization_response("not json at all", key="base_rule")
    assert result["base_rule"] == {}


def test_parse_empty_object():
    result = _parse_normalization_response("{}", key="base_rule")
    assert result["base_rule"] == {}


# ── _fast_normalize_object: address_object ────────────────────────────────────


def test_fast_address_host():
    data = {"type": "host", "value": "10.0.0.1", "description": "test server"}
    result = _fast_normalize_object("address_object", data)
    assert result is not None
    assert result["base_data"]["type"] == "ip-netmask"
    assert result["base_data"]["value"] == "10.0.0.1"
    assert "no LLM" in result["reasoning"]


def test_fast_address_network():
    data = {"type": "ip_netmask", "value": "192.168.0.0/24"}
    result = _fast_normalize_object("address_object", data)
    assert result is not None
    assert result["base_data"]["type"] == "ip-netmask"


def test_fast_address_range():
    data = {"type": "ip_range", "value": "10.0.0.1-10.0.0.50"}
    result = _fast_normalize_object("address_object", data)
    assert result is not None
    assert result["base_data"]["type"] == "ip-range"


def test_fast_address_fqdn():
    data = {"type": "fqdn", "value": "example.com"}
    result = _fast_normalize_object("address_object", data)
    assert result is not None
    assert result["base_data"]["type"] == "fqdn"


def test_fast_address_fqdn_inferred():
    data = {"type": "host", "value": "updates.microsoft.com"}
    result = _fast_normalize_object("address_object", data)
    assert result is not None
    assert result["base_data"]["type"] == "fqdn"


# ── _fast_normalize_object: service_object ────────────────────────────────────


def test_fast_service_tcp():
    data = {"protocol": "tcp", "destination_port": "443", "description": "HTTPS"}
    result = _fast_normalize_object("service_object", data)
    assert result is not None
    assert result["base_data"]["protocol"] == "tcp"
    assert result["base_data"]["port"] == "443"


def test_fast_service_udp():
    data = {"protocol": "udp", "port": "53"}
    result = _fast_normalize_object("service_object", data)
    assert result is not None
    assert result["base_data"]["protocol"] == "udp"


def test_fast_service_range():
    data = {"protocol": "tcp", "dst_port": "8080-8090"}
    result = _fast_normalize_object("service_object", data)
    assert result is not None
    assert result["base_data"]["port"] == "8080-8090"


def test_fast_service_unknown_proto():
    data = {"protocol": "gre", "port": "0"}
    result = _fast_normalize_object("service_object", data)
    assert result is not None
    assert result["base_data"]["protocol"] == "any"


# ── _fast_normalize_object: service_group ────────────────────────────────────


def test_fast_service_group():
    data = {"members": ["HTTP", "HTTPS", "FTP"]}
    result = _fast_normalize_object("service_group", data)
    assert result is not None
    assert result["base_data"]["members"] == ["HTTP", "HTTPS", "FTP"]


def test_fast_service_group_string_member():
    data = {"member": "HTTP"}
    result = _fast_normalize_object("service_group", data)
    assert result is not None
    assert result["base_data"]["members"] == ["HTTP"]


# ── _fast_normalize_object: url_category ─────────────────────────────────────


def test_fast_url_category():
    data = {"categories": ["social-networking", "streaming-media"]}
    result = _fast_normalize_object("url_category", data)
    assert result is not None
    assert "social-networking" in result["base_data"]["categories"]


def test_fast_url_category_string():
    data = {"category": "malware"}
    result = _fast_normalize_object("url_category", data)
    assert result is not None
    assert result["base_data"]["categories"] == ["malware"]


# ── _fast_normalize_object: edl ──────────────────────────────────────────────


def test_fast_edl():
    data = {"type": "ip", "url": "https://feeds.example.com/ips.txt", "refresh_interval": 30}
    result = _fast_normalize_object("edl", data)
    assert result is not None
    assert result["base_data"]["type"] == "ip"
    assert result["base_data"]["url"] == "https://feeds.example.com/ips.txt"
    assert result["base_data"]["refresh_interval_minutes"] == 30


def test_fast_edl_defaults():
    data = {"type": "domain", "location": "https://cdn.example.com/domains.txt"}
    result = _fast_normalize_object("edl", data)
    assert result is not None
    assert result["base_data"]["refresh_interval_minutes"] == 60


# ── Rules require LLM — fast path returns None ───────────────────────────────


def test_fast_returns_none_for_security_rule():
    assert _fast_normalize_object("security_rule", {"action": "allow"}) is None


def test_fast_returns_none_for_nat_rule():
    assert _fast_normalize_object("nat_rule", {"nat_type": "pat"}) is None


def test_fast_returns_none_for_application():
    assert _fast_normalize_object("application", {"name": "ssl"}) is None


# ── Enterprise config: all fast-path objects succeed ─────────────────────────


@pytest.mark.parametrize("filename,vendor,device", ENTERPRISE_CONFIGS)
def test_fast_path_all_address_objects(filename, vendor, device):
    """Non-group address objects normalize via fast path; groups return None (LLM)."""
    policy = load_from_file(SAMPLES_DIR / filename, vendor, device)
    fast_count = 0
    for addr in policy.address_objects:
        data = addr.model_dump()
        result = _fast_normalize_object("address_object", data)
        if result is None:
            continue  # group/wildcard — LLM handles it
        assert result["base_data"].get("type") in ("ip-netmask", "ip-range", "fqdn"), \
            f"{vendor}: {addr.name} unexpected type {result['base_data'].get('type')}"
        assert result["base_data"].get("value"), \
            f"{vendor}: {addr.name} has empty value"
        fast_count += 1
    # At least half of addresses should hit the fast path
    total = len(policy.address_objects)
    assert fast_count >= total // 2, \
        f"{vendor}: only {fast_count}/{total} addresses hit fast path"


@pytest.mark.parametrize("filename,vendor,device", ENTERPRISE_CONFIGS)
def test_fast_path_all_service_objects(filename, vendor, device):
    policy = load_from_file(SAMPLES_DIR / filename, vendor, device)
    for svc in policy.service_objects:
        data = svc.model_dump()
        result = _fast_normalize_object("service_object", data)
        assert result is not None, f"{vendor}: {svc.name} returned None from fast path"
        assert result["base_data"].get("protocol") in ("tcp", "udp", "icmp", "any"), \
            f"{vendor}: {svc.name} unexpected protocol"


@pytest.mark.parametrize("filename,vendor,device", ENTERPRISE_CONFIGS)
def test_fast_path_all_service_groups(filename, vendor, device):
    policy = load_from_file(SAMPLES_DIR / filename, vendor, device)
    for grp in policy.service_groups:
        data = grp.model_dump()
        result = _fast_normalize_object("service_group", data)
        assert result is not None, f"{vendor}: {grp.name} returned None from fast path"
        assert isinstance(result["base_data"].get("members"), list), \
            f"{vendor}: {grp.name} members is not a list"


@pytest.mark.parametrize("filename,vendor,device", ENTERPRISE_CONFIGS)
def test_enterprise_config_has_rules(filename, vendor, device):
    """Sanity check: each enterprise config loads with at least some rules."""
    policy = load_from_file(SAMPLES_DIR / filename, vendor, device)
    assert len(policy.rules) > 0, f"{vendor}: no security rules loaded"


@pytest.mark.parametrize("filename,vendor,device", ENTERPRISE_CONFIGS)
def test_enterprise_config_has_addresses(filename, vendor, device):
    policy = load_from_file(SAMPLES_DIR / filename, vendor, device)
    assert len(policy.address_objects) > 0, f"{vendor}: no address objects loaded"


# ── LLM tests: normalize_rule for each vendor ────────────────────────────────

_GOOD_RULE_FIELDS = {"action", "src_zones", "dst_zones", "src_addresses", "dst_addresses"}
_GOOD_NAT_FIELDS = {"nat_type", "src_zones", "dst_zones"}


def _is_good_rule(base_rule: dict) -> bool:
    return bool(base_rule) and bool(base_rule.keys() & _GOOD_RULE_FIELDS)


def _is_good_nat(base_rule: dict) -> bool:
    return bool(base_rule) and bool(base_rule.keys() & _GOOD_NAT_FIELDS)


@pytest.mark.llm
@pytest.mark.parametrize("filename,vendor,device", ENTERPRISE_CONFIGS)
async def test_normalize_security_rules_llm(filename, vendor, device):
    """Normalize the first 3 security rules from each vendor config."""
    policy = load_from_file(SAMPLES_DIR / filename, vendor, device)
    rules = policy.rules[:3]
    assert rules, f"{vendor}: no rules to test"

    failures = []
    for rule in rules:
        result = await normalize_rule(
            vendor=vendor,
            rule_type="security_rule",
            rule_name=rule.name,
            vendor_data=rule.model_dump(),
        )
        if not _is_good_rule(result.get("base_rule", {})):
            failures.append(f"{rule.name}: {result}")

    assert not failures, f"{vendor} rule failures:\n" + "\n".join(failures)


@pytest.mark.llm
@pytest.mark.parametrize("filename,vendor,device", ENTERPRISE_CONFIGS)
async def test_normalize_nat_rules_llm(filename, vendor, device):
    """Normalize the first 2 NAT rules from each vendor config."""
    policy = load_from_file(SAMPLES_DIR / filename, vendor, device)
    if not policy.nat_rules:
        pytest.skip(f"{vendor}: no NAT rules in enterprise config")

    nat_rules = policy.nat_rules[:2]
    failures = []
    for rule in nat_rules:
        result = await normalize_rule(
            vendor=vendor,
            rule_type="nat_rule",
            rule_name=rule.name,
            vendor_data=rule.model_dump(),
        )
        if not _is_good_nat(result.get("base_rule", {})):
            failures.append(f"{rule.name}: {result}")

    assert not failures, f"{vendor} NAT failures:\n" + "\n".join(failures)


@pytest.mark.llm
@pytest.mark.parametrize("filename,vendor,device", ENTERPRISE_CONFIGS)
async def test_normalize_address_objects_llm(filename, vendor, device):
    """Fast path should handle address objects; verify no LLM fallthrough."""
    policy = load_from_file(SAMPLES_DIR / filename, vendor, device)
    # Use only non-group addresses (those that hit the fast path)
    addrs = [a for a in policy.address_objects if a.value][:5]
    if not addrs:
        pytest.skip(f"{vendor}: no non-group address objects")
    for addr in addrs:
        result = await normalize_object(
            vendor=vendor,
            object_type="address_object",
            object_name=addr.name,
            vendor_data=addr.model_dump(),
        )
        assert result["base_data"], f"{vendor}: {addr.name} returned empty base_data"
        assert "no LLM" in result["reasoning"], \
            f"{vendor}: {addr.name} unexpectedly called LLM for address object"


# ── LLM end-to-end: simulate a full import for each config ───────────────────


@pytest.mark.llm
@pytest.mark.parametrize("filename,vendor,device", ENTERPRISE_CONFIGS)
async def test_full_import_simulation_llm(filename, vendor, device):
    """Simulate the import preview for the first 20 objects of each config.

    Tests the same code path as the /import/preview endpoint: fast-path
    objects must all succeed, LLM objects must have >70% success rate.
    """
    _RULE_TYPES = {"security_rule", "nat_rule"}

    policy = load_from_file(SAMPLES_DIR / filename, vendor, device)

    candidates: list[tuple[str, str, dict]] = []
    sources = [
        ("security_rule", [(r.name, r.model_dump()) for r in policy.rules]),
        ("nat_rule",       [(r.name, r.model_dump()) for r in policy.nat_rules]),
        ("address_object", [(o.name, o.model_dump()) for o in policy.address_objects]),
        ("service_object", [(o.name, o.model_dump()) for o in policy.service_objects]),
        ("service_group",  [(o.name, o.model_dump()) for o in policy.service_groups]),
    ]
    for obj_type, items in sources:
        for name, data in items:
            candidates.append((obj_type, name, data))
            if len(candidates) >= 20:
                break
        if len(candidates) >= 20:
            break

    llm_objects = [(t, n, d) for t, n, d in candidates if t in _RULE_TYPES]
    fast_objects = [(t, n, d) for t, n, d in candidates if t not in _RULE_TYPES]

    # Fast-path objects must all succeed
    fast_failures = []
    for obj_type, name, data in fast_objects:
        result = await normalize_object(vendor=vendor, object_type=obj_type,
                                        object_name=name, vendor_data=data)
        if not result.get("base_data"):
            fast_failures.append(f"{obj_type}/{name}")
    assert not fast_failures, f"{vendor}: fast-path failures: {fast_failures}"

    if not llm_objects:
        return

    # LLM objects: allow up to 30% failure rate (LLM is non-deterministic)
    llm_failures = []
    for obj_type, name, data in llm_objects:
        result = await normalize_rule(vendor=vendor, rule_type=obj_type,
                                       rule_name=name, vendor_data=data)
        if not result.get("base_rule"):
            llm_failures.append(f"{obj_type}/{name}")

    failure_rate = len(llm_failures) / len(llm_objects)
    assert failure_rate <= 0.30, (
        f"{vendor}: LLM failure rate {failure_rate:.0%} > 30% "
        f"({len(llm_failures)}/{len(llm_objects)} failed): {llm_failures}"
    )
