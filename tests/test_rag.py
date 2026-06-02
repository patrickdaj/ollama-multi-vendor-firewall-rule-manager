"""Tests for RAG ingestion pipeline.

Uses an in-memory ChromaDB (via the in_memory_vectorstore fixture in conftest)
so no external services are required.
"""
from __future__ import annotations

import pytest

from src.firewall.models import FirewallPolicy, FirewallRule, NATRule, NATType, RuleAction
from src.rag.loader import ingest_policy, ingest_raw_text


class TestIngestPolicy:
    def test_ingest_security_rules(self, in_memory_vectorstore, paloalto_policy):
        count = ingest_policy(paloalto_policy)
        assert count > 0
        # Rules should be retrievable
        docs = in_memory_vectorstore.similarity_search("allow web traffic", k=10)
        assert any("allow-web-out" in d.page_content for d in docs)

    def test_ingest_nat_rules(self, in_memory_vectorstore, paloalto_policy):
        ingest_policy(paloalto_policy)
        docs = in_memory_vectorstore.similarity_search("destination NAT port forward", k=10)
        assert any("dnat" in d.metadata.get("type", "") or "nat" in d.page_content.lower() for d in docs)

    def test_ingest_address_objects(self, in_memory_vectorstore, paloalto_policy):
        ingest_policy(paloalto_policy)
        docs = in_memory_vectorstore.similarity_search("web server host address", k=10)
        assert any("web-server-01" in d.page_content for d in docs)

    def test_ingest_metadata_types(self, in_memory_vectorstore, paloalto_policy):
        ingest_policy(paloalto_policy)
        all_docs = in_memory_vectorstore.similarity_search("rule", k=100)
        types = {d.metadata.get("type") for d in all_docs}
        assert "security_rule" in types
        assert "nat_rule" in types
        assert "address_object" in types

    def test_ingest_idempotent(self, in_memory_vectorstore, paloalto_policy):
        count1 = ingest_policy(paloalto_policy)
        count2 = ingest_policy(paloalto_policy)
        # Second ingest should produce same count (updates, not duplicates)
        assert count1 == count2

    def test_ingest_empty_policy(self, in_memory_vectorstore):
        empty = FirewallPolicy(vendor="paloalto", device="empty-fw")
        count = ingest_policy(empty)
        assert count == 0

    def test_vendor_metadata_preserved(self, in_memory_vectorstore, paloalto_policy):
        ingest_policy(paloalto_policy)
        docs = in_memory_vectorstore.similarity_search("rule", k=50,
                                                       filter={"vendor": "paloalto"})
        assert all(d.metadata.get("vendor") == "paloalto" for d in docs)

    def test_device_metadata_preserved(self, in_memory_vectorstore, paloalto_policy):
        ingest_policy(paloalto_policy)
        docs = in_memory_vectorstore.similarity_search("rule", k=50,
                                                       filter={"device": "pa-fw01"})
        assert all(d.metadata.get("device") == "pa-fw01" for d in docs)

    def test_nat_type_metadata(self, in_memory_vectorstore, paloalto_policy):
        ingest_policy(paloalto_policy)
        docs = in_memory_vectorstore.similarity_search("nat", k=20,
                                                       filter={"type": "nat_rule"})
        nat_types = {d.metadata.get("nat_type") for d in docs}
        assert "pat" in nat_types or "dnat" in nat_types

    def test_multi_vendor_isolation(self, in_memory_vectorstore, paloalto_policy, fortinet_policy):
        ingest_policy(paloalto_policy)
        ingest_policy(fortinet_policy)

        pan_docs = in_memory_vectorstore.similarity_search("rule", k=50,
                                                           filter={"vendor": "paloalto"})
        forti_docs = in_memory_vectorstore.similarity_search("rule", k=50,
                                                             filter={"vendor": "fortinet"})
        assert all(d.metadata["vendor"] == "paloalto" for d in pan_docs)
        assert all(d.metadata["vendor"] == "fortinet" for d in forti_docs)


class TestIngestRawText:
    def test_ingest_plain_text(self, in_memory_vectorstore):
        text = "access-list OUTSIDE_IN extended permit tcp any host 10.0.1.100 eq 443"
        count = ingest_raw_text(text, {"vendor": "cisco_asa", "device": "asa-test"})
        assert count >= 1

    def test_ingest_preserves_metadata(self, in_memory_vectorstore):
        meta = {"vendor": "fortinet", "device": "fg01", "filename": "policy.conf"}
        ingest_raw_text("firewall policy config text here", meta)
        docs = in_memory_vectorstore.similarity_search("firewall policy", k=5)
        assert any(d.metadata.get("vendor") == "fortinet" for d in docs)

    def test_ingest_large_text_splits(self, in_memory_vectorstore):
        # 5000-char text should be split into multiple chunks
        long_text = "rule allow src any dst any svc HTTP\n" * 150
        count = ingest_raw_text(long_text)
        assert count > 1
