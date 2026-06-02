#!/usr/bin/env python3
"""Bootstrap the RAG vector store from the enterprise sample config files.

Run this once after starting the stack to populate ChromaDB with
structured policy data from all four vendor sample configs.

Usage:
    python scripts/bootstrap_rag.py
    python scripts/bootstrap_rag.py --query "shadow rules"     # verify after ingest
    python scripts/bootstrap_rag.py --clear                    # wipe and re-ingest
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root to path so src/ imports work without pip install
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.firewall.loaders import load_from_file
from src.rag.loader import ingest_policy
from src.rag.vectorstore import get_vectorstore

SAMPLES_DIR = Path(__file__).parent.parent / "data" / "configs" / "samples"

CONFIGS = [
    {
        "file": SAMPLES_DIR / "paloalto_enterprise.xml",
        "vendor": "paloalto",
        "device": "pa-fw01",
        "description": "ACME Corp PAN-OS 11.1",
    },
    {
        "file": SAMPLES_DIR / "fortinet_enterprise.json",
        "vendor": "fortinet",
        "device": "fg-fw01",
        "description": "ACME Corp FortiGate 7.4",
    },
    {
        "file": SAMPLES_DIR / "cisco_asa_enterprise.txt",
        "vendor": "cisco_asa",
        "device": "asa-fw01",
        "description": "ACME Corp ASA 9.18",
    },
    {
        "file": SAMPLES_DIR / "cisco_ftd_enterprise.json",
        "vendor": "cisco_ftd",
        "device": "ftd-fw01",
        "description": "ACME Corp FTD 7.4 / FMC 7.4",
    },
]


def clear_collection() -> None:
    vs = get_vectorstore()
    try:
        vs._collection.delete(where={"vendor": {"$ne": ""}})
        print("Vector store cleared.")
    except Exception as e:
        print(f"Clear warning: {e}")


def ingest_all(verbose: bool = True) -> dict[str, int]:
    results: dict[str, int] = {}
    total = 0

    for cfg in CONFIGS:
        path = cfg["file"]
        if not path.exists():
            print(f"  SKIP  {path.name} (not found)")
            continue

        print(f"\n  Loading {path.name} → {cfg['device']} ({cfg['description']})")
        try:
            policy = load_from_file(path, cfg["vendor"], cfg["device"])
            count = ingest_policy(policy)
            results[cfg["device"]] = count
            total += count

            if verbose:
                print(f"         {policy.summary()}")
                print(f"         → {count} documents ingested")
        except Exception as e:
            print(f"  ERROR  {cfg['device']}: {e}")
            import traceback
            traceback.print_exc()

    print(f"\n  Total: {total} documents across {len(results)} devices")
    return results


def verify_query(query: str) -> None:
    vs = get_vectorstore()
    print(f"\n  Verifying search: '{query}'")
    docs = vs.similarity_search(query, k=5)
    if not docs:
        print("  No results — did ingestion complete?")
        return
    for doc in docs:
        m = doc.metadata
        print(f"    [{m.get('device','?')} / {m.get('vendor','?')}] "
              f"type={m.get('type','?')} name={m.get('rule_name', m.get('name','?'))}")
        print(f"    {doc.page_content[:120].replace(chr(10),' ')}")
        print()


def print_summary() -> None:
    vs = get_vectorstore()
    try:
        count = vs._collection.count()
        print(f"\n  Vector store: {count} total documents in collection '{vs._collection.name}'")
    except Exception:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap RAG from sample configs")
    parser.add_argument("--clear",   action="store_true", help="Clear vector store before ingesting")
    parser.add_argument("--query",   type=str, default="", help="Run a test query after ingesting")
    parser.add_argument("--quiet",   action="store_true", help="Less verbose output")
    parser.add_argument("--list",    action="store_true", help="List what will be ingested, then exit")
    args = parser.parse_args()

    print("=" * 60)
    print("  Firewall RAG Bootstrap")
    print("=" * 60)

    if args.list:
        for cfg in CONFIGS:
            exists = "✓" if cfg["file"].exists() else "✗"
            print(f"  [{exists}] {cfg['device']:12} {cfg['vendor']:12} {cfg['file'].name}")
        return

    if args.clear:
        clear_collection()

    ingest_all(verbose=not args.quiet)
    print_summary()

    if args.query:
        verify_query(args.query)
    else:
        # Default verification queries
        for q in [
            "shadow rules that can never be hit",
            "duplicate address objects with same IP",
            "inbound HTTPS to web server",
            "outbound PAT source NAT",
        ]:
            verify_query(q)


if __name__ == "__main__":
    main()
