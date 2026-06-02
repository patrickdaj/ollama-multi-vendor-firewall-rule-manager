#!/usr/bin/env bash
# Firewall RAG Manager — interactive demo
# Run after: docker compose up -d && docker compose exec app python scripts/bootstrap_rag.py

set -euo pipefail

API="http://localhost:8080"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

header()  { echo; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"; echo -e "${BOLD}  $1${RESET}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"; }
section() { echo; echo -e "${YELLOW}▶ $1${RESET}"; }
result()  { echo -e "${DIM}$1${RESET}"; }
ok()      { echo -e "${GREEN}✓ $1${RESET}"; }
note()    { echo -e "${DIM}  $1${RESET}"; }

# ── Preflight ──────────────────────────────────────────────────────────────────
header "Firewall RAG Manager — Demo"

if ! curl -sf "$API/health" > /dev/null 2>&1; then
    echo -e "${RED}✗ API not reachable at $API${RESET}"
    echo "  Run: docker compose up -d"
    exit 1
fi

DOC_COUNT=$(curl -s "$API/api/v1/rag/status" | python3 -c "import sys,json; print(json.load(sys.stdin).get('document_count',0))" 2>/dev/null || echo 0)
if [[ "$DOC_COUNT" -lt 10 ]]; then
    echo -e "${RED}✗ Vector store is empty (${DOC_COUNT} documents)${RESET}"
    echo "  Run: docker compose exec app python scripts/bootstrap_rag.py"
    exit 1
fi

ok "API healthy"
ok "Vector store: ${DOC_COUNT} documents across 4 devices (pa-fw01, fg-fw01, asa-fw01, ftd-fw01)"

search() {
    local label="$1" query="$2" limit="${3:-4}"
    section "$label"
    note "GET /api/v1/rag/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$query'))")&limit=$limit"
    echo
    curl -s "$API/api/v1/rag/search?$(python3 -c "import urllib.parse; print('q='+urllib.parse.quote('$query'))")&limit=$limit" \
      | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data['results']:
    m = r['metadata']
    device  = m.get('device','?')
    vendor  = m.get('vendor','?')
    name    = m.get('rule_name', m.get('name','?'))
    rtype   = m.get('type','?')
    content = r['content'].replace('\n', ' ')[:120]
    print(f'  [{device} / {vendor}]  {name}  ({rtype})')
    print(f'  {content}')
    print()
"
}

chat() {
    local label="$1" message="$2" session="${3:-demo-$$}"
    section "$label"
    note "POST /api/v1/chat  (LLM response — may take 15–60s on CPU)"
    echo -e "  ${BOLD}Q: $message${RESET}"
    echo
    local payload
    payload=$(python3 -c "import json; print(json.dumps({'session_id':'$session','message':'$message'}))")
    local answer
    answer=$(curl -s --max-time 120 -X POST "$API/api/v1/chat" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('answer','(no answer)'))" 2>/dev/null \
        || echo "(request timed out — try again or check docker logs fw-app)")
    echo "$answer" | fold -s -w 80 | sed 's/^/  /'
}

# ── Demo ───────────────────────────────────────────────────────────────────────

header "Part 1 — Semantic Search  (instant, no LLM)"
note "Vector similarity search over 306 ingested policy documents"

search "Shadow rule candidates — any/any policies that block rules below them" \
       "shadow rule allow any any legacy temp" 4

search "Redundant address objects — same IP defined under multiple names" \
       "duplicate address object same IP redundant" 4

search "Inbound DNAT rules — public IPs mapped to internal servers" \
       "DNAT inbound HTTPS web server port forward" 4

search "EDLs and threat feeds configured across devices" \
       "external dynamic list threat feed blocklist" 4

search "SSL inspection and decryption rules" \
       "SSL TLS decryption inspection forward proxy" 3

# ── LLM queries ───────────────────────────────────────────────────────────────

echo
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Part 2 — AI Chat  (RAG + Ollama LLM)${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
note "Each query retrieves relevant policy docs then asks the LLM to reason over them"
echo
read -rp "  Run LLM queries? They take 15–60s each on CPU. [y/N] " yn
yn_lower=$(echo "$yn" | tr '[:upper:]' '[:lower:]')
[[ "$yn_lower" != "y" ]] && { echo "  Skipping LLM queries."; echo; exit 0; }

chat "Shadow rule analysis on pa-fw01" \
     "Which rules on pa-fw01 are shadowed and can never be matched? Name them specifically." \
     "demo-shadow"

chat "Redundant object analysis across all devices" \
     "Find all address objects that have duplicate IP values across any of the four devices." \
     "demo-dup"

chat "Cross-vendor translation — PAT rule" \
     "Translate the outbound PAT NAT rule from pa-fw01 to equivalent FortiGate CLI syntax." \
     "demo-xlate"

chat "Policy comparison — inbound access" \
     "Compare the inbound security rules between pa-fw01 and fg-fw01. What does one allow that the other doesn't?" \
     "demo-compare"

echo
header "Done"
ok "Vector store: $DOC_COUNT documents ready"
ok "REST API:    $API"
ok "MCP Server:  http://localhost:8001/sse"
echo
note "Next steps:"
note "  Chat UI:         open http://localhost:8080 (after adding a frontend)"
note "  Full chat API:   curl -X POST $API/api/v1/chat -d '{\"session_id\":\"s1\",\"message\":\"...\"}'"
note "  Ingest a device: curl -X POST $API/api/v1/firewall/devices/pa-fw01/ingest"
note "  Claude Desktop:  see QUICKSTART.md"
echo
