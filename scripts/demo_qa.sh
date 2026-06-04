#!/usr/bin/env bash
# Firewall RAG Manager — single Q/A demo for asciinema recordings
# Run after: docker compose up -d && docker compose exec app python scripts/bootstrap_rag.py

set -euo pipefail

API="http://localhost:8080"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

header()  { echo; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"; echo -e "${BOLD}  $1${RESET}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"; }
section() { echo; echo -e "${YELLOW}▶ $1${RESET}"; }
note()    { echo -e "${DIM}$1${RESET}"; }

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

pause() {
    echo
    read -rp "Press Enter to continue to the next demo step... "
}

chat() {
    local label="$1" message="$2" session="${3:-demo-$$}"
    clear
    header "$label"
    note "POST /api/v1/chat  (LLM response — may take 15–60s on CPU)"
    echo -e "\n  ${BOLD}Q: $message${RESET}\n"
    local payload
    payload=$(SESSION_ID="$session" MESSAGE="$message" python3 -c "import json, os; print(json.dumps({'session_id': os.environ['SESSION_ID'], 'message': os.environ['MESSAGE']}))")
    local answer
    answer=$(curl -s --max-time 120 -X POST "$API/api/v1/chat" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('answer','(no answer)'))" 2>/dev/null \
        || echo "(request timed out — try again or check docker logs fw-app)")
    echo "$answer" | fold -s -w 80 | sed 's/^/  /'
    pause
}

clear
header "Firewall RAG Manager — Single Q/A Demo"
note "Each screen shows one question, one answer, then waits for you. Perfect for asciinema recordings."

echo
note "Vector store: ${DOC_COUNT} documents across 4 devices"
echo
pause

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

clear
header "Single Q/A Demo Complete"
ok() { echo -e "${GREEN}✓ $1${RESET}"; }
ok "Review complete. Use the recorded session for static step-by-step playback."
echo
