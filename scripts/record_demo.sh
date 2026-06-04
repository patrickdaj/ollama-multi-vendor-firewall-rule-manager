#!/usr/bin/env bash
# Drive a demo session for asciinema recording.
# Usage:
#   asciinema rec demo.cast --command ./scripts/record_demo.sh
#   agg demo.cast demo.gif

set -euo pipefail

CHAT_URL="http://localhost:8080/api/v1/chat"
_Q=0  # per-question session counter

BLUE="\033[1;34m"
YELLOW="\033[0;33m"
DIM="\033[2m"
RESET="\033[0m"

type_text() {
    local text="$1"
    local delay="${2:-0.04}"
    local i
    for (( i=0; i<${#text}; i++ )); do
        printf "%s" "${text:$i:1}"
        sleep "$delay"
    done
    printf "\n"
}

stream_words() {
    local text="$1"
    local delay="${2:-0.010}"
    while IFS= read -r line; do
        for word in $line; do
            printf "%s " "$word"
            sleep "$delay"
        done
        printf "\n"
    done <<< "$text"
}

ask() {
    local question="$1"
    _Q=$(( _Q + 1 ))
    local session="demo-$$-${_Q}"

    clear
    printf "\n"
    printf "${DIM}  Firewall RAG Manager — pa-fw01 · fg-fw01 · asa-fw01 · ftd-fw01${RESET}\n"
    printf "\n"

    printf "${BLUE}  You: ${RESET}"
    type_text "$question" 0.04

    printf "\n"
    printf "${YELLOW}  Assistant: ${RESET}▌"

    local json answer
    json=$(curl -s -X POST "$CHAT_URL" \
        -H "Content-Type: application/json" \
        --data-binary @- <<EOF
{"session_id":"$session","message":$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$question")}
EOF
    )
    answer=$(printf '%s' "$json" | python3 -c "import sys,json; print(json.load(sys.stdin)['answer'])")

    printf "\r${YELLOW}  Assistant: ${RESET}"
    stream_words "$answer" 0.010

    sleep 4
}

# ── 1. Shadow rules ──────────────────────────────────────────────────────────
ask "Which rules on pa-fw01 are shadowed and can never be matched?"

# ── 2. Any/any permits ───────────────────────────────────────────────────────
ask "List any permit-all rules across the four devices."

# ── 3. Duplicate address objects ─────────────────────────────────────────────
ask "Which address objects on fg-fw01 have duplicate IP values?"

# ── 4. Missing logging ───────────────────────────────────────────────────────
ask "Which security rules on pa-fw01 have logging disabled?"

# ── 5. Inbound RDP exposure ──────────────────────────────────────────────────
ask "Which rules allow inbound RDP on any device?"

# ── 6. DNAT to web DMZ ───────────────────────────────────────────────────────
ask "List the DNAT rules forwarding inbound HTTPS to the web DMZ."

# ── 7. Top risks ─────────────────────────────────────────────────────────────
ask "What are the top 3 policy risks on fg-fw01?"

# ── 8. Cross-vendor translation ──────────────────────────────────────────────
ask "Translate the outbound PAT rule from pa-fw01 to FortiGate CLI syntax."

# ── 9. Policy gap ────────────────────────────────────────────────────────────
ask "What does pa-fw01 allow inbound that fg-fw01 does not?"

# ── 10. Comparison (matches final question in demo.sh) ───────────────────────
ask "Compare the inbound security rules between pa-fw01 and fg-fw01. What does one allow that the other doesn't?"
