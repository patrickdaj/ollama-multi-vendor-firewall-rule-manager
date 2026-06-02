# ollama-multi-vendor-firewall-rule-manager

A local-first, AI-powered firewall management platform. It connects directly to your firewalls, ingests every meaningful policy object into a semantic knowledge base, and exposes that knowledge through a chat interface and MCP tools — enabling analysis, optimization, and cross-vendor translation that would otherwise require expensive commercial tools or weeks of manual effort.

**Supported vendors:** Palo Alto Networks (PAN-OS), Cisco ASA, Cisco FTD, Fortinet FortiGate  
**Runs entirely on-premises.** No cloud. No telemetry. Your configs never leave your network.

---

## See it work

Up and running in 5 commands using built-in sample configs — no live firewalls needed.

    # One-time: install Ollama (https://ollama.com) and pull the models
    ollama pull llama3.2 && ollama pull nomic-embed-text

    git clone <repo> && cd ollama-multi-vendor-firewall-rule-manager
    cp .env.example .env
    docker compose up -d
    docker compose exec app python scripts/bootstrap_rag.py

This loads 306 documents across four sample firewalls (PAN-OS, FortiGate, ASA, FTD). Then:

    ./scripts/chat.sh

**Shadow rule detection:**

    You: Which rules on pa-fw01 are shadowed and can never be matched?

    Assistant: On pa-fw01, three rules are shadowed by allow-any-any-legacy at
    position 15, which permits all traffic from any source to any destination:

      1. block-servers-direct-internet (position 16)
         Intended to deny the servers zone from reaching the internet directly.
         Unreachable because allow-any-any-legacy matches first.

      2. block-inbound-rdp (position 17)
         Intended to block inbound RDP from untrust. Unreachable for the same reason.

      3. block-inbound-smb (position 18)
         Intended to block inbound SMB/RPC. Also unreachable.

    Recommendation: Remove or disable allow-any-any-legacy (tagged 'legacy',
    'cleanup-needed'). The three block rules below it will become active immediately.

**Cross-vendor translation:**

    You: Translate the outbound PAT rule from pa-fw01 to FortiGate CLI syntax

    Assistant: The nat-outbound-pat rule on pa-fw01 translates all internal traffic to
    203.0.113.1 via PAT. The FortiGate equivalent uses a central-SNAT-map entry:

      config firewall central-snat-map
          edit 1
              set srcintf "trust" "servers" "vpn" "dmz"
              set dstintf "untrust"
              set orig-addr "grp-all-internal"
              set dst-addr "all"
              set nat enable
              set nat-ippool "pool-outbound"
          next
      end

      config firewall ippool
          edit "pool-outbound"
              set startip 203.0.113.1
              set endip   203.0.113.1
              set type overload
          next
      end

    Note: Ensure the IP pool "pool-outbound" exists before applying the SNAT map.

RAG search is instant. AI chat runs locally via Ollama — Apple Silicon (Metal) and NVIDIA GPUs are fully utilized since Ollama runs natively on the host.

---

## What it manages

This platform ingests and reasons over the complete policy state of every connected device:

| Tier | Objects |
|------|---------|
| **Policy** | Security rules, NAT (static/dynamic/PAT/DNAT), decryption/SSL inspection, DoS protection, authentication/captive portal, QoS |
| **Objects** | Addresses (host/network/range/FQDN), address groups, services, service groups, applications, application groups/filters, URL categories, GeoIP regions |
| **Threat & Profiles** | Antivirus, IPS/vulnerability, anti-spyware, URL filtering, DNS security, file blocking, sandboxing, SSL inspection profiles |
| **Dynamic Intelligence** | External Dynamic Lists (EDLs), threat feeds, custom threat signatures |
| **Identity** | User groups (User-ID/FSSO), HIP profiles, ZTNA tags, device identity |
| **Topology** | Zones, interfaces, VPN tunnels, routing context |

---

## Architecture

```
  Firewalls (direct device API — no management platform intermediary)
  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │ PAN-OS   │  │ Cisco ASA│  │ Cisco FTD│  │ FortiGate│
  │ XML API  │  │ REST API │  │ FMC REST │  │ REST v2  │
  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
       └──────────────┴──────────────┴──────────────┘
                              │
                    vendor connectors
                              │
                    ┌─────────▼──────────┐
                    │   vendor-agnostic  │
                    │   policy models    │  FirewallRule, NATRule,
                    │                    │  ApplicationObject, EDL,
                    └─────────┬──────────┘  DecryptionRule, ...
                              │
                    ┌─────────▼──────────┐
                    │   RAG pipeline     │  text → embeddings →
                    │   (ChromaDB +      │  ChromaDB (persistent)
                    │   nomic-embed)     │
                    └─────────┬──────────┘
                              │
               ┌──────────────┼──────────────┐
               │                             │
    ┌──────────▼──────────┐     ┌────────────▼────────────┐
    │   FastAPI + WS      │     │   MCP Server            │
    │   Chat interface    │     │   (Claude Desktop /      │
    │   REST API          │     │    any MCP client)       │
    └─────────────────────┘     └─────────────────────────┘
               │                             │
               └──────────────┬──────────────┘
                    ┌──────────▼──────────┐
                    │   Ollama LLM        │  llama3.2 or any
                    │   (local, native)   │  compatible model
                    └─────────────────────┘
```

**Why direct-to-device?**  
Panorama, FortiManager, and Cisco Defense Orchestrator are management platforms in their own right — adding another abstraction layer on top of them makes the system more complex without adding value. This platform is the management layer. It connects directly to PAN-OS firewalls, FortiGate devices, ASA appliances, and FMC (which is the native API for FTD). Every vendor gets the same semantic treatment regardless of where it lives in your network.

**How the intelligence layer works:**  
The LLM (running locally via Ollama) has broad knowledge of firewall concepts, vendor CLI syntax, REST API structures, and security best practices from its training data. What it lacks is knowledge of *your* environment — your device names, your rule contents, your object values, your policy decisions. The RAG pipeline bridges that gap: policy data ingested from your devices becomes a searchable vector store. When you ask a question, relevant chunks of your actual data are retrieved and passed to the LLM as context. The result is natural-language reasoning over your real policy state.

**MCP makes it actionable:**  
The Model Context Protocol server exposes structured tools — search, analyze, translate, optimize — that any MCP-capable client (Claude Desktop, custom agents) can call. Tools can read from the vector store or reach out to live devices, giving the LLM the ability to act on what it reasons about.

---

## Capabilities

### Cross-vendor policy translation
Generate equivalent config for any supported vendor from an existing rule or NAT entry. The LLM knows the syntax of every vendor; RAG provides your specific object names and existing examples on the target platform.

```
"Translate rule allow-web-out from pa-fw01 to FortiGate CLI syntax"
"Convert the outbound-pat NAT rule on asa-core to PAN-OS"
"Generate FortiGate VIP config equivalent to the webserver-dnat rule on pa-fw01"
```

### Policy analysis
```
"Find all shadow rules on pa-fw01"           → rules that can never be hit due to ordering
"Find redundant address objects on fg-fw01"   → objects with duplicate IP values
"Which rules allow any/any on any device?"    → permissive rule detection
"Audit pa-fw01 for rules missing logging"     → compliance gap analysis
```

### Optimization
```
"Give me a prioritized optimization plan for pa-fw01"
→ shadow rules, redundant objects, permissive rules, disabled cleanup,
  consolidation candidates — each with severity and recommended fix
```

### Semantic search
```
"Which rules allow RDP to the database subnet on any device?"
"What address objects reference the 10.10.10.0/24 range?"
"Which NAT rules perform DNAT to the DMZ web servers?"
"Show me all rules with the strict-av antivirus profile applied"
```

### Cross-vendor comparison
```
"Compare the security coverage of pa-fw01 and fg-fw01"
→ rules on A not covered by B, rules on B not covered by A, behavioral differences
```

---

## Getting started

### Prerequisites
- [Ollama](https://ollama.com) installed and running natively on the host
- Docker + Docker Compose
- 8 GB RAM minimum (16 GB recommended)
- 10 GB disk space for models

### Start the platform

```bash
# Pull models once (runs natively — uses Metal on Apple Silicon, CUDA on NVIDIA)
ollama pull llama3.2
ollama pull nomic-embed-text

cp .env.example .env
# Edit .env — add your firewall device IPs and credentials

docker compose up -d
# Services: chromadb (:8000), api (:8080), mcp (:8001)
# Ollama runs on the host at :11434 — containers reach it via host.docker.internal
```

### Add your devices

In `.env`, set `FIREWALL_DEVICES` as a JSON array:

```bash
FIREWALL_DEVICES='[
  {
    "name": "pa-fw01",
    "vendor": "paloalto",
    "host": "10.0.0.1",
    "username": "admin",
    "password": "secret",
    "api_key": "LUFRPT1..."
  },
  {
    "name": "asa-core",
    "vendor": "cisco_asa",
    "host": "10.0.0.2",
    "username": "admin",
    "password": "secret",
    "verify_ssl": false
  },
  {
    "name": "ftd-edge",
    "vendor": "cisco_ftd",
    "host": "10.0.0.3",
    "username": "admin",
    "password": "secret"
  },
  {
    "name": "fg-fw01",
    "vendor": "fortinet",
    "host": "10.0.0.4",
    "username": "admin",
    "password": "secret",
    "verify_ssl": false
  }
]'
```

**Vendor values:**
| Value | Device | API used |
|-------|--------|----------|
| `paloalto` | PAN-OS firewall | PAN-OS XML API (pan-os-python) |
| `cisco_asa` | Cisco ASA (9.3+) | ASA REST API |
| `cisco_asa_ssh` | Cisco ASA (pre-9.3) | CLI via SSH (netmiko) |
| `cisco_ftd` | Cisco FTD | Firepower Management Center REST API |
| `fortinet` | FortiGate | FortiOS REST API v2 |

### Ingest a device

```bash
# Pull full policy from a live device and store it
curl -X POST http://localhost:8080/api/v1/firewall/devices/pa-fw01/ingest

# Or bootstrap without live devices using sample configs
curl -X POST http://localhost:8080/api/v1/rag/ingest/file \
  -F file=@data/configs/samples/paloalto_sample.xml \
  -F vendor=paloalto -F device=pa-fw01
```

### Chat

```bash
# REST (single turn)
curl -X POST http://localhost:8080/api/v1/chat \
  -H "Content-Type: application/json" \
  -d '{"session_id":"s1","message":"Which rules allow outbound traffic from the trust zone?"}'

# CLI (streaming) — runs fw-chat inside the fw-app container
./scripts/chat.sh
```

### WebSocket streaming

```javascript
const ws = new WebSocket('ws://localhost:8080/ws/chat/my-session');
ws.send(JSON.stringify({ action: 'chat', message: 'Find shadow rules on pa-fw01' }));
ws.onmessage = (e) => {
  const { type, content } = JSON.parse(e.data);
  if (type === 'token') process.stdout.write(content);
};
```

### Claude Desktop (MCP)

Add the `mcpServers` block to your Claude Desktop config file — **merge it in**, don't replace the whole file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "firewall-manager": {
      "command": "docker",
      "args": ["exec", "-i", "-e", "MCP_TRANSPORT=stdio", "fw-mcp", "fw-mcp"]
    }
  }
}
```

Then **restart Claude Desktop**. Claude Desktop will pipe stdio into the running `fw-mcp` container each time it needs to call a tool — make sure `docker compose up -d` is running before opening Claude Desktop.

> The `-e MCP_TRANSPORT=stdio` override is needed because the container normally runs in SSE mode (for HTTP clients on port 8001). Claude Desktop uses stdio, so we override that per-exec.

---

## MCP tools reference

| Tool | Description |
|------|-------------|
| `search_firewall_rules` | Semantic search over security rules |
| `search_nat_rules` | Semantic search over NAT rules by type |
| `search_address_objects` | Find address objects by name, IP, or description |
| `search_application_objects` | Find App-ID / application signatures |
| `search_edls` | Search External Dynamic Lists and threat feeds |
| `ask_firewall_policy` | Natural language Q&A over all policy data |
| `find_shadow_rules` | Detect unreachable rules due to ordering |
| `find_redundant_objects` | Find objects with duplicate values |
| `find_permissive_rules` | Identify overly broad allow rules |
| `optimize_policy` | Full policy audit with prioritized recommendations |
| `translate_rule_to_vendor` | Generate equivalent rule on target vendor |
| `translate_nat_rule_to_vendor` | Generate equivalent NAT config on target vendor |
| `translate_application_policy` | Translate App-ID policy across vendors |
| `compare_device_policies` | Coverage gap analysis between two devices |
| `analyze_decryption_coverage` | SSL inspection gap analysis |
| `list_configured_devices` | Show registered device inventory |
| `fetch_and_ingest_device` | Connect to live device and ingest full policy |
| `get_live_rules` | Pull current rules from live device |

---

## Development

```bash
uv pip install -e .[dev]

pytest                          # full test suite (no live devices needed)
pytest --cov=src                # with coverage
ruff check . && ruff format .   # lint + format
mypy src/                       # type check

fw-api                          # start API server
fw-mcp                          # start MCP server
fw-chat chat                    # interactive CLI chat
fw-ingest pa-fw01               # ingest a specific device
```

---

## Roadmap

### Phase 1 — Foundation ✅
Security rules · NAT (all types) · Address and service objects · Security profiles · RAG pipeline · MCP tools (search, shadow, translate, optimize) · FastAPI + WebSocket chat · Docker Compose

### Phase 2 — Full object coverage 🔄
Application objects and groups (App-ID, FortiGuard apps, OpenAppID) · Decryption / SSL inspection policies and profiles · Zone definitions · DoS and zone protection policies · Authentication and captive portal policies · GeoIP and region objects

### Phase 3 — Threat intelligence
External Dynamic Lists (EDLs) with change tracking · Threat feed metadata · Custom threat signature inventories · Scheduled policy sync with diff detection

### Phase 4 — Identity and posture
User-ID / FSSO group ingestion · HIP profiles and objects (PAN-OS) · ZTNA tag mapping (FortiGate) · User- and device-based policy analysis

### Phase 5 — Advanced operations
VPN topology mapping · SD-WAN policy ingestion · Compliance checking (CIS benchmarks, NIST) · Policy push with approval workflow · Change diff tracking against last-ingested snapshot
