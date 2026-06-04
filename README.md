# Ignis

A local-first, AI-powered firewall management platform. Connects to your firewalls, ingests every policy object into a semantic knowledge base, and exposes that knowledge through a web UI, chat interface, and MCP tools — enabling analysis, optimization, and cross-vendor policy management that would otherwise require expensive commercial tools.

**Supported vendors:** Palo Alto Networks (PAN-OS), Cisco ASA, Cisco FTD, Fortinet FortiGate  
**Runs entirely on-premises.** No cloud. No telemetry. Your configs never leave your network.

---

## See it work


Up and running in 5 commands using built-in sample configs — no live firewalls needed.

```bash
ollama pull llama3.2 && ollama pull nomic-embed-text

git clone <repo> && cd ollama-multi-vendor-firewall-rule-manager
cp .env.example .env
docker compose up -d
docker compose exec app python scripts/bootstrap_rag.py
```

Then open **http://localhost:8080** for the web UI. The Ignis AI dock is pinned to the bottom of every page — type your task and press Enter.

---

## What it does

### Observe — understand your current state

- Ingest the complete policy from every connected device (rules, NAT, objects, profiles, EDLs, zones)
- Snapshot-based version history with automatic diff tracking between syncs
- Semantic search and AI chat over all policy data via ChromaDB + local LLM
- Shadow rule detection, redundancy analysis, permissive rule auditing

### Manage — define what should be there

- **Group hierarchy** — group firewalls into a tree; policy defined at a group level is inherited by all child groups and devices
- **Vendor-agnostic group policy** — write rules once using logical zone names and normalized objects; the platform handles vendor-specific rendering
- **AI-assisted translation** — when a new vendor is added to a group, gap detection identifies which objects and rule fields need vendor-specific translations; the AI proposes translations, a human approves, and from that point forward pushes are deterministic
- **Import policy from device** — promote a device's existing observed-state policy to group desired-state: the AI normalizes each rule and object to vendor-agnostic form, you review and confirm
- **Push engine** (future phase) — once translations are approved, push the desired-state policy to devices

---

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | System components, data model, request flows |
| [docs/policy-management.md](docs/policy-management.md) | Group hierarchy, rulebases, zone mappings, translation workflow |
| [docs/vendor-support.md](docs/vendor-support.md) | Per-vendor object coverage, translation complexity matrix |

---

## Quick start

### Prerequisites

- Docker + Docker Compose
- 8 GB RAM minimum (16 GB recommended for larger models)
- **Ollama** (default) — [install](https://ollama.com), runs natively for full GPU/Metal acceleration
- Or: OpenAI or Anthropic API key (set `LLM_PROVIDER` in `.env`)

### Start

```bash
cp .env.example .env          # edit LLM_PROVIDER, model, and device credentials
ollama pull llama3.2 && ollama pull nomic-embed-text
docker compose up -d
```

Services: web UI + API at `:8080`, MCP server at `:8001`, ChromaDB at `:8000`, Postgres at `:5432`.

### Add devices

Register devices via the UI (Devices page) or API:

```bash
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{"name":"pa-fw01","vendor":"paloalto","host":"10.0.0.1","username":"admin","password":"secret"}'
```

Then onboard (pull full policy from device):

```bash
curl -X POST http://localhost:8080/api/v1/firewall/devices/pa-fw01/onboard
```

**Vendor values:** `paloalto` · `cisco_asa` · `cisco_asa_ssh` · `cisco_ftd` · `fortinet`

### Bootstrap sample data (no live devices needed)

```bash
docker compose exec app python scripts/bootstrap_rag.py
```

Loads 306 documents across four sample firewalls (PAN-OS, FortiGate, ASA, FTD).

### Claude Desktop (MCP)

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

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

Restart Claude Desktop. Requires `docker compose up -d` to be running.

---

## Example queries

```
"Which rules on pa-fw01 are shadowed and can never be matched?"
"Find all rules that allow any/any on any device"
"Translate the outbound PAT rule from pa-fw01 to FortiGate CLI syntax"
"Compare security coverage between pa-fw01 and fg-fw01"
"Which address objects reference the 10.10.10.0/24 range?"
"Audit pa-fw01 for rules missing logging"
```

---

## Development

```bash
uv pip install -e .[dev]

pytest                          # full test suite
pytest --cov=src                # with coverage
ruff check . && ruff format .   # lint + format
mypy src/                       # type check

fw-api                          # start API server (port 8080)
fw-mcp                          # start MCP server (port 8001)
fw-chat chat                    # interactive CLI chat

# Frontend (requires Node 22)
cd frontend && nvm use 22 && npm run dev    # dev server (port 5173)
cd frontend && nvm use 22 && npm run build  # production build → src/api/static/
```

---

## MCP tools

| Tool | Description |
|---|---|
| `search_firewall_rules` | Semantic search over security rules |
| `search_nat_rules` | Semantic search over NAT rules |
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
| `compare_device_policies` | Coverage gap analysis between two devices |
| `list_configured_devices` | Show registered device inventory |
| `fetch_and_ingest_device` | Connect to live device and ingest full policy |
| `list_groups` | Show group hierarchy with device and rule counts |
| `get_group_effective_policy` | Compute full ordered rulebase for a group |
| `detect_translation_gaps` | Find missing vendor translations and create proposals |
| `list_pending_proposals` | Show AI proposals awaiting review |
| `generate_ai_translations` | Drive AI to fill empty translation proposals |

---

## Roadmap

### Phase 1 — Foundation ✅
Security rules · NAT · Address/service objects · RAG pipeline · MCP tools · FastAPI + WebSocket chat · Docker Compose · PostgreSQL source of truth with versioned snapshots and diff tracking · Pluggable LLM (Ollama · OpenAI · Anthropic) · React web UI (dashboard, devices, policy browser, snapshot history, chat)

### Phase 2 — Full object coverage ✅
Service groups · Application objects and groups · Decryption policies and profiles · Zone definitions · DoS and auth policies · EDLs · Security profiles · Snapshot diff viewer · Policy browser with inline JSON editor

### Phase 3 — Group policy management ✅
Group hierarchy · Group policy rules (pre/post rulebases) · Shared object namespace · Zone alias mappings · Vendor translation model (deterministic + AI-assisted) · AI generation for translation proposals · Translation proposal review workflow · Gap detection on new vendor onboarding · Import policy from device (AI-assisted observed→desired state promotion) · Group policy MCP tools

#### Policy promotion workflow (observed → desired state)

When a device is onboarded it lands in one of three states:

| State | Description | Path forward |
|---|---|---|
| No policy / scrap | Device has no useful policy or you want a clean slate | Assign to group, define policy at group level, push overwrites device |
| Promote as-is | Device has a good policy you want to use as the group baseline | **Import to group** — convert snapshot to desired state, review, confirm |
| Massage and promote | Device has a partial or imperfect policy to be merged or tweaked | **Import to group** with per-rule review and editing before confirming |

The first case is already handled — observed state and desired state are fully separate and the push engine simply writes the group policy down. The second and third require a **"Import policy from device"** workflow:

1. Read the device's latest snapshot (`PolicyObject` rows — observed, vendor-specific)
2. AI converts each rule/object to vendor-agnostic `base_rule` / `base_data` JSONB (the reverse of the translation layer)
3. Candidate rules/objects land in a staging review panel (diff-style: check/uncheck/edit each entry)
4. On confirm → written as `GroupPolicyRule` / `GroupPolicyObject` rows in the group's desired state

**UI entry point:** Groups page → Overview tab → "Import policy from [device]" button, available after a device is assigned to a group. Produces a side-by-side panel: observed vendor rule on the left, proposed vendor-agnostic form on the right, with inline editing before commit.

### Phase 3.5 — Task queue infrastructure (pre-requisite for multi-user scale)
Introduce an async task queue (Huey or similar) backed by Redis · Long-running operations (push, drift detection, snapshot ingestion, RAG re-index) offloaded to workers · Job status polling via API · Per-user / per-device job isolation · Required before Phase 4 push engine goes multi-user

### Phase 4 — Push engine
Deterministic vendor translation layer · Effective policy computation · Push with pre-flight diff preview · Drift detection (desired vs observed state) · Rollback support · All push jobs executed via task queue workers (see Phase 3.5)

### Phase 5 — Threat intelligence and identity
EDL change tracking · Scheduled policy sync · User-ID / FSSO group ingestion · HIP profiles (PAN-OS) · ZTNA tag mapping

### Phase 6 — Compliance and ecosystem
CIS benchmark checks · NIST policy compliance · IPAM/CMDB enrichment (Netbox, Infoblox) · ServiceNow CMDB · Terraform provider for policy-as-code
