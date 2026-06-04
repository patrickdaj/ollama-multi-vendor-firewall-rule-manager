# Architecture

## Overview

This platform manages firewall policy across multiple vendors from a single source of truth. It has two distinct operational modes that coexist:

- **Observe** — ingest the current state of devices into Postgres and index it for AI-assisted analysis and chat
- **Manage** — define desired-state policy in a vendor-neutral group hierarchy and push it to devices (push engine is a future phase)

---

## Components

```mermaid
flowchart TB
  subgraph fw [Firewalls]
    direction LR
    pa[PAN-OS]
    asa[Cisco ASA]
    ftd[Cisco FTD]
    fg[FortiGate]
  end

  subgraph connectors [Vendor Connectors + Loaders]
    direction LR
    cn[pan-os-python · ASA REST · FMC REST · FortiOS REST\nNormalize to vendor-agnostic Pydantic models]
  end

  subgraph pg [PostgreSQL — Source of Truth]
    direction LR
    subgraph obs [Observed State]
      snap[Snapshot]
      pobj[PolicyObject JSONB]
      pdiff[PolicyDiff]
    end
    subgraph des [Desired State]
      dg[DeviceGroup hierarchy]
      gpr[GroupPolicyRule pre/post]
      gpo[GroupPolicyObject shared]
      dzm[DeviceZoneMapping]
      ot[ObjectTranslation approved]
      rt[RuleTranslation approved]
      tp[TranslationProposal pending]
    end
  end

  chroma[(ChromaDB\nSemantic search\nCompliance index)]
  push[Push Engine\nfuture phase]
  api[FastAPI + WebSocket\nREST :8080\nReact SPA]
  mcp[MCP Server\n:8001 SSE / stdio]
  llm[LLM Provider\nOllama · OpenAI · Anthropic]

  fw -->|ingest| connectors
  connectors --> pg
  obs -->|index| chroma
  des -->|resolve| push
  push -->|push config| fw
  chroma --> api
  chroma --> mcp
  api --> llm
  mcp --> llm
```

---

## Data model — two categories

### Observed state (ingest pipeline)

Written on every device sync. Never edited directly by users.

| Table | Purpose |
|---|---|
| `devices` | Registered device inventory with encrypted credentials |
| `snapshots` | One row per ingest run; tracks status and object count |
| `policy_objects` | Every policy object from a snapshot stored as JSONB |
| `policy_diffs` | Change records auto-computed between consecutive snapshots |

### Desired state (policy management)

Managed by users via the UI or API. These tables form the SOT for what should be on devices.

| Table | Purpose |
|---|---|
| `device_groups` | Hierarchical group tree (parent_id self-reference) — rendered as "Groups" in the UI |
| `group_policy_rules` | Rules defined at group level (pre/post rulebases, vendor-agnostic) |
| `group_policy_objects` | Shared objects at group or root scope |
| `device_zone_mappings` | Maps logical zone names → device-specific zone names |
| `object_translations` | Approved vendor-specific representation of a named object |
| `rule_translations` | Approved vendor-specific override for a group rule |
| `translation_proposals` | AI-generated translation proposals pending human review |

---

## Request flow — chat query

```mermaid
sequenceDiagram
  participant U as User
  participant API as FastAPI /chat
  participant Bot as ChatBot
  participant DB as ChromaDB
  participant LLM as LLM Provider

  U->>API: WebSocket {action:chat, message}
  API->>Bot: stream(message)
  Bot->>DB: semantic search (top-k)
  DB-->>Bot: context chunks
  Bot->>LLM: system+context+history+message
  LLM-->>Bot: token stream
  Bot-->>API: yield tokens
  API-->>U: {type:token, content} × N
  API-->>U: {type:end, history}
```

## Request flow — device ingest

```mermaid
sequenceDiagram
  participant C as Client
  participant API as FastAPI
  participant Conn as Vendor Connector
  participant PG as PostgreSQL
  participant Chroma as ChromaDB

  C->>API: POST /firewall/devices/{name}/onboard
  API->>PG: fetch + decrypt credentials
  API->>Conn: connect to device
  Conn-->>API: raw policy data
  API->>API: normalize → FirewallPolicy model
  API->>PG: save_snapshot()
  Note over PG: write Snapshot + PolicyObject rows
  Note over PG: compute PolicyDiff vs prev snapshot
  API->>Chroma: reindex device objects
  API-->>C: {snapshot_id, object_count, diff_count}
```

## Request flow — AI translation generation

```mermaid
sequenceDiagram
  participant U as User / MCP
  participant API as FastAPI
  participant PG as PostgreSQL
  participant AI as src/ai/translation.py
  participant LLM as LLM Provider

  U->>API: POST /proposals/{id}/generate
  API->>PG: fetch TranslationProposal
  API->>PG: fetch base_data (GroupPolicyObject) or base_rule (GroupPolicyRule)
  API->>AI: generate_object_translation() or generate_rule_translation()
  AI->>LLM: system prompt + vendor profile + object context
  LLM-->>AI: {translation: {...}, reasoning: "..."}
  AI-->>API: (translation_dict, reasoning_str)
  API->>PG: proposal.proposed_translation = ..., proposal.ai_model = ...
  API-->>U: {proposal_id, status: "generated"}
  Note over U,PG: Proposal still pending — human reviews via web UI
```

## Request flow — import policy from device

```mermaid
sequenceDiagram
  participant U as User
  participant API as FastAPI
  participant PG as PostgreSQL
  participant AI as src/ai/import_policy.py
  participant LLM as LLM Provider

  U->>API: POST /groups/{id}/import/{device}/preview
  API->>PG: fetch latest complete snapshot for device
  API->>PG: fetch PolicyObject rows (security_rule, nat_rule, address_object, …)
  loop For each object
    API->>AI: normalize_rule() or normalize_object()
    AI->>LLM: system prompt + vendor data + target schema
    LLM-->>AI: {base_rule/base_data: {...}, reasoning: "..."}
  end
  API-->>U: ImportPreview{candidates[]}

  U->>API: POST /groups/{id}/import/{device}/confirm (selected candidates)
  API->>PG: write GroupPolicyRule / GroupPolicyObject rows for selected=true
  API-->>U: {rules_created, objects_created}
```

## Request flow — push (future)

```mermaid
sequenceDiagram
  participant C as Client
  participant API as FastAPI
  participant PG as PostgreSQL
  participant Trans as Translation Engine
  participant Dev as Device

  C->>API: POST /groups/{id}/push/{device_name}
  API->>PG: compute effective policy (ancestor chain)
  API->>PG: load RuleTranslation + ObjectTranslation for vendor
  API->>PG: load DeviceZoneMapping for device
  API->>Trans: merge base_rule + vendor overrides
  Trans->>Trans: substitute logical → physical zones
  Trans->>Trans: generate vendor-specific config
  Trans-->>API: rendered config
  API->>Dev: submit via vendor API
  Dev-->>API: commit result
  API->>API: ingest new snapshot
  API->>PG: compute drift diff (desired vs observed)
  API-->>C: {pushed, diff_count}
```

---

## LLM configuration

Two providers are configured independently — one for reasoning, one for embeddings:

```bash
LLM_PROVIDER=ollama        # ollama | openai | anthropic
LLM_MODEL=llama3.2
EMBED_PROVIDER=ollama      # ollama | openai
EMBED_MODEL=nomic-embed-text
```

This lets you run, for example, `anthropic` + `claude-sonnet-4-6` for chat while keeping `ollama` + `nomic-embed-text` for embeddings (fast, local, no API cost).

---

## Frontend

The React SPA is built with Vite + React + Tailwind CSS v4. It is served directly from FastAPI's static file handler in production (built output lands in `src/api/static/`). In development, run `npm run dev` from `frontend/` — the Vite dev server proxies `/api` and `/ws` to `localhost:8080`.

Build requires Node 22+ (`nvm use 22`).

See [docs/policy-management.md](policy-management.md) for the group hierarchy design.  
See [docs/vendor-support.md](vendor-support.md) for per-vendor object coverage.
