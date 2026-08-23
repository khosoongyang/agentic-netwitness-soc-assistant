# Aegis architecture

Practical reference for maintainers. Not a design thesis - if something here
doesn't match the code, the code is right; open an issue/fix this file.

## Layers and dependency direction

```
frontend/            HTML/CSS/vanilla JS, no build step, no framework
    │  fetch()
    ▼
backend/routes/       thin HTTP transport - parse request, call a service, jsonify
    │
    ▼
backend/services/     application logic: case listing, dashboard aggregates,
    │                 report editing, settings, NetWitness/search facades
    ▼
workflow/             orchestration (engine.py) and the durable state
    │                 machine (state_store.py) - the ONE source of truth for
    │                 run/attempt/stage/approval state
    ▼
agents/               the five SOC stages - each owns its own prompts,
    │                 scoring, business rules
    ▼
integrations/         external systems: NetWitness, OpenAI
knowledge_base/        SOPs/policies/playbooks the reporting agent reads
schemas/                JSON data contracts
```

Rules this repository holds to (verified during Phase 8/9 cleanup, not
aspirational):

- `agents/*` never imports Flask.
- `workflow/*` never imports the frontend or `backend/routes`.
- `integrations/*` never imports `backend/routes`.
- **The reporting agent (`agents/reporting/`) is one agent, not the
  application's container.** It used to (historically) bundle its own
  Flask app, dashboard, NetWitness client and ticket-store - all of that
  donor code was removed in Phase 9. What remains under `agents/reporting/`
  is genuinely reporting-owned: report generation/editing/export logic,
  templates, schemas, and the CLI/subprocess adapters `workflow/engine.py`
  shells out to.

## The five SOC stages

Defined in `workflow/commands.py`:

```python
STAGES = ("parsing", "triage", "threat_intel", "investigation", "reporting")
APPROVAL_STAGES = ("triage", "investigation", "reporting")
```

| Stage | Owner | What it does | HITL gate |
|---|---|---|---|
| Parsing & Normalisation | `agents/parsing/` | Raw NetWitness alert → normalised, structured record | No |
| Triage | `agents/triage/` | LLM-assisted classification, risk score, MITRE tagging | **Yes** - analyst approves or rejects before Threat Intel runs |
| Threat Intelligence Enrichment | `agents/threat_intelligence/` | IOC lookups (VirusTotal/AbuseIPDB/OTX where configured) | No |
| Investigation | `agents/investigation/` | Evidence correlation, MITRE ATT&CK mapping, verdict; can loop back for more evidence ("evidence gap") | **Yes** |
| Reporting | `agents/reporting/` | Executive summary / technical findings / SOC analyst review / final report, each individually editable and exportable | **Yes** - per-section confirm, then final confirm |

See [`workflow.md`](workflow.md) for exactly how approvals, reruns and
recovery work.

## Backend

`backend/app.py` is a Flask application **factory** (`create_app()`) - the
only business logic in the entire `backend/` package is in `services/`;
`routes/` files are thin (parse the request, call the matching service
method, `jsonify` the result, translate a service exception into the
canonical `{"error": {"code", "message"}}` contract via `backend/errors.py`).

```
backend/
├── app.py          create_app(): registers every blueprint, installs error handlers
├── errors.py        APIError + the global exception handler (never leaks tracebacks)
├── routes/           one blueprint per domain: cases, workflow, netwitness,
│                     reports, chatbot, search, settings, admin_pipeline, imports, dashboard
└── services/          the actual logic each route file calls into
```

## Agents

Each agent owns its own prompts, model choice, structured schema and
fallback logic - Phase 9's OpenAI-infrastructure audit deliberately did
**not** force every agent onto one identical LLM-calling pattern (see
"OpenAI" below).

- **`agents/parsing/`** - `parser_normaliser.py` is the canonical
  implementation (a divergently-forked duplicate at
  `parsing-normalisation-codes/` was removed in Phase 9 after confirming
  zero consumers).
- **`agents/triage/`** - `soc_triage_agent.py`, LangChain `ChatOpenAI`-backed.
- **`agents/threat_intelligence/`** - `threat_intel.py`, provider lookups
  live directly in this stage module (not yet split into a separate
  `integrations/threat_intel/` provider layer - deferred, not required by
  current provider count).
- **`agents/investigation/`** - invoked **out-of-process**: `workflow/engine.py`
  drops the triaged alert into `agents/investigation/triaged_alerts/` and
  launches `python main.py` as a subprocess (`cwd` = this directory), which
  writes its result into `incident_reports/`. This is a genuine
  process-isolation boundary, not a historical leftover - correlation
  engine, MITRE mapper, policy engine and a Chroma-backed policy index all
  live here.
- **`agents/reporting/`** - also subprocess-invoked
  (`agents/reporting/agents/reporting_agent.py` is the actual entry point,
  launched by `agents/reporting/adapters/run_reporting.py`). Everything
  under `agents/reporting/` besides that donor-shaped `agents/`/`backend/`/
  `dashboard/` naming (all confirmed either live-but-reporting-owned or
  deleted as dead donor code in Phase 9) is genuinely reporting logic:
  `reporting/` (context building, narrative, rendering, validation,
  export), `config/`, `report_templates/`, `report_assets/`.

## Integrations

- **`integrations/netwitness/`** - `client.py` (the interactive,
  UI-facing client - deliberately safe error messages, see
  `diagnostics.py`'s `NetWitnessError` docstring: *"An integration failure
  whose public message never contains secrets"*), `auth.py`
  (`NetWitnessConfig`), `incidents.py`, `alerts.py`, `diagnostics.py`, and
  `fetch_api.py` (a second, complete NetWitness client with its own
  token/auth flow, used only by `workflow/engine.py`'s background
  "comprehensive incident payload" enrichment fallback - kept separate
  rather than merged into `client.py` because unifying two independently
  correct auth implementations without a live NetWitness environment to
  verify against would risk silently changing authentication behavior).
- **`integrations/openai/`** - `client.py` wraps the raw `openai` SDK
  (used by `workflow/engine.py`'s AI stage summaries and the reporting
  agent's PDF-export text extraction). Three other call sites
  (`agents/triage/soc_triage_agent.py`, `agents/investigation/{mitre_mapper,orchestrator}.py`)
  use LangChain's `ChatOpenAI` instead - a different interface, not
  mechanically unifiable with a raw-SDK client wrapper, and each carries
  its own model choice and prompt. This is a deliberate scope boundary,
  not an oversight: "one shared client infrastructure" does not mean "one
  code path for every LLM call."

## Repositories / storage

There is no `backend/repositories/` layer - `backend/services/*.py` talk to
SQLite directly (parameterized queries; table/column names that come from
outside a hardcoded allowlist are always validated against that allowlist
before being interpolated - see `pipeline_service.py:_stage()` for the
pattern). Extracting a repository layer was considered during Phase 8/9 and
deliberately deferred: it would mean rewriting the SQL access inside
several actively-serving files for an ownership/cosmetic benefit, which
the migration's own rules explicitly caution against ("do not perform
aggressive internal decomposition merely because it is large").

## Knowledge base / schemas

- `knowledge_base/reporting/{policies,procedures,playbooks}/` - Markdown
  SOPs the reporting agent's RAG context builder retrieves from.
- `schemas/reporting/*.json` - reference JSON schemas documenting the data
  contracts between stages (not runtime-validated against; a documentation
  artifact, not a jsonschema-enforced gate).

## Runtime

Mutable, non-source data lives under `runtime/` (Chroma vector store,
uploads) and `soc_db/` (the workflow SQLite database, intentionally
tracked as demo data - see the README's **Demo data** section) and
`agents/reporting/outputs/` (per-run reporting artifacts, gitignored).
