# Aegis

Aegis is an agentic SOC (Security Operations Center) investigation platform
that turns a raw NetWitness incident into an analyst-reviewed, exportable
incident report, with a human approval gate before every stage that would
otherwise act autonomously.

## Architecture

```
frontend (HTML/CSS/vanilla JS)
        │  fetch()
        ▼
backend/            Flask routes + services (HTTP layer only)
        │
        ▼
workflow/           orchestration + the durable state machine
        │
        ▼
agents/             the five SOC stages (parsing, triage, threat_intelligence,
        │           investigation, reporting)
        ▼
integrations/       external systems (NetWitness, OpenAI)
knowledge_base/      SOPs, policies, playbooks the reporting agent cites
schemas/             data contracts
```

Dependencies only ever point downward through that list - `agents/` never
imports Flask, `workflow/` never imports the frontend, and the reporting
agent is one stage among five, not the application's container. See
[`docs/architecture.md`](docs/architecture.md) for the full picture.

## Workflow

Every incident moves through five stages, in order:

1. **Parsing & Normalisation** - turns a raw NetWitness alert into a
   normalised, structured record.
2. **Triage** - an LLM-assisted classification, risk score and MITRE
   ATT&CK tagging. **Requires analyst approval** before continuing.
3. **Threat Intelligence Enrichment** - looks up IOCs (VirusTotal,
   AbuseIPDB, AlienVault OTX where configured).
4. **Investigation** - correlates evidence, maps to MITRE ATT&CK, and
   reaches a verdict; can loop back for more evidence (an "evidence gap")
   before continuing. **Requires analyst approval** before continuing.
5. **Reporting** - generates executive summary, technical findings, SOC
   analyst review and a final incident report, each individually editable
   and exportable as DOCX/PDF. **Requires analyst approval** (per section,
   then a final confirmation) before a report is considered final.

Reruns, rejections and interrupted-run recovery are all supported without
losing prior approval history - see [`docs/workflow.md`](docs/workflow.md)
for exactly what is and isn't safe to rely on.

## Main features

- Case archive with filtering, sorting and CSV export
- Per-case workspace: stage status, run/rerun controls, approvals,
  evidence-gap decisions, MITRE ATT&CK view, entity graph, activity log
- NetWitness authentication, incident/alert retrieval and sync, or fully
  offline operation against previously-imported/cached cases
- JSON, CSV, TXT and LOG incident import
- Global and case-scoped "Ask Aegis" chat, grounded in the case's own
  workflow data
- Report review, section-by-section editing, confirmation and DOCX/PDF
  export, with hash-verified report-candidate integrity
- Semantic (Chroma-backed) search and a guarded pipeline-inspection/admin
  panel (developer-mode gated, confirmation-string protected)

## Technology stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML, CSS, vanilla JavaScript (no build step, no framework) |
| Workflow state | SQLite (`soc_db/`) |
| Vector search | Chroma |
| LLM | OpenAI API (chat/investigation/reporting), optional local Ollama fallback for reporting narrative |
| Document export | python-docx, reportlab, pypdf |
| Testing | pytest |

## Installation

Requires Python 3.11+ (developed and tested against 3.14; the codebase uses
only standard-library and third-party features available since 3.11).

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

## Configuration

```bash
cp .env.example .env
```

Then fill in whichever sections you need - every variable is optional
except `OPENAI_API_KEY` for AI-assisted features; NetWitness and the
threat-intelligence providers can all be left blank (see below). Full
variable-by-variable reference: [`docs/configuration.md`](docs/configuration.md).

## Running locally

```bash
python app.py
```

Open <http://127.0.0.1:5000>. Health check:

```bash
curl http://127.0.0.1:5000/api/health
# {"application": "Aegis", "status": "ok"}
```

Aegis binds to `127.0.0.1` (localhost only) by default - see
**Security / deployment notes** below before changing that.

## NetWitness setup

Set `NW_HOST`, `NW_USERNAME`/`NW_PASSWORD` (or `NW_TOKEN` directly) in
`.env`, or configure them from the running app's Integrations page. TLS
certificate verification is **on by default**; for a lab appliance with a
self-signed certificate, either point `NW_CERT_PATH` at its CA bundle or
set `NETWITNESS_VERIFY_SSL=false` explicitly (development/demo use only -
see [`docs/configuration.md`](docs/configuration.md)).

NetWitness is entirely optional. With it unconfigured, Aegis still serves
every case already imported or held in `soc_db/`.

## OpenAI setup

Set `OPENAI_API_KEY` in `.env`, or from the running app's Settings page.
`OPENAI_MODEL` selects the model (default `gpt-4o-mini`). Without a key,
Triage/Investigation/Reporting fall back to their non-LLM/templated paths
rather than failing the stage outright.

## Runtime / data paths

| Path | Contents |
|---|---|
| `soc_db/` | The workflow state machine and case archive (SQLite, tracked as demo data - see below) |
| `chroma_db/` | Seed vector store copied into `runtime/chroma/` on first use |
| `runtime/chroma/` | The live Chroma vector store (gitignored) |
| `runtime/uploads/` | Uploaded incident files, server-generated filenames (gitignored) |
| `agents/reporting/outputs/` | Per-run reporting-agent artifacts and generated reports (gitignored) |
| `outputs/` | Static parsing fixtures used by tests/demos (tracked) |

See [`docs/configuration.md`](docs/configuration.md) for how to point any
of these somewhere else, and **Demo data** below for what's actually inside
`soc_db/`.

## Tests

```bash
.venv/bin/python -m pytest -q
```

`conftest.py` redirects every mutable database, reporting artifact and
vector-store path to a temporary directory before collection, so a test run
never modifies tracked files - verified by diffing `git status` before and
after a run. Current baseline: 293 passed, 3 failed. The 3 failures are
pre-existing reporting-fixture gaps (stale test fixtures, not application
bugs) - see [`docs/workflow.md`](docs/workflow.md#known-test-gaps).

## Repository structure

```
app.py                  Flask launcher (11 lines - no business logic)
backend/                HTTP layer: routes/, services/, errors.py
frontend/                index.html, css/, js/
workflow/               engine.py, state_store.py, commands.py
agents/
├── parsing/            raw alert -> normalised record
├── triage/              LLM-assisted classification + MITRE tagging
├── threat_intelligence/ IOC enrichment orchestration
├── investigation/       correlation, MITRE mapping, verdict
└── reporting/           report generation, editing, approval, export
integrations/
├── netwitness/          NetWitness client, auth, alerts, fetch API
└── openai/              shared OpenAI client
knowledge_base/          SOPs, policies, playbooks (reporting agent inputs)
schemas/                 JSON data contracts
scripts/                 maintenance/eval CLI utilities
tests/                   pytest suite
runtime/, soc_db/, chroma_db/   mutable/demo data (see above)
docs/                    architecture.md, workflow.md, configuration.md
```

## Security / deployment notes

Aegis is a **single-operator, localhost-only application** - there is no
login, no per-user accounts, and no session concept anywhere in the stack
(one shared analyst-name/settings state, matching a workstation tool rather
than a multi-tenant service). This is an intentional, documented design
choice for its current use as an FYP/demo tool, not an oversight:

- The server binds to `127.0.0.1` by default (`app.py`); do not change this
  to `0.0.0.0` or put it on a shared network without first adding an
  authentication layer - none exists today.
- Debug mode is off (`debug=False`); the Flask interactive debugger is
  never exposed.
- Admin/destructive endpoints (pipeline record deletion, Chroma collection
  wipe) require an explicit `developer_mode` setting **and** an exact
  type-to-confirm string per call - they are not exposed to a casual click.
- NetWitness TLS verification is on by default; see **NetWitness setup**.
- Secrets (OpenAI key, NetWitness credentials/token) are held server-side
  only - never returned by any API response, never sent to frontend
  JavaScript, never written to browser storage.
- `.env` is gitignored; `.env.example` contains placeholders only.

If you need to run Aegis beyond a trusted local workstation, add an
authentication layer first - see [`docs/configuration.md`](docs/configuration.md)
for the full security posture and what would need to change.

## Demo data

`soc_db/` and `chroma_db/` are intentionally committed so the app has
something to show without a live NetWitness connection. **If this data is
not entirely synthetic** (it may contain real internal hostnames, usernames
or IP addresses from a lab NetWitness instance), treat it as sensitive:
verify/scrub it before pushing this repository to any remote you don't
fully control, especially a public one.

## Known limitations

- No authentication/authorization layer (see **Security / deployment
  notes** - intentional for current localhost/demo use, not yet built for
  broader deployment).
- `workflow/engine.py` and `workflow/state_store.py` remain large,
  single-file modules; splitting them safely needs characterization tests
  for their internal boundaries that don't exist yet (they implement the
  system's stale-write/lease/approval safety guarantees, so this wasn't
  risked during cleanup).
- A handful of root-level "investigation tool" modules
  (`diamond_model.py`, `ioc_correlation.py`, `triage_verdict.py`, and
  similar) are still at the repository root rather than under
  `agents/investigation/`.
- 3 reporting-agent tests fail against stale fixture data (see **Tests**
  above) - not a functional regression, just fixtures that need
  regenerating.
