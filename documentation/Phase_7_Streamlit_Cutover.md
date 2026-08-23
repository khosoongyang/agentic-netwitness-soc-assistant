# Phase 7 final parity and UI cutover

This is the recorded pre-removal inventory and final migration decision for
the Aegis Flask/HTML/CSS/JavaScript cutover. The generated evaluation indexes
dated 2026-07-30 remain historical snapshots; they are not active setup or
launch guidance.

## Pre-removal reference classification

| Location | Classification | Decision |
|---|---|---|
| `scripts/legacy_streamlit_app.py` | A, C and D | Migrated features were verified against Flask; framework rendering, transient animations, rerun workarounds and duplicate orchestration were removed. |
| `chroma_viewer.py` | A and D | Pipeline SQLite inspection and Chroma status/search/browse/sync/wipe are owned by the canonical Pipeline and Search pages; the standalone viewer was removed. |
| `requirements.txt` | C | The retired UI dependency and cloud-only SQLite shim were removed. Chroma itself remains pinned. |
| `.streamlit/` | C | Theme configuration and the secrets template were removed after environment-variable guidance moved to `.env.example`. |
| `README.md`, `DEPLOY.md`, CI comments and `.gitignore` | E | Active launch/deployment instructions were cut over to `python app.py`; cloud-only wording was removed. |
| Generated evaluation indexes dated 2026-07-30 | E | Retained and prominently marked historical for evaluation traceability. |
| `soc_workflow.py`, `case_view.py`, `incident_map.py` comments | D | Presentation-framework wording was removed; reusable business/data logic remains. |
| Legacy workspace source assertion in `tests/test_ai_stage_summaries.py` | F | Replaced with behavioral coverage proving the Flask case service preserves both `ai_summary` and native stage output. |
| Reporting agent, templates, exporters, schemas and knowledge base | Not UI-specific | Retained unchanged. |

No category-B user-facing feature was found. All required behavior had a
canonical Flask owner before removal.

## Final feature parity matrix

| Feature | Legacy Streamlit | New Flask App | Parity | Action Required | Notes |
|---|---|---|---|---|---|
| Overview/dashboard | Metrics, pipeline and recent cases | Overview route/page | PASS | None | Backend-derived metrics and case links |
| Cases list | Archive table | Cases API/page | PASS | None | Canonical case database |
| Search/filter/sort | Case controls | URL/browser controls plus bounded API query | PASS | None | CSV export retained |
| Case workspace | Per-case page | Workspace route/page | PASS | None | Case identity comes from URL and backend |
| Parsing & Normalisation | Stage panel/action | Canonical workflow stage action | PASS | None | Existing runner retained |
| Triage | Stage panel/action | Canonical workflow stage action | PASS | None | Existing agent retained |
| Triage approval/rejection | Buttons and rerun | Approval API/workspace controls | PASS | None | Durable atomic transition |
| Threat Intelligence Enrichment | Stage panel/action | Canonical workflow stage action | PASS | None | Existing enrichment retained |
| Investigation | Stage panel/action | Canonical workflow stage action | PASS | None | Global lock semantics retained |
| Investigation approval/rejection | Buttons and rerun | Approval API/workspace controls | PASS | None | Durable atomic transition |
| Evidence-gap handling | Existing automatic investigation loop | Existing automatic loop surfaced in workflow state | PASS | None | No manual transition exists in canonical workflow |
| Reporting | Stage panel/action | Workflow plus Reports workspace | PASS | None | Reporting agent remains a subsystem |
| Reporting review/approval | Candidate preview and controls | Reports API/page and final confirmation | PASS | None | Manifest/hash checks retained |
| Stage reruns | Stage controls | Rerun API/workspace controls | PASS | None | Attempts and downstream invalidation retained |
| Resume/recovery | Rerun/resume behavior | Resume API and bounded polling | PASS | None | Durable state remains authoritative |
| NetWitness authentication | Credentials/token forms | Integrations service/page | PASS | None | Credentials stay server-side |
| NetWitness connection testing | Connection control | Test endpoint/control | PASS | None | Safe diagnostic response |
| NetWitness incident retrieval | Incident fetch | Integration API | PASS | None | Pagination and identity guards retained |
| NetWitness alert/detail retrieval | Alert fetch/detail | Integration API | PASS | None | Existing client implementation reused |
| NetWitness sync | Sync control | Sync endpoint/control | PASS | None | Canonical case upsert |
| Incident upload/import | File uploader | Import page/API | PASS | None | JSON, CSV, TXT and LOG validation |
| Ask Aegis | Global chat | Ask Aegis page/API | PASS | None | Existing responder retained |
| Case-scoped Ask Aegis | Contextual chat | Workspace chat/API | PASS | None | Context resolved from trusted case ID |
| Triage review/edit/export | Editable ticket and downloads | Reports workspace/API | PASS | None | DOCX/PDF exports retained |
| Report review | Candidate reports | Reports workspace | PASS | None | Structured blocks and warnings rendered |
| Report editing | Block editor/revert | Reports editor/revert | PASS | None | Existing editing persistence reused |
| Report confirmation | Section/final controls | Section and final confirmation APIs | PASS | None | Identity/integrity guards retained |
| PDF export | Download buttons | Download endpoint/control | PASS | None | Existing exporter retained |
| DOCX export | Download buttons | Download endpoint/control | PASS | None | Existing exporter retained |
| JSON/ZIP report data | Generated-file downloads | Reporting data/download routes | PASS | None | Approved artifact resolver retained |
| Settings | Analyst, LLM and integration controls | Settings and Integrations pages | PASS | None | Secrets are never returned |
| Chroma/semantic search | Search and collection tools | Search and Pipeline pages | PASS | None | Mutable store is backend-owned |
| Data Pipeline/admin tools | SQLite/Chroma browser and mutation controls | Pipeline page/API | PASS | None | Whitelist, developer mode and typed confirmation |
| Offline/cached cases | Bundled database fallback | Canonical case APIs without NetWitness | PASS | None | NetWitness may remain unconfigured |
| Agent-board animation | Transient progress animation | Durable progress note and run polling | PASS (replacement) | None | Animation was presentation-only |
| NetWitness certificate upload | Wrote an uploaded file on the server | Explicit server CA path | PASS (replacement) | None | Arbitrary server-file writes intentionally obsolete |
| NetWitness endpoint scanner | Developer-only alternate-path probe | Canonical documented endpoints and connection test | OBSOLETE | None | Environment-specific scanner was not required application behavior |
| UI navigation/widget state | Server rerun session | Browser router and DOM state | PASS (replacement) | None | Not workflow state |

## Former session-state ownership

| Responsibility | Canonical owner |
|---|---|
| Navigation and selected page | Browser history and `frontend/js/router.js` |
| Selected case and stage | URL case identity plus browser page state |
| Search, filters and sorting | URL/browser controls; validated backend query |
| Incidents and case identity | Canonical SQLite store and case APIs |
| Workflow/run state, attempts, leases and approvals | `workflow_state_store.py` and workflow commands |
| NetWitness credentials and token | Server-side NetWitness service/environment |
| Analyst name and developer mode | Server-side settings service |
| Report drafts and confirmations | Existing reporting edit/approval persistence |
| Chat transcript/display state | Browser; trusted case context is rebuilt server-side |
| Chroma client and mutable vector state | Backend search service and `runtime/chroma/` |
| Transient worker progress | Durable workflow progress plus bounded browser polling |

## End-to-end acceptance mapping

The primary path is exercised by workflow command/API tests, NetWitness mock
tests, import tests, report candidate-integrity tests and Flask feature tests:

`NetWitness/import -> case -> parsing -> triage -> triage approval -> threat
intelligence -> investigation -> investigation approval -> reporting -> final
approval -> DOCX/PDF`.

Negative and recovery coverage includes rejection, rerun/downstream
invalidation, stale attempts, duplicate approvals, interrupted-run resume,
automatic evidence-gap handling, unavailable NetWitness, malformed upload,
offline cases and report integrity failure. The four accepted reporting fixture
failures are unchanged from the established baseline and are not UI-cutover
regressions.

## Cutover decision

The root `app.py` is the sole supported Aegis application launcher. It imports
only the canonical root `backend.app.create_app`. The donor
`soc_reporting_agent/backend/app.py` remains outside the root application and
is deferred to later technical-debt work. Workflow, agent, report and database
semantics were not changed in this phase.
