# API reference

Concise endpoint reference, not a full OpenAPI spec. Every response follows
one of two shapes: the route's own JSON on success, or
`{"error": {"code": "...", "message": "..."}}` with an appropriate HTTP
status on failure (`backend/errors.py` - no traceback or internal detail is
ever included). All routes are under `/api`.

## Health

| Method | Path | Notes |
|---|---|---|
| GET | `/api/health` | `{"application": "Aegis", "status": "ok"}` |

## Dashboard

| Method | Path | Notes |
|---|---|---|
| GET | `/api/dashboard` | Overview aggregates: severity counts, pipeline stage counts, recent cases |

## Cases

| Method | Path | Notes |
|---|---|---|
| GET | `/api/cases` | Filterable/sortable case list |
| GET | `/api/cases/export` | CSV export of the case list |
| GET | `/api/cases/<case_id>` | Full case detail (all stage results, MITRE view, entity graph, evidence) |
| GET | `/api/cases/<case_id>/workflow` | Workflow/stage status for one case |
| GET | `/api/cases/<case_id>/raw` | Raw stored incident record |

## Workflow: stage runs, reruns, approvals

| Method | Path | Notes |
|---|---|---|
| GET | `/api/runs/<run_id>` | Status of a specific run |
| POST | `/api/cases/<case_id>/stages/<stage>/runs` | Start a stage |
| POST | `/api/cases/<case_id>/stages/<stage>/reruns` | Rerun a stage (advances that stage's attempt counter; invalidates its downstream results - see [`workflow.md`](workflow.md)) |
| POST | `/api/cases/<case_id>/approvals/<stage>` | Approve or reject a stage (`triage`, `investigation`, `reporting`) |
| POST | `/api/cases/<case_id>/evidence-gap-decisions` | Record an evidence-gap decision during Investigation |
| POST | `/api/cases/<case_id>/workflow/resume` | Re-trigger the durable claim path after an interruption (see **Restart / recovery** in [`workflow.md`](workflow.md)) |

## NetWitness integration

| Method | Path | Notes |
|---|---|---|
| GET | `/api/integrations/netwitness/status` | Connection/config status - never returns credentials |
| POST | `/api/integrations/netwitness/login` | Username/password login |
| POST | `/api/integrations/netwitness/token` | Configure a session token directly |
| POST | `/api/integrations/netwitness/test` | Test the current connection |
| GET | `/api/integrations/netwitness/incidents` | List incidents (`page`, `limit`, `since`) |
| GET | `/api/integrations/netwitness/incidents/<incident_id>` | One incident |
| GET | `/api/integrations/netwitness/incidents/<incident_id>/alerts` | Alerts for one incident |
| GET | `/api/integrations/netwitness/alerts/<alert_id>` | One alert |
| POST | `/api/integrations/netwitness/sync` | Sync incidents into the local case archive |

## Imports

| Method | Path | Notes |
|---|---|---|
| POST | `/api/imports/incidents` | Upload a JSON/CSV/TXT/LOG incident file (5 MB limit, server-generated storage filename - see the README's security notes) |

## Ask Aegis

| Method | Path | Notes |
|---|---|---|
| POST | `/api/chat` | Global Ask Aegis |
| POST | `/api/cases/<case_id>/chat` | Case-scoped Ask Aegis, grounded in that case's workflow data |

## Reports

| Method | Path | Notes |
|---|---|---|
| GET | `/api/cases/<case_id>/reports` | List reports for a case |
| GET | `/api/cases/<case_id>/reports/<report_type>` | Read one report section |
| PUT | `/api/cases/<case_id>/reports/<report_type>` | Save an edit (draft state) |
| DELETE | `/api/cases/<case_id>/reports/<report_type>/draft` | Discard a draft edit |
| POST | `/api/cases/<case_id>/reports/<report_type>/confirm` | Confirm a section |
| POST | `/api/cases/<case_id>/reports/final/confirm` | Final confirmation of the whole report |
| GET | `/api/cases/<case_id>/reports/<report_type>/download?format=docx\|pdf` | Download one section (identity/hash re-verified on every download) |
| GET | `/api/cases/<case_id>/reports/export-all` | ZIP of every exported report |
| GET | `/api/cases/<case_id>/reports/data/download` | Raw reporting JSON |

## Search

| Method | Path | Notes |
|---|---|---|
| GET | `/api/search/status` | Whether the vector store is available |
| POST | `/api/search` | Semantic search |
| GET | `/api/search/vectors` | Browse indexed vectors |

## Settings

| Method | Path | Notes |
|---|---|---|
| GET | `/api/settings` | Current settings (never includes the OpenAI key itself - only `openai_configured: bool`) |
| PUT | `/api/settings` | Update analyst name, developer mode, OpenAI model/key |

## Admin (developer-mode gated + exact confirmation string required - see the README's security notes)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/pipeline` | Read-only pipeline summary |
| GET | `/api/pipeline/<stage>/records` | Read-only record listing |
| GET | `/api/pipeline/<stage>/records/<record_id>/download` | CSV export of one record |
| DELETE | `/api/admin/pipeline/<stage>/records/<record_id>` | Delete one record - requires `developer_mode` and body `{"confirmation": "DELETE <stage>/<record_id>"}` |
| DELETE | `/api/admin/pipeline/<stage>` | Clear a whole stage table - requires `developer_mode` and body `{"confirmation": "CLEAR <stage>"}` |
| POST | `/api/admin/vector/sync` | Rebuild the vector index from the case archive - requires `developer_mode` |
| DELETE | `/api/admin/vector/collections/<collection_name>` | Wipe a Chroma collection - requires `developer_mode` and confirmation |

`<stage>` for pipeline/admin routes is always validated against a fixed
allowlist (`PIPELINE_STAGES`) before use, including in SQL - see
`backend/services/pipeline_service.py`.
