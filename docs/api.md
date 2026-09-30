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
| GET | `/api/cases` | Filterable/sortable case list (`query`, `search`, `severity`, `status`, `workflow_status`, `stage`, `verdict`, `time_range`, `updated_from`, `updated_to`, `sort`, `direction`, `page`, `limit`) |
| GET | `/api/cases/query-schema` | Fields, values, operators and examples of the case query language (drives autocomplete and syntax help) |
| GET | `/api/cases/export` | CSV export of the case list |
| GET | `/api/cases/<case_id>` | Full case detail (all stage results, MITRE view, entity graph, evidence) |
| GET | `/api/cases/<case_id>/workflow` | Workflow/stage status for one case |
| GET | `/api/cases/<case_id>/raw` | Raw stored incident record |

### Case query language (`/api/cases?query=...`)

The Operations Overview search box sends its text as `query`. Parsing lives
in `backend/services/case_query.py`; the SQL compiler is in
`backend/services/case_service.py`.

- **Free text**: if the text contains no field expression it is one legacy
  contains-phrase over title, assignee and ID - `command and control` is a
  phrase, not Boolean logic. `%` and `_` match themselves.
- **Structured**: any `field:value` switches to the query language.
  `AND` / `OR` / `NOT` (any case), parentheses and `field:(A OR B)` value
  lists are supported; precedence is NOT > AND > OR and terms side by side
  are ANDed. A run of bare words is one phrase:
  `PowerShell severity:HIGH` = phrase "PowerShell" AND severity HIGH.

| Field | Meaning | Operators | Values |
|---|---|---|---|
| `case` (alias `id`) | Exact incident ID | `:` `:=` | e.g. `INC-53027` |
| `title` | Title contains (case-insensitive) | `:` | any text |
| `severity` | NetWitness severity, ordered CRITICAL > HIGH > MEDIUM > LOW | `:` `:=` `:>` `:>=` `:<` `:<=` | `CRITICAL` `HIGH` `MEDIUM` `LOW` |
| `workflow_status` | Aegis workflow state (not the NetWitness `status`) | `:` | `"Not Started"` `"In Progress"` `"Awaiting Action"` `"Awaiting Approval"` `Rejected` `Failed` `Complete` |
| `stage` | Derived current workflow stage | `:` | `parsing` `triage` `threat_intel` `investigation` `reporting` (readable names such as `"Threat Intelligence"` accepted) |
| `verdict` | Unified Verdict (same resolver as the case workspace) | `:` | `CRITICAL` `HIGH` `MEDIUM` `LOW` `UNRATED` |
| `approval_stage` | Stage waiting for analyst approval | `:` | `triage` `investigation` `reporting` |
| `source` | NetWitness incident source (primary), via the `ix_incidents_primary_source` expression index | `:` | `ESA` (Event Stream Analysis), `ECAT`, `"Risk Scoring"` |
| `created`, `updated` | NetWitness created / last-updated time | `:` `:=` `:>` `:>=` `:<` `:<=` | `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM[:SS]`, optional `Z` / `±HH:MM` |

Dates without a timezone are UTC, and a date covers its typed precision:
`updated:2026-09-30` is that whole UTC day, `updated:>2026-09-30` starts at
2026-10-01T00:00:00. The Filters panel's Custom range is UTC too, so the
same wall-clock time means the same instant in both.

The query is ANDed with every Filters-panel parameter (the same field in
both is ANDed, never overridden) before sorting and pagination. The
response includes `query: {text, mode, normalised, fields}`.

Invalid queries fail before the database is opened, with a positioned
error for the search box:

```json
{"error": {"code": "INVALID_QUERY", "message": "Unknown severity \"VERYHIGH\".",
           "details": {"param": "query", "start": 9, "end": 17,
                       "hint": "Expected: CRITICAL, HIGH, MEDIUM, LOW."}}}
```

`status:` is deliberately not a field (`Did you mean workflow_status:?`).
Limits: 1,000 characters, 64 terms, 16 nesting levels. If the `source:`
index is missing the request fails with `503 QUERY_INDEX_UNAVAILABLE`
instead of scanning raw JSON; `db_init()` recreates it.

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
