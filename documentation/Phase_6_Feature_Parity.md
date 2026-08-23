# Phase 6 remaining-feature inventory

This inventory was created before implementation and updated after validation.
It compares the preserved `scripts/legacy_streamlit_app.py` with the canonical
Flask/HTML/CSS/JavaScript application.

| Feature | Legacy Streamlit | Flask after Phase 6 | Parity | Notes |
|---|---|---|---|---|
| Overview metrics/recent cases | Available | Available | PASS | Migrated earlier |
| Case archive, filtering and raw case identity | Available | Available | PASS | Migrated earlier |
| Case CSV export and raw incident JSON | Available | Available | PASS | Read-only download and exact-case raw endpoint |
| Case workflow stages, approvals, reruns and resume | Available | Available | PASS | Canonical commands retained |
| NetWitness login/token/test/sync | Available | Available | PASS | Migrated in Phase 5 |
| JSON/CSV/TXT/LOG incident import | Available | Available | PASS | Migrated in Phase 5 |
| Case evidence, MITRE, timeline, graph and activity views | Available | Available | PASS | Existing case-view model rendered in workspace |
| Global Ask Aegis | Available | Available | PASS | Global chat page and server-side service |
| Case-grounded Ask Aegis | Available | Available | PASS | Backend resolves canonical context from case ID |
| Standalone chat-triggered workflow orchestration | Available | Canonical workflow actions | PASS (replacement) | Duplicate orchestration intentionally obsolete; case responder retained |
| Agent-board animation/transient thinking panel | Available | Durable run progress | PASS (replacement) | Streamlit-only animation replaced by persisted polling |
| Reporting candidate review | Available | Available | PASS | Structured report APIs and workspace |
| Report block editing and revert | Available | Available | PASS | Existing report-edit persistence reused |
| Reporting approval/final confirmation | Available | Available | PASS | Original manifest/hash validation retained |
| Report DOCX/PDF/JSON/ZIP downloads | Available | Available | PASS | Existing exporters and approved resolver reused |
| Triage ticket review/edit/DOCX/PDF | Available | Available | PASS | Existing triage ticket module reused |
| Analyst display name | Session setting | Server setting | PASS | No secret involved; used by workflow/report actions |
| OpenAI status/key replacement/model | Available | Available | PASS | Raw key is never returned |
| NetWitness settings and CA path | Available | Available | PASS | Integrations page retained |
| NetWitness certificate file uploader | Available | Server-side CA path | PASS (replacement) | Arbitrary certificate file writes intentionally removed |
| NetWitness endpoint scanner/manual alternate path | Developer diagnostic | Standard canonical endpoints | DEFERRED | Environment-specific diagnostic is not required for Aegis operation |
| Global semantic incident search | Available when Chroma works | Available | PASS | Backend-owned vector search |
| Chroma connection/vector status | Available | Available | PASS | Safe unavailable state included |
| Chroma search/browse/sync/wipe | Available | Available | PASS | Mutations require developer mode and typed confirmation |
| Pipeline stage counts/records/raw JSON | Available | Available | PASS | Read-only pipeline API/page |
| Pipeline record/artifact downloads | Available | CSV plus canonical case report workspace | PASS (consolidated) | Report/ticket downloads use identity-checked report APIs |
| Pipeline record delete/stage clear | Developer action | Developer action | PASS | Stage whitelist and exact typed confirmation |
| Arbitrary artifact/file browsing | Not available | Not available | PASS | Forbidden by design |
| Streamlit auto-rerun/DOM/session widgets | Framework behavior | Native browser rendering | NOT APPLICABLE | Streamlit infrastructure only |
| Legacy cloud deployment controls | Deployment infrastructure | Removed in Phase 7 | PASS | Replaced by Flask local/deployment guidance |

No major application feature remained dependent on the retired UI framework.
Deferred entries were environment diagnostics rather than required analyst
workflow functionality.
