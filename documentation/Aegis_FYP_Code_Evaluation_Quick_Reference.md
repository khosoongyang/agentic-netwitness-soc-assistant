# 1. Aegis FYP Code Evaluation Quick Reference Guide

**Project:** Aegis - Agentic SOC Automation  
**Team:** Kho Soong Yang; Shahrul Gunawan S/O Iqbal Suppiah; Teo Rui Xuan  
**Version:** 1.0  
**Generation date:** 2026-07-30  
**Repository:** agentic-netwitness-soc-assistant  
**Branch:** merge-final-evaluation  
**Total documented code/configuration files:** 131

This document helps team members locate, explain and demonstrate important code during the FYP evaluation.

## 2. How to Use This Document During the Evaluation

This is a searchable navigation guide. It is not intended to be read from beginning to end during the evaluation.

### 2.1 Fastest usage method

1. Listen for the main functionality mentioned by the evaluator.
2. Open the Master Functionality Index.
3. Search for the functionality.
4. Identify the file path.
5. Identify the class, function or method.
6. Copy the suggested Ctrl + F term.
7. Open the file in Visual Studio Code.
8. Press Ctrl + F.
9. Search for the exact symbol or `[FYP-*]` label.
10. Show the entry-point or main processing function.
11. Explain its input.
12. Explain its processing.
13. Explain its output.
14. Explain the next function or stage.
15. Follow the cross-file chain only when deeper detail is requested.

### 2.2 Recommended answer order

1. Purpose
2. File
3. Function
4. Input
5. Processing
6. Output
7. Next function or stage

> This functionality is implemented in `<file path>`, mainly inside `<function name>`. It receives `<input>`, performs `<main processing>`, and produces `<output>`. The result is then used by `<next component or function>`.

### 2.3 Ten-second answer method

> The functionality is implemented in `<file>`, inside `<function>`. It receives `<input>`, performs `<processing>`, and passes the result to `<next stage>`.

Begin with the ten-second answer and expand only when asked.

### 2.4 Complete usage examples

**Evaluator asks:** Where are IOCs extracted?

**Search in document:** def extract_iocs  
**Open:** `threat_intel.py`  
**Ctrl + F:** `def extract_iocs`  
**Code to show:** `extract_iocs`  
**Ten-second answer:** Threat-intel extraction is threat_intel.extract_iocs; non-NetWitness import normalisation also has alert_triage._extract_iocs.  
**Follow-up code:** alert_triage.py

**Evaluator asks:** Where is deterministic severity calculated?

**Search in document:** Severity Calculation  
**Open:** `alert_triage.py`  
**Ctrl + F:** `Severity Calculation`  
**Code to show:** `analyze_alert`  
**Ten-second answer:** alert_triage.analyze_alert sums weighted indicators and applies strong-indicator floors.  
**Follow-up code:** triage_verdict.py

**Evaluator asks:** Where is the next stage selected?

**Search in document:** State-Aware Stage Dispatcher  
**Open:** `soc_workflow.py`  
**Ctrl + F:** `State-Aware Stage Dispatcher`  
**Code to show:** `run_stage_chain`  
**Ten-second answer:** run_stage_chain dispatches durable Streamlit work; build_orchestration_decision selects ticket UI actions.  
**Follow-up code:** orchestration_service.py

**Evaluator asks:** Where is human approval stored?

**Search in document:** [FYP-APPROVAL]  
**Open:** `workflow_state_store.py`  
**Ctrl + F:** `[FYP-APPROVAL]`  
**Code to show:** `approve_triage / approve_investigation / commit_reporting_approval`  
**Ten-second answer:** workflow_state_store records atomic triage/investigation/reporting approvals and audit rows.  
**Follow-up code:** workflow_approvals

**Evaluator asks:** What happens on an earlier-stage re-run?

**Search in document:** def rerun_stage  
**Open:** `workflow_state_store.py`  
**Ctrl + F:** `def rerun_stage`  
**Code to show:** `rerun_stage`  
**Ten-second answer:** workflow_state_store.rerun_stage clears affected downstream outputs, increments the attempt, and blocks later work until rerun in order.  
**Follow-up code:** run_stage_chain

**Evaluator asks:** Where is the incident timeline generated?

**Search in document:** def normalize_incident_input  
**Open:** `soc_investigation_agent_revised/mitre_mapper.py`  
**Ctrl + F:** `def normalize_incident_input`  
**Code to show:** `normalize_incident_input`  
**Ten-second answer:** mitre_mapper.normalize_incident_input builds the ordered timeline; orchestrator.build_timeline_text renders investigation context.  
**Follow-up code:** orchestrator.py

**Evaluator asks:** Where is the final report generated?

**Search in document:** class ReportingAgent  
**Open:** `soc_reporting_agent/agents/reporting_agent.py`  
**Ctrl + F:** `class ReportingAgent`  
**Code to show:** `ReportingAgent`  
**Ten-second answer:** ReportingAgent builds sections; template_document_exporter generates final document artifacts.  
**Follow-up code:** template_document_exporter.py

**Evaluator asks:** How does Ask Aegis get completed results?

**Search in document:** def build_aegis_context  
**Open:** `case_view.py`  
**Ctrl + F:** `def build_aegis_context`  
**Code to show:** `build_aegis_context`  
**Ten-second answer:** case_view.build_aegis_context reads current stage results on every message and size-bounds them.  
**Follow-up code:** app.py chat_respond

### 2.5 Which document section to use

| Situation | Section to Open |
|---|---|
| Where a feature is implemented | Master Functionality Index |
| How a component works | Component Quick Reference |
| How files connect | Function Call Chains |
| How data is passed | Inputs, Outputs and Data Handoffs |
| A variable or status | Important Variables and Workflow States |
| An API | API Reference |
| PostgreSQL or ChromaDB | Database and Knowledge-Base Reference |
| LLM behaviour | LLM and Rule-Based Processing |
| Approval or re-runs | Approval, Stage Locking and Re-run Logic |
| A failure | Error Handling and Fallback Index |
| Ownership | Team Ownership and Question Routing |
| A term | Quick Search-Term Index |
| Any file | File-by-File Code Map |

### 2.6 Visual Studio Code preparation

1. Open the repository root and both quick-reference files.
2. Pin `app.py`, `soc_workflow.py`, `workflow_state_store.py`, and one main file per stage.
3. Pin approval/re-run logic, `case_view.build_aegis_context`, and report export.
4. Enable Explorer and Outline; increase editor font size.
5. Collapse generated/dependency directories; do not open `.env`.
6. Close unnecessary terminals and keep repository-wide search available.

### 2.7 Keyboard shortcuts

| Action | Shortcut |
|---|---|
| Find in current file | Ctrl + F |
| Find across repository | Ctrl + Shift + F |
| Open file by name | Ctrl + P |
| Go to symbol | Ctrl + Shift + O |
| Go to definition | F12 |
| Peek definition | Alt + F12 |
| Go back | Alt + Left Arrow |
| Open Explorer | Ctrl + Shift + E |
| Open Markdown preview | Ctrl + Shift + V |

### 2.8 What not to do

- Do not scroll through the whole codebase without the index.
- Do not start with a long answer or guess a symbol.
- Do not show unrelated code or expose API keys.
- Do not claim unimplemented functionality exists.
- Do not say the LLM performs deterministic rule logic.
- Do not confuse a UI handler with its processing function.
- Do not confuse unlocking with executing.
- Do not rely only on line numbers.

## 3. Table of Contents

<!-- WORD_TOC -->

1. Title Page
2. How to Use This Document
3. Table of Contents
4. Repository Code Coverage Summary
5. One-Page System Workflow Overview
6. System Architecture Summary
7. Master Functionality Index
8. Component Quick-Reference Sections
9. Evaluator Question Index
10. Function Call Chains
11. Inputs, Outputs and Data Handoffs
12. Important Variables and Workflow States
13. API Reference
14. Database and Knowledge-Base Reference
15. LLM and Rule-Based Processing
16. Approval, Stage Locking and Re-run Logic
17. Error Handling and Fallback Index
18. Team Ownership and Question Routing
19. Ten-Second and Detailed Explanations
20. Live Demonstration Checklist
21. Quick Search-Term Index
22. File-by-File Code Map
23. Intended Behaviour Versus Actual Implementation
24. Test Code Reference
25. Full Code Documentation Coverage

## 4. Repository Code Coverage Summary

| Category | Files Found | Files Documented | Files Excluded | Coverage |
|---|---|---|---|---|
| CSS | 1 | 1 | 0 | 100% |
| Dependency configuration | 2 | 2 | 0 | 100% |
| HTML | 1 | 1 | 0 | 100% |
| JavaScript | 1 | 1 | 0 | 100% |
| Jinja2 | 5 | 5 | 0 | 100% |
| Python | 112 | 112 | 0 | 100% |
| TOML | 2 | 2 | 0 | 100% |
| TOML template | 1 | 1 | 0 | 100% |
| YAML | 6 | 6 | 0 | 100% |

All relevant first-party source-code files were reviewed. No canonical file remains undocumented. The seven files in `parsing-normalisation-codes/` are excluded superseded duplicates and are listed in the coverage report. Two changed SQLite binaries require origin review but are not source documentation targets.

## 5. One-Page System Workflow Overview

| Stage | Trigger | Main File | Entry Point | Input | Output | Approval | Next Behaviour |
|---|---|---|---|---|---|---|---|
| Parsing | Run Parsing/Run Next | soc_workflow.py; services/parser_normaliser.py | run_parsing | raw incident/alert | parsing_result/artifacts | None in STAGES | Completes; Triage becomes runnable, not inherently executed by stage_workflow |
| Triage | Start Triage | soc_workflow.py; soc_triage_agent.py | run_triage | parsed incident/context | triage_result/ticket | Triage approval | Approval unlocks TI; Streamlit caller may spawn background dispatcher |
| Threat Intelligence | Run Next/background chain | threat_intel.py; soc_workflow.py | resume_after_triage_approval | approved triage + IOCs | threat_intel_result | Flask STAGES: TI approval; durable Streamlit: no separate TI approval | Flask waits for approval; durable chain can continue to Investigation |
| Investigation | Run Next/background chain | soc_workflow.py; investigation orchestrator.py | run_investigation_stage | triage/TI/policies/vectors | investigation_result | Investigation approval | Pauses Awaiting Approval; approval unlocks Reporting |
| Reporting | Run Next/background chain | soc_workflow.py; reporting_agent.py | run_reporting_stage | approved upstream results | reporting_result + DOCX/PDF candidates | Final reporting approval | Approval pins candidate and marks workflow Complete |

## 6. System Architecture Summary

- **Dashboard/frontend:** `app.py` is the integrated Streamlit UI; `dashboard/index.html`, `app.js`, and `style.css` form a separate Flask-served SPA.
- **Backend:** `backend/app.py` exposes 90 routes and delegates casework, workflow gating, errors, LLM calls, and exports.
- **Workflow orchestration:** `soc_workflow.py` executes durable stages; `workflow_state_store.py` persists run/approval/lease state; `stage_workflow.py` is the ticket workflow gate.
- **Parsing:** reporting service adapters and `parser_normaliser.py`.
- **Triage:** deterministic `alert_triage.py` plus LLM-assisted `TriageAgent`.
- **Threat intelligence:** NetWitness, VirusTotal, AbuseIPDB, OTX, and internal correlation.
- **Investigation:** policy/vector retrieval, correlation, timeline, MITRE mapping, and structured final analysis.
- **Reporting:** context building, RAG, LLM/deterministic narrative, templates, editable review, and DOCX/PDF export.
- **Chatbot:** `case_view.build_aegis_context`, Streamlit chat, and `/api/ask`.
- **Storage:** SQLite workflow/pipeline/triage stores, PostgreSQL casework, ChromaDB collections, and run-scoped files.

## 7. Master Functionality Index

| ID | Functionality | Component | File Path | Class or Function | Ctrl + F | Input | Output | Quick Explanation | Called By | Calls |
|---|---|---|---|---|---|---|---|---|---|---|
| APP-01 | Streamlit application startup and page routing | Application/UI | `app.py` | module entry / _render_top_nav | module entry | Streamlit state and configuration | Rendered pages | Streamlit executes the script top-to-bottom on each interaction. | streamlit run app.py | _bridge_cloud_secrets, db_init, routing blocks |
| APP-02 | Cloud/local secret bridging | Application/UI | `app.py` | _bridge_cloud_secrets | _bridge_cloud_secrets | st.secrets | os.environ entries | Copies configured secret values into the process environment without overwriting existing values. | app.py import-time bootstrap | os.environ.setdefault |
| APP-03 | NetWitness incident ingestion | Application/UI | `app.py` | nw_fetch_incidents | nw_fetch_incidents | Bearer token and paginated API | Enriched incident dictionaries | Fetches incident pages and related alerts under bounded time limits. | maybe_auto_fetch/manual fetch | _bounded_get, nw_alerts |
| UI-01 | Case workflow stage selector | Application/UI | `app.py` | _case_stage_states / _render_case_stage_selector | _case_stage_states | Persisted workflow state | Enabled/locked stage controls | Computes and renders the stage status used by the Streamlit workspace. | My Workspace | workflow_state_store.get_state |
| UI-02 | Standalone dashboard refresh | Frontend | `soc_reporting_agent/dashboard/app.js` | refresh | refresh | Route, filters, ticket id | state and DOM refresh | Loads dashboard/ticket/export state from the Flask API. | route/actions | api, render |
| UI-03 | Central dashboard action dispatcher | Frontend | `soc_reporting_agent/dashboard/app.js` | action | action | data-action DOM events | API mutations/navigation | Routes buttons to run, approve, reject, rerun, report, and Ask Aegis handlers. | document click delegation | runNext, decision, runAgent |
| API-01 | Flask API service | Backend | `soc_reporting_agent/backend/app.py` | app / api_* route handlers | app | HTTP requests | JSON/blob responses | Exposes ticket, workflow, agent, report, integration, and chatbot endpoints. | dashboard/app.js | casework store and workflow services |
| API-02 | Central API error contract | Backend | `soc_reporting_agent/backend/error_handling.py` | api_guard / install_api_guards | api_guard | route calls and exceptions | normalised error JSON | Wraps API routes and maps known failures to analyst-readable status codes. | backend/app.py startup | Flask response helpers |
| PAR-01 | Parsing and normalisation | Parsing/Services | `soc_reporting_agent/services/parser_normaliser.py` | process_alert / normalisation helpers | process_alert | raw NetWitness or imported alert | processed/normalised alert artifacts | Maps aliases, timestamps, entities, and encoded PowerShell into the canonical schema. | soc_workflow.run_parsing and adapters | parser_context_guard, powershell_decoder |
| PAR-02 | Parser context isolation | Parsing/Services | `soc_reporting_agent/services/parser_context_guard.py` | context guard functions | context guard functions | incident/ticket context | validated context decision | Prevents stale or cross-incident parser artifacts from being accepted. | parser adapter/service | path and identity checks |
| TRI-01 | Deterministic severity/risk/confidence | Triage | `alert_triage.py` | analyze_alert | analyze_alert | normalised alert text/fields | classification, severity, score, confidence | Uses weighted regex indicators and corroboration rules; it is not an LLM path. | normalize_to_incident | validate_alert, _scan_text |
| TRI-02 | LLM-assisted SOC triage | Triage | `soc_triage_agent/soc_triage_agent.py` | TriageAgent / soc_triage_chat_respond | TriageAgent | incident, retrieved context, model config | triage JSON/ticket/chat answer | Builds prompts, invokes the configured model, repairs JSON, and caches outputs. | soc_workflow.run_triage / app.chat_respond | build_llm, _extract_json, _repair_json |
| TRI-03 | Final triage verdict aggregation | Triage | `triage_verdict.py` | aggregate_verdict | aggregate_verdict | triage, TI, investigation, correlation signals | combined verdict | Combines rule/API/agent signals while retaining provenance. | case_view and reporting helpers | signal helpers |
| TI-01 | IOC extraction and validation | Threat intelligence | `threat_intel.py` | extract_iocs | extract_iocs | processed alert | validated hashes/IPs/domains/URLs | Extracts provider-ready IOCs and drops private or malformed candidates. | enrich_alert | is_ip_address, is_private_ip, is_external_domain |
| TI-02 | VirusTotal enrichment | Threat intelligence | `threat_intel.py` | query_virustotal_file_hash / query_virustotal_ip / query_virustotal_domain | query_virustotal_file_hash | validated IOC and VT_API_KEY | provider result | Calls the three VirusTotal v3 indicator endpoints with timeout/error handling. | enrich_alert | requests.get |
| TI-03 | AbuseIPDB enrichment | Threat intelligence | `threat_intel.py` | query_abuseipdb | query_abuseipdb | public IP and ABUSEIPDB_API_KEY | abuse confidence result | Queries the AbuseIPDB check endpoint and normalises failures. | enrich_alert | requests.get |
| TI-04 | AlienVault OTX enrichment | Threat intelligence | `threat_intel.py` | query_otx_indicator | query_otx_indicator | validated IOC and OTX_API_KEY | pulse/reputation result | Queries the OTX indicator endpoint and normalises failures. | enrich_alert | requests.get |
| TI-05 | Threat-intelligence risk calculation | Threat intelligence | `threat_intel.py` | calculate_enrichment_risk | calculate_enrichment_risk | provider results | risk score/label | Aggregates provider evidence into deterministic enrichment risk. | enrich_alert | provider-result iteration |
| NW-01 | NetWitness authentication | Threat intelligence | `APIRetrieval.py` | authenticate_netwitness / get_auth_token | authenticate_netwitness | host, username, password | access token | Authenticates to Respond and stores token aliases without logging credentials. | API retrieval functions | POST /rest/api/auth/userpass |
| NW-02 | NetWitness comprehensive alert retrieval | Threat intelligence | `APIRetrieval.py` | fetch_all_alerts_and_endpoint_events | fetch_all_alerts_and_endpoint_events | incident id and token | raw alert/event set | Combines incident, fetch API, and paginated related-alert retrieval. | workflow enrichment path | fetch_* helpers |
| COR-01 | Internal IOC correlation | Threat intelligence | `ioc_correlation.py` | correlate_iocs | correlate_iocs | current IOCs and incident corpus | corroboration snapshot | Finds prior/open-case IOC matches with a ubiquity guard. | triage/workflow views | SQLite reads |
| COR-02 | Incident grouping correlation | Investigation | `soc_investigation_agent_revised/correlation_engine.py` | CorrelationEngine.correlate_alert | CorrelationEngine.correlate_alert | new alert and active incidents | Tier 1 match or Tier 2 seed | Scores indicator, tactic, and temporal proximity. | investigation main/sync | evaluate_tier1 |
| INV-01 | Investigation orchestration | Investigation | `soc_investigation_agent_revised/orchestrator.py` | orchestrate_incident | orchestrate_incident | triaged alert, policies, vector context | FinalIncidentAnalysis | Runs policy selection, two-pass analysis, milestone checks, and final synthesis. | soc_workflow.run_investigation | get_llm, PolicyVectorIndex, generate_final_analysis |
| INV-02 | Investigation timeline construction | Investigation | `soc_investigation_agent_revised/mitre_mapper.py` | normalize_incident_input | normalize_incident_input | incident alerts/events | ordered TimelineEvent list | Normalises timestamps and event/entity descriptions for mapping. | map_incident_mitre_ttps | parse_event_timestamp, parse_user_host |
| INV-03 | MITRE ATT&CK mapping | Investigation | `soc_investigation_agent_revised/mitre_mapper.py` | map_incident_mitre_ttps | map_incident_mitre_ttps | normalised timeline | IncidentMitreAnalysis | Uses LLM mapping when available and fallback_heuristic_mapper otherwise. | investigation workflow | generate_markdown_table, fallback_heuristic_mapper |
| INV-04 | Knowledge/policy vector retrieval | Investigation | `soc_investigation_agent_revised/orchestrator.py` | PolicyVectorIndex / get_policy_manager | PolicyVectorIndex | policy documents and query | relevant policy context | Indexes policy sections in ChromaDB and retrieves relevant investigation guidance. | orchestrate_incident | ChromaDB, embeddings |
| ORCH-01 | Durable workflow stage dispatcher | Orchestration/State | `soc_workflow.py` | run_stage_chain | run_stage_chain | incident_id, run_id, persisted statuses | stage execution/state updates | Resumes the one stage currently marked Processing and pauses at approvals/failures. | app.py background threads | resume_after_triage_approval, run_investigation_stage, run_reporting_stage |
| ORCH-02 | Triage routing decision | Orchestration/State | `soc_workflow.py` | needs_investigation | needs_investigation | triage classification | boolean route | Routes critical/high/medium cases to investigation. | workflow runners | classification normalisation |
| ORCH-03 | Triage-to-investigation handoff | Orchestration/State | `soc_workflow.py` | handoff_to_investigation | handoff_to_investigation | triage result and incident | queued investigation alert JSON | Builds and writes the investigation input while quarantining stale queue files. | investigate_with_feedback | build_investigation_alert, atomic write |
| ORCH-04 | Investigation-to-reporting handoff | Orchestration/State | `soc_workflow.py` | handoff_to_reporting | handoff_to_reporting | upstream results and run identity | run-scoped reporting input files/manifest | Writes verified, attempt-scoped reporting inputs. | run_reporting_stage | skills_sidecar, manifest hashing |
| ORCH-05 | Ticket orchestration decision | Backend | `soc_reporting_agent/backend/orchestration_service.py` | build_orchestration_decision | build_orchestration_decision | ticket stage results/approvals | next allowed action | Delegates stage eligibility to stage_workflow and returns the UI decision. | backend routes/ticket workflow | stage_workflow.can_run/status |
| STATE-01 | Workflow database initialisation | Orchestration/State | `workflow_state_store.py` | db_init | db_init | database path/config | tables and additive migrations | Creates durable incident, approval, lock, activity, and report-edit storage. | app/workflow entry points | _ensure_workflow_columns |
| STATE-02 | Canonical stage locking | Backend | `soc_reporting_agent/backend/stage_workflow.py` | can_run / prerequisite_met | can_run | ticket results and approvals | allowed flag and reason | Requires prior stages to be complete and approved before a stage may run. | orchestration_service/backend routes | STAGES, output_valid, is_approved |
| STATE-03 | Atomic stage leases | Orchestration/State | `workflow_state_store.py` | claim_stage / renew_stage_lease / release_stage_lease | claim_stage | incident/run/stage/worker ids | lease state | Prevents duplicate concurrent stage workers and detects stale writers. | soc_workflow durable stages | transactional SQLite updates |
| APPROVAL-01 | Triage approval/rejection | Orchestration/State | `workflow_state_store.py` | approve_triage / reject_triage | approve_triage | run identity, analyst, comments | approved/unlocked or rejected/blocked state | Records the first human gate atomically. | app.py controls | _atomic_stage_transition |
| APPROVAL-02 | Investigation approval/rejection | Orchestration/State | `workflow_state_store.py` | approve_investigation / reject_investigation | approve_investigation | run identity, analyst, comments | reporting pending or blocked | Records the second human gate atomically. | app.py controls | _atomic_stage_transition |
| APPROVAL-03 | Reporting approval commit | Orchestration/State | `workflow_state_store.py` | commit_reporting_approval | commit_reporting_approval | exact attempt/result plus analyst decision | Complete workflow and immutable approved-set audit | Binds approval to the exact report candidate reviewed. | reporting_approval.py | _atomic_stage_transition |
| RERUN-01 | Downstream invalidation | Orchestration/State | `workflow_state_store.py` | rerun_stage | rerun_stage | incident/run/stage | new attempt and cleared downstream results | Restarts TI/Investigation/Reporting and invalidates only affected later stages. | app.py rerun actions | _tx |
| RERUN-02 | Investigation evidence-gap feedback | Orchestration/State | `soc_workflow.py` | detect_evidence_gaps / investigate_with_feedback | detect_evidence_gaps | investigation playbook results | optional deeper triage and rerun | Automatically repeats investigation within configured pass/threshold limits. | investigation workflow | deep_triage_supplement, run_investigation |
| REP-01 | Reporting context construction | Reporting | `soc_reporting_agent/reporting/context_builder.py` | build_context | build_context | validated upstream JSON | normalised report context | Normalises assets, users, IOCs, evidence, timeline, gaps, and recommendations. | reporting agent | normalisation helpers |
| REP-02 | LLM narrative generation with validation | Reporting | `soc_reporting_agent/reporting/llm_narrative.py` | enhance_narrative | enhance_narrative | report context and section | validated/repaired section text | Builds prompts, invokes providers, checks unsupported claims, repairs, and falls back deterministically. | reporting agent | invoke_llm_with_retries, validate_llm_section_quality |
| REP-03 | Editable report lifecycle | Reporting | `soc_reporting_agent/reporting/editable_reports.py` | report edit/confirm helpers | report edit/confirm helpers | generated sections and analyst edits | draft/editable/confirmed states | Preserves report history and confirmation status. | backend report routes/app.py | manifest and file helpers |
| EXPORT-01 | DOCX report export | Reporting | `soc_reporting_agent/reporting/template_document_exporter.py` | create_docx_from_blocks / generate_reporting_export | create_docx_from_blocks | approved report blocks/context | DOCX file and manifest | Creates branded Word output with tables, callouts, lists, and validation. | backend export routes/soc_workflow | python-docx helpers |
| EXPORT-02 | PDF report export | Reporting | `soc_reporting_agent/reporting/template_document_exporter.py` | convert_docx_to_pdf | convert_docx_to_pdf | generated DOCX | PDF file | Uses LibreOffice headless conversion and reports conversion failure. | generate_reporting_export | libreoffice_binary, subprocess |
| CHAT-01 | Ask Aegis context construction | Application/UI | `case_view.py` | build_aegis_context | build_aegis_context | live case/workflow results | size-bounded cumulative context | Rebuilds case context per message so invalidated downstream data disappears naturally. | app.py chat panels | build_overview, build_timeline, chat summarizers |
| CHAT-02 | Ask Aegis backend endpoint | Backend | `soc_reporting_agent/backend/app.py` | api_ask | api_ask | question, agent, ticket_id | answer and follow-ups | Uses OpenAI-compatible generation when configured and a deterministic local answer otherwise. | dashboard ask UI | invoke_openai_text, build_local_agent_answer |
| DB-01 | Live reporting casework store | Backend | `soc_reporting_agent/backend/postgres_casework_store.py` | PostgresCaseworkStore | PostgresCaseworkStore | ticket/casework queries | PostgreSQL rows and audit records | Implements the store interface selected by store_factory. | backend/app.py | psycopg2 |
| DB-02 | Legacy/test casework store | Backend | `soc_reporting_agent/backend/casework_store.py` | CaseworkStore | CaseworkStore | ticket/casework queries | SQLite rows | Implements the same interface for tests/legacy use and seeds demo data. | one validation script | sqlite3 |
| DB-03 | Casework store selection | Backend | `soc_reporting_agent/backend/store_factory.py` | get_casework_store | get_casework_store | environment/Postgres availability | Postgres store or unavailable sentinel | Current live selection does not switch to SQLite silently. | backend/app.py | PostgresCaseworkStore, UnavailableCaseworkStore |
| KB-01 | Reporting RAG retrieval | Reporting | `soc_reporting_agent/reporting/rag_context.py` | retrieve_context | retrieve_context | report query and knowledge-base path | retrieved policy/procedure snippets | Queries ChromaDB when available and returns a safe empty context on failure. | reporting context/generation | ChromaDB |
| ERR-01 | LLM provider fallback | Backend | `soc_reporting_agent/backend/openai_client.py` | invoke_openai_text | invoke_openai_text | prompt/model configuration | text response or controlled error | Tries Responses then Chat Completions with compatibility retries. | Ask Aegis/reporting | OpenAI-compatible HTTP client |
| TEST-01 | Workflow re-run regression tests | Tests | `tests/test_stage_rerun.py` | test_* | test_* | temporary database and sample results | assertions | Verifies attempt counters, invalidation, approvals, and stale-write safety. | pytest | workflow_state_store |

## 8. Component Quick-Reference Sections

### Application and UI

**Purpose:** Run the two presentation surfaces, load incidents, render state, and dispatch analyst actions.  
**Main owner:** Kho Soong Yang / Shahrul Gunawan S/O Iqbal Suppiah  
**Main file:** `app.py`  
**Entry-point function:** `Streamlit module entry`  
**Other important files:** ui_components.py; case_view.py; dashboard/

| Function/Class | File | Purpose | Input | Output | Called By | Calls |
|---|---|---|---|---|---|---|
| See file map | app.py | Run the two presentation surfaces, load incidents, render state, and dispatch analyst actions. | NetWitness/API/state | Rendered UI and actions | workflow/UI | workflow and backend services |

**Ctrl + F search terms:** `Streamlit module entry`, `[FYP-FILE]`, `[FYP-EVALUATOR]`  
**Input:** NetWitness/API/state  
**Processing:** Run the two presentation surfaces, load incidents, render state, and dispatch analyst actions.  
**Output:** Rendered UI and actions  
**Called by:** the preceding workflow/UI component documented in the call chains.  
**Calls:** ui_components.py; case_view.py; dashboard/.  
**Next stage:** workflow and backend services.  
**Validation:** See `[FYP-VALIDATION]` in the listed files.  
**Error handling:** See `[FYP-ERROR]`; unhandled errors propagate to the route/stage boundary.  
**Fallback behaviour:** See `[FYP-FALLBACK]`; no fallback is claimed where none exists.

**Ten-second explanation:** This component starts in `app.py` at `Streamlit module entry`. It receives NetWitness/API/state, performs run the two presentation surfaces, load incidents, render state, and dispatch analyst actions., produces Rendered UI and actions, and hands control/data to workflow and backend services.

**Detailed explanation:** Entry is `Streamlit module entry`. Inputs are validated in the file's `[FYP-VALIDATION]` paths, processed through the functions above, and written/returned as Rendered UI and actions. The next consumer is workflow and backend services. Failure paths either produce the documented fallback/status or propagate to the caller.

**Demonstration steps**

Open: `app.py`  
Ctrl + F: `Streamlit module entry`  
Show: the entry point and its nearest `[FYP-INPUT]` / `[FYP-OUTPUT]` annotations  
Explain: purpose -> input -> processing -> output -> next stage  
Follow-up: ui_components.py; case_view.py; dashboard/
### Parsing and Normalisation

**Purpose:** Convert heterogeneous alerts into the canonical downstream schema.  
**Main owner:** Kho Soong Yang  
**Main file:** `soc_reporting_agent/services/parser_normaliser.py`  
**Entry-point function:** `process_alert / adapter main`  
**Other important files:** parser_context_guard.py; powershell_decoder.py

| Function/Class | File | Purpose | Input | Output | Called By | Calls |
|---|---|---|---|---|---|---|
| See file map | soc_reporting_agent/services/parser_normaliser.py | Convert heterogeneous alerts into the canonical downstream schema. | raw alert | processed/normalised artifacts | workflow/UI | Triage |

**Ctrl + F search terms:** `process_alert / adapter main`, `[FYP-FILE]`, `[FYP-EVALUATOR]`  
**Input:** raw alert  
**Processing:** Convert heterogeneous alerts into the canonical downstream schema.  
**Output:** processed/normalised artifacts  
**Called by:** the preceding workflow/UI component documented in the call chains.  
**Calls:** parser_context_guard.py; powershell_decoder.py.  
**Next stage:** Triage.  
**Validation:** See `[FYP-VALIDATION]` in the listed files.  
**Error handling:** See `[FYP-ERROR]`; unhandled errors propagate to the route/stage boundary.  
**Fallback behaviour:** See `[FYP-FALLBACK]`; no fallback is claimed where none exists.

**Ten-second explanation:** This component starts in `soc_reporting_agent/services/parser_normaliser.py` at `process_alert / adapter main`. It receives raw alert, performs convert heterogeneous alerts into the canonical downstream schema., produces processed/normalised artifacts, and hands control/data to Triage.

**Detailed explanation:** Entry is `process_alert / adapter main`. Inputs are validated in the file's `[FYP-VALIDATION]` paths, processed through the functions above, and written/returned as processed/normalised artifacts. The next consumer is Triage. Failure paths either produce the documented fallback/status or propagate to the caller.

**Demonstration steps**

Open: `soc_reporting_agent/services/parser_normaliser.py`  
Ctrl + F: `process_alert / adapter main`  
Show: the entry point and its nearest `[FYP-INPUT]` / `[FYP-OUTPUT]` annotations  
Explain: purpose -> input -> processing -> output -> next stage  
Follow-up: parser_context_guard.py; powershell_decoder.py
### Triage

**Purpose:** Classify severity/confidence, recommend actions, and construct tickets.  
**Main owner:** Shahrul Gunawan S/O Iqbal Suppiah  
**Main file:** `soc_triage_agent/soc_triage_agent.py`  
**Entry-point function:** `TriageAgent / soc_triage_chat_respond`  
**Other important files:** alert_triage.py; triage_verdict.py

| Function/Class | File | Purpose | Input | Output | Called By | Calls |
|---|---|---|---|---|---|---|
| analyze_alert | alert_triage.py | Deterministic severity/risk/confidence | normalised alert text/fields | Uses weighted regex indicators and corroboration rules; it is not an LLM path. | normalize_to_incident | validate_alert, _scan_text |
| TriageAgent / soc_triage_chat_respond | soc_triage_agent/soc_triage_agent.py | LLM-assisted SOC triage | incident, retrieved context, model config | Builds prompts, invokes the configured model, repairs JSON, and caches outputs. | soc_workflow.run_triage / app.chat_respond | build_llm, _extract_json, _repair_json |
| aggregate_verdict | triage_verdict.py | Final triage verdict aggregation | triage, TI, investigation, correlation signals | Combines rule/API/agent signals while retaining provenance. | case_view and reporting helpers | signal helpers |

**Ctrl + F search terms:** `TriageAgent / soc_triage_chat_respond`, `[FYP-FILE]`, `[FYP-EVALUATOR]`  
**Input:** parsed incident/context  
**Processing:** Classify severity/confidence, recommend actions, and construct tickets.  
**Output:** triage result/ticket  
**Called by:** the preceding workflow/UI component documented in the call chains.  
**Calls:** alert_triage.py; triage_verdict.py.  
**Next stage:** Approval/Threat Intel.  
**Validation:** See `[FYP-VALIDATION]` in the listed files.  
**Error handling:** See `[FYP-ERROR]`; unhandled errors propagate to the route/stage boundary.  
**Fallback behaviour:** See `[FYP-FALLBACK]`; no fallback is claimed where none exists.

**Ten-second explanation:** This component starts in `soc_triage_agent/soc_triage_agent.py` at `TriageAgent / soc_triage_chat_respond`. It receives parsed incident/context, performs classify severity/confidence, recommend actions, and construct tickets., produces triage result/ticket, and hands control/data to Approval/Threat Intel.

**Detailed explanation:** Entry is `TriageAgent / soc_triage_chat_respond`. Inputs are validated in the file's `[FYP-VALIDATION]` paths, processed through the functions above, and written/returned as triage result/ticket. The next consumer is Approval/Threat Intel. Failure paths either produce the documented fallback/status or propagate to the caller.

**Demonstration steps**

Open: `soc_triage_agent/soc_triage_agent.py`  
Ctrl + F: `TriageAgent / soc_triage_chat_respond`  
Show: the entry point and its nearest `[FYP-INPUT]` / `[FYP-OUTPUT]` annotations  
Explain: purpose -> input -> processing -> output -> next stage  
Follow-up: alert_triage.py; triage_verdict.py
### Threat Intelligence

**Purpose:** Validate IOCs, call reputation providers, and calculate enrichment risk.  
**Main owner:** Kho Soong Yang  
**Main file:** `threat_intel.py`  
**Entry-point function:** `run_threat_intel_for_dashboard`  
**Other important files:** APIRetrieval.py; nw_alerts.py; ioc_correlation.py

| Function/Class | File | Purpose | Input | Output | Called By | Calls |
|---|---|---|---|---|---|---|
| See file map | threat_intel.py | Validate IOCs, call reputation providers, and calculate enrichment risk. | triage/processed alert | enrichment result | workflow/UI | Investigation/Reporting |

**Ctrl + F search terms:** `run_threat_intel_for_dashboard`, `[FYP-FILE]`, `[FYP-EVALUATOR]`  
**Input:** triage/processed alert  
**Processing:** Validate IOCs, call reputation providers, and calculate enrichment risk.  
**Output:** enrichment result  
**Called by:** the preceding workflow/UI component documented in the call chains.  
**Calls:** APIRetrieval.py; nw_alerts.py; ioc_correlation.py.  
**Next stage:** Investigation/Reporting.  
**Validation:** See `[FYP-VALIDATION]` in the listed files.  
**Error handling:** See `[FYP-ERROR]`; unhandled errors propagate to the route/stage boundary.  
**Fallback behaviour:** See `[FYP-FALLBACK]`; no fallback is claimed where none exists.

**Ten-second explanation:** This component starts in `threat_intel.py` at `run_threat_intel_for_dashboard`. It receives triage/processed alert, performs validate iocs, call reputation providers, and calculate enrichment risk., produces enrichment result, and hands control/data to Investigation/Reporting.

**Detailed explanation:** Entry is `run_threat_intel_for_dashboard`. Inputs are validated in the file's `[FYP-VALIDATION]` paths, processed through the functions above, and written/returned as enrichment result. The next consumer is Investigation/Reporting. Failure paths either produce the documented fallback/status or propagate to the caller.

**Demonstration steps**

Open: `threat_intel.py`  
Ctrl + F: `run_threat_intel_for_dashboard`  
Show: the entry point and its nearest `[FYP-INPUT]` / `[FYP-OUTPUT]` annotations  
Explain: purpose -> input -> processing -> output -> next stage  
Follow-up: APIRetrieval.py; nw_alerts.py; ioc_correlation.py
### Investigation

**Purpose:** Correlate evidence, evaluate playbooks, build timeline/MITRE, and synthesise findings.  
**Main owner:** Teo Rui Xuan  
**Main file:** `soc_investigation_agent_revised/orchestrator.py`  
**Entry-point function:** `orchestrate_incident`  
**Other important files:** correlation_engine.py; mitre_mapper.py; vector_engine.py; policy_engine.py

| Function/Class | File | Purpose | Input | Output | Called By | Calls |
|---|---|---|---|---|---|---|
| CorrelationEngine.correlate_alert | soc_investigation_agent_revised/correlation_engine.py | Incident grouping correlation | new alert and active incidents | Scores indicator, tactic, and temporal proximity. | investigation main/sync | evaluate_tier1 |
| orchestrate_incident | soc_investigation_agent_revised/orchestrator.py | Investigation orchestration | triaged alert, policies, vector context | Runs policy selection, two-pass analysis, milestone checks, and final synthesis. | soc_workflow.run_investigation | get_llm, PolicyVectorIndex, generate_final_analysis |
| normalize_incident_input | soc_investigation_agent_revised/mitre_mapper.py | Investigation timeline construction | incident alerts/events | Normalises timestamps and event/entity descriptions for mapping. | map_incident_mitre_ttps | parse_event_timestamp, parse_user_host |
| map_incident_mitre_ttps | soc_investigation_agent_revised/mitre_mapper.py | MITRE ATT&CK mapping | normalised timeline | Uses LLM mapping when available and fallback_heuristic_mapper otherwise. | investigation workflow | generate_markdown_table, fallback_heuristic_mapper |
| PolicyVectorIndex / get_policy_manager | soc_investigation_agent_revised/orchestrator.py | Knowledge/policy vector retrieval | policy documents and query | Indexes policy sections in ChromaDB and retrieves relevant investigation guidance. | orchestrate_incident | ChromaDB, embeddings |

**Ctrl + F search terms:** `orchestrate_incident`, `[FYP-FILE]`, `[FYP-EVALUATOR]`  
**Input:** triage/TI/policies/vectors  
**Processing:** Correlate evidence, evaluate playbooks, build timeline/MITRE, and synthesise findings.  
**Output:** investigation result  
**Called by:** the preceding workflow/UI component documented in the call chains.  
**Calls:** correlation_engine.py; mitre_mapper.py; vector_engine.py; policy_engine.py.  
**Next stage:** Approval/Reporting.  
**Validation:** See `[FYP-VALIDATION]` in the listed files.  
**Error handling:** See `[FYP-ERROR]`; unhandled errors propagate to the route/stage boundary.  
**Fallback behaviour:** See `[FYP-FALLBACK]`; no fallback is claimed where none exists.

**Ten-second explanation:** This component starts in `soc_investigation_agent_revised/orchestrator.py` at `orchestrate_incident`. It receives triage/TI/policies/vectors, performs correlate evidence, evaluate playbooks, build timeline/mitre, and synthesise findings., produces investigation result, and hands control/data to Approval/Reporting.

**Detailed explanation:** Entry is `orchestrate_incident`. Inputs are validated in the file's `[FYP-VALIDATION]` paths, processed through the functions above, and written/returned as investigation result. The next consumer is Approval/Reporting. Failure paths either produce the documented fallback/status or propagate to the caller.

**Demonstration steps**

Open: `soc_investigation_agent_revised/orchestrator.py`  
Ctrl + F: `orchestrate_incident`  
Show: the entry point and its nearest `[FYP-INPUT]` / `[FYP-OUTPUT]` annotations  
Explain: purpose -> input -> processing -> output -> next stage  
Follow-up: correlation_engine.py; mitre_mapper.py; vector_engine.py; policy_engine.py
### Reporting

**Purpose:** Build context, generate/validate narratives, manage edits, and export reports.  
**Main owner:** Kho Soong Yang  
**Main file:** `soc_reporting_agent/agents/reporting_agent.py`  
**Entry-point function:** `ReportingAgent`  
**Other important files:** reporting/; report_templates/

| Function/Class | File | Purpose | Input | Output | Called By | Calls |
|---|---|---|---|---|---|---|
| build_context | soc_reporting_agent/reporting/context_builder.py | Reporting context construction | validated upstream JSON | Normalises assets, users, IOCs, evidence, timeline, gaps, and recommendations. | reporting agent | normalisation helpers |
| enhance_narrative | soc_reporting_agent/reporting/llm_narrative.py | LLM narrative generation with validation | report context and section | Builds prompts, invokes providers, checks unsupported claims, repairs, and falls back deterministically. | reporting agent | invoke_llm_with_retries, validate_llm_section_quality |
| report edit/confirm helpers | soc_reporting_agent/reporting/editable_reports.py | Editable report lifecycle | generated sections and analyst edits | Preserves report history and confirmation status. | backend report routes/app.py | manifest and file helpers |
| create_docx_from_blocks / generate_reporting_export | soc_reporting_agent/reporting/template_document_exporter.py | DOCX report export | approved report blocks/context | Creates branded Word output with tables, callouts, lists, and validation. | backend export routes/soc_workflow | python-docx helpers |
| convert_docx_to_pdf | soc_reporting_agent/reporting/template_document_exporter.py | PDF report export | generated DOCX | Uses LibreOffice headless conversion and reports conversion failure. | generate_reporting_export | libreoffice_binary, subprocess |
| retrieve_context | soc_reporting_agent/reporting/rag_context.py | Reporting RAG retrieval | report query and knowledge-base path | Queries ChromaDB when available and returns a safe empty context on failure. | reporting context/generation | ChromaDB |

**Ctrl + F search terms:** `ReportingAgent`, `[FYP-FILE]`, `[FYP-EVALUATOR]`  
**Input:** approved upstream results  
**Processing:** Build context, generate/validate narratives, manage edits, and export reports.  
**Output:** report sections/DOCX/PDF  
**Called by:** the preceding workflow/UI component documented in the call chains.  
**Calls:** reporting/; report_templates/.  
**Next stage:** Approval/Download.  
**Validation:** See `[FYP-VALIDATION]` in the listed files.  
**Error handling:** See `[FYP-ERROR]`; unhandled errors propagate to the route/stage boundary.  
**Fallback behaviour:** See `[FYP-FALLBACK]`; no fallback is claimed where none exists.

**Ten-second explanation:** This component starts in `soc_reporting_agent/agents/reporting_agent.py` at `ReportingAgent`. It receives approved upstream results, performs build context, generate/validate narratives, manage edits, and export reports., produces report sections/DOCX/PDF, and hands control/data to Approval/Download.

**Detailed explanation:** Entry is `ReportingAgent`. Inputs are validated in the file's `[FYP-VALIDATION]` paths, processed through the functions above, and written/returned as report sections/DOCX/PDF. The next consumer is Approval/Download. Failure paths either produce the documented fallback/status or propagate to the caller.

**Demonstration steps**

Open: `soc_reporting_agent/agents/reporting_agent.py`  
Ctrl + F: `ReportingAgent`  
Show: the entry point and its nearest `[FYP-INPUT]` / `[FYP-OUTPUT]` annotations  
Explain: purpose -> input -> processing -> output -> next stage  
Follow-up: reporting/; report_templates/
### Orchestration and State

**Purpose:** Enforce ordering, durable state, leases, approvals, handoffs, and reruns.  
**Main owner:** Shared  
**Main file:** `soc_workflow.py`  
**Entry-point function:** `run_stage_chain`  
**Other important files:** workflow_state_store.py; backend/stage_workflow.py; orchestration_service.py

| Function/Class | File | Purpose | Input | Output | Called By | Calls |
|---|---|---|---|---|---|---|
| See file map | soc_workflow.py | Enforce ordering, durable state, leases, approvals, handoffs, and reruns. | run id and stage state | transitions/artifacts | workflow/UI | Next stage/UI |

**Ctrl + F search terms:** `run_stage_chain`, `[FYP-FILE]`, `[FYP-EVALUATOR]`  
**Input:** run id and stage state  
**Processing:** Enforce ordering, durable state, leases, approvals, handoffs, and reruns.  
**Output:** transitions/artifacts  
**Called by:** the preceding workflow/UI component documented in the call chains.  
**Calls:** workflow_state_store.py; backend/stage_workflow.py; orchestration_service.py.  
**Next stage:** Next stage/UI.  
**Validation:** See `[FYP-VALIDATION]` in the listed files.  
**Error handling:** See `[FYP-ERROR]`; unhandled errors propagate to the route/stage boundary.  
**Fallback behaviour:** See `[FYP-FALLBACK]`; no fallback is claimed where none exists.

**Ten-second explanation:** This component starts in `soc_workflow.py` at `run_stage_chain`. It receives run id and stage state, performs enforce ordering, durable state, leases, approvals, handoffs, and reruns., produces transitions/artifacts, and hands control/data to Next stage/UI.

**Detailed explanation:** Entry is `run_stage_chain`. Inputs are validated in the file's `[FYP-VALIDATION]` paths, processed through the functions above, and written/returned as transitions/artifacts. The next consumer is Next stage/UI. Failure paths either produce the documented fallback/status or propagate to the caller.

**Demonstration steps**

Open: `soc_workflow.py`  
Ctrl + F: `run_stage_chain`  
Show: the entry point and its nearest `[FYP-INPUT]` / `[FYP-OUTPUT]` annotations  
Explain: purpose -> input -> processing -> output -> next stage  
Follow-up: workflow_state_store.py; backend/stage_workflow.py; orchestration_service.py
### Ask Aegis

**Purpose:** Ground chat answers in the selected case's current stage results.  
**Main owner:** Shared  
**Main file:** `case_view.py`  
**Entry-point function:** `build_aegis_context`  
**Other important files:** app.py; backend/app.py; openai_client.py

| Function/Class | File | Purpose | Input | Output | Called By | Calls |
|---|---|---|---|---|---|---|
| See file map | case_view.py | Ground chat answers in the selected case's current stage results. | question + current case | answer/followups | workflow/UI | Analyst |

**Ctrl + F search terms:** `build_aegis_context`, `[FYP-FILE]`, `[FYP-EVALUATOR]`  
**Input:** question + current case  
**Processing:** Ground chat answers in the selected case's current stage results.  
**Output:** answer/followups  
**Called by:** the preceding workflow/UI component documented in the call chains.  
**Calls:** app.py; backend/app.py; openai_client.py.  
**Next stage:** Analyst.  
**Validation:** See `[FYP-VALIDATION]` in the listed files.  
**Error handling:** See `[FYP-ERROR]`; unhandled errors propagate to the route/stage boundary.  
**Fallback behaviour:** See `[FYP-FALLBACK]`; no fallback is claimed where none exists.

**Ten-second explanation:** This component starts in `case_view.py` at `build_aegis_context`. It receives question + current case, performs ground chat answers in the selected case's current stage results., produces answer/followups, and hands control/data to Analyst.

**Detailed explanation:** Entry is `build_aegis_context`. Inputs are validated in the file's `[FYP-VALIDATION]` paths, processed through the functions above, and written/returned as answer/followups. The next consumer is Analyst. Failure paths either produce the documented fallback/status or propagate to the caller.

**Demonstration steps**

Open: `case_view.py`  
Ctrl + F: `build_aegis_context`  
Show: the entry point and its nearest `[FYP-INPUT]` / `[FYP-OUTPUT]` annotations  
Explain: purpose -> input -> processing -> output -> next stage  
Follow-up: app.py; backend/app.py; openai_client.py
### Database and Knowledge Base

**Purpose:** Persist workflow/casework and retrieve semantic context.  
**Main owner:** Shared  
**Main file:** `workflow_state_store.py`  
**Entry-point function:** `db_init / Chroma accessors`  
**Other important files:** casework stores; vector_engine.py; rag_context.py

| Function/Class | File | Purpose | Input | Output | Called By | Calls |
|---|---|---|---|---|---|---|
| See file map | workflow_state_store.py | Persist workflow/casework and retrieve semantic context. | records/documents/queries | rows/retrieved chunks | workflow/UI | All stages |

**Ctrl + F search terms:** `db_init / Chroma accessors`, `[FYP-FILE]`, `[FYP-EVALUATOR]`  
**Input:** records/documents/queries  
**Processing:** Persist workflow/casework and retrieve semantic context.  
**Output:** rows/retrieved chunks  
**Called by:** the preceding workflow/UI component documented in the call chains.  
**Calls:** casework stores; vector_engine.py; rag_context.py.  
**Next stage:** All stages.  
**Validation:** See `[FYP-VALIDATION]` in the listed files.  
**Error handling:** See `[FYP-ERROR]`; unhandled errors propagate to the route/stage boundary.  
**Fallback behaviour:** See `[FYP-FALLBACK]`; no fallback is claimed where none exists.

**Ten-second explanation:** This component starts in `workflow_state_store.py` at `db_init / Chroma accessors`. It receives records/documents/queries, performs persist workflow/casework and retrieve semantic context., produces rows/retrieved chunks, and hands control/data to All stages.

**Detailed explanation:** Entry is `db_init / Chroma accessors`. Inputs are validated in the file's `[FYP-VALIDATION]` paths, processed through the functions above, and written/returned as rows/retrieved chunks. The next consumer is All stages. Failure paths either produce the documented fallback/status or propagate to the caller.

**Demonstration steps**

Open: `workflow_state_store.py`  
Ctrl + F: `db_init / Chroma accessors`  
Show: the entry point and its nearest `[FYP-INPUT]` / `[FYP-OUTPUT]` annotations  
Explain: purpose -> input -> processing -> output -> next stage  
Follow-up: casework stores; vector_engine.py; rag_context.py
### Tests and Scripts

**Purpose:** Exercise stage contracts, reruns, exports, UI static assumptions, and fallbacks.  
**Main owner:** Shared  
**Main file:** `tests/`  
**Entry-point function:** `pytest test functions / script main`  
**Other important files:** soc_reporting_agent/tests; soc_reporting_agent/scripts

| Function/Class | File | Purpose | Input | Output | Called By | Calls |
|---|---|---|---|---|---|---|
| test_* | tests/test_stage_rerun.py | Workflow re-run regression tests | temporary database and sample results | Verifies attempt counters, invalidation, approvals, and stale-write safety. | pytest | workflow_state_store |

**Ctrl + F search terms:** `pytest test functions / script main`, `[FYP-FILE]`, `[FYP-EVALUATOR]`  
**Input:** fixtures/temp stores  
**Processing:** Exercise stage contracts, reruns, exports, UI static assumptions, and fallbacks.  
**Output:** assertions/results  
**Called by:** the preceding workflow/UI component documented in the call chains.  
**Calls:** soc_reporting_agent/tests; soc_reporting_agent/scripts.  
**Next stage:** CI/evaluation.  
**Validation:** See `[FYP-VALIDATION]` in the listed files.  
**Error handling:** See `[FYP-ERROR]`; unhandled errors propagate to the route/stage boundary.  
**Fallback behaviour:** See `[FYP-FALLBACK]`; no fallback is claimed where none exists.

**Ten-second explanation:** This component starts in `tests/` at `pytest test functions / script main`. It receives fixtures/temp stores, performs exercise stage contracts, reruns, exports, ui static assumptions, and fallbacks., produces assertions/results, and hands control/data to CI/evaluation.

**Detailed explanation:** Entry is `pytest test functions / script main`. Inputs are validated in the file's `[FYP-VALIDATION]` paths, processed through the functions above, and written/returned as assertions/results. The next consumer is CI/evaluation. Failure paths either produce the documented fallback/status or propagate to the caller.

**Demonstration steps**

Open: `tests/`  
Ctrl + F: `pytest test functions / script main`  
Show: the entry point and its nearest `[FYP-INPUT]` / `[FYP-OUTPUT]` annotations  
Explain: purpose -> input -> processing -> output -> next stage  
Follow-up: soc_reporting_agent/tests; soc_reporting_agent/scripts


## 9. Evaluator Question Index

| ID | Evaluator Question | Direct Answer | File Path | Function or Class | Ctrl + F Term | Follow-Up |
|---|---|---|---|---|---|---|
| Q-01 | Where does the application start? | The main UI starts by running app.py with Streamlit; the standalone API starts in soc_reporting_agent/backend/app.py. | app.py | module entry | streamlit run app.py | soc_reporting_agent/backend/app.py |
| Q-02 | Where is dashboard routing handled? | Streamlit routing is in app.py; the standalone browser SPA routes through state.route/readRoute/render in dashboard/app.js. | soc_reporting_agent/dashboard/app.js | readRoute / render | function readRoute | app.py page routing |
| Q-03 | Where are backend routes registered? | Flask @app.route handlers are defined in backend/app.py. | soc_reporting_agent/backend/app.py | api_* | @app.route | dashboard/app.js |
| Q-04 | Where is parsing executed? | soc_workflow.run_parsing delegates to the reporting parser service/adapter. | soc_workflow.py | run_parsing | def run_parsing | services/parser_normaliser.py |
| Q-05 | Where is field normalisation implemented? | The canonical mapping/timestamp/entity logic is in services/parser_normaliser.py. | soc_reporting_agent/services/parser_normaliser.py | normalisation helpers | [FYP-FILE] | parser_context_guard.py |
| Q-06 | Where is parser input validated? | parser_context_guard.py and validation helpers in parser_normaliser.py reject stale/mismatched inputs. | soc_reporting_agent/services/parser_context_guard.py | guard helpers | [FYP-VALIDATION] | run_parser_normalisation.py |
| Q-07 | Where is deterministic severity calculated? | alert_triage.analyze_alert sums weighted indicators and applies strong-indicator floors. | alert_triage.py | analyze_alert | Severity Calculation | triage_verdict.py |
| Q-08 | Where is confidence calculated? | alert_triage.analyze_alert sets true-positive confidence from strong or corroborating indicators; the LLM triage path also normalises its own confidence. | alert_triage.py | analyze_alert | True-Positive Confidence Heuristic | soc_triage_agent.py |
| Q-09 | Where is the risk score calculated? | The deterministic risk score is the deduplicated sum of matched indicator weights in analyze_alert. | alert_triage.py | analyze_alert | Risk Scoring | calculate_enrichment_risk |
| Q-10 | Where are IOCs extracted? | Threat-intel extraction is threat_intel.extract_iocs; non-NetWitness import normalisation also has alert_triage._extract_iocs. | threat_intel.py | extract_iocs | def extract_iocs | alert_triage.py |
| Q-11 | Where are private IPs filtered? | threat_intel.is_private_ip filters provider-bound IP candidates. | threat_intel.py | is_private_ip | def is_private_ip | extract_iocs |
| Q-12 | Where is IOC validation performed? | is_ip_address, is_private_ip, and is_external_domain validate provider inputs before enrichment. | threat_intel.py | validation helpers | def is_ip_address | extract_iocs |
| Q-13 | Where is VirusTotal called? | Three query_virustotal_* functions call the v3 file, IP, and domain endpoints. | threat_intel.py | query_virustotal_* | query_virustotal_file_hash | enrich_alert |
| Q-14 | Where is AbuseIPDB called? | query_abuseipdb calls /api/v2/check for public IPs. | threat_intel.py | query_abuseipdb | def query_abuseipdb | enrich_alert |
| Q-15 | Where is AlienVault OTX called? | query_otx_indicator calls the OTX general indicator endpoint. | threat_intel.py | query_otx_indicator | def query_otx_indicator | enrich_alert |
| Q-16 | Where is internal evidence correlated? | ioc_correlation.correlate_iocs checks the internal incident corpus; CorrelationEngine handles incident grouping. | ioc_correlation.py | correlate_iocs | def correlate_iocs | correlation_engine.py |
| Q-17 | Where does investigation start? | The durable wrapper is soc_workflow.run_investigation_stage; the investigation engine entry is orchestrator.orchestrate_incident. | soc_workflow.py | run_investigation_stage | def run_investigation_stage | orchestrator.py |
| Q-18 | Where is the incident timeline generated? | mitre_mapper.normalize_incident_input builds the ordered timeline; orchestrator.build_timeline_text renders investigation context. | soc_investigation_agent_revised/mitre_mapper.py | normalize_incident_input | def normalize_incident_input | orchestrator.py |
| Q-19 | Where is MITRE ATT&CK mapped? | map_incident_mitre_ttps uses the LLM and falls back to fallback_heuristic_mapper. | soc_investigation_agent_revised/mitre_mapper.py | map_incident_mitre_ttps | def map_incident_mitre_ttps | fallback_heuristic_mapper |
| Q-20 | Where is incident classification produced? | TriageAgent and alert_triage produce triage classification; the investigation final analysis may substantiate it later. | soc_triage_agent/soc_triage_agent.py | TriageAgent | class TriageAgent | final_verdict.py |
| Q-21 | Where is the final report generated? | ReportingAgent builds sections; template_document_exporter generates final document artifacts. | soc_reporting_agent/agents/reporting_agent.py | ReportingAgent | class ReportingAgent | template_document_exporter.py |
| Q-22 | Where is DOCX export implemented? | create_docx_from_blocks and generate_reporting_export create Word artifacts. | soc_reporting_agent/reporting/template_document_exporter.py | create_docx_from_blocks | def create_docx_from_blocks | generate_reporting_export |
| Q-23 | Where is PDF export implemented? | convert_docx_to_pdf resolves LibreOffice and converts the generated DOCX. | soc_reporting_agent/reporting/template_document_exporter.py | convert_docx_to_pdf | def convert_docx_to_pdf | libreoffice_binary |
| Q-24 | How does Ask Aegis get completed results? | case_view.build_aegis_context reads current stage results on every message and size-bounds them. | case_view.py | build_aegis_context | def build_aegis_context | app.py chat_respond |
| Q-25 | Where is knowledge retrieval performed? | Investigation uses PolicyVectorIndex; reporting uses rag_context.retrieve_context. | soc_reporting_agent/reporting/rag_context.py | retrieve_context | [FYP-RAG] | orchestrator.PolicyVectorIndex |
| Q-26 | Where is the next stage selected? | run_stage_chain dispatches durable Streamlit work; build_orchestration_decision selects ticket UI actions. | soc_workflow.py | run_stage_chain | State-Aware Stage Dispatcher | orchestration_service.py |
| Q-27 | Where is human approval stored? | workflow_state_store records atomic triage/investigation/reporting approvals and audit rows. | workflow_state_store.py | approve_triage / approve_investigation / commit_reporting_approval | [FYP-APPROVAL] | workflow_approvals |
| Q-28 | How are stages locked? | stage_workflow.can_run checks ordered prerequisites/approvals; workflow_state_store transitions also enforce expected statuses. | soc_reporting_agent/backend/stage_workflow.py | can_run | def can_run | workflow_state_store.py |
| Q-29 | Does approval automatically execute the next stage? | The Flask dashboard approval only unlocks and needs Run Next Step; the Streamlit durable handlers may spawn run_stage_chain immediately after approval. | soc_reporting_agent/dashboard/app.js | decision / runNext | Run Next Step | app.py approval handlers |
| Q-30 | What happens on an earlier-stage re-run? | workflow_state_store.rerun_stage clears affected downstream outputs, increments the attempt, and blocks later work until rerun in order. | workflow_state_store.py | rerun_stage | def rerun_stage | run_stage_chain |
| Q-31 | Where is workflow state stored? | The Streamlit path uses soc_pipeline.db through workflow_state_store; the standalone reporting backend uses the casework store/ticket fields. | workflow_state_store.py | get_state / db_init | def get_state | postgres_casework_store.py |
| Q-32 | Where is PostgreSQL used? | store_factory selects PostgresCaseworkStore for the live reporting backend. | soc_reporting_agent/backend/store_factory.py | get_casework_store | def get_casework_store | postgres_casework_store.py |
| Q-33 | Where is ChromaDB used? | app.py indexes incidents/stage buckets; investigation indexes policy/evidence; reporting retrieves KB context. | app.py | chroma_connect / pipeline_chroma_search | def chroma_connect | vector_engine.py / rag_context.py |
| Q-34 | Where is NetWitness integrated? | app.py and APIRetrieval.py authenticate and query incidents/alerts; nw_alerts.py merges digests. | APIRetrieval.py | fetch_all_alerts_and_endpoint_events | NetWitness Respond | app.py nw_fetch_incidents |
| Q-35 | Where are LLM calls made? | TriageAgent, investigation orchestrator/mapper, reporting llm_narrative, and backend openai_client contain model calls. | soc_reporting_agent/backend/openai_client.py | invoke_openai_text | [FYP-LLM] | llm_narrative.py |
| Q-36 | Where are prompts constructed? | TriageAgent methods, orchestrator chains, mitre_mapper prompt constants, and llm_narrative.build_section_prompt build prompts. | soc_reporting_agent/reporting/llm_narrative.py | build_section_prompt | def build_section_prompt | soc_triage_agent.py |
| Q-37 | Where is LLM output parsed/repaired? | Triage uses _extract_json/_repair_json; reporting normalises, validates, and repairs sections. | soc_triage_agent/soc_triage_agent.py | _extract_json / _repair_json | def _extract_json | llm_narrative.py |
| Q-38 | What happens if an LLM fails? | Provider fallbacks/retries are attempted, then deterministic narrative/local answers or explicit failure status are used. | soc_reporting_agent/reporting/llm_narrative.py | invoke_llm_with_retries / deterministic_narrative | [FYP-FALLBACK] | openai_client.py |
| Q-39 | What happens if an API fails? | Backend api_guard normalises errors; provider functions return controlled unavailable/error records; UI shows toast/modal feedback. | soc_reporting_agent/backend/error_handling.py | api_guard | def api_guard | dashboard/app.js api |
| Q-40 | Where are security controls? | Secret names come from environment/Streamlit secrets; Gitleaks/CI scan configs check commits; output escaping and path guards protect UI/files. | .github/workflows/secrets-scan.yml | Gitleaks workflow | [FYP-SECURITY] | app.js esc / reporting trusted paths |
| Q-41 | Where is logging implemented? | Workflow _log/progress helpers, investigation log functions, Flask activity records, and workflow_activity persist diagnostics/audit. | soc_workflow.py | _log | def _log | workflow_state_store.record_activity |
| Q-42 | Which tests protect re-run/locking? | test_stage_rerun.py and backend test_stage_workflow.py exercise invalidation and stage eligibility. | tests/test_stage_rerun.py | test_* | [FYP-FILE] | soc_reporting_agent/tests/test_stage_workflow.py |

## 10. Function Call Chains

1. **Application startup:** `streamlit run app.py -> app.py module bootstrap -> _bridge_cloud_secrets -> db_init/pipeline_db_init -> session-state setup -> page routing/render`
2. **Dashboard rendering:** `browser loads dashboard/index.html -> app.js startup -> refresh -> GET /api/dashboard -> render -> ticketPanel/agent workspace`
3. **Incident loading:** `maybe_auto_fetch/manual fetch -> app.nw_fetch_incidents -> NetWitness /rest/api/incidents -> nw_alerts enrichment -> db_upsert_incidents -> UI refresh`
4. **Parsing:** `Run Parsing/agent launch -> soc_workflow.run_parsing -> adapters/run_parser_normalisation.py -> services/parser_normaliser.py -> processed/normalised artifacts -> parsing_result`
5. **Triage:** `parsed incident -> soc_workflow.run_triage -> TriageAgent/soc_triage_chat_respond -> LLM JSON parse/repair -> ticket/triage_result -> Awaiting Approval`
6. **Threat intelligence:** `approved triage -> run_stage_chain -> resume_after_triage_approval -> threat_intel.run_threat_intel_for_dashboard -> provider queries -> threat_intel_result -> investigation Processing/Blocked`
7. **Investigation:** `run_stage_chain -> run_investigation_stage -> handoff_to_investigation -> run_investigation -> orchestrator.orchestrate_incident -> correlation/timeline/MITRE -> investigation_result -> Awaiting Approval`
8. **Reporting:** `approved investigation -> run_reporting_stage -> handoff_to_reporting -> adapters/run_reporting.py -> ReportingAgent -> report context/narrative/renderer -> reporting_result -> Awaiting Approval`
9. **Approval:** `analyst Approve -> app.py or POST /api/tickets/<id>/approve -> workflow_state_store/stage_workflow approval transition -> audit state -> next stage eligible`
10. **Proceeding to next stage:** `Flask dashboard approval -> next.allowed becomes true -> analyst clicks Run Next Step -> POST /api/tickets/<id>/run-next-step -> start_background_run`
11. **Re-running a stage:** `analyst Re-run -> workflow_state_store.rerun_stage or POST agent rerun -> attempt increment/guard -> run_stage_chain/background adapter`
12. **Invalidating downstream stages:** `rerun_stage(threat_intel|investigation) -> clear downstream *_result_json and timestamps -> set downstream Pending -> UI shows rerun/locked states`
13. **Locking stages:** `UI asks orchestration_service.build_orchestration_decision -> stage_workflow.can_run -> prerequisite_met/is_approved/output_valid -> allowed flag/reason -> disabled/enabled button`
14. **Asking Aegis:** `analyst submits question -> app.chat_respond or POST /api/ask -> build live case context -> invoke model/local fallback -> clean answer -> chat UI`
15. **Building chatbot context:** `case selection -> case_view.build_aegis_context -> load current workflow state -> build overview/timeline/evidence/report summaries -> cap text/lists -> prompt context`
16. **Retrieving knowledge:** `report/investigation query -> rag_context.retrieve_context or PolicyVectorIndex search -> ChromaDB collection query -> relevant documents -> prompt context`
17. **Calling the LLM:** `prompt builder -> invoke_openai_text / invoke_llm -> Responses API or Chat Completions/Ollama -> text/JSON response`
18. **Parsing LLM output:** `provider response -> _extract_json/_normalise_llm_output -> schema/quality checks -> structured result`
19. **Applying fallback logic:** `model/provider failure or invalid output -> compatibility retry/repair -> deterministic_narrative/fallback_heuristic_mapper/build_local_agent_answer -> status/fallback_used`
20. **Database reads:** `UI/route/workflow -> store.get_ticket or workflow_state_store.get_state -> SQL SELECT -> row normalisation -> caller response`
21. **Database writes:** `stage/approval/action -> transactional store method/_atomic_stage_transition -> INSERT/UPDATE + audit -> commit -> refreshed state`
22. **DOCX generation:** `approved/confirmed report -> generate_reporting_export -> markdown_to_report_blocks -> create_docx_from_blocks -> candidate/export manifest -> download route`
23. **PDF generation:** `DOCX generation -> libreoffice_binary -> convert_docx_to_pdf -> PDF artifact -> download route`
24. **Final export:** `dashboard download -> ticket/report export route -> cache/read approved artifact -> send_file/blob -> analyst download`
25. **Error handling:** `exception -> provider/local try-except or api_guard -> controlled status/error JSON/log -> toast/modal or blocked/failed state`
26. **Test execution:** `pytest tests/ soc_reporting_agent/tests -> fixture/temp DB setup -> target function/route -> assertions -> pass/fail report`

## 11. Inputs, Outputs and Data Handoffs

| Component | Input Source | Important Input Fields | Output Destination | Important Output Fields | Consumed By |
|---|---|---|---|---|---|
| NetWitness ingestion | NetWitness REST | incident/alert JSON, token | SQLite incidents + session state | id, title, severity, alerts | Parsing/UI |
| Parsing | raw incident/alert | timestamps, entities, metakeys, message | processed/normalised JSON and CSV | processed_alert, parser_summary, validation | Triage |
| Triage | processed alert + RAG/LLM config | incident facts, entities, IOCs | triage_result/ticket + workflow DB | classification, severity, confidence, actions | Approval/Threat Intel |
| Threat intelligence | triage/processed alert | hashes, IPs, domains, URLs | threat_intel_result + workflow DB | providers, risk_score, warnings | Investigation/Reporting |
| Investigation | triage alert, TI, policies, vectors | entities, timeline events, playbook steps | investigation_result + files/workflow DB | findings, evidence, MITRE, timeline, gaps | Approval/Reporting |
| Reporting | all upstream results | facts, evidence, timelines, limitations | reports/, manifests, reporting_result | sections, validation, export paths | Approval/Download/Ask Aegis |
| Ask Aegis | current case/workflow state | case summary and stage snippets | chat response/session state | answer, followups | Analyst |
| Frontend | Flask API JSON/blob | tickets, runs, approvals, exports | browser state/DOM/download | route, selected ticket/agent/report | Analyst actions |

## 12. Important Variables and Workflow States

| Variable or State | Meaning | Created In | Updated In | Read By | Possible Values |
|---|---|---|---|---|---|
| STAGES | Ordered five-stage ticket workflow | stage_workflow.py | static | workflow/orchestration/UI | parsing, triage, threat_intel, investigation, reporting |
| workflow_status | Overall durable run lifecycle | workflow_state_store.start_run | stage transitions/approval | app.py/run_stage_chain | Processing, Awaiting Action, Awaiting Approval, Complete, Failed, Rejected |
| approval_stage | Current human gate | workflow_state_store | approve/reject/rerun | UI and transition guards | triage, investigation, reporting, null |
| parsing_status | Parsing stage state | start_run | parsing runner | UI/workflow | Pending, Processing, Complete, Failed |
| triage_status | Triage stage state | start_run | triage runner/approval | UI/workflow | Pending, Processing, Awaiting Approval, Approved, Rejected, Failed |
| threat_intel_status | Threat intelligence stage state | start_run | TI runner/retry/rerun | UI/workflow | Pending, Processing, Complete, Complete with Warnings, Failed |
| investigation_status | Investigation stage state | start_run | investigation runner/approval | UI/workflow | Pending, Processing, Awaiting Approval, Approved, Rejected, Failed, Blocked |
| reporting_status | Reporting stage state | start_run | reporting runner/approval | UI/workflow | Pending, Processing, Awaiting Approval, Approved, Rejected, Failed, Blocked |
| *_attempt | Stage execution generation | start_run | rerun_stage | leases/approval audit/manifests | positive integer |
| worker_lease_expires_at | Stage worker TTL lease | claim_stage | renew/release lease | durable runners | ISO timestamp or null |
| state.agentRunGuards | Client optimistic run guard | dashboard/app.js | run/rerun responses | workspace renderers | per-ticket/agent guard objects |
| st.session_state.case_selected_stage | Selected Streamlit workspace tab | app.py selector | stage button click | case detail renderer | stage key |

## 13. API Reference

| API or Service | File | Function | Purpose | Input | Output | Failure Handling |
|---|---|---|---|---|---|---|
| RSA NetWitness Respond | app.py; APIRetrieval.py | nw_login / nw_fetch_incidents / fetch_* | Authenticate and retrieve incidents/alerts | host, credentials/token, pagination | incident/alert JSON | timeouts/auth errors return actionable status; bounded partial fetch |
| VirusTotal v3 | threat_intel.py | query_virustotal_file_hash/ip/domain | IOC reputation | validated hash/IP/domain + VT_API_KEY | normalised reputation | missing key/unavailable/HTTP exception recorded per IOC |
| AbuseIPDB v2 | threat_intel.py | query_abuseipdb | IP abuse reputation | public IP + ABUSEIPDB_API_KEY | confidence/reports | controlled unavailable/error result |
| AlienVault OTX | threat_intel.py | query_otx_indicator | IOC pulse/reputation | IOC type/value + OTX_API_KEY | general indicator result | controlled unavailable/error result |
| OpenAI-compatible Responses/Chat | backend/openai_client.py; llm_narrative.py | invoke_openai_text / _invoke_openai* | Triage/report/chat/investigation generation | prompt, model, API configuration | text/structured result | Responses -> Chat fallback, parameter retries, deterministic fallback where available |
| Ollama | reporting/llm_narrative.py | _invoke_ollama | Local report narrative generation | prompt/model/base URL | section text | retry/quality validation/deterministic narrative |
| Flask internal REST API | backend/app.py | 90 @app.route handlers | Dashboard/ticket/workflow/report integration | HTTP request | JSON/blob/file | api_guard normalisation and route-specific validation |

### Internal Flask route index

| Method | Route | Handler |
|---|---|---|
| GET | / | index |
| GET | /<path:path> | static_files |
| GET | /api/case | api_case |
| GET | /api/workflow-state | api_workflow_state |
| GET | /api/correlation | api_correlation |
| GET | /api/parsing | api_parsing |
| POST | /api/tickets/<ticket_id>/parsing/continue-available-data | api_parsing_continue_available_data |
| GET | /api/threat-intel | api_threat_intel |
| GET | /api/triage | api_triage |
| GET | /api/investigation | api_investigation |
| GET | /api/reporting | api_reporting |
| GET | /api/runs | api_runs |
| GET | /api/runs/<run_id> | api_run_status |
| POST | /api/runs/<run_id>/pause | api_run_pause |
| POST | /api/run/<agent>/pause | api_pause_latest_agent |
| POST | /api/tickets/<ticket_id>/pause-agent | api_pause_ticket_agent |
| POST | /api/run/<agent> | api_run_agent |
| POST | /api/tickets/<ticket_id>/agents/<agent>/run | api_ticket_agent_run |
| POST | /api/tickets/<ticket_id>/agents/<agent>/rerun | api_ticket_agent_rerun |
| GET | /api/tickets/<ticket_id>/agents/<agent>/runs | api_ticket_agent_runs |
| GET | /api/tickets/<ticket_id>/agents/status | api_ticket_agents_status |
| GET | /api/dashboard | api_dashboard |
| GET | /api/tickets/lookup | api_tickets_lookup |
| GET | /api/tickets | api_tickets |
| GET | /api/tickets/<ticket_id> | api_ticket_detail |
| POST | /api/tickets/from-alert/<alert_id> | api_ticket_from_alert |
| POST | /api/tickets/<ticket_id>/link-alert | api_ticket_link_alert |
| POST | /api/tickets/<ticket_id>/unlink-alert | api_ticket_unlink_alert |
| GET | /api/correlation/recommendations | api_correlation_recommendations |
| GET | /api/tickets/<ticket_id>/correlation-recommendations | api_ticket_correlation_recommendations |
| POST | /api/tickets/<ticket_id>/run-correlation | api_ticket_run_correlation |
| POST | /api/correlation/recommendations/<recommendation_id>/confirm | api_confirm_correlation_recommendation |
| POST | /api/correlation/recommendations/<recommendation_id>/reject | api_reject_correlation_recommendation |
| POST | /api/correlation/recommendations/<recommendation_id>/edit | api_edit_correlation_recommendation |
| POST | /api/tickets/<ticket_id>/move-alert | api_ticket_move_alert |
| POST | /api/tickets/<ticket_id>/split-alert | api_ticket_split_alert |
| POST | /api/tickets/<ticket_id>/merge | api_ticket_merge |
| POST | /api/tickets/<ticket_id>/run-next-step | api_ticket_run_next_step |
| POST | /api/tickets/<ticket_id>/approve | api_ticket_approve |
| POST | /api/tickets/<ticket_id>/reject | api_ticket_reject |
| POST | /api/tickets/<ticket_id>/request-more-evidence | api_ticket_more_evidence |
| POST | /api/tickets/<ticket_id>/investigation/evidence-gap-decision | api_ticket_evidence_gap_decision |
| POST | /api/tickets/<ticket_id>/confirm-soc-review | api_ticket_confirm_soc_review |
| POST | /api/tickets/<ticket_id>/assign | api_ticket_assign |
| GET | /api/tickets/<ticket_id>/activity | api_ticket_activity |
| GET | /api/tickets/<ticket_id>/reports | api_ticket_reports |
| GET | /api/tickets/<ticket_id>/reports/<report_key> | api_ticket_report_section |
| POST | /api/tickets/<ticket_id>/reports/<report_key>/draft | api_ticket_report_save_draft |
| POST | /api/tickets/<ticket_id>/reports/<report_key>/confirm | api_ticket_report_confirm |
| GET, POST | /api/tickets/<ticket_id>/reports/<report_key>/export/<file_type> | api_ticket_report_export |
| GET | /api/netwitness/alerts | api_netwitness_alerts |
| GET | /api/netwitness/alerts/<alert_id> | api_netwitness_alert |
| GET | /api/netwitness/history | api_netwitness_history |
| POST | /api/netwitness/sync | api_netwitness_sync |
| POST | /api/workflow/return-to-triage | api_workflow_return_to_triage |
| POST | /api/workflow/continue-limited | api_workflow_continue_limited |
| POST | /api/workflow/mark-insufficient | api_workflow_mark_insufficient |
| POST | /api/workflow/mark-and-continue | api_workflow_mark_and_continue |
| POST | /api/approval | api_approval |
| POST | /api/reset | api_reset |
| POST | /api/ask | api_ask |
| GET | /api/integrations/status | api_integrations_status |
| POST | /api/integrations/openai-test | api_openai_test |
| POST | /api/netwitness/test | api_netwitness_test |
| GET | /api/netwitness/incidents | api_netwitness_incidents |
| GET | /api/agent-output/<agent_key>/analyst-view | api_agent_output_analyst_view |
| POST | /api/agent-output/<agent_key>/save-edit | api_agent_output_save_edit |
| POST | /api/agent-output/<agent_key>/reset-edit | api_agent_output_reset_edit |
| POST | /api/agent-output/<agent_key>/confirm-review | api_agent_output_confirm_review |
| GET | /api/reports | api_reports_list |
| GET | /api/reports/manifest | api_reports_manifest |
| GET | /api/reports/section/<section_key> | api_reports_section |
| GET | /api/reports/<section_key> | api_reports_section_alias |
| GET | /api/reports/<section_key>/drafts | api_reports_section_drafts |
| POST | /api/reports/section/<section_key>/save | api_reports_section_save |
| POST | /api/reports/<section_key>/save-draft | api_reports_section_save_alias |
| POST | /api/reports/section/<section_key>/improve | api_reports_section_improve |
| POST | /api/reports/<section_key>/improve | api_reports_section_improve_alias |
| POST | /api/reports/section/<section_key>/confirm | api_reports_section_confirm |
| POST | /api/reports/<section_key>/confirm | api_reports_section_confirm_alias |
| POST | /api/reports/confirm | api_reports_confirm |
| POST | /api/reports/<section_key>/export/docx | api_reports_section_export_docx |
| POST | /api/reports/<section_key>/export/pdf | api_reports_section_export_pdf |
| GET | /api/reports/<section_key>/download/<file_type> | api_reports_section_download |
| POST | /api/reports/export/docx | api_reports_export_docx |
| POST | /api/reports/export/pdf | api_reports_export_pdf |
| GET | /api/reports/download/<file_type> | api_reports_download |
| GET | /api/tickets/<ticket_id>/exports/status | api_ticket_export_status |
| GET | /api/tickets/<ticket_id>/exports/<agent_key>/<file_type> | api_ticket_agent_template_export |
| GET | /api/tickets/<ticket_id>/exports/reporting/<report_key>/<file_type> | api_ticket_reporting_template_export |

## 14. Database and Knowledge-Base Reference

| Table or Collection | Purpose | Important Fields | Written By | Read By |
|---|---|---|---|---|
| workflow SQLite: incidents | Incident facts plus all durable stage status/result/attempt/lease columns | id, run_id, *_status, *_result_json, *_attempt | workflow_state_store | app.py, soc_workflow.py, case_view.py |
| workflow SQLite: fetch_log | NetWitness fetch audit | fetched_at, count | ingestion | refresh/statistics |
| workflow SQLite: workflow_approvals | Immutable approval decision history | incident_id, run_id, approval_stage, stage_attempt, decision | _atomic_stage_transition | approval history/export |
| workflow SQLite: global_execution_locks | Cross-run shared resource leases | lock_name, owner_id, expires_at | acquire/renew/release_global_lock | reporting/investigation workers |
| workflow SQLite: workflow_activity | Workflow audit trail | stage, action, actor, metadata_json | record_activity | case activity UI |
| workflow SQLite: report_edits | Analyst report draft state | incident_id, run_id, report_type, version, edited_blocks_json | upsert_report_edit | report editor/export |
| pipeline SQLite: eight PIPELINE_STAGES tables | Stage-bucket records and workflow run summaries | id, incident_id, stage, summary, raw_json | pipeline_insert | Data Pipeline UI |
| triage SQLite: ticket_counter/tickets/triage_cache | Triage numbering, tickets, and cached model results | UNC/ticket data, incident_fingerprint, result_json | TriageAgent | triage/chat |
| casework store: counters/alerts/tickets/ticket_alerts/incidents | Standalone dashboard case/ticket core | identifiers, stage result JSON, links, owners/status | CaseworkStore/PostgresCaseworkStore | Flask routes |
| casework store: correlation_recommendations/activity/agent_runs | Recommendation review, audit, and execution telemetry | recommendation/status, action, run progress/errors | casework store | Dashboard workflow panels |
| ChromaDB: soc_incidents | Top-level incident semantic search | document title/summary + metadata | app.chroma_sync | app.chroma_search |
| ChromaDB: pipeline_<stage> | Semantic mirror of each pipeline bucket | stage document and metadata | pipeline_chroma_insert | Data Pipeline search |
| ChromaDB: investigation policy/evidence collections | Policy/evidence retrieval for investigation | policy chunks, incident vectors | PolicyVectorIndex/vector_engine/sync_engine | orchestrator |
| ChromaDB: reporting knowledge collection | Reporting SOP/policy/playbook retrieval | knowledge documents/metadata | rag_context | report prompts |

## 15. LLM and Rule-Based Processing

| Agent or Component | Prompt Function | Model Call | Parser | Repair Logic | Fallback | Status Field |
|---|---|---|---|---|---|---|
| Deterministic alert triage | none | none | regex/table rules | n/a | generic action | classification/severity/is_true_positive |
| LLM TriageAgent | TriageAgent prompt methods | build_llm / _stream_or_invoke | _extract_json | _repair_json | cached/mock/error result | status/confidence |
| Investigation orchestration | get_chain_p1/get_chain_p2 prompts | get_llm | structured output models | milestone checks | deterministic/failed analysis paths | status |
| MITRE mapper | MITRE system prompt + timeline formatter | map_incident_mitre_ttps | IncidentMitreAnalysis | structured parser | fallback_heuristic_mapper | mapping_method/status |
| Reporting narrative | build_section_prompt | invoke_llm_with_retries | _normalise_llm_output | repair_llm_section | deterministic_narrative | generation_status/fallback_used |
| Ask Aegis | case/ticket context prompt | invoke_openai_text or soc_triage_chat_respond | clean_ask_answer_for_ui | alignment cleanup | build_local_agent_answer | success/status |

Rule-generated results (`alert_triage`, risk calculations, state gates), API results (TI/NetWitness), retrieved knowledge (ChromaDB), copied upstream facts, and LLM-generated narratives remain separately labelled in code and context.

## 16. Approval, Stage Locking and Re-run Logic

Expected approval flow: Stage completes -> Analyst reviews -> Approve -> state updates -> next stage available -> next stage idle -> analyst opens next stage -> Start Process -> execution.

Expected rerun flow: Earlier stage reruns -> output changes -> downstream outputs are cleared/outdated -> later stages blocked/pending -> affected stages rerun in order.

| Behaviour | File | Function | State Variable | UI Effect | Match Status |
|---|---|---|---|---|---|
| Triage approval (Streamlit) | workflow_state_store.py | approve_triage | triage_status / threat_intel_status | Triage Approved; TI Pending | Partially matches: state is unlocked, but app handlers can immediately spawn run_stage_chain |
| Investigation approval (Streamlit) | workflow_state_store.py | approve_investigation | investigation_status / reporting_status | Investigation Approved; Reporting Pending | Partially matches: approval itself does not run, but caller may spawn dispatcher |
| Reporting approval | workflow_state_store.py | commit_reporting_approval | reporting_status / workflow_status | Approved / Complete | Matches final human gate and pins exact report candidate |
| Ticket approval (Flask dashboard) | backend/app.py | api_ticket_approve | approval result/ticket fields | Run Next Step becomes enabled | Matches expected unlock-without-auto-run flow |
| Ticket run next | backend/app.py | api_ticket_run_next_step | orchestration decision / agent run | Selected agent starts | Matches explicit Start Process action |
| Threat Intel rerun | workflow_state_store.py | rerun_stage | attempt + downstream statuses/results | Investigation/Reporting Pending/cleared | Matches downstream invalidation |
| Investigation rerun | workflow_state_store.py | rerun_stage | attempt + reporting status/result | Reporting Pending/cleared | Matches downstream invalidation |
| Reporting rerun | workflow_state_store.py | rerun_stage | reporting attempt/result | New report attempt; prior approval audit preserved | Matches; no downstream stage exists |
| Evidence-gap feedback loop | soc_workflow.py | investigate_with_feedback | WORKFLOW_FEEDBACK_* | Automatic deeper triage/investigation pass | Deliberate exception: automatic rerun, no manual approval click |

## 17. Error Handling and Fallback Index

| Failure Scenario | File | Function | Detection | Fallback or Response | User Impact |
|---|---|---|---|---|---|
| NetWitness auth rejected/expired | APIRetrieval.py/app.py | authenticate_netwitness / nw_verify_token | HTTP status/body signature | refresh/login failure with actionable message | No downstream fetch |
| NetWitness fetch timeout | app.py | _bounded_get / nw_fetch_incidents | wall-clock deadline | return partial incidents plus diagnostic | UI remains responsive |
| TI provider key missing | threat_intel.py | query_* | environment/key presence | unavailable provider result | Other providers still run |
| TI provider HTTP failure | threat_intel.py | query_* | HTTP exception/status | error record/warning | Enrichment may complete with warnings |
| LLM Responses API incompatible | backend/openai_client.py | invoke_openai_text | provider exception | Chat Completions/parameter retry | Request may still succeed |
| LLM report output invalid | llm_narrative.py | validate/repair/invoke_llm_with_retries | quality/locked-fact checks | repair or deterministic narrative | No unsupported section accepted silently |
| ChromaDB unavailable | app.py/rag_context.py/vector_engine.py | connect/retrieve functions | import/connection/query exception | empty retrieval/disabled semantic feature | Core workflow continues |
| PostgreSQL unavailable | store_factory.py/error_handling.py | get_casework_store | connection/health failure | UnavailableCaseworkStore and clear 503-like error | No silent SQLite data fork |
| Stage already running/stale write | workflow_state_store.py | claim_stage/_guarded_update | lease/run/attempt mismatch | StageClaimError/StaleWriteError | Duplicate worker stops |
| Approval conflict | workflow_state_store.py | _atomic_stage_transition | expected state mismatch | ApprovalConflictError and refreshed state | Analyst sees conflict, no overwrite |
| Reporting export conversion failure | template_document_exporter.py | convert_docx_to_pdf | missing/failing LibreOffice | error recorded; DOCX may remain | PDF unavailable, source report preserved |
| Flask route exception | backend/error_handling.py | api_guard | caught exception type | normalised JSON/status | Dashboard toast/modal receives readable error |

## 18. Team Ownership and Question Routing

| Component | Main Owner | Backup Member | Main Files | Questions |
|---|---|---|---|---|
| Parsing and Normalisation | Kho Soong Yang | Editable: shared backup | services/parser_normaliser.py; parser_context_guard.py | Field mapping, validation, timestamps, PowerShell |
| Threat Intelligence | Kho Soong Yang | Editable: shared backup | threat_intel.py; APIRetrieval.py; nw_alerts.py | IOCs, providers, NetWitness |
| Reporting | Kho Soong Yang | Editable: shared backup | reporting/; report_templates/ | Context, narrative, review, DOCX/PDF |
| System integration/UI | Kho Soong Yang | Shahrul Gunawan S/O Iqbal Suppiah | app.py; ui_components.py; dashboard/ | Startup, pages, integration, UI |
| Triage | Shahrul Gunawan S/O Iqbal Suppiah | Editable: shared backup | soc_triage_agent/; alert_triage.py | Classification, severity, confidence, tickets |
| Dashboard contribution | Shahrul Gunawan S/O Iqbal Suppiah | Kho Soong Yang | app.py; dashboard/ | Workflow controls and presentation |
| Investigation | Teo Rui Xuan | Editable: shared backup | soc_investigation_agent_revised/ | Correlation, timeline, MITRE, playbooks |
| Orchestration/Chat/Testing/Documentation | Shared | Editable by team | soc_workflow.py; workflow_state_store.py; case_view.py; tests/ | Cross-stage flow, approvals, reruns, QA |

## 19. Ten-Second and Detailed Explanations

Use each component's Ten-second and Detailed explanation in Section 8. Every detailed explanation follows: entry point -> input -> validation -> processing -> output -> next function -> error/fallback.

## 20. Live Demonstration Checklist

### Preparation

- Open repository root and pin the quick-reference guide/index.
- Pin entry/orchestration/state/stage main files.
- Confirm no `.env` or live secret is visible.
- Keep Ctrl + Shift + F ready; use `[FYP-EVALUATOR]`.
- Preselect one known incident and verify database/API availability.

### During evaluation

- Start with the ten-second answer.
- Show one main function, not a wall of code.
- Trace one follow-up call only when asked.
- Distinguish Streamlit durable workflow from Flask dashboard workflow.
- State clearly when behaviour partially matches the intended design.

## 21. Quick Search-Term Index

Key labels: `[FYP-FILE]` `[FYP-FUNCTION]` `[FYP-CLASS]` `[FYP-ENTRY-POINT]` `[FYP-FLOW]` `[FYP-APPROVAL]` `[FYP-STAGE-LOCK]` `[FYP-RERUN]` `[FYP-STATE]` `[FYP-DATABASE]` `[FYP-API]` `[FYP-LLM]` `[FYP-RAG]` `[FYP-ERROR]` `[FYP-FALLBACK]` `[FYP-EXPORT]` `[FYP-EVALUATOR]`.

Full verified category and alphabetical index: `documentation/FYP_SEARCH_TERMS.md`.

## 22. File-by-File Code Map

| File Path | Language | File Purpose | Important Classes | Important Functions | Used By | Calls | Inputs | Outputs | Search Terms |
|---|---|---|---|---|---|---|---|---|---|
| `.github/workflows/code-scan.yml` | YAML | This file runs dependency and static-analysis security checks in GitHub Actions. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | consuming framework/tool | function arguments and upstream artifacts | return values and documented side effects | code-scan.yml, [FYP-FILE] |
| `.github/workflows/secrets-scan.yml` | YAML | This file runs Gitleaks secret detection in GitHub Actions. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | consuming framework/tool | function arguments and upstream artifacts | return values and documented side effects | secrets-scan.yml, [FYP-FILE] |
| `.gitleaks.toml` | TOML | This file configures repository secret-detection rules and allowlists. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | consuming framework/tool | maintainer-controlled configuration | runtime/framework settings | .gitleaks.toml, [FYP-FILE] |
| `.streamlit/config.toml` | TOML | This file configures Streamlit runtime configuration behaviour. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | consuming framework/tool | function arguments and upstream artifacts | return values and documented side effects | config.toml, [FYP-FILE] |
| `.streamlit/secrets.toml.example` | TOML template | This file documents the secret names expected by Streamlit without containing live credential values. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | consuming framework/tool | function arguments and upstream artifacts | return values and documented side effects | secrets.toml.example, [FYP-FILE] |
| `alert_triage.py` | Python | Deterministic, rule-based multi-source alert triage & normalization for the Triage stage (owner: Shahrul Gunawan S/O Iqbal Suppiah). | - | _is_private_ip, _resolve, validate_alert, _scan_text, analyze_alert, _extract_iocs, normalize_to_incident, format_analysis | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, hashlib, re, typing | parsed alert/incident and retrieved context | classification, severity, confidence, ticket, approval state | _is_private_ip, _resolve, validate_alert, _scan_text, analyze_alert, _extract_iocs |
| `APIRetrieval.py` | Python | Retrieves incident + alert telemetry from the RSA NetWitness Respond REST API (a self-hosted SIEM/SOAR product — the org's own NetWitness deployment, not a public/cloud service), with an on-disk export JSON fallback for offline/repeatable runs. This is the mod | - | _maybe_b64_decode, authenticate_netwitness, _is_expired_token_response, get_auth_token, refresh_token, fetch_incident_details, fetch_incident_via_fetch_api, fetch_alerts_via_fetch_api | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, base64, dotenv, json, os, requests, sys | incident IOCs and NetWitness/provider responses | validated enrichment/correlation records | _maybe_b64_decode, authenticate_netwitness, _is_expired_token_response, get_auth_token, refresh_token, fetch_incident_details |
| `app.py` | Python | Main Streamlit dashboard and orchestration UI for Aegis, the agentic SOC (Security Operations Center) automation platform for NetWitness alert handling. This is the single entry point evaluators run (`streamlit run app.py`) and the file that ties the three age | - | _openai_ef, _bridge_cloud_secrets, _maybe_reload_agent_modules, _workflow_store, _resolve_full_incident, _board_touch, _run_triage_workflow_with_ui, _workflow_worker | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | base64, case_view, collections, concurrent.futures, datetime, importlib, json | function arguments and upstream artifacts | return values and documented side effects | _openai_ef, _bridge_cloud_secrets, _maybe_reload_agent_modules, _workflow_store, _resolve_full_incident, _board_touch |
| `asset_criticality.py` | Python | Deterministic, code-only asset-criticality model. Classifies an incident's named host/user entity into a tier (critical_infrastructure production_server / workstation / unclassified) from naming-pattern regex, then derives a criticality-adjusted response urgen | - | classify_asset, _containment_checklist, assess_incident, format_assessment | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, re | parsed alert/incident and retrieved context | classification, severity, confidence, ticket, approval state | classify_asset, _containment_checklist, assess_incident, format_assessment |
| `case_view.py` | Python | single backend aggregator for the "My Workspace" case-details page AND the source of the Ask Aegis chatbot's cross-stage context. | - | _provenance, _json_or_empty, _slim_incident_from_state, load_incident_for_case_view, _unique_ips, _extract_agent_key_findings, _collect_alert_titles, build_overview | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, incident_map, json, re, soc_workflow, tactic_inference | function arguments and upstream artifacts | return values and documented side effects | _provenance, _json_or_empty, _slim_incident_from_state, load_incident_for_case_view, _unique_ips, _extract_agent_key_findings |
| `chroma_viewer.py` | Python | This module provides the Streamlit inspection interface for browsing ChromaDB collections and stored incident context. | - | _openai_ef, get_chroma_client, connect_chroma, get_collection, sqlite_load, sqlite_count | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | datetime, json, os, pathlib, re, sqlite3, streamlit | function arguments and upstream artifacts | return values and documented side effects | _openai_ef, get_chroma_client, connect_chroma, get_collection, sqlite_load, sqlite_count |
| `clearIncident.py` | Python | This module provides a command-line maintenance action for clearing an incident from the local workflow stores. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | glob, os, shutil, sqlite3 | function arguments and upstream artifacts | return values and documented side effects | clearIncident.py, [FYP-FILE] |
| `compliance_evidence.py` | Python | Deterministic mapping of one finalized incident's response onto SOC 2 Trust Services Criteria controls (mainly CC7 System Operations, plus CC2/CC4 and conditional A1/C1/P TSCs when the incident actually implicates them). Produces analyst-facing audit EVIDENCE | - | _disabled, _s, _first, _as_list, _triage_bits, _detection_summary, _ctrl, build_compliance_evidence | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, os, typing | function arguments and upstream artifacts | return values and documented side effects | _disabled, _s, _first, _as_list, _triage_bits, _detection_summary |
| `config.yaml` | YAML | This file records triage and retrieval configuration values mirrored by the application. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | consuming framework/tool | maintainer-controlled configuration | runtime/framework settings | config.yaml, [FYP-FILE] |
| `detection_engineering.py` | Python | This module derives detection-engineering recommendations from incident evidence for analyst review and reporting. | - | validate_sigma, to_elastic_eql, catalog_entry, _capability_by_tactic, assess_attack_coverage, format_coverage | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, json, re, sqlite3 | function arguments and upstream artifacts | return values and documented side effects | validate_sigma, to_elastic_eql, catalog_entry, _capability_by_tactic, assess_attack_coverage, format_coverage |
| `detection_rules.py` | Python | This module builds and formats detection rules from confirmed incident indicators and techniques. | - | _is_public_ip, _select_indicators, _severity_level, _yq, build_sigma_rule, sigma_to_yaml, to_splunk, to_sentinel_kql | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, ipaddress, re, uuid | function arguments and upstream artifacts | return values and documented side effects | _is_public_ip, _select_indicators, _severity_level, _yq, build_sigma_rule, sigma_to_yaml |
| `diamond_model.py` | Python | This module maps incident evidence into Diamond Model adversary, capability, infrastructure, and victim facets. | - | _is_public_ip, _focus_host, _extract, _infer_mitre_from_titles, _mitre, _asset_tier, build_diamond, _dot_escape | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, ipaddress, os, re, typing | function arguments and upstream artifacts | return values and documented side effects | _is_public_ip, _focus_host, _extract, _infer_mitre_from_titles, _mitre, _asset_tier |
| `endpoint_profile.py` | Python | This module summarises endpoint, user, and process evidence used during investigation. | - | _classify_entity_name, _looks_ipv6, _ip_tag, profile_entity, format_profile | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, collections, json, re, sqlite3, typing | function arguments and upstream artifacts | return values and documented side effects | _classify_entity_name, _looks_ipv6, _ip_tag, profile_entity, format_profile |
| `eval_harness.py` | Python | This module runs repeatable evaluation scenarios and records pipeline quality results. | - | _triage_result, _c_tactic, _c_verdict, _c_diamond, _c_sop, _c_sidecar, _selector, _c_playbook | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, json, os, pathlib, sys, tempfile | function arguments and upstream artifacts | return values and documented side effects | _triage_result, _c_tactic, _c_verdict, _c_diamond, _c_sop, _c_sidecar |
| `final_verdict.py` | Python | Deterministic, rule-based capstone that runs AFTER investigation and asks whether the investigation SUBSTANTIATED the triage-time risk prediction. Re-aggregates triage_verdict.py's verdict with investigation- side signals into a refined verdict, plus a disposi | - | _disabled, _s, _as_list, _triage_base, _ioc_evidence, _response_readiness, _diamond_signal, _mitre_confirmation | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, os, typing | parsed alert/incident and retrieved context | classification, severity, confidence, ticket, approval state | _disabled, _s, _as_list, _triage_base, _ioc_evidence, _response_readiness |
| `INC-Reset.py` | Python | This module provides a command-line reset action for the named incident and its persisted workflow state. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | glob, os, shutil, sqlite3 | function arguments and upstream artifacts | return values and documented side effects | INC-Reset.py, [FYP-FILE] |
| `incident_expansion.py` | Python | This module expands a seed incident with related alert and entity evidence. | LocalCorpusSource, NetWitnessEventsSource | _frontier, expand_incident_map | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, json, re, sqlite3, time, typing | function arguments and upstream artifacts | return values and documented side effects | LocalCorpusSource, NetWitnessEventsSource, _frontier, expand_incident_map |
| `incident_map.py` | Python | This module builds the analyst-facing incident relationship and evidence map. | _Graph | _is_private_ip, _classify_value, _walk_alert, build_incident_map, _dot_escape, to_dot, map_caption, summarize_map | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, ipaddress, re, typing | function arguments and upstream artifacts | return values and documented side effects | _Graph, _is_private_ip, _classify_value, _walk_alert, build_incident_map, _dot_escape |
| `ioc_correlation.py` | Python | [FYP-PROCESS] Evidence Correlation against the LOCAL incident corpus (not external threat intel — see threat_intel.py for that). Scores "have WE seen this IOC before, how severe, is it in an open case" — distinct from threat_intel.py's external reputation scor | - | _is_public_ip, _boundary, _extract_iocs, _seed_ids, _corpus_correlate, _subnet_prefix, _subnet_correlate, _case_correlate | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, ipaddress, os, pathlib, re, sqlite3, time | incident IOCs and NetWitness/provider responses | validated enrichment/correlation records | _is_public_ip, _boundary, _extract_iocs, _seed_ids, _corpus_correlate, _subnet_prefix |
| `mitigation_mapping.py` | Python | This module maps findings and MITRE techniques to containment and mitigation guidance. | ControlType, ControlLayer, ImplementationStatus, Effectiveness, SecurityControl | _c, build_mitigation_coverage, format_mitigation | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, dataclasses, enum, os | function arguments and upstream artifacts | return values and documented side effects | ControlType, ControlLayer, _c, build_mitigation_coverage, format_mitigation |
| `nw_alerts.py` | Python | Pure, stdlib-only helper functions for parsing NetWitness Respond "/rest/api/incidents/{id}/alerts" API responses and distilling their nested event/endpoint data into the incident's alertMeta structure. Extracted verbatim from app.py to slim the Streamlit mono | - | _extract_alert_items, _alerts_has_more, _alerts_error_hint, _distill_alerts, _merge_alert_digest, _alerts_fetch_warning | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__ | incident IOCs and NetWitness/provider responses | validated enrichment/correlation records | _extract_alert_items, _alerts_has_more, _alerts_error_hint, _distill_alerts, _merge_alert_digest, _alerts_fetch_warning |
| `osquery_investigation.py` | Python | This module constructs and interprets osquery-based endpoint investigation actions. | - | _is_public_ip, _focus, _infer_platform, _extract_iocs, _mitre, _platform_ok, _ioc_pivot_queries, _select_hunt | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, ipaddress, os, re, typing | function arguments and upstream artifacts | return values and documented side effects | _is_public_ip, _focus, _infer_platform, _extract_iocs, _mitre, _platform_ok |
| `report_editing.py` | Python | This module manages editable report drafts and analyst-supplied report changes. | - | _analyst_edits_dir, report_row_state, save_report_edit, discard_report_edit, export_report, reporting_data_json | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, json, pathlib, reporting.editable_reports, reporting_approval, soc_workflow | function arguments and upstream artifacts | return values and documented side effects | _analyst_edits_dir, report_row_state, save_report_edit, discard_report_edit, export_report, reporting_data_json |
| `reporting_approval.py` | Python | This module validates and records human approval decisions for reporting outputs. | ReportValidationError | _resolve_trusted_path, _canonical_manifest_bytes, _verify_candidate_manifest, approve_reporting_candidate, resolve_approved_report_file, build_export_all_zip | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, hashlib, json, pathlib, soc_workflow, typing, workflow_state_store | function arguments and upstream artifacts | return values and documented side effects | ReportValidationError, _resolve_trusted_path, _canonical_manifest_bytes, _verify_candidate_manifest, approve_reporting_candidate, resolve_approved_report_file |
| `reporting_sop.py` | Python | This module applies reporting standard-operating-procedure checks to generated content. | - | _disabled, _safe, _s, _as_list, _identity, _classification, _mitre, _pick_playbook | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, os, typing | function arguments and upstream artifacts | return values and documented side effects | _disabled, _safe, _s, _as_list, _identity, _classification |
| `requirements.txt` | Dependency configuration | This file declares the Python dependencies installed for this application component. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | consuming framework/tool | maintainer-controlled configuration | runtime/framework settings | requirements.txt, [FYP-FILE] |
| `skills_sidecar.py` | Python | This module builds deterministic supplemental analysis passed from investigation into reporting. | - | _disabled, _safe, _collect_diamond, _collect_verdict, _collect_correlation, _collect_asset, _collect_mitigation, _collect_sop | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, os, typing | function arguments and upstream artifacts | return values and documented side effects | _disabled, _safe, _collect_diamond, _collect_verdict, _collect_correlation, _collect_asset |
| `soc_investigation_agent_revised/bench_correlation.py` | Python | This module benchmarks investigation correlation behaviour against representative alert inputs. | - | clean_environment, copy_test_alerts, analyze_results, main_bench | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | asyncio, chromadb, correlation_engine, main, os, shutil, sync_engine | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | clean_environment, copy_test_alerts, analyze_results, main_bench |
| `soc_investigation_agent_revised/chroma_compat.py` | Python | Shared compatibility shim for safely opening persisted ChromaDB collections — the low-level plumbing underneath every knowledge-base RAG (Retrieval-Augmented Generation) vector store used by this agent (soc_alerts in vector_engine.py, soc_incidents in sync_eng | - | is_embedding_function_conflict, open_persistent_collection | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | typing | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | is_embedding_function_conflict, open_persistent_collection |
| `soc_investigation_agent_revised/correlation_config.py` | Python | Central tunable-constants module for the Two-Tier SOC Alert Correlation Engine (correlation_engine.py). Holds every weight, penalty, threshold and window size used by the correlation scoring formulas so they are not hardcoded/scattered across correlation_engin | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | - | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | correlation_config.py, [FYP-FILE] |
| `soc_investigation_agent_revised/correlation_engine.py` | Python | [FYP-PROCESS] THE evidence-correlation engine for the Investigation stage — decides whether an incoming alert belongs to an existing active incident (Tier 1: direct scoring against each active incident) or should be bridged with other unassigned alerts into a | CorrelationEngine | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | asyncio, correlation_config, ingest_pipeline, json, math, os, sync_engine | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | CorrelationEngine |
| `soc_investigation_agent_revised/ingest_pipeline.py` | Python | [FYP-PROCESS] Raw-log normalization layer — turns a single raw alert JSON file (as handed off by soc_workflow.py's handoff_to_investigation() into triaged_alerts/) into the standard in-memory alert dict shape ({"id", "document", "metadata", ["alerts"]}) used e | - | get_nested_value, extract_mapped_fields, parse_timestamp_to_epoch, scan_indicators, serialize_json_to_narrative, process_log_file | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | datetime, json, os, re, yaml | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | get_nested_value, extract_mapped_fields, parse_timestamp_to_epoch, scan_indicators, serialize_json_to_narrative, process_log_file |
| `soc_investigation_agent_revised/log_config.yaml` | YAML | This file maps investigation log-source fields into canonical entity and timestamp names. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | consuming framework/tool | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | log_config.yaml, [FYP-FILE] |
| `soc_investigation_agent_revised/main.py` | Python | This module runs the standalone investigation-agent command-line workflow and file-queue entry points. | - | start_background_sync, stop_background_sync, get_or_create_incident_folder, find_file_by_incident_id, write_markdown_report, select_playbook_automatically, extract_indicators_locally, generate_local_standalone_report | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | argparse, asyncio, collections, correlation_engine, dotenv, ingest_pipeline, json | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | start_background_sync, stop_background_sync, get_or_create_incident_folder, find_file_by_incident_id, write_markdown_report, select_playbook_automatically |
| `soc_investigation_agent_revised/mitre_mapper.py` | Python | MITRE ATT&CK TTP mapping engine. Takes a fully-correlated incident (whatever shape it arrives in — sync_engine.Incident, a plain dict, or a raw list of events) and produces a structured, chronologically-ordered mapping of the incident's observed behavior onto | TimelineEvent, MitreTTPMapping, IncidentMitreAnalysis | parse_event_timestamp, parse_user_host, normalize_incident_input, format_event_sequence, generate_markdown_table, fallback_heuristic_mapper, map_incident_mitre_ttps | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | dotenv, json, os, pydantic, re, typing | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | TimelineEvent, MitreTTPMapping, parse_event_timestamp, parse_user_host, normalize_incident_input, format_event_sequence |
| `soc_investigation_agent_revised/orchestrator.py` | Python | [FYP-ENTRY-POINT] The Investigation stage's own internal orchestrator — runs a playbook-driven, milestone-by-milestone investigation over a correlated alert group and produces the final structured incident analysis (attack narrative, business impact, MITRE map | Color, SuspiciousSeeds, MilestoneCheck, MilestoneExecution, BusinessImpactChecklist | log_info, log_success, log_warning, log_error, _structured_method, get_llm, classify_policies_for_investigation, get_policy_manager | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | chroma_compat, dotenv, ingest_pipeline, json, langchain_core.prompts, langchain_openai, mitre_mapper | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | Color, SuspiciousSeeds, log_info, log_success, log_warning, log_error |
| `soc_investigation_agent_revised/playbooks/phishing.yaml` | YAML | This file defines the phishing investigation playbook and required evidence steps. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | consuming framework/tool | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | phishing.yaml, [FYP-FILE] |
| `soc_investigation_agent_revised/playbooks/privilegeEscalation.yaml` | YAML | This file defines the privilege-escalation investigation playbook and required evidence steps. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | consuming framework/tool | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | privilegeEscalation.yaml, [FYP-FILE] |
| `soc_investigation_agent_revised/policy_engine.py` | Python | This module loads investigation playbooks and evaluates their required evidence milestones. | PolicyAuditRecord, PolicyManager | run_policy_compliance_rules, extract_actionable_rules | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | os, pydantic, re, time, typing | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | PolicyAuditRecord, PolicyManager, run_policy_compliance_rules, extract_actionable_rules |
| `soc_investigation_agent_revised/sync_engine.py` | Python | This module synchronises incident, vector, and investigation artifacts used by the investigation agent. | IncidentSeverity, IncidentStatus, IncidentMetadata, Incident, BaseIncidentRepository | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | abc, asyncio, chroma_compat, enum, json, logging, os | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | IncidentSeverity, IncidentStatus |
| `soc_investigation_agent_revised/vector_engine.py` | Python | RAG (Retrieval-Augmented Generation) knowledge-base engine for individual raw alerts. Owns the "soc_alerts" ChromaDB collection — the scratch-space vector store that every alert log is embedded into during ingestion, and that both the Two-Tier Correlation Engi | - | _open_collection, clear_collection, ingest_logs, query_semantic, get_alerts_by_temporal_window, has_technical_token_overlap, correlate_rrf | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | chromadb, chromadb.utils, dotenv, os | triage result, parsed alerts, policies, vector context | correlation, timeline, MITRE, investigation result | _open_collection, clear_collection, ingest_logs, query_semantic, get_alerts_by_temporal_window, has_technical_token_overlap |
| `soc_reporting_agent/adapters/common.py` | Python | Centralise the small pieces of plumbing (paths, JSON I/O, a generic subprocess runner, OpenAI env config, and a legacy incident normaliser) that every adapters/run_*.py entry point in this folder would otherwise duplicate. This module is imported, never execut | - | now_iso, read_json, write_json, latest_file, copy_if_exists, severity_from_score, _first_non_empty, _ioc_risk_score | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, dotenv, json, os, pathlib, shutil | function arguments and upstream artifacts | return values and documented side effects | now_iso, read_json, write_json, latest_file, copy_if_exists, severity_from_score |
| `soc_reporting_agent/adapters/export_documents.py` | Python | This module exports reporting results into analyst-downloadable document artifacts. | - | main | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, config, json, os, pathlib, reporting, sys | function arguments and upstream artifacts | return values and documented side effects | main |
| `soc_reporting_agent/adapters/run_parser_normalisation.py` | Python | This module provides the command-line adapter for the parsing and normalisation stage. | - | progress, selected_ticket_id, load_raw_alert_context, mirror_ticket_parser_outputs, main | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, adapters.common, json, os, pathlib, services.parser_context_guard, services.parser_normaliser | function arguments and upstream artifacts | return values and documented side effects | progress, selected_ticket_id, load_raw_alert_context, mirror_ticket_parser_outputs, main |
| `soc_reporting_agent/adapters/run_reporting.py` | Python | This module provides the command-line adapter for the reporting stage. | - | _copy_first_existing, _prepare_inputs, _clean, _first, _iso_to_ts, _is_new_enough, _run_succeeded, _normalise_status | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, adapters.common, backend.reporting_context_resolver, datetime, json, os, pathlib | function arguments and upstream artifacts | return values and documented side effects | _copy_first_existing, _prepare_inputs, _clean, _first, _iso_to_ts, _is_new_enough |
| `soc_reporting_agent/agents/__init__.py` | Python | This module implements reporting agent behaviour for init. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | - | function arguments and upstream artifacts | return values and documented side effects | __init__.py, [FYP-FILE] |
| `soc_reporting_agent/agents/reporting_agent.py` | Python | This module coordinates reporting context, narrative generation, validation, and output persistence. | - | parse_args, _status_word, _print_loaded_sources, _print_status, _add_postgres_display_fields, _friendly_report_name, main | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | argparse, config, pathlib, reporting.context_builder, reporting.export_context_enhancer, reporting.input_loader, reporting.output_writer | function arguments and upstream artifacts | return values and documented side effects | parse_args, _status_word, _print_loaded_sources, _print_status, _add_postgres_display_fields, _friendly_report_name |
| `soc_reporting_agent/backend/__init__.py` | Python | Package marker for the `backend` package (SOC Reporting subsystem Flask API/service layer: app.py, orchestration_service.py, stage_workflow.py, ticket_workflow.py, reporting_context_resolver.py, error_handling.py, export_cache.py, openai_client.py, casework_st | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | - | HTTP requests and persisted ticket/agent state | JSON/blob responses and persisted workflow updates | __init__.py, [FYP-FILE] |
| `soc_reporting_agent/backend/app.py` | Python | [FYP-ENTRY-POINT] Flask API backend for the SOC Reporting Agent dashboard (soc_reporting_agent subsystem). This is the single Flask application exposing the full REST API consumed by the vanilla JS/HTML dashboard (dashboard/app.js, dashboard/index.html): ticke | - | now_iso, safe_read_json, read_data, write_json, first_value, display_status, parse_possible_json_string, looks_like_raw_json_text | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend, backend.error_handling, backend.export_cache, backend.netwitness_client, backend.openai_client, backend.orchestration_service | HTTP requests and persisted ticket/agent state | JSON/blob responses and persisted workflow updates | now_iso, safe_read_json, read_data, write_json, first_value, display_status |
| `soc_reporting_agent/backend/casework_store.py` | Python | Legacy/local SQLite implementation of the Aegis "casework store" -- the persistence layer for SOC alerts, incident tickets, per-stage agent results (parsing / triage / threat-intel / investigation / reporting), analyst approvals, incident-grouping (correlation | CaseworkStore | now_iso, _json, _loads, _norm_status, _first, _severity_from_score, normalise_alert | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend, datetime, json, pathlib, services.parser_context_guard, sqlite3 | HTTP requests and persisted ticket/agent state | JSON/blob responses and persisted workflow updates | CaseworkStore, now_iso, _json, _loads, _norm_status, _first |
| `soc_reporting_agent/backend/error_handling.py` | Python | Shared error-handling utilities for the SOC Reporting subsystem's Flask API layer (backend/app.py). Provides a single, analyst-friendly JSON error contract so that every "/api/..." endpoint returns a consistent shape (success flag, error_code, severity, title, | ApiError | error_payload, api_error, safe_load_json_file, safe_write_json_file, api_guard, install_api_guards | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend.postgres_casework_store, flask, functools, json, pathlib, psycopg2 | HTTP requests and persisted ticket/agent state | JSON/blob responses and persisted workflow updates | ApiError, error_payload, api_error, safe_load_json_file, safe_write_json_file, api_guard |
| `soc_reporting_agent/backend/export_cache.py` | Python | Content-hash-based caching layer for generated report/agent export artifacts (Word .docx / PDF / JSON). Generating a Word document (and converting it to PDF) is comparatively expensive and involves an LLM call in the caller (see reporting/template_document_exp | - | utc_now, safe_filename, _json_default, stable_json, file_digest, calculate_source_hash, metadata_path, load_metadata | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, hashlib, json, pathlib, typing | HTTP requests and persisted ticket/agent state | JSON/blob responses and persisted workflow updates | utc_now, safe_filename, _json_default, stable_json, file_digest, calculate_source_hash |
| `soc_reporting_agent/backend/openai_client.py` | Python | Thin, centralised wrapper around the OpenAI Python SDK for this subsystem. Consolidates what used to be a mix of Chat Completions, LangChain ChatOpenAI, and Responses API call sites into one helper (invoke_openai_text) so model selection, parameter compatibili | - | is_placeholder_key, latest_model, supports_temperature, build_client, _extract_responses_text, invoke_openai_text, _strip_markdown_fences, _first_balanced_json_object | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, json, os, re, typing | HTTP requests and persisted ticket/agent state | JSON/blob responses and persisted workflow updates | is_placeholder_key, latest_model, supports_temperature, build_client, _extract_responses_text, invoke_openai_text |
| `soc_reporting_agent/backend/orchestration_service.py` | Python | Rule-based "Orchestration Agent" for the SOC Reporting subsystem. Given a persisted ticket record, it decides the single next safe workflow action (which agent stage should run next, or which human approval gate is blocking progress) without executing any agen | - | now_iso, norm, _result, _has_result, _first, _has_usable_investigation_content, is_investigation_usable_for_reporting, investigation_reporting_mode | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend, datetime, typing | HTTP requests and persisted ticket/agent state | JSON/blob responses and persisted workflow updates | now_iso, norm, _result, _has_result, _first, _has_usable_investigation_content |
| `soc_reporting_agent/backend/postgres_casework_store.py` | Python | PostgreSQL-backed implementation of the Aegis "casework store" -- THE operational database layer for SOC alerts, incident tickets, per-stage agent results, analyst approvals, incident-grouping (correlation) recommendations, activity/audit log entries, and agen | PostgresUnavailableError, PostgresCaseworkStore | postgres_required_payload, now_iso, _json, _loads, _norm_status, _first, _severity_from_score, _row_keys | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend, datetime, json, os, pathlib, psycopg2 | HTTP requests and persisted ticket/agent state | JSON/blob responses and persisted workflow updates | PostgresUnavailableError, PostgresCaseworkStore, postgres_required_payload, now_iso, _json, _loads |
| `soc_reporting_agent/backend/reporting_context_resolver.py` | Python | Bridges investigation/approval context between the Postgres-backed ticket record (the dashboard's source of truth) and the legacy filesystem-based inputs/outputs JSON contract that the standalone Reporting agent adapter (soc_reporting_agent/adapters/run_report | ResolvedContext | _norm, _read_json, _write_json, _unique_paths, _ticket_value, investigation_candidate_paths, approval_candidate_paths, is_approval_approved | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend, dataclasses, json, pathlib, shutil, typing | HTTP requests and persisted ticket/agent state | JSON/blob responses and persisted workflow updates | ResolvedContext, _norm, _read_json, _write_json, _unique_paths, _ticket_value |
| `soc_reporting_agent/backend/stage_workflow.py` | Python | Canonical five-stage ticket workflow state machine for the SOC Reporting subsystem. This is the single source of truth for "what stage is this ticket on, is that stage's output valid, has it been approved, and is it allowed to run/re-run right now". Every othe | - | now_iso, norm, canonical_agent, stage_definition, result_for, result_status, has_run, has_output_content | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, typing | HTTP requests and persisted ticket/agent state | JSON/blob responses and persisted workflow updates | now_iso, norm, canonical_agent, stage_definition, result_for, result_status |
| `soc_reporting_agent/backend/store_factory.py` | Python | [FYP-EVALUATOR] Single seam/factory that decides which casework store implementation the rest of the backend uses. This is the intended "swap the database implementation here" point referenced by backend/casework_store.py's module docstring ("PostgreSQL is the | UnavailableCaseworkStore | get_casework_store, postgres_unavailable_result | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend.postgres_casework_store, typing | HTTP requests and persisted ticket/agent state | JSON/blob responses and persisted workflow updates | UnavailableCaseworkStore, get_casework_store, postgres_unavailable_result |
| `soc_reporting_agent/backend/ticket_workflow.py` | Python | Ticket/case-level workflow presentation and decision-surfacing layer for the SOC Reporting subsystem. Where stage_workflow.py owns the raw per-stage state machine (locked/ready/running/pending_approval/approved rerun_required), this module turns that state int | - | norm, _result, _has_result, _has_usable_investigation_content, is_investigation_usable_for_reporting, investigation_reporting_mode, has_investigation_evidence_gap, evidence_gap_decision | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend, typing | HTTP requests and persisted ticket/agent state | JSON/blob responses and persisted workflow updates | norm, _result, _has_result, _has_usable_investigation_content, is_investigation_usable_for_reporting, investigation_reporting_mode |
| `soc_reporting_agent/config/__init__.py` | Python | This module implements reporting configuration behaviour for init. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | - | maintainer-controlled configuration | runtime/framework settings | __init__.py, [FYP-FILE] |
| `soc_reporting_agent/config/settings.py` | Python | This module loads reporting-service paths and runtime configuration from environment variables. | - | configured_llm_providers, selected_model_for_provider, selected_llm_model | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | os, pathlib | maintainer-controlled configuration | runtime/framework settings | configured_llm_providers, selected_model_for_provider, selected_llm_model |
| `soc_reporting_agent/dashboard/app.js` | JavaScript | Implements the app portion of the Aegis Frontend component. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | browser DOM, Fetch API, backend/app.py | DOM events and backend JSON/blob responses | DOM updates, HTTP requests, downloads | app.js, [FYP-FILE] |
| `soc_reporting_agent/dashboard/index.html` | HTML | Implements the index portion of the Aegis Frontend component. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | dashboard/app.js, dashboard/style.css | DOM events and backend JSON/blob responses | DOM updates, HTTP requests, downloads | index.html, [FYP-FILE] |
| `soc_reporting_agent/dashboard/style.css` | CSS | Implements the style portion of the Aegis Frontend component. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | dashboard/index.html, dashboard/app.js | DOM events and backend JSON/blob responses | DOM updates, HTTP requests, downloads | style.css, [FYP-FILE] |
| `soc_reporting_agent/report_templates/executive_summary_template.md.j2` | Jinja2 | Renders the concise management-facing executive-summary section. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | Jinja2, report_renderer.py | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | executive_summary_template.md.j2, [FYP-FILE] |
| `soc_reporting_agent/report_templates/incident_report_template.md.j2` | Jinja2 | Renders the complete final incident report from verified stage context. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | Jinja2, report_renderer.py | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | incident_report_template.md.j2, [FYP-FILE] |
| `soc_reporting_agent/report_templates/soc_analyst_review_template.md.j2` | Jinja2 | Renders the analyst-review section used to assess investigation evidence and gaps. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | Jinja2, report_renderer.py | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | soc_analyst_review_template.md.j2, [FYP-FILE] |
| `soc_reporting_agent/report_templates/soc_triage_review_template.md.j2` | Jinja2 | Renders the analyst-facing review of triage conclusions and confidence. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | Jinja2, report_renderer.py | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | soc_triage_review_template.md.j2, [FYP-FILE] |
| `soc_reporting_agent/report_templates/technical_findings_template.md.j2` | Jinja2 | Renders detailed technical evidence and investigation findings for SOC readers. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | Jinja2, report_renderer.py | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | technical_findings_template.md.j2, [FYP-FILE] |
| `soc_reporting_agent/reporting/__init__.py` | Python | This module implements report generation and export behaviour for init. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | - | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | __init__.py, [FYP-FILE] |
| `soc_reporting_agent/reporting/compact_renderer.py` | Python | This module renders compact analyst-readable report text from structured reporting data. | - | is_placeholder, count_placeholders, table_placeholder_ratio, filter_empty_columns, filter_empty_rows, compact_table, compact_table_summary, build_evidence_register_summary | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, re, typing | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | is_placeholder, count_placeholders, table_placeholder_ratio, filter_empty_columns, filter_empty_rows, compact_table |
| `soc_reporting_agent/reporting/context_builder.py` | Python | This module merges validated upstream stage outputs into the reporting context. | - | _first, _list, _get, _label, _normalise_asset, _normalise_user, _normalise_ioc, _normalise_evidence | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, re, typing | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | _first, _list, _get, _label, _normalise_asset, _normalise_user |
| `soc_reporting_agent/reporting/editable_reports.py` | Python | This module implements report generation and export behaviour for editable reports. | CandidateManifestConflictError | _aegis_logo_path, utc_now, markdown_to_plain_text, incident_report_dir, editable_dir, drafts_dir, confirmed_dir, exports_dir | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, hashlib, json, os, pathlib, re | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | CandidateManifestConflictError, _aegis_logo_path, utc_now, markdown_to_plain_text, incident_report_dir, editable_dir |
| `soc_reporting_agent/reporting/export_context_enhancer.py` | Python | This module implements report generation and export behaviour for export context enhancer. | - | is_unknown, first_present, as_list, get_path, _normalise_lookup, _quality, _bump, _parse_key_value | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, re, reporting.compact_renderer, reporting.llm_narrative, typing | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | is_unknown, first_present, as_list, get_path, _normalise_lookup, _quality |
| `soc_reporting_agent/reporting/input_loader.py` | Python | This module implements report generation and export behaviour for input loader. | ReportingInputError | load_json_file, load_reporting_inputs | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | json, pathlib, typing | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | ReportingInputError, load_json_file, load_reporting_inputs |
| `soc_reporting_agent/reporting/llm_narrative.py` | Python | Generates the free-text narrative sections of a SOC incident report (executive summary, technical analysis, business impact explanation, attack narrative, conclusion, analyst-friendly explanation, and the SOC analyst review checklist). All structured/factual f | - | selected_provider, selected_model, _cache_dir, _cache_file, _load_cached_narrative, _save_cached_narrative, _clean_sentence_join, _asset_story | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, config, json, os, pathlib, re, reporting.compact_renderer | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | selected_provider, selected_model, _cache_dir, _cache_file, _load_cached_narrative, _save_cached_narrative |
| `soc_reporting_agent/reporting/output_writer.py` | Python | This module implements report generation and export behaviour for output writer. | - | write_json, _display_fields, build_reporting_result, write_outputs, try_store_postgres | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | config, json, pathlib, reporting.status_display, typing | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | write_json, _display_fields, build_reporting_result, write_outputs, try_store_postgres |
| `soc_reporting_agent/reporting/rag_context.py` | Python | This module implements report generation and export behaviour for rag context. | - | _chunk_text, _score, _context_text, _is_ransomware_context, _required_files_for_context, direct_file_retrieval, chromadb_retrieval, _empty | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, config, pathlib, typing | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | _chunk_text, _score, _context_text, _is_ransomware_context, _required_files_for_context, direct_file_retrieval |
| `soc_reporting_agent/reporting/report_renderer.py` | Python | This module implements report generation and export behaviour for report renderer. | - | render_reports | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, config, jinja2, pathlib, reporting.editable_reports, reporting.structured_report, typing | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | render_reports |
| `soc_reporting_agent/reporting/report_validator.py` | Python | This module implements report generation and export behaviour for report validator. | ReportIntegrityError | validate_required_fields, build_missing_field_gaps, _validate_docx_integrity_and_tables, _validate_pdf_integrity, _validate_structured_content, validate_generated_report | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | pathlib, re, reporting.schema_normaliser, reporting.structured_report, typing | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | ReportIntegrityError, validate_required_fields, build_missing_field_gaps, _validate_docx_integrity_and_tables, _validate_pdf_integrity, _validate_structured_content |
| `soc_reporting_agent/reporting/schema_normaliser.py` | Python | This module implements report generation and export behaviour for schema normaliser. | - | get_nested, first_present, to_list, yes_no, classify_ioc, _extract_label, normalise_severity, normalise_confidence | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | re, typing | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | get_nested, first_present, to_list, yes_no, classify_ioc, _extract_label |
| `soc_reporting_agent/reporting/status_display.py` | Python | This module implements report generation and export behaviour for status display. | - | _meta, get_status_metadata, status_display, status_explanation, status_workflow_impact, calculate_llm_enhancement_score | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, typing | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | _meta, get_status_metadata, status_display, status_explanation, status_workflow_impact, calculate_llm_enhancement_score |
| `soc_reporting_agent/reporting/structured_report.py` | Python | This module defines and builds the structured report sections used for review and export. | - | clean_inline, _split_pipe_row, _is_separator_row, _is_table_row, _cells, _looks_like_plain_table_row, _plain_cells, parse_pipe_table | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, json, pathlib, re, typing | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | clean_inline, _split_pipe_row, _is_separator_row, _is_table_row, _cells, _looks_like_plain_table_row |
| `soc_reporting_agent/reporting/template_document_exporter.py` | Python | This module generates DOCX and PDF report artifacts from approved report content. | - | aegis_logo_path, utc_now, safe_filename, read_json, scrub_template_context, write_json, first_present, to_list | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend.export_cache, backend.openai_client, datetime, jinja2, json, os | approved upstream results and report edits | report sections, manifests, DOCX/PDF/TXT artifacts | aegis_logo_path, utc_now, safe_filename, read_json, scrub_template_context, write_json |
| `soc_reporting_agent/requirements.txt` | Dependency configuration | This file declares the Python dependencies installed for this application component. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | consuming framework/tool | maintainer-controlled configuration | runtime/framework settings | requirements.txt, [FYP-FILE] |
| `soc_reporting_agent/scripts/test_agent_rerun_ui_static.py` | Python | This module implements test and validation behaviour for test agent rerun ui static. | - | check | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | pathlib | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | check |
| `soc_reporting_agent/scripts/test_evidence_gap_branch_and_reporting_wrapper.py` | Python | This module implements test and validation behaviour for test evidence gap branch and reporting wrapper. | - | assert_true, make_ticket, test_decision_buttons_and_branches, test_reporting_wrapper_backfill, main | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, adapters, adapters.common, backend, backend.casework_store, json, pathlib | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | assert_true, make_ticket, test_decision_buttons_and_branches, test_reporting_wrapper_backfill, main |
| `soc_reporting_agent/scripts/test_export_cache.py` | Python | This module implements test and validation behaviour for test export cache. | - | write_json, seed_outputs, assert_true, main | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend.export_cache, json, pathlib, reporting.template_document_exporter, shutil, sys | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | write_json, seed_outputs, assert_true, main |
| `soc_reporting_agent/scripts/test_merged_report_context.py` | Python | This module implements test and validation behaviour for test merged report context. | - | write_json, reset_fixture, seed_inputs, test_merged_context, main | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, json, os, pathlib, shutil, sys | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | write_json, reset_fixture, seed_inputs, test_merged_context, main |
| `soc_reporting_agent/scripts/test_reporting_appendix_context.py` | Python | This module implements test and validation behaviour for test reporting appendix context. | - | write_json, reset_io, seed_inputs, test_context_and_templates, test_adapter_success_wrapper, test_failed_subprocess_not_completed, main | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, json, pathlib, shutil, subprocess, sys | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | write_json, reset_io, seed_inputs, test_context_and_templates, test_adapter_success_wrapper, test_failed_subprocess_not_completed |
| `soc_reporting_agent/scripts/test_reporting_context_resolution.py` | Python | This module implements test and validation behaviour for test reporting context resolution. | - | write_json, run_case, case_ticket_limited, case_outputs_completed_with_gaps, case_unknown_needs_more_data, case_failed_blocks, case_missing_blocks, main | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend, backend.reporting_context_resolver, json, pathlib, shutil, sys | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | write_json, run_case, case_ticket_limited, case_outputs_completed_with_gaps, case_unknown_needs_more_data, case_failed_blocks |
| `soc_reporting_agent/scripts/test_reporting_gate_with_limited_investigation.py` | Python | This module implements test and validation behaviour for test reporting gate with limited investigation. | - | ticket_with, run_case, main | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend, json, pathlib, sys | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | ticket_with, run_case, main |
| `soc_reporting_agent/scripts/test_reporting_workspace_ui_static.py` | Python | This module implements test and validation behaviour for test reporting workspace ui static. | - | check | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | pathlib | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | check |
| `soc_reporting_agent/scripts/test_structured_report_review_exports.py` | Python | This module implements test and validation behaviour for test structured report review exports. | - | write, main | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, json, pathlib, reporting.editable_reports, shutil, sys, zipfile | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | write, main |
| `soc_reporting_agent/services/__init__.py` | Python | This module backend services shared by dashboard adapters and Flask routes. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | - | function arguments and upstream artifacts | return values and documented side effects | __init__.py, [FYP-FILE] |
| `soc_reporting_agent/services/alert_indexing_service.py` | Python | This module indexes normalised alerts for retrieval and downstream case correlation. | - | _text, _lower, _unique, flatten_strings, parse_timestamp, extract_iocs, pick_value, _powershell_from_alert | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, json, re, typing | function arguments and upstream artifacts | return values and documented side effects | _text, _lower, _unique, flatten_strings, parse_timestamp, extract_iocs |
| `soc_reporting_agent/services/parser_context_guard.py` | Python | This module validates parser context and prevents cross-incident or stale input reuse. | - | _is_useful, _first, _clean, _normalise_for_compare, _dig, _as_dict, _raw_source, _title_clean | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, json, pathlib, re, shutil, typing | function arguments and upstream artifacts | return values and documented side effects | _is_useful, _first, _clean, _normalise_for_compare, _dig, _as_dict |
| `soc_reporting_agent/services/parser_normaliser.py` | Python | This is the CORE PARSING & NORMALISATION implementation for the whole Aegis platform's Stage 0 ("Parsing" / "NetWitness Alert Loading"). It takes a raw, messy RSA NetWitness incident/alert export (arbitrary, deeply-nested JSON with many possible field-name var | - | load_json_file, save_json_file, make_json_safe, prune_empty_and_null_values, is_useful, flatten_nested_values, dedupe, first | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, argparse, csv, datetime, ipaddress, json, pathlib | function arguments and upstream artifacts | return values and documented side effects | load_json_file, save_json_file, make_json_safe, prune_empty_and_null_values, is_useful, flatten_nested_values |
| `soc_reporting_agent/tests/test_compact_renderer.py` | Python | Unit tests for the report "compaction" helpers in reporting/compact_renderer.py (placeholder detection/counting, table column/row filtering, evidence/data-impact/chain-of-custody/approval summary builders) plus the plain-text/markdown table parsing entry point | TestIsPlaceholder, TestCountPlaceholders, TestFilterEmptyColumns, TestFilterEmptyRows, TestTablePlaceholderRatio | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, pytest, reporting.compact_renderer, reporting.structured_report | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | TestIsPlaceholder, TestCountPlaceholders |
| `soc_reporting_agent/tests/test_openai_client_json_extraction.py` | Python | Unit tests for backend/openai_client.py's extract_json_object() -- the tolerant parser that turns an LLM's raw text response back into a Python dict, even when the model wraps the JSON in a markdown code fence, surrounds it with prose, or emits malformed/non-o | - | test_extract_json_object_plain_object, test_extract_json_object_strips_markdown_fence, test_extract_json_object_with_surrounding_text, test_extract_json_object_balanced_nested_object_with_braces_in_string, test_extract_json_object_invalid_or_non_object_returns_empty_dict | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend.openai_client, json | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | test_extract_json_object_plain_object, test_extract_json_object_strips_markdown_fence, test_extract_json_object_with_surrounding_text, test_extract_json_object_balanced_nested_object_with_braces_in_string, test_extract_json_object_invalid_or_non_object_returns_empty_dict |
| `soc_reporting_agent/tests/test_stage_workflow.py` | Python | Unit tests for the five-stage pipeline state machine in backend/stage_workflow.py (Parsing -> Triage -> Threat Intelligence -> Investigation -> Reporting) and its dashboard presentation layer in backend/ticket_workflow.py, covering initial lock state, sequenti | StageWorkflowTests | finish, approve | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, backend, pathlib, sys, unittest | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | StageWorkflowTests, finish, approve |
| `soc_reporting_agent/tests/test_structured_report_tables.py` | Python | This module implements test and validation behaviour for test structured report tables. | - | test_plain_correlated_alerts_with_blank_lines_becomes_one_table, test_markdown_table_spacing_separator_and_long_cell, test_multiple_tables_and_non_table_paragraph_are_not_merged, test_template_exporter_uses_shared_plain_table_parser, test_legacy_paragraph_blocks_are_repaired_for_editable_confirmation, test_collapsed_header_separator_merges_with_following_table, test_complete_collapsed_priority_table_is_recovered, test_editable_confirmed_blocks_are_repaired_and_persisted | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, json, pytest, reporting.editable_reports, reporting.structured_report, reporting.template_document_exporter, zipfile | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | test_plain_correlated_alerts_with_blank_lines_becomes_one_table, test_markdown_table_spacing_separator_and_long_cell, test_multiple_tables_and_non_table_paragraph_are_not_merged, test_template_exporter_uses_shared_plain_table_parser, test_legacy_paragraph_blocks_are_repaired_for_editable_confirmation, test_collapsed_header_separator_merges_with_following_table |
| `soc_reporting_agent/utils/__init__.py` | Python | This module small stateless helpers shared across parsing and analysis services. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | - | function arguments and upstream artifacts | return values and documented side effects | __init__.py, [FYP-FILE] |
| `soc_reporting_agent/utils/powershell_decoder.py` | Python | This module detects and decodes encoded PowerShell command content during normalisation. | - | _dedupe, _normalise_b64, extract_encoded_command, decode_powershell_encoded_command, _is_public_ip, extract_iocs_from_powershell, analyse_decoded_powershell, analyse_powershell_command_lines | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, base64, binascii, ipaddress, re, typing, urllib.parse | function arguments and upstream artifacts | return values and documented side effects | _dedupe, _normalise_b64, extract_encoded_command, decode_powershell_encoded_command, _is_public_ip, extract_iocs_from_powershell |
| `soc_triage_agent/__init__.py` | Python | This module soc_triage_agent package ======================== The implementation lives in soc_triage_agent.py inside this folder. | - | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | soc_triage_agent | parsed alert/incident and retrieved context | classification, severity, confidence, ticket, approval state | __init__.py, [FYP-FILE] |
| `soc_triage_agent/soc_triage_agent.py` | Python | This module performs LLM-assisted SOC triage, tool routing, ticket construction, and chatbot responses. | OpenAILLMConfig, TriageAgent | _provider_supports_json_mode, build_llm, _normalize_mitre_tactic, _normalize_mitre_technique, _ticket_db_init, _increment_suffix, _next_unc, _store_ticket | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, dataclasses, datetime, hashlib, json, langchain_core.messages, langchain_core.output_parsers | parsed alert/incident and retrieved context | classification, severity, confidence, ticket, approval state | OpenAILLMConfig, TriageAgent, _provider_supports_json_mode, build_llm, _normalize_mitre_tactic, _normalize_mitre_technique |
| `soc_workflow.py` | Python | THE ORCHESTRATION ENGINE for the Aegis SOC platform. This is a headless, code-driven "puppet master" — not a UI file — that sequences the four pipeline stages (Parsing, Triage, Investigation, Reporting), persists every stage transition to the pipeline database | LeaseRenewer, ThreatIntelValidationError | build_post_investigation_record, _pl_con, pipeline_db_init, pipeline_insert, _log, _write_json, _read_json, _safe_ticket_id | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, argparse, datetime, hashlib, json, nw_alerts, os | incident/run identifiers and stage results/status | persisted transitions, approvals, handoff artifacts | LeaseRenewer, ThreatIntelValidationError, build_post_investigation_record, _pl_con, pipeline_db_init, pipeline_insert |
| `tactic_inference.py` | Python | This module infers MITRE ATT&CK tactics from incident evidence using deterministic mappings. | - | _as_str_list, _has_native_mitre, _keyword_scan, infer_tactics, augment_incident | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, os, typing | function arguments and upstream artifacts | return values and documented side effects | _as_str_list, _has_native_mitre, _keyword_scan, infer_tactics, augment_incident |
| `tests/test_ai_stage_summaries.py` | Python | Verifies the short "AI summary" orientation layer shown on each stage card in app.py's My Workspace — soc_workflow.py's limit_ai_summary_sentences() hard cap, generate_stage_ai_summary() (Threat Intelligence/Investigation/Reporting) and generate_parsing_ai_sum | - | _install_fake_openai, _sentence_count, test_sentence_guard_keeps_only_two_sentences_without_splitting_ips, test_sentence_guard_caps_a_single_run_on_at_eighty_words, test_every_stage_uses_ai_context_and_hard_caps_model_output, test_parsing_summary_is_capped_without_truncating_thinking, test_summary_backfill_merges_without_overwriting_native_stage_output, test_workspace_summary_card_never_falls_back_to_native_stage_summary | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, json, pathlib, pytest, re, soc_workflow, sys | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | _install_fake_openai, _sentence_count, test_sentence_guard_keeps_only_two_sentences_without_splitting_ips, test_sentence_guard_caps_a_single_run_on_at_eighty_words, test_every_stage_uses_ai_context_and_hard_caps_model_output, test_parsing_summary_is_capped_without_truncating_thinking |
| `tests/test_apiretrieval.py` | Python | Verifies APIRetrieval.py — the standalone NetWitness Respond REST API client used to pull an incident's raw details/alerts (the first step of the SOC pipeline, ahead of Parsing & Normalisation). Covers credential decoding, NetWitness session-token authenticati | TestAPIRetrievalHelperFunctions, TestAPIRetrievalAuthentication, TestAPIRetrievalFetchAutoReauth, TestAPIRetrievalComprehensivePayload | - | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | APIRetrieval, __future__, json, os, pytest, requests, unittest.mock | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | TestAPIRetrievalHelperFunctions, TestAPIRetrievalAuthentication |
| `tests/test_chroma_compat.py` | Python | Verifies soc_investigation_agent_revised/chroma_compat.py's open_persistent_collection() — the shared helper every persistent ChromaDB-backed knowledge store in the investigation agent (soc_alerts in vector_engine.py, soc_incidents in sync_engine.py, soc_polic | - | test_new_or_matching_collection_uses_requested_embedding, test_embedding_conflict_reopens_collection_without_override, test_unrelated_value_error_is_not_hidden, test_failed_compatible_reopen_preserves_original_error | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | pytest, soc_investigation_agent_revised.chroma_compat, unittest.mock | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | test_new_or_matching_collection_uses_requested_embedding, test_embedding_conflict_reopens_collection_without_override, test_unrelated_value_error_is_not_hidden, test_failed_compatible_reopen_preserves_original_error |
| `tests/test_investigation_stage.py` | Python | This module implements test and validation behaviour for test investigation stage. | - | _isolated_db, _triage_result, _incident, _run_to_investigation_processing, test_expired_unreassigned_worker_cannot_complete_stage, test_worker_id_alone_is_not_sufficient_after_lease_expiry, test_workflow_state_store_has_no_threading_import, test_soc_workflow_has_no_streamlit_import | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, ast, case_view, datetime, json, pathlib, pytest | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | _isolated_db, _triage_result, _incident, _run_to_investigation_processing, test_expired_unreassigned_worker_cannot_complete_stage, test_worker_id_alone_is_not_sufficient_after_lease_expiry |
| `tests/test_parsing_only.py` | Python | Verifies the "Parsing only" workflow boundary in soc_workflow.py — that running the Parsing stage in isolation (parsing_only=True) never triggers Triage, even when a mock Triage implementation is available. | - | _isolated_workflow, test_parsing_only_does_not_invoke_or_start_triage | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, pytest, soc_workflow, workflow_state_store | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | _isolated_workflow, test_parsing_only_does_not_invoke_or_start_triage |
| `tests/test_reporting_stage.py` | Python | This module implements test and validation behaviour for test reporting stage. | - | _isolated_db, _isolated_artifact_root, _run_awaiting_reporting_approval, _write_minimal_docx, _write_minimal_pdf, _build_candidate_set, _approve_via_state, test_run_scoped_handoff_includes_threat_intel_in_reporting_inputs | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, case_view, hashlib, json, pathlib, pytest, reporting_approval | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | _isolated_db, _isolated_artifact_root, _run_awaiting_reporting_approval, _write_minimal_docx, _write_minimal_pdf, _build_candidate_set |
| `tests/test_stage_rerun.py` | Python | Verifies workflow_state_store.rerun_stage() — the durable-DB operation behind the "Rerun this stage" button in app.py's My Workspace, for each of the three re-runnable downstream stages (Threat Intelligence, Investigation, Reporting). Confirms a rerun resets t | - | _isolated_db, _run_with_approved_triage, test_rerun_threat_intel_restarts_stage_and_invalidates_downstream, test_rerun_investigation_removes_old_approval_and_can_be_approved_again, test_rerun_reporting_reopens_a_completed_workflow, test_duplicate_rerun_is_rejected_while_stage_is_processing, test_fresh_rerun_cannot_replace_a_run_that_is_already_processing | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, json, pytest, workflow_state_store | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | _isolated_db, _run_with_approved_triage, test_rerun_threat_intel_restarts_stage_and_invalidates_downstream, test_rerun_investigation_removes_old_approval_and_can_be_approved_again, test_rerun_reporting_reopens_a_completed_workflow, test_duplicate_rerun_is_rejected_while_stage_is_processing |
| `tests/test_thinking_process_rendering.py` | Python | Verifies soc_workflow.render_agent_thinking_plain() — the plain- text "Thinking Process" panel shown per stage in app.py's My Workspace, which explains what each agent did/is doing without dumping the raw stage result or any hidden model chain-of-thought. | - | test_parsing_thinking_prefers_persisted_parser_narrative, test_triage_thinking_comes_from_trace, test_threat_intel_thinking_uses_persisted_risk_and_next_action, test_investigation_thinking_uses_sync_and_orchestrator_outputs, test_reporting_thinking_uses_persisted_manifest_and_quality_checks, test_completed_stage_thinking_is_timestamped_progress_not_result_dump, test_processing_stage_thinking_shows_live_heartbeat_and_progress_note | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, soc_workflow | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | test_parsing_thinking_prefers_persisted_parser_narrative, test_triage_thinking_comes_from_trace, test_threat_intel_thinking_uses_persisted_risk_and_next_action, test_investigation_thinking_uses_sync_and_orchestrator_outputs, test_reporting_thinking_uses_persisted_manifest_and_quality_checks, test_completed_stage_thinking_is_timestamped_progress_not_result_dump |
| `tests/test_threat_intel_workflow.py` | Python | This module implements test and validation behaviour for test threat intel workflow. | - | _isolated_db, _triage_result, _incident, _start_and_reach_triage_approval, _approve_triage, _save_raw_incident, _mock_all_ti_keys_absent, test_approve_triage_unlocks_but_does_not_start_threat_intel | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, ast, datetime, json, pathlib, pytest, soc_workflow | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | _isolated_db, _triage_result, _incident, _start_and_reach_triage_approval, _approve_triage, _save_raw_incident |
| `tests/test_vector_engine.py` | Python | Verifies the module-load-time collection-repair logic in soc_investigation_agent_revised/vector_engine.py's _open_collection() — the "soc_alerts" scratch ChromaDB collection used to hold alerts for the current investigation run. vector_engine.py builds this co | - | _load_vector_engine, test_legacy_embedding_function_conflict_recreates_scratch_collection, test_unrelated_chroma_value_error_is_not_destructively_repaired | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, importlib.util, pathlib, pytest, sys, types, unittest.mock | fixtures, sample artifacts, monkeypatched dependencies | assertions and pass/fail exit status | _load_vector_engine, test_legacy_embedding_function_conflict_recreates_scratch_collection, test_unrelated_chroma_value_error_is_not_destructively_repaired |
| `threat_hunting.py` | Python | This module creates threat-hunting pivots and queries from confirmed incident indicators. | - | score_hypothesis, detect_anomalies, ioc_sweep_plan, _entity_daily_counts, build_hunt_package, format_hunt | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, json, re, sqlite3, statistics | function arguments and upstream artifacts | return values and documented side effects | score_hypothesis, detect_anomalies, ioc_sweep_plan, _entity_daily_counts, build_hunt_package, format_hunt |
| `threat_intel.py` | Python | Implements the "Threat Intelligence Enrichment" workflow stage — stage 3 of 5 in the Aegis pipeline (Parsing & Normalisation -> Triage -> Threat Intelligence Enrichment -> Investigation -> Reporting). Looks up IOCs pulled off an already-triaged alert against e | - | load_processed_alert, save_json, flatten_value, save_csv, is_available, is_ip_address, is_private_ip, is_external_domain | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | csv, datetime, dotenv, json, os, pathlib, re | incident IOCs and NetWitness/provider responses | validated enrichment/correlation records | load_processed_alert, save_json, flatten_value, save_csv, is_available, is_ip_address |
| `triage_ticket_editing.py` | Python | Analyst "Open & Edit / Export Word / Export PDF" layer for the TRIAGE stage's ticket (the triage-side twin of report_editing.py). Pure data-transform / export plumbing — NO severity, confidence, risk or verdict calculation happens in this file; every rating fi | - | _txt, _joined, _threat_intel_blocks, build_ticket_blocks, _content_signature, ticket_row_state, save_report_edit, discard_report_edit | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, hashlib, json, pathlib, report_editing, reporting.editable_reports | parsed alert/incident and retrieved context | classification, severity, confidence, ticket, approval state | _txt, _joined, _threat_intel_blocks, build_ticket_blocks, _content_signature, ticket_row_state |
| `triage_verdict.py` | Python | Deterministic, rule-based capstone that rolls up every triage-side skill's individual signal (base severity, asset criticality, internal IOC correlation, external threat intel, investigation severity) into ONE prioritized incident verdict, with every contribut | - | _sev_to_level, _base_severity, _asset_signal, _ioc_signal, _investigation_signal, _ti_signal, aggregate_verdict, format_verdict | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, os, typing | parsed alert/incident and retrieved context | classification, severity, confidence, ticket, approval state | _sev_to_level, _base_severity, _asset_signal, _ioc_signal, _investigation_signal, _ti_signal |
| `ui_components.py` | Python | Shared "Aegis" design-system component library for the Streamlit SOC dashboard — pure Python functions that each return a raw HTML string (plus one shared <style> block) to be rendered via `st.markdown(html, unsafe_allow_html=True)`. Ported from the team's | - | _e, sev_class, page_title, pill, hero, stat_row, circular_pipeline, stepper | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, html, math, typing, urllib.parse | function arguments and upstream artifacts | return values and documented side effects | _e, sev_class, page_title, pill, hero, stat_row |
| `velociraptor_investigation.py` | Python | This module constructs Velociraptor endpoint evidence requests and normalises returned findings. | - | _is_public_ip, _focus, _infer_platform, _extract_iocs, _mitre, _select_hunt, _ioc_pivot_vql, _collector_command | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, ipaddress, os, re, typing | function arguments and upstream artifacts | return values and documented side effects | _is_public_ip, _focus, _infer_platform, _extract_iocs, _mitre, _select_hunt |
| `workflow_state_store.py` | Python | THE single source of truth for per-incident workflow state. Owns the SQLite `incidents` table schema (every stage-status / approval-status rerun-attempt / worker-lease column lives here) plus the permanent `workflow_approvals` (analyst decision audit trail), ` | WorkflowAlreadyRunningError, StaleWriteError, ApprovalConflictError, StageClaimError, GlobalLockBusyError | db_connect, _autocommit_connect, _tx, db_init, _ensure_workflow_columns, _ensure_workflow_approvals_attempt_columns, _ensure_workflow_approvals_metadata_column, start_run | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime, json, pathlib, sqlite3, uuid | incident/run identifiers and stage results/status | persisted transitions, approvals, handoff artifacts | WorkflowAlreadyRunningError, StaleWriteError, db_connect, _autocommit_connect, _tx, db_init |
| `workflow_validation.py` | Python | This module validates cross-stage workflow state, required outputs, and transition readiness. | ParsingValidationError | validate_parsing_result, mandatory_triage_approval, build_thinking_process | framework, entry point, imports, or tests; see inline [FYP-USED-BY] | __future__, datetime | incident/run identifiers and stage results/status | persisted transitions, approvals, handoff artifacts | ParsingValidationError, validate_parsing_result, mandatory_triage_approval, build_thinking_process |

## 23. Intended Behaviour Versus Actual Implementation

| Feature | Intended Behaviour | Actual Implementation | Match Status | File and Function |
|---|---|---|---|---|
| Ordered five-stage workflow | Parsing -> Triage -> TI -> Investigation -> Reporting | stage_workflow.STAGES implements that exact order | Matches | stage_workflow.py:STAGES |
| Approval unlocks but does not execute | Next stage stays idle until Start Process | Flask dashboard matches; Streamlit handlers may spawn run_stage_chain after approval | Partially matches | dashboard/app.js decision/runNext; app.py approval handlers |
| Downstream invalidation | Earlier rerun marks later outputs outdated/blocked | rerun_stage clears later result/status fields and increments the restarted attempt | Matches | workflow_state_store.py:rerun_stage |
| Threat Intel approval | Explicit human approval after TI | Flask STAGES has threat_intel_approval; durable Streamlit workflow proceeds from TI to Investigation without a separate TI approval function | Partially matches | stage_workflow.py:STAGES; soc_workflow.py:run_stage_chain |
| Investigation evidence-gap loop | Analyst-controlled rework | investigate_with_feedback can automatically rerun within configured threshold/pass limits | Partially matches | soc_workflow.py:investigate_with_feedback |
| PostgreSQL live store | Backend initialises/uses PostgreSQL schema | store_factory selects PostgresCaseworkStore; referenced database/postgres_schema.sql is not present in this repository snapshot, so initialise=True depends on an external/missing file | Partially matches | postgres_casework_store.py:init_db |
| SQLite fallback for live backend | Use SQLite if Postgres is unavailable | Current factory returns an unavailable sentinel; it does not silently switch to CaseworkStore | Does not match if SQLite fallback was intended | store_factory.py:get_casework_store |
| Report finalisation | Only approved report set is downloadable as authoritative | commit_reporting_approval pins exact attempt/result in immutable approval metadata | Matches | workflow_state_store.py:commit_reporting_approval |
| Ask Aegis rerun invalidation | Chat stops using stale downstream results | Context is rebuilt from live state each message, so cleared results disappear without a separate cache invalidator | Matches | case_view.py:build_aegis_context |
| CLI full end-to-end run | CLI timeout flags drive all later stages | soc_workflow.main accepts investigation/reporting timeout flags but comments/code mark them reserved; durable post-triage stages are UI/state driven | Partially matches | soc_workflow.py:main |

## 24. Test Code Reference

| Test File | Tested Component | Test Functions | Setup | Expected Result | Related Application Code |
|---|---|---|---|---|---|
| `soc_reporting_agent/scripts/test_agent_rerun_ui_static.py` | Tests | check | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | see imports and inline [FYP-CALLS] |
| `soc_reporting_agent/scripts/test_evidence_gap_branch_and_reporting_wrapper.py` | Tests | test_decision_buttons_and_branches, test_reporting_wrapper_backfill | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, adapters, adapters.common, backend, backend.casework_store, shutil |
| `soc_reporting_agent/scripts/test_export_cache.py` | Tests | assert_true, main, seed_outputs, write_json | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, backend.export_cache, reporting.template_document_exporter, shutil, time |
| `soc_reporting_agent/scripts/test_merged_report_context.py` | Tests | test_merged_context | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, shutil |
| `soc_reporting_agent/scripts/test_reporting_appendix_context.py` | Tests | test_adapter_success_wrapper, test_context_and_templates, test_failed_subprocess_not_completed | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, shutil, subprocess |
| `soc_reporting_agent/scripts/test_reporting_context_resolution.py` | Tests | case_failed_blocks, case_missing_blocks, case_outputs_completed_with_gaps, case_ticket_limited, case_unknown_needs_more_data, main, run_case, write_json | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, backend, backend.reporting_context_resolver, shutil |
| `soc_reporting_agent/scripts/test_reporting_gate_with_limited_investigation.py` | Tests | main, run_case, ticket_with | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, backend |
| `soc_reporting_agent/scripts/test_reporting_workspace_ui_static.py` | Tests | check | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | see imports and inline [FYP-CALLS] |
| `soc_reporting_agent/scripts/test_structured_report_review_exports.py` | Tests | main, write | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, reporting.editable_reports, shutil, zipfile |
| `soc_reporting_agent/tests/test_compact_renderer.py` | Tests | test_all_placeholders, test_approved_report_summary, test_compact_markdown_separator_becomes_table_block, test_compact_when_many_placeholders, test_containment_summary, test_deep_nesting, test_empty_dict, test_empty_inputs, test_empty_list_is_placeholder, test_empty_note_when_no_evidence, test_empty_note_when_real_custody_exists, test_empty_string_is_placeholder | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, reporting.compact_renderer, reporting.structured_report |
| `soc_reporting_agent/tests/test_openai_client_json_extraction.py` | Tests | test_extract_json_object_balanced_nested_object_with_braces_in_string, test_extract_json_object_invalid_or_non_object_returns_empty_dict, test_extract_json_object_plain_object, test_extract_json_object_strips_markdown_fence, test_extract_json_object_with_surrounding_text | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, backend.openai_client |
| `soc_reporting_agent/tests/test_stage_workflow.py` | Tests | test_backend_start_and_approval_guards, test_initial_state_and_buttons, test_latest_rerun_reason_replaces_earlier_reason, test_only_immediate_next_stage_unlocks_after_required_approval, test_reporting_approval_completes_workflow, test_rerun_invalidates_approval_and_all_existing_downstream_outputs | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, backend |
| `soc_reporting_agent/tests/test_structured_report_tables.py` | Tests | test_cached_blocks_are_repaired_before_reuse, test_collapsed_header_separator_merges_with_following_table, test_complete_collapsed_priority_table_is_recovered, test_docx_contains_native_table_and_no_pipe_paragraphs, test_double_backslash_before_pipe_is_one_literal_backslash_then_separator, test_editable_confirmed_blocks_are_repaired_and_persisted, test_escaped_pipe_stays_inside_one_cell, test_legacy_paragraph_blocks_are_repaired_for_editable_confirmation, test_malformed_row_produces_warning_not_silent_column_change, test_markdown_table_spacing_separator_and_long_cell, test_multiple_tables_and_non_table_paragraph_are_not_merged, test_ordinary_prose_with_colon_and_pipe_is_not_converted | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, reporting.editable_reports, reporting.structured_report, reporting.template_document_exporter, zipfile |
| `tests/test_ai_stage_summaries.py` | Tests | test_every_stage_uses_ai_context_and_hard_caps_model_output, test_parsing_summary_is_capped_without_truncating_thinking, test_sentence_guard_caps_a_single_run_on_at_eighty_words, test_sentence_guard_keeps_only_two_sentences_without_splitting_ips, test_successful_downstream_stages_generate_ai_summary_before_persisting, test_summary_backfill_merges_without_overwriting_native_stage_output, test_workspace_summary_card_never_falls_back_to_native_stage_summary | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, re, soc_workflow, types, workflow_state_store |
| `tests/test_apiretrieval.py` | Tests | test_authenticate_netwitness_failure, test_authenticate_netwitness_success, test_fetch_alerts_via_fetch_api_auto_reauthenticates, test_fetch_incident_via_fetch_api_auto_reauthenticates, test_get_auth_token_with_username_and_password, test_get_comprehensive_incident_payload_disk_file, test_get_comprehensive_incident_payload_live_fetch, test_is_expired_token_response, test_maybe_b64_decode_plain_and_encoded | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | APIRetrieval, __future__, requests, unittest.mock |
| `tests/test_chroma_compat.py` | Tests | test_embedding_conflict_reopens_collection_without_override, test_failed_compatible_reopen_preserves_original_error, test_new_or_matching_collection_uses_requested_embedding, test_unrelated_value_error_is_not_hidden | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | soc_investigation_agent_revised.chroma_compat, unittest.mock |
| `tests/test_investigation_stage.py` | Tests | test_build_case_view_never_calls_investigation_stage_functions, test_build_case_view_rejects_stale_run_id, test_data_availability_distinguishes_empty_success_from_unavailable, test_duplicate_investigation_approval_still_rejected_with_new_schema, test_entity_graph_never_labels_cooccurrence_as_connected_to, test_expired_unreassigned_worker_cannot_complete_stage, test_get_approval_history_returns_all_decisions_in_order, test_global_lock_busy_error_is_a_stage_claim_error, test_host_and_user_never_derived_from_narrative_prose, test_investigation_stage_failure_blocks_reporting, test_investigation_stage_passes_persisted_threat_intel_explicitly, test_ioc_correlation_failure_produces_warning_without_failing_workflow | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, ast, case_view, datetime, soc_workflow, workflow_state_store |
| `tests/test_parsing_only.py` | Tests | test_parsing_only_does_not_invoke_or_start_triage | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, soc_workflow, workflow_state_store |
| `tests/test_reporting_stage.py` | Tests | test_approve_reporting_candidate_end_to_end, test_approve_reporting_candidate_fails_on_identity_mismatch, test_approve_reporting_candidate_fails_when_docx_tampered_after_generation, test_commit_reporting_approval_fails_when_attempt_changed, test_commit_reporting_approval_fails_when_reporting_result_json_changed, test_commit_reporting_approval_is_only_approve_reporting_workflow_status_setter, test_complete_stage_expected_stage_attempt_rejects_stale_worker, test_final_incident_report_export_populates_section_exports, test_finalize_candidate_manifest_idempotent_on_identical_repeat_call, test_finalize_candidate_manifest_refuses_to_overwrite_differing_content, test_get_approved_reporting_sets_reads_durable_metadata_survives_rerun_clear, test_rejected_reporting_attempt_can_be_rerun | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, case_view, hashlib, reporting_approval, soc_workflow, workflow_state_store |
| `tests/test_stage_rerun.py` | Tests | test_duplicate_rerun_is_rejected_while_stage_is_processing, test_fresh_rerun_cannot_replace_a_run_that_is_already_processing, test_rerun_investigation_removes_old_approval_and_can_be_approved_again, test_rerun_reporting_reopens_a_completed_workflow, test_rerun_threat_intel_restarts_stage_and_invalidates_downstream | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, workflow_state_store |
| `tests/test_thinking_process_rendering.py` | Tests | test_completed_stage_thinking_is_timestamped_progress_not_result_dump, test_investigation_thinking_uses_sync_and_orchestrator_outputs, test_parsing_thinking_prefers_persisted_parser_narrative, test_processing_stage_thinking_shows_live_heartbeat_and_progress_note, test_reporting_thinking_uses_persisted_manifest_and_quality_checks, test_threat_intel_thinking_uses_persisted_risk_and_next_action, test_triage_thinking_comes_from_trace | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, soc_workflow |
| `tests/test_threat_intel_workflow.py` | Tests | test_abuseipdb_ip_lookup_returns_reputation, test_agent_source_reflects_repo_path, test_api_keys_read_at_call_time_not_import_time, test_approval_functions_do_not_start_threads_or_import_soc_workflow, test_approval_history_rows_cannot_be_duplicated, test_approve_triage_unlocks_but_does_not_start_threat_intel, test_begin_stage_refuses_a_stage_that_was_never_unlocked, test_begin_stage_starts_reporting_after_investigation_approval, test_begin_stage_starts_threat_intel_exactly_once_after_approval, test_duplicate_approve_click_raises_conflict, test_expired_lease_permits_new_worker_to_resume, test_external_domain_extracted | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, ast, datetime, soc_workflow, threat_intel, unittest.mock, workflow_state_store |
| `tests/test_vector_engine.py` | Tests | test_legacy_embedding_function_conflict_recreates_scratch_collection, test_unrelated_chroma_value_error_is_not_destructively_repaired | temporary files/DBs, sample JSON, monkeypatches, or static source reads | assertions pass and the protected contract remains stable | __future__, importlib.util, types, unittest.mock |

## 25. Full Code Documentation Coverage

Canonical documented files: **131**. Excluded duplicate files: **7**. Undocumented canonical files: **0**. Files requiring manual source review: **0**.

The complete per-file checklist, exclusion reasons, validation commands, and Git diff confirmation are in `documentation/FYP_CODE_DOCUMENTATION_COVERAGE.md`.
