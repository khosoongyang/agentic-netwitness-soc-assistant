# FYP Code Documentation Coverage Report

**Repository name:** agentic-netwitness-soc-assistant (Aegis)  
**Branch:** merge-final-evaluation  
**Scan date:** 2026-07-30  
**Source extensions scanned:** .bat, .c, .cmd, .cpp, .cs, .css, .go, .h, .html, .ini, .ipynb, .j2, .java, .js, .jsx, .php, .ps1, .py, .rb, .rs, .scss, .sh, .sql, .svelte, .toml, .ts, .tsx, .vue, .yaml, .yml; Dockerfile; Makefile; requirements.txt; secrets.toml.example  
**Directories scanned:** repository root, `.github/`, `.streamlit/`, `soc_triage_agent/`, `soc_investigation_agent_revised/`, `soc_reporting_agent/`, `tests/`  
**Directories excluded:** `.git/` (VCS internals), virtual environments and dependency directories (third party), `__pycache__/` (generated), `outputs/`, `testdata/`, `triaged_alerts/`, `incident_reports/` (generated fixtures/results), `chroma_db/`, `chroma_storage/` (generated vector stores), `documentation/` (deliverables, not source)

## Coverage summary

- Total tracked repository files at recovery scan: **295**
- Total source/configuration files found: **138**
- Canonical relevant first-party files documented: **131**
- Excluded superseded duplicates: **7**
- Undocumented canonical files: **0**
- Files requiring manual source-documentation review: **0**
- Binary working-tree files requiring origin review: **2** (`soc_db/soc_incidents.db`, `soc_db/soc_pipeline.db`)

**All relevant first-party source-code files were reviewed.**

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

## Complete per-file checklist

| File Path | Language | Component | Status | Evidence/Reason |
|---|---|---|---|---|
| `.github/workflows/code-scan.yml` | YAML | CI security | Documented | Verified [FYP-FILE] overview and definition annotations |
| `.github/workflows/secrets-scan.yml` | YAML | CI security | Documented | Verified [FYP-FILE] overview and definition annotations |
| `.gitleaks.toml` | TOML | Configuration | Documented | Verified [FYP-FILE] overview and definition annotations |
| `.streamlit/config.toml` | TOML | Streamlit configuration | Documented | Verified [FYP-FILE] overview and definition annotations |
| `.streamlit/secrets.toml.example` | TOML template | Streamlit configuration | Documented | Verified [FYP-FILE] overview and definition annotations |
| `alert_triage.py` | Python | Triage | Documented | Verified [FYP-FILE] overview and definition annotations |
| `APIRetrieval.py` | Python | Threat intelligence | Documented | Verified [FYP-FILE] overview and definition annotations |
| `app.py` | Python | Application/UI | Documented | Verified [FYP-FILE] overview and definition annotations |
| `asset_criticality.py` | Python | Triage | Documented | Verified [FYP-FILE] overview and definition annotations |
| `case_view.py` | Python | Application/UI | Documented | Verified [FYP-FILE] overview and definition annotations |
| `chroma_viewer.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `clearIncident.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `compliance_evidence.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `config.yaml` | YAML | Configuration | Documented | Verified [FYP-FILE] overview and definition annotations |
| `detection_engineering.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `detection_rules.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `diamond_model.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `endpoint_profile.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `eval_harness.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `final_verdict.py` | Python | Triage | Documented | Verified [FYP-FILE] overview and definition annotations |
| `INC-Reset.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `incident_expansion.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `incident_map.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `ioc_correlation.py` | Python | Threat intelligence | Documented | Verified [FYP-FILE] overview and definition annotations |
| `mitigation_mapping.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `nw_alerts.py` | Python | Threat intelligence | Documented | Verified [FYP-FILE] overview and definition annotations |
| `osquery_investigation.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `parsing-normalisation-codes/soc_reporting_agent/adapters/common.py` | Python | Analysis helpers | Excluded with reason | Superseded duplicate; canonical copy is under soc_reporting_agent/ |
| `parsing-normalisation-codes/soc_reporting_agent/adapters/run_parser_normalisation.py` | Python | Analysis helpers | Excluded with reason | Superseded duplicate; canonical copy is under soc_reporting_agent/ |
| `parsing-normalisation-codes/soc_reporting_agent/services/__init__.py` | Python | Analysis helpers | Excluded with reason | Superseded duplicate; canonical copy is under soc_reporting_agent/ |
| `parsing-normalisation-codes/soc_reporting_agent/services/parser_context_guard.py` | Python | Analysis helpers | Excluded with reason | Superseded duplicate; canonical copy is under soc_reporting_agent/ |
| `parsing-normalisation-codes/soc_reporting_agent/services/parser_normaliser.py` | Python | Analysis helpers | Excluded with reason | Superseded duplicate; canonical copy is under soc_reporting_agent/ |
| `parsing-normalisation-codes/soc_reporting_agent/utils/__init__.py` | Python | Analysis helpers | Excluded with reason | Superseded duplicate; canonical copy is under soc_reporting_agent/ |
| `parsing-normalisation-codes/soc_reporting_agent/utils/powershell_decoder.py` | Python | Analysis helpers | Excluded with reason | Superseded duplicate; canonical copy is under soc_reporting_agent/ |
| `report_editing.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `reporting_approval.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `reporting_sop.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `requirements.txt` | Dependency configuration | Configuration | Documented | Verified [FYP-FILE] overview and definition annotations |
| `skills_sidecar.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/bench_correlation.py` | Python | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/chroma_compat.py` | Python | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/correlation_config.py` | Python | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/correlation_engine.py` | Python | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/ingest_pipeline.py` | Python | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/log_config.yaml` | YAML | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/main.py` | Python | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/mitre_mapper.py` | Python | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/orchestrator.py` | Python | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/playbooks/phishing.yaml` | YAML | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/playbooks/privilegeEscalation.yaml` | YAML | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/policy_engine.py` | Python | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/sync_engine.py` | Python | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_investigation_agent_revised/vector_engine.py` | Python | Investigation | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/adapters/common.py` | Python | Stage adapters | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/adapters/export_documents.py` | Python | Stage adapters | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/adapters/run_parser_normalisation.py` | Python | Stage adapters | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/adapters/run_reporting.py` | Python | Stage adapters | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/agents/__init__.py` | Python | Reporting agent | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/agents/reporting_agent.py` | Python | Reporting agent | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/backend/__init__.py` | Python | Backend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/backend/app.py` | Python | Backend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/backend/casework_store.py` | Python | Backend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/backend/error_handling.py` | Python | Backend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/backend/export_cache.py` | Python | Backend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/backend/openai_client.py` | Python | Backend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/backend/orchestration_service.py` | Python | Backend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/backend/postgres_casework_store.py` | Python | Backend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/backend/reporting_context_resolver.py` | Python | Backend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/backend/stage_workflow.py` | Python | Backend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/backend/store_factory.py` | Python | Backend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/backend/ticket_workflow.py` | Python | Backend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/config/__init__.py` | Python | Configuration | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/config/settings.py` | Python | Configuration | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/dashboard/app.js` | JavaScript | Frontend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/dashboard/index.html` | HTML | Frontend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/dashboard/style.css` | CSS | Frontend | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/report_templates/executive_summary_template.md.j2` | Jinja2 | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/report_templates/incident_report_template.md.j2` | Jinja2 | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/report_templates/soc_analyst_review_template.md.j2` | Jinja2 | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/report_templates/soc_triage_review_template.md.j2` | Jinja2 | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/report_templates/technical_findings_template.md.j2` | Jinja2 | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/__init__.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/compact_renderer.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/context_builder.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/editable_reports.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/export_context_enhancer.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/input_loader.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/llm_narrative.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/output_writer.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/rag_context.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/report_renderer.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/report_validator.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/schema_normaliser.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/status_display.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/structured_report.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/reporting/template_document_exporter.py` | Python | Reporting | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/requirements.txt` | Dependency configuration | Configuration | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/scripts/test_agent_rerun_ui_static.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/scripts/test_evidence_gap_branch_and_reporting_wrapper.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/scripts/test_export_cache.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/scripts/test_merged_report_context.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/scripts/test_reporting_appendix_context.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/scripts/test_reporting_context_resolution.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/scripts/test_reporting_gate_with_limited_investigation.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/scripts/test_reporting_workspace_ui_static.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/scripts/test_structured_report_review_exports.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/services/__init__.py` | Python | Parsing/Services | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/services/alert_indexing_service.py` | Python | Parsing/Services | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/services/parser_context_guard.py` | Python | Parsing/Services | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/services/parser_normaliser.py` | Python | Parsing/Services | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/tests/test_compact_renderer.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/tests/test_openai_client_json_extraction.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/tests/test_stage_workflow.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/tests/test_structured_report_tables.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/utils/__init__.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_reporting_agent/utils/powershell_decoder.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_triage_agent/__init__.py` | Python | Triage | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_triage_agent/soc_triage_agent.py` | Python | Triage | Documented | Verified [FYP-FILE] overview and definition annotations |
| `soc_workflow.py` | Python | Orchestration/State | Documented | Verified [FYP-FILE] overview and definition annotations |
| `tactic_inference.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `tests/test_ai_stage_summaries.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `tests/test_apiretrieval.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `tests/test_chroma_compat.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `tests/test_investigation_stage.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `tests/test_parsing_only.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `tests/test_reporting_stage.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `tests/test_stage_rerun.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `tests/test_thinking_process_rendering.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `tests/test_threat_intel_workflow.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `tests/test_vector_engine.py` | Python | Tests | Documented | Verified [FYP-FILE] overview and definition annotations |
| `threat_hunting.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `threat_intel.py` | Python | Threat intelligence | Documented | Verified [FYP-FILE] overview and definition annotations |
| `triage_ticket_editing.py` | Python | Triage | Documented | Verified [FYP-FILE] overview and definition annotations |
| `triage_verdict.py` | Python | Triage | Documented | Verified [FYP-FILE] overview and definition annotations |
| `ui_components.py` | Python | Application/UI | Documented | Verified [FYP-FILE] overview and definition annotations |
| `velociraptor_investigation.py` | Python | Analysis helpers | Documented | Verified [FYP-FILE] overview and definition annotations |
| `workflow_state_store.py` | Python | Orchestration/State | Documented | Verified [FYP-FILE] overview and definition annotations |
| `workflow_validation.py` | Python | Orchestration/State | Documented | Verified [FYP-FILE] overview and definition annotations |

## Undocumented files

None.

## Excluded files and folder categories

- `parsing-normalisation-codes/`: seven stale/superseded duplicates. Canonical maintained copies are under `soc_reporting_agent/`.
- Third-party dependency/virtual-environment directories: not first-party source.
- Generated output, fixture-result, vector-store, cache, binary database, media, and documentation artifacts: not executable first-party source.
- JSON inputs/outputs and generated workflow artifacts: runtime data, not source code.
- JSON Schema files under `soc_reporting_agent/schemas/`: reviewed as declarative validation assets and indexed by filename, but not treated as comment-capable source files because JSON has no comment syntax.

## Validation commands

- Python syntax parse: PostgreSQL pgAdmin Python 3.13 `ast.parse` across all 119 Python files found (112 canonical + 7 excluded duplicate): passed.
- JavaScript syntax: `node --check soc_reporting_agent/dashboard/app.js`: passed.
- Documentation safety: AST comparison of every modified tracked Python file against `HEAD` after stripping docstrings/comments: no logic differences.
- Whitespace patch check: `git diff --check`: passed.
- Python regression suites: `pytest tests soc_reporting_agent/tests -q`: **215 passed**, 1 deprecation warning.
- Standalone reporting validators with a `main()` entry point: **2 passed, 5 reported baseline/environment drift**. Passing scripts were `test_reporting_context_resolution.py` and `test_structured_report_review_exports.py`; the other scripts reported stale threat-intelligence approval/input assumptions, a missing report template, or a child-process dependency-path issue. These failures are separate from the documentation-only source diff and are described in the delivery report.
- Word artifact: OOXML structure, fixed-width table geometry, headings, TOC field, and page rendering were validated during final artifact QA.

## Git diff confirmation

Tracked Python application changes are comment/docstring-only by AST equivalence. Non-Python source/configuration changes are comments/whitespace only. The two modified SQLite binaries pre-date Codex's completion pass and remain untouched because their origin cannot be determined safely.
