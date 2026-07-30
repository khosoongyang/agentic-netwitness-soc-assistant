"""
[FYP-FILE] reporting/status_display.py (354 lines)
# File: soc_reporting_agent/reporting/status_display.py
# Purpose: This module implements report generation and export behaviour for status display.
# Inputs: Receives function arguments, configured state, and persisted artifacts described below.
# Outputs: Produces return values and documented state, file, database, export, or UI effects.
# Workflow position: Aegis report generation and export.
# Important dependencies: __future__, typing.
# Key evaluator search terms: _meta, get_status_metadata, status_display, status_explanation, status_workflow_impact, calculate_llm_enhancement_score, [FYP-FUNCTION].

[FYP-SECTION] Responsibility
Central "technical status code -> analyst-facing text" translation layer
for the Reporting Agent. Every stage of the pipeline (report generation,
field validation, LLM enhancement, per-section LLM guardrail outcome,
report cache, PostgreSQL persistence, RAG retrieval, completeness scoring)
emits a short machine-readable status string (e.g.
"llm_retry_successful_with_warnings", "success_chromadb",
"cache_disabled"); this module is the single source of truth mapping each
of those codes to a 3-part human-readable {display, explanation,
workflow_impact} tuple, so the same status never gets worded differently
in different parts of the UI/report.

[FYP-SECTION] Structure
STATUS_DISPLAY_MAP nests dict[category][technical_status] -> meta dict for
8 categories: report, validation, llm, data_consistency, llm_section,
cache, postgresql, rag, quality (9 including quality). get_status_metadata()
is the only lookup path callers actually use; the three status_display()/
status_explanation()/status_workflow_impact() one-field convenience
wrappers below it are not called elsewhere in this codebase as of this
pass (get_status_metadata() is called directly and the full dict
destructured) but are kept as the module's public single-field API.
calculate_llm_enhancement_score() is a separate, unrelated concern living
in the same file: it scores LLM section outcomes into a 0-100 completeness
score independent of the display-text mapping above.

[FYP-USED-BY] reporting/output_writer.py (get_status_metadata,
calculate_llm_enhancement_score, via _display_fields()/
build_reporting_result()); agents/reporting_agent.py:main() (both
functions directly, plus a second get_status_metadata("postgresql", ...)
call after try_store_postgres() and a get_status_metadata("llm_section", ...)
call while printing per-section LLM status to the console).
"""
from __future__ import annotations

from typing import Any


def _meta(display: str, explanation: str, workflow_impact: str) -> dict[str, str]:
    """[FYP-FUNCTION] Tiny dict-literal constructor used throughout
    STATUS_DISPLAY_MAP to build each {display, explanation,
    workflow_impact} entry with named, self-documenting arguments instead
    of a bare dict literal repeated ~70 times."""
    return {
        "display": display,
        "explanation": explanation,
        "workflow_impact": workflow_impact,
    }


# [FYP-SECTION] [FYP-KNOWLEDGE-BASE] The status-code -> display-text lookup
# table itself. Each top-level key is a "category" (matches the
# `category` argument callers pass to get_status_metadata()); each nested
# key is a "technical_status" value as produced elsewhere in the pipeline
# (e.g. context["report_status"], context["llm_status"],
# context["rag_status"], a per-section llm_section_results[...]["status"]).
STATUS_DISPLAY_MAP: dict[str, dict[str, dict[str, str]]] = {
    "report": {
        "ready_for_analyst_review": _meta(
            "Ready for analyst review",
            "The report was generated successfully and contains enough information for SOC analyst review.",
            "Workflow can continue to analyst review, approval, closure, or escalation.",
        ),
        "missing_information_required": _meta(
            "More information required",
            "Required case fields are missing, so the report may be incomplete until the analyst validates or supplies the missing information.",
            "Workflow can continue for review, but the analyst should resolve the missing fields before closure.",
        ),
        "generated_with_warnings": _meta(
            "Generated with warnings",
            "The report was created, but non-critical issues or weak fields were detected.",
            "Workflow can continue, but the warnings should be reviewed.",
        ),
        "failed": _meta(
            "Report generation failed",
            "The report could not be generated successfully.",
            "Workflow should stop until the failure is corrected.",
        ),
        "case_context_inconsistent": _meta(
            "Generated, but case context requires review",
            "The report was generated, but conflicting case data was detected across input files.",
            "Workflow should continue only as a draft until a SOC analyst resolves the data conflict.",
        ),
    },
    "validation": {
        "passed": _meta(
            "Validation passed",
            "Required incident fields were found after context loading and recovery.",
            "Report generation can continue.",
        ),
        "passed_with_warnings": _meta(
            "Validation passed with warnings",
            "Required fields are present, but optional or supporting fields may be weak or incomplete.",
            "Report generation can continue, but the analyst should review the warnings.",
        ),
        "failed": _meta(
            "Validation failed",
            "One or more required fields are missing.",
            "The report can be generated as a draft, but analyst review is required before closure or decision-making.",
        ),
        "skipped": _meta(
            "Validation skipped",
            "Validation was not performed for this run.",
            "The report should be reviewed manually before use.",
        ),
        "failed_due_to_case_conflict": _meta(
            "Validation failed due to inconsistent case context",
            "Input files appear to contain conflicting incident, alert, severity, confidence, or classification values.",
            "Do not close or action the case until the conflicting context is resolved.",
        ),
    },
    "llm": {
        "llm_enhancement_successful": _meta(
            "LLM enhancement completed successfully",
            "All LLM-enhanced sections passed guardrail validation and were used in the final report.",
            "Final report can be reviewed with the LLM-enhanced narrative included.",
        ),
        "llm_enhancement_successful_with_warnings": _meta(
            "LLM enhancement completed with minor warnings",
            "The LLM output was accepted, but minor quality warnings were recorded.",
            "Final report remains usable; analyst may review the warnings for context.",
        ),
        "llm_retry_successful": _meta(
            "LLM enhancement completed after retry",
            "One or more LLM sections needed a retry, and the retry produced acceptable output.",
            "Final report includes accepted LLM-enhanced content.",
        ),
        "llm_retry_successful_with_warnings": _meta(
            "LLM enhancement completed after retry with minor warnings",
            "A retry produced acceptable LLM output, but minor warnings were still recorded.",
            "Final report remains usable; analyst may review the warnings for context.",
        ),
        "partial_llm_enhancement_with_guardrails": _meta(
            "LLM enhancement partially applied",
            "Some LLM-generated sections failed hard guardrail checks and were replaced with deterministic fallback content. The final report remains complete.",
            "Workflow can continue because unsafe or weak sections were safely replaced.",
        ),
        "llm_failed_cached_report_used": _meta(
            "LLM failed, cached enhanced report reused",
            "The current LLM enhancement failed, but a previous valid enhanced report was available and reused.",
            "Workflow can continue, but the analyst should confirm the cached report still matches the current incident context.",
        ),
        "llm_failed_fallback_used": _meta(
            "LLM failed, deterministic fallback report used",
            "LLM enhancement failed, so the report was generated using deterministic content only.",
            "Workflow can continue because the deterministic report is still available.",
        ),
        "llm_failed_all_providers_fallback_used": _meta(
            "All LLM providers failed, deterministic fallback report used",
            "Every configured LLM provider failed, so the system used deterministic report content.",
            "Workflow can continue locally, but LLM provider configuration should be checked.",
        ),
        "deterministic_fallback_after_llm_guardrail_rejection": _meta(
            "LLM rejected by guardrails, deterministic fallback report used",
            "LLM output was generated but did not pass guardrail validation, so deterministic content was used.",
            "Workflow can continue because the final report avoids unsafe LLM content.",
        ),
        "llm_disabled_deterministic_generation": _meta(
            "LLM disabled, deterministic report generated",
            "LLM usage is turned off in configuration. The report was generated without LLM enhancement.",
            "Workflow can continue with deterministic reporting only.",
        ),
        "llm_disabled": _meta(
            "LLM disabled, deterministic report generated",
            "LLM usage is turned off in configuration. The report was generated without LLM enhancement.",
            "Workflow can continue with deterministic reporting only.",
        ),
        "llm_context_validation_failed": _meta(
            "LLM skipped due to insufficient case context",
            "Required case context was too incomplete to safely call the LLM.",
            "Workflow can continue with deterministic reporting, but missing fields should be resolved.",
        ),
    },
    "data_consistency": {
        "passed": _meta("Data consistency passed", "Incident identifiers and key assessment fields are consistent across loaded inputs.", "Workflow can continue to analyst review."),
        "passed_with_warnings": _meta("Data consistency passed with warnings", "Minor differences or non-blocking conflicts were detected across input files.", "Workflow can continue, but the analyst should review the warnings."),
        "failed_due_to_case_conflict": _meta("Data consistency failed due to case conflict", "The loaded files appear to mix different incidents or conflicting key assessment values.", "Treat the report as a draft only until the case context is corrected."),
    },
    "llm_section": {
        "llm_used": _meta("LLM section accepted", "This section passed guardrail validation and was included in the report.", "No action required beyond normal analyst review."),
        "llm_used_with_warning": _meta("LLM section accepted with minor warnings", "This section was usable, but minor quality warnings were recorded.", "Review the warnings if this section is important to the decision."),
        "llm_retry_successful": _meta("LLM section accepted after retry", "The first attempt failed or was weak, but a retry produced acceptable output.", "No action required beyond normal analyst review."),
        "llm_retry_successful_with_warning": _meta("LLM section accepted after retry with warnings", "A retry produced usable output, but minor warnings were recorded.", "Review the warnings if this section is important to the decision."),
        "llm_retry_successful_after_repair": _meta("LLM section accepted after retry and repair", "The section needed a targeted retry and a safe repair before it passed guardrail validation.", "No action required beyond normal analyst review."),
        "llm_retry_successful_after_repair_with_warning": _meta("LLM section accepted after retry and repair with warnings", "The section was improved through retry and repair, but minor warnings remain.", "Review the warnings if this section is important to the decision."),
        "llm_used_after_repair": _meta("LLM section accepted after safe repair", "The section was usable after a small deterministic repair, such as cleaning a trailing sentence.", "No action required beyond normal analyst review."),
        "llm_used_after_repair_with_warning": _meta("LLM section accepted after safe repair with warnings", "The section was repaired and accepted, but minor warnings remain.", "Review the warnings if this section is important to the decision."),
        "llm_used_after_uncertainty_repair": _meta("LLM section accepted after uncertainty repair", "The LLM section was usable, and the system added a deterministic uncertainty sentence to make limitations explicit.", "No action required beyond normal analyst review."),
        "llm_used_after_uncertainty_repair_with_warning": _meta("LLM section accepted after uncertainty repair with warnings", "The system added an uncertainty sentence, but minor warnings remain.", "Review the warnings if this section is important to the decision."),
        "llm_used_after_sentence_repair": _meta("LLM section accepted after sentence repair", "The system removed or repaired an incomplete trailing sentence and accepted the cleaned section.", "No action required beyond normal analyst review."),
        "llm_used_after_sentence_repair_with_warning": _meta("LLM section accepted after sentence repair with warnings", "The system repaired an incomplete sentence, but minor warnings remain.", "Review the warnings if this section is important to the decision."),
        "llm_used_after_checklist_repair": _meta("LLM checklist accepted after item-count repair", "The checklist was completed to the required number of analyst actions using safe deterministic repair.", "No action required beyond normal analyst review."),
        "llm_used_after_checklist_repair_with_warning": _meta("LLM checklist accepted after item-count repair with warnings", "The checklist was repaired and accepted, but minor warnings remain.", "Review the warnings if this section is important to the decision."),
        "fallback_used": _meta("Safe fallback section used", "The LLM output failed hard guardrails, so deterministic fallback content was used.", "The report remains safe, but the rejected section reason should be reviewed."),
        "fallback_used_after_retry_failed": _meta("Safe fallback section used after retry failed", "The LLM output failed hard guardrails, a targeted retry was attempted, and deterministic fallback was used because the retry was still unsafe or incomplete.", "The report remains safe, but the rejected section reason should be reviewed."),
        "not_used": _meta("LLM not used for this section", "This section used deterministic content only.", "No LLM dependency for this section."),
        "deterministic_locked": _meta("Deterministic section locked", "This section is intentionally generated by deterministic code and is not rewritten by the LLM.", "No LLM dependency for this section."),
    },
    "cache": {
        "cache_updated": _meta(
            "Enhanced report saved to cache",
            "The accepted LLM-enhanced narrative was saved and can be reused if a future LLM call fails.",
            "No negative impact; cache improves future resilience.",
        ),
        "cached_report_used": _meta(
            "Cached enhanced report reused",
            "A previous valid enhanced report was reused because the current LLM generation did not succeed.",
            "Workflow can continue, but the analyst should confirm the cached content matches the current context.",
        ),
        "cache_miss": _meta(
            "No cached report used",
            "No suitable cached enhanced report was available for this run.",
            "No impact if the current report was generated successfully.",
        ),
        "not_used": _meta(
            "Cache not used",
            "Report cache was not used for this run.",
            "No impact on current report generation.",
        ),
        "cache_disabled": _meta(
            "Cache disabled",
            "Report caching is turned off.",
            "No impact on current report generation.",
        ),
        "not_recorded": _meta(
            "Cache status not recorded",
            "The agent did not record a cache status for this run.",
            "No direct workflow impact, but observability is reduced.",
        ),
    },
    "postgresql": {
        "postgres_store_success": _meta(
            "Stored in PostgreSQL",
            "The reporting result was saved to the PostgreSQL database.",
            "Workflow completed with database persistence.",
        ),
        "postgres_disabled": _meta(
            "PostgreSQL storage disabled",
            "Database storage is turned off. The report was still saved locally.",
            "No impact on local report generation.",
        ),
        "postgres_skipped": _meta(
            "PostgreSQL storage skipped",
            "Database storage was not required for this run.",
            "No impact on local report generation.",
        ),
    },
    "rag": {
        "success_direct_file_retrieval": _meta(
            "Local knowledge files loaded and matched",
            "Relevant local reporting guidance was loaded from knowledge files and matched to the case context.",
            "Workflow can continue with local RAG context.",
        ),
        "rag_enabled_no_knowledge_files_found": _meta(
            "RAG enabled but no knowledge files found",
            "RAG was enabled, but no local knowledge base files were available to retrieve from.",
            "Workflow can continue using case context only, but knowledge base setup should be checked.",
        ),
        "rag_enabled_no_relevant_context_found": _meta(
            "RAG enabled but no relevant context matched",
            "Knowledge files were loaded, but no relevant guidance matched the current case.",
            "Workflow can continue using case context only.",
        ),
        "success_chromadb": _meta(
            "RAG context retrieved from ChromaDB",
            "Relevant reporting context was retrieved from the vector database.",
            "Workflow can continue with vector-based RAG context.",
        ),
        "disabled": _meta(
            "RAG disabled",
            "RAG retrieval is turned off in configuration.",
            "Workflow can continue using available case context only.",
        ),
        "forced_failure_for_test": _meta(
            "RAG failure simulated for testing",
            "RAG retrieval was intentionally forced to fail for a test scenario.",
            "Workflow should continue using fallback context if available.",
        ),
    },
    "quality": {
        "excellent": _meta(
            "Excellent completeness",
            "All or nearly all required report fields and sections are present.",
            "Report is suitable for analyst review.",
        ),
        "good": _meta(
            "Good completeness",
            "Most required fields are present, with some missing or weaker supporting details.",
            "Report is usable, but analyst should review missing items.",
        ),
        "needs_review": _meta(
            "Completeness needs review",
            "Several important report fields are missing or incomplete.",
            "Analyst should resolve missing items before closure.",
        ),
        "insufficient": _meta(
            "Insufficient completeness",
            "The report is missing too much required context for reliable review.",
            "Workflow should pause for additional evidence or manual analyst input.",
        ),
    },
}


# [FYP-FUNCTION] `get_status_metadata` — retrieves get status metadata data for the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `category`, `technical_status`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/agents/reporting_agent.py:_add_postgres_display_fields, soc_reporting_agent/agents/reporting_agent.py:_print_status, soc_reporting_agent/agents/reporting_agent.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_meta`, `get`, `replace`, `startswith`, `str`, `title`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def get_status_metadata(category: str, technical_status: Any) -> dict[str, str]:
    raw = "not_recorded" if technical_status in [None, ""] else str(technical_status)
    category_map = STATUS_DISPLAY_MAP.get(category, {})
    if raw in category_map:
        return category_map[raw]

    if category == "postgresql" and raw.startswith("postgres_store_failed"):
        return _meta(
            "PostgreSQL save failed",
            f"The database save step failed. Technical detail: {raw}",
            "Local report generation is still complete, but database persistence should be checked.",
        )
    if category == "rag" and raw.startswith("chromadb_failed_direct_file_fallback"):
        return _meta(
            "ChromaDB failed, local RAG fallback used",
            "Vector database retrieval failed, so the agent used local file retrieval instead.",
            "Workflow can continue, but ChromaDB should be checked later.",
        )
    if category == "cache" and raw.startswith("cache_error"):
        return _meta(
            "Cache unavailable",
            f"The report cache could not be read or written. Technical detail: {raw}",
            "Workflow can continue, but cached fallback will not be available.",
        )

    return _meta(
        raw.replace("_", " ").title(),
        f"No detailed explanation is configured for technical status '{raw}'.",
        "Review the technical status if this affects the workflow.",
    )


# [FYP-FUNCTION] `status_display` — implements the status display operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `category`, `technical_status`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `get_status_metadata`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def status_display(category: str, technical_status: Any) -> str:
    return get_status_metadata(category, technical_status)["display"]


# [FYP-FUNCTION] `status_explanation` — implements the status explanation operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `category`, `technical_status`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `get_status_metadata`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def status_explanation(category: str, technical_status: Any) -> str:
    return get_status_metadata(category, technical_status)["explanation"]


# [FYP-FUNCTION] `status_workflow_impact` — implements the status workflow impact operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `category`, `technical_status`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `get_status_metadata`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def status_workflow_impact(category: str, technical_status: Any) -> str:
    return get_status_metadata(category, technical_status)["workflow_impact"]


# [FYP-FUNCTION] `calculate_llm_enhancement_score` — implements the calculate llm enhancement score operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `section_results`, `llm_status`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/agents/reporting_agent.py:main, soc_reporting_agent/reporting/output_writer.py:build_reporting_result; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `isinstance`, `round`, `str`, `values`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def calculate_llm_enhancement_score(section_results: dict[str, Any], llm_status: str) -> dict[str, Any]:
    if not section_results:
        if "disabled" in str(llm_status):
            return {"score": 0, "max_score": 100, "status": "not_used", "accepted_sections": 0, "fallback_sections": 0, "warning_sections": 0, "total_sections": 0}
        return {"score": 0, "max_score": 100, "status": "not_recorded", "accepted_sections": 0, "fallback_sections": 0, "warning_sections": 0, "total_sections": 0}

    score_total = 0
    max_total = 0
    accepted = 0
    fallback = 0
    warnings = 0
    counted = 0

    for result in section_results.values():
        status = str(result.get("status", "")) if isinstance(result, dict) else str(result)
        hard = result.get("hard_fail_issues", []) if isinstance(result, dict) else []
        soft = result.get("soft_warnings", []) if isinstance(result, dict) else []

        if status in {"deterministic_locked", "not_used"}:
            continue

        counted += 1
        max_total += 100
        if "fallback" in status or hard:
            score_total += 35
            fallback += 1
        elif soft or "warning" in status:
            score_total += 80
            accepted += 1
            warnings += 1
        else:
            score_total += 100
            accepted += 1

    if max_total == 0:
        return {"score": 0, "max_score": 100, "status": "not_used", "accepted_sections": accepted, "fallback_sections": fallback, "warning_sections": warnings, "total_sections": counted}

    score = round((score_total / max_total) * 100)
    if score >= 95:
        status = "excellent"
    elif score >= 80:
        status = "good_with_minor_warnings" if warnings else "good"
    elif score >= 60:
        status = "partial_enhancement"
    else:
        status = "fallback_heavy"

    return {"score": score, "max_score": 100, "status": status, "accepted_sections": accepted, "fallback_sections": fallback, "warning_sections": warnings, "total_sections": counted}
