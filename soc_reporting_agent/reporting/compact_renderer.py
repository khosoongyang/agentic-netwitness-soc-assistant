# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, re, typing.
# =============================================================================
# File: soc_reporting_agent/reporting/compact_renderer.py
# Purpose: This module renders compact analyst-readable report text from structured reporting data.
# Main functionality: is_placeholder, count_placeholders, table_placeholder_ratio, filter_empty_columns, filter_empty_rows, compact_table.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis report generation and export component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, re, typing.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: is_placeholder, count_placeholders, table_placeholder_ratio, filter_empty_columns, filter_empty_rows, compact_table, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

from __future__ import annotations

import re
from typing import Any

PLACEHOLDER_VALUES = {
    "not provided",
    "to be validated",
    "pending analyst validation",
    "evidence link unavailable",
    "to be assigned",
    "pending",
    "not linked",
    "unavailable from source telemetry",
    "",
    "unknown",
    "unknown-alert",
    "unknown-incident",
    "none",
    "null",
    "n/a",
    "na",
    "-",
    "—",
}


# =============================================================================
# [FYP-SECTION] REPORT GENERATION AND EXPORT EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `is_placeholder` — evaluates is placeholder conditions so invalid or unsafe report generation and export processing is stopped early.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/compact_renderer.py:build_approval_summary, soc_reporting_agent/reporting/compact_renderer.py:build_chain_of_custody_note, soc_reporting_agent/reporting/compact_renderer.py:build_evidence_register_summary; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `isinstance`, `len`, `lower`, `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def is_placeholder(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) == 0
    return str(value).strip().lower() in PLACEHOLDER_VALUES


# [FYP-FUNCTION] `count_placeholders` — implements the count placeholders operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/compact_renderer.py:count_placeholders, soc_reporting_agent/reporting/export_context_enhancer.py:finalise_section_placeholder_counts, soc_reporting_agent/reporting/template_document_exporter.py:build_agent_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `count_placeholders`, `is_placeholder`, `isinstance`, `sum`, `values`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def count_placeholders(value: Any) -> int:
    if isinstance(value, dict):
        return sum(count_placeholders(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return sum(count_placeholders(v) for v in value)
    return 1 if is_placeholder(value) else 0


# [FYP-FUNCTION] `table_placeholder_ratio` — implements the table placeholder ratio operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `rows`, `columns`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/compact_renderer.py:compact_table, soc_reporting_agent/reporting/compact_renderer.py:compact_table_summary, soc_reporting_agent/tests/test_compact_renderer.py:test_all_placeholders; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `is_placeholder`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def table_placeholder_ratio(rows: list[list[Any]], columns: list[str]) -> float:
    total = 0
    placeholders = 0
    for row in rows or []:
        for cell in row or []:
            total += 1
            if is_placeholder(cell):
                placeholders += 1
    if total == 0:
        return 0.0
    return placeholders / total


# [FYP-FUNCTION] `filter_empty_columns` — implements the filter empty columns operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `columns`, `rows`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/compact_renderer.py:compact_table, soc_reporting_agent/tests/test_compact_renderer.py:test_empty_inputs, soc_reporting_agent/tests/test_compact_renderer.py:test_hides_all_placeholder_column; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `enumerate`, `is_placeholder`, `len`, `max`, `range`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def filter_empty_columns(columns: list[str], rows: list[list[Any]]) -> tuple[list[str], list[list[Any]], list[int]]:
    if not columns:
        return columns, rows, []
    widths = [len(columns)] + [len(r) for r in (rows or [])]
    max_width = max(widths) if widths else 0
    normalised = [r + [""] * (max_width - len(r)) for r in (rows or [])]
    hidden: list[int] = []
    for idx in range(len(columns)):
        all_empty = True
        for row in normalised:
            cell = row[idx] if idx < len(row) else ""
            if not is_placeholder(cell):
                all_empty = False
                break
        if all_empty:
            hidden.append(idx)
    kept = [c for i, c in enumerate(columns) if i not in hidden]
    kept_rows = [[cell for i, cell in enumerate(r) if i not in hidden] for r in normalised]
    return kept, kept_rows, hidden


# [FYP-FUNCTION] `filter_empty_rows` — implements the filter empty rows operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `columns`, `rows`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/compact_renderer.py:compact_table, soc_reporting_agent/tests/test_compact_renderer.py:test_keeps_partial_row, soc_reporting_agent/tests/test_compact_renderer.py:test_removes_all_placeholder_row; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `any`, `append`, `is_placeholder`, `len`, `max`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def filter_empty_rows(columns: list[str], rows: list[list[Any]]) -> tuple[list[str], list[list[Any]]]:
    if not columns:
        return columns, rows
    max_width = max(len(columns), *(len(r) for r in (rows or [])))
    normalised = [r + [""] * (max_width - len(r)) for r in (rows or [])]
    kept = []
    for row in normalised:
        if any(not is_placeholder(cell) for cell in row):
            kept.append(row)
    return columns, kept


# [FYP-FUNCTION] `compact_table` — implements the compact table operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `columns`, `rows`, `section_name`, `gaps`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/compact_renderer.py:build_evidence_register_summary, soc_reporting_agent/reporting/export_context_enhancer.py:build_compact_render_tables; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `bool`, `compact_table_summary`, `filter_empty_columns`, `filter_empty_rows`, `len`, `max`, `table_placeholder_ratio`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def compact_table(
    columns: list[str],
    rows: list[list[Any]],
    section_name: str,
    gaps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    max_width = max([len(columns), *(len(r) for r in (rows or []))]) if (columns or rows) else 0
    normalised = [r + [""] * (max_width - len(r)) for r in (rows or [])]
    original_count = len(normalised)
    display_columns, display_rows, hidden_cols = filter_empty_columns(columns, normalised)
    display_columns, display_rows = filter_empty_rows(display_columns, display_rows)
    ratio = table_placeholder_ratio(normalised, columns)
    summary = compact_table_summary(columns, normalised, section_name, gaps) if ratio > 0.4 else None
    return {
        "columns": display_columns,
        "rows": display_rows,
        "hidden_columns": hidden_cols,
        "hidden_rows": max(0, original_count - len(display_rows)),
        "placeholder_ratio": ratio,
        "summary": summary,
        "compact": bool(summary),
    }


# [FYP-FUNCTION] `compact_table_summary` — implements the compact table summary operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `columns`, `rows`, `section_name`, `gaps`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/compact_renderer.py:compact_table; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `get`, `is_placeholder`, `join`, `len`, `lower`, `max`, `next`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def compact_table_summary(columns: list[str], rows: list[list[Any]], section_name: str, gaps: list[dict[str, Any]] | None = None) -> str | None:
    max_width = max(len(columns), *(len(r) for r in (rows or [])))
    normalised = [r + [""] * (max_width - len(r)) for r in (rows or [])]
    placeholder_ratio = table_placeholder_ratio(normalised, columns)
    if placeholder_ratio <= 0.4:
        return None
    summary_parts = [f"{section_name} summary:"]
    for row in normalised[:8]:
        label = next((str(c) for c in row if not is_placeholder(c)), None)
        if label:
            values = [str(c) for c in row if not is_placeholder(c) and str(c) != label]
            suffix = f" (values unavailable)" if not values else f": {', '.join(values)}"
            summary_parts.append(f"- {label}{suffix}")
        else:
            summary_parts.append(f"- Values unavailable for this {section_name.lower()} entry")
    if gaps:
        for gap in gaps[:4]:
            summary_parts.append(f"- Evidence gap: {gap.get('gap', gap.get('missing_field', 'Missing information'))}")
    return "\n".join(summary_parts)


# [FYP-FUNCTION] `build_evidence_register_summary` — constructs build evidence register summary output for the next report generation and export consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `evidence`, `evidence_gaps`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/export_context_enhancer.py:enhance_export_context, soc_reporting_agent/tests/test_compact_renderer.py:test_compact_when_many_placeholders, soc_reporting_agent/tests/test_compact_renderer.py:test_full_when_few_placeholders; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `all`, `append`, `compact_table`, `get`, `is_placeholder`, `len`, `max`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_evidence_register_summary(evidence: list[dict[str, Any]], evidence_gaps: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    columns = ["Evidence ID", "Source", "Type", "Description", "Timestamp", "Confidence", "Raw Reference"]
    rows = []
    for item in evidence or []:
        rows.append([
            item.get("id") or "",
            item.get("source") or "",
            item.get("type") or "",
            item.get("description") or "",
            item.get("timestamp") or "",
            item.get("confidence") or "",
            item.get("raw_reference") or "",
        ])
    max_width = max(len(columns), *(len(r) for r in rows)) if rows else len(columns)
    normalised = [r + [""] * (max_width - len(r)) for r in rows]
    compacted = compact_table(columns, normalised, "Evidence register", evidence_gaps)
    placeholder_ratio = compacted["placeholder_ratio"]
    timestamp_missing = all(is_placeholder(r[4]) for r in normalised) if normalised else True
    confidence_missing = all(is_placeholder(r[5]) for r in normalised) if normalised else True
    raw_ref_missing = all(is_placeholder(r[6]) for r in normalised) if normalised else True
    notes = []
    if timestamp_missing:
        notes.append("Timestamps were not supplied with the current export. Evidence IDs are generated from available reporting context for analyst traceability.")
    if confidence_missing:
        notes.append("Confidence values were not supplied with the current export and remain pending analyst validation.")
    if raw_ref_missing:
        notes.append("Raw event references were not supplied with the current export. Evidence IDs are generated from available reporting context for analyst traceability.")
    return {
        "columns": compacted["columns"],
        "rows": compacted["rows"],
        "hidden_columns": compacted["hidden_columns"],
        "hidden_rows": compacted["hidden_rows"],
        "summary": compacted["summary"],
        "notes": notes,
        "placeholder_ratio": placeholder_ratio,
        "compact": compacted["compact"],
    }


# [FYP-FUNCTION] `build_data_impact_summary` — constructs build data impact summary output for the next report generation and export consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `context`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/export_context_enhancer.py:enhance_export_context, soc_reporting_agent/tests/test_compact_renderer.py:test_includes_impact_context, soc_reporting_agent/tests/test_compact_renderer.py:test_returns_compact_summary; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `get`, `join`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_data_impact_summary(context: dict[str, Any]) -> str:
    assessment = context.get("data_impact_assessment") or {}
    business_impact = context.get("impact_assessment", {}).get("business", "")
    security_risk = context.get("impact_assessment", {}).get("security", "")
    lines = [
        "Data impact assessment:",
        "No evidence of data access, data exfiltration, encryption impact, or personal data exposure was provided in the current telemetry. These items remain unresolved and require analyst validation before closure or notification decisions.",
    ]
    bullets = [
        "- Data access: No evidence provided, requires validation",
        "- Data exfiltration: No evidence provided, requires validation",
        "- Encryption / modification / deletion: Not confirmed by supplied host telemetry",
        "- Personal data involvement: Cannot determine from current evidence",
        "- Notification requirement: Legal / Compliance decision only if data impact is confirmed",
    ]
    if business_impact:
        bullets.append(f"- Business impact context: {str(business_impact)[:220]}")
    if security_risk:
        bullets.append(f"- Security risk context: {str(security_risk)[:220]}")
    return "\n".join(lines + [""] + bullets)


# [FYP-FUNCTION] `build_chain_of_custody_note` — constructs build chain of custody note output for the next report generation and export consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `evidence`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/export_context_enhancer.py:enhance_export_context, soc_reporting_agent/tests/test_compact_renderer.py:test_empty_note_when_no_evidence, soc_reporting_agent/tests/test_compact_renderer.py:test_empty_note_when_real_custody_exists; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `any`, `get`, `is_placeholder`, `isinstance`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_chain_of_custody_note(evidence: list[dict[str, Any]]) -> str:
    has_real_custody = False
    for item in evidence or []:
        if not isinstance(item, dict):
            continue
        if any(
            v for v in (
                item.get("collection_time"),
                item.get("collector"),
                item.get("storage_location"),
                item.get("hash"),
                item.get("integrity"),
            ) if not is_placeholder(v)
        ):
            has_real_custody = True
            break
    if has_real_custody:
        return ""
    return (
        "Formal chain-of-custody metadata was not supplied in the current source context. "
        "Evidence IDs in this report are reporting references only and should be validated against the source case folder or SIEM export before legal or forensic use."
    )


# [FYP-FUNCTION] `build_approval_summary` — constructs build approval summary output for the next report generation and export consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `approval`, `containment`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/compact_renderer.py:containment_table_summary, soc_reporting_agent/reporting/export_context_enhancer.py:enhance_export_context, soc_reporting_agent/tests/test_compact_renderer.py:test_approved_report_summary; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `is_placeholder`, `isinstance`, `lower`, `replace`, `str`, `title`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_approval_summary(approval: dict[str, Any], containment: dict[str, Any]) -> dict[str, str]:
    approval_status = approval.get("approval_status") if isinstance(approval, dict) else None
    analyst_decision = approval.get("analyst_decision") if isinstance(approval, dict) else None
    approved_by = approval.get("approved_by") if isinstance(approval, dict) else None
    report_generation_status = approval.get("report_generation_approval_status") if isinstance(approval, dict) else None
    report_generation_approved_by = approval.get("report_generation_approved_by") if isinstance(approval, dict) else None
    final_review_status = approval.get("final_analyst_review_status") if isinstance(approval, dict) else None
    approved_action = approval.get("approved_action") if isinstance(approval, dict) else None
    containment_approval = containment.get("approval_status") if isinstance(containment, dict) else None
    containment_status = containment.get("status") if isinstance(containment, dict) else None
    containment_execution = containment.get("execution_status") if isinstance(containment, dict) else None
    recommended_action = containment.get("recommended_action") if isinstance(containment, dict) else None
    blocking_reason = containment.get("blocking_reason") if isinstance(containment, dict) else None

    entries = {}
    if not is_placeholder(report_generation_status):
        reviewer = report_generation_approved_by if not is_placeholder(report_generation_approved_by) else approved_by
        if not is_placeholder(reviewer):
            entries["report"] = f"Report generation approval status: {str(report_generation_status).title()} by {reviewer}."
        else:
            entries["report"] = f"Report generation approval status: {str(report_generation_status).title()}."
    elif not is_placeholder(approval_status) and not is_placeholder(analyst_decision):
        reviewer = approved_by if not is_placeholder(approved_by) else "SOC Analyst"
        entries["report"] = f"Report generation approval status: {str(analyst_decision).title()} by {reviewer}."
    elif not is_placeholder(approval_status):
        entries["report"] = f"Report generation approval status: {str(approval_status).title()}."
    else:
        entries["report"] = "Report generation approval status: Not recorded in approval context."

    if not is_placeholder(containment_approval):
        entries["containment"] = f"Containment approval status: {str(containment_approval).replace('_', ' ').title()}."
    elif not is_placeholder(containment_status) and "approved" in str(containment_status).lower():
        entries["containment"] = f"Containment approval status: {str(containment_status).replace('_', ' ').title()}."
    else:
        entries["containment"] = "Containment approval status: Approval type requires analyst validation."

    if not is_placeholder(recommended_action):
        entries["recommended"] = f"Recommended containment action: {recommended_action}."
    else:
        entries["recommended"] = "Recommended containment action: Not provided in available context."

    if not is_placeholder(containment_execution):
        entries["execution"] = f"Containment execution status: {str(containment_execution).replace('_', ' ').title()}."
    else:
        entries["execution"] = "Containment execution status: Not evidenced in source telemetry."

    if not is_placeholder(final_review_status):
        entries["final_review"] = f"Final analyst review status: {str(final_review_status).replace('_', ' ').title()}."

    if not is_placeholder(approved_action):
        entries["approved_action"] = f"Approved action: {approved_action}."
    if not is_placeholder(blocking_reason):
        entries["blocking"] = f"Blocking reason: {blocking_reason}."
    if is_placeholder(approval_status) and is_placeholder(containment_status):
        entries["note"] = "Approval record exists, but approval type requires analyst validation."
    return entries


# [FYP-FUNCTION] `containment_table_summary` — implements the containment table summary operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `containment`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `build_approval_summary`, `isinstance`, `join`, `values`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def containment_table_summary(containment: dict[str, Any]) -> str | None:
    if not isinstance(containment, dict):
        return None
    summary = build_approval_summary({}, containment)
    if not summary:
        return None
    return "\n".join(summary.values())


_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9])")
_NUMBERED_ITEM_RE = re.compile(r"(?:^|(?<=\s))(\d{1,2})\.\s+")


# [FYP-FUNCTION] `split_into_sentences` — implements the split into sentences operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `text`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/export_context_enhancer.py:_incident_timeline_from_chronology, soc_reporting_agent/reporting/export_context_enhancer.py:build_readable_narrative_sections; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `split`, `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def split_into_sentences(text: Any) -> list[str]:
    """Split a narrative paragraph into individual sentences for bullet-list
    rendering. Presentation-only: every word is preserved, only the layout
    changes from one dense paragraph to one bullet per sentence."""
    text = str(text or "").strip()
    if not text:
        return []
    parts = [p.strip() for p in _SENTENCE_SPLIT_RE.split(text) if p.strip()]
    return parts or [text]


# [FYP-FUNCTION] `split_numbered_items` — implements the split numbered items operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `text`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/export_context_enhancer.py:build_readable_narrative_sections; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `end`, `enumerate`, `finditer`, `len`, `list`, `start`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def split_numbered_items(text: Any) -> list[str]:
    """Split an inline-numbered narrative ("1. ... 2. ... 3. ...") into its
    individual items for checklist/table rendering. Relies on numbering
    markers already present in the source text; presentation-only."""
    text = str(text or "").strip()
    if not text:
        return []
    matches = list(_NUMBERED_ITEM_RE.finditer(text))
    if not matches:
        return [text]
    items = []
    for idx, match in enumerate(matches):
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        item = text[start:end].strip()
        if item:
            items.append(item)
    return items or [text]


# [FYP-FUNCTION] `split_label_value` — implements the split label value operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `sentence`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/compact_renderer.py:approval_summary_table; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `partition`, `rstrip`, `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def split_label_value(sentence: Any) -> tuple[str, str]:
    """Split a "Label: value." sentence into its (label, value) parts for
    table rendering. Falls back to ("", sentence) if no label is present.
    Presentation-only: no wording is altered, only relocated into columns."""
    text = str(sentence or "").strip()
    if not text:
        return "", ""
    label, sep, value = text.partition(": ")
    if not sep:
        return "", text
    return label.strip(), value.strip().rstrip(".").strip()


# [FYP-FUNCTION] `approval_summary_table` — implements the approval summary table operation used by the surrounding report generation and export workflow.
# [FYP-INPUT] Parameters: `summary`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis report generation and export workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/reporting/export_context_enhancer.py:enhance_export_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `split_label_value`, `values`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def approval_summary_table(summary: dict[str, Any]) -> list[list[str]]:
    """Convert build_approval_summary()'s prose sentences into table rows."""
    rows = []
    for sentence in (summary or {}).values():
        label, value = split_label_value(sentence)
        if label and value:
            rows.append([label, value])
    return rows
