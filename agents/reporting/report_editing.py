# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, datetime, json, pathlib, reporting, reporting_approval, soc_workflow, sys.
# =============================================================================
# File: report_editing.py
# Purpose: This module manages editable report drafts and analyst-supplied report changes.
# Main functionality: _analyst_edits_dir, report_row_state, save_report_edit, discard_report_edit, export_report, reporting_data_json.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis reporting component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, datetime, json, pathlib, reporting, reporting_approval, soc_workflow, sys.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: _analyst_edits_dir, report_row_state, save_report_edit, discard_report_edit, export_report, reporting_data_json, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

"""
report_editing.py — analyst "Open & Edit" layer for the Reports tab.

Sits alongside reporting_approval.py but owns a completely different
concern: reporting_approval.py is the ONLY place that may approve/export the
immutable, hash-verified candidate report set produced by the Reporting
pipeline. This module never touches that candidate set, never writes into
reporting_attempt_dir(...)/<incident_id>/reports/exports/ (the hash-pinned
docx/pdf paths reporting_approval.py re-verifies on every download), and
never calls commit_reporting_approval(). It only reads the same
already-loaded, already hash-verified structured_content
(case_view.build_reporting()'s current_attempt) as the AI-generated
"original", and layers analyst edits on top of it in the separate
report_edits SQLite table (workflow_state_store.py).

Regeneration safety needs no hook into soc_workflow.py or
soc_reporting_agent at all: every Reporting rerun already gets a brand-new
reporting_attempt_dir()/report_set_id (see soc_workflow.reporting_attempt_dir
docstring), so "is this saved edit stale?" is simply
edit.source_report_set_id != current_attempt.report_set_id, computed at read
time in report_row_state() below.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from workflow import state_store as wss
from workflow.engine import reporting_attempt_dir

from .reporting_approval import DISPLAY_TITLES, resolve_approved_report_file
# Bare import (not `.reporting.editable_reports`): this package's __init__.py
# puts agents/reporting/ itself on sys.path so every reference to the
# reporting/ subpackage — from here or from within reporting/ itself —
# resolves to the same module objects, never a second copy.
from reporting.editable_reports import (
    incident_report_dir, render_blocks_to_docx, render_blocks_to_pdf)
from reporting.final_report_assembler import (
    COMPONENT_REPORT_TYPES, assemble_final_incident_report)
from reporting.candidate_materialiser import (
    CandidateMaterialisationError, materialise_reviewed_candidate)

CORE_REPORT_TYPES = ["executive_summary", "technical_findings",
                     "soc_analyst_review", "final_incident_report"]

REPORT_DESCRIPTIONS: dict[str, str] = {
    "executive_summary": "High-level overview of the incident and key findings.",
    "technical_findings": "Detailed technical analysis, evidence and indicators.",
    "soc_analyst_review": "Analyst assessment, decisions and recommendations.",
    "final_incident_report": (
        "Complete standalone incident report generated using its own final "
        "incident report template."),
}

# Stable semantic tones consumed by the frontend status badges.
STATUS_TONES = {
    "Not generated": "critical",
    "Regeneration required": "critical",
    "Outdated": "critical",
    "Edited": "high",
    "Reviewed": "low",
    "Approved": "low",
    "Finalised": "low",
    "Draft ready": "info",
    "Ready for Review": "info",
}


class ReportEditingError(RuntimeError):
    """Analyst-facing failure raised by mark_reviewed() — mirrors
    reporting_approval.ReportValidationError's role for the approval gate;
    backend/services/report_service.py catches this and re-raises it as a
    ReportServiceError with an HTTP-appropriate status code."""


def resolve_report_status(latest_version: dict[str, Any] | None, review: dict[str, Any] | None) -> str:
    """Phase 3 status resolution (see agents/reporting/report_editing.py's
    module docstring and the approved Reporting redesign): status is derived
    entirely from (a) whether a report_versions row exists at all, (b)
    whether THAT EXACT row has a matching report_reviews row, and (c) that
    row's immutable `origin` field — never from version number, and never by
    mutating either table. A later edit simply produces a new version with
    no review row yet, which is how "Reviewed" naturally reverts to "Edited"
    without any stored status ever being overwritten."""
    if latest_version is None:
        return "Not generated"
    if review is not None:
        return "Reviewed"
    if latest_version.get("origin") in ("ai_generated", "assembled"):
        return "Ready for Review"
    return "Edited"


def _resolve_approved_display_status(incident_id: str, run_id: str, report_type: str,
                                     reporting_status: str, latest_version: dict[str, Any]) -> str | None:
    """Phase 7 / Correction 4: "Approved" (or "Finalised" for
    final_incident_report) must be shown ONLY when the CURRENT latest
    version is EXACTLY the one baked into the most recently approved
    report_sets row — never merely because the whole workflow's
    reporting_status flag happens to say "Approved". That flag doesn't
    know which specific version it covered, so on its own it would
    incorrectly keep showing "Approved" after a component changes
    underneath an already-approved Final Incident Report (re-assembly
    produces a new 'assembled' version with no analyst edit — has_edits
    alone can't catch this case, only comparing version ids can).

    Falls back to the old whole-workflow check only for legacy/simplified
    approvals that never produced per-report version tracking (an empty
    report_version_ids_json — e.g. a direct v1 approval that predates the
    reviewed-candidate flow), so existing approved incidents don't lose
    their displayed status."""
    approved_set = wss.get_latest_report_set(incident_id, run_id, status="approved")
    if approved_set is not None:
        approved_version_ids = json.loads(approved_set.get("report_version_ids_json") or "{}")
        if approved_version_ids:
            if approved_version_ids.get(report_type) == latest_version["id"]:
                return "Finalised" if report_type == "final_incident_report" else "Approved"
            return None
    if reporting_status == "Approved":
        return "Approved"
    return None


# =============================================================================
# [FYP-SECTION] REPORTING EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `_analyst_edits_dir` — implements the analyst edits dir operation used by the surrounding reporting workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `reporting_stage_attempt`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include report_editing.py:export_report; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `incident_report_dir`, `reporting_attempt_dir`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _analyst_edits_dir(incident_id: str, run_id: str, reporting_stage_attempt: int) -> Path:
    """A folder that sits BESIDE (never inside) the hash-pinned exports/
    folder that reporting_approval.py re-verifies before every download —
    reuses editable_reports.incident_report_dir() for the same
    <attempt_dir>/<incident_id>/reports/ nesting convention, then adds a new
    leaf directory nothing else on the read side ever looks at."""
    attempt_dir = reporting_attempt_dir(incident_id, run_id, reporting_stage_attempt)
    return incident_report_dir(attempt_dir, incident_id) / "analyst_edits"


# [FYP-FUNCTION] `report_row_state` — implements the report row state operation used by the surrounding reporting workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `report_type`, `current_attempt`, `reporting_status`, `reporting_updated_at`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:_render_reports_workspace; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `bool`, `get`, `get_report_edit`, `loads`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def report_row_state(incident_id: str, run_id: str, report_type: str, *,
                     current_attempt: dict[str, Any], reporting_status: str,
                     reporting_updated_at: str | None) -> dict[str, Any]:
    """Merges the AI-generated original (already hash-verified by
    case_view.build_reporting()'s current_attempt) with the latest immutable
    report_versions row (report_edits' Phase-3 successor — see
    ensure_report_version_seeded()) and that row's report_reviews fact, and
    derives a single display status/timestamp/block-list for the Reports tab
    row and its editor. Never raises — worst case is "Not generated" with an
    empty block list, since this is called on every render just to decide
    what a row looks like."""
    reports_by_type = {r.get("report_type"): r for r in (current_attempt.get("reports") or [])}
    original_report = reports_by_type.get(report_type) or {}
    original_blocks = original_report.get("structured_content") or []
    current_report_set_id = current_attempt.get("report_set_id")

    # final_incident_report is deliberately NEVER seeded from the
    # generation pipeline's own independently-rendered original — Phase 5
    # (see _maybe_assemble_final_incident_report()) makes it authoritative
    # only from the assembled combination of the three reviewed component
    # reports, so its report_versions history starts empty until that
    # assembly writes its first row. This avoids ever surfacing the
    # independent AI draft as something reviewable in its own right, which
    # could contradict the reviewed component content.
    if original_blocks and report_type != "final_incident_report":
        wss.ensure_report_version_seeded(
            incident_id, run_id, report_type,
            ai_blocks=original_blocks, ai_report_set_id=current_report_set_id)

    latest = wss.get_latest_report_version(incident_id, run_id, report_type)
    review = wss.get_report_review(latest["id"]) if latest else None
    # origin-driven, NOT version-number-driven (an analyst edit can legally
    # land as version 1 whenever no AI content was ever seeded first — e.g.
    # a report that hasn't been generated yet still got a manual save).
    has_edits = bool(latest and latest.get("origin") == "analyst_edit")
    is_stale = bool(
        latest and latest.get("source_report_set_id") and current_report_set_id
        and latest["source_report_set_id"] != current_report_set_id)

    # Checked BEFORE has_edits: "Approved"/"Finalised" is a terminal state
    # that supersedes "Reviewed" once the exact current version has been
    # formally approved, regardless of whether that version's origin was
    # an analyst edit or the AI original — an analyst-authored version that
    # WAS the one approved must show "Approved", not get stuck on
    # "Reviewed" forever. It only ever applies when the version ids
    # actually match (see _resolve_approved_display_status), so an edit or
    # re-assembly since approval still correctly falls through below.
    approved_display = (
        _resolve_approved_display_status(incident_id, run_id, report_type, reporting_status, latest)
        if latest is not None else None)

    if latest is None:
        status = "Not generated"
    elif is_stale:
        status = "Regeneration required" if reporting_status in ("Processing", "Failed") else "Outdated"
    elif approved_display is not None:
        status = approved_display
    elif has_edits:
        status = "Reviewed" if review is not None else "Edited"
    else:
        status = resolve_report_status(latest, review)  # "Ready for Review" | "Reviewed"

    display_blocks = json.loads(latest["content_json"]) if latest else []
    last_saved_iso = latest.get("created_at") if latest else None

    return {
        "report_type": report_type,
        "title": DISPLAY_TITLES.get(report_type, report_type),
        "description": REPORT_DESCRIPTIONS.get(report_type, ""),
        "status": status,
        "tone": STATUS_TONES.get(status, "info"),
        "last_saved_iso": last_saved_iso,
        "has_edits": has_edits,
        "is_stale": is_stale,
        "blocks": display_blocks,
        "original_blocks": original_blocks,
        "edited_at": latest.get("created_at") if has_edits else None,
        "edited_by": latest.get("edited_by") if has_edits else None,
        "version": latest.get("version") if latest else 0,
        "current_report_set_id": current_report_set_id,
        "exists": bool(latest),
        "review_status": "Reviewed" if review is not None else None,
        "reviewed_by": review.get("reviewed_by") if review else None,
        "reviewed_at": review.get("reviewed_at") if review else None,
        "report_version_id": latest.get("id") if latest else None,
    }


# [FYP-FUNCTION] `save_report_edit` — persists or updates save report edit state used by the surrounding reporting workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `report_type`, `blocks`, `analyst`, `original_blocks`, `source_report_set_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:_render_report_editor; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `record_activity`, `upsert_report_edit`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def save_report_edit(incident_id: str, run_id: str, report_type: str,
                     blocks: list[dict[str, Any]], analyst: str,
                     *, original_blocks: list[dict[str, Any]] | None = None,
                     source_report_set_id: str | None) -> dict[str, Any]:
    """Persists the analyst's edited block list as a NEW immutable
    report_versions row (origin='analyst_edit') — never updates a prior
    version. `original_blocks` is accepted for call-site compatibility with
    backend/services/report_service.py but is no longer written anywhere:
    the AI-original snapshot is preserved as its own real version (v1, see
    ensure_report_version_seeded()) rather than a side column, so it never
    needs to be re-supplied on every save."""
    row = wss.create_report_version(
        incident_id, run_id, report_type,
        content=blocks, origin="analyst_edit", edited_by=analyst,
        source_report_set_id=source_report_set_id)
    wss.record_activity(
        incident_id, run_id, "reporting", "report_edit_saved", actor=analyst,
        metadata={"report_type": report_type, "version": row.get("version")})
    return row


# [FYP-FUNCTION] `discard_report_edit` — implements the discard report edit operation used by the surrounding reporting workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `report_type`, `analyst`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include app.py:<module>, app.py:_render_report_editor, app.py:_render_reports_workspace; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `discard_report_edit`, `record_activity`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def discard_report_edit(incident_id: str, run_id: str, report_type: str, analyst: str,
                        *, ai_blocks: list[dict[str, Any]], ai_report_set_id: str | None) -> dict[str, Any]:
    """"Replace with latest AI version" — under the Phase 3 immutable-version
    model this APPENDS a new version reverting to the current AI-generated
    content (origin='ai_generated'), rather than deleting the analyst's
    prior edit. Nothing is ever destroyed: the discarded edit remains
    visible as an earlier version in the report's history. Caller (backend/
    services/report_service.py) supplies ai_blocks/ai_report_set_id from the
    already-loaded current candidate, since this module never re-fetches
    case_view/generation output itself."""
    row = wss.create_report_version(
        incident_id, run_id, report_type,
        content=ai_blocks, origin="ai_generated", edited_by="Aegis",
        source_report_set_id=ai_report_set_id,
        change_summary=f"Reverted to the AI-generated version by {analyst}.")
    wss.record_activity(
        incident_id, run_id, "reporting", "report_edit_discarded", actor=analyst,
        metadata={"report_type": report_type})
    return row


def mark_reviewed(incident_id: str, run_id: str, report_type: str, analyst: str,
                  *, expected_report_version_id: int | None = None) -> dict[str, Any]:
    """The real, persisted "Mark as Reviewed" action (supersedes the
    interim frontend wiring to the soft, activity-log-only confirm_section
    endpoint). Records a report_reviews row against the CURRENT latest
    report_versions row — never mutates report_versions itself. If the
    analyst's editor loaded an older version than what's now latest
    (expected_report_version_id mismatch), refuses rather than silently
    reviewing content the analyst never actually saw."""
    latest = wss.get_latest_report_version(incident_id, run_id, report_type)
    if latest is None:
        raise ReportEditingError("This report has no saved content to review yet.")
    if (expected_report_version_id is not None
            and int(expected_report_version_id) != int(latest["id"])):
        raise ReportEditingError(
            "This report changed since it was loaded — reload before marking it reviewed.")
    row = wss.create_report_review(latest["id"], reviewed_by=analyst)
    wss.record_activity(
        incident_id, run_id, "reporting", "report_marked_reviewed", actor=analyst,
        metadata={"report_type": report_type, "report_version_id": latest["id"]})
    if report_type in COMPONENT_REPORT_TYPES:
        _maybe_assemble_final_incident_report(incident_id, run_id)
    return row


def _maybe_assemble_final_incident_report(incident_id: str, run_id: str) -> None:
    """Phase 5: (re)assembles the Final Incident Report the moment all
    three component reports (executive_summary, technical_findings,
    soc_analyst_review) are Reviewed on their current latest version — no
    LLM call, no Investigation re-run, content taken verbatim from those
    exact reviewed versions (see reporting.final_report_assembler).

    Idempotent and change-driven, per the approved design: records exactly
    which component version ids produced this assembly
    (source_version_ids_json). If the latest Final Incident Report version
    was already assembled from this EXACT set of version ids, does nothing.
    Otherwise appends a new 'assembled' version — Ready for Review again —
    even if the previous Final Incident Report version had itself already
    been analyst-edited or reviewed: that prior version is never mutated or
    deleted, only superseded, because a component changing underneath it
    means it may now be stale."""
    reviewed_sections: dict[str, list[dict[str, Any]]] = {}
    source_version_ids: dict[str, int] = {}
    for component_type in COMPONENT_REPORT_TYPES:
        latest_component = wss.get_latest_report_version(incident_id, run_id, component_type)
        if latest_component is None or wss.get_report_review(latest_component["id"]) is None:
            return  # not all three are reviewed yet
        reviewed_sections[component_type] = json.loads(latest_component["content_json"])
        source_version_ids[component_type] = latest_component["id"]

    existing_final = wss.get_latest_report_version(incident_id, run_id, "final_incident_report")
    if existing_final is not None:
        existing_source_ids = json.loads(existing_final.get("source_version_ids_json") or "null")
        if existing_source_ids == source_version_ids:
            return  # already assembled from exactly these reviewed versions

    assembled_blocks = assemble_final_incident_report(incident_id, reviewed_sections=reviewed_sections)
    wss.create_report_version(
        incident_id, run_id, "final_incident_report",
        content=assembled_blocks, origin="assembled", edited_by="Aegis",
        source_version_ids=source_version_ids,
        change_summary=("Assembled from the latest reviewed Executive Summary, "
                        "Technical Findings, and SOC Analyst Review."))
    wss.record_activity(
        incident_id, run_id, "reporting", "final_incident_report_assembled", actor="Aegis",
        metadata={"source_version_ids": source_version_ids})


def list_report_versions(incident_id: str, run_id: str, report_type: str) -> list[dict[str, Any]]:
    """Phase 4: full, newest-first version history for the Reports tab's
    version-history panel. Each entry carries its own review facts
    (report_reviews is a 1:1 join per version_id — a version reviewed at
    some point in the past stays "reviewed" in its own history entry even
    after a later edit made the report's CURRENT status "Edited" again;
    nothing here is inherited or re-derived across entries)."""
    rows = wss.list_report_versions(incident_id, run_id, report_type)
    return [
        {
            "report_version_id": row["id"],
            "version": row["version"],
            "origin": row["origin"],
            "edited_by": row["edited_by"],
            "created_at": row["created_at"],
            "change_summary": row.get("change_summary"),
            "review_status": row.get("review_status"),
            "reviewed_by": row.get("reviewed_by"),
            "reviewed_at": row.get("reviewed_at"),
            "blocks": json.loads(row["content_json"]),
        }
        for row in rows
    ]


# [FYP-FUNCTION] `export_report` — constructs export report output for the next reporting consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `report_type`, `file_type`, `row_state`, `reporting_stage_attempt`, `analyst`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:_cached_report_export_bytes; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `FileNotFoundError`, `ValueError`, `_analyst_edits_dir`, `mkdir`, `now`, `read_bytes`, `record_activity`, `render_blocks_to_docx`.
# [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

_APPROVED_DISPLAY_STATUSES = ("Approved", "Finalised")


def export_report(incident_id: str, run_id: str, report_type: str, file_type: str,
                  *, row_state: dict[str, Any], reporting_stage_attempt: int,
                  analyst: str) -> tuple[bytes, str]:
    """Phase 8: two distinct, never-conflated export paths.

    1. If row_state["status"] is "Approved"/"Finalised" — meaning
       report_row_state() has already confirmed the CURRENT version is
       EXACTLY the one baked into the latest approved report_sets row (see
       _resolve_approved_display_status()) — this serves the frozen,
       hash-verified bytes from that approved candidate set
       (reporting_approval.resolve_approved_report_file()) rather than
       rendering anything fresh. An approved export is always the literal
       file that was approved, never a fresh render that merely happens to
       look the same.
    2. Otherwise (draft/edited/reviewed-but-not-approved, or the approved
       file couldn't be resolved for some reason): renders the LATEST
       SAVED content fresh (row_state["blocks"] already encodes edited-if-
       present-else-AI-original precedence, see report_row_state()) to
       Word or PDF, reusing the same block-rendering utilities the
       Reporting pipeline itself uses, stamped with a "DRAFT — NOT
       APPROVED" watermark — writing into a folder that can never collide
       with the hash-pinned candidate export set.

    Returns (file_bytes, filename)."""
    if file_type not in ("docx", "pdf"):
        raise ValueError(f"Unsupported file_type: {file_type!r}")

    if row_state["status"] in _APPROVED_DISPLAY_STATUSES:
        approved = resolve_approved_report_file(incident_id, run_id, report_type, file_type)
        if approved is not None:
            data, _sha256 = approved
            filename = f"{report_type}_{incident_id}_approved.{file_type}"
            wss.record_activity(
                incident_id, run_id, "reporting", f"report_export_{file_type}", actor=analyst,
                metadata={"report_type": report_type, "source": "approved"})
            return data, filename

    blocks = row_state["blocks"]
    if not blocks:
        raise FileNotFoundError(f"No content available yet for {report_type}.")
    title = row_state["title"]
    out_dir = _analyst_edits_dir(incident_id, run_id, reporting_stage_attempt)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"{report_type}_{incident_id}_{stamp}.{file_type}"
    path = out_dir / filename
    # Always watermarked here — reached only when NOT serving the verified
    # approved bytes above, so this render must never be mistaken for the
    # official approved artefact even if the text happens to be identical.
    meta = {"confirmed_by": analyst, "watermark": "DRAFT — NOT APPROVED"}
    if file_type == "docx":
        render_blocks_to_docx(path, title, blocks, incident_id, meta)
    else:
        render_blocks_to_pdf(path, title, blocks, incident_id, meta)
    data = path.read_bytes()
    wss.record_activity(
        incident_id, run_id, "reporting", f"report_export_{file_type}", actor=analyst,
        metadata={"report_type": report_type, "has_edits": row_state["has_edits"],
                  "filename": filename, "source": "draft"})
    return data, filename


# [FYP-FUNCTION] `reporting_data_json` — implements the reporting data json operation used by the surrounding reporting workflow.
# [FYP-INPUT] Parameters: `state`, `incident_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:_render_reports_workspace; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `dumps`, `encode`, `get`, `isoformat`, `loads`, `now`, `strftime`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def reporting_data_json(state: dict[str, Any], incident_id: str) -> tuple[bytes, str]:
    """"Reporting Data / Download JSON" — re-serializes the same
    reporting_result_json blob already sitting in the incidents row (the
    structured data the Reporting pipeline used to generate the reports),
    with no filesystem access needed."""
    try:
        payload = json.loads(state.get("reporting_result_json") or "{}")
    except Exception:
        payload = {}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"reporting_data_{incident_id}_{stamp}.json"
    data = json.dumps(
        {"incident_id": incident_id, "generated_at": datetime.now(timezone.utc).isoformat(),
         "reporting_data": payload},
        indent=2, default=str).encode("utf-8")
    return data, filename


def submit_for_approval(incident_id: str, run_id: str, reporting_stage_attempt: int, *,
                        analyst: str) -> dict[str, Any]:
    """Phase 6: the gate + trigger for "Submit for Approval". Refuses
    unless all four core reports are currently Reviewed on their latest
    version (no approval submission without full review — the approved
    report set must be exactly what was reviewed, never a stale or
    unreviewed draft), then materialises a new, immutable reviewed
    candidate set — a sibling of, never a mutation of, the original
    AI-generated candidate_manifest.json.

    `based_on_report_set_id` lineage: prefers the most recently APPROVED
    report_sets row (a later reviewed submission is "based on" whatever was
    last approved, not the original draft), falling back to the original
    'generated' row if nothing has been approved yet.

    Registers the result as a new report_sets row (status='materialised')
    — Phase 7's approve_reporting_candidate() is what later flips that row
    to 'approved'; this function never approves anything itself.

    Returns the published candidate manifest dict."""
    reviewed_reports: dict[str, dict[str, Any]] = {}
    for report_type in CORE_REPORT_TYPES:
        latest = wss.get_latest_report_version(incident_id, run_id, report_type)
        review = wss.get_report_review(latest["id"]) if latest else None
        if latest is None or review is None:
            raise ReportEditingError(
                f"'{DISPLAY_TITLES.get(report_type, report_type)}' must be marked Reviewed "
                "before this report set can be submitted for approval.")
        reviewed_reports[report_type] = {
            "version_id": latest["id"],
            "blocks": json.loads(latest["content_json"]),
        }

    based_on = (wss.get_latest_report_set(incident_id, run_id, status="approved")
               or wss.get_latest_report_set(incident_id, run_id, status="generated"))
    based_on_report_set_id = based_on["report_set_id"] if based_on else None

    # Matches workflow/engine.py's own reporting_output_dir = attempt_dir /
    # "outputs" convention (what REPORTING_OUTPUT_DIR is actually set to for
    # the Reporting subprocess, and therefore what editable_reports.
    # finalize_candidate_manifest()'s own `output_dir` argument really is)
    # — required so reporting_approval._resolve_trusted_path()'s relative-
    # path reconstruction (attempt_dir / manifest's stored relative path)
    # lands on the real file instead of a doubled/wrong path.
    output_dir = reporting_attempt_dir(incident_id, run_id, reporting_stage_attempt) / "outputs"
    try:
        manifest, manifest_file = materialise_reviewed_candidate(
            output_dir, incident_id, run_id, reporting_stage_attempt,
            reviewed_reports=reviewed_reports,
            based_on_report_set_id=based_on_report_set_id,
            analyst=analyst)
    except CandidateMaterialisationError as exc:
        raise ReportEditingError(str(exc)) from exc

    report_set_id = manifest["report_set_id"]
    wss.create_report_set(
        incident_id, run_id,
        report_set_id=report_set_id,
        based_on_report_set_id=based_on_report_set_id,
        manifest_path=str(manifest_file),
        manifest_sha256=manifest["candidate_manifest_sha256"],
        report_version_ids={rt: entry["version_id"] for rt, entry in reviewed_reports.items()},
        status="materialised", created_by=analyst)
    wss.record_activity(
        incident_id, run_id, "reporting", "reviewed_candidate_materialised", actor=analyst,
        metadata={"report_set_id": report_set_id, "based_on_report_set_id": based_on_report_set_id})
    return manifest
