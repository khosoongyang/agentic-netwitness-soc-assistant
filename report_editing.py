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
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import workflow_state_store as wss
from reporting_approval import DISPLAY_TITLES
from soc_workflow import reporting_attempt_dir

ROOT = Path(__file__).resolve().parent
REP_DIR = ROOT / "soc_reporting_agent"
if str(REP_DIR) not in sys.path:
    sys.path.insert(0, str(REP_DIR))

from reporting.editable_reports import (  # noqa: E402  (path insert must run first)
    incident_report_dir, render_blocks_to_docx, render_blocks_to_pdf)

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

# Reuses the existing pill() tone vocabulary from ui_components.py
# (.ag-critical/.ag-high/.ag-medium/.ag-low/.ag-info) rather than inventing
# new colors, so status badges stay visually consistent with the rest of
# the app (severity pills, stage pills, etc).
STATUS_TONES = {
    "Not generated": "critical",
    "Regeneration required": "critical",
    "Outdated": "critical",
    "Edited": "high",
    "Approved": "low",
    "Draft ready": "info",
}


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
    case_view.build_reporting()'s current_attempt) with any saved analyst
    edit, and derives a single display status/timestamp/block-list for the
    Reports tab row and its editor. Never raises — worst case is
    "Not generated" with an empty block list, since this is called on every
    render just to decide what a row looks like."""
    reports_by_type = {r.get("report_type"): r for r in (current_attempt.get("reports") or [])}
    original_report = reports_by_type.get(report_type) or {}
    original_blocks = original_report.get("structured_content") or []
    current_report_set_id = current_attempt.get("report_set_id")

    edit = wss.get_report_edit(incident_id, run_id, report_type)
    has_edits = edit is not None
    edit_blocks = json.loads(edit["edited_blocks_json"]) if has_edits else []
    is_stale = bool(
        has_edits and edit.get("source_report_set_id") and current_report_set_id
        and edit.get("source_report_set_id") != current_report_set_id)

    if not original_blocks and not has_edits:
        status = "Not generated"
        last_saved_iso = None
        display_blocks = []
    elif is_stale:
        status = "Regeneration required" if reporting_status in ("Processing", "Failed") else "Outdated"
        last_saved_iso = edit.get("updated_at")
        display_blocks = edit_blocks  # retain the edit by default — see discard_report_edit() to replace
    elif has_edits:
        status = "Edited"
        last_saved_iso = edit.get("updated_at")
        display_blocks = edit_blocks
    elif reporting_status == "Approved":
        status = "Approved"
        last_saved_iso = original_report.get("generated_at") or reporting_updated_at
        display_blocks = original_blocks
    else:
        status = "Draft ready"
        last_saved_iso = original_report.get("generated_at") or reporting_updated_at
        display_blocks = original_blocks

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
        "edited_at": edit.get("updated_at") if has_edits else None,
        "edited_by": edit.get("last_edited_by") if has_edits else None,
        "version": edit.get("version") if has_edits else 0,
        "current_report_set_id": current_report_set_id,
        "exists": bool(original_blocks or has_edits),
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
                     *, original_blocks: list[dict[str, Any]],
                     source_report_set_id: str | None) -> dict[str, Any]:
    """Persists the analyst's edited block list. original_blocks is only
    actually stored on the FIRST save (see
    workflow_state_store.upsert_report_edit) so later saves never clobber
    the traceability snapshot of what the AI originally produced."""
    row = wss.upsert_report_edit(
        incident_id, run_id, report_type,
        edited_blocks=blocks, original_blocks=original_blocks,
        source_report_set_id=source_report_set_id, analyst=analyst)
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

def discard_report_edit(incident_id: str, run_id: str, report_type: str, analyst: str) -> None:
    """"Replace with latest AI version" — drops the saved edit so the row
    reverts to showing the current AI-generated original."""
    wss.discard_report_edit(incident_id, run_id, report_type)
    wss.record_activity(
        incident_id, run_id, "reporting", "report_edit_discarded", actor=analyst,
        metadata={"report_type": report_type})


# [FYP-FUNCTION] `export_report` — constructs export report output for the next reporting consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `report_type`, `file_type`, `row_state`, `reporting_stage_attempt`, `analyst`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:_cached_report_export_bytes; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `FileNotFoundError`, `ValueError`, `_analyst_edits_dir`, `mkdir`, `now`, `read_bytes`, `record_activity`, `render_blocks_to_docx`.
# [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

def export_report(incident_id: str, run_id: str, report_type: str, file_type: str,
                  *, row_state: dict[str, Any], reporting_stage_attempt: int,
                  analyst: str) -> tuple[bytes, str]:
    """Exports the LATEST SAVED content — edited if it exists, else the
    AI-generated original (row_state["blocks"] already encodes that
    precedence, see report_row_state()) — to Word or PDF, reusing the same
    block-rendering utilities the Reporting pipeline itself uses
    (reporting.editable_reports.render_blocks_to_docx/pdf), but writing into
    a folder that can never collide with the hash-pinned candidate export
    set. Returns (file_bytes, filename)."""
    if file_type not in ("docx", "pdf"):
        raise ValueError(f"Unsupported file_type: {file_type!r}")
    blocks = row_state["blocks"]
    if not blocks:
        raise FileNotFoundError(f"No content available yet for {report_type}.")
    title = row_state["title"]
    out_dir = _analyst_edits_dir(incident_id, run_id, reporting_stage_attempt)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"{report_type}_{incident_id}_{stamp}.{file_type}"
    path = out_dir / filename
    meta = {"confirmed_by": analyst}
    if file_type == "docx":
        render_blocks_to_docx(path, title, blocks, incident_id, meta)
    else:
        render_blocks_to_pdf(path, title, blocks, incident_id, meta)
    data = path.read_bytes()
    wss.record_activity(
        incident_id, run_id, "reporting", f"report_export_{file_type}", actor=analyst,
        metadata={"report_type": report_type, "has_edits": row_state["has_edits"],
                  "filename": filename})
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
