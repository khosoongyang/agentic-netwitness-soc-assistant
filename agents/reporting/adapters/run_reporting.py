# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, adapters, backend, datetime, json, os, pathlib, shutil.
# =============================================================================
# File: soc_reporting_agent/adapters/run_reporting.py
# Purpose: This module provides the command-line adapter for the reporting stage.
# Main functionality: _copy_first_existing, _prepare_inputs, _clean, _first, _iso_to_ts, _is_new_enough.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis stage adapter component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, adapters, backend, datetime, json, os, pathlib, shutil.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: _copy_first_existing, _prepare_inputs, _clean, _first, _iso_to_ts, _is_new_enough, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT_BOOTSTRAP = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT_BOOTSTRAP) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT_BOOTSTRAP))
# Phase 8: template_document_exporter.py (lazily imported by
# reporting.editable_reports for PDF conversion) now reaches
# integrations.openai.client and agents.reporting.export_cache - both
# repo-root packages, outside this subprocess's own PROJECT_ROOT_BOOTSTRAP.
# Also guards against agents/reporting/agents/ (the donor reporting_agent.py)
# shadowing the real top-level agents/ package the same way Batch C's
# run_parser_normalisation.py fix does.
REPO_ROOT_BOOTSTRAP = str(PROJECT_ROOT_BOOTSTRAP.parent.parent)
sys.path = [p for p in sys.path if p != REPO_ROOT_BOOTSTRAP]
sys.path.insert(0, REPO_ROOT_BOOTSTRAP)

from adapters.common import INPUTS_DIR, OUTPUTS_DIR, PROJECT_ROOT, copy_if_exists, latest_file, now_iso, read_json, run_script, write_json
from backend.reporting_context_resolver import ensure_reporting_inputs


# =============================================================================
# [FYP-SECTION] STAGE ADAPTER EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `_copy_first_existing` — implements the copy first existing operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `candidates`, `dest`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_prepare_inputs; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `copy2`, `exists`, `mkdir`, `resolve`, `stat`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _copy_first_existing(candidates: list[Path], dest: Path) -> bool:
    for path in candidates:
        if path.exists() and path.stat().st_size > 0:
            if path.resolve() != dest.resolve():
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dest)
            return True
    return False


# [FYP-FUNCTION] `_prepare_inputs` — implements the prepare inputs operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `ticket_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_copy_first_existing`, `copy_if_exists`, `ensure_reporting_inputs`, `exists`, `extend`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _prepare_inputs(ticket_id: str | None = None) -> None:
    copy_if_exists(OUTPUTS_DIR / "triage_result.json", INPUTS_DIR / "triage_result.json")
    inv_candidates = []
    approval_candidates = []
    if ticket_id:
        inv_candidates.extend([
            OUTPUTS_DIR / ticket_id / "investigation" / "investigation_result.json",
            OUTPUTS_DIR / ticket_id / "investigation_result.json",
        ])
        approval_candidates.extend([
            OUTPUTS_DIR / ticket_id / "investigation_approval_result.json",
            OUTPUTS_DIR / ticket_id / "approval" / "investigation_approval_result.json",
        ])
    inv_candidates.extend([
        OUTPUTS_DIR / "investigation_result.json",
        INPUTS_DIR / "investigation_result.json",
        OUTPUTS_DIR / "unknown" / "investigation_result.json",
    ])
    approval_candidates.extend([
        OUTPUTS_DIR / "investigation_approval_result.json",
        INPUTS_DIR / "investigation_approval_result.json",
        OUTPUTS_DIR / "approval_result.json",
        INPUTS_DIR / "approval_result.json",
    ])
    _copy_first_existing(inv_candidates, INPUTS_DIR / "investigation_result.json")
    _copy_first_existing(approval_candidates, INPUTS_DIR / "approval_result.json")
    ensure_reporting_inputs(PROJECT_ROOT, ticket_id=ticket_id)
    if not (INPUTS_DIR / "enriched_alert.json").exists():
        copy_if_exists(OUTPUTS_DIR / "enriched_alert.json", INPUTS_DIR / "enriched_alert.json")


# [FYP-FUNCTION] `_clean` — implements the clean operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:env_load, soc_reporting_agent/adapters/run_reporting.py:_first, soc_reporting_agent/services/parser_context_guard.py:_title_clean; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `isinstance`, `lower`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _clean(value: Any) -> Any:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, str) and value.strip().lower() in {"unknown", "unknown-incident", "inc-0001", "not provided", "untitled"}:
        return None
    return value


# [FYP-FUNCTION] `_first` — implements the first operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `default`, `*values`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include compliance_evidence.py:_build, compliance_evidence.py:_triage_bits, soc_reporting_agent/adapters/run_reporting.py:_normalise_reporting_result; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_clean`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _first(*values: Any, default: Any = None) -> Any:
    for value in values:
        cleaned = _clean(value)
        if cleaned is not None:
            return cleaned
    return default


# [FYP-FUNCTION] `_iso_to_ts` — implements the iso to ts operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_normalise_reporting_result; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `fromisoformat`, `replace`, `str`, `timestamp`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _iso_to_ts(value: Any) -> float | None:
    try:
        if not value:
            return None
        text = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return None


# [FYP-FUNCTION] `_is_new_enough` — evaluates is new enough conditions so invalid or unsafe stage adapter processing is stopped early.
# [FYP-INPUT] Parameters: `path`, `started_ts`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_find_reporting_result, soc_reporting_agent/adapters/run_reporting.py:_has_report_artifacts, soc_reporting_agent/adapters/run_reporting.py:_latest_manifest; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `exists`, `stat`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _is_new_enough(path: Path, started_ts: float | None) -> bool:
    if not path.exists() or path.stat().st_size == 0:
        return False
    if started_ts is None:
        return True
    # Allow a small clock-resolution tolerance for files written at process start.
    return path.stat().st_mtime >= started_ts - 1.0


# [FYP-FUNCTION] `_run_succeeded` — orchestrates the run succeeded entry point and its ordered stage adapter operations.
# [FYP-INPUT] Parameters: `run_result`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_normalise_reporting_result; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `bool`, `get`, `int`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _run_succeeded(run_result: dict[str, Any]) -> bool:
    return bool(run_result.get("success")) and int(run_result.get("returncode", 1)) == 0


# [FYP-FUNCTION] `_normalise_status` — transforms normalise status input into the stable representation required by downstream stage adapter processing.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_has_limitations; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `lower`, `replace`, `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _normalise_status(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


# [FYP-FUNCTION] `_has_limitations` — evaluates has limitations conditions so invalid or unsafe stage adapter processing is stopped early.
# [FYP-INPUT] Parameters: `inv`, `approval`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_resolve_reporting_mode; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_normalise_status`, `bool`, `get`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _has_limitations(inv: dict[str, Any], approval: dict[str, Any]) -> bool:
    status = _normalise_status(inv.get("status") or inv.get("workflow_decision"))
    limited_statuses = {
        "completed_limited",
        "completed_with_warnings",
        "completed_with_evidence_gaps",
        "needs_more_data",
        "waiting_for_telemetry",
        "insufficient_telemetry",
        "partial",
        "partial_success",
        "needs_analyst_review",
    }
    return (
        status in limited_statuses
        or bool(inv.get("missing_evidence") or inv.get("missing_fields"))
        or _normalise_status(approval.get("reporting_mode")) == "with_limitations"
        or _normalise_status(inv.get("reporting_mode")) == "with_limitations"
    )


# [FYP-FUNCTION] `_resolve_reporting_mode` — implements the resolve reporting mode operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `inv`, `approval`, `wrapper`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_normalise_reporting_result; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_first`, `_has_limitations`, `get`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _resolve_reporting_mode(inv: dict[str, Any], approval: dict[str, Any], wrapper: dict[str, Any] | None = None) -> str:
    explicit = _first(
        approval.get("reporting_mode"),
        approval.get("approved_reporting_mode"),
        inv.get("reporting_mode"),
        (wrapper or {}).get("reporting_mode"),
        default=None,
    )
    if explicit:
        return str(explicit)
    return "with_limitations" if _has_limitations(inv, approval) else "standard"


# [FYP-FUNCTION] `_limitations` — implements the limitations operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `inv`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_normalise_reporting_result; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `isinstance`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _limitations(inv: dict[str, Any]) -> list[Any]:
    value = inv.get("missing_evidence") or inv.get("limitations") or inv.get("missing_fields") or []
    if isinstance(value, list):
        return value
    return [value] if value else []


# [FYP-FUNCTION] `_error_summary` — implements the error summary operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `run_result`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_normalise_reporting_result; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `len`, `reversed`, `splitlines`, `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _error_summary(run_result: dict[str, Any]) -> str:
    stderr = str(run_result.get("stderr") or "").strip()
    stdout = str(run_result.get("stdout") or "").strip()
    text = stderr or stdout or "Reporting Agent failed before generating report sections."
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in reversed(lines):
        if "Error" in line or "Exception" in line or "UndefinedError" in line or "Traceback" not in line:
            if len(line) > 500:
                return line[:497] + "..."
            return line
    return lines[-1][:500] if lines else "Reporting Agent failed before generating report sections."


# [FYP-FUNCTION] `_clear_stale_reporting_wrappers` — persists or updates clear stale reporting wrappers state used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `ticket_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `exists`, `extend`, `unlink`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _clear_stale_reporting_wrappers(ticket_id: str | None = None) -> None:
    candidates = [
        OUTPUTS_DIR / "reporting_result.json",
        INPUTS_DIR / "reporting_result.json",
        OUTPUTS_DIR / "final_report.json",
    ]
    if ticket_id:
        candidates.extend([
            OUTPUTS_DIR / ticket_id / "reporting" / "reporting_result.json",
            OUTPUTS_DIR / ticket_id / "reporting" / "final_report.json",
            OUTPUTS_DIR / ticket_id / "reporting_result.json",
        ])
    for path in candidates:
        try:
            if path.exists():
                path.unlink()
        except Exception:
            pass


# [FYP-FUNCTION] `_artifact_candidates` — implements the artifact candidates operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `ticket_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_find_reporting_result; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `add`, `append`, `exists`, `extend`, `latest_file`, `resolve`, `set`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _artifact_candidates(ticket_id: str | None = None) -> list[Path]:
    candidates: list[Path] = []
    if ticket_id:
        candidates.extend([
            OUTPUTS_DIR / ticket_id / "reporting" / "reporting_result.json",
            OUTPUTS_DIR / ticket_id / "reporting_result.json",
            OUTPUTS_DIR / ticket_id / "reports" / "report_manifest.json",
            OUTPUTS_DIR / ticket_id / "reporting" / "final_report.json",
        ])
    candidates.extend([
        OUTPUTS_DIR / "final_report.json",
        OUTPUTS_DIR / "reporting_result.json",
        latest_file("*/reporting_result.json", OUTPUTS_DIR) or Path("/__missing__"),
        latest_file("*/reports/report_manifest.json", OUTPUTS_DIR) or Path("/__missing__"),
        latest_file("*/reports/editable/final_incident_report.txt", OUTPUTS_DIR) or Path("/__missing__"),
        latest_file("*/final_report.txt", OUTPUTS_DIR) or Path("/__missing__"),
    ])
    out: list[Path] = []
    seen: set[str] = set()
    for p in candidates:
        if p and str(p) != "/__missing__":
            key = str(p.resolve()) if p.exists() else str(p)
            if key not in seen:
                out.append(p)
                seen.add(key)
    return out


# [FYP-FUNCTION] `_find_reporting_result` — implements the find reporting result operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `ticket_id`, `started_ts`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_normalise_reporting_result; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_artifact_candidates`, `_is_new_enough`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _find_reporting_result(ticket_id: str | None = None, started_ts: float | None = None) -> Path | None:
    for path in _artifact_candidates(ticket_id):
        if path.name == "reporting_result.json" and _is_new_enough(path, started_ts):
            return path
    return None


# [FYP-FUNCTION] `_real_report_artifact_paths` — implements the real report artifact paths operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `ticket_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_has_report_artifacts; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `add`, `append`, `exists`, `extend`, `latest_file`, `resolve`, `set`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _real_report_artifact_paths(ticket_id: str | None = None) -> list[Path]:
    paths: list[Path] = []
    if ticket_id:
        paths.extend([
            OUTPUTS_DIR / ticket_id / "reports" / "report_manifest.json",
            OUTPUTS_DIR / ticket_id / "reports" / "editable" / "final_incident_report.txt",
            OUTPUTS_DIR / ticket_id / "reports" / "drafts" / "final_incident_report.txt",
            OUTPUTS_DIR / ticket_id / "reporting" / "report_manifest.json",
        ])
    latest_manifest = latest_file("*/reports/report_manifest.json", OUTPUTS_DIR)
    latest_final = latest_file("*/reports/editable/final_incident_report.txt", OUTPUTS_DIR)
    latest_draft = latest_file("*/reports/drafts/final_incident_report.txt", OUTPUTS_DIR)
    for p in (latest_manifest, latest_final, latest_draft):
        if p:
            paths.append(p)
    out: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path.resolve()) if path.exists() else str(path)
        if key not in seen:
            out.append(path)
            seen.add(key)
    return out


# [FYP-FUNCTION] `_has_report_artifacts` — evaluates has report artifacts conditions so invalid or unsafe stage adapter processing is stopped early.
# [FYP-INPUT] Parameters: `ticket_id`, `started_ts`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_normalise_reporting_result; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_is_new_enough`, `_real_report_artifact_paths`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _has_report_artifacts(ticket_id: str | None = None, started_ts: float | None = None) -> bool:
    for path in _real_report_artifact_paths(ticket_id):
        if _is_new_enough(path, started_ts):
            return True
    return False


# [FYP-FUNCTION] `_latest_manifest` — implements the latest manifest operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `ticket_id`, `started_ts`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_normalise_reporting_result; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_is_new_enough`, `append`, `extend`, `latest_file`, `read_json`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _latest_manifest(ticket_id: str | None = None, started_ts: float | None = None) -> dict[str, Any]:
    paths: list[Path] = []
    if ticket_id:
        paths.extend([
            OUTPUTS_DIR / ticket_id / "reports" / "report_manifest.json",
            OUTPUTS_DIR / ticket_id / "reporting" / "report_manifest.json",
        ])
    latest = latest_file("*/reports/report_manifest.json", OUTPUTS_DIR)
    if latest:
        paths.append(latest)
    for path in paths:
        data = read_json(path, {}) if path and _is_new_enough(path, started_ts) else {}
        if data:
            return data
    return {}


# [FYP-FUNCTION] `_copy_report_artifacts` — implements the copy report artifacts operation used by the surrounding stage adapter workflow.
# [FYP-INPUT] Parameters: `ticket_id`, `wrapper`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:_normalise_reporting_result; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `mkdir`, `write_json`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _copy_report_artifacts(ticket_id: str | None, wrapper: dict[str, Any]) -> None:
    if not ticket_id:
        return
    ticket_dir = OUTPUTS_DIR / ticket_id / "reporting"
    ticket_dir.mkdir(parents=True, exist_ok=True)
    write_json(ticket_dir / "reporting_result.json", wrapper)
    write_json(OUTPUTS_DIR / "reporting_result.json", wrapper)
    write_json(INPUTS_DIR / "reporting_result.json", wrapper)


# [FYP-FUNCTION] `_normalise_reporting_result` — transforms normalise reporting result input into the stable representation required by downstream stage adapter processing.
# [FYP-INPUT] Parameters: `run_result`, `ticket_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_reporting.py:main, soc_reporting_agent/scripts/test_evidence_gap_branch_and_reporting_wrapper.py:test_reporting_wrapper_backfill, soc_reporting_agent/scripts/test_reporting_appendix_context.py:test_failed_subprocess_not_completed; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_copy_report_artifacts`, `_error_summary`, `_find_reporting_result`, `_first`, `_has_report_artifacts`, `_is_new_enough`, `_iso_to_ts`, `_latest_manifest`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _normalise_reporting_result(run_result: dict, ticket_id: str | None = None) -> dict[str, Any]:
    started_ts = _iso_to_ts(run_result.get("started_at"))
    result_path = _find_reporting_result(ticket_id, started_ts=started_ts)
    final_txt_path = latest_file("*/reports/editable/final_incident_report.txt", OUTPUTS_DIR) or latest_file("*/final_report.txt", OUTPUTS_DIR)
    if final_txt_path and _is_new_enough(final_txt_path, started_ts):
        shutil.copy2(final_txt_path, OUTPUTS_DIR / "final_report.txt")

    generated = read_json(result_path, {}) if result_path else {}
    processed = read_json(INPUTS_DIR / "processed_alert.json", {}) or read_json(OUTPUTS_DIR / "processed_alert.json", {}) or {}
    enriched = read_json(INPUTS_DIR / "enriched_alert.json", {}) or read_json(OUTPUTS_DIR / "enriched_alert.json", {}) or {}
    triage = read_json(OUTPUTS_DIR / "triage_result.json", {}) or read_json(INPUTS_DIR / "triage_result.json", {}) or {}
    inv = read_json(OUTPUTS_DIR / "investigation_result.json", {}) or read_json(INPUTS_DIR / "investigation_result.json", {}) or read_json(OUTPUTS_DIR / "unknown" / "investigation_result.json", {}) or {}
    approval = read_json(OUTPUTS_DIR / "investigation_approval_result.json", {}) or read_json(INPUTS_DIR / "investigation_approval_result.json", {}) or {}
    manifest = _latest_manifest(ticket_id, started_ts=started_ts)

    if generated:
        wrapper = dict(generated)
        wrapper.setdefault("agent", "Reporting Agent")
        wrapper.setdefault("agent_source", "agents/reporting_agent.py")
        reports = wrapper.get("generated_reports") or {}
        has_reports = bool(reports or manifest)
        if _run_succeeded(run_result):
            wrapper["status"] = "completed"
            wrapper["report_status"] = wrapper.get("report_status") or "completed"
        elif has_reports:
            wrapper["status"] = "completed_with_warnings"
            wrapper["report_status"] = "completed_with_warnings"
        else:
            wrapper["status"] = "failed"
            wrapper["report_status"] = "failed"
        wrapper.setdefault("ticket_id", ticket_id)
        wrapper["incident_id"] = _first(processed.get("incident_id"), enriched.get("incident_id"), triage.get("incident_id"), inv.get("incident_id"), wrapper.get("incident_id"), default=ticket_id or "INC-0001")
        wrapper["alert_id"] = _first(processed.get("alert_id"), enriched.get("alert_id"), triage.get("alert_id"), inv.get("alert_id"), wrapper.get("alert_id"), default="UNKNOWN-ALERT")
        wrapper["title"] = _first(processed.get("alert_title"), processed.get("alert_name"), enriched.get("alert_title"), enriched.get("alert_name"), triage.get("title"), inv.get("title"), wrapper.get("title"), default="SOC incident")
        wrapper["reporting_mode"] = _resolve_reporting_mode(inv, approval, wrapper)
        wrapper["investigation_status"] = inv.get("status") or wrapper.get("investigation_status")
        wrapper["investigation_limitations"] = _limitations(inv) or wrapper.get("investigation_limitations") or []
        wrapper["limitations"] = wrapper.get("limitations") or wrapper["investigation_limitations"]
        if wrapper["status"] == "failed":
            wrapper["summary"] = "Reporting Agent failed before generating report sections."
            wrapper["error_summary"] = _error_summary(run_result)
        wrapper["report_manifest"] = manifest or wrapper.get("report_manifest") or {}
        wrapper["dashboard_copy_created_at"] = now_iso()
        wrapper["real_reporting_result_path"] = str(result_path.relative_to(PROJECT_ROOT)) if result_path else None
        wrapper["final_report_text_path"] = str(final_txt_path.relative_to(PROJECT_ROOT)) if final_txt_path else None
        wrapper["subprocess"] = run_result
        _copy_report_artifacts(ticket_id, wrapper)
        return wrapper

    artifacts_exist = _has_report_artifacts(ticket_id, started_ts=started_ts)
    fallback_status = "completed" if _run_succeeded(run_result) and artifacts_exist else ("completed_with_warnings" if artifacts_exist else "failed")
    wrapper = {
        "agent": "Reporting Agent",
        "agent_source": "agents/reporting_agent.py",
        "status": fallback_status,
        "report_status": fallback_status,
        "ticket_id": ticket_id,
        "incident_id": _first(processed.get("incident_id"), enriched.get("incident_id"), triage.get("incident_id"), inv.get("incident_id"), default=ticket_id or "INC-0001"),
        "alert_id": _first(processed.get("alert_id"), enriched.get("alert_id"), triage.get("alert_id"), inv.get("alert_id"), default="UNKNOWN-ALERT"),
        "title": _first(processed.get("alert_title"), processed.get("alert_name"), enriched.get("alert_title"), enriched.get("alert_name"), triage.get("title"), inv.get("title"), default="SOC incident"),
        "reporting_mode": _resolve_reporting_mode(inv, approval),
        "summary": (
            "Reporting completed and a dashboard reporting_result.json wrapper was generated from report artefacts."
            if fallback_status == "completed" else
            "Reporting completed with warnings. A dashboard reporting_result.json wrapper was generated from available report artefacts."
            if artifacts_exist else
            "Reporting Agent failed before generating report sections."
        ),
        "error_summary": None if artifacts_exist or _run_succeeded(run_result) else _error_summary(run_result),
        "limitations": _limitations(inv),
        "investigation_status": inv.get("status"),
        "investigation_limitations": _limitations(inv),
        "report_manifest": manifest,
        "generated_reports": manifest.get("sections", {}) if isinstance(manifest, dict) else {},
        "recommended_next_action": "Review the generated report sections and confirm SOC Analyst Review." if artifacts_exist else "Fix the Reporting Agent error and rerun Reporting.",
        "subprocess": run_result,
        "created_at": now_iso(),
    }
    _copy_report_artifacts(ticket_id, wrapper)
    return wrapper


# [FYP-FUNCTION] `main` — orchestrates the main entry point and its ordered stage adapter operations.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis stage adapter workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:<module>, eval_harness.py:<module>, soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `RuntimeError`, `_clear_stale_reporting_wrappers`, `_normalise_reporting_result`, `_prepare_inputs`, `bool`, `get`, `getenv`, `int`.
# [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

def main() -> int:
    strict = os.getenv("STRICT_AGENT_MODE", "false").lower() == "true"
    ticket_id = os.getenv("SOC_TICKET_ID") or None
    _prepare_inputs(ticket_id=ticket_id)
    _clear_stale_reporting_wrappers(ticket_id=ticket_id)
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    key_looks_real = bool(openai_key and not openai_key.lower().startswith("replace_with"))
    use_llm = os.getenv("REPORTING_USE_LLM", "true").lower() == "true" and key_looks_real
    extra_env = {
        "REPORTING_USE_LLM": "true" if use_llm else "false",
        "REPORTING_LLM_PROVIDER": os.getenv("REPORTING_LLM_PROVIDER", "openai"),
        "REPORTING_LLM_MODEL": os.getenv("REPORTING_LLM_MODEL", os.getenv("OPENAI_MODEL", "gpt-4o-mini")),
        "REPORTING_INPUT_DIR": str(INPUTS_DIR),
        "REPORTING_OUTPUT_DIR": str(OUTPUTS_DIR),
    }
    if ticket_id:
        extra_env["SOC_TICKET_ID"] = ticket_id
    print("[Reporting Adapter] Running original reporting agent with OpenAI settings from .env")
    run_result = run_script(PROJECT_ROOT / "agents" / "reporting_agent.py", timeout=int(os.getenv("REPORTING_TIMEOUT", "420")), extra_env=extra_env)
    if strict and not run_result.get("success"):
        raise RuntimeError(run_result.get("stderr") or "Reporting agent failed")
    output = _normalise_reporting_result(run_result, ticket_id=ticket_id)
    write_json(OUTPUTS_DIR / "final_report.json", output)
    write_json(OUTPUTS_DIR / "reporting_result.json", output)
    write_json(INPUTS_DIR / "reporting_result.json", output)
    print(f"[Reporting Adapter] Wrote {OUTPUTS_DIR / 'final_report.json'}")
    if ticket_id:
        print(f"[Reporting Adapter] Wrote {OUTPUTS_DIR / ticket_id / 'reporting' / 'reporting_result.json'}")
    print(f"[Reporting Adapter] Status: {output.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
