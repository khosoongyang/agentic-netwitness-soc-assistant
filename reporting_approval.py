# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, hashlib, json, pathlib, soc_workflow, typing, workflow_state_store.
# =============================================================================
# File: reporting_approval.py
# Purpose: This module validates and records human approval decisions for reporting outputs.
# Main functionality: ReportValidationError, _resolve_trusted_path, _canonical_manifest_bytes, _verify_candidate_manifest, approve_reporting_candidate, resolve_approved_report_file.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis reporting component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, hashlib, json, pathlib, soc_workflow, typing, workflow_state_store.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: ReportValidationError, _resolve_trusted_path, _canonical_manifest_bytes, _verify_candidate_manifest, approve_reporting_candidate, resolve_approved_report_file, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

"""
reporting_approval.py — the ONLY caller of
workflow_state_store.commit_reporting_approval(), and the sole place that
validates a Reporting candidate set before approving it.

Layering (see workflow_state_store.py's own module docstring for the
symmetric statement from its side): workflow_state_store.py is a pure
database layer — SQLite schema, atomic compare-and-swap, approval-history
insertion, workflow-state transitions — and must never touch the
filesystem. This module is where filesystem/hash/DOCX/PDF/manifest
validation actually happens; it calls into workflow_state_store only once
it has already fully validated the candidate set, handing over
already-computed metadata for a pure DB write. app.py's Reporting tab
calls approve_reporting_candidate() directly — never
workflow_state_store.commit_reporting_approval() itself — so there is
exactly one place in the whole app that can approve a Reporting candidate
set, and it always validates first.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import workflow_state_store as wss
from soc_workflow import _TRUSTED_OUTPUT_ROOT, reporting_attempt_dir


# =============================================================================
# [FYP-SECTION] REPORTING EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-CLASS] `ReportValidationError` — owns ReportValidationError state or behaviour for the reporting component.
# [FYP-PROCESS] Important methods: no public methods; class-level data/exception semantics only.
# [FYP-USED-BY] Static constructor/type references include reporting_approval.py:_resolve_trusted_path, reporting_approval.py:_verify_candidate_manifest, reporting_approval.py:approve_reporting_candidate.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class ReportValidationError(RuntimeError):
    """Raised by approve_reporting_candidate() when the candidate set
    cannot be approved — identity mismatch, a file hash that no longer
    matches the candidate manifest, or a report whose validation.status is
    "error". Carries a specific, analyst-facing reason; never a generic
    "something is wrong"."""


# [FYP-FUNCTION] `_resolve_trusted_path` — implements the resolve trusted path operation used by the surrounding reporting workflow.
# [FYP-INPUT] Parameters: `raw_path`, `attempt_dir`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include reporting_approval.py:_verify_candidate_manifest, reporting_approval.py:build_export_all_zip, reporting_approval.py:resolve_approved_report_file; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `ReportValidationError`, `is_absolute`, `is_file`, `resolve`, `startswith`, `str`.
# [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

def _resolve_trusted_path(raw_path: str, *, attempt_dir: Path) -> Path:
    """Every path referenced by a candidate manifest is validated before
    being trusted: it must resolve successfully, stay inside this
    attempt's own directory (which itself is inside the global trusted
    artefact root), and point at a real file. A "deterministic-looking"
    path is never trusted on its own."""
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = attempt_dir / raw_path
    resolved = candidate.resolve()
    trusted_root = _TRUSTED_OUTPUT_ROOT.resolve()
    if not str(resolved).startswith(str(trusted_root)):
        raise ReportValidationError(f"path escapes the trusted artefact root: {raw_path}")
    if not str(resolved).startswith(str(attempt_dir.resolve())):
        raise ReportValidationError(f"path escapes this attempt's own directory: {raw_path}")
    if not resolved.is_file():
        raise ReportValidationError(f"required file is missing: {raw_path}")
    return resolved


# [FYP-FUNCTION] `_canonical_manifest_bytes` — implements the canonical manifest bytes operation used by the surrounding reporting workflow.
# [FYP-INPUT] Parameters: `manifest_without_hash`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include reporting_approval.py:_verify_candidate_manifest, soc_reporting_agent/reporting/editable_reports.py:finalize_candidate_manifest; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `dumps`, `encode`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _canonical_manifest_bytes(manifest_without_hash: dict[str, Any]) -> bytes:
    return json.dumps(manifest_without_hash, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# [FYP-FUNCTION] `_verify_candidate_manifest` — implements the verify candidate manifest operation used by the surrounding reporting workflow.
# [FYP-INPUT] Parameters: `candidate_manifest_path`, `incident_id`, `run_id`, `expected_reporting_attempt`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include reporting_approval.py:approve_reporting_candidate, reporting_approval.py:build_export_all_zip; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `ReportValidationError`, `_canonical_manifest_bytes`, `_resolve_trusted_path`, `get`, `hexdigest`, `items`, `join`, `loads`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _verify_candidate_manifest(candidate_manifest_path: str, *, incident_id: str,
                               run_id: str, expected_reporting_attempt: int) -> dict[str, Any]:
    """Loads and fully re-verifies a candidate_manifest.json: identity
    (all three of incident_id/run_id/reporting_stage_attempt — not
    incident_id alone), every structured_content/docx/pdf file's SHA-256
    against what the manifest claims, the full canonical-manifest hash,
    and that no report's validation.status is "error". Raises
    ReportValidationError with a specific reason on any failure. Returns
    the manifest dict on success."""
    attempt_dir = reporting_attempt_dir(incident_id, run_id, expected_reporting_attempt)
    manifest_path = _resolve_trusted_path(candidate_manifest_path, attempt_dir=attempt_dir)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ReportValidationError(f"candidate manifest could not be read: {exc}") from exc

    if (str(manifest.get("incident_id")) != str(incident_id)
            or manifest.get("run_id") != run_id
            or manifest.get("reporting_stage_attempt") != expected_reporting_attempt):
        raise ReportValidationError(
            f"candidate manifest identity mismatch: "
            f"{manifest.get('incident_id')!r}/{manifest.get('run_id')!r}/"
            f"{manifest.get('reporting_stage_attempt')!r} != expected "
            f"{incident_id!r}/{run_id!r}/{expected_reporting_attempt!r}")

    reports = manifest.get("reports") or []
    if not reports:
        raise ReportValidationError("candidate manifest has no reports")

    for report in reports:
        report_type = report.get("report_type")
        for artefact_key in ("structured_content", "docx", "pdf"):
            artefact = report.get(artefact_key) or {}
            raw_path = artefact.get("path")
            expected_sha256 = artefact.get("sha256")
            if not raw_path or not expected_sha256:
                raise ReportValidationError(
                    f"candidate manifest entry for '{report_type}' is missing {artefact_key}")
            resolved = _resolve_trusted_path(raw_path, attempt_dir=attempt_dir)
            actual_size = resolved.stat().st_size
            actual_sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()
            if actual_size != artefact.get("size") or actual_sha256 != expected_sha256:
                raise ReportValidationError(
                    f"'{report_type}' {artefact_key} no longer matches the reviewed "
                    f"candidate set (hash mismatch) — the file changed after generation")
        validation = report.get("validation") or {}
        if validation.get("status") == "error":
            raise ReportValidationError(
                f"'{report_type}' has a blocking validation error and cannot be "
                f"approved: {'; '.join(validation.get('errors') or []) or 'unspecified'}")

    manifest_without_hash = {k: v for k, v in manifest.items() if k != "candidate_manifest_sha256"}
    recomputed_digest = hashlib.sha256(_canonical_manifest_bytes(manifest_without_hash)).hexdigest()
    if recomputed_digest != manifest.get("candidate_manifest_sha256"):
        raise ReportValidationError(
            "candidate manifest's own content no longer matches its published hash "
            "— the manifest was altered after generation")

    return manifest


# [FYP-FUNCTION] `approve_reporting_candidate` — applies the human-in-the-loop approve reporting candidate decision and returns or persists the resulting workflow state.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `analyst`, `comments`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>, tests/test_reporting_stage.py:test_approve_reporting_candidate_end_to_end, tests/test_reporting_stage.py:test_approve_reporting_candidate_fails_on_identity_mismatch; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `ReportValidationError`, `_verify_candidate_manifest`, `commit_reporting_approval`, `get`, `get_state`, `int`, `len`, `loads`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def approve_reporting_candidate(incident_id: str, run_id: str, *, analyst: str,
                                comments: str = "") -> dict[str, Any]:
    """The ONLY function that may approve a Reporting candidate set.

    1. Reads current state, captures the EXACT reporting_result_json
       string being reviewed (used later as a compare-and-swap guard, so a
       concurrent rerun between this validation pass and the final DB
       write causes the approval to fail rather than silently apply to a
       different candidate set).
    2. Resolves and fully re-verifies the candidate manifest referenced by
       that result (_verify_candidate_manifest, above) — identity, every
       file's hash, the manifest's own hash, and no blocking validation
       errors. Raises ReportValidationError on any failure; the caller
       (app.py) is expected to show that message to the analyst.
    3. Builds the durable approval metadata and hands off to the pure-DB
       workflow_state_store.commit_reporting_approval() — which performs
       its own final, transactional re-check of workflow_status/
       approval_stage/reporting_status/reporting_attempt/
       reporting_result_json before writing anything.
    """
    state = wss.get_state(incident_id)
    if not state:
        raise ReportValidationError(f"incident {incident_id!r} has no workflow state")
    if (state.get("run_id") != run_id
            or state.get("workflow_status") != "Awaiting Approval"
            or state.get("approval_stage") != "reporting"
            or state.get("reporting_status") != "Awaiting Approval"):
        raise ReportValidationError(
            "Reporting is not currently awaiting approval for this run "
            f"(workflow_status={state.get('workflow_status')!r}, "
            f"approval_stage={state.get('approval_stage')!r}, "
            f"reporting_status={state.get('reporting_status')!r})")

    reporting_attempt = int(state.get("reporting_attempt") or 1)
    reporting_result_json = state.get("reporting_result_json") or "{}"
    try:
        reporting_result = json.loads(reporting_result_json)
    except Exception as exc:
        raise ReportValidationError(f"reporting_result_json could not be parsed: {exc}") from exc

    candidate_manifest_path = (reporting_result.get("document_exports") or {}).get(
        "candidate_manifest_path")
    if not candidate_manifest_path:
        raise ReportValidationError(
            "no candidate manifest is referenced for this attempt — Reporting may not "
            "have finished generating, or generation failed before publishing one")

    manifest = _verify_candidate_manifest(
        candidate_manifest_path, incident_id=incident_id, run_id=run_id,
        expected_reporting_attempt=reporting_attempt)

    warning_count = sum(
        len((report.get("validation") or {}).get("warnings") or [])
        for report in manifest.get("reports") or [])
    approval_metadata = {
        "report_set_id": manifest.get("report_set_id"),
        "candidate_manifest_path": candidate_manifest_path,
        "candidate_manifest_sha256": manifest.get("candidate_manifest_sha256"),
        "reporting_stage_attempt": reporting_attempt,
        "validation_status": "warning" if warning_count else "valid",
        "warning_count": warning_count,
    }

    return wss.commit_reporting_approval(
        incident_id, run_id,
        expected_reporting_attempt=reporting_attempt,
        expected_reporting_result_json=reporting_result_json,
        metadata=approval_metadata,
        approved_by=analyst, comments=comments)


# ═══════════════════════════════════════════════════════════════════════
# Downloads / Export All — always resolve the APPROVED attempt (via the
# durable workflow_approvals record, never a guessed "latest" directory),
# always re-verify file hashes immediately before serving bytes. Nothing
# here calls run_reporting/export_documents/DOCX/PDF/LLM generation.
# ═══════════════════════════════════════════════════════════════════════

DISPLAY_TITLES = {
    "executive_summary": "Executive Summary",
    "technical_findings": "Technical Findings",
    "soc_analyst_review": "SOC Analyst Review",
    "final_incident_report": "Final Incident Report",
}


# [FYP-FUNCTION] `resolve_approved_report_file` — implements the resolve approved report file operation used by the surrounding reporting workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `report_type`, `file_type`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_resolve_trusted_path`, `get`, `get_latest_approved_reporting_set`, `hexdigest`, `loads`, `next`, `read_bytes`, `read_text`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def resolve_approved_report_file(incident_id: str, run_id: str, report_type: str,
                                 file_type: str) -> tuple[bytes, str] | None:
    """Resolves and hash-verifies ONE file (docx or pdf) from the most
    recently APPROVED Reporting candidate set — resolved via
    workflow_state_store.get_latest_approved_reporting_set() (the durable
    workflow_approvals record), never from whatever reporting_result_json
    currently holds (which may belong to a later, not-yet-approved
    rerun). Returns (bytes, sha256) or None if unavailable/unverifiable —
    never raises, since this is called on every report view request just to
    decide whether to show a download button."""
    try:
        latest = wss.get_latest_approved_reporting_set(incident_id, run_id)
        if not latest or not latest.get("candidate_manifest_path"):
            return None
        attempt_dir = reporting_attempt_dir(incident_id, run_id, latest["reporting_stage_attempt"])
        manifest_path = _resolve_trusted_path(latest["candidate_manifest_path"], attempt_dir=attempt_dir)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("report_set_id") != latest.get("report_set_id"):
            return None
        report = next((r for r in manifest.get("reports") or []
                      if r.get("report_type") == report_type), None)
        if not report:
            return None
        artefact = report.get(file_type) or {}
        raw_path, expected_sha256 = artefact.get("path"), artefact.get("sha256")
        if not raw_path or not expected_sha256:
            return None
        resolved = _resolve_trusted_path(raw_path, attempt_dir=attempt_dir)
        data = resolved.read_bytes()
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != expected_sha256:
            return None
        return data, actual_sha256
    except Exception:
        return None


# [FYP-FUNCTION] `build_export_all_zip` — constructs build export all zip output for the next reporting consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `BytesIO`, `ReportValidationError`, `ZipFile`, `_resolve_trusted_path`, `_verify_candidate_manifest`, `append`, `dumps`, `get`.
# [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

def build_export_all_zip(incident_id: str, run_id: str) -> dict[str, Any]:
    """Builds the Export All ZIP in-process, purely from the approved
    candidate set's already-generated, already-verified files — no
    subprocess, no regeneration, no LLM calls. Raises ReportValidationError
    (with a specific reason) if the approved set can't be fully
    re-verified; the caller shows that to the analyst rather than
    packaging a partial/altered set."""
    import io
    import re as _re
    import zipfile

    latest = wss.get_latest_approved_reporting_set(incident_id, run_id)
    if not latest or not latest.get("candidate_manifest_path"):
        raise ReportValidationError("no approved Reporting candidate set exists for this run")

    manifest = _verify_candidate_manifest(
        latest["candidate_manifest_path"], incident_id=incident_id, run_id=run_id,
        expected_reporting_attempt=latest["reporting_stage_attempt"])
    attempt_dir = reporting_attempt_dir(
        incident_id, run_id, latest["reporting_stage_attempt"])

    zip_manifest_entries = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for report in manifest.get("reports") or []:
            report_type = report.get("report_type")
            display_title = DISPLAY_TITLES.get(report_type, report_type)
            for file_type in ("docx", "pdf"):
                artefact = report.get(file_type) or {}
                resolved = _resolve_trusted_path(artefact["path"], attempt_dir=attempt_dir)
                arcname = f"{display_title}.{file_type}"
                zf.write(resolved, arcname)
                zip_manifest_entries.append({
                    "report_type": report_type, "title": display_title,
                    "format": file_type, "filename": arcname,
                    "sha256": artefact.get("sha256"), "size": artefact.get("size"),
                    "validation": report.get("validation"),
                })
        export_manifest = {
            "incident_id": incident_id, "run_id": run_id,
            "reporting_stage_attempt": latest["reporting_stage_attempt"],
            "report_set_id": manifest.get("report_set_id"),
            "candidate_manifest_sha256": manifest.get("candidate_manifest_sha256"),
            "approved_by": latest.get("approved_by"),
            "approved_at": latest.get("approved_at"),
            "generated_at": manifest.get("generated_at"),
            "files": zip_manifest_entries,
        }
        zf.writestr("manifest.json", json.dumps(export_manifest, indent=2, ensure_ascii=False))

    zip_bytes = buf.getvalue()
    zip_sha256 = hashlib.sha256(zip_bytes).hexdigest()
    safe_incident = _re.sub(r"[^A-Za-z0-9_-]", "_", str(incident_id))
    filename = f"Aegis_{safe_incident}_Reports_Attempt-{latest['reporting_stage_attempt']}.zip"
    return {
        "bytes": zip_bytes, "sha256": zip_sha256, "filename": filename,
        "report_set_id": manifest.get("report_set_id"),
        "reporting_stage_attempt": latest["reporting_stage_attempt"],
        "candidate_manifest_sha256": manifest.get("candidate_manifest_sha256"),
    }
