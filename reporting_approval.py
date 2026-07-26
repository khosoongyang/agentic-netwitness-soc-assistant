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


class ReportValidationError(RuntimeError):
    """Raised by approve_reporting_candidate() when the candidate set
    cannot be approved — identity mismatch, a file hash that no longer
    matches the candidate manifest, or a report whose validation.status is
    "error". Carries a specific, analyst-facing reason; never a generic
    "something is wrong"."""


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


def _canonical_manifest_bytes(manifest_without_hash: dict[str, Any]) -> bytes:
    return json.dumps(manifest_without_hash, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


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


def resolve_approved_report_file(incident_id: str, run_id: str, report_type: str,
                                 file_type: str) -> tuple[bytes, str] | None:
    """Resolves and hash-verifies ONE file (docx or pdf) from the most
    recently APPROVED Reporting candidate set — resolved via
    workflow_state_store.get_latest_approved_reporting_set() (the durable
    workflow_approvals record), never from whatever reporting_result_json
    currently holds (which may belong to a later, not-yet-approved
    rerun). Returns (bytes, sha256) or None if unavailable/unverifiable —
    never raises, since this is called on every Streamlit rerender just to
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
