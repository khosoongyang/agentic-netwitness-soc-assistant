"""candidate_materialiser.py — Phase 6 of the Reporting redesign.

materialise_reviewed_candidate() renders the four core reports' LATEST
REVIEWED report_versions content into a NEW, immutable candidate manifest —
it never opens the original AI-generated candidate_manifest.json (v1,
published by editable_reports.finalize_candidate_manifest()) or its
reports/exports/ folder in write mode. The new manifest lives in its own
folder, reports/reviewed_candidates/<report_set_id>/, a sibling of v1's own
location, and is built in the EXACT SAME shape (incident_id/run_id/
reporting_stage_attempt/report_set_id/reports[]/candidate_manifest_sha256)
that reporting_approval._verify_candidate_manifest() already knows how to
verify — that function needs ZERO changes to validate a materialised set;
only WHICH manifest path gets handed to it changes (Phase 7).

This module is pure filesystem/hash work, mirroring
editable_reports.finalize_candidate_manifest() closely on purpose so the two
manifests stay structurally interchangeable. It never touches the database —
the caller (agents/reporting/report_editing.py::submit_for_approval())
registers the result in workflow_state_store's report_sets table.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reporting.editable_reports import (
    CORE_REPORT_KEYS, incident_report_dir, render_blocks_to_docx, render_blocks_to_pdf)
from reporting.report_validator import validate_generated_report

DISPLAY_TITLES = {
    "executive_summary": "Executive Summary",
    "technical_findings": "Technical Findings",
    "soc_analyst_review": "SOC Analyst Review",
    "final_incident_report": "Final Incident Report",
}


class CandidateMaterialisationError(RuntimeError):
    """Analyst-facing failure — e.g. a required report's blocks were
    missing when this was called (report_editing.py is responsible for
    confirming every core report is actually Reviewed before calling this;
    this is a defensive backstop, not the primary gate)."""


def reviewed_candidates_root(output_dir: Path, incident_id: str) -> Path:
    """Sibling of editable_reports.exports_dir()/candidate_manifest_path()
    — nested under the same reports/ folder, never inside it."""
    return incident_report_dir(output_dir, incident_id) / "reviewed_candidates"


def _candidate_dir_token(report_set_id: str) -> str:
    """The on-disk folder name is a short hash of report_set_id, not the
    full 32-char uuid4 hex — this directory already sits many levels deep
    (…/reporting/attempt_N/<incident_id>/reports/reviewed_candidates/<token>/
    <report_type>.docx), and Windows' ~260-char MAX_PATH is a real
    constraint at that depth. Same precedent as workflow/engine.py's
    _artifact_dir() truncating its own hash to 10 chars for the identical
    reason. `report_set_id` itself (the full uuid) remains the actual
    identifier everywhere in the manifest content and the report_sets DB
    row — only the folder name is shortened, and only once, here."""
    return hashlib.sha256(report_set_id.encode()).hexdigest()[:10]


def _hash_file(path: Path) -> tuple[str, int]:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def _rel(output_dir: Path, path: Path) -> str:
    try:
        return str(path.relative_to(output_dir.parent))
    except Exception:
        return str(path)


def _canonical_manifest_bytes(manifest_without_hash: dict[str, Any]) -> bytes:
    """Identical serialisation to editable_reports._canonical_manifest_bytes()
    / reporting_approval._canonical_manifest_bytes() — deliberately
    duplicated (matching this codebase's own precedent of
    reporting_approval.py keeping its own local copy rather than importing
    editable_reports' private helper) so this module's hashing never
    silently drifts if either of those changes independently."""
    return json.dumps(manifest_without_hash, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def materialise_reviewed_candidate(output_dir: Path, incident_id: str, run_id: str,
                                   reporting_stage_attempt: int, *,
                                   reviewed_reports: dict[str, dict[str, Any]],
                                   based_on_report_set_id: str | None,
                                   analyst: str) -> tuple[dict[str, Any], Path]:
    """`reviewed_reports` must map every one of editable_reports.
    CORE_REPORT_KEYS to {"version_id": int, "blocks": [...]} — the exact
    latest REVIEWED report_versions content for each of the four core
    reports. Renders each to structured_content/docx/pdf into a fresh
    reports/reviewed_candidates/<short token>/ folder and publishes an
    immutable candidate_manifest.json there. Returns (manifest dict,
    manifest file path) — the caller (report_editing.py) persists that
    exact path into the report_sets row rather than reconstructing it
    independently, so the on-disk folder-naming scheme only needs to be
    correct in this one place."""
    missing = [key for key in CORE_REPORT_KEYS if key not in reviewed_reports]
    if missing:
        raise CandidateMaterialisationError(
            f"Cannot materialise a reviewed candidate — missing reviewed content for: {', '.join(missing)}")

    report_set_id = uuid.uuid4().hex
    candidate_dir = reviewed_candidates_root(output_dir, incident_id) / _candidate_dir_token(report_set_id)
    candidate_dir.mkdir(parents=True, exist_ok=True)

    report_entries: list[dict[str, Any]] = []
    for key in CORE_REPORT_KEYS:
        entry = reviewed_reports[key]
        blocks = entry["blocks"]
        title = DISPLAY_TITLES.get(key, key)
        structured_path = candidate_dir / f"{key}.json"
        docx_path = candidate_dir / f"{key}.docx"
        pdf_path = candidate_dir / f"{key}.pdf"

        structured_path.write_text(json.dumps(blocks, indent=2, ensure_ascii=False), encoding="utf-8")
        meta = {"confirmed_by": analyst, "source_report_version_id": entry["version_id"]}
        render_blocks_to_docx(docx_path, title, blocks, incident_id, meta)
        render_blocks_to_pdf(pdf_path, title, blocks, incident_id, meta, docx_path=docx_path)

        validation = validate_generated_report(
            docx_path=docx_path, pdf_path=pdf_path, structured_content_path=structured_path,
            report_title=title, incident_id=incident_id)

        def _hashed(p: Path) -> dict[str, Any]:
            sha, size = _hash_file(p)
            return {"path": _rel(output_dir, p), "sha256": sha, "size": size}

        report_entries.append({
            "report_type": key,
            "title": title,
            "filename": {"docx": docx_path.name, "pdf": pdf_path.name},
            "template": None,
            "source_report_version_id": entry["version_id"],
            "structured_content": _hashed(structured_path),
            "docx": _hashed(docx_path),
            "pdf": _hashed(pdf_path),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "validation": validation,
        })

    manifest_without_hash: dict[str, Any] = {
        "incident_id": incident_id,
        "run_id": run_id,
        "reporting_stage_attempt": reporting_stage_attempt,
        "report_set_id": report_set_id,
        "based_on_report_set_id": based_on_report_set_id,
        "materialised_by": analyst,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reports": report_entries,
        # Same metadata-only compatibility alias editable_reports.
        # finalize_candidate_manifest() publishes — never a second document.
        "legacy_combined_incident_report": {"deprecated": True, "points_to": "final_incident_report"},
    }
    digest = hashlib.sha256(_canonical_manifest_bytes(manifest_without_hash)).hexdigest()
    full_manifest = dict(manifest_without_hash)
    full_manifest["candidate_manifest_sha256"] = digest

    manifest_file = candidate_dir / "candidate_manifest.json"
    # Same atomic-write pattern as finalize_candidate_manifest(): temp file,
    # fsync, then os.replace() — a crash mid-write can never leave a
    # partially-written manifest behind. This path is always fresh (a new
    # uuid4 report_set_id every call), so unlike finalize_candidate_manifest()
    # there is no pre-existing-file/idempotency case to handle here.
    tmp_path = manifest_file.with_name(f".{manifest_file.name}.tmp-{uuid.uuid4().hex[:8]}")
    try:
        with open(tmp_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(full_manifest, indent=2, ensure_ascii=False))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, manifest_file)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    return full_manifest, manifest_file
