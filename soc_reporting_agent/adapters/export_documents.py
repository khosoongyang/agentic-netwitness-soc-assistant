"""Headless DOCX/PDF export adapter.

Confirms all report sections and exports the combined incident report as
Word + PDF using the reporting package's own exporters. Used by the SOC
workflow orchestrator after a reporting run; the Flask dashboard's manual
confirm/export flow is unaffected.

Usage:  python adapters/export_documents.py [incident_id]
Prints a single machine-readable line:  EXPORT_JSON:{...}
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT_BOOTSTRAP = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT_BOOTSTRAP) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT_BOOTSTRAP))

from config import settings
from reporting import editable_reports as er


def main() -> int:
    incident_id = sys.argv[1] if len(sys.argv) > 1 else None
    output_dir = settings.OUTPUT_DIR
    result: dict = {"incident_id": incident_id}

    # Combined export requires every section confirmed; the workflow is
    # headless so sections are auto-confirmed here. Analysts can still edit
    # and re-confirm in the reporting dashboard afterwards.
    try:
        er.confirm_report(output_dir, analyst="SOC Workflow (auto-confirm)",
                          incident_id=incident_id)
    except Exception as exc:
        result["confirm_error"] = str(exc)

    try:
        docx = er.export_docx(output_dir, incident_id=incident_id)
        result["docx"] = docx.get("path")
    except Exception as exc:
        result["docx_error"] = str(exc)

    try:
        pdf = er.export_pdf(output_dir, incident_id=incident_id)
        result["pdf"] = pdf.get("path")
    except Exception as exc:
        result["pdf_error"] = str(exc)

    # Individual section exports — powers per-section downloads in the
    # dashboard's Generated Files panel. Best-effort: a failure on one
    # section must not block the combined docx/pdf produced above.
    for section_key in ("executive_summary", "technical_findings",
                        "soc_analyst_review"):
        try:
            section_docx = er.export_section_docx(output_dir, section_key,
                                                   incident_id=incident_id)
            result[f"{section_key}_docx"] = section_docx.get("path")
        except Exception as exc:
            result[f"{section_key}_docx_error"] = str(exc)
        try:
            section_pdf = er.export_section_pdf(output_dir, section_key,
                                                 incident_id=incident_id)
            result[f"{section_key}_pdf"] = section_pdf.get("path")
        except Exception as exc:
            result[f"{section_key}_pdf_error"] = str(exc)

    # Immutable final snapshot — only after every section above has been
    # confirmed and exported. run_id/reporting_stage_attempt are threaded
    # through as env vars (set by soc_workflow.run_reporting_stage()
    # alongside REPORTING_INPUT_DIR/REPORTING_OUTPUT_DIR) rather than new
    # positional CLI args, so the existing `python export_documents.py
    # [incident_id]` invocation shape is unchanged.
    run_id = os.getenv("SOC_RUN_ID")
    attempt_raw = os.getenv("SOC_REPORTING_ATTEMPT")
    try:
        reporting_stage_attempt = int(attempt_raw) if attempt_raw else 1
    except ValueError:
        reporting_stage_attempt = 1
    try:
        candidate_manifest = er.finalize_candidate_manifest(
            output_dir, incident_id, run_id, reporting_stage_attempt)
        result["candidate_manifest_path"] = str(
            er.candidate_manifest_path(output_dir, incident_id))
        result["report_set_id"] = candidate_manifest.get("report_set_id")
        result["candidate_manifest_sha256"] = candidate_manifest.get("candidate_manifest_sha256")
    except er.CandidateManifestConflictError as exc:
        # A published candidate set already exists and differs — this is
        # not a generation failure, it's a bug-guard; surface it loudly
        # rather than silently accepting either version.
        result["candidate_manifest_error"] = str(exc)
        print("EXPORT_JSON:" + json.dumps(result, default=str))
        return 1
    except Exception as exc:
        # Any other failure here (missing/unreadable DOCX or PDF, a
        # ReportIntegrityError from report_validator, etc.) means no
        # candidate manifest was published — a generation/validator
        # execution failure. run_reporting_stage() must see this as a
        # failed attempt (Reporting=Failed, Workflow=Failed), never as a
        # published-but-blocked candidate set.
        result["candidate_manifest_error"] = str(exc)
        print("EXPORT_JSON:" + json.dumps(result, default=str))
        return 1

    print("EXPORT_JSON:" + json.dumps(result, default=str))
    return 0 if (result.get("docx") or result.get("pdf")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
