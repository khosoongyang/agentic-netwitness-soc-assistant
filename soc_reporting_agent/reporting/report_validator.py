"""
[FYP-FILE] reporting/report_validator.py (151 lines)
# File: soc_reporting_agent/reporting/report_validator.py
# Purpose: This module implements report generation and export behaviour for report validator.
# Inputs: Receives function arguments, configured state, and persisted artifacts described below.
# Outputs: Produces return values and documented state, file, database, export, or UI effects.
# Workflow position: Aegis report generation and export.
# Important dependencies: pathlib, re, reporting, typing.
# Key evaluator search terms: validate_required_fields, build_missing_field_gaps, ReportIntegrityError, _validate_docx_integrity_and_tables, _validate_pdf_integrity, _validate_structured_content, [FYP-FUNCTION].

[FYP-SECTION] Responsibility
Two independent validation layers that share this module by convention
rather than by call graph:

1. [FYP-EVALUATOR] Field-presence validation (REQUIRED_FIELDS,
   validate_required_fields(), build_missing_field_gaps()) — a
   dotted-path completeness check against a *finished* context dict.
   Searched the codebase for callers: none found in agents/, scripts/, or
   elsewhere in reporting/. context_builder.py computes its own
   `missing_required_fields`/`evidence_gaps` independently (from upstream
   investigation/triage "missing_evidence"/"missing_fields" data, see
   context_builder.py around line 326), and does not call into this
   function. Only get_nested() (imported from schema_normaliser.py, not
   defined here) is actually exercised at runtime by this module. Confirm
   during evaluation whether validate_required_fields()/
   build_missing_field_gaps() are legacy/superseded or an intentionally
   separate completeness-check utility not yet wired into build_context().

2. Post-generation artefact validation (ReportIntegrityError,
   validate_generated_report() and its three `_validate_*` helpers below)
   — this half IS live: called by
   reporting/editable_reports.py:finalize_candidate_manifest() (lazy
   import) to decide, per rendered report, whether the generated DOCX/PDF/
   structured-content artefacts are safe to publish for analyst review.

[FYP-USED-BY] reporting/editable_reports.py (validate_generated_report(),
via lazy import in finalize_candidate_manifest()).
"""
import re
from pathlib import Path
from typing import Any

from reporting.schema_normaliser import get_nested
from reporting.structured_report import load_blocks, paragraph_contains_raw_pipe_table

# [FYP-SECTION] Field-presence completeness check (see module docstring
# point 1 — no confirmed in-repo callers as of this pass).
REQUIRED_FIELDS=['incident_id','alert_id','severity.label','confidence.label','classification','likely_scenario','affected_assets','affected_users','iocs','evidence','investigation_summary']
def validate_required_fields(context: dict[str, Any]) -> list[str]:
    """[FYP-FUNCTION] Return the subset of REQUIRED_FIELDS dotted paths
    that resolve (via get_nested()) to an empty/absent value (None, '',
    [], {}, or the 'Not Provided' sentinel) in `context`. An empty return
    list means every required field is populated.
    [FYP-EVALUATOR] No confirmed caller found in this codebase pass — the
    live pipeline's missing_required_fields is instead assembled directly
    in context_builder.build_context() from upstream evidence-gap data.
    Worth checking at evaluation time whether this was meant to replace
    that logic."""
    missing=[]
    for f in REQUIRED_FIELDS:
        v=get_nested(context,f)
        if v in [None,'',[],{},'Not Provided']: missing.append(f)
    return missing
def build_missing_field_gaps(missing_fields: list[str]) -> list[dict[str,str]]:
    """[FYP-FUNCTION] Convert a list of dotted field-path strings (e.g. the
    output of validate_required_fields()) into the same
    {priority, gap, required_data} evidence-gap dict shape used elsewhere
    in the pipeline for missing_evidence/evidence_gaps entries. Every entry
    is hardcoded priority='High'. [FYP-EVALUATOR] Shares no confirmed
    caller with validate_required_fields() (see that function's note)."""
    return [{'priority':'High','gap':f'Missing required reporting field: {f}','required_data':f'Provide {f} from enriched alert, triage, investigation, or approval output.'} for f in missing_fields]


# ═══════════════════════════════════════════════════════════════════════
# Post-generation report validation — used by
# editable_reports.finalize_candidate_manifest() to decide, per report,
# whether a candidate set is publishable at all (integrity failures raise
# and block publication entirely) versus publishable-but-approval-blocked
# (content-level problems, recorded as validation.status="error") versus
# clean-with-warnings (approval allowed, warnings stay visible).
# ═══════════════════════════════════════════════════════════════════════

try:
    from docx import Document as _DocxDocument
except Exception:  # pragma: no cover
    _DocxDocument = None

try:
    import pypdf
except Exception:  # pragma: no cover
    pypdf = None


class ReportIntegrityError(RuntimeError):
    """[FYP-CLASS] Raised when a report artefact cannot even be opened/read — a
    generation-time failure (missing/corrupt DOCX, unopenable/zero-page
    PDF, unreadable structured content), distinct from a content-level
    validation problem on a file that DID open successfully. Callers must
    let this propagate: it is what makes finalize_candidate_manifest()
    refuse to publish a candidate manifest, and run_reporting_stage() mark
    the whole attempt Reporting=Failed/Workflow=Failed rather than
    Awaiting Approval."""


_JINJA_PLACEHOLDER_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}")
_RAW_ENTITY_RE = re.compile(r"&(?:amp|lt|gt|quot|#39);")
_UNRESOLVED_TABLE_SEPARATOR_RE = re.compile(r"\|\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?")


def _validate_docx_integrity_and_tables(docx_path: Path) -> tuple[list[str], list[str]]:
    """[FYP-FUNCTION] [FYP-VALIDATION] Content-level DOCX checks. Raises ReportIntegrityError if the file
    can't even be opened — a generation failure, not a content problem."""
    if _DocxDocument is None:
        raise ReportIntegrityError("python-docx is not installed — cannot validate DOCX output.")
    try:
        document = _DocxDocument(str(docx_path))
    except Exception as exc:
        raise ReportIntegrityError(f"DOCX file could not be opened: {docx_path} ({exc})") from exc
    errors: list[str] = []
    warnings: list[str] = []
    full_text = "\n".join(p.text for p in document.paragraphs)
    if _JINJA_PLACEHOLDER_RE.search(full_text):
        errors.append("Unresolved Jinja2 placeholder remains in the exported DOCX.")
    if paragraph_contains_raw_pipe_table(full_text):
        errors.append("Raw pipe-table syntax remains in the exported DOCX.")
    if _RAW_ENTITY_RE.search(full_text):
        warnings.append("A literal HTML entity (e.g. &amp;) appears to be displayed unescaped.")
    return errors, warnings


def _validate_pdf_integrity(pdf_path: Path) -> tuple[list[str], list[str]]:
    """[FYP-FUNCTION] [FYP-VALIDATION] Content-level PDF checks. Raises ReportIntegrityError if the PDF
    can't be opened or has zero pages — a generation failure."""
    if pypdf is None:
        raise ReportIntegrityError("pypdf is not installed — cannot validate PDF output.")
    try:
        reader = pypdf.PdfReader(str(pdf_path))
        page_count = len(reader.pages)
    except Exception as exc:
        raise ReportIntegrityError(f"PDF file could not be opened: {pdf_path} ({exc})") from exc
    if page_count < 1:
        raise ReportIntegrityError(f"PDF has zero pages: {pdf_path}")
    errors: list[str] = []
    warnings: list[str] = []
    if getattr(reader, "is_encrypted", False):
        warnings.append("PDF reports as encrypted; contents could not be fully inspected.")
    else:
        try:
            text = "\n".join((page.extract_text() or "") for page in reader.pages)
        except Exception:
            text = ""
        if _UNRESOLVED_TABLE_SEPARATOR_RE.search(text):
            errors.append("Unresolved Markdown table separator syntax (e.g. |---|---|) remains in the PDF text.")
    return errors, warnings


def _validate_structured_content(structured_content_path: Path) -> tuple[list[str], list[str]]:
    """[FYP-FUNCTION] [FYP-VALIDATION] Content-level checks against the structured block JSON — the same
    source the web preview renders from, so a problem here means the
    preview itself would show it too."""
    try:
        blocks = load_blocks(structured_content_path)
    except Exception as exc:
        raise ReportIntegrityError(
            f"Structured content could not be read: {structured_content_path} ({exc})") from exc
    errors: list[str] = []
    warnings: list[str] = []
    for block in blocks or []:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "paragraph" and paragraph_contains_raw_pipe_table(str(block.get("text") or "")):
            errors.append("Raw pipe-table syntax remains in a paragraph block.")
        row_warnings = block.get("row_warnings")
        if row_warnings:
            warnings.extend(str(w) for w in row_warnings)
    if not blocks:
        errors.append("Structured content is empty — no reviewable preview content was produced.")
    return errors, warnings


def validate_generated_report(*, docx_path: Path, pdf_path: Path, structured_content_path: Path,
                              report_title: str, incident_id: str) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-ENTRY-POINT] [FYP-VALIDATION] Validates one already-generated report's three artefacts (structured
    content / DOCX / PDF).

    File-open/integrity failures RAISE (ReportIntegrityError) and must be
    allowed to propagate — that is what makes
    editable_reports.finalize_candidate_manifest() refuse to publish a
    candidate manifest at all, and run_reporting_stage() mark the attempt
    Failed. Content-level problems on artefacts that DID open successfully
    (unresolved Jinja placeholders, raw pipe-table syntax, etc.) are
    returned as a structured result instead, so a complete-but-imperfect
    candidate set can still be published (validation.status="error") and
    previewed by the analyst — just not approved
    (reporting_approval.approve_reporting_candidate() refuses on
    status="error").
    """
    docx_errors, docx_warnings = _validate_docx_integrity_and_tables(Path(docx_path))
    pdf_errors, pdf_warnings = _validate_pdf_integrity(Path(pdf_path))
    struct_errors, struct_warnings = _validate_structured_content(Path(structured_content_path))

    errors = docx_errors + pdf_errors + struct_errors
    warnings = docx_warnings + pdf_warnings + struct_warnings
    status = "error" if errors else ("warning" if warnings else "valid")
    return {"status": status, "errors": errors, "warnings": warnings}
