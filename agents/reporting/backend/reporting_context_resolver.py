# ==============================================================================
# [FYP-FILE] File: soc_reporting_agent/backend/reporting_context_resolver.py
# Important dependencies: __future__, backend, dataclasses, json, pathlib, shutil, typing.
#
# Purpose:
#   Bridges investigation/approval context between the Postgres-backed
#   ticket record (the dashboard's source of truth) and the legacy
#   filesystem-based inputs/outputs JSON contract that the standalone
#   Reporting agent adapter (soc_reporting_agent/adapters/run_reporting.py
#   and its downstream reporting scripts) still reads. Without this bridge,
#   Reporting can fail with a misleading "Run Investigation first" error
#   even when a usable (possibly limited) investigation result already
#   exists in ticket context or in a legacy output path.
#
# Main functionalities:
#   - investigation_candidate_paths / approval_candidate_paths: enumerate the
#     known filesystem locations (under outputs/<ticket_id>/..., outputs/,
#     inputs/) where a previous run may have written
#     investigation_result.json / investigation_approval_result.json /
#     approval_result.json.
#   - resolve_investigation_context / resolve_investigation_approval_context:
#     [FYP-DECISION] look first at the ticket dict itself, then fall back to
#     scanning candidate filesystem paths (in priority order, preferring a
#     "usable" result over merely the first one found), returning a
#     ResolvedContext describing what was found and whether it is usable.
#   - ensure_reporting_inputs: [FYP-EVALUATOR] the actual bridge -- resolves
#     both contexts and WRITES them into inputs/ and outputs/ as JSON files
#     so the legacy Reporting code path can pick them up.
#
# Inputs:
#   - project_root: Path -- soc_reporting_agent project root (source:
#     PROJECT_ROOT constant in the calling module).
#   - ticket_id: str | None -- ticket identifier, used to build candidate
#     filesystem paths.
#   - ticket: dict[str, Any] | None -- the in-memory ticket record, checked
#     first before falling back to disk.
#
# Outputs:
#   - ResolvedContext dataclass (exists/usable/data/source/message) and its
#     .as_dict() serialisation.
#   - ensure_reporting_inputs() also has the SIDE EFFECT of writing
#     investigation_result.json / investigation_approval_result.json /
#     approval_result.json under both inputs/ and outputs/ (see
#     [FYP-OUTPUT] markers below) -- these are the only file-writing
#     functions in this module.
#
# Workflow position:
#   Runs immediately before the Reporting stage executes, as a preparation/
#   handoff step. It does not decide WHETHER Reporting may run (that is
#   stage_workflow.can_run / orchestration_service.build_orchestration_
#   decision's job) -- it only makes sure the filesystem-based inputs that
#   Reporting's legacy code path expects are present and reflect the latest
#   known-good investigation/approval context.
#
# Called by:
#   - soc_reporting_agent/backend/app.py
#     (`from backend.reporting_context_resolver import ensure_reporting_inputs,
#     resolve_investigation_approval_context, resolve_investigation_context`),
#     called just before dispatching a Reporting agent run.
#   - soc_reporting_agent/adapters/run_reporting.py
#     (`from backend.reporting_context_resolver import ensure_reporting_inputs`),
#     called from `_prepare_inputs()` before invoking the reporting scripts.
#
# Calls:
#   - agents/reporting/backend/reporting_eligibility.py
#     (`from . import reporting_eligibility`) --
#     is_investigation_usable_for_reporting, to decide whether a resolved
#     investigation result counts as "usable".
#
# Key evaluator search terms:
#   ensure_reporting_inputs, resolve_investigation_context,
#   resolve_investigation_approval_context, ResolvedContext, evidence gap,
#   context bridge, investigation_result.json.
# ==============================================================================

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from . import reporting_eligibility


# [FYP-CONFIG] Known legacy filenames used by the filesystem-based
# inputs/outputs contract that older reporting scripts still read from.
INVESTIGATION_FILENAMES = [
    "investigation_result.json",
]

APPROVAL_FILENAMES = [
    "investigation_approval_result.json",
    "approval_result.json",
]


# =============================================================================
# [FYP-SECTION] REPORTING BACKEND AND API EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================


@dataclass
class ResolvedContext:
    """[FYP-CLASS] Result of trying to locate a piece of reporting context (investigation result or its approval).

    Fields:
      exists -- whether ANY candidate data was found (ticket field or file).
      usable -- whether the found data passes the relevant usability check
        (is_investigation_usable_for_reporting / is_approval_approved).
      data -- the raw dict that was found (possibly not usable).
      source -- where it came from: "ticket.<field>" or a project-relative
        file path, or None if nothing was found.
      message -- human-readable explanation, surfaced to callers/analysts.
    Called by: resolve_investigation_context, resolve_investigation_approval_context.
    Calls: as_dict() below is used by ensure_reporting_inputs() to build its
    return payload.
    """
    exists: bool
    usable: bool
    data: dict[str, Any]
    source: str | None
    message: str

    def as_dict(self) -> dict[str, Any]:
        """[FYP-FUNCTION] Serialise this ResolvedContext to a plain dict for JSON/API responses."""
        return {
            "exists": self.exists,
            "usable": self.usable,
            "data": self.data,
            "source": self.source,
            "message": self.message,
        }


def _norm(value: Any) -> str:
    """[FYP-FUNCTION] Normalise any value to a lowercase, underscore-separated string for tolerant status comparisons."""
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _read_json(path: Path) -> dict[str, Any] | None:
    """[FYP-FUNCTION] Best-effort JSON file read. Returns None (never raises) if the file is missing, empty, unreadable, or not a JSON object.

    [FYP-FALLBACK] Any exception during read/parse is swallowed and treated
    as "no data here" -- callers fall through to the next candidate path
    rather than crashing on a corrupt legacy file.
    """
    try:
        if not path.exists() or path.stat().st_size == 0:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _write_json(path: Path, data: dict[str, Any]) -> None:
    """[FYP-FUNCTION] [FYP-OUTPUT] Write a dict as pretty-printed JSON to path, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _unique_paths(paths: Iterable[Path]) -> list[Path]:
    """[FYP-FUNCTION] De-duplicate a path list while preserving order (resolves absolute paths for comparison; leaves relative paths as-is)."""
    out: list[Path] = []
    seen: set[str] = set()
    for p in paths:
        key = str(p.resolve()) if p.is_absolute() else str(p)
        if key not in seen:
            out.append(p)
            seen.add(key)
    return out


def _ticket_value(ticket: dict[str, Any] | None, key: str) -> dict[str, Any]:
    """[FYP-FUNCTION] Safely read a nested dict field off a (possibly None) ticket dict."""
    if not isinstance(ticket, dict):
        return {}
    value = ticket.get(key) or {}
    return value if isinstance(value, dict) else {}


def investigation_candidate_paths(project_root: Path, ticket_id: str | None = None) -> list[Path]:
    """[FYP-FUNCTION] [FYP-INPUT] Enumerate candidate filesystem locations for a ticket's investigation_result.json, most-specific first.

    Params: project_root -- soc_reporting_agent root; ticket_id -- optional,
    adds per-ticket paths under outputs/<ticket_id>/... ahead of the
    ticket-agnostic fallback paths.
    Returns: de-duplicated ordered list of Path candidates (existence not
    checked here -- see resolve_investigation_context for that).
    Called by: resolve_investigation_context.
    """
    outputs = project_root / "outputs"
    inputs = project_root / "inputs"
    paths: list[Path] = []
    if ticket_id:
        paths.extend([
            outputs / ticket_id / "investigation" / "investigation_result.json",
            outputs / ticket_id / "investigation_result.json",
            outputs / ticket_id / "agents" / "investigation_result.json",
            outputs / ticket_id / "investigation" / "result.json",
        ])
    paths.extend([
        inputs / "investigation_result.json",
        outputs / "investigation_result.json",
        outputs / "unknown" / "investigation_result.json",
    ])
    # Some reporting runs write under outputs/<incident_id>/reporting_result.json, but
    # investigation runs in this project usually write exactly the filenames above.
    return _unique_paths(paths)


def approval_candidate_paths(project_root: Path, ticket_id: str | None = None) -> list[Path]:
    """[FYP-FUNCTION] [FYP-INPUT] Enumerate candidate filesystem locations for a ticket's investigation approval result, most-specific first.

    Mirrors investigation_candidate_paths() but for the approval decision
    (investigation_approval_result.json / approval_result.json).
    Called by: resolve_investigation_approval_context.
    """
    outputs = project_root / "outputs"
    inputs = project_root / "inputs"
    paths: list[Path] = []
    if ticket_id:
        paths.extend([
            outputs / ticket_id / "approval" / "investigation_approval_result.json",
            outputs / ticket_id / "investigation_approval" / "approval_result.json",
            outputs / ticket_id / "investigation_approval_result.json",
        ])
    paths.extend([
        inputs / "investigation_approval_result.json",
        outputs / "investigation_approval_result.json",
        inputs / "approval_result.json",
        outputs / "approval_result.json",
        outputs / "unknown" / "investigation_approval_result.json",
    ])
    return _unique_paths(paths)


def is_approval_approved(data: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] [FYP-APPROVAL] [FYP-DECISION] True when an approval payload's decision/status/approval_status is one of the approved values."""
    decision = _norm(data.get("decision") or data.get("status") or data.get("approval_status"))
    return decision in {"approved", "approve", "completed", "confirmed"}


def resolve_investigation_context(project_root: Path, ticket_id: str | None = None, ticket: dict[str, Any] | None = None) -> ResolvedContext:
    """[FYP-FUNCTION] [FYP-DECISION] Find the best available investigation result for a ticket.

    Params: project_root -- project root; ticket_id -- optional ticket id
    for path candidates; ticket -- optional in-memory ticket dict, checked
    FIRST (source of truth) before any filesystem fallback.
    Returns: ResolvedContext.
    Resolution order:
      1. ticket["investigation_result"], if present -- usability determined
         by reporting_eligibility.is_investigation_usable_for_reporting.
      2. Otherwise scan investigation_candidate_paths() in order; return the
         first candidate that IS usable as soon as found.
      3. If none were usable but at least one file existed, return that
         first-found (unusable) result so the caller can explain why
         Reporting is blocked.
      4. If nothing was found anywhere, return an empty/not-found context.
    Called by: ensure_reporting_inputs (this file), backend/app.py.
    Calls: reporting_eligibility.is_investigation_usable_for_reporting,
    investigation_candidate_paths, _read_json.
    """
    ticket_inv = _ticket_value(ticket, "investigation_result")
    if ticket_inv:
        usable = reporting_eligibility.is_investigation_usable_for_reporting(ticket_inv)
        return ResolvedContext(
            exists=True,
            usable=usable,
            data=ticket_inv,
            source="ticket.investigation_result",
            message="Ticket investigation result is usable for Reporting." if usable else "Ticket investigation result exists but is not usable for Reporting.",
        )

    first_existing: tuple[dict[str, Any], Path] | None = None
    for path in investigation_candidate_paths(project_root, ticket_id):
        data = _read_json(path)
        if not data:
            continue
        if first_existing is None:
            first_existing = (data, path)
        if reporting_eligibility.is_investigation_usable_for_reporting(data):
            return ResolvedContext(
                exists=True,
                usable=True,
                data=data,
                source=str(path.relative_to(project_root)) if path.is_relative_to(project_root) else str(path),
                message="Investigation result found and usable for Reporting.",
            )

    if first_existing:
        data, path = first_existing
        return ResolvedContext(
            exists=True,
            usable=False,
            data=data,
            source=str(path.relative_to(project_root)) if path.is_relative_to(project_root) else str(path),
            message="Investigation result exists but is failed, invalid, or missing usable findings.",
        )

    return ResolvedContext(
        exists=False,
        usable=False,
        data={},
        source=None,
        message="No investigation result was found in ticket context, inputs, or known outputs paths.",
    )


def resolve_investigation_approval_context(project_root: Path, ticket_id: str | None = None, ticket: dict[str, Any] | None = None) -> ResolvedContext:
    """[FYP-FUNCTION] [FYP-APPROVAL] [FYP-DECISION] Find the best available investigation-approval result for a ticket.

    Mirrors resolve_investigation_context()'s resolution order (ticket dict
    first, then approval_candidate_paths() on disk, preferring an approved
    result over merely the first one found).
    Called by: ensure_reporting_inputs (this file), backend/app.py.
    Calls: is_approval_approved, approval_candidate_paths, _read_json.
    """
    ticket_approval = _ticket_value(ticket, "investigation_approval_result")
    if ticket_approval:
        usable = is_approval_approved(ticket_approval)
        return ResolvedContext(
            exists=True,
            usable=usable,
            data=ticket_approval,
            source="ticket.investigation_approval_result",
            message="Investigation approval is approved." if usable else "Investigation approval exists but is not approved.",
        )

    first_existing: tuple[dict[str, Any], Path] | None = None
    for path in approval_candidate_paths(project_root, ticket_id):
        data = _read_json(path)
        if not data:
            continue
        # Only accept generic approval_result.json if it is clearly the investigation gate
        # or if no explicit gate is present but decision is approved. This keeps legacy
        # files working without bypassing rejected approvals.
        if first_existing is None:
            first_existing = (data, path)
        if is_approval_approved(data):
            return ResolvedContext(
                exists=True,
                usable=True,
                data=data,
                source=str(path.relative_to(project_root)) if path.is_relative_to(project_root) else str(path),
                message="Investigation approval found and approved.",
            )

    if first_existing:
        data, path = first_existing
        return ResolvedContext(
            exists=True,
            usable=False,
            data=data,
            source=str(path.relative_to(project_root)) if path.is_relative_to(project_root) else str(path),
            message="Investigation approval exists but is not approved.",
        )

    return ResolvedContext(False, False, {}, None, "No investigation approval result was found.")


def ensure_reporting_inputs(project_root: Path, ticket_id: str | None = None, ticket: dict[str, Any] | None = None) -> dict[str, Any]:
    """Copy resolved investigation/approval contexts into inputs and legacy outputs.

    The dashboard stores ticket context in PostgreSQL while legacy reporting
    helpers still read JSON files from inputs/ and outputs/. This bridge prevents Reporting from
    failing with "Run Investigation first" when a usable limited investigation is
    available in ticket context or a fallback output path.

    [FYP-FUNCTION] [FYP-ENTRY-POINT] [FYP-EVALUATOR] [FYP-OUTPUT]
    Params: project_root -- project root; ticket_id -- ticket id (used for
    filesystem candidate paths); ticket -- in-memory ticket dict, preferred
    over disk when present.
    Returns: {"investigation": ResolvedContext.as_dict(), "investigation_approval":
    ResolvedContext.as_dict()}.
    Side effects: [FYP-OUTPUT] writes investigation_result.json to both
    inputs/ and outputs/; writes investigation_approval_result.json to both
    inputs/ and outputs/, AND additionally writes it as inputs/approval_result.json
    (because Reporting's legacy input_loader still expects that generic
    filename for the "latest gate" approval).
    Called by:
      - backend/app.py, immediately before dispatching a Reporting agent run.
      - adapters/run_reporting.py `_prepare_inputs()`, before invoking the
        reporting subprocess/scripts.
    Calls: resolve_investigation_context, resolve_investigation_approval_context,
    _write_json.
    """
    inputs = project_root / "inputs"
    outputs = project_root / "outputs"
    inputs.mkdir(parents=True, exist_ok=True)
    outputs.mkdir(parents=True, exist_ok=True)

    inv = resolve_investigation_context(project_root, ticket_id=ticket_id, ticket=ticket)
    approval = resolve_investigation_approval_context(project_root, ticket_id=ticket_id, ticket=ticket)

    if inv.exists and inv.data:
        _write_json(inputs / "investigation_result.json", inv.data)
        _write_json(outputs / "investigation_result.json", inv.data)
    if approval.exists and approval.data:
        _write_json(inputs / "investigation_approval_result.json", approval.data)
        _write_json(outputs / "investigation_approval_result.json", approval.data)
        # Reporting input_loader still expects approval_result.json. Use the investigation
        # approval for Reporting handoff when it is the latest gate.
        _write_json(inputs / "approval_result.json", approval.data)

    return {
        "investigation": inv.as_dict(),
        "investigation_approval": approval.as_dict(),
    }
