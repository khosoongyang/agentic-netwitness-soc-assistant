"""Pure evaluation of the persisted canonical Parsing envelope.

Canonical audit Phase 5 rules, extracted unchanged so that BOTH
workflow.engine.load_parsing_result_for_run() (the canonical loader) and
workflow.readiness (Phase 6 stage readiness) apply the exact same semantics
without either one calling the other. Reads nothing and writes nothing: the
caller passes the incidents row it already has.
"""
from __future__ import annotations

import json

from agents.parsing.parser_context_guard import (
    CASE_IDENTITY_MATCH, CASE_IDENTITY_MISMATCH, resolve_case_identity,
)

MISSING_PARSING_RESULT = "missing_parsing_result"
PARSING_RUN_MISMATCH = "parsing_run_mismatch"
PARSING_IDENTITY_MISMATCH = "parsing_identity_mismatch"
PARSING_IDENTITY_UNVERIFIED = "parsing_identity_unverified"


def evaluate_parsing_envelope(state: dict | None, incident_id: str,
                              run_id: str) -> tuple[dict | None, str | None, str | None]:
    """Return (canonical Parsing result, None, None) when the run-scoped
    parsing_result_json envelope on `state` belongs to `run_id` and its case
    identity, re-resolved from the inline content (resolve_case_identity()),
    is a match for `incident_id`; otherwise (None, reason_code, detail).

    The returned result is the envelope plus its re-resolved
    `case_identity` -- exactly what load_parsing_result_for_run() returned
    in Phase 5."""
    if not state or state.get("run_id") != run_id:
        return None, PARSING_RUN_MISMATCH, (
            f"run {run_id!r} is not the current workflow run for case {incident_id!r}")
    try:
        summary = json.loads(state.get("parsing_result_json") or "{}")
    except Exception:
        return None, MISSING_PARSING_RESULT, "the persisted Parsing result is unreadable"
    if not isinstance(summary, dict) or not summary:
        return None, MISSING_PARSING_RESULT, f"no Parsing result is persisted for run {run_id!r}"
    if summary.get("run_id") != run_id:
        return None, PARSING_RUN_MISMATCH, (
            f"the persisted Parsing result belongs to run {summary.get('run_id')!r}, "
            f"not the current run {run_id!r}")
    case_identity = resolve_case_identity(summary, incident_id)
    if case_identity["status"] == CASE_IDENTITY_MISMATCH:
        return None, PARSING_IDENTITY_MISMATCH, (
            f"the persisted Parsing result belongs to case "
            f"{case_identity['parsed_case_reference']!r}, not {incident_id!r}")
    if case_identity["status"] != CASE_IDENTITY_MATCH:
        return None, PARSING_IDENTITY_UNVERIFIED, (
            f"the persisted Parsing result has no verifiable case identity "
            f"({case_identity['reason']}) -- canonical Parsing rerun required")
    out = dict(summary)
    out["case_identity"] = case_identity
    return out, None, None
