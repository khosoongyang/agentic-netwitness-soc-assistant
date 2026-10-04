"""Canonical stage readiness (canonical audit Phase 6).

One deterministic answer to "can stage X run for case C / run R now?", with a
stable machine-readable reason. Evaluation only: this module reads the
incidents row, the run-scoped approval history and (where a stage needs it)
the run's raw-incident artifact, and never writes statuses, approvals, DB
rows, files or Agent Activity.

It checks a stage's PREREQUISITES -- upstream stage statuses, the canonical
upstream results they produced (case + run identity, result shape) and the
analyst approvals they require. It deliberately does not check the target
stage's own status: whether that stage may transition (Pending -> Processing,
re-run, claim) stays the atomic job of workflow.state_store, so a worker that
has already claimed its stage can re-check readiness without invalidating
itself.

Callers: workflow.commands (before the state-store transition, and for
available_actions) and the durable stage workers in workflow.engine (after
claiming, which also covers resume / run_stage_chain).
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from typing import Any

from workflow import state_store as wss
from workflow.parsing_canonical import evaluate_parsing_envelope

STAGES = ("parsing", "triage", "threat_intel", "investigation", "reporting")

# Failure categories. "status" means an upstream stage's status does not allow
# this stage yet (commands report it as the existing STAGE_LOCKED); every other
# category is a canonical-input problem (STAGE_NOT_READY).
CATEGORY_STATUS = "status"
CATEGORY_INPUT = "input"
CATEGORY_IDENTITY = "identity"
CATEGORY_RUN = "run"
CATEGORY_APPROVAL = "approval"

# Degraded labels: optional evidence unavailable, the stage may still run.
DEGRADED_RAW_INCIDENT = "raw_incident_unavailable"
DEGRADED_THREAT_INTEL = "threat_intel_degraded"

# Which upstream statuses / inputs each stage needs (Phase 6 matrix).
_UPSTREAM_STAGES = {
    "triage": ("parsing",),
    "threat_intel": ("parsing", "triage"),
    "investigation": ("parsing", "triage", "threat_intel"),
    "reporting": ("parsing", "triage", "threat_intel", "investigation"),
}
_RAW_INCIDENT_REQUIRED = {"triage"}
_TI_DONE = {"Complete", "Complete with Warnings"}
_TI_RESULT_OK = {"completed", "completed_with_warnings"}
# Columns readiness reads; a caller-supplied row missing any of them (e.g.
# backend/services/case_service.py's display projection) is re-read in full.
_REQUIRED_COLUMNS = frozenset({
    "id", "run_id", "raw_json", "raw_incident_path", "parsing_status", "parsing_result_json",
    "triage_status", "triage_result_json", "threat_intel_status", "threat_intel_result_json",
    "investigation_status", "investigation_result_json", "investigation_attempt",
})


class StageNotReadyError(RuntimeError):
    """Raised by a stage worker whose prerequisites are not (or no longer)
    satisfied. Carries the full readiness record."""

    def __init__(self, readiness: dict):
        self.readiness = readiness
        super().__init__(
            f"{readiness.get('stage')} not ready: {readiness.get('reason_code')} — "
            f"{readiness.get('detail')}")


class _NotReady(Exception):
    def __init__(self, reason_code: str, category: str, detail: str):
        super().__init__(detail)
        self.reason_code = reason_code
        self.category = category
        self.detail = detail


def _read_state(case_id: str) -> dict | None:
    """SELECT-only read of the incidents row (no db_init(), no writes)."""
    try:
        with closing(wss.db_connect()) as con:
            row = con.execute("SELECT * FROM incidents WHERE id=?", (str(case_id),)).fetchone()
    except sqlite3.Error:
        return None
    return dict(row) if row else None


def _approval_rows(case_id: str, run_id: str, stage: str) -> list[dict]:
    """SELECT-only read of this run's decisions for one gate."""
    try:
        with closing(wss.db_connect()) as con:
            rows = con.execute(
                "SELECT * FROM workflow_approvals WHERE incident_id=? AND run_id=? "
                "AND approval_stage=? ORDER BY decided_at ASC",
                (str(case_id), run_id, stage)).fetchall()
    except sqlite3.Error:
        return []
    return [dict(r) for r in rows]


def _newest(rows: list[dict]) -> dict | None:
    # Canonical audit Phase 4 ordering (agents/reporting/reporting/
    # context_builder.py::_build_approval_context): newest by
    # (approval_attempt, decided_at).
    if not rows:
        return None
    return max(rows, key=lambda r: (int(r.get("approval_attempt") or 0), str(r.get("decided_at") or "")))


def _json_object(raw: Any) -> dict | None:
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


# ── Upstream status gates ──────────────────────────────────────────────────

def _check_upstream_status(state: dict, upstream: str) -> None:
    status = state.get(f"{upstream}_status")
    if upstream == "parsing":
        if status != "Complete":
            code = "parsing_failed" if status == "Failed" else "parsing_not_complete"
            raise _NotReady(code, CATEGORY_STATUS, f"Parsing is {status or 'not started'}, not Complete")
    elif upstream == "triage":
        if status != "Approved":
            code = "triage_rejected" if status == "Rejected" else "triage_not_approved"
            raise _NotReady(code, CATEGORY_STATUS, f"Triage is {status or 'not started'}, not Approved")
    elif upstream == "threat_intel":
        if status not in _TI_DONE:
            raise _NotReady("threat_intel_not_complete", CATEGORY_STATUS,
                            f"Threat Intelligence is {status or 'not started'}, not Complete")
    elif upstream == "investigation":
        if status != "Approved":
            code = "investigation_rejected" if status == "Rejected" else "investigation_not_approved"
            raise _NotReady(code, CATEGORY_STATUS,
                            f"Investigation is {status or 'not started'}, not Approved")


# ── Canonical inputs ───────────────────────────────────────────────────────

def _check_parsing(case_id: str, run_id: str, state: dict, inputs: dict) -> None:
    # Phase 5 rules, shared verbatim with load_parsing_result_for_run().
    result, code, detail = evaluate_parsing_envelope(state, case_id, run_id)
    if result is None:
        category = (CATEGORY_RUN if code == "parsing_run_mismatch"
                    else CATEGORY_INPUT if code == "missing_parsing_result" else CATEGORY_IDENTITY)
        raise _NotReady(code, category, f"Parsing: {detail}")
    if result.get("status") != "completed":
        raise _NotReady("parsing_failed", CATEGORY_INPUT,
                        f"Parsing: the persisted result status is {result.get('status')!r}")
    processed = result.get("processed_alert")
    if not isinstance(processed, dict) or not processed:
        raise _NotReady("missing_processed_alert", CATEGORY_INPUT,
                        "Parsing: the canonical result carries no processed_alert")
    inputs["parsing"] = result


def _check_raw_incident(case_id: str, run_id: str, state: dict, inputs: dict,
                        degraded: dict, *, required: bool) -> None:
    from workflow import engine   # artifact root / trust rules live there

    incident, code, detail = engine.inspect_raw_incident_for_run(case_id, run_id, state)
    if incident:
        inputs["raw_incident"] = incident
        return
    inputs["raw_incident"] = None   # a foreign or missing record is never handed on
    if code is None:
        code, detail = "missing_raw_incident", "the raw incident artifact is empty"
    if required:
        category = (CATEGORY_RUN if code == "raw_incident_run_mismatch"
                    else CATEGORY_IDENTITY if code == "raw_incident_identity_mismatch" else CATEGORY_INPUT)
        raise _NotReady(code, category, f"Raw incident: {detail}")
    degraded[DEGRADED_RAW_INCIDENT] = f"{code}: {detail}"


def _check_triage(case_id: str, run_id: str, state: dict, inputs: dict) -> None:
    triage = _json_object(state.get("triage_result_json"))
    if not triage:
        raise _NotReady("missing_triage_result", CATEGORY_INPUT,
                        "Triage: no Triage result is persisted for this run")
    if triage.get("error") or str(triage.get("status") or "").lower() == "failed":
        raise _NotReady("triage_result_failed", CATEGORY_INPUT,
                        "Triage: the persisted Triage result is a failure")
    ticket = triage.get("ticket") if isinstance(triage.get("ticket"), dict) else {}
    payload = triage.get("metakeys_payload") if isinstance(triage.get("metakeys_payload"), dict) else {}
    claims = [str(v) for v in (payload.get("incident_id"), ticket.get("incident_id")) if v not in (None, "")]
    if not claims:
        raise _NotReady("triage_identity_unverified", CATEGORY_IDENTITY,
                        "Triage: the result carries no case identity")
    foreign = next((c for c in claims if c != str(case_id)), None)
    if foreign is not None:
        raise _NotReady("triage_identity_mismatch", CATEGORY_IDENTITY,
                        f"Triage: the result belongs to case {foreign!r}, not {case_id!r}")
    if triage.get("run_id") != run_id:
        raise _NotReady("triage_run_mismatch", CATEGORY_RUN,
                        f"Triage: the result belongs to run {triage.get('run_id')!r}, "
                        f"not the current run {run_id!r}")
    if not str(ticket.get("unc") or "").strip():
        raise _NotReady("missing_triage_ticket", CATEGORY_INPUT,
                        "Triage: the result carries no real ticket")
    inputs["triage"] = triage


def _check_triage_approval(case_id: str, run_id: str) -> None:
    # Triage decisions carry no reliable execution attempt (known state_store
    # issue -- always stage_attempt=1), so, as in Phase 4, the newest
    # decision for THIS run is the current one.
    newest = _newest(_approval_rows(case_id, run_id, "triage"))
    decision = str((newest or {}).get("decision") or "").lower()
    if decision == "approved":
        return
    if decision == "rejected":
        raise _NotReady("triage_rejected", CATEGORY_APPROVAL,
                        "Triage: the newest Triage decision for this run is a rejection")
    raise _NotReady("triage_approval_not_recorded", CATEGORY_APPROVAL,
                    "Triage: no Triage approval is recorded for this run")


def _check_threat_intel(case_id: str, run_id: str, state: dict, inputs: dict,
                        degraded: dict) -> None:
    ti = _json_object(state.get("threat_intel_result_json"))
    if not ti:
        raise _NotReady("missing_threat_intel_result", CATEGORY_INPUT,
                        "Threat Intelligence: no result is persisted for this run")
    status = str(ti.get("status") or "").lower()
    if status not in _TI_RESULT_OK:
        raise _NotReady("threat_intel_result_failed", CATEGORY_INPUT,
                        f"Threat Intelligence: the persisted result status is {ti.get('status')!r}")
    if ti.get("incident_id") in (None, ""):
        raise _NotReady("threat_intel_identity_unverified", CATEGORY_IDENTITY,
                        "Threat Intelligence: the result carries no case identity")
    if str(ti.get("incident_id")) != str(case_id):
        raise _NotReady("threat_intel_identity_mismatch", CATEGORY_IDENTITY,
                        f"Threat Intelligence: the result belongs to case {ti.get('incident_id')!r}, "
                        f"not {case_id!r}")
    if ti.get("run_id") != run_id:
        raise _NotReady("threat_intel_run_mismatch", CATEGORY_RUN,
                        f"Threat Intelligence: the result belongs to run {ti.get('run_id')!r}, "
                        f"not the current run {run_id!r}")
    if status == "completed_with_warnings":
        # Provider failure / partial coverage is a valid TI execution state:
        # the stage result exists, its evidence is degraded.
        degraded[DEGRADED_THREAT_INTEL] = "Threat Intelligence completed with warnings"
    inputs["threat_intel"] = ti


def _check_investigation(case_id: str, run_id: str, state: dict, inputs: dict) -> None:
    inv = _json_object(state.get("investigation_result_json"))
    if not inv:
        raise _NotReady("missing_investigation_result", CATEGORY_INPUT,
                        "Investigation: no result is persisted for this run")
    if str(inv.get("status") or "").lower() in {"failed", "lock_lost"}:
        raise _NotReady("investigation_result_failed", CATEGORY_INPUT,
                        "Investigation: the persisted result is a failure")
    problem = wss.investigation_identity_problem(case_id, inv)   # Phase 1 rule
    if problem:
        raise _NotReady("investigation_identity_mismatch", CATEGORY_IDENTITY, f"Investigation: {problem}")
    if str(case_id) not in {str(inv.get("incident_id") or ""), str(inv.get("investigated_for") or "")}:
        raise _NotReady("investigation_identity_unverified", CATEGORY_IDENTITY,
                        "Investigation: the result carries no case identity")
    if inv.get("run_id") != run_id:
        raise _NotReady("investigation_run_mismatch", CATEGORY_RUN,
                        f"Investigation: the result belongs to run {inv.get('run_id')!r}, "
                        f"not the current run {run_id!r}")
    inputs["investigation"] = inv


def _check_investigation_approval(case_id: str, run_id: str, state: dict) -> None:
    # Phase 4: the current decision must be on the CURRENT investigation
    # attempt; an older attempt's decision is never inherited.
    attempt = int(state.get("investigation_attempt") or 1)
    rows = _approval_rows(case_id, run_id, "investigation")
    newest = _newest([r for r in rows if int(r.get("stage_attempt") or 0) == attempt])
    decision = str((newest or {}).get("decision") or "").lower()
    if decision == "approved":
        return
    if decision == "rejected":
        raise _NotReady("investigation_rejected", CATEGORY_APPROVAL,
                        f"Investigation: attempt {attempt} was rejected")
    older = " (an older attempt's decision is not inherited)" if rows else ""
    raise _NotReady("investigation_approval_not_recorded", CATEGORY_APPROVAL,
                    f"Investigation: no approval is recorded for attempt {attempt}{older}")


# ── Parsing start (the raw NetWitness record on the case row) ──────────────

def _check_case_record(case_id: str, state: dict, inputs: dict) -> None:
    raw = _json_object(state.get("raw_json"))
    if isinstance(raw, dict) and isinstance(raw.get("incident"), dict):
        raw = dict(raw["incident"])
    if not raw:
        raise _NotReady("missing_raw_incident", CATEGORY_INPUT,
                        "Parsing: the case has no raw NetWitness incident record")
    own_id = raw.get("id") or raw.get("incidentId")
    if own_id not in (None, "") and str(own_id) != str(case_id):
        raise _NotReady("raw_incident_identity_mismatch", CATEGORY_IDENTITY,
                        f"Parsing: the case's raw record is {str(own_id)!r}, not {case_id!r}")
    inputs["raw_record"] = raw


# ── Entry point ────────────────────────────────────────────────────────────

def evaluate_stage_readiness(case_id: str, stage: str, *, run_id: str | None = None,
                             state: dict | None = None) -> dict:
    """Evaluate whether `stage` may run for `case_id` on `run_id` (default:
    the case's current run). Read-only. Returns

        {"ready", "stage", "case_id", "run_id", "reason_code", "detail",
         "category", "degraded", "degraded_details", "inputs"}

    `inputs` holds the canonical inputs that were validated (parsing,
    raw_incident, triage, threat_intel, investigation, raw_record) for
    callers that want them; it is never meant to be serialised."""
    stage = str(stage or "").strip().lower()
    if stage not in STAGES:
        raise ValueError(f"unknown workflow stage: {stage!r}")
    if state is None or not _REQUIRED_COLUMNS <= set(state):
        state = _read_state(case_id) or state
    inputs: dict[str, Any] = {}
    degraded: dict[str, str] = {}
    effective_run = run_id if run_id is not None else ((state or {}).get("run_id") or None)
    result = {"ready": False, "stage": stage, "case_id": str(case_id), "run_id": effective_run,
              "reason_code": None, "detail": None, "category": None,
              "degraded": [], "degraded_details": {}, "inputs": inputs}
    try:
        if not state:
            raise _NotReady("case_not_found", CATEGORY_INPUT, "the case has no workflow state")
        if stage == "parsing":
            _check_case_record(case_id, state, inputs)
        else:
            if not state.get("run_id"):
                raise _NotReady("workflow_not_started", CATEGORY_STATUS,
                                "this case does not have an active workflow run")
            if effective_run != state.get("run_id"):
                raise _NotReady("run_not_current", CATEGORY_RUN,
                                f"run {effective_run!r} is not the current workflow run "
                                f"{state.get('run_id')!r}")
            upstream = _UPSTREAM_STAGES[stage]
            # Status gates first (cheap, no I/O), then the canonical inputs.
            for name in upstream:
                _check_upstream_status(state, name)
            _check_parsing(case_id, effective_run, state, inputs)
            if stage in _RAW_INCIDENT_REQUIRED:
                _check_raw_incident(case_id, effective_run, state, inputs, degraded, required=True)
            if "triage" in upstream:
                _check_triage(case_id, effective_run, state, inputs)
                _check_triage_approval(case_id, effective_run)
            if "threat_intel" in upstream:
                _check_threat_intel(case_id, effective_run, state, inputs, degraded)
            if "investigation" in upstream:
                _check_investigation(case_id, effective_run, state, inputs)
                _check_investigation_approval(case_id, effective_run, state)
            if stage not in _RAW_INCIDENT_REQUIRED:
                # Optional evidence last, so a stage that is not ready never
                # reads the artifact.
                _check_raw_incident(case_id, effective_run, state, inputs, degraded, required=False)
    except _NotReady as exc:
        result.update(reason_code=exc.reason_code, detail=exc.detail, category=exc.category)
        return result
    result.update(ready=True, degraded=sorted(degraded), degraded_details=dict(degraded))
    return result


def public_view(readiness: dict) -> dict:
    """The serialisable part of a readiness record (no canonical inputs)."""
    return {k: v for k, v in readiness.items() if k != "inputs"}
