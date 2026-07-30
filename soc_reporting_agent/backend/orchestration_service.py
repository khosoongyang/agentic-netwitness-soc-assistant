# ==============================================================================
# [FYP-FILE] File: soc_reporting_agent/backend/orchestration_service.py
# Important dependencies: __future__, backend, datetime, typing.
#
# Purpose:
#   Rule-based "Orchestration Agent" for the SOC Reporting subsystem. Given a
#   persisted ticket record, it decides the single next safe workflow action
#   (which agent stage should run next, or which human approval gate is
#   blocking progress) without executing any agent itself. This subsystem's
#   orchestration is deliberately conservative: agents only ever produce
#   evidence, analysts approve gates, and this module decides the next step.
#
# Main functionalities:
#   - build_orchestration_decision(ticket): the CURRENT, canonical decision
#     engine. Walks stage_workflow.STAGES in order and returns the first
#     stage that is not yet completed/approved, using stage_workflow as the
#     single source of truth for stage completion/lock/approval state.
#   - can_run_agent(ticket, agent): thin re-export of stage_workflow.can_run,
#     kept here so callers that already import orchestration_service do not
#     need a second import for a simple "can this stage run" check.
#   - Investigation usability / evidence-gap predicates
#     (is_investigation_usable_for_reporting, investigation_reporting_mode,
#     has_investigation_evidence_gap, evidence_gap_decision,
#     evidence_gap_decision_pending) that decide whether a limited
#     investigation result may still be carried into Reporting.
#   - _legacy_build_orchestration_decision / _legacy_can_run_agent: an older,
#     hand-rolled rule engine that inspects each *_result dict directly
#     instead of going through stage_workflow. Retained in the file for
#     reference/history only -- see "Legacy" section banner below for why it
#     is not treated as dead code to delete.
#
# Inputs:
#   - ticket: dict[str, Any] -- a persisted SOC ticket/casework record
#     containing per-stage result payloads (parsing_result, triage_result,
#     threat_intel_result, investigation_result, reporting_result,
#     soc_review_result, approval_result, investigation_approval_result),
#     correlation_recommendations, current_stage, and status.
#
# Outputs:
#   - dict built by _decision(): status, agent/next_agent, next_label/label,
#     allowed, can_continue, workflow_decision, current_stage, ticket_id,
#     requires_human_approval, approval_gate, reason, required_inputs,
#     missing_inputs, risk_notes, validation_status, created_at.
#     This is the "orchestration decision" object surfaced to the dashboard
#     as next_step / orchestration_decision_result.
#
# Workflow position:
#   Runs on demand, after any stage completes or any analyst approval is
#   recorded -- it is not itself a pipeline stage. It sits above
#   stage_workflow.py (which owns the low-level per-stage status/lock state)
#   and is consumed by the Flask dashboard backend and by
#   ticket_workflow.next_agent() to answer "what should happen next for this
#   ticket".
#
# Called by:
#   - soc_reporting_agent/backend/app.py
#     (`from backend.orchestration_service import build_orchestration_decision`,
#     used in the `POST /api/tickets/<ticket_id>/run-next-step` route to
#     decide and then kick off the next agent run).
#   - soc_reporting_agent/backend/ticket_workflow.py
#     (`next_agent()` performs a deferred/local import of
#     build_orchestration_decision to avoid a circular import with this
#     module at package load time).
#
# Calls:
#   - soc_reporting_agent/backend/stage_workflow.py
#     (STAGES, status, can_run, has_run, workflow_complete, status_message)
#     -- the canonical stage-completion/lock/approval state machine.
#
# Key evaluator search terms:
#   orchestration entry point, build_orchestration_decision, next step,
#   workflow decision, stage lock, approval gate, evidence gap,
#   run-next-step, can_run_agent.
# ==============================================================================

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend import stage_workflow


# [FYP-SECTION] Decision vocabulary -----------------------------------------
# These sets normalise the many different status/decision strings that
# individual agents may write into their *_result payloads down to a small,
# well-known vocabulary the orchestration logic can branch on safely.
COMPLETED_STATUSES = {
    "completed", "completed_limited", "completed_with_warnings", "completed_with_evidence_gaps",
    "generated_with_warnings", "success", "passed", "ready",
}
# [FYP-DECISION] Investigation statuses that are "usable" for Reporting even
# though they represent a limited/partial result (evidence gaps, missing
# telemetry, etc.) rather than a full clean pass.
USABLE_LIMITED_INVESTIGATION_STATUSES = {
    "completed", "completed_limited", "completed_with_warnings", "completed_with_evidence_gaps",
    "needs_more_data", "waiting_for_telemetry", "insufficient_telemetry", "needs_analyst_review",
    "partial", "partial_success",
}
# [FYP-DECISION] [FYP-FALLBACK] Investigation statuses that must always block
# Reporting -- these represent true execution/context failures, not evidence
# gaps, so there is no safe fallback content to report on.
BLOCKING_INVESTIGATION_STATUSES = {
    "failed", "crashed", "invalid_output", "not_started", "missing_required_context",
    "execution_error", "timed_out", "timeout", "error",
}
# [FYP-APPROVAL] Decision values recorded by an analyst (or auto-approval
# short-circuits) that count as "approved" for a given gate.
APPROVED_DECISIONS = {"approved", "approve", "completed", "continue_to_reporting"}

# [FYP-UI] Human-readable labels for each agent, used for activity-log
# messages and any UI surface that still keys off agent name rather than
# stage_workflow.STAGES[*]["label"].
AGENT_LABELS = {
    "parsing": "Parsing & Normalisation",
    "triage": "Triage Agent",
    "threat_intel": "Threat Intelligence Enrichment",
    "investigation": "Investigation Agent",
    "reporting": "Reporting Agent",
    "orchestration": "Orchestration Agent",
}


# [FYP-CONFIG] Maps agent name -> the stage_workflow.STAGES "key" for that
# agent, used to fill in current_stage when a decision does not explicitly
# set one.
_STAGE_BY_AGENT = {
    "parsing": "parsing_normalisation",
    "triage": "triage",
    "threat_intel": "threat_intelligence",
    "investigation": "investigation",
    "reporting": "reporting",
}


def now_iso() -> str:
    """[FYP-FUNCTION] Current UTC timestamp, ISO-8601. Used to stamp decision objects."""
    return datetime.now(timezone.utc).isoformat()


def norm(value: Any) -> str:
    """[FYP-FUNCTION] Normalise any value to a lowercase, underscore-separated string.

    Used throughout this module to make status/decision string comparisons
    resilient to case and spacing differences between what agents write
    ("Needs More Data") and what this module compares against
    ("needs_more_data").
    """
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _result(ticket: dict[str, Any], key: str) -> dict[str, Any]:
    """[FYP-FUNCTION] Safely read a nested result dict off a ticket (never raises, never returns non-dict)."""
    value = ticket.get(key) or {}
    return value if isinstance(value, dict) else {}


def _has_result(result: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] True when a stage result dict exists and is non-empty."""
    return bool(result and isinstance(result, dict))


def _first(*values: Any, default: Any = None) -> Any:
    """[FYP-FUNCTION] Return the first "meaningful" value (not None/""/[]/{}) among values, else default."""
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return default


# [FYP-SECTION] Investigation usability & evidence-gap helpers --------------
# These helpers decide whether a (possibly limited) Investigation result can
# still be carried into Reporting, and whether the analyst needs to make an
# explicit "continue with limitations vs. return to Triage" decision first.

def _has_usable_investigation_content(result: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] Check whether an investigation_result carries any reportable content.

    Params: result -- investigation_result dict (source: ticket["investigation_result"]).
    Returns: True if any summary/classification field OR any evidence-list
    field (findings, missing_evidence, iocs, ...) is populated.
    Used by: is_investigation_usable_for_reporting (below) as the fallback
    check once status alone is not conclusive.
    """
    if not _has_result(result):
        return False
    for key in ("summary", "investigation_summary", "classification", "likely_scenario", "recommended_next_action"):
        if result.get(key) not in (None, "", [], {}):
            return True
    for key in ("findings", "missing_evidence", "missing_fields", "available_evidence", "observed_evidence", "iocs"):
        if result.get(key) not in (None, "", [], {}):
            return True
    return False


def is_investigation_usable_for_reporting(result: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] [FYP-DECISION] Decide whether Reporting may run on this Investigation result.

    Params: result -- investigation_result dict.
    Returns: bool. True unless the status is a true execution/context
    failure (BLOCKING_INVESTIGATION_STATUSES) or the result has no usable
    content at all. A "limited" investigation (missing telemetry, partial
    evidence, etc.) is still usable -- Reporting documents the gap instead of
    being blocked outright.
    Called by: build_orchestration_decision / _legacy_build_orchestration_decision
    (this file), backend/ticket_workflow.py, backend/reporting_context_resolver.py.
    """
    if not _has_result(result):
        return False
    status = norm(result.get("status") or result.get("report_status") or result.get("workflow_decision"))
    if status in BLOCKING_INVESTIGATION_STATUSES:
        return False
    if status in USABLE_LIMITED_INVESTIGATION_STATUSES:
        return _has_usable_investigation_content(result) or status in COMPLETED_STATUSES
    return _has_usable_investigation_content(result)


def investigation_reporting_mode(result: dict[str, Any]) -> str:
    """[FYP-FUNCTION] [FYP-DECISION] Return "with_limitations" or "standard" reporting mode for an investigation result."""
    status = norm(result.get("status") or result.get("report_status"))
    if status in {
        "completed_limited", "completed_with_warnings", "completed_with_evidence_gaps", "needs_more_data",
        "waiting_for_telemetry", "insufficient_telemetry", "partial", "partial_success", "needs_analyst_review",
    }:
        return "with_limitations"
    return "standard"


def has_investigation_evidence_gap(result: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] [FYP-DECISION] True when Investigation flagged missing evidence/telemetry that needs an analyst decision."""
    if not _has_result(result):
        return False
    status = norm(result.get("status") or result.get("report_status") or result.get("workflow_decision"))
    if status in {
        "completed_with_evidence_gaps", "completed_limited", "needs_more_data", "waiting_for_telemetry",
        "insufficient_telemetry", "partial", "partial_success",
    }:
        return True
    return bool(result.get("missing_evidence") or result.get("missing_fields") or result.get("triage_requery_request"))


def evidence_gap_decision(ticket: dict[str, Any]) -> str:
    """[FYP-FUNCTION] Read the analyst's recorded evidence-gap decision ("continue_to_reporting" / "return_to_triage")."""
    approval = _result(ticket, "investigation_approval_result")
    return norm(approval.get("evidence_gap_decision") or approval.get("decision"))


def evidence_gap_decision_pending(ticket: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] [FYP-APPROVAL] True when Investigation has an evidence gap and the analyst has not yet chosen how to proceed."""
    inv = _result(ticket, "investigation_result")
    if not has_investigation_evidence_gap(inv):
        return False
    decision = evidence_gap_decision(ticket)
    return decision not in {"continue_to_reporting", "approved", "approve", "completed", "return_to_triage"}


def approval_complete(ticket: dict[str, Any], gate: str) -> bool:
    """[FYP-FUNCTION] [FYP-APPROVAL] Check whether a named approval gate ("triage_approval", "investigation_approval", ...) is satisfied.

    Params: ticket -- ticket dict; gate -- gate name (normalised internally).
    Returns: True if the relevant approval_result/investigation_approval_result
    dict carries a decision/approval_status/status in APPROVED_DECISIONS.
    """
    gate_norm = norm(gate)
    if gate_norm in {"triage_approval", "approval", "analyst_approval"}:
        data = _result(ticket, "approval_result")
    elif gate_norm in {"investigation_approval", "investigation_evidence_decision"}:
        data = _result(ticket, "investigation_approval_result")
    else:
        data = _result(ticket, "approval_result") or _result(ticket, "investigation_approval_result")
    decision = norm(data.get("decision") or data.get("approval_status") or data.get("status"))
    return decision in APPROVED_DECISIONS


# [FYP-SECTION] Triage context helpers ---------------------------------------

def _triage_has_core_context(triage: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] True when Triage produced both a severity/classification AND a confidence value."""
    severity = _first(triage.get("severity"), triage.get("classification"), triage.get("priority"))
    confidence = _first(triage.get("confidence"), triage.get("confidence_level"))
    return severity not in (None, "", [], {}) and confidence not in (None, "", [], {})


def _triage_requires_approval(triage: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] [FYP-DECISION] [FYP-APPROVAL] Decide whether this Triage result must be gated behind SOC approval.

    Honours an explicit approval_required flag (bool or truthy string) from
    the Triage output when present; otherwise falls back to a risk heuristic:
    Critical/High severity or risk_score >= 70 requires approval.
    """
    explicit = triage.get("approval_required")
    if isinstance(explicit, bool):
        return explicit
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip().lower() in {"1", "true", "yes", "y", "required", "pending"}
    severity = str(_first(triage.get("severity"), triage.get("classification"), triage.get("priority"), default="")).strip().title()
    try:
        risk_score = float(triage.get("risk_score") or 0)
    except Exception:
        # [FYP-FALLBACK] Non-numeric/missing risk_score falls back to 0 rather
        # than raising, so a malformed Triage payload cannot crash decisioning.
        risk_score = 0
    return severity in {"Critical", "High"} or risk_score >= 70


# [FYP-SECTION] Decision object builder --------------------------------------

def _decision(
    ticket: dict[str, Any],
    *,
    workflow_decision: str,
    next_agent: str | None,
    label: str,
    allowed: bool,
    reason: str,
    current_stage: str | None = None,
    requires_human_approval: bool = False,
    approval_gate: str | None = None,
    required_inputs: list[str] | None = None,
    missing_inputs: list[str] | None = None,
    risk_notes: list[str] | None = None,
    validation_status: str = "passed",
) -> dict[str, Any]:
    """[FYP-FUNCTION] Build the single canonical "orchestration decision" dict.

    Params: ticket plus keyword-only fields describing the decision (see
    module header "Outputs" for the full field list and their meaning).
    Returns: dict consumed by the dashboard as next_step /
    orchestration_decision_result. Every branch of
    build_orchestration_decision / _legacy_build_orchestration_decision
    funnels through this single builder so the output shape stays
    consistent, including the derived can_continue flag and the
    validation_status auto-downgrade to "blocked" when missing_inputs is set.
    Called by: build_orchestration_decision, _legacy_build_orchestration_decision.
    """
    next_agent = norm(next_agent) or None
    decision = {
        "status": "completed",
        "agent": next_agent,  # compatibility with the existing next_step UI contract
        "next_agent": next_agent,
        "next_label": label,
        "label": label,
        "allowed": bool(allowed),
        "can_continue": bool(allowed and next_agent),
        "workflow_decision": workflow_decision,
        "current_stage": current_stage or ticket.get("current_stage") or _STAGE_BY_AGENT.get(next_agent or "", "unknown"),
        "ticket_id": ticket.get("ticket_id"),
        "requires_human_approval": bool(requires_human_approval),
        "approval_gate": approval_gate,
        "reason": reason,
        "required_inputs": required_inputs or [],
        "missing_inputs": missing_inputs or [],
        "risk_notes": risk_notes or [],
        "validation_status": validation_status if not missing_inputs else "blocked",
        "created_at": now_iso(),
    }
    return decision


# [FYP-SECTION] Correlation / incident-grouping helpers ----------------------

def pending_correlation_recommendations(ticket: dict[str, Any]) -> list[dict[str, Any]]:
    """[FYP-FUNCTION] Return correlation_recommendations entries still awaiting analyst review ("pending" status)."""
    items = ticket.get("correlation_recommendations") or []
    if not isinstance(items, list):
        return []
    return [item for item in items if norm(item.get("status")) == "pending"]


def _correlation_has_result(ticket: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] True when a correlation_result has been written with a non-empty status. (Unused by the active decision path; retained for the legacy engine below.)"""
    result = _result(ticket, "correlation_result")
    return bool(result and result.get("status") not in {"", None})


# [FYP-SECTION] Legacy rule-based decision engine (reference only) ----------
# The two functions below (_legacy_build_orchestration_decision,
# _legacy_can_run_agent) are the ORIGINAL orchestration rule engine. They
# inspect each *_result dict directly rather than delegating to
# stage_workflow.py's canonical per-stage state machine.
#
# [FYP-USED-BY] No direct caller confidently identified: a repo-wide search
# found no import or call site for either function outside this file. The
# active decision path is build_orchestration_decision() further below,
# which is driven by stage_workflow.STAGES. These are kept only as
# documented reference/history of the pre-stage_workflow rule set and are
# NOT part of the live request path.

def _legacy_build_orchestration_decision(ticket: dict[str, Any]) -> dict[str, Any]:
    """Return the next workflow decision for one SOC ticket.

    The Orchestration Agent is deliberately rule-based. Agents provide evidence,
    analysts approve gates, and this service decides only the safe next step.

    [FYP-FUNCTION] Legacy (superseded) orchestration rule engine.
    Params: ticket -- ticket dict (same shape as build_orchestration_decision).
    Returns: decision dict via _decision(), branching directly over each
    *_result field instead of stage_workflow state.
    Called by: not called anywhere in this repository (see section note above).
    Calls: _decision, _has_result, pending_correlation_recommendations,
    _triage_has_core_context, _triage_requires_approval, approval_complete,
    is_investigation_usable_for_reporting, investigation_reporting_mode,
    evidence_gap_decision_pending.
    """
    ticket = ticket or {}
    stage = norm(ticket.get("current_stage"))
    status = norm(ticket.get("status"))
    parsing = _result(ticket, "parsing_result")
    triage = _result(ticket, "triage_result")
    threat = _result(ticket, "threat_intel_result")
    correlation = _result(ticket, "correlation_result")
    investigation = _result(ticket, "investigation_result")
    reporting = _result(ticket, "reporting_result")
    soc_review = _result(ticket, "soc_review_result")

    if stage == "triage" and "evidence" in status:
        return _decision(
            ticket,
            workflow_decision="return_to_triage_for_more_evidence",
            next_agent="triage",
            label="Run Triage for More Evidence",
            allowed=True,
            reason="Investigation requested additional NetWitness evidence from Triage.",
            current_stage="triage",
            required_inputs=["related_alerts", "investigation_result.triage_requery_request"],
            risk_notes=["Triage owns NetWitness re-query and enrichment before the workflow continues."],
        )

    if not _has_result(parsing):
        return _decision(
            ticket,
            workflow_decision="run_parsing_normalisation",
            next_agent="parsing",
            label="Run Parsing & Normalisation",
            allowed=True,
            reason="Ticket needs raw alert parsing and normalisation before agent analysis.",
            current_stage="parsing_normalisation",
            required_inputs=["related_alerts.raw"],
        )

    if not _has_result(triage):
        return _decision(
            ticket,
            workflow_decision="run_triage",
            next_agent="triage",
            label="Run Triage",
            allowed=True,
            reason="Parsed alert context is ready. Triage can classify severity, confidence, and next action.",
            current_stage="triage",
            required_inputs=["parsing_result"],
        )

    pending_grouping = pending_correlation_recommendations(ticket)
    if pending_grouping:
        triage_grouping = [r for r in pending_grouping if norm(r.get("source_stage")) in {"triage", "correlation", ""}]
        if triage_grouping:
            return _decision(
                ticket,
                workflow_decision="awaiting_triage_incident_grouping_review",
                next_agent=None,
                label="Review Triage Incident Grouping",
                allowed=False,
                reason=f"{len(triage_grouping)} incident grouping recommendation(s) from Triage require SOC analyst review before the workflow continues.",
                current_stage="triage_grouping_review",
                requires_human_approval=True,
                approval_gate="incident_grouping_review",
                required_inputs=["incident_grouping.review_decision"],
                risk_notes=["Analyst may confirm, reject, edit, move, split, or merge alert groupings."],
            )

    missing_before_investigation: list[str] = []
    if not _triage_has_core_context(triage):
        if _first(triage.get("severity"), triage.get("classification"), triage.get("priority")) in (None, "", [], {}):
            missing_before_investigation.append("triage_result.severity")
        if _first(triage.get("confidence"), triage.get("confidence_level")) in (None, "", [], {}):
            missing_before_investigation.append("triage_result.confidence")
    if missing_before_investigation:
        return _decision(
            ticket,
            workflow_decision="blocked_missing_triage_context",
            next_agent=None,
            label="Triage Context Required",
            allowed=False,
            reason="Investigation is blocked because the Triage Agent output is missing severity or confidence.",
            current_stage="triage",
            required_inputs=["triage_result.severity", "triage_result.confidence"],
            missing_inputs=missing_before_investigation,
        )

    if _triage_requires_approval(triage) and not approval_complete(ticket, "triage_approval"):
        return _decision(
            ticket,
            workflow_decision="awaiting_soc_approval",
            next_agent=None,
            label="Awaiting SOC Approval",
            allowed=False,
            reason="SOC analyst approval of the Triage result is required before Threat Intelligence Enrichment can run.",
            current_stage="triage_approval",
            requires_human_approval=True,
            approval_gate="triage_approval",
            required_inputs=["approval_result"],
            risk_notes=["Approval gate prevents automated progression into Threat Intelligence, Investigation, or containment."],
        )

    if not _has_result(threat):
        return _decision(
            ticket,
            workflow_decision="run_threat_intelligence",
            next_agent="threat_intel",
            label="Run Threat Intel",
            allowed=True,
            reason="Triage is complete and any required SOC approval is complete. Threat Intelligence does not require SOC approval.",
            current_stage="threat_intelligence",
            required_inputs=["triage_result", "iocs"],
        )

    if not _has_result(investigation):
        return _decision(
            ticket,
            workflow_decision="run_investigation",
            next_agent="investigation",
            label="Run Investigation",
            allowed=True,
            reason="Triage and Threat Intelligence are complete. Enriched alert context is ready for Investigation.",
            current_stage="investigation",
            required_inputs=["triage_result", "threat_intel_result", "approval_result"],
        )

    # Investigation can generate its own linking/archive recommendations. Those
    # must be reviewed before Reporting, but there is no separate visible
    # correlation stage in the analyst workflow.
    pending_grouping = pending_correlation_recommendations(ticket)
    if pending_grouping:
        archive_count = len([r for r in pending_grouping if r.get("requires_archive_approval") or r.get("archive_after_approval")])
        return _decision(
            ticket,
            workflow_decision="archive_approval_required" if archive_count else "investigation_incident_grouping_review_required",
            next_agent=None,
            label="Review Investigation Incident Grouping",
            allowed=False,
            reason=f"{len(pending_grouping)} investigation-generated incident grouping recommendation(s) require SOC analyst review before Reporting. {archive_count} recommendation(s) include duplicate-ticket archive actions that will only run after approval.",
            current_stage="investigation_grouping_review",
            requires_human_approval=True,
            approval_gate="incident_grouping_review",
            required_inputs=["incident_grouping.review_decision"],
            risk_notes=["No alerts or tickets are archived until the analyst confirms or edits the recommendation."],
        )

    if not is_investigation_usable_for_reporting(investigation):
        return _decision(
            ticket,
            workflow_decision="blocked_investigation_not_usable",
            next_agent=None,
            label="Investigation Blocked",
            allowed=False,
            reason="Investigation did not produce usable findings. Re-run Investigation or return to Triage for more context.",
            current_stage="investigation",
            required_inputs=["investigation_result.usable_findings"],
            missing_inputs=["usable_investigation_findings"],
        )

    reporting_mode = investigation_reporting_mode(investigation)
    if evidence_gap_decision_pending(ticket):
        return _decision(
            ticket,
            workflow_decision="evidence_gap_decision_required",
            next_agent=None,
            label="Choose Evidence Gap Action",
            allowed=False,
            reason="Investigation produced usable findings but has evidence gaps. Choose whether to continue to Reporting with limitations or return to Triage for more evidence.",
            current_stage="investigation_evidence_decision",
            requires_human_approval=True,
            approval_gate="investigation_evidence_gap_decision",
            required_inputs=["investigation_approval_result.evidence_gap_decision"],
            risk_notes=["Limited investigation context must be acknowledged by the analyst before Reporting."],
        )

    if not approval_complete(ticket, "investigation_approval"):
        reason = "SOC analyst approval is required before Reporting can run."
        if reporting_mode == "with_limitations":
            reason = "Investigation completed with evidence gaps. SOC analyst approval is required before Reporting can run with limitations."
        return _decision(
            ticket,
            workflow_decision="awaiting_investigation_approval",
            next_agent=None,
            label="Awaiting Investigation Approval",
            allowed=False,
            reason=reason,
            current_stage="investigation_approval",
            requires_human_approval=True,
            approval_gate="investigation_approval",
            required_inputs=["investigation_approval_result"],
        )

    if not _has_result(reporting):
        label = "Run Reporting with Limitations" if reporting_mode == "with_limitations" else "Generate Report"
        reason = "Investigation approval is complete. Reporting can run with documented evidence limitations." if reporting_mode == "with_limitations" else "Investigation approval is complete and Reporting can run."
        return _decision(
            ticket,
            workflow_decision="run_reporting",
            next_agent="reporting",
            label=label,
            allowed=True,
            reason=reason,
            current_stage="reporting",
            required_inputs=["triage_result", "threat_intel_result", "investigation_result", "investigation_approval_result"],
        )

    if not _has_result(soc_review):
        return _decision(
            ticket,
            workflow_decision="awaiting_soc_review",
            next_agent=None,
            label="Awaiting SOC Analyst Review",
            allowed=False,
            reason="SOC analyst review is required before case closure.",
            current_stage="soc_analyst_review",
            requires_human_approval=True,
            approval_gate="soc_analyst_review",
            required_inputs=["soc_review_result"],
        )

    return _decision(
        ticket,
        workflow_decision="ready_for_closure",
        next_agent=None,
        label="Ready for Closure",
        allowed=False,
        reason="All workflow stages are complete and the case can be closed.",
        current_stage="case_closure",
        required_inputs=[],
    )


def _legacy_can_run_agent(ticket: dict[str, Any], agent: str) -> tuple[bool, str]:
    """[FYP-FUNCTION] Legacy (superseded) per-agent eligibility check, mirroring _legacy_build_orchestration_decision's rules.

    Params: ticket -- ticket dict; agent -- agent name to check.
    Returns: (allowed: bool, reason: str).
    Called by: not called anywhere in this repository (see section note above);
    superseded by stage_workflow.can_run / can_run_agent() below.
    """
    agent_norm = norm(agent)
    if agent_norm == "correlation":
        return True, "Correlation can run to recommend alert grouping."
    if agent_norm == "orchestration":
        return True, "Orchestration can run to refresh the workflow decision."
    parsing = _result(ticket, "parsing_result")
    triage = _result(ticket, "triage_result")
    threat = _result(ticket, "threat_intel_result")
    correlation = _result(ticket, "correlation_result")
    investigation = _result(ticket, "investigation_result")

    if agent_norm in {"parsing", "parsing_normalisation"}:
        return True, "Parsing can run for a new ticket or retry."
    if agent_norm == "triage":
        if not _has_result(parsing):
            return False, "Run Parsing & Normalisation first. Triage requires normalised alert context."
        return True, "Triage can run."
    if agent_norm in {"threat_intel", "threat_intelligence"}:
        if not _has_result(triage):
            return False, "Run Triage Agent first. Threat intelligence requires triage context."
        if not _triage_has_core_context(triage):
            return False, "Threat intelligence requires Triage severity and confidence. Re-run Triage before continuing."
        if _triage_requires_approval(triage) and not approval_complete(ticket, "triage_approval"):
            return False, "SOC analyst approval is required before Threat Intelligence Enrichment can run."
        if pending_correlation_recommendations(ticket):
            return False, "Review pending incident grouping recommendations before Threat Intelligence Enrichment."
        return True, "Threat intelligence enrichment can run."
    if agent_norm == "investigation":
        if not _has_result(threat):
            return False, "Run Threat Intelligence Enrichment first. Investigation requires enriched IOC context."
        if pending_correlation_recommendations(ticket):
            return False, "Review pending incident grouping recommendations before Investigation."
        if not _triage_has_core_context(triage):
            return False, "Investigation requires Triage severity and confidence. Re-run Triage before continuing."
        if _triage_requires_approval(triage) and not approval_complete(ticket, "triage_approval"):
            return False, "SOC analyst approval is required before Investigation can run."
        return True, "Investigation can run."
    if agent_norm == "reporting":
        if not _has_result(investigation):
            return False, "Run Investigation first. Reporting requires investigation context."
        if pending_correlation_recommendations(ticket):
            return False, "Review pending incident grouping recommendations before Reporting."
        if not is_investigation_usable_for_reporting(investigation):
            return False, "Investigation did not produce usable findings. Re-run Investigation or return to Triage for more context."
        if evidence_gap_decision_pending(ticket):
            return False, "Choose Continue to Reporting Agent or Go back to Triage before running Reporting."
        if not approval_complete(ticket, "investigation_approval"):
            if investigation_reporting_mode(investigation) == "with_limitations":
                return False, "SOC analyst approval is required before Reporting can run with investigation evidence gaps."
            return False, "SOC analyst approval is required before Reporting can run."
        if investigation_reporting_mode(investigation) == "with_limitations":
            return True, "Reporting can run with documented investigation limitations."
        return True, "Reporting can run."
    return False, "Unknown agent."


# [FYP-SECTION] Canonical stage_workflow-driven decision engine (ACTIVE) -----
# This is the live decision path used by the dashboard. Unlike the legacy
# engine above, it does not re-derive stage completion/approval logic itself;
# it delegates entirely to stage_workflow.py (STAGES order, status(), and
# can_run()) so there is exactly one source of truth for stage lock/approval
# state shared between the orchestration decision, the agent panel, and the
# workflow-steps UI.

def build_orchestration_decision(ticket: dict[str, Any]) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-ENTRY-POINT] [FYP-EVALUATOR] Return the next allowed action from the canonical persisted stage state.

    Params: ticket -- persisted ticket dict (source: CASEWORK.get_ticket() in
    backend/app.py, i.e. Postgres-backed casework storage).
    Returns: decision dict via _decision() -- see module header "Outputs".
    Side effects: none (pure function over the ticket dict); the caller is
    responsible for persisting the decision if desired.
    Called by:
      - backend/app.py, route `POST /api/tickets/<ticket_id>/run-next-step`
        (THE orchestration entry point exercised by the dashboard's
        "Run Next Step" action).
      - backend/ticket_workflow.py `next_agent()` (deferred import).
    Calls: stage_workflow.workflow_complete, stage_workflow.STAGES,
    stage_workflow.status, stage_workflow.can_run, stage_workflow.has_run,
    stage_workflow.status_message, _decision.
    Decision logic:
      1. If every stage is complete/approved -> "workflow_completed".
      2. Otherwise, walk STAGES in fixed pipeline order. For the first stage
         not yet completed/approved:
         - "pending_approval" -> block and report the approval gate.
         - can_run() True -> allow running (labelled "Re-run" if has_run()
           is already True, i.e. this is a rerun after an upstream change).
         - otherwise -> blocked, using stage_workflow.status_message() (or
           the can_run() reason as a fallback) to explain why it is locked.
    """
    ticket = ticket or {}
    if stage_workflow.workflow_complete(ticket):
        return _decision(
            ticket,
            workflow_decision="workflow_completed",
            next_agent=None,
            label="Workflow Completed",
            allowed=False,
            reason="Reporting is completed and approved. The workflow is complete.",
            current_stage="case_closure",
        )

    for stage in stage_workflow.STAGES:
        current = stage_workflow.status(ticket, stage)
        if current in {"completed", "approved"}:
            continue
        if current == "pending_approval":
            return _decision(
                ticket,
                workflow_decision=f"awaiting_{stage['approval_gate']}",
                next_agent=None,
                label=f"Approve {stage['label']}",
                allowed=False,
                reason=f"{stage['label']} is complete and must be approved before the next stage can run.",
                current_stage=stage["approval_gate"],
                requires_human_approval=True,
                approval_gate=stage["approval_gate"],
                required_inputs=[stage["approval_gate"]],
            )

        allowed, reason = stage_workflow.can_run(ticket, stage)
        if allowed:
            rerun = stage_workflow.has_run(ticket, stage)
            return _decision(
                ticket,
                workflow_decision=f"{'rerun' if rerun else 'run'}_{stage['key']}",
                next_agent=stage["agent"],
                label=f"{'Re-run' if rerun else 'Start'} {stage['label']}",
                allowed=True,
                reason=reason,
                current_stage=stage["key"],
                required_inputs=[] if stage["agent"] == "parsing" else [stage_workflow.STAGES[stage_workflow.STAGES.index(stage) - 1]["result_key"]],
            )

        return _decision(
            ticket,
            workflow_decision=f"blocked_{stage['key']}",
            next_agent=None,
            label=f"{stage['label']} Locked",
            allowed=False,
            reason=stage_workflow.status_message(ticket, stage) or reason,
            current_stage=stage["key"],
            validation_status="blocked",
        )

    return _decision(
        ticket,
        workflow_decision="workflow_completed",
        next_agent=None,
        label="Workflow Completed",
        allowed=False,
        reason="All workflow stages are complete and approved.",
        current_stage="case_closure",
    )


def can_run_agent(ticket: dict[str, Any], agent: str) -> tuple[bool, str]:
    """[FYP-FUNCTION] [FYP-EVALUATOR] [FYP-STAGE-LOCK] Public "can this stage run right now" check.

    Params: ticket -- ticket dict; agent -- stage/agent identifier.
    Returns: (allowed, reason) tuple, delegated straight to
    stage_workflow.can_run so this module and stage_workflow never disagree
    about stage eligibility.
    Called by: backend/app.py (agent-run eligibility checks alongside the
    AGENT_ADAPTERS dispatch table).
    Calls: stage_workflow.can_run.
    """
    return stage_workflow.can_run(ticket, agent)
