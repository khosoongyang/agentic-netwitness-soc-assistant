# ==============================================================================
# [FYP-FILE] File: soc_reporting_agent/backend/ticket_workflow.py
# Important dependencies: __future__, backend, typing.
#
# Purpose:
#   Ticket/case-level workflow presentation and decision-surfacing layer for
#   the SOC Reporting subsystem. Where stage_workflow.py owns the raw
#   per-stage state machine (locked/ready/running/pending_approval/approved/
#   rerun_required), this module turns that state into the structures the
#   dashboard/API actually returns: the analyst-facing agent panel, the
#   ordered workflow steps list, the "next step" summary, and a fully
#   decorated ticket dict.
#
# Main functionalities:
#   - decorate_ticket(ticket): [FYP-ENTRY-POINT] the main function other
#     modules call. Adds workflow_steps, next_step, orchestration_decision_
#     result, and agent_panel onto a raw ticket dict before it is returned
#     from the API.
#   - agent_panel(ticket) / workflow_steps(ticket): build the two dashboard
#     UI structures directly from stage_workflow's canonical per-stage state
#     (the CURRENT, active implementations).
#   - next_agent(ticket): computes the single "what should happen next"
#     answer by delegating to orchestration_service.build_orchestration_
#     decision (imported lazily inside the function body to avoid a circular
#     import, since orchestration_service does not import this module).
#   - can_run_agent(ticket, agent): thin re-export of stage_workflow.can_run.
#   - is_investigation_usable_for_reporting / investigation_reporting_mode /
#     has_investigation_evidence_gap / evidence_gap_decision(_pending) /
#     approval_complete / approval_required / triage_requires_approval:
#     duplicated business-rule helpers (near-identical to the versions in
#     orchestration_service.py) used by backend/app.py to render
#     ticket-detail views and gate UI actions without needing a full
#     orchestration decision.
#   - _legacy_agent_panel / _legacy_workflow_steps: an older panel/steps
#     builder that inspected each *_result field directly instead of going
#     through stage_workflow. Retained for reference only -- see "Legacy"
#     section banner below.
#
# Inputs:
#   - ticket: dict[str, Any] -- persisted ticket/casework record (same shape
#     as consumed by orchestration_service.py and stage_workflow.py).
#
# Outputs:
#   - agent_panel(ticket) -> list[dict]: one card per pipeline stage with
#     status/lock_reason/last_run_time/last_output_summary/actions/
#     embedded_gate for the dashboard's Agent Panel widget.
#   - workflow_steps(ticket) -> list[dict]: the five operational stages in
#     fixed order with status/state/message/description, for the workflow
#     progress UI.
#   - next_agent(ticket) -> dict: agent/label/allowed/reason/
#     workflow_decision/requires_human_approval/approval_gate/missing_inputs/
#     required_inputs/orchestration_decision.
#   - decorate_ticket(ticket) -> dict: the input ticket plus the three
#     outputs above merged in.
#
# Workflow position:
#   Sits directly below the Flask API layer (backend/app.py) and above
#   stage_workflow.py (canonical state) and orchestration_service.py
#   (next-step decision). It is the last hop before a ticket dict is
#   serialised back to the dashboard frontend.
#
# Called by:
#   - soc_reporting_agent/backend/app.py
#     (`from backend import stage_workflow, ticket_workflow`) --
#     decorate_ticket / approval_complete / investigation_reporting_mode /
#     triage_requires_approval, used across ticket-detail and agent-run
#     routes to render ticket state and gate actions.
#   - soc_reporting_agent/backend/reporting_context_resolver.py
#     (`from backend import ticket_workflow`) --
#     is_investigation_usable_for_reporting, used when resolving whether a
#     found investigation result can be handed to Reporting.
#
# Calls:
#   - soc_reporting_agent/backend/stage_workflow.py (STAGES, status,
#     status_label, status_message, can_run, has_run, has_output_content,
#     output_valid, is_approved, stage_definition, execution_complete) --
#     canonical per-stage state.
#   - soc_reporting_agent/backend/orchestration_service.py
#     (build_orchestration_decision, imported lazily inside next_agent() to
#     avoid a circular import at module load time).
#
# Key evaluator search terms:
#   agent panel, workflow steps, next_agent, decorate_ticket, evidence gap,
#   approval gate, stage lock, embedded_gate.
# ==============================================================================

from __future__ import annotations

from typing import Any

from backend import stage_workflow


# [FYP-SECTION] Status vocabulary (duplicated from orchestration_service.py
# for this module's own status-labelling helpers below) --------------------
COMPLETED_STATUSES = {"completed", "completed_limited", "completed_with_warnings", "completed_with_evidence_gaps", "generated_with_warnings", "success", "passed", "ready"}
USABLE_LIMITED_INVESTIGATION_STATUSES = {"completed", "completed_limited", "completed_with_warnings", "completed_with_evidence_gaps", "needs_more_data", "waiting_for_telemetry", "insufficient_telemetry", "needs_analyst_review", "partial", "partial_success"}
BLOCKING_INVESTIGATION_STATUSES = {"failed", "crashed", "invalid_output", "not_started", "missing_required_context", "execution_error", "timed_out", "timeout", "error"}
FAILED_STATUSES = {"failed", "execution_error", "timed_out", "rejected", "reject", "error"}
RUNNING_STATUSES = {"running", "thinking", "in_progress", "started", "queued"}


def norm(value: Any) -> str:
    """[FYP-FUNCTION] Normalise any value to a lowercase, underscore-separated string for tolerant status comparisons."""
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _result(ticket: dict[str, Any], key: str) -> dict[str, Any]:
    """[FYP-FUNCTION] Safely read a nested result dict off a ticket (never raises, never returns non-dict)."""
    value = ticket.get(key) or {}
    return value if isinstance(value, dict) else {}


def _has_result(result: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] True when a stage result dict exists and is non-empty."""
    return bool(result and isinstance(result, dict))




def _has_usable_investigation_content(result: dict[str, Any]) -> bool:
    """Return True when Investigation produced enough information to report with limitations.

    Missing telemetry is an evidence gap, not a workflow failure.
    Reporting should continue when an investigation result contains a summary,
    findings, missing-evidence records, or available evidence, even if the
    selected playbook could not be fully answered.

    [FYP-FUNCTION] Params: result -- investigation_result dict. Returns: bool.
    Called by: is_investigation_usable_for_reporting (below).
    """
    if not _has_result(result):
        return False
    for key in ("summary", "investigation_summary", "classification", "likely_scenario", "recommended_next_action"):
        if result.get(key) not in (None, "", [], {}):
            return True
    for key in ("findings", "missing_evidence", "missing_fields", "available_evidence", "observed_evidence", "iocs"):
        value = result.get(key)
        if value not in (None, "", [], {}):
            return True
    return False


def is_investigation_usable_for_reporting(result: dict[str, Any]) -> bool:
    """Allow Reporting when Investigation is limited but usable.

    Block only true execution/context failures. Evidence gaps such as
    needs_more_data, waiting_for_telemetry, or insufficient_telemetry should be
    carried into Reporting and clearly documented.

    [FYP-FUNCTION] [FYP-DECISION] Params: result -- investigation_result dict.
    Returns: bool. Called by: backend/app.py ticket-detail rendering,
    reporting_context_resolver.resolve_investigation_context (as
    backend.ticket_workflow.is_investigation_usable_for_reporting).
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
    if status in {"completed_limited", "completed_with_warnings", "completed_with_evidence_gaps", "needs_more_data", "waiting_for_telemetry", "insufficient_telemetry", "partial", "partial_success", "needs_analyst_review"}:
        return "with_limitations"
    return "standard"

def has_investigation_evidence_gap(result: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] [FYP-DECISION] True when Investigation flagged missing evidence/telemetry that needs an analyst decision."""
    if not _has_result(result):
        return False
    status = norm(result.get("status") or result.get("report_status") or result.get("workflow_decision"))
    if status in {"completed_with_evidence_gaps", "completed_limited", "needs_more_data", "waiting_for_telemetry", "insufficient_telemetry", "partial", "partial_success"}:
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


def _status_from_result(result: dict[str, Any], ready_label: str = "Ready") -> str:
    """[FYP-FUNCTION] [FYP-UI] Map a raw result dict to a display status string ("Pending"/"Failed"/"Running"/"Completed with Evidence Gaps"/"Completed"). Used by the legacy agent panel builder below."""
    status = norm(result.get("status") or result.get("report_status") or result.get("decision"))
    if not result:
        return "Pending"
    if status in FAILED_STATUSES:
        return "Failed"
    if status in RUNNING_STATUSES:
        return "Running"
    if status in {"needs_more_data", "waiting_for_telemetry", "insufficient_telemetry", "completed_with_evidence_gaps"}:
        return "Completed with Evidence Gaps"
    if status in {"missing_information_required"}:
        return ready_label
    if status in COMPLETED_STATUSES or result:
        return "Completed"
    return "Completed"


def _workflow_status(result: dict[str, Any]) -> str:
    """[FYP-FUNCTION] [FYP-STATE] Map a raw result dict to a coarse workflow status ("pending"/"failed"/"in_progress"/"completed"). Used by the legacy workflow-steps builder below."""
    status = norm(result.get("status") or result.get("report_status") or result.get("decision"))
    if not result:
        return "pending"
    if status in FAILED_STATUSES:
        return "failed"
    if status in RUNNING_STATUSES:
        return "in_progress"
    if status in {"needs_more_data", "waiting_for_telemetry", "insufficient_telemetry"}:
        return "completed"
    if status in {"missing_information_required"}:
        return "pending"
    return "completed"


def _summary(result: dict[str, Any], fallback: str) -> str:
    """[FYP-FUNCTION] Pick the best one-line summary string out of a result dict (analyst_summary/summary/next_action/... in priority order), else fallback."""
    if not result:
        return fallback
    for key in ("analyst_summary", "summary", "recommended_next_action", "next_action", "classification", "status", "report_status", "decision"):
        value = result.get(key)
        if value not in (None, "", [], {}):
            return str(value)
    return fallback


def _last_time(ticket: dict[str, Any], agent_key: str, result: dict[str, Any]) -> str | None:
    """[FYP-FUNCTION] Find the best-effort "last ran at" timestamp for an agent: first from the result dict's own timestamp fields, else by scanning activity_log for a matching action/actor entry."""
    for key in ("updated_at", "created_at", "dashboard_copy_created_at", "finished_at"):
        if result.get(key):
            return str(result[key])
    for item in ticket.get("activity_log") or []:
        action = norm(item.get("action"))
        actor = norm(item.get("actor"))
        if agent_key in action or agent_key in actor:
            return item.get("created_at")
    return None


def approval_complete(ticket: dict[str, Any], gate: str = "triage_approval") -> bool:
    """[FYP-FUNCTION] [FYP-APPROVAL] Check whether a named approval gate is satisfied, delegating to stage_workflow.is_approved for the canonical answer."""
    stage = stage_workflow.stage_definition(gate)
    return bool(stage and stage_workflow.is_approved(ticket, stage))


def approval_required(ticket: dict[str, Any], gate: str = "triage_approval") -> bool:
    """[FYP-FUNCTION] [FYP-APPROVAL] True when a gate's stage has completed execution but has not yet been approved (i.e. it is currently blocking on the analyst)."""
    stage = stage_workflow.stage_definition(gate)
    return bool(
        stage
        and stage.get("approval_gate")
        and stage_workflow.execution_complete(ticket, stage)
        and not stage_workflow.is_approved(ticket, stage)
    )


def triage_requires_approval(triage: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] [FYP-APPROVAL] True whenever a Triage result exists.

    Note: unlike orchestration_service._triage_requires_approval (which uses
    a severity/risk_score heuristic), this module treats Triage as ALWAYS an
    analyst approval gate in the canonical workflow -- see inline comment.
    """
    # Triage is always an analyst approval gate in the canonical workflow.
    return bool(triage)


def _gate_status(ticket: dict[str, Any], gate: str) -> str:
    """[FYP-FUNCTION] [FYP-APPROVAL] [FYP-UI] Compute a display status ("Completed"/"Failed"/"Ready"/"Locked"/"Pending") for an embedded approval gate. Used only by the legacy agent panel builder below."""
    stage = norm(ticket.get("current_stage"))
    key = "investigation_approval_result" if gate == "investigation_approval" else "approval_result"
    result = _result(ticket, key)
    if gate == "investigation_approval" and norm(result.get("evidence_gap_decision")) == "return_to_triage":
        return "Pending"
    if approval_complete(ticket, gate):
        return "Completed"
    if result and norm(result.get("decision")) in {"rejected", "reject"}:
        return "Failed"
    if stage == gate or (gate == "investigation_approval" and stage == "investigation_evidence_decision") or (gate == "triage_approval" and stage == "analyst_approval"):
        return "Ready"
    if gate == "triage_approval" and not _has_result(_result(ticket, "triage_result")):
        return "Locked"
    if gate == "investigation_approval" and not _has_result(_result(ticket, "investigation_result")):
        return "Locked"
    return "Pending"


def _gate_locked_reason(ticket: dict[str, Any], gate: str) -> str:
    """[FYP-FUNCTION] Explanation string for why an embedded approval gate is currently locked. Used only by the legacy agent panel builder below."""
    if gate == "triage_approval" and not _has_result(_result(ticket, "triage_result")):
        return "Run Triage Agent before the first SOC approval gate."
    if gate == "investigation_approval" and not _has_result(_result(ticket, "investigation_result")):
        return "Run Investigation Agent before the second SOC approval gate."
    return "Approval actions are available only while the ticket is awaiting this approval gate."


def _action_run(agent: str, label: str, enabled: bool) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-UI] Build a "run this agent" action descriptor for the agent panel."""
    return {"id": "run-agent", "agent": agent, "label": label, "enabled": enabled}


def _action_view(agent: str, enabled: bool) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-UI] Build a "view agent output" action descriptor for the agent panel."""
    return {"id": "view-agent-output", "agent": agent, "label": "View Output", "enabled": enabled}


def _action_retry(agent: str, enabled: bool) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-UI] [FYP-RERUN] Build a "re-run this agent" action descriptor for the agent panel."""
    return {"id": "rerun-agent", "agent": agent, "label": "Re-run", "enabled": enabled}


def pending_correlation_recommendations(ticket: dict[str, Any]) -> list[dict[str, Any]]:
    """[FYP-FUNCTION] Return correlation_recommendations entries still awaiting analyst review ("pending" status)."""
    items = ticket.get("correlation_recommendations") or []
    if not isinstance(items, list):
        return []
    return [item for item in items if norm(item.get("status")) == "pending"]


# [FYP-SECTION] Legacy agent panel / workflow steps builders (reference only)
# The two functions below (_legacy_agent_panel, _legacy_workflow_steps)
# predate the canonical stage_workflow-driven builders further down this
# file (agent_panel, workflow_steps). They compute status by inspecting each
# *_result field and ticket["current_stage"]/["status"] directly rather than
# delegating to stage_workflow.status()/can_run().
#
# [FYP-USED-BY] No direct caller confidently identified: a repo-wide search
# found no import or call site for either function outside this file. The
# live UI-facing builders are agent_panel()/workflow_steps() further below.
# Retained here as documented reference/history only -- NOT part of the live
# request path.

def _legacy_agent_panel(ticket: dict[str, Any]) -> list[dict[str, Any]]:
    """Build the dashboard Agent Panel.

    Approval/review gates are embedded inside their owning operational stage,
    rather than rendered as separate visual workflow agents:
    - first SOC approval lives inside Triage Agent
    - second SOC approval lives inside Investigation Agent
    - final SOC analyst review lives inside Reporting Agent

    [FYP-FUNCTION] Legacy (superseded) agent-panel builder.
    Params: ticket -- ticket dict. Returns: list of panel card dicts (same
    shape as agent_panel() below). Called by: not called anywhere in this
    repository (see section note above).
    """
    approval = _result(ticket, "approval_result")
    inv_approval = _result(ticket, "investigation_approval_result")
    soc_review = _result(ticket, "soc_review_result")

    first_gate_status = _gate_status(ticket, "triage_approval")
    second_gate_status = _gate_status(ticket, "investigation_approval")
    reporting = _result(ticket, "reporting_result")
    soc_review_ready = norm(ticket.get("current_stage")) == "soc_analyst_review" and bool(reporting) and not soc_review

    panel: list[dict[str, Any]] = []

    def add_agent(
        key: str,
        label: str,
        result_key: str,
        run_label: str,
        fallback: str,
        *,
        status_override: str | None = None,
        extra_summary: str | None = None,
        extra_actions: list[dict[str, Any]] | None = None,
        embedded_gate: dict[str, Any] | None = None,
    ) -> None:
        """[FYP-FUNCTION] Append one agent-panel card, resolving its status/actions/summary. Local helper closed over `ticket`/`panel`, used only inside _legacy_agent_panel."""
        result = _result(ticket, result_key)
        allowed, reason = can_run_agent(ticket, key)
        status = status_override or _status_from_result(result)
        if status_override is None:
            if not result and allowed:
                status = "Ready"
            elif not allowed and not result:
                status = "Locked"
        actions = [
            _action_run(key, run_label, allowed),
            _action_view(key, bool(result)),
            _action_retry(key, bool(result) and allowed),
        ]
        if extra_actions:
            actions.extend(extra_actions)
        summary = _summary(result, fallback)
        if extra_summary:
            summary = f"{summary} {extra_summary}" if summary and summary != fallback else extra_summary
        panel.append({
            "key": key,
            "label": label,
            "status": status,
            "locked": status == "Locked",
            "lock_reason": "" if status != "Locked" else reason,
            "last_run_time": _last_time(ticket, key, result),
            "last_output_summary": summary,
            "required_input_status": f"Ready: {reason}" if allowed else reason,
            "embedded_gate": embedded_gate or {},
            "actions": actions,
        })

    pending_grouping = pending_correlation_recommendations(ticket)
    triage_pending_grouping = [r for r in pending_grouping if norm(r.get("source_stage")) in {"triage", "correlation", ""}]
    investigation_pending_grouping = [r for r in pending_grouping if norm(r.get("source_stage")) == "investigation"]

    add_agent("parsing", "Parsing & Normalisation", "parsing_result", "Run Parsing", "No parser output has been written to this ticket yet.")
    add_agent(
        "triage",
        "Triage Agent",
        "triage_result",
        "Run Triage",
        "No triage output has been written to this ticket yet.",
        status_override="Awaiting Analyst Review" if triage_pending_grouping else ("Awaiting Approval" if first_gate_status == "Ready" else None),
        extra_summary=(f"{len(triage_pending_grouping)} incident grouping recommendation(s) from Triage need confirmation, edit, or rejection." if triage_pending_grouping else ("SOC analyst approval is required before Investigation can run." if first_gate_status == "Ready" else None)),
        extra_actions=([
            {"id": "approve-ticket", "label": "Approve", "enabled": True},
            {"id": "reject-ticket", "label": "Reject", "enabled": True},
            {"id": "more-evidence", "label": "Request More Evidence", "enabled": True},
        ] if first_gate_status == "Ready" and not triage_pending_grouping else None),
        embedded_gate=({"label": "Incident Grouping Review", "status": "awaiting_review", "summary": "Triage found possible related alerts. Confirm, edit, or reject the recommendation before continuing."} if triage_pending_grouping else ({"label": "SOC Analyst Approval", "status": "awaiting_approval", "summary": "SOC analyst approval is required before Investigation can run."} if first_gate_status == "Ready" else ({"label": "SOC Analyst Approval", "status": "approved", "summary": _summary(approval, "First SOC approval completed.")} if approval_complete(ticket, "triage_approval") else None))),
    )

    threat_status_override = None
    threat_extra_summary = None
    threat_extra_actions: list[dict[str, Any]] = []
    threat_gate: dict[str, Any] = {}

    add_agent(
        "threat_intel",
        "Threat Intelligence Enrichment",
        "threat_intel_result",
        "Run Threat Intel",
        "No threat intelligence output has been written to this ticket yet.",
        status_override=threat_status_override,
        extra_summary=threat_extra_summary,
        extra_actions=threat_extra_actions,
        embedded_gate=threat_gate,
    )

    investigation_status_override = "Awaiting Analyst Review" if investigation_pending_grouping else None
    investigation_extra_summary = (f"{len(investigation_pending_grouping)} investigation grouping/archive recommendation(s) need confirmation, edit, or rejection before Reporting." if investigation_pending_grouping else None)
    investigation_extra_actions: list[dict[str, Any]] = []
    investigation_gate: dict[str, Any] = ({"label": "Incident Grouping Review", "status": "awaiting_review", "summary": "Investigation found possible related alerts or duplicate tickets. Review the recommendation before Reporting."} if investigation_pending_grouping else {})
    if not investigation_pending_grouping and second_gate_status == "Ready":
        inv_result = _result(ticket, "investigation_result")
        inv_mode = investigation_reporting_mode(inv_result)
        if has_investigation_evidence_gap(inv_result):
            investigation_status_override = "Evidence Gap Decision Required"
            investigation_extra_summary = "Investigation completed with evidence gaps. Choose whether to continue to Reporting Agent with limitations or go back to Triage Agent for more evidence."
            investigation_extra_actions = [
                {"id": "continue-to-reporting", "label": "Continue to Reporting Agent", "enabled": True},
                {"id": "return-to-triage", "label": "Go back to Triage", "enabled": True},
                {"id": "view-agent-output", "agent": "investigation", "label": "View Output", "enabled": True},
            ]
            investigation_gate = {"label": "Evidence Gap Decision", "status": "decision_required", "summary": investigation_extra_summary}
        else:
            investigation_status_override = "Awaiting Approval"
            investigation_extra_summary = "SOC analyst approval is required before Reporting can run."
            investigation_extra_actions = [
                {"id": "approve-ticket", "label": "Approve", "enabled": True},
                {"id": "reject-ticket", "label": "Reject", "enabled": True},
                {"id": "more-evidence", "label": "Request More Evidence", "enabled": True},
            ]
            investigation_gate = {"label": "SOC Analyst Approval", "status": "awaiting_approval", "summary": investigation_extra_summary}
    elif approval_complete(ticket, "investigation_approval"):
        investigation_gate = {"label": "SOC Analyst Approval", "status": "approved", "summary": _summary(inv_approval, "Investigation approval completed.")}

    add_agent(
        "investigation",
        "Investigation Agent",
        "investigation_result",
        "Run Investigation",
        "No investigation output has been written to this ticket yet.",
        status_override=investigation_status_override,
        extra_summary=investigation_extra_summary,
        extra_actions=investigation_extra_actions,
        embedded_gate=investigation_gate,
    )

    reporting_status_override = None
    reporting_extra_summary = None
    reporting_extra_actions: list[dict[str, Any]] = []
    reporting_gate: dict[str, Any] = {}
    if soc_review_ready:
        reporting_status_override = "Awaiting Review"
        reporting_extra_summary = "SOC analyst review is required before case closure."
        reporting_extra_actions = [
            {"id": "confirm-soc-review", "label": "Confirm Review", "enabled": True},
        ]
        reporting_gate = {"label": "SOC Analyst Review", "status": "awaiting_review", "summary": reporting_extra_summary}
    elif soc_review:
        reporting_gate = {"label": "SOC Analyst Review", "status": "confirmed", "summary": _summary(soc_review, "SOC analyst review confirmed.")}

    add_agent(
        "reporting",
        "Reporting Agent",
        "reporting_result",
        "Generate Report",
        "No report output has been written to this ticket yet.",
        status_override=reporting_status_override,
        extra_summary=reporting_extra_summary,
        extra_actions=reporting_extra_actions,
        embedded_gate=reporting_gate,
    )

    return panel

def _legacy_workflow_steps(ticket: dict[str, Any]) -> list[dict[str, Any]]:
    """Return only the operational stages shown in the visual workflow.

    Human gates remain enforced by next_agent/can_run_agent and embedded in the
    agent panel, but they are no longer separate visual workflow nodes.

    [FYP-FUNCTION] Legacy (superseded) workflow-steps builder.
    Params: ticket -- ticket dict. Returns: list of six step dicts (five
    agent stages plus case_closure), same shape as workflow_steps() below.
    Called by: not called anywhere in this repository (see section note
    above).
    """
    stage = norm(ticket.get("current_stage") or "parsing_normalisation")
    ticket_status = norm(ticket.get("status"))
    parsing = _result(ticket, "parsing_result")
    triage = _result(ticket, "triage_result")
    threat = _result(ticket, "threat_intel_result")
    investigation = _result(ticket, "investigation_result")
    reporting = _result(ticket, "reporting_result")
    soc_review = _result(ticket, "soc_review_result")

    # [FYP-FUNCTION] `status_for` — implements the status for operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `key`, `result`, `prior_ok`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/ticket_workflow.py:_legacy_workflow_steps; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_workflow_status`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def status_for(key: str, result: dict[str, Any], prior_ok: bool) -> str:
        if _workflow_status(result) != "pending":
            return _workflow_status(result)
        return "pending" if prior_ok else "locked"

    triage_gate_open = bool(triage) and (not triage_requires_approval(triage) or approval_complete(ticket, "triage_approval"))

    parsing_status = status_for("parsing_normalisation", parsing, True)
    triage_status = status_for("triage", triage, bool(parsing))
    threat_status = status_for("threat_intelligence", threat, triage_gate_open and not pending_correlation_recommendations(ticket))
    investigation_status = status_for("investigation", investigation, bool(threat) and triage_gate_open)
    reporting_status = status_for("reporting", reporting, approval_complete(ticket, "investigation_approval"))
    closure_status = "completed" if ticket_status == "closed" else ("in_progress" if stage == "case_closure" else ("locked" if not soc_review else "pending"))

    if stage == "triage" and "evidence" in ticket_status:
        triage_status = "in_progress"
        investigation_status = "pending"
        reporting_status = "locked"
    pending_grouping = pending_correlation_recommendations(ticket)
    if pending_grouping:
        triage_pending_grouping = [r for r in pending_grouping if norm(r.get("source_stage")) in {"triage", "correlation", ""}]
        investigation_pending_grouping = [r for r in pending_grouping if norm(r.get("source_stage")) == "investigation"]
        if triage_pending_grouping:
            triage_status = "awaiting_review"
            threat_status = "locked"
            investigation_status = "locked"
            reporting_status = "locked"
        elif investigation_pending_grouping:
            investigation_status = "awaiting_review"
            reporting_status = "locked"
    if triage and triage_requires_approval(triage) and not approval_complete(ticket, "triage_approval"):
        triage_status = "awaiting_approval"
        threat_status = "locked"
        investigation_status = "locked"
    if investigation and not approval_complete(ticket, "investigation_approval"):
        investigation_status = "evidence_gap_decision" if evidence_gap_decision_pending(ticket) else "awaiting_approval"
    if reporting and not soc_review and ticket_status != "closed":
        reporting_status = "awaiting_review"

    # [FYP-FUNCTION] `state_text` — implements the state text operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `status`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/ticket_workflow.py:_legacy_workflow_steps; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `get`, `replace`, `title`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def state_text(status: str) -> str:
        return {
            "awaiting_approval": "Awaiting SOC Approval",
            "awaiting_review": "Awaiting SOC Analyst Review",
            "evidence_gap_decision": "Evidence Gap Decision",
            "in_progress": "In Progress",
        }.get(status, status.replace("_", " ").title())

    return [
        {"key": "parsing_normalisation", "agent": "parsing", "label": "Parsing & Normalisation", "status": parsing_status, "state": state_text(parsing_status), "description": "Raw NetWitness export parsed into clean SOC context"},
        {"key": "triage", "agent": "triage", "label": "Triage Agent", "status": triage_status, "state": state_text(triage_status), "description": "Severity, confidence, triage decision, and initial incident grouping check"},
        {"key": "threat_intelligence", "agent": "threat_intel", "label": "Threat Intel Enrichment", "status": threat_status, "state": state_text(threat_status), "description": "IOC reputation checks using VT, AbuseIPDB, and OTX"},
        {"key": "investigation", "agent": "investigation", "label": "Investigation Agent", "status": investigation_status, "state": state_text(investigation_status), "description": "Evidence investigation and scope analysis"},
        {"key": "reporting", "agent": "reporting", "label": "Reporting Agent", "status": reporting_status, "state": state_text(reporting_status), "description": "Generate analyst-ready reports"},
        {"key": "case_closure", "label": "Case Closure", "status": closure_status, "state": state_text(closure_status), "description": "Close the case after review"},
    ]


# [FYP-SECTION] Canonical stage_workflow-driven UI builders (ACTIVE) --------
# These are the live panel/steps builders, computing everything from
# stage_workflow's canonical per-stage status() rather than re-deriving
# status from raw result fields (contrast with the legacy builders above).

def agent_panel(ticket: dict[str, Any]) -> list[dict[str, Any]]:
    """Build stage cards from persisted workflow state, not button labels.

    [FYP-FUNCTION] [FYP-UI] Params: ticket -- ticket dict. Returns: list of
    panel card dicts, one per stage_workflow.STAGES entry, each with key,
    label, status/workflow_status, status_message, locked/lock_reason,
    has_run, output_valid, approval_required/approval_state, last_run_time,
    last_output_summary, required_input_status, description, embedded_gate,
    and actions (run/re-run/view/approve, each individually enabled based on
    stage_workflow.can_run()/has_run()/has_output_content()).
    Called by: decorate_ticket() below (feeds the dashboard Agent Panel).
    Calls: stage_workflow.STAGES/result_for/status/can_run/has_run/
    has_output_content/status_message/output_valid/is_approved,
    _action_run/_action_view/_action_retry, _summary, _last_time.
    """
    panel: list[dict[str, Any]] = []
    fallbacks = {
        "parsing": "No parser output has been written to this ticket yet.",
        "triage": "No triage output has been written to this ticket yet.",
        "threat_intel": "No threat intelligence output has been written to this ticket yet.",
        "investigation": "No investigation output has been written to this ticket yet.",
        "reporting": "No report output has been written to this ticket yet.",
    }
    descriptions = {
        "parsing": "Raw NetWitness export parsed into clean SOC context",
        "triage": "Severity, confidence, and triage decision",
        "threat_intel": "IOC reputation and threat intelligence enrichment",
        "investigation": "Evidence investigation and scope analysis",
        "reporting": "Analyst-ready incident reporting",
    }

    for stage in stage_workflow.STAGES:
        agent = stage["agent"]
        result = stage_workflow.result_for(ticket, stage)
        current = stage_workflow.status(ticket, stage)
        eligible, eligibility_reason = stage_workflow.can_run(ticket, stage)
        ran = stage_workflow.has_run(ticket, stage)
        has_output = stage_workflow.has_output_content(ticket, stage)
        message = stage_workflow.status_message(ticket, stage)
        actions: list[dict[str, Any]] = []

        if current == "running":
            actions.append(_action_run(agent, "Processing...", False))
        elif ran:
            actions.append(_action_retry(agent, eligible))
        else:
            actions.append(_action_run(agent, "Start Process", eligible))

        actions.append(_action_view(agent, has_output))
        if current == "pending_approval":
            actions.append({
                "id": "approve-ticket",
                "agent": agent,
                "gate": stage["approval_gate"],
                "label": "Approve",
                "enabled": True,
            })

        fallback = fallbacks[agent]
        summary = message or _summary(result, fallback)
        locked = not eligible and current in {"locked", "rerun_required"}
        panel.append({
            "key": agent,
            "label": stage["label"],
            "status": stage_workflow.status_label(current),
            "workflow_status": current,
            "status_message": message,
            "locked": locked,
            "lock_reason": message if locked else "",
            "has_run": ran,
            "output_valid": stage_workflow.output_valid(ticket, stage),
            "approval_required": bool(stage["approval_gate"]),
            "approval_state": (
                "approved" if stage_workflow.is_approved(ticket, stage)
                else "pending" if current == "pending_approval"
                else "not_required" if not stage["approval_gate"]
                else "not_approved"
            ),
            "last_run_time": _last_time(ticket, agent, result),
            "last_output_summary": summary,
            "required_input_status": eligibility_reason,
            "description": descriptions[agent],
            "embedded_gate": (
                {
                    "label": "SOC Analyst Approval",
                    "status": "awaiting_approval",
                    "summary": f"Approve the latest valid {stage['label']} result to continue.",
                }
                if current == "pending_approval"
                else {
                    "label": "SOC Analyst Approval",
                    "status": "approved",
                    "summary": f"{stage['label']} was approved.",
                }
                if current == "approved"
                else {}
            ),
            "actions": actions,
        })
    return panel


def workflow_steps(ticket: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the exact five operational stages in required order.

    [FYP-FUNCTION] [FYP-UI] Params: ticket -- ticket dict. Returns: list of
    five step dicts (key, agent, label, status, state, message,
    description), one per stage_workflow.STAGES entry, driven entirely by
    stage_workflow.status()/status_label()/status_message().
    Called by: decorate_ticket() below.
    Calls: stage_workflow.STAGES/status/status_label/status_message.
    """
    descriptions = {
        "parsing": "Raw NetWitness export parsed into clean SOC context",
        "triage": "Severity, confidence, and triage decision",
        "threat_intel": "IOC reputation and threat intelligence enrichment",
        "investigation": "Evidence investigation and scope analysis",
        "reporting": "Generate analyst-ready reports",
    }
    return [
        {
            "key": stage["key"],
            "agent": stage["agent"],
            "label": stage["label"],
            "status": stage_workflow.status(ticket, stage),
            "state": stage_workflow.status_label(stage_workflow.status(ticket, stage)),
            "message": stage_workflow.status_message(ticket, stage),
            "description": descriptions[stage["agent"]],
        }
        for stage in stage_workflow.STAGES
    ]

def next_agent(ticket: dict[str, Any]) -> dict[str, Any]:
    """[FYP-FUNCTION] Compute the "what happens next" summary for a ticket.

    Params: ticket -- ticket dict. Returns: dict with agent/label/allowed/
    reason/workflow_decision/requires_human_approval/approval_gate/
    missing_inputs/required_inputs/orchestration_decision (the full raw
    decision dict is also included for callers that need more detail).
    Calls: backend.orchestration_service.build_orchestration_decision --
    imported HERE (function-local), not at module top, specifically to break
    a circular import: orchestration_service.py does not import
    ticket_workflow, but if this module imported orchestration_service at
    module load time while orchestration_service (or a future version of it)
    imported ticket_workflow, Python would fail to fully initialise either
    module. The local import defers resolution until next_agent() is
    actually called, by which point both modules are fully loaded.
    Called by: decorate_ticket() below.
    """
    from backend.orchestration_service import build_orchestration_decision

    decision = build_orchestration_decision(ticket)
    return {
        "agent": decision.get("next_agent"),
        "label": decision.get("next_label") or decision.get("label"),
        "allowed": decision.get("allowed"),
        "reason": decision.get("reason"),
        "workflow_decision": decision.get("workflow_decision"),
        "requires_human_approval": decision.get("requires_human_approval", False),
        "approval_gate": decision.get("approval_gate"),
        "missing_inputs": decision.get("missing_inputs", []),
        "required_inputs": decision.get("required_inputs", []),
        "orchestration_decision": decision,
    }


def can_run_agent(ticket: dict[str, Any], agent: str) -> tuple[bool, str]:
    """[FYP-FUNCTION] [FYP-STAGE-LOCK] Public "can this stage run right now" check, delegated straight to stage_workflow.can_run."""
    return stage_workflow.can_run(ticket, agent)


def decorate_ticket(ticket: dict[str, Any]) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-ENTRY-POINT] [FYP-EVALUATOR] Attach workflow_steps/next_step/orchestration_decision_result/agent_panel onto a raw ticket dict.

    Params: ticket -- raw persisted ticket dict (source: CASEWORK store).
    Returns: a shallow copy of ticket with four additional keys merged in:
    workflow_steps, next_step, orchestration_decision_result, agent_panel.
    Side effects: none (does not mutate the input ticket -- builds `out` as
    a fresh dict copy first).
    Called by: soc_reporting_agent/backend/app.py, wherever a ticket is
    serialised into an API response (ticket list, ticket detail, after
    agent-run/approval actions) -- this is the standard "finalise a ticket
    for the frontend" entry point for this subsystem.
    Calls: workflow_steps, next_agent, agent_panel (all in this file).
    """
    out = dict(ticket)
    out["workflow_steps"] = workflow_steps(ticket)
    next_step = next_agent(ticket)
    out["next_step"] = next_step
    # Always expose the latest computed orchestration decision in API responses.
    # The database still stores the last recorded decision when Run Next Step or
    # the Orchestration Agent runs, but the UI should not display stale logic
    # after an analyst approves, rejects, or requests more evidence.
    out["orchestration_decision_result"] = next_step.get("orchestration_decision") or out.get("orchestration_decision_result") or {}
    out["agent_panel"] = agent_panel(out)
    return out
