from __future__ import annotations

from typing import Any

from backend import stage_workflow


COMPLETED_STATUSES = {"completed", "completed_limited", "completed_with_warnings", "completed_with_evidence_gaps", "generated_with_warnings", "success", "passed", "ready"}
USABLE_LIMITED_INVESTIGATION_STATUSES = {"completed", "completed_limited", "completed_with_warnings", "completed_with_evidence_gaps", "needs_more_data", "waiting_for_telemetry", "insufficient_telemetry", "needs_analyst_review", "partial", "partial_success"}
BLOCKING_INVESTIGATION_STATUSES = {"failed", "crashed", "invalid_output", "not_started", "missing_required_context", "execution_error", "timed_out", "timeout", "error"}
FAILED_STATUSES = {"failed", "execution_error", "timed_out", "rejected", "reject", "error"}
RUNNING_STATUSES = {"running", "thinking", "in_progress", "started", "queued"}


def norm(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _result(ticket: dict[str, Any], key: str) -> dict[str, Any]:
    value = ticket.get(key) or {}
    return value if isinstance(value, dict) else {}


def _has_result(result: dict[str, Any]) -> bool:
    return bool(result and isinstance(result, dict))




def _has_usable_investigation_content(result: dict[str, Any]) -> bool:
    """Return True when Investigation produced enough information to report with limitations.

    Missing telemetry is an evidence gap, not a workflow failure.
    Reporting should continue when an investigation result contains a summary,
    findings, missing-evidence records, or available evidence, even if the
    selected playbook could not be fully answered.
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
    status = norm(result.get("status") or result.get("report_status"))
    if status in {"completed_limited", "completed_with_warnings", "completed_with_evidence_gaps", "needs_more_data", "waiting_for_telemetry", "insufficient_telemetry", "partial", "partial_success", "needs_analyst_review"}:
        return "with_limitations"
    return "standard"

def has_investigation_evidence_gap(result: dict[str, Any]) -> bool:
    if not _has_result(result):
        return False
    status = norm(result.get("status") or result.get("report_status") or result.get("workflow_decision"))
    if status in {"completed_with_evidence_gaps", "completed_limited", "needs_more_data", "waiting_for_telemetry", "insufficient_telemetry", "partial", "partial_success"}:
        return True
    return bool(result.get("missing_evidence") or result.get("missing_fields") or result.get("triage_requery_request"))


def evidence_gap_decision(ticket: dict[str, Any]) -> str:
    approval = _result(ticket, "investigation_approval_result")
    return norm(approval.get("evidence_gap_decision") or approval.get("decision"))


def evidence_gap_decision_pending(ticket: dict[str, Any]) -> bool:
    inv = _result(ticket, "investigation_result")
    if not has_investigation_evidence_gap(inv):
        return False
    decision = evidence_gap_decision(ticket)
    return decision not in {"continue_to_reporting", "approved", "approve", "completed", "return_to_triage"}


def _status_from_result(result: dict[str, Any], ready_label: str = "Ready") -> str:
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
    if not result:
        return fallback
    for key in ("analyst_summary", "summary", "recommended_next_action", "next_action", "classification", "status", "report_status", "decision"):
        value = result.get(key)
        if value not in (None, "", [], {}):
            return str(value)
    return fallback


def _last_time(ticket: dict[str, Any], agent_key: str, result: dict[str, Any]) -> str | None:
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
    stage = stage_workflow.stage_definition(gate)
    return bool(stage and stage_workflow.is_approved(ticket, stage))


def approval_required(ticket: dict[str, Any], gate: str = "triage_approval") -> bool:
    stage = stage_workflow.stage_definition(gate)
    return bool(
        stage
        and stage.get("approval_gate")
        and stage_workflow.execution_complete(ticket, stage)
        and not stage_workflow.is_approved(ticket, stage)
    )


def triage_requires_approval(triage: dict[str, Any]) -> bool:
    # Triage is always an analyst approval gate in the canonical workflow.
    return bool(triage)


def _gate_status(ticket: dict[str, Any], gate: str) -> str:
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
    if gate == "triage_approval" and not _has_result(_result(ticket, "triage_result")):
        return "Run Triage Agent before the first SOC approval gate."
    if gate == "investigation_approval" and not _has_result(_result(ticket, "investigation_result")):
        return "Run Investigation Agent before the second SOC approval gate."
    return "Approval actions are available only while the ticket is awaiting this approval gate."


def _action_run(agent: str, label: str, enabled: bool) -> dict[str, Any]:
    return {"id": "run-agent", "agent": agent, "label": label, "enabled": enabled}


def _action_view(agent: str, enabled: bool) -> dict[str, Any]:
    return {"id": "view-agent-output", "agent": agent, "label": "View Output", "enabled": enabled}


def _action_retry(agent: str, enabled: bool) -> dict[str, Any]:
    return {"id": "rerun-agent", "agent": agent, "label": "Re-run", "enabled": enabled}


def pending_correlation_recommendations(ticket: dict[str, Any]) -> list[dict[str, Any]]:
    items = ticket.get("correlation_recommendations") or []
    if not isinstance(items, list):
        return []
    return [item for item in items if norm(item.get("status")) == "pending"]


def _legacy_agent_panel(ticket: dict[str, Any]) -> list[dict[str, Any]]:
    """Build the dashboard Agent Panel.

    Approval/review gates are embedded inside their owning operational stage,
    rather than rendered as separate visual workflow agents:
    - first SOC approval lives inside Triage Agent
    - second SOC approval lives inside Investigation Agent
    - final SOC analyst review lives inside Reporting Agent
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
    """
    stage = norm(ticket.get("current_stage") or "parsing_normalisation")
    ticket_status = norm(ticket.get("status"))
    parsing = _result(ticket, "parsing_result")
    triage = _result(ticket, "triage_result")
    threat = _result(ticket, "threat_intel_result")
    investigation = _result(ticket, "investigation_result")
    reporting = _result(ticket, "reporting_result")
    soc_review = _result(ticket, "soc_review_result")

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


def agent_panel(ticket: dict[str, Any]) -> list[dict[str, Any]]:
    """Build stage cards from persisted workflow state, not button labels."""
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
    """Return the exact five operational stages in required order."""
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
    return stage_workflow.can_run(ticket, agent)


def decorate_ticket(ticket: dict[str, Any]) -> dict[str, Any]:
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
