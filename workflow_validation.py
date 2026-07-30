# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, datetime.
# =============================================================================
# File: workflow_validation.py
# Purpose: This module validates cross-stage workflow state, required outputs, and transition readiness.
# Main functionality: ParsingValidationError, validate_parsing_result, mandatory_triage_approval, build_thinking_process.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis workflow orchestration and state component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, datetime.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: ParsingValidationError, validate_parsing_result, mandatory_triage_approval, build_thinking_process, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

"""
workflow_validation.py — Parsing->Triage handoff validation and mandatory
approval-gate policy for soc_workflow.run_until_triage_approval().

Not related to soc_investigation_agent_revised/orchestrator.py, which is the
Investigation agent's internal LLM playbook-step engine and has no approval
or validation logic — a different subsystem.
"""
from __future__ import annotations

from datetime import datetime, timezone


# =============================================================================
# [FYP-SECTION] WORKFLOW ORCHESTRATION AND STATE EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-CLASS] `ParsingValidationError` — owns ParsingValidationError state or behaviour for the workflow orchestration and state component.
# [FYP-PROCESS] Important methods: no public methods; class-level data/exception semantics only.
# [FYP-USED-BY] Static constructor/type references include workflow_validation.py:validate_parsing_result.
# [FYP-OUTPUT] Instances expose the state and operations defined by the class body; local methods document side effects.
# [FYP-ERROR] Constructor/method exceptions propagate unless a documented local fallback handles them.

class ParsingValidationError(Exception):
    """Raised when Stage 0 (Parsing) output is unsafe to hand off to Triage."""


# [FYP-FUNCTION] `validate_parsing_result` — evaluates validate parsing result conditions so invalid or unsafe workflow orchestration and state processing is stopped early.
# [FYP-INPUT] Parameters: `incident_id`, `parsing_result`, `skip`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:run_until_triage_approval; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `ParsingValidationError`, `get`, `isinstance`, `isoformat`, `now`, `str`.
# [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

def validate_parsing_result(*, incident_id: str, parsing_result: dict,
                            skip: bool = False) -> dict:
    """Verify Parsing completed, produced a normalised_alert, and that alert
    belongs to the incident this workflow run is processing. `skip=True` is
    for --mock-triage, where parsing is stubbed and has nothing to validate.

    Returns a validation record (folded into the Thinking Process panel).
    Raises ParsingValidationError if the handoff would be unsafe.
    """
    if skip:
        return {"valid": True, "incident_id": str(incident_id),
                "checks_passed": ["mock_mode"]}

    if not isinstance(parsing_result, dict):
        raise ParsingValidationError(
            f"parsing_result is not a dict for incident {incident_id!r}")

    if parsing_result.get("status") != "completed":
        raise ParsingValidationError(
            f"Parsing did not complete for incident {incident_id!r} "
            f"(status={parsing_result.get('status')!r})")

    normalised_alert = parsing_result.get("normalised_alert")
    if not normalised_alert:
        raise ParsingValidationError(
            f"Parsing completed but returned no normalised_alert for "
            f"incident {incident_id!r}")

    alert_summary = normalised_alert.get("alert_summary") or {}
    compat_view = normalised_alert.get("compatibility_view") or {}
    parsed_incident_id = str(
        alert_summary.get("incident_id") or compat_view.get("incident_id") or "")

    if parsed_incident_id and parsed_incident_id != str(incident_id):
        raise ParsingValidationError(
            f"normalised_alert belongs to incident {parsed_incident_id!r}, "
            f"expected {incident_id!r} — refusing stale/mismatched handoff")

    return {
        "valid": True,
        "incident_id": str(incident_id),
        "parsed_incident_id": parsed_incident_id or str(incident_id),
        "selected_alert_id": parsing_result.get("selected_alert_id"),
        "normalised_alert_count": parsing_result.get("normalised_alert_count"),
        "checks_passed": [
            "parsing_status_completed",
            "normalised_alert_present",
            "incident_id_match" if parsed_incident_id else "incident_id_unavailable_in_alert",
        ],
        "validated_at": datetime.now(timezone.utc).isoformat(),
    }


MANDATORY_APPROVAL_POLICY = (
    "Mandatory SOC Analyst approval policy — required after every Triage run "
    "regardless of classification, risk level, or recommended actions."
)


# [FYP-FUNCTION] `mandatory_triage_approval` — implements the mandatory triage approval operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `incident_id`, `triage_result`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:run_until_triage_approval; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `isoformat`, `now`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def mandatory_triage_approval(*, incident_id: str, triage_result: dict) -> dict:
    """Always requires SOC analyst approval after Triage. For Aegis, the
    stage after approval is now Threat Intelligence Enrichment (which
    itself does not require a separate approval and hands off to
    Investigation automatically on success) — there is no conditional
    'skip investigation' route decided here."""
    ticket = triage_result.get("ticket") or {}
    return {
        "approval_required": True,
        "approval_stage": "triage",
        "incident_id": str(incident_id),
        "ticket_unc": ticket.get("unc"),
        "next_stage_after_approval": "threat_intelligence",
        "reason": MANDATORY_APPROVAL_POLICY,
        "gated_at": datetime.now(timezone.utc).isoformat(),
    }


# [FYP-FUNCTION] `build_thinking_process` — constructs build thinking process output for the next workflow orchestration and state consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `incident`, `inc_id`, `parsing_result`, `validation`, `triage_result`, `gate`, `run_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:run_until_triage_approval; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `next`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_thinking_process(*, incident: dict, inc_id: str, parsing_result: dict,
                           validation: dict, triage_result: dict,
                           gate: dict, run_id: str) -> dict:
    """Structured decision rationale for the analyst-facing 'Thinking Process'
    panel — assembled only from real parsing/triage/workflow data, never
    from raw model chain-of-thought."""
    ticket = triage_result.get("ticket") or {}
    meta   = triage_result.get("metakeys_payload") or {}
    trace  = triage_result.get("trace") or []
    risk_step = next((s for s in trace if s.get("step") == "Risk Rating"), {})

    return {
        "run_id": run_id,
        "parsing_completed": parsing_result.get("status") == "completed",
        "normalised_alert_used": {
            "incident_id": validation.get("parsed_incident_id"),
            "selected_alert_id": validation.get("selected_alert_id"),
        },
        "triage_agent_selected_because": (
            "Parsing completed and was validated as belonging to this incident; "
            "TriageAgent.triage() (soc_triage_agent/soc_triage_agent.py) is the "
            "sole Triage implementation invoked."),
        "workflow_rule_triggered": (
            "Mandatory-approval policy — Triage always routes to SOC Analyst "
            "approval, then Investigation; no conditional skip is applied here."),
        "triage_decision": {
            "classification": ticket.get("classification"),
            "incident_category": ticket.get("incident_category"),
            "mitre_tactic": ticket.get("mitre_tactic"),
            "mitre_technique": ticket.get("mitre_technique"),
        },
        "evidence_used": {
            "matched_metakeys": ticket.get("metakeys", []),
            "matched_ioc_count": ticket.get("matched_ioc_count"),
            "ioc_summary": meta.get("ioc_summary"),
        },
        # soc_triage_agent.py has no genuine "confidence" field — only a
        # likelihood-based risk rating. Labeled honestly, not renamed.
        "risk_level": meta.get("risk_level"),
        "risk_rationale": (risk_step.get("data") or {}).get("rationale")
                          or (ticket.get("risk_rating") or {}).get("rationale"),
        "missing_information": parsing_result.get("missing_important_fields", []),
        "why_workflow_paused": gate.get("reason"),
        "approval_stage": gate.get("approval_stage"),
        "next_stage_after_approval": gate.get("next_stage_after_approval"),
    }
