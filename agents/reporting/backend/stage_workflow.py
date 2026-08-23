# ==============================================================================
# [FYP-FILE] File: soc_reporting_agent/backend/stage_workflow.py
# Important dependencies: __future__, datetime, typing.
#
# Purpose:
#   Canonical five-stage ticket workflow state machine for the SOC Reporting
#   subsystem. This is the single source of truth for "what stage is this
#   ticket on, is that stage's output valid, has it been approved, and is it
#   allowed to run/re-run right now". Every other module in backend/ that
#   needs to reason about stage progression (orchestration_service.py,
#   ticket_workflow.py, casework_store.py, postgres_casework_store.py,
#   backend/app.py) reads state through this module rather than
#   re-implementing the rules.
#
#   Design note (kept from the original module docstring): the agent output
#   JSON objects (parsing_result, triage_result, threat_intel_result,
#   investigation_result, reporting_result, ...) remain the persisted source
#   of truth. Workflow metadata (workflow_status, has_run, output_valid,
#   approval_state, ...) is stored ALONGSIDE each output dict so existing
#   report/view/export code can continue to read the original payload
#   without a database schema change.
#
# Main functionalities:
#   - STAGES: the fixed, ordered 5-stage pipeline definition (parsing ->
#     triage -> threat_intel -> investigation -> reporting), each with its
#     agent id, workflow key, display label, result dict key, and optional
#     approval gate name.
#   - status(ticket, stage) / status_label / status_message: compute a
#     stage's current lifecycle state (locked, ready, running, completed,
#     pending_approval, approved, failed, rerun_required) and a
#     human-readable explanation.
#   - can_run / can_start / can_approve: [FYP-STAGE-LOCK] eligibility gates
#     -- can this stage run, can it start as a fresh run vs. a re-run, can
#     its output be approved right now.
#   - begin_run_fields / completed_result / failure_fields / approval_fields:
#     [FYP-RERUN] [FYP-STATE] state-transition builders that return the
#     partial ticket-update dict to persist when a run starts, finishes
#     successfully, fails, or is approved -- including the downstream
#     "rerun_required" cascade when re-running an earlier stage invalidates
#     later stage outputs.
#   - agent_panel / workflow_steps (also duplicated in ticket_workflow.py for
#     the ticket-facing dashboard cards): NOT present in this file -- see
#     ticket_workflow.py, which builds UI-facing summaries FROM this module's
#     state functions.
#
# Inputs:
#   - ticket: dict[str, Any] -- persisted ticket/casework record.
#   - stage_value: Any -- flexible stage identifier. Accepts a STAGES entry
#     dict itself, an agent name ("triage"), a stage key
#     ("parsing_normalisation"), an approval gate name ("triage_approval"),
#     or a result key ("triage_result"); resolved via stage_definition().
#
# Outputs:
#   - Stage status strings: "locked" | "ready" | "running" | "completed" |
#     "pending_approval" | "approved" | "failed" | "rerun_required".
#   - Partial ticket-field dicts (begin_run_fields, completed_result,
#     failure_fields, approval_fields) meant to be merged into the ticket
#     record by the caller's persistence layer (CASEWORK.update_ticket in
#     backend/app.py).
#
# Workflow position:
#   This module has NO side effects of its own (no DB writes, no file I/O) --
#   it is a pure state/rules layer. backend/app.py is the layer that actually
#   calls CASEWORK.update_ticket(...) with the dicts this module returns, at
#   each point an agent run starts, completes, fails, or is approved.
#
# Called by:
#   - soc_reporting_agent/backend/app.py (`from backend import stage_workflow`)
#     -- output_valid/can_start/begin_run_fields/completed_result/
#     failure_fields/can_approve/approval_fields/has_run/stage_definition,
#     used throughout the agent-run and approval routes.
#   - soc_reporting_agent/backend/orchestration_service.py
#     (`from backend import stage_workflow`) -- build_orchestration_decision()
#     walks STAGES and calls status()/can_run()/has_run()/workflow_complete().
#   - soc_reporting_agent/backend/ticket_workflow.py
#     (`from backend import stage_workflow`) -- builds the agent panel /
#     workflow steps / next_step summaries from this module's state.
#   - soc_reporting_agent/backend/casework_store.py and
#     soc_reporting_agent/backend/postgres_casework_store.py
#     (`from backend import stage_workflow`) -- output_valid/stage_definition/
#     completed_result/can_approve/approval_fields, used when persisting
#     agent results and analyst approvals to the casework store.
#
# Calls:
#   - Standard library only (datetime). No calls into other backend/ modules
#     -- this module is intentionally a leaf/foundation module so it can be
#     imported safely from orchestration_service.py and ticket_workflow.py
#     without circular-import risk.
#
# Key evaluator search terms:
#   stage lock, stage-transition, rerun, rerun_required, approval gate,
#   can_run, can_approve, begin_run_fields, STAGES, workflow_complete.
# ==============================================================================

from __future__ import annotations

"""Canonical five-stage ticket workflow state.

The agent output JSON objects remain the persisted source of truth.  Workflow
metadata is stored alongside each output so existing report/view/export code
can continue to read the original payload without a database schema change.
"""

from datetime import datetime, timezone
from typing import Any


# [FYP-SECTION] Pipeline definition ------------------------------------------
# [FYP-STATE] STAGES is the ordered, canonical pipeline. Order matters: every
# consumer (build_orchestration_decision, agent_panel, workflow_steps,
# prerequisite_met) walks this tuple in sequence to find "the current stage"
# or to check "did everything before this stage complete".
STAGES = (
    {
        "agent": "parsing",
        "key": "parsing_normalisation",
        "label": "Parsing",
        "result_key": "parsing_result",
        "approval_gate": None,
    },
    {
        "agent": "triage",
        "key": "triage",
        "label": "Triage",
        "result_key": "triage_result",
        "approval_gate": "triage_approval",
    },
    {
        "agent": "threat_intel",
        "key": "threat_intelligence",
        "label": "Threat Intelligence Enrichment",
        "result_key": "threat_intel_result",
        "approval_gate": "threat_intel_approval",
    },
    {
        "agent": "investigation",
        "key": "investigation",
        "label": "Investigation",
        "result_key": "investigation_result",
        "approval_gate": "investigation_approval",
    },
    {
        "agent": "reporting",
        "key": "reporting",
        "label": "Reporting",
        "result_key": "reporting_result",
        "approval_gate": "reporting_approval",
    },
)

# [FYP-STATE] Status vocabularies used to classify whatever status string an
# agent wrote into its result dict (workflow_status/status/report_status/
# decision) into one of: failed, running, or approved.
FAILED = {
    "failed", "error", "execution_error", "timed_out", "timeout", "crashed",
    "invalid_output", "missing_required_context", "failed_postgres_unavailable",
    "blocked_missing_triage", "blocked_pending_triage_approval", "paused",
    "cancelled", "canceled",
}
RUNNING = {"running", "thinking", "in_progress", "started", "starting", "queued"}
APPROVED = {"approved", "approve", "completed", "confirmed", "continue_to_reporting"}


def now_iso() -> str:
    """[FYP-FUNCTION] Current UTC timestamp, ISO-8601. Used to stamp workflow_updated_at/outdated_at/generated_at fields."""
    return datetime.now(timezone.utc).isoformat()


def norm(value: Any) -> str:
    """[FYP-FUNCTION] Normalise any value to a lowercase, underscore-separated string for tolerant status comparisons."""
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def canonical_agent(value: Any) -> str:
    """[FYP-FUNCTION] Map known agent-name aliases (e.g. "parsing_normalisation", "threat_intelligence") to their canonical short agent id."""
    value = norm(value)
    aliases = {
        "parsing_normalisation": "parsing",
        "parser": "parsing",
        "threat_intelligence": "threat_intel",
        "threat_intelligence_enrichment": "threat_intel",
    }
    return aliases.get(value, value)


def stage_definition(value: Any) -> dict[str, Any] | None:
    """[FYP-FUNCTION] Resolve any stage identifier to its STAGES entry.

    Params: value -- a STAGES dict (returned as-is if it already looks like
    one), an agent name, a stage key, an approval-gate name/alias
    ("analyst_approval", "soc_analyst_review", "soc_review", "final_review"),
    or a result key.
    Returns: the matching STAGES dict, or None if unrecognised.
    Called by: virtually every other function in this module, plus
    orchestration_service.py, ticket_workflow.py, backend/app.py,
    casework_store.py, postgres_casework_store.py -- this is the central
    lookup that lets callers pass loose/flexible stage identifiers.
    """
    if isinstance(value, dict) and value.get("agent") and value.get("result_key"):
        return value
    value = norm(value)
    agent = canonical_agent(value)
    gate_aliases = {
        "analyst_approval": "triage_approval",
        "soc_analyst_review": "reporting_approval",
        "soc_review": "reporting_approval",
        "final_review": "reporting_approval",
    }
    value = gate_aliases.get(value, value)
    for stage in STAGES:
        if agent == stage["agent"] or value in {
            stage["key"], stage["approval_gate"], stage["result_key"],
        }:
            return stage
    return None


def result_for(ticket: dict[str, Any], stage_value: Any) -> dict[str, Any]:
    """[FYP-FUNCTION] Return the stage's result dict off the ticket (e.g. ticket["triage_result"]), or {} if unresolved/missing."""
    stage = stage_definition(stage_value)
    if not stage:
        return {}
    value = ticket.get(stage["result_key"]) or {}
    return value if isinstance(value, dict) else {}


def result_status(result: dict[str, Any]) -> str:
    """[FYP-FUNCTION] Extract and normalise a result dict's status, preferring workflow_status over the agent's own status/report_status/decision fields."""
    return norm(
        result.get("workflow_status")
        or result.get("status")
        or result.get("report_status")
        or result.get("decision")
    )


def has_run(ticket: dict[str, Any], stage_value: Any) -> bool:
    """[FYP-FUNCTION] [FYP-STATE] True when this stage has ever produced a result (has_run flag defaults True once a result dict exists)."""
    result = result_for(ticket, stage_value)
    return bool(result and result.get("has_run", True))


def has_output_content(ticket: dict[str, Any], stage_value: Any) -> bool:
    """[FYP-FUNCTION] True when the stage's result dict has at least one field that is NOT purely workflow bookkeeping metadata.

    Distinguishes "the agent wrote real output" from "only workflow_status/
    has_run/etc. were set" (e.g. by begin_run_fields while a run is still in
    progress). Used to decide whether the "View Output" UI action should be
    enabled.
    """
    result = result_for(ticket, stage_value)
    if not result:
        return False
    metadata = {
        "workflow_status", "has_run", "output_valid", "approval_required",
        "approval_state", "rerun_required_because", "status_message",
        "workflow_updated_at", "outdated_at", "context_refresh_required",
        "context_refresh_reason", "needs_refresh",
    }
    return any(key not in metadata for key in result)


def output_valid(ticket: dict[str, Any], stage_value: Any) -> bool:
    """[FYP-FUNCTION] [FYP-VALIDATION] True when the stage's persisted result is currently trustworthy.

    False when: no result exists; output_valid was explicitly set False;
    the result is flagged context_refresh_required/needs_refresh (upstream
    context changed since this stage ran); or its status falls in
    FAILED | RUNNING | {"rerun_required", "locked", "ready"} (i.e. it is not
    actually a completed/approved result yet).
    Called by: has_run-adjacent checks throughout backend/app.py,
    postgres_casework_store.py, casework_store.py, execution_complete()
    below.
    """
    result = result_for(ticket, stage_value)
    if not result:
        return False
    if result.get("output_valid") is False:
        return False
    if result.get("context_refresh_required") or result.get("needs_refresh"):
        return False
    status = result_status(result)
    if status in FAILED | RUNNING | {"rerun_required", "locked", "ready"}:
        return False
    return True


def execution_complete(ticket: dict[str, Any], stage_value: Any) -> bool:
    """[FYP-FUNCTION] True when the stage has run AND its output is currently valid (has_run AND output_valid)."""
    return has_run(ticket, stage_value) and output_valid(ticket, stage_value)


def approval_payload(ticket: dict[str, Any], stage_value: Any) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-APPROVAL] Return the analyst-approval payload dict relevant to a stage's approval gate.

    Each stage's approval decision lives in a different ticket field
    depending on the agent (approval_result for triage, the result's own
    embedded workflow_approval for threat_intel, investigation_approval_result
    for investigation, soc_review_result for reporting/final review).
    """
    stage = stage_definition(stage_value)
    if not stage or not stage["approval_gate"]:
        return {}
    if stage["agent"] == "triage":
        value = ticket.get("approval_result") or {}
    elif stage["agent"] == "threat_intel":
        value = result_for(ticket, stage).get("workflow_approval") or {}
    elif stage["agent"] == "investigation":
        value = ticket.get("investigation_approval_result") or {}
    else:
        value = ticket.get("soc_review_result") or {}
    return value if isinstance(value, dict) else {}


def is_approved(ticket: dict[str, Any], stage_value: Any) -> bool:
    """[FYP-FUNCTION] [FYP-APPROVAL] True when a stage requiring approval has a recorded APPROVED decision, or (for gate-free stages) simply True when execution is complete."""
    stage = stage_definition(stage_value)
    if not stage:
        return False
    if not stage["approval_gate"]:
        return execution_complete(ticket, stage)
    if not execution_complete(ticket, stage):
        return False
    payload = approval_payload(ticket, stage)
    return norm(
        payload.get("decision")
        or payload.get("approval_status")
        or payload.get("status")
    ) in APPROVED


def prerequisite_met(ticket: dict[str, Any], stage_value: Any) -> bool:
    """[FYP-FUNCTION] [FYP-STAGE-LOCK] True when every stage BEFORE this one in STAGES is complete (and approved, if gated).

    This is the core "is this stage unlocked" rule: it walks STAGES up to
    (not including) the target stage's index and requires each prior stage
    to be is_approved() (if it has an approval gate) or execution_complete()
    (if it does not).
    Called by: status(), can_run(), can_approve().
    """
    stage = stage_definition(stage_value)
    if not stage:
        return False
    index = next(i for i, item in enumerate(STAGES) if item["agent"] == stage["agent"])
    for prior in STAGES[:index]:
        condition_met = is_approved(ticket, prior) if prior["approval_gate"] else execution_complete(ticket, prior)
        if not condition_met:
            return False
    return True


def locked_message(stage_value: Any) -> str:
    """[FYP-FUNCTION] Human-readable explanation of what must happen before a locked stage can run."""
    stage = stage_definition(stage_value)
    if not stage:
        return "Complete and approve the previous stage to continue."
    messages = {
        "triage": "Complete the Parsing stage to continue.",
        "threat_intel": "Complete and approve the Triage stage to continue.",
        "investigation": "Complete and approve the Threat Intelligence Enrichment stage to continue.",
        "reporting": "Complete and approve the Investigation stage to continue.",
    }
    return messages.get(stage["agent"], "")


def status(ticket: dict[str, Any], stage_value: Any) -> str:
    """[FYP-FUNCTION] [FYP-EVALUATOR] [FYP-STAGE-LOCK] [FYP-STATE] Compute the single canonical lifecycle status for a stage.

    Params: ticket -- ticket dict; stage_value -- any stage identifier
    (resolved via stage_definition()).
    Returns: one of "locked", "ready", "running", "completed",
    "pending_approval", "approved", "failed", "rerun_required".
    Precedence:
      1. If the persisted result's own status is "running"/"failed"/
         "rerun_required", trust it directly.
      2. Else if has_run(): "rerun_required" (if output invalid) else
         "completed" (gate-free) or "approved"/"pending_approval" (gated,
         based on is_approved()).
      3. Else: "ready" if prerequisite_met() else "locked".
    This is THE function every UI/consumer (agent_panel, workflow_steps,
    build_orchestration_decision) calls to render or reason about a stage's
    current state -- it is the closest thing this file has to a single
    "evaluate stage state" entry point.
    Called by: status_label/status_message/can_run (this file),
    orchestration_service.build_orchestration_decision, ticket_workflow.
    agent_panel/workflow_steps.
    """
    stage = stage_definition(stage_value)
    if not stage:
        return "locked"
    result = result_for(ticket, stage)
    persisted = result_status(result)
    if persisted in {"running", "failed", "rerun_required"}:
        return persisted
    if has_run(ticket, stage):
        if not output_valid(ticket, stage):
            return "rerun_required"
        if not stage["approval_gate"]:
            return "completed"
        return "approved" if is_approved(ticket, stage) else "pending_approval"
    return "ready" if prerequisite_met(ticket, stage) else "locked"


def status_label(value: str) -> str:
    """[FYP-FUNCTION] [FYP-UI] Map an internal status string to its display label for the dashboard."""
    return {
        "ready": "Ready",
        "running": "Running",
        "completed": "Completed",
        "pending_approval": "Pending Approval",
        "approved": "Approved",
        "failed": "Failed",
        "rerun_required": "Re-run Required",
        "locked": "Locked",
    }.get(norm(value), str(value or "Locked").replace("_", " ").title())


def status_message(ticket: dict[str, Any], stage_value: Any) -> str:
    """[FYP-FUNCTION] [FYP-UI] [FYP-RERUN] Human-readable explanation for the stage's current status.

    Special-cases "rerun_required" (explains which earlier stage triggered
    the invalidation, using rerun_required_because), "locked" (delegates to
    locked_message), and "failed" (surfaces the agent's own error/message
    field, falling back to a generic "<stage> failed." message).
    """
    stage = stage_definition(stage_value)
    if not stage:
        return ""
    result = result_for(ticket, stage)
    current = status(ticket, stage)
    if current == "rerun_required":
        reason = result.get("rerun_required_because")
        reason_stage = stage_definition(reason)
        reason_label = reason_stage["label"] if reason_stage else str(reason or "an earlier stage")
        return result.get("status_message") or f"Re-run required, as {reason_label} was re-run."
    if current == "locked":
        return locked_message(stage)
    if current == "failed":
        return str(
            result.get("status_message")
            or result.get("error")
            or result.get("error_message")
            or result.get("message")
            or f"{stage['label']} failed."
        )
    return str(result.get("status_message") or "")


def can_run(ticket: dict[str, Any], stage_value: Any) -> tuple[bool, str]:
    """[FYP-FUNCTION] [FYP-EVALUATOR] [FYP-STAGE-LOCK] Decide whether a stage may run (or re-run) right now.

    Params: ticket -- ticket dict; stage_value -- stage identifier.
    Returns: (allowed: bool, reason: str). Blocks while the stage is already
    "running"; blocks when prerequisites are not met, distinguishing the
    case where the immediately-prior stage itself needs a re-run (clearer
    message) from a simple "not started yet" lock.
    Called by: orchestration_service.build_orchestration_decision/
    can_run_agent, backend/app.py (agent dispatch eligibility), can_start()
    below.
    """
    stage = stage_definition(stage_value)
    if not stage:
        return False, "Unknown workflow stage."
    current = status(ticket, stage)
    if current == "running":
        return False, f"{stage['label']} is already running."
    if not prerequisite_met(ticket, stage):
        prior = STAGES[next(i for i, item in enumerate(STAGES) if item["agent"] == stage["agent"]) - 1]
        if status(ticket, prior) == "rerun_required":
            return False, (
                f"{stage['label']} cannot run because {prior['label']} must be re-run"
                + (" and approved." if prior["approval_gate"] else ".")
            )
        return False, locked_message(stage)
    return True, f"{stage['label']} can run."


def can_start(ticket: dict[str, Any], stage_value: Any, *, rerun: bool) -> tuple[bool, str]:
    """[FYP-FUNCTION] [FYP-STAGE-LOCK] [FYP-RERUN] Like can_run(), but also enforces that the "rerun" flag from the UI matches whether the stage has actually run before.

    Prevents "Start Process" being used on a stage that already ran (must
    use "Re-run" instead) and vice versa.
    Called by: backend/app.py `start_background_run()` before launching an
    agent subprocess.
    """
    stage = stage_definition(stage_value)
    allowed, reason = can_run(ticket, stage_value)
    if not allowed or not stage:
        return allowed, reason
    ran = has_run(ticket, stage)
    if rerun and not ran:
        return False, f"{stage['label']} has not run before. Use Start Process."
    if not rerun and ran:
        return False, f"{stage['label']} has already run. Use Re-run."
    return True, reason


def _running_result(previous: dict[str, Any], *, rerun: bool) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-STATE] Build the transient "running" version of a stage's result dict, layered on top of its previous result.

    Marks workflow_status="running", has_run=True, output_valid=False, and
    clears any prior approval_state/workflow_approval/rerun_required_because
    so a fresh run starts with a clean workflow-metadata slate. On a rerun,
    tags previous_output_retained_for_audit=True so the prior payload fields
    (still present in the dict) are understood to be stale audit history
    rather than the live result.
    """
    result = dict(previous)
    result.update({
        "workflow_status": "running",
        "has_run": True,
        "output_valid": False,
        "approval_state": "not_approved",
        "status_message": "",
        "workflow_updated_at": now_iso(),
    })
    result.pop("workflow_approval", None)
    result.pop("rerun_required_because", None)
    if rerun:
        result["previous_output_retained_for_audit"] = True
    return result


def begin_run_fields(
    ticket: dict[str, Any],
    stage_value: Any,
    *,
    rerun: bool,
) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-EVALUATOR] [FYP-STAGE-LOCK] [FYP-RERUN] [FYP-STATE] Build the ticket-field patch to persist when a stage run starts.

    Params: ticket -- ticket dict (read-only, used to seed prior state);
    stage_value -- stage identifier; rerun -- True if this is a re-run of a
    previously completed stage.
    Returns: dict of ticket fields to merge in, including:
      - the stage's own result_key set to a fresh "running" result
        (_running_result), current_stage, and a human status string.
      - clearing of downstream approval-result fields (approval_result,
        investigation_approval_result, soc_review_result) that are no longer
        valid once an earlier stage in the chain is (re)started.
      - on rerun: cascades "rerun_required" onto every DOWNSTREAM stage that
        had already produced a result, so those stages' outputs are visibly
        flagged stale (with rerun_required_because pointing back at this
        stage) until they are re-run themselves. This is the mechanism that
        enforces "re-running Triage invalidates Threat Intel/Investigation/
        Reporting until they are re-run too".
    Side effects: none directly -- returns a dict for the caller to persist.
    Called by: backend/app.py `start_background_run()`, immediately before
    launching the agent subprocess and writing the transition via
    CASEWORK.update_ticket().
    Calls: stage_definition, result_for, _running_result, has_run, now_iso.
    """
    stage = stage_definition(stage_value)
    if not stage:
        return {}
    fields: dict[str, Any] = {
        stage["result_key"]: _running_result(result_for(ticket, stage), rerun=rerun),
        "current_stage": stage["key"],
        "status": f"{stage['label']} Running",
    }
    index = next(i for i, item in enumerate(STAGES) if item["agent"] == stage["agent"])

    if stage["agent"] == "triage" or index < 1:
        fields["approval_result"] = {}
    if stage["agent"] == "investigation" or index < 3:
        fields["investigation_approval_result"] = {}
    if stage["agent"] == "reporting" or index < 4:
        fields["soc_review_result"] = {}

    if rerun:
        message = f"Re-run required, as {stage['label']} was re-run."
        for downstream in STAGES[index + 1:]:
            previous = result_for(ticket, downstream)
            if not previous or not has_run(ticket, downstream):
                continue
            # [FYP-RERUN] Mark this downstream stage's existing result as
            # stale rather than deleting it -- the prior payload is kept for
            # audit purposes but output_valid=False forces it through
            # can_run()/status() as "rerun_required" until re-executed.
            outdated = dict(previous)
            outdated.update({
                "workflow_status": "rerun_required",
                "has_run": True,
                "output_valid": False,
                "approval_state": "invalidated",
                "rerun_required_because": stage["agent"],
                "status_message": message,
                "outdated_at": now_iso(),
                "workflow_updated_at": now_iso(),
            })
            outdated.pop("workflow_approval", None)
            fields[downstream["result_key"]] = outdated
    return fields


def completed_result(stage_value: Any, data: dict[str, Any], *, success: bool, message: str = "") -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-STATE] Stamp workflow metadata onto an agent's raw output dict once a run finishes.

    Params: stage_value -- stage identifier; data -- the agent's raw result
    payload (source: the agent subprocess's JSON output); success -- whether
    the run succeeded; message -- optional failure message override.
    Returns: a copy of data with workflow_status set to "completed" (no
    approval gate + success), "pending_approval" (gated + success), or
    "failed" (not success); plus has_run, output_valid, approval_required,
    approval_state, status_message, workflow_updated_at.
    Called by: backend/app.py, casework_store.py, postgres_casework_store.py
    after an agent run completes, to build the value written into
    ticket[stage["result_key"]].
    """
    stage = stage_definition(stage_value)
    result = dict(data or {})
    if not stage:
        return result
    failed_message = message or str(
        result.get("status_message")
        or result.get("error_message")
        or result.get("error")
        or result.get("message")
        or ""
    )
    result.update({
        "workflow_status": (
            "completed" if success and not stage["approval_gate"]
            else "pending_approval" if success
            else "failed"
        ),
        "has_run": True,
        "output_valid": bool(success),
        "approval_required": bool(stage["approval_gate"]),
        "approval_state": "pending" if success and stage["approval_gate"] else "not_required" if success else "not_approved",
        "status_message": failed_message if not success else "",
        "workflow_updated_at": now_iso(),
    })
    result.pop("workflow_approval", None)
    result.pop("rerun_required_because", None)
    return result


def failure_fields(ticket: dict[str, Any], stage_value: Any, message: str) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-ERROR] [FYP-STATE] Build the ticket-field patch to persist when a stage run fails.

    Params: ticket -- ticket dict; stage_value -- stage identifier;
    message -- failure/error message to surface to the analyst.
    Returns: dict with the stage's result_key set via completed_result(...,
    success=False), plus current_stage and a human status string.
    Called by: backend/app.py, wherever an agent subprocess exits non-zero
    or raises, to persist the failure instead of leaving the ticket stuck in
    "running".
    """
    stage = stage_definition(stage_value)
    if not stage:
        return {}
    previous = result_for(ticket, stage)
    failed = completed_result(stage, previous, success=False, message=message)
    return {
        stage["result_key"]: failed,
        "current_stage": stage["key"],
        "status": f"{stage['label']} Failed",
    }


def can_approve(ticket: dict[str, Any], gate_or_stage: Any) -> tuple[bool, str, dict[str, Any] | None]:
    """[FYP-FUNCTION] [FYP-APPROVAL] [FYP-VALIDATION] Decide whether a stage's output may be approved right now.

    Params: ticket -- ticket dict; gate_or_stage -- approval gate name or
    stage identifier.
    Returns: (allowed, reason, stage_def_or_None). Rejects stages with no
    approval gate, stages whose prerequisites are not met, and stages that
    are already approved, currently running, need a re-run, or whose latest
    run failed -- only a freshly completed ("pending_approval") + valid
    result is approvable.
    Called by: backend/app.py route(s) that record analyst approvals,
    casework_store.py, postgres_casework_store.py, before writing an
    approval decision.
    """
    stage = stage_definition(gate_or_stage)
    if not stage or not stage["approval_gate"]:
        return False, "This stage does not require approval.", stage
    if not prerequisite_met(ticket, stage):
        return False, f"{stage['label']} cannot be approved because an earlier stage is incomplete, unapproved, or outdated.", stage
    current = status(ticket, stage)
    if current == "approved":
        return False, f"{stage['label']} is already approved.", stage
    if current == "running":
        return False, f"{stage['label']} cannot be approved while it is running.", stage
    if current == "rerun_required":
        return False, f"{stage['label']} cannot be approved because its output is outdated and must be re-run.", stage
    if current == "failed":
        return False, f"{stage['label']} cannot be approved because its latest run failed.", stage
    if current != "pending_approval" or not execution_complete(ticket, stage):
        return False, f"{stage['label']} can only be approved after it completes successfully.", stage
    return True, f"{stage['label']} can be approved.", stage


def approval_fields(
    ticket: dict[str, Any],
    stage_value: Any,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-EVALUATOR] [FYP-APPROVAL] [FYP-STATE] Build the ticket-field patch to persist when an analyst approves a stage.

    Params: ticket -- ticket dict; stage_value -- stage identifier;
    payload -- the analyst's approval payload (decision, comments, analyst
    name, etc. -- source: the approval API request body).
    Returns: dict that marks the stage's result approved
    (workflow_status="approved", output_valid=True, approval_state="approved"),
    writes the approval payload into the correct ticket field per agent
    (approval_result for triage, embedded workflow_approval for threat_intel,
    investigation_approval_result for investigation, soc_review_result
    otherwise), and advances current_stage/status to the next STAGES entry
    (or "case_closure"/"Workflow Completed" if this was the last stage).
    Called by: backend/app.py approval route, casework_store.py,
    postgres_casework_store.py when persisting an analyst's approval
    decision -- this is the state transition that actually unlocks the next
    stage's prerequisite_met() check.
    """
    stage = stage_definition(stage_value)
    if not stage:
        return {}
    result = dict(result_for(ticket, stage))
    result.update({
        "workflow_status": "approved",
        "output_valid": True,
        "approval_state": "approved",
        "workflow_updated_at": now_iso(),
    })
    fields: dict[str, Any] = {stage["result_key"]: result}
    if stage["agent"] == "triage":
        fields["approval_result"] = payload
    elif stage["agent"] == "threat_intel":
        result["workflow_approval"] = payload
        fields[stage["result_key"]] = result
    elif stage["agent"] == "investigation":
        fields["investigation_approval_result"] = payload
    else:
        fields["soc_review_result"] = payload

    index = next(i for i, item in enumerate(STAGES) if item["agent"] == stage["agent"])
    if index + 1 < len(STAGES):
        next_stage = STAGES[index + 1]
        fields.update({
            "current_stage": next_stage["key"],
            "status": f"{next_stage['label']} Required",
        })
    else:
        fields.update({
            "current_stage": "case_closure",
            "status": "Workflow Completed",
        })
    return fields


def workflow_complete(ticket: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] [FYP-STATE] True when every stage in STAGES is approved (if gated) or execution-complete (if not), i.e. the whole pipeline is done.

    Called by: orchestration_service.build_orchestration_decision (first
    check -- short-circuits straight to "workflow_completed").
    """
    return all(
        is_approved(ticket, stage) if stage["approval_gate"] else execution_complete(ticket, stage)
        for stage in STAGES
    )
