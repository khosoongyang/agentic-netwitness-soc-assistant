from __future__ import annotations

"""Canonical five-stage ticket workflow state.

The agent output JSON objects remain the persisted source of truth.  Workflow
metadata is stored alongside each output so existing report/view/export code
can continue to read the original payload without a database schema change.
"""

from datetime import datetime, timezone
from typing import Any


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

FAILED = {
    "failed", "error", "execution_error", "timed_out", "timeout", "crashed",
    "invalid_output", "missing_required_context", "failed_postgres_unavailable",
    "blocked_missing_triage", "blocked_pending_triage_approval", "paused",
    "cancelled", "canceled",
}
RUNNING = {"running", "thinking", "in_progress", "started", "starting", "queued"}
APPROVED = {"approved", "approve", "completed", "confirmed", "continue_to_reporting"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def norm(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def canonical_agent(value: Any) -> str:
    value = norm(value)
    aliases = {
        "parsing_normalisation": "parsing",
        "parser": "parsing",
        "threat_intelligence": "threat_intel",
        "threat_intelligence_enrichment": "threat_intel",
    }
    return aliases.get(value, value)


def stage_definition(value: Any) -> dict[str, Any] | None:
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
    stage = stage_definition(stage_value)
    if not stage:
        return {}
    value = ticket.get(stage["result_key"]) or {}
    return value if isinstance(value, dict) else {}


def result_status(result: dict[str, Any]) -> str:
    return norm(
        result.get("workflow_status")
        or result.get("status")
        or result.get("report_status")
        or result.get("decision")
    )


def has_run(ticket: dict[str, Any], stage_value: Any) -> bool:
    result = result_for(ticket, stage_value)
    return bool(result and result.get("has_run", True))


def has_output_content(ticket: dict[str, Any], stage_value: Any) -> bool:
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
    return has_run(ticket, stage_value) and output_valid(ticket, stage_value)


def approval_payload(ticket: dict[str, Any], stage_value: Any) -> dict[str, Any]:
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
    return all(
        is_approved(ticket, stage) if stage["approval_gate"] else execution_complete(ticket, stage)
        for stage in STAGES
    )
