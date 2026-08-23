"""HTTP transport for canonical workflow commands."""

from __future__ import annotations

from typing import Any, Callable

from flask import Blueprint, jsonify, request

from workflow import commands

from ..errors import APIError


workflow_blueprint = Blueprint("workflow_commands", __name__, url_prefix="/api")


def _json_body() -> dict[str, Any]:
    body = request.get_json(silent=True)
    if body is None:
        return {}
    if not isinstance(body, dict):
        raise APIError("INVALID_REQUEST", "The request body must be a JSON object.", 400)
    return body


def _command(call: Callable[..., dict[str, Any]], *args: Any, **kwargs: Any):
    try:
        return call(*args, **kwargs)
    except commands.WorkflowCommandError as exc:
        raise APIError(exc.code, exc.message, exc.status_code) from exc


@workflow_blueprint.post("/cases/<case_id>/stages/<stage>/runs")
def start_stage(case_id: str, stage: str):
    result = _command(commands.start_stage, case_id, stage)
    return jsonify(result), 202


@workflow_blueprint.post("/cases/<case_id>/stages/<stage>/reruns")
def rerun_stage(case_id: str, stage: str):
    result = _command(commands.rerun_stage, case_id, stage)
    return jsonify(result), 202


@workflow_blueprint.get("/runs/<run_id>")
def run_status(run_id: str):
    return jsonify(_command(commands.get_run_status, run_id))


@workflow_blueprint.post("/cases/<case_id>/approvals/<stage>")
def decide_approval(case_id: str, stage: str):
    body = _json_body()
    decision = str(body.get("decision") or "").strip().lower()
    analyst = str(body.get("analyst") or "").strip()
    comments = str(body.get("comments") or "")
    if decision == "approve":
        result = _command(
            commands.approve_stage,
            case_id,
            stage,
            analyst=analyst,
            comments=comments,
        )
    elif decision == "reject":
        result = _command(
            commands.reject_stage,
            case_id,
            stage,
            analyst=analyst,
            comments=comments,
        )
    else:
        raise APIError(
            "INVALID_APPROVAL_DECISION",
            "decision must be either approve or reject.",
            400,
        )
    return jsonify(result)


@workflow_blueprint.post("/cases/<case_id>/workflow/resume")
def resume_workflow(case_id: str):
    result = _command(commands.resume_workflow, case_id)
    return jsonify(result), 202


@workflow_blueprint.post("/cases/<case_id>/evidence-gap-decisions")
def evidence_gap_decision(case_id: str):
    body = _json_body()
    result = _command(
        commands.apply_evidence_gap_decision,
        case_id,
        str(body.get("decision") or ""),
    )
    return jsonify(result)
