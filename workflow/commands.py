"""Thin command adapter over Aegis's existing workflow implementation.

No transition rules are implemented by Flask or JavaScript. Commands call
the existing atomic transitions in ``workflow_state_store`` and the existing
workers in ``soc_workflow``. Background threads mirror the legacy Streamlit
launch model and are only an in-process execution adapter.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

import workflow_state_store as wss


STAGES = ("parsing", "triage", "threat_intel", "investigation", "reporting")
APPROVAL_STAGES = ("triage", "investigation", "reporting")
_STAGE_ALIASES = {
    "parsing": "parsing",
    "parsing_normalisation": "parsing",
    "parsing_and_normalisation": "parsing",
    "triage": "triage",
    "threat_intel": "threat_intel",
    "threat_intelligence": "threat_intel",
    "threat_intelligence_enrichment": "threat_intel",
    "investigation": "investigation",
    "reporting": "reporting",
}
_WORKER_START_GRACE_SECONDS = 15


class WorkflowCommandError(RuntimeError):
    """Stable application error raised around canonical workflow failures."""

    def __init__(self, code: str, message: str, status_code: int = 409):
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


@dataclass
class _BackgroundTask:
    thread: threading.Thread
    stage: str
    started_at: str
    error: str | None = None


_TASKS: dict[str, _BackgroundTask] = {}
_TASKS_LOCK = threading.Lock()
_FRESH_LAUNCH_LOCK = threading.Lock()


def normalise_stage(stage: str) -> str:
    key = str(stage or "").strip().lower().replace("-", "_").replace(" ", "_")
    try:
        return _STAGE_ALIASES[key]
    except KeyError as exc:
        raise WorkflowCommandError(
            "INVALID_STAGE", f"Unknown workflow stage: {stage or 'empty stage'}.", 400
        ) from exc


def _state_or_error(case_id: str) -> dict[str, Any]:
    state = wss.get_state(str(case_id))
    if state is None:
        raise WorkflowCommandError("CASE_NOT_FOUND", "Case was not found.", 404)
    return state


def _current_run(state: dict[str, Any]) -> str:
    run_id = str(state.get("run_id") or "")
    if not run_id:
        raise WorkflowCommandError(
            "WORKFLOW_NOT_STARTED", "This case does not have an active workflow run."
        )
    return run_id


def _canonical_conflict(exc: Exception, *, default_code: str) -> WorkflowCommandError:
    message = str(exc)
    lowered = message.lower()
    if "already" in lowered and "running" in lowered:
        code = "ALREADY_RUNNING"
    elif "processing" in lowered:
        code = "WORKFLOW_BUSY"
    elif "stale" in lowered:
        code = "STALE_ATTEMPT"
    elif "already" in lowered and "decid" in lowered:
        code = "DUPLICATE_APPROVAL"
    else:
        code = default_code
    return WorkflowCommandError(code, message)


def _task_wrapper(run_id: str, target: Callable[..., Any], args: tuple[Any, ...]) -> None:
    try:
        target(*args)
    except Exception as exc:  # persisted workflow state remains authoritative
        with _TASKS_LOCK:
            task = _TASKS.get(run_id)
            if task is not None:
                task.error = str(exc)[:500]


def _spawn_background(
    run_id: str,
    stage: str,
    target: Callable[..., Any],
    args: tuple[Any, ...],
) -> None:
    with _TASKS_LOCK:
        existing = _TASKS.get(run_id)
        if existing is not None and existing.thread.is_alive():
            raise WorkflowCommandError(
                "ALREADY_RUNNING", "This workflow already has an active worker."
            )
        thread = threading.Thread(
            target=_task_wrapper,
            args=(run_id, target, args),
            daemon=True,
            name=f"aegis-{stage}-{run_id[-12:]}",
        )
        _TASKS[run_id] = _BackgroundTask(
            thread=thread,
            stage=stage,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        thread.start()


def _ensure_no_local_worker(run_id: str) -> None:
    with _TASKS_LOCK:
        task = _TASKS.get(run_id)
        if task is not None and task.thread.is_alive():
            raise WorkflowCommandError(
                "ALREADY_RUNNING", "This workflow already has an active worker."
            )


def _raw_incident(state: dict[str, Any]) -> dict[str, Any]:
    try:
        raw = json.loads(state.get("raw_json") or "{}")
    except (TypeError, ValueError):
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    if isinstance(raw.get("incident"), dict):
        raw = dict(raw["incident"])
    incident = dict(raw)
    incident.setdefault("id", str(state.get("id") or ""))
    incident.setdefault("title", state.get("title") or "Untitled case")
    incident.setdefault("severity", state.get("severity"))
    incident.setdefault("status", state.get("status"))
    incident.setdefault("assignee", state.get("assignee"))
    return incident


def _fresh_worker(
    incident: dict[str, Any],
    *,
    allow_retry: bool,
    parsing_only: bool,
) -> dict[str, Any]:
    from soc_workflow import run_until_triage_approval

    return run_until_triage_approval(
        incident,
        allow_retry=allow_retry,
        parsing_only=parsing_only,
    )


def _stage_chain(case_id: str, run_id: str) -> None:
    from soc_workflow import run_stage_chain

    run_stage_chain(case_id, run_id)


def _launch_fresh(
    case_id: str,
    stage: str,
    *,
    allow_retry: bool,
    executor: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Launch the existing Parsing/Triage entry point and observe its run ID."""
    with _FRESH_LAUNCH_LOCK:
        before = _state_or_error(case_id)
        if before.get("workflow_status") == "Processing":
            raise WorkflowCommandError(
                "ALREADY_RUNNING", "This case's workflow is already processing."
            )
        if before.get("workflow_status") == "Awaiting Approval" and not allow_retry:
            raise WorkflowCommandError(
                "ALREADY_RUNNING", "This case is already awaiting an approval decision."
            )
        previous_run_id = before.get("run_id")
        incident = _raw_incident(before)
        worker = executor or _fresh_worker
        provisional = f"launch:{case_id}:{time.monotonic_ns()}"
        _spawn_background(
            provisional,
            stage,
            worker,
            (incident,),
        ) if executor else _spawn_fresh_default(
            provisional, stage, worker, incident, allow_retry, stage == "parsing"
        )

        deadline = time.monotonic() + 2.0
        state = before
        while time.monotonic() < deadline:
            state = _state_or_error(case_id)
            if state.get("run_id") and state.get("run_id") != previous_run_id:
                break
            with _TASKS_LOCK:
                task = _TASKS.get(provisional)
                if task is not None and not task.thread.is_alive() and task.error:
                    raise WorkflowCommandError("SERVICE_FAILURE", task.error, 500)
            time.sleep(0.01)
        else:
            raise WorkflowCommandError(
                "SERVICE_FAILURE", "The workflow did not publish a run identity.", 500
            )

        run_id = str(state["run_id"])
        with _TASKS_LOCK:
            task = _TASKS.get(provisional)
            if task is not None:
                _TASKS[run_id] = task
        return {
            "case_id": str(case_id),
            "run_id": run_id,
            "stage": stage,
            "status": "running",
            "attempt": 1,
        }


def _spawn_fresh_default(
    provisional: str,
    stage: str,
    worker: Callable[..., Any],
    incident: dict[str, Any],
    allow_retry: bool,
    parsing_only: bool,
) -> None:
    def invoke(payload: dict[str, Any]) -> Any:
        return worker(
            payload,
            allow_retry=allow_retry,
            parsing_only=parsing_only,
        )

    _spawn_background(provisional, stage, invoke, (incident,))


def start_stage(
    case_id: str,
    stage: str,
    *,
    executor: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Start an eligible stage through the existing canonical transition."""
    stage = normalise_stage(stage)
    if stage in {"parsing", "triage"}:
        return _launch_fresh(
            str(case_id), stage, allow_retry=False, executor=executor
        )

    state = _state_or_error(case_id)
    run_id = _current_run(state)
    _ensure_no_local_worker(run_id)
    try:
        result = wss.begin_stage(str(case_id), run_id, stage)
    except wss.ApprovalConflictError as exc:
        raise _canonical_conflict(exc, default_code="STAGE_LOCKED") from exc
    _spawn_background(run_id, stage, executor or _stage_chain, (str(case_id), run_id))
    updated = _state_or_error(case_id)
    return {
        **result,
        "case_id": str(case_id),
        "status": "running",
        "attempt": int(updated.get(f"{stage}_attempt") or 1),
    }


def rerun_stage(
    case_id: str,
    stage: str,
    *,
    executor: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Re-run a stage using the legacy UI's exact canonical path."""
    stage = normalise_stage(stage)
    if stage in {"parsing", "triage"}:
        return _launch_fresh(
            str(case_id), stage, allow_retry=True, executor=executor
        )

    state = _state_or_error(case_id)
    run_id = _current_run(state)
    _ensure_no_local_worker(run_id)
    try:
        result = wss.rerun_stage(str(case_id), run_id, stage)
    except wss.ApprovalConflictError as exc:
        raise _canonical_conflict(exc, default_code="STAGE_LOCKED") from exc
    _spawn_background(run_id, stage, executor or _stage_chain, (str(case_id), run_id))
    updated = _state_or_error(case_id)
    return {
        **result,
        "case_id": str(case_id),
        "status": "running",
        "attempt": int(updated.get(f"{stage}_attempt") or 1),
    }


def approve_stage(
    case_id: str,
    stage: str,
    *,
    analyst: str,
    comments: str = "",
) -> dict[str, Any]:
    """Approve an existing gate without automatically starting its successor."""
    stage = normalise_stage(stage)
    if stage not in APPROVAL_STAGES:
        raise WorkflowCommandError(
            "INVALID_STAGE", f"{stage} does not have an analyst approval gate.", 400
        )
    if not str(analyst or "").strip():
        raise WorkflowCommandError("INVALID_REQUEST", "analyst is required.", 400)
    state = _state_or_error(case_id)
    run_id = _current_run(state)
    prior_decisions = [
        item for item in wss.get_approval_history(str(case_id), run_id)
        if item.get("approval_stage") == stage
    ]
    if prior_decisions and not (
        state.get("workflow_status") == "Awaiting Approval"
        and state.get("approval_stage") == stage
        and state.get(f"{stage}_status") == "Awaiting Approval"
    ):
        raise WorkflowCommandError(
            "DUPLICATE_APPROVAL", f"{stage} was already decided for this workflow run."
        )
    try:
        if stage == "triage":
            result = wss.approve_triage(
                str(case_id), run_id, approved_by=analyst.strip(), comments=comments
            )
        elif stage == "investigation":
            result = wss.approve_investigation(
                str(case_id), run_id, approved_by=analyst.strip(), comments=comments
            )
        else:
            from reporting_approval import approve_reporting_candidate

            result = approve_reporting_candidate(
                str(case_id), run_id, analyst=analyst.strip(), comments=comments
            )
    except wss.ApprovalConflictError as exc:
        decisions = [
            item for item in wss.get_approval_history(str(case_id), run_id)
            if item.get("approval_stage") == stage
        ]
        if decisions:
            raise WorkflowCommandError(
                "DUPLICATE_APPROVAL", f"{stage} was already decided for this workflow run."
            ) from exc
        raise _canonical_conflict(exc, default_code="APPROVAL_CONFLICT") from exc
    except Exception as exc:
        if exc.__class__.__name__ == "ReportValidationError":
            raise WorkflowCommandError("APPROVAL_CONFLICT", str(exc)) from exc
        raise
    return {**result, "case_id": str(case_id), "stage": stage, "decision": "approve"}


def reject_stage(
    case_id: str,
    stage: str,
    *,
    analyst: str,
    comments: str,
) -> dict[str, Any]:
    """Reject an existing gate through the stage's atomic transition."""
    stage = normalise_stage(stage)
    if stage not in APPROVAL_STAGES:
        raise WorkflowCommandError(
            "INVALID_STAGE", f"{stage} does not have an analyst approval gate.", 400
        )
    analyst = str(analyst or "").strip()
    reason = str(comments or "").strip()
    if not analyst:
        raise WorkflowCommandError("INVALID_REQUEST", "analyst is required.", 400)
    if not reason:
        raise WorkflowCommandError(
            "REJECTION_REASON_REQUIRED", "A rejection reason is required.", 400
        )
    state = _state_or_error(case_id)
    run_id = _current_run(state)
    try:
        if stage == "triage":
            result = wss.reject_triage(
                str(case_id), run_id, rejected_by=analyst, reason=reason
            )
        elif stage == "investigation":
            result = wss.reject_investigation(
                str(case_id), run_id, rejected_by=analyst, reason=reason
            )
        else:
            result = wss.reject_reporting(
                str(case_id), run_id, rejected_by=analyst, reason=reason
            )
    except wss.ApprovalConflictError as exc:
        decisions = [
            item for item in wss.get_approval_history(str(case_id), run_id)
            if item.get("approval_stage") == stage
        ]
        if decisions:
            raise WorkflowCommandError(
                "DUPLICATE_APPROVAL", f"{stage} was already decided for this workflow run."
            ) from exc
        raise _canonical_conflict(exc, default_code="APPROVAL_CONFLICT") from exc
    return {**result, "case_id": str(case_id), "stage": stage, "decision": "reject"}


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _processing_stage(state: dict[str, Any]) -> str | None:
    return next(
        (stage for stage in STAGES if state.get(f"{stage}_status") == "Processing"),
        None,
    )


def _live_lease(state: dict[str, Any]) -> bool:
    expiry = _parse_time(state.get("worker_lease_expires_at"))
    if expiry is not None and expiry > datetime.now(timezone.utc):
        return True
    updated = _parse_time(state.get("workflow_updated_at"))
    if not state.get("worker_id") and updated is not None:
        return (datetime.now(timezone.utc) - updated).total_seconds() < _WORKER_START_GRACE_SECONDS
    return False


def available_actions(state: dict[str, Any]) -> dict[str, Any]:
    """Describe controls conservatively; canonical transitions still recheck."""
    workflow_busy = state.get("workflow_status") == "Processing"
    run_id = state.get("run_id")
    processing_stage = _processing_stage(state)
    resume_enabled = bool(
        workflow_busy
        and processing_stage in {"threat_intel", "investigation", "reporting"}
        and not _live_lease(state)
    )
    upstream_ready = {
        "parsing": True,
        "triage": state.get("parsing_status") == "Complete",
        "threat_intel": state.get("triage_status") == "Approved",
        "investigation": state.get("threat_intel_status")
        in {"Complete", "Complete with Warnings"},
        "reporting": state.get("investigation_status") == "Approved",
    }
    rerun_statuses = {
        "parsing": {"Complete", "Failed"},
        "triage": {"Awaiting Approval", "Approved", "Failed", "Rejected"},
        "threat_intel": {"Complete", "Complete with Warnings", "Failed"},
        "investigation": {"Awaiting Approval", "Approved", "Failed"},
        "reporting": {"Awaiting Approval", "Approved", "Failed", "Rejected"},
    }
    output: dict[str, list[dict[str, Any]]] = {}
    for stage in STAGES:
        status = state.get(f"{stage}_status")
        stage_actions: list[dict[str, Any]] = []
        if stage == "parsing":
            can_start = not run_id and not workflow_busy
        elif stage == "triage":
            can_start = bool(run_id and status == "Pending" and upstream_ready[stage]
                             and not workflow_busy)
        else:
            can_start = bool(run_id and status == "Pending" and upstream_ready[stage]
                             and not workflow_busy)
        if can_start or status in {None, "", "Pending"}:
            stage_actions.append({
                "type": "start",
                "label": "Run",
                "enabled": can_start,
                "confirmation": False,
                "reason": None if can_start else "This stage is locked by canonical workflow state.",
            })
        can_rerun = bool(
            run_id and not workflow_busy and status in rerun_statuses[stage]
            and upstream_ready[stage]
        )
        if status in rerun_statuses[stage]:
            stage_actions.append({
                "type": "rerun",
                "label": "Re-run",
                "enabled": can_rerun,
                "confirmation": True,
                "reason": None if can_rerun else "The workflow is busy or an upstream gate is locked.",
            })
        awaiting = bool(
            stage in APPROVAL_STAGES
            and state.get("workflow_status") == "Awaiting Approval"
            and state.get("approval_stage") == stage
            and status == "Awaiting Approval"
        )
        if stage in APPROVAL_STAGES and (awaiting or status == "Awaiting Approval"):
            stage_actions.extend((
                {
                    "type": "approve", "label": "Approve", "enabled": awaiting,
                    "confirmation": False,
                    "reason": None if awaiting else "This approval gate is no longer current.",
                },
                {
                    "type": "reject", "label": "Reject", "enabled": awaiting,
                    "confirmation": True,
                    "reason": None if awaiting else "This approval gate is no longer current.",
                },
            ))
        if processing_stage == stage:
            stage_actions.append({
                "type": "resume",
                "label": "Resume",
                "enabled": resume_enabled,
                "confirmation": False,
                "reason": (
                    None if resume_enabled
                    else "The worker is active or is still within its start grace period."
                ),
            })
        output[stage] = stage_actions
    return {
        "stages": output,
        "evidence_gap": {
            "mode": "automatic",
            "decisions": [],
            "message": "Evidence-gap repair is handled automatically by Investigation.",
        },
    }


def resume_workflow(
    case_id: str,
    *,
    executor: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Resume a persisted downstream Processing stage via run_stage_chain."""
    state = _state_or_error(case_id)
    run_id = _current_run(state)
    stage = _processing_stage(state)
    if state.get("workflow_status") != "Processing" or stage not in {
        "threat_intel", "investigation", "reporting"
    }:
        raise WorkflowCommandError(
            "WORKFLOW_NOT_RESUMABLE",
            "No supported interrupted downstream stage is ready to resume.",
        )
    if _live_lease(state):
        raise WorkflowCommandError(
            "ALREADY_RUNNING", "The workflow worker is active or still starting."
        )
    _spawn_background(run_id, stage, executor or _stage_chain, (str(case_id), run_id))
    return {
        "case_id": str(case_id),
        "run_id": run_id,
        "stage": stage,
        "status": "running",
        "attempt": int(state.get(f"{stage}_attempt") or 1),
    }


def get_run_status(run_id: str) -> dict[str, Any]:
    """Return persisted run state plus safe in-process worker activity."""
    wss.db_init()
    with wss.db_connect() as connection:
        row = connection.execute(
            "SELECT * FROM incidents WHERE run_id=?", (str(run_id),)
        ).fetchone()
    if row is None:
        raise WorkflowCommandError("RUN_NOT_FOUND", "Workflow run was not found.", 404)
    state = dict(row)
    stage = state.get("worker_stage") or _processing_stage(state)
    with _TASKS_LOCK:
        task = _TASKS.get(str(run_id))
        worker_alive = bool(task and task.thread.is_alive())
        task_error = task.error if task else None
        task_started = task.started_at if task else None
    attempt = (
        int(state.get(f"{stage}_attempt") or 1)
        if stage in {"threat_intel", "investigation", "reporting"}
        else 1
    )
    status = str(state.get("workflow_status") or "Unknown")
    completed_at = state.get("workflow_updated_at") if status in {
        "Complete", "Failed", "Rejected", "Awaiting Approval", "Awaiting Action"
    } else None
    return {
        "run_id": str(run_id),
        "case_id": str(state.get("id")),
        "stage": stage,
        "attempt": attempt,
        "status": status,
        "stage_status": state.get(f"{stage}_status") if stage else None,
        "started_at": task_started or state.get("workflow_updated_at"),
        "updated_at": state.get("workflow_updated_at"),
        "completed_at": completed_at,
        "progress": {
            "worker_alive": worker_alive,
            "worker_stage": state.get("worker_stage"),
            "note": state.get("worker_progress_note"),
            "heartbeat_at": state.get("worker_heartbeat_at"),
            "lease_expires_at": state.get("worker_lease_expires_at"),
        },
        "error": state.get("last_error") or task_error,
        "poll": status == "Processing",
    }


def apply_evidence_gap_decision(case_id: str, decision: str) -> dict[str, Any]:
    """Reject invented manual decisions; existing gap handling is automatic."""
    _state_or_error(case_id)
    raise WorkflowCommandError(
        "INVALID_EVIDENCE_GAP_DECISION",
        "Investigation evidence gaps are handled by the existing automatic feedback loop; "
        "no analyst evidence-gap transition is currently defined.",
        400,
    )
