"""Characterization tests for the Phase 4 workflow command adapter."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from workflow import state_store as wss
from workflow import commands


@pytest.fixture(autouse=True)
def isolated_workflow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "commands.db")
    with commands._TASKS_LOCK:
        commands._TASKS.clear()
    wss.db_init()
    with wss.db_connect() as connection:
        connection.execute(
            "INSERT INTO incidents (id, title, severity, status, raw_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                "CASE-001", "Command characterization", "HIGH", "New",
                json.dumps({"id": "CASE-001", "title": "Command characterization"}),
            ),
        )
        connection.commit()
    yield
    with commands._TASKS_LOCK:
        commands._TASKS.clear()


def _run_at_triage_approval() -> str:
    run_id = wss.start_run("CASE-001")
    wss._guarded_update("CASE-001", run_id, {
        "parsing_status": "Complete",
        "triage_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval",
        "approval_stage": "triage",
    })
    return run_id


def _run_after_triage_approval() -> str:
    run_id = _run_at_triage_approval()
    wss.approve_triage("CASE-001", run_id, approved_by="Analyst")
    return run_id


def test_fresh_stage_start_uses_existing_run_identity_generation() -> None:
    def existing_fresh_entrypoint(incident: dict) -> None:
        wss.start_run(incident["id"])

    result = commands.start_stage(
        "CASE-001", "parsing", executor=existing_fresh_entrypoint
    )

    assert result["run_id"].startswith("CASE-001@")
    assert result["status"] == "running"
    assert wss.get_state("CASE-001")["run_id"] == result["run_id"]


def test_start_stage_delegates_to_begin_stage_and_rejects_duplicate() -> None:
    run_id = _run_after_triage_approval()
    commands.start_stage("CASE-001", "threat_intel", executor=lambda *_: None)

    state = wss.get_state("CASE-001")
    assert state["run_id"] == run_id
    assert state["threat_intel_status"] == "Processing"
    with pytest.raises(commands.WorkflowCommandError) as duplicate:
        commands.start_stage("CASE-001", "threat_intel", executor=lambda *_: None)
    assert duplicate.value.code in {"ALREADY_RUNNING", "WORKFLOW_BUSY"}


def test_locked_stage_preserves_canonical_rejection() -> None:
    _run_at_triage_approval()
    with pytest.raises(commands.WorkflowCommandError) as error:
        commands.start_stage("CASE-001", "investigation", executor=lambda *_: None)
    assert error.value.code == "STAGE_LOCKED"


def test_rerun_increments_attempt_and_invalidates_downstream() -> None:
    run_id = _run_after_triage_approval()
    wss._guarded_update("CASE-001", run_id, {
        "threat_intel_status": "Complete",
        "investigation_status": "Approved",
        "investigation_result_json": json.dumps({"old": True}),
        "reporting_status": "Approved",
        "reporting_result_json": json.dumps({"old": True}),
        "workflow_status": "Complete",
    })

    result = commands.rerun_stage(
        "CASE-001", "threat_intel", executor=lambda *_: None
    )
    state = wss.get_state("CASE-001")

    assert result["attempt"] == 2
    assert state["threat_intel_status"] == "Processing"
    assert state["investigation_status"] == "Pending"
    assert state["investigation_result_json"] is None
    assert state["reporting_status"] == "Pending"
    assert state["reporting_result_json"] is None


def test_triage_rerun_uses_fresh_canonical_run_and_resets_downstream() -> None:
    previous_run_id = _run_after_triage_approval()
    wss._guarded_update("CASE-001", previous_run_id, {
        "threat_intel_status": "Complete",
        "investigation_status": "Approved",
        "reporting_status": "Approved",
        "workflow_status": "Complete",
    })

    def existing_retry_entrypoint(incident: dict) -> None:
        wss.start_run(incident["id"], allow_retry=True)

    result = commands.rerun_stage(
        "CASE-001", "triage", executor=existing_retry_entrypoint
    )
    state = wss.get_state("CASE-001")

    assert result["run_id"] != previous_run_id
    assert state["run_id"] == result["run_id"]
    assert state["parsing_status"] == "Processing"
    assert state["threat_intel_status"] == "Pending"
    assert state["investigation_status"] == "Pending"
    assert state["reporting_status"] == "Pending"


def test_approval_and_duplicate_approval_use_atomic_state_store() -> None:
    run_id = _run_at_triage_approval()
    result = commands.approve_stage(
        "CASE-001", "triage", analyst="SOC Analyst", comments="Reviewed"
    )

    assert result["decision"] == "approve"
    assert wss.get_state("CASE-001")["triage_status"] == "Approved"
    assert len(wss.get_approval_history("CASE-001", run_id)) == 1
    with pytest.raises(commands.WorkflowCommandError) as duplicate:
        commands.approve_stage("CASE-001", "triage", analyst="SOC Analyst")
    assert duplicate.value.code == "DUPLICATE_APPROVAL"


def test_rejection_requires_reason_and_blocks_downstream() -> None:
    _run_at_triage_approval()
    with pytest.raises(commands.WorkflowCommandError) as missing_reason:
        commands.reject_stage(
            "CASE-001", "triage", analyst="SOC Analyst", comments=""
        )
    assert missing_reason.value.code == "REJECTION_REASON_REQUIRED"

    commands.reject_stage(
        "CASE-001", "triage", analyst="SOC Analyst", comments="False positive"
    )
    state = wss.get_state("CASE-001")
    assert state["triage_status"] == "Rejected"
    assert state["threat_intel_status"] == "Blocked"


def test_resume_uses_existing_dispatcher_only_after_start_grace() -> None:
    run_id = _run_after_triage_approval()
    old = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    wss._guarded_update("CASE-001", run_id, {
        "threat_intel_status": "Processing",
        "workflow_status": "Processing",
        "worker_id": None,
        "worker_lease_expires_at": None,
    })
    with wss.db_connect() as connection:
        connection.execute(
            "UPDATE incidents SET workflow_updated_at=? WHERE id=? AND run_id=?",
            (old, "CASE-001", run_id),
        )
        connection.commit()
    called = threading.Event()

    def dispatcher(case_id: str, dispatched_run_id: str) -> None:
        assert case_id == "CASE-001"
        assert dispatched_run_id == run_id
        called.set()

    result = commands.resume_workflow("CASE-001", executor=dispatcher)

    assert result["stage"] == "threat_intel"
    assert called.wait(1)


def test_run_status_and_evidence_gap_policy_are_presentation_adapters() -> None:
    run_id = _run_at_triage_approval()
    status = commands.get_run_status(run_id)
    assert status["case_id"] == "CASE-001"
    assert status["status"] == "Awaiting Approval"
    assert status["poll"] is False

    with pytest.raises(commands.WorkflowCommandError) as unsupported:
        commands.apply_evidence_gap_decision("CASE-001", "continue")
    assert unsupported.value.code == "INVALID_EVIDENCE_GAP_DECISION"
