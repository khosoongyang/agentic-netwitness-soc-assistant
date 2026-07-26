from __future__ import annotations

import json

import pytest

import workflow_state_store as wss


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "rerun.db")
    wss.db_init()


def _run_with_approved_triage(incident_id: str = "INC-1") -> str:
    run_id = wss.start_run(incident_id)
    wss._guarded_update(incident_id, run_id, {
        "parsing_status": "Complete",
        "triage_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval",
        "approval_stage": "triage",
    })
    wss.approve_triage(incident_id, run_id, approved_by="analyst")
    return run_id


def test_rerun_threat_intel_restarts_stage_and_invalidates_downstream():
    run_id = _run_with_approved_triage()
    wss._guarded_update("INC-1", run_id, {
        "threat_intel_status": "Complete",
        "threat_intel_result_json": json.dumps({"status": "completed"}),
        "investigation_status": "Awaiting Approval",
        "investigation_result_json": json.dumps({"status": "completed"}),
        "reporting_status": "Approved",
        "reporting_result_json": json.dumps({"status": "completed"}),
        "workflow_status": "Complete",
    })

    wss.rerun_stage("INC-1", run_id, "threat_intel")

    state = wss.get_state("INC-1")
    assert state["threat_intel_status"] == "Processing"
    assert state["threat_intel_result_json"] is None
    assert state["investigation_status"] == "Pending"
    assert state["investigation_result_json"] is None
    assert state["reporting_status"] == "Pending"
    assert state["reporting_result_json"] is None
    assert state["workflow_status"] == "Processing"


def test_rerun_investigation_removes_old_approval_and_can_be_approved_again():
    run_id = _run_with_approved_triage()
    wss._guarded_update("INC-1", run_id, {
        "threat_intel_status": "Complete",
        "investigation_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval",
        "approval_stage": "investigation",
    })
    wss.approve_investigation("INC-1", run_id, approved_by="analyst")
    wss._guarded_update("INC-1", run_id, {
        "reporting_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval",
        "approval_stage": "reporting",
    })

    wss.rerun_stage("INC-1", run_id, "investigation")
    state = wss.get_state("INC-1")
    assert state["investigation_status"] == "Processing"
    assert state["reporting_status"] == "Pending"

    wss._guarded_update("INC-1", run_id, {
        "investigation_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval",
        "approval_stage": "investigation",
    })
    wss.approve_investigation("INC-1", run_id, approved_by="analyst")
    assert wss.get_state("INC-1")["investigation_status"] == "Approved"


def test_rerun_reporting_reopens_a_completed_workflow():
    run_id = _run_with_approved_triage()
    wss._guarded_update("INC-1", run_id, {
        "threat_intel_status": "Complete",
        "investigation_status": "Approved",
        "reporting_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval",
        "approval_stage": "reporting",
    })
    _state = wss.get_state("INC-1")
    wss.commit_reporting_approval(
        "INC-1", run_id,
        expected_reporting_attempt=_state["reporting_attempt"],
        expected_reporting_result_json=_state["reporting_result_json"],
        metadata={}, approved_by="analyst")

    wss.rerun_stage("INC-1", run_id, "reporting")

    state = wss.get_state("INC-1")
    assert state["reporting_status"] == "Processing"
    assert state["workflow_status"] == "Processing"
    assert state["approval_stage"] is None


def test_duplicate_rerun_is_rejected_while_stage_is_processing():
    run_id = _run_with_approved_triage()
    wss._guarded_update("INC-1", run_id, {
        "threat_intel_status": "Complete",
        "workflow_status": "Awaiting Approval",
    })
    wss.rerun_stage("INC-1", run_id, "threat_intel")

    with pytest.raises(wss.ApprovalConflictError):
        wss.rerun_stage("INC-1", run_id, "threat_intel")


def test_fresh_rerun_cannot_replace_a_run_that_is_already_processing():
    wss.start_run("INC-1")

    with pytest.raises(wss.WorkflowAlreadyRunningError):
        wss.start_run("INC-1", allow_retry=True)
