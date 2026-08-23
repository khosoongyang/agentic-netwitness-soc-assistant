"""
[FYP-FILE]
# Important dependencies: __future__, json, pytest, workflow_state_store.
File: tests/test_stage_rerun.py
Purpose: Verifies workflow_state_store.rerun_stage() — the durable-DB
    operation behind the "Rerun this stage" button in app.py's My
    Workspace, for each of the three re-runnable downstream stages
    (Threat Intelligence, Investigation, Reporting). Confirms a rerun
    resets the target stage to "Processing", clears/invalidates every
    stage AFTER it (result JSON -> None, status -> "Pending"), never
    touches stages before it, and is rejected while the target stage is
    already Processing or while a fresh run is already in flight.
Main functionalities: Drives workflow_state_store (wss) functions
    directly against an isolated SQLite DB — start_run(), _guarded_update()
    (test-only direct state seeding), approve_triage()/approve_investigation(),
    commit_reporting_approval(), rerun_stage() — and asserts the resulting
    state via get_state().
Inputs: An isolated tmp_path SQLite file (wss.DB_FILE, monkeypatched); no
    real soc_db/ is touched. Incident id "INC-1" throughout; states are
    hand-seeded with wss._guarded_update() rather than by running real
    stage logic, since this file is only exercising the rerun/state-machine
    contract in workflow_state_store.py, not the stages themselves.
Outputs: Assertions on the dict returned by wss.get_state() after each
    rerun_stage()/approve_*() call, and on exceptions
    (wss.ApprovalConflictError, wss.WorkflowAlreadyRunningError) raised by
    invalid rerun/start attempts.
Workflow position: Cross-stage state-machine contract for
    workflow_state_store.py's rerun/downstream-invalidation logic — see
    also tests/test_investigation_stage.py and
    tests/test_threat_intel_workflow.py, which test rerun_stage() together
    with the real stage-execution functions in soc_workflow.py rather than
    in isolation.
Called by: Executed by pytest, or by running
    `python -m pytest tests/test_stage_rerun.py`.
Calls: workflow_state_store (wss) — start_run(), _guarded_update(),
    approve_triage(), approve_investigation(), commit_reporting_approval(),
    rerun_stage(), get_state(), db_init(); exception classes
    ApprovalConflictError, WorkflowAlreadyRunningError.
Key evaluator search terms: rerun_stage, downstream invalidation, stage
    rerun, ApprovalConflictError, WorkflowAlreadyRunningError,
    reporting_status Pending, workflow state machine.
[/FYP-FILE]
"""
from __future__ import annotations

import json

import pytest

from workflow import state_store as wss


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] Fixtures and state-seeding helpers
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """[FYP-FUNCTION] Isolate every test to its own tmp_path SQLite file so
    no test reads/writes the real soc_db/ database."""
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "rerun.db")
    wss.db_init()


def _run_with_approved_triage(incident_id: str = "INC-1") -> str:
    """[FYP-FUNCTION] Test helper (not itself a test). Starts a run and
    fast-forwards it, via direct DB seeding + the real approve_triage(),
    to "Triage Approved" — the common starting point every test below
    builds on."""
    run_id = wss.start_run(incident_id)
    wss._guarded_update(incident_id, run_id, {
        "parsing_status": "Complete",
        "triage_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval",
        "approval_stage": "triage",
    })
    wss.approve_triage(incident_id, run_id, approved_by="analyst")
    return run_id


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] rerun_stage() resets the target stage and invalidates
# everything downstream of it, while leaving upstream stages untouched
# ══════════════════════════════════════════════════════════════════════════

def test_rerun_threat_intel_restarts_stage_and_invalidates_downstream():
    """[FYP-FUNCTION] Validates workflow_state_store.rerun_stage() for the
    "threat_intel" target: a completed run (Threat Intel/Investigation/
    Reporting all Complete-or-later) is rerun from Threat Intelligence.
    Asserts threat_intel_status resets to "Processing" with its result JSON
    cleared, both downstream stages (investigation, reporting) drop to
    "Pending" with their result JSON cleared, and workflow_status becomes
    "Processing" again.
    """
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
    """[FYP-FUNCTION] Validates workflow_state_store.rerun_stage() for the
    "investigation" target: after Investigation was already approved and
    Reporting moved to "Awaiting Approval", rerunning Investigation must
    reset investigation_status to "Processing" and invalidate
    reporting_status back to "Pending". Also confirms the stage remains
    approvable afterward — re-seeding "Awaiting Approval" and calling
    approve_investigation() again succeeds and lands on "Approved", proving
    the rerun fully cleared the prior approval rather than leaving stale
    state that would block re-approval.
    """
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
    """[FYP-FUNCTION] Validates workflow_state_store.rerun_stage() for the
    "reporting" target — the last stage, so there is nothing downstream to
    invalidate. Commits a real reporting approval via
    commit_reporting_approval() first, then reruns Reporting. Asserts
    reporting_status resets to "Processing", workflow_status returns to
    "Processing" (reopening what had been a completed workflow), and
    approval_stage is cleared back to None.
    """
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


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] Guards that stop a rerun from clobbering a run that is
# already in flight
# ══════════════════════════════════════════════════════════════════════════

# [FYP-RERUN] [FYP-EVALUATOR]
def test_duplicate_rerun_is_rejected_while_stage_is_processing():
    """[FYP-FUNCTION] Validates workflow_state_store.rerun_stage() refuses a
    second rerun of the same stage while the first rerun's "Processing"
    state is still live. Asserts the second rerun_stage("threat_intel")
    call raises wss.ApprovalConflictError instead of silently restarting an
    already-restarting stage.
    """
    run_id = _run_with_approved_triage()
    wss._guarded_update("INC-1", run_id, {
        "threat_intel_status": "Complete",
        "workflow_status": "Awaiting Approval",
    })
    wss.rerun_stage("INC-1", run_id, "threat_intel")

    with pytest.raises(wss.ApprovalConflictError):
        wss.rerun_stage("INC-1", run_id, "threat_intel")


def test_fresh_rerun_cannot_replace_a_run_that_is_already_processing():
    """[FYP-FUNCTION] Validates workflow_state_store.start_run() (the
    "retry from scratch" path used when no prior run exists to target with
    rerun_stage()) refuses to start a new run for an incident whose
    existing run is still Processing. Asserts start_run(..., allow_retry=True)
    raises wss.WorkflowAlreadyRunningError rather than starting a
    second, concurrent run for the same incident.
    """
    wss.start_run("INC-1")

    with pytest.raises(wss.WorkflowAlreadyRunningError):
        wss.start_run("INC-1", allow_retry=True)
