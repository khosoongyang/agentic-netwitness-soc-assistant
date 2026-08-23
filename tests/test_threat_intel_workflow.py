# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, ast, datetime, json, pathlib, pytest, soc_workflow, threat_intel.
# =============================================================================
# File: tests/test_threat_intel_workflow.py
# Purpose: This module implements test and validation behaviour for test threat intel workflow.
# Main functionality: _isolated_db, _triage_result, _incident, _start_and_reach_triage_approval, _approve_triage, _save_raw_incident.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis test and validation component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, ast, datetime, json, pathlib, pytest, soc_workflow, threat_intel.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: _isolated_db, _triage_result, _incident, _start_and_reach_triage_approval, _approve_triage, _save_raw_incident, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

"""
tests/test_threat_intel_workflow.py — Threat Intelligence Enrichment stage:
durable resume, atomic stage claims/leases, the new VirusTotal/AbuseIPDB/
AlienVault OTX engine (threat_intel.py), and the full Triage -> Threat
Intelligence -> Investigation -> Reporting approval chain.

All HTTP is mocked (unittest.mock.patch("requests.get", ...)) — no live
external API calls. workflow_state_store.DB_FILE and
soc_workflow._TRUSTED_OUTPUT_ROOT are monkeypatched to a tmp_path per test
so tests never touch the real soc_db/ or outputs/ directories.
"""
from __future__ import annotations

import ast
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

import workflow_state_store as wss
import soc_workflow as sw
import threat_intel as ti


ROOT = Path(__file__).resolve().parent.parent


# ══════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════

# =============================================================================
# [FYP-SECTION] TEST SETUP, FIXTURES, AND ASSERTIONS
# =============================================================================

# [FYP-FUNCTION] `_isolated_db` — implements the isolated db operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `tmp_path`, `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Yields values to its iterator consumer; any state/file/database effects are visible in the body.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `db_init`, `setattr`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """Every test gets its own SQLite file and its own trusted artifact
    root — never touches the real soc_db/ or outputs/ directories."""
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "test_incidents.db")
    monkeypatch.setattr(sw, "_TRUSTED_OUTPUT_ROOT", tmp_path / "artifacts")
    wss.db_init()
    yield


# [FYP-FUNCTION] `_triage_result` — implements the triage result operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `incident_id`, `**ticket_overrides`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include eval_harness.py:run_evals, tests/test_investigation_stage.py:_run_to_investigation_processing, tests/test_investigation_stage.py:test_build_case_view_never_calls_investigation_stage_functions; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `update`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _triage_result(incident_id: str, **ticket_overrides) -> dict:
    ticket = {"incident_id": incident_id, "unc": "#001", "classification": "high"}
    ticket.update(ticket_overrides)
    return {"ticket": ticket,
           "metakeys_payload": {"incident_id": incident_id, "metakey_values": {}}}


# [FYP-FUNCTION] `_incident` — implements the incident operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `incident_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tests/test_investigation_stage.py:test_build_case_view_never_calls_investigation_stage_functions, tests/test_investigation_stage.py:test_entity_graph_never_labels_cooccurrence_as_connected_to, tests/test_investigation_stage.py:test_host_and_user_never_derived_from_narrative_prose; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: no nested function/service calls.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _incident(incident_id: str = "INC-1") -> dict:
    return {"id": incident_id, "title": "Test incident", "alertMeta": {}}


# [FYP-FUNCTION] `_start_and_reach_triage_approval` — orchestrates the start and reach triage approval entry point and its ordered test and validation operations.
# [FYP-INPUT] Parameters: `incident_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tests/test_threat_intel_workflow.py:test_approval_history_rows_cannot_be_duplicated, tests/test_threat_intel_workflow.py:test_approve_triage_unlocks_but_does_not_start_threat_intel, tests/test_threat_intel_workflow.py:test_begin_stage_starts_threat_intel_exactly_once_after_approval; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_guarded_update`, `_triage_result`, `save_triage_result`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _start_and_reach_triage_approval(incident_id: str = "INC-1") -> str:
    """Fresh run, straight to 'Awaiting Approval / triage' — the state
    approve_triage() requires."""
    run_id = wss.start_run(incident_id)
    wss.save_triage_result(incident_id, run_id, _triage_result(incident_id))
    wss._guarded_update(incident_id, run_id, {
        "triage_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval",
        "approval_stage": "triage",
    })
    return run_id


# [FYP-FUNCTION] `_approve_triage` — applies the human-in-the-loop approve triage decision and returns or persists the resulting workflow state.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include tests/test_threat_intel_workflow.py:test_approval_history_rows_cannot_be_duplicated, tests/test_threat_intel_workflow.py:test_duplicate_approve_click_raises_conflict, tests/test_threat_intel_workflow.py:test_expired_lease_permits_new_worker_to_resume; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `approve_triage`, `begin_stage`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _approve_triage(incident_id: str, run_id: str) -> None:
    """Approve Triage AND start Threat Intelligence — mirrors the real
    two-step UI flow (Approve unlocks it Pending; a separate Start
    Process click calls begin_stage() to flip it to Processing). Most
    tests below only care about exercising Threat Intelligence itself,
    not the approve/begin_stage boundary, so this helper folds both
    steps together; see test_approve_triage_unlocks_but_does_not_start_*
    for tests of that boundary in isolation."""
    wss.approve_triage(incident_id, run_id, approved_by="tester")
    wss.begin_stage(incident_id, run_id, "threat_intel")


# [FYP-FUNCTION] `_save_raw_incident` — persists or updates save raw incident state used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `incident`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include tests/test_threat_intel_workflow.py:test_full_incident_reloadable_after_session_loss, tests/test_threat_intel_workflow.py:test_investigation_completion_is_awaiting_approval_not_complete, tests/test_threat_intel_workflow.py:test_investigation_failure_persists_actionable_last_error; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_incident`, `_save_run_artifact`, `save_raw_incident_path`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _save_raw_incident(incident_id: str, run_id: str, incident: dict | None = None) -> None:
    path = sw._save_run_artifact(incident_id, run_id, "raw_incident.json",
                                 "raw_incident", incident or _incident(incident_id))
    wss.save_raw_incident_path(incident_id, run_id, str(path))


# [FYP-FUNCTION] `_mock_all_ti_keys_absent` — implements the mock all ti keys absent operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include tests/test_threat_intel_workflow.py:test_investigation_receives_persisted_threat_intel_result, tests/test_threat_intel_workflow.py:test_missing_api_keys_produce_warnings_not_fabricated_results, tests/test_threat_intel_workflow.py:test_missing_key_warning_only_fires_for_applicable_provider; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `delenv`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _mock_all_ti_keys_absent(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)


# ══════════════════════════════════════════════════════════════════════════
# Approval atomicity
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_approve_triage_unlocks_but_does_not_start_threat_intel` — verifies approve triage unlocks but does not start threat intel behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_start_and_reach_triage_approval`, `approve_triage`, `get_state`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_approve_triage_unlocks_but_does_not_start_threat_intel():
    """Approving Triage must only save the decision and unlock Threat
    Intelligence (left "Pending") — it must never itself start it. That
    is a separate, explicit action (begin_stage()), fired only when the
    analyst clicks Threat Intelligence's own Start Process button."""
    run_id = _start_and_reach_triage_approval("INC-1")
    wss.approve_triage("INC-1", run_id, approved_by="tester")
    state = wss.get_state("INC-1")
    assert state["triage_status"] == "Approved"
    assert state["threat_intel_status"] == "Pending"
    assert state["workflow_status"] == "Awaiting Action"
    assert state["approval_stage"] is None


# [FYP-FUNCTION] `test_begin_stage_starts_threat_intel_exactly_once_after_approval` — verifies begin stage starts threat intel exactly once after approval behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_start_and_reach_triage_approval`, `approve_triage`, `begin_stage`, `get_state`, `raises`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_begin_stage_starts_threat_intel_exactly_once_after_approval():
    run_id = _start_and_reach_triage_approval("INC-1")
    wss.approve_triage("INC-1", run_id, approved_by="tester")
    wss.begin_stage("INC-1", run_id, "threat_intel")
    state = wss.get_state("INC-1")
    assert state["threat_intel_status"] == "Processing"
    assert state["workflow_status"] == "Processing"
    with pytest.raises(wss.ApprovalConflictError):
        wss.begin_stage("INC-1", run_id, "threat_intel")


# [FYP-FUNCTION] `test_begin_stage_refuses_a_stage_that_was_never_unlocked` — verifies begin stage refuses a stage that was never unlocked behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_guarded_update`, `begin_stage`, `raises`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_begin_stage_refuses_a_stage_that_was_never_unlocked():
    """Threat Intelligence cannot be started before Triage is Approved —
    begin_stage() must check the upstream precondition itself, not just
    the target stage's own "Pending" status."""
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {"workflow_status": "Awaiting Action"})
    with pytest.raises(wss.ApprovalConflictError):
        wss.begin_stage("INC-1", run_id, "threat_intel")


# [FYP-FUNCTION] `test_duplicate_approve_click_raises_conflict` — verifies duplicate approve click raises conflict behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_start_and_reach_triage_approval`, `raises`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_duplicate_approve_click_raises_conflict():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    with pytest.raises(wss.ApprovalConflictError):
        _approve_triage("INC-1", run_id)


# [FYP-FUNCTION] `test_approval_history_rows_cannot_be_duplicated` — verifies approval history rows cannot be duplicated behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_start_and_reach_triage_approval`, `db_connect`, `execute`, `fetchall`, `len`, `raises`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_approval_history_rows_cannot_be_duplicated():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    with pytest.raises(wss.ApprovalConflictError):
        _approve_triage("INC-1", run_id)
    with wss.db_connect() as con:
        rows = con.execute(
            "SELECT * FROM workflow_approvals WHERE incident_id=? AND run_id=? "
            "AND approval_stage='triage'", ("INC-1", run_id)).fetchall()
    assert len(rows) == 1


# [FYP-FUNCTION] `test_rejection_is_atomic_and_blocks_downstream_stage` — verifies rejection is atomic and blocks downstream stage behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_start_and_reach_triage_approval`, `get_state`, `raises`, `reject_triage`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_rejection_is_atomic_and_blocks_downstream_stage():
    run_id = _start_and_reach_triage_approval("INC-1")
    wss.reject_triage("INC-1", run_id, rejected_by="tester", reason="not real")
    state = wss.get_state("INC-1")
    assert state["triage_status"] == "Rejected"
    assert state["threat_intel_status"] == "Blocked"
    assert state["workflow_status"] == "Rejected"
    with pytest.raises(wss.ApprovalConflictError):
        wss.reject_triage("INC-1", run_id, rejected_by="tester", reason="again")


# [FYP-FUNCTION] `test_investigation_approval_unlocks_but_does_not_start_reporting` — verifies investigation approval unlocks but does not start reporting behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_guarded_update`, `approve_investigation`, `get_state`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_investigation_approval_unlocks_but_does_not_start_reporting():
    """Approving Investigation must only unlock Reporting (left
    "Pending"), never start it — and must never jump straight to
    workflow_status "Complete" either; only commit_reporting_approval()
    may ever set that."""
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {
        "workflow_status": "Awaiting Approval", "approval_stage": "investigation",
        "investigation_status": "Awaiting Approval"})
    wss.approve_investigation("INC-1", run_id, approved_by="tester")
    state = wss.get_state("INC-1")
    assert state["investigation_status"] == "Approved"
    assert state["reporting_status"] == "Pending"
    assert state["workflow_status"] == "Awaiting Action"
    assert state["workflow_status"] != "Complete"


# [FYP-FUNCTION] `test_begin_stage_starts_reporting_after_investigation_approval` — verifies begin stage starts reporting after investigation approval behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_guarded_update`, `approve_investigation`, `begin_stage`, `get_state`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_begin_stage_starts_reporting_after_investigation_approval():
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {
        "workflow_status": "Awaiting Approval", "approval_stage": "investigation",
        "investigation_status": "Awaiting Approval"})
    wss.approve_investigation("INC-1", run_id, approved_by="tester")
    wss.begin_stage("INC-1", run_id, "reporting")
    state = wss.get_state("INC-1")
    assert state["reporting_status"] == "Processing"
    assert state["workflow_status"] == "Processing"


# [FYP-FUNCTION] `test_reporting_approval_is_required_for_workflow_complete` — verifies reporting approval is required for workflow complete behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_guarded_update`, `commit_reporting_approval`, `get_state`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_reporting_approval_is_required_for_workflow_complete():
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {
        "workflow_status": "Awaiting Approval", "approval_stage": "reporting",
        "reporting_status": "Awaiting Approval"})
    assert wss.get_state("INC-1")["workflow_status"] != "Complete"
    _state = wss.get_state("INC-1")
    wss.commit_reporting_approval(
        "INC-1", run_id,
        expected_reporting_attempt=_state["reporting_attempt"],
        expected_reporting_result_json=_state["reporting_result_json"],
        metadata={}, approved_by="tester")
    state = wss.get_state("INC-1")
    assert state["reporting_status"] == "Approved"
    assert state["workflow_status"] == "Complete"


# [FYP-FUNCTION] `test_triage_approval_retained_after_investigation_approval` — verifies triage approval retained after investigation approval behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_guarded_update`, `_start_and_reach_triage_approval`, `approve_investigation`, `db_connect`, `execute`, `fetchone`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_triage_approval_retained_after_investigation_approval():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    wss._guarded_update("INC-1", run_id, {
        "workflow_status": "Awaiting Approval", "approval_stage": "investigation",
        "investigation_status": "Awaiting Approval"})
    wss.approve_investigation("INC-1", run_id, approved_by="tester2")
    with wss.db_connect() as con:
        triage_row = con.execute(
            "SELECT * FROM workflow_approvals WHERE incident_id=? AND run_id=? "
            "AND approval_stage='triage'", ("INC-1", run_id)).fetchone()
        inv_row = con.execute(
            "SELECT * FROM workflow_approvals WHERE incident_id=? AND run_id=? "
            "AND approval_stage='investigation'", ("INC-1", run_id)).fetchone()
    assert triage_row is not None and triage_row["decision"] == "approved"
    assert inv_row is not None and inv_row["decision"] == "approved"


# [FYP-FUNCTION] `test_approval_functions_do_not_start_threads_or_import_soc_workflow` — verifies approval functions do not start threads or import soc workflow behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `any`, `isinstance`, `parse`, `read_text`, `walk`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_approval_functions_do_not_start_threads_or_import_soc_workflow():
    src = (ROOT / "workflow" / "state_store.py").read_text(encoding="utf-8")
    assert "threading.Thread" not in src
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any(a.name in ("soc_workflow", "workflow.engine") for a in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module not in ("soc_workflow", "workflow.engine")


# [FYP-FUNCTION] `test_worker_never_touches_streamlit` — verifies worker never touches streamlit behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `any`, `isinstance`, `parse`, `read_text`, `walk`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_worker_never_touches_streamlit():
    src = (ROOT / "workflow" / "engine.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any(a.name == "streamlit" for a in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module != "streamlit"


# ══════════════════════════════════════════════════════════════════════════
# Stage claim / lease
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_two_resume_actions_cannot_claim_the_same_stage` — verifies two resume actions cannot claim the same stage behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_start_and_reach_triage_approval`, `claim_stage`, `raises`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_two_resume_actions_cannot_claim_the_same_stage():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    sw.claim_stage("INC-1", run_id, stage="threat_intel",
                   status_column="threat_intel_status", expect_status="Processing")
    with pytest.raises(sw.StageClaimError):
        sw.claim_stage("INC-1", run_id, stage="threat_intel",
                       status_column="threat_intel_status", expect_status="Processing")


# [FYP-FUNCTION] `test_expired_lease_permits_new_worker_to_resume` — verifies expired lease permits new worker to resume behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_start_and_reach_triage_approval`, `claim_stage`, `commit`, `db_connect`, `execute`, `isoformat`, `now`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_expired_lease_permits_new_worker_to_resume():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    worker_a, _ = sw.claim_stage("INC-1", run_id, stage="threat_intel",
                                 status_column="threat_intel_status",
                                 expect_status="Processing")
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with wss.db_connect() as con:
        con.execute("UPDATE incidents SET worker_lease_expires_at=? WHERE id=?",
                   (past, "INC-1"))
        con.commit()
    worker_b, _ = sw.claim_stage("INC-1", run_id, stage="threat_intel",
                                 status_column="threat_intel_status",
                                 expect_status="Processing")
    assert worker_b != worker_a


# [FYP-FUNCTION] `test_valid_heartbeat_prevents_false_interrupted_warning` — verifies valid heartbeat prevents false interrupted warning behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_start_and_reach_triage_approval`, `claim_stage`, `fromisoformat`, `get_state`, `now`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_valid_heartbeat_prevents_false_interrupted_warning():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    sw.claim_stage("INC-1", run_id, stage="threat_intel",
                   status_column="threat_intel_status", expect_status="Processing")
    state = wss.get_state("INC-1")
    lease = state["worker_lease_expires_at"]
    assert lease and datetime.fromisoformat(lease) > datetime.now(timezone.utc)


# [FYP-FUNCTION] `test_worker_that_loses_lease_cannot_save_result` — verifies worker that loses lease cannot save result behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_start_and_reach_triage_approval`, `claim_stage`, `commit`, `complete_stage`, `db_connect`, `execute`, `get_state`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_worker_that_loses_lease_cannot_save_result():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    worker_a, _ = sw.claim_stage("INC-1", run_id, stage="threat_intel",
                                 status_column="threat_intel_status",
                                 expect_status="Processing")
    # Simulate the lease being reassigned to a different worker/stage.
    with wss.db_connect() as con:
        con.execute("UPDATE incidents SET worker_id=?, worker_stage=? WHERE id=?",
                   ("someone-else", "threat_intel", "INC-1"))
        con.commit()
    ok = sw.complete_stage(
        "INC-1", run_id, worker_a, stage="threat_intel",
        result_column="threat_intel_result_json", result={"status": "completed"},
        status_updates={"threat_intel_status": "Complete"})
    assert ok is False
    state = wss.get_state("INC-1")
    assert state["threat_intel_status"] == "Processing"  # untouched by the stale worker


# [FYP-FUNCTION] `test_late_worker_cannot_overwrite_newer_worker_result` — verifies late worker cannot overwrite newer worker result behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_start_and_reach_triage_approval`, `claim_stage`, `commit`, `complete_stage`, `db_connect`, `execute`, `get_state`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_late_worker_cannot_overwrite_newer_worker_result():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    worker_a, _ = sw.claim_stage("INC-1", run_id, stage="threat_intel",
                                 status_column="threat_intel_status",
                                 expect_status="Processing")
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with wss.db_connect() as con:
        con.execute("UPDATE incidents SET worker_lease_expires_at=? WHERE id=?",
                   (past, "INC-1"))
        con.commit()
    worker_b, _ = sw.claim_stage("INC-1", run_id, stage="threat_intel",
                                 status_column="threat_intel_status",
                                 expect_status="Processing")
    ok_b = sw.complete_stage(
        "INC-1", run_id, worker_b, stage="threat_intel",
        result_column="threat_intel_result_json", result={"status": "completed", "marker": "B"},
        status_updates={"threat_intel_status": "Complete", "investigation_status": "Processing",
                        "workflow_status": "Processing"})
    assert ok_b is True
    ok_a = sw.complete_stage(
        "INC-1", run_id, worker_a, stage="threat_intel",
        result_column="threat_intel_result_json", result={"status": "completed", "marker": "A"},
        status_updates={"threat_intel_status": "Complete"})
    assert ok_a is False
    saved = json.loads(wss.get_state("INC-1")["threat_intel_result_json"])
    assert saved["marker"] == "B"


# [FYP-FUNCTION] `test_stage_result_and_status_transition_are_committed_atomically` — verifies stage result and status transition are committed atomically behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_start_and_reach_triage_approval`, `claim_stage`, `complete_stage`, `get_state`, `object`, `raises`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_stage_result_and_status_transition_are_committed_atomically():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    worker_id, _ = sw.claim_stage("INC-1", run_id, stage="threat_intel",
                                  status_column="threat_intel_status",
                                  expect_status="Processing")

    real_tx = wss._tx

    # [FYP-FUNCTION] `_boom` — implements the boom operation used by the surrounding test and validation workflow.
    # [FYP-INPUT] Parameters: `fn`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `real_tx`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _boom(fn):
        # [FYP-FUNCTION] `_wrapped` — implements the wrapped operation used by the surrounding test and validation workflow.
        # [FYP-INPUT] Parameters: `con`; values come from its direct caller, route, UI event, fixture, or stage handoff.
        # [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
        # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
        # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
        # [FYP-CALLS] Calls: `RuntimeError`, `fn`.
        # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

        def _wrapped(con):
            fn(con)
            raise RuntimeError("simulated crash after UPDATE, before COMMIT")
        return real_tx(_wrapped)

    with patch.object(wss, "_tx", side_effect=_boom):
        with pytest.raises(RuntimeError):
            sw.complete_stage(
                "INC-1", run_id, worker_id, stage="threat_intel",
                result_column="threat_intel_result_json", result={"status": "completed"},
                status_updates={"threat_intel_status": "Complete"})
    state = wss.get_state("INC-1")
    # Rolled back entirely — status untouched, no partial write.
    assert state["threat_intel_status"] == "Processing"
    assert state["threat_intel_result_json"] in (None, "")


# ══════════════════════════════════════════════════════════════════════════
# Artifact envelope / atomic writes
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_full_incident_reloadable_after_session_loss` — verifies full incident reloadable after session loss behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_incident`, `_save_raw_incident`, `load_raw_incident_for_run`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_full_incident_reloadable_after_session_loss():
    run_id = wss.start_run("INC-1")
    incident = _incident("INC-1")
    _save_raw_incident("INC-1", run_id, incident)
    # "session loss" — nothing but incident_id/run_id survives.
    reloaded = sw.load_raw_incident_for_run("INC-1", run_id)
    assert reloaded == incident


# [FYP-FUNCTION] `test_raw_incident_artifact_rejects_mismatched_run_id` — verifies raw incident artifact rejects mismatched run id behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_save_raw_incident`, `load_raw_incident_for_run`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_raw_incident_artifact_rejects_mismatched_run_id():
    run_id = wss.start_run("INC-1")
    _save_raw_incident("INC-1", run_id)
    assert sw.load_raw_incident_for_run("INC-1", "some-other-run-id") is None


# [FYP-FUNCTION] `test_partially_written_artifact_is_never_loaded` — verifies partially written artifact is never loaded behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_artifact_dir`, `_save_raw_incident`, `glob`, `list`, `load_raw_incident_for_run`, `mkdir`, `save_raw_incident_path`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_partially_written_artifact_is_never_loaded(tmp_path):
    run_id = wss.start_run("INC-1")
    target_dir = sw._artifact_dir("INC-1", run_id)
    target_dir.mkdir(parents=True, exist_ok=True)
    bad_path = target_dir / "raw_incident.json"
    bad_path.write_text('{"incident_id": "INC-1", "run_id": "' + run_id + '", "payload": ',
                        encoding="utf-8")   # truncated / invalid JSON
    wss.save_raw_incident_path("INC-1", run_id, str(bad_path))
    assert sw.load_raw_incident_for_run("INC-1", run_id) is None

    # And the real writer never leaves a stray temp file behind.
    _save_raw_incident("INC-1", run_id)
    tmp_leftovers = list(target_dir.glob(".*tmp*"))
    assert tmp_leftovers == []


# ══════════════════════════════════════════════════════════════════════════
# Durable resume / new-process resume / dispatcher correctness
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_resume_after_triage_approval_survives_fresh_state_reload` — verifies resume after triage approval survives fresh state reload behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_mock_all_ti_keys_absent`, `_save_raw_incident`, `_start_and_reach_triage_approval`, `get_state`, `resume_after_triage_approval`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_resume_after_triage_approval_survives_fresh_state_reload(monkeypatch):
    _mock_all_ti_keys_absent(monkeypatch)
    run_id = _start_and_reach_triage_approval("INC-1")
    _save_raw_incident("INC-1", run_id)
    _approve_triage("INC-1", run_id)
    result = sw.resume_after_triage_approval("INC-1", run_id)
    assert result["status"] in ("completed", "completed_with_warnings")
    state = wss.get_state("INC-1")
    assert state["threat_intel_status"] in ("Complete", "Complete with Warnings")
    assert state["investigation_status"] == "Processing"


# [FYP-FUNCTION] `test_new_process_can_resume_using_only_persisted_state` — verifies new process can resume using only persisted state behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_mock_all_ti_keys_absent`, `_save_raw_incident`, `_start_and_reach_triage_approval`, `resume_after_triage_approval`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_new_process_can_resume_using_only_persisted_state(monkeypatch):
    """Simulates a fresh process: only incident_id/run_id are known, no
    shared in-memory object from the approval call."""
    _mock_all_ti_keys_absent(monkeypatch)
    run_id = _start_and_reach_triage_approval("INC-1")
    _save_raw_incident("INC-1", run_id)
    _approve_triage("INC-1", run_id)
    incident_id, run_id_copy = "INC-1", str(run_id)
    del run_id
    result = sw.resume_after_triage_approval(incident_id, run_id_copy)
    assert result["status"] in ("completed", "completed_with_warnings")


# [FYP-FUNCTION] `test_resume_rejects_stale_run_id` — verifies resume rejects stale run id behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_mock_all_ti_keys_absent`, `_start_and_reach_triage_approval`, `raises`, `resume_after_triage_approval`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_resume_rejects_stale_run_id(monkeypatch):
    _mock_all_ti_keys_absent(monkeypatch)
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    # The run_id/status guard lives in _claim_stage() (raises StageClaimError) —
    # ThreatIntelValidationError is reserved for a triage_result whose OWN
    # embedded incident_id doesn't match (see
    # test_threat_intel_validation_error_on_incident_id_mismatch). Both close
    # the same "never resume a stale/mismatched run" requirement.
    with pytest.raises(sw.StageClaimError):
        sw.resume_after_triage_approval("INC-1", "stale-run-id")


# [FYP-FUNCTION] `test_threat_intel_validation_error_on_incident_id_mismatch` — verifies threat intel validation error on incident id mismatch behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_triage_result`, `raises`, `run_threat_intel`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_threat_intel_validation_error_on_incident_id_mismatch():
    mismatched_triage = _triage_result("INC-OTHER")
    with pytest.raises(sw.ThreatIntelValidationError):
        sw.run_threat_intel(incident_id="INC-1", run_id="r1",
                            normalised_alert=None, triage_result=mismatched_triage)


# [FYP-FUNCTION] `test_resume_dispatches_directly_to_investigation_when_threat_intel_already_complete` — verifies resume dispatches directly to investigation when threat intel already complete behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `AssertionError`, `Mock`, `_guarded_update`, `assert_called_once_with`, `assert_not_called`, `run_stage_chain`, `setattr`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_resume_dispatches_directly_to_investigation_when_threat_intel_already_complete(monkeypatch):
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {
        "threat_intel_status": "Complete", "investigation_status": "Processing",
        "workflow_status": "Processing"})
    fake_resume = Mock(side_effect=AssertionError("must not be called"))
    fake_inv_stage = Mock(return_value={"status": "awaiting_approval"})
    monkeypatch.setattr(sw, "resume_after_triage_approval", fake_resume)
    monkeypatch.setattr(sw, "run_investigation_stage", fake_inv_stage)
    sw.run_stage_chain("INC-1", run_id)
    fake_resume.assert_not_called()
    fake_inv_stage.assert_called_once_with("INC-1", run_id)


# [FYP-FUNCTION] `test_resume_dispatches_directly_to_reporting_when_investigation_already_approved` — verifies resume dispatches directly to reporting when investigation already approved behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `AssertionError`, `Mock`, `_guarded_update`, `assert_called_once_with`, `assert_not_called`, `run_stage_chain`, `setattr`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_resume_dispatches_directly_to_reporting_when_investigation_already_approved(monkeypatch):
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {
        "threat_intel_status": "Complete", "investigation_status": "Approved",
        "reporting_status": "Processing", "workflow_status": "Processing"})
    fake_resume = Mock(side_effect=AssertionError("must not be called"))
    fake_inv_stage = Mock(side_effect=AssertionError("must not be called"))
    fake_rep_stage = Mock(return_value={"status": "awaiting_approval"})
    monkeypatch.setattr(sw, "resume_after_triage_approval", fake_resume)
    monkeypatch.setattr(sw, "run_investigation_stage", fake_inv_stage)
    monkeypatch.setattr(sw, "run_reporting_stage", fake_rep_stage)
    sw.run_stage_chain("INC-1", run_id)
    fake_resume.assert_not_called()
    fake_inv_stage.assert_not_called()
    fake_rep_stage.assert_called_once_with("INC-1", run_id)


# [FYP-FUNCTION] `test_worker_start_grace_period_suppresses_false_interruption` — verifies worker start grace period suppresses false interruption behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `fromisoformat`, `isoformat`, `now`, `timedelta`, `total_seconds`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_worker_start_grace_period_suppresses_false_interruption():
    now = datetime.now(timezone.utc)
    row_starting = {"workflow_status": "Processing",
                   "workflow_updated_at": now.isoformat(),
                   "worker_lease_expires_at": None}
    grace_seconds = 15
    updated = datetime.fromisoformat(row_starting["workflow_updated_at"])
    age = (datetime.now(timezone.utc) - updated).total_seconds()
    assert age < grace_seconds   # "starting", not "interrupted"

    stale_updated = (now - timedelta(seconds=grace_seconds + 5)).isoformat()
    age_stale = (datetime.now(timezone.utc)
                - datetime.fromisoformat(stale_updated)).total_seconds()
    assert age_stale >= grace_seconds   # now legitimately "interrupted"


# [FYP-FUNCTION] `test_frontend_polling_stops_at_approval_or_terminal_state` — verifies frontend polling stops at approval or terminal state behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: no nested function/service calls.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_frontend_polling_stops_at_approval_or_terminal_state():
    for terminal in ("Awaiting Approval", "Failed", "Rejected", "Complete"):
        assert terminal != "Processing"   # the polling loop's only trigger condition


# ══════════════════════════════════════════════════════════════════════════
# Failure handling
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_unexpected_worker_exception_sets_failed_and_blocked` — verifies unexpected worker exception sets failed and blocked behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `Mock`, `RuntimeError`, `_approve_triage`, `_save_raw_incident`, `_start_and_reach_triage_approval`, `get_state`, `resume_after_triage_approval`, `setattr`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_unexpected_worker_exception_sets_failed_and_blocked(monkeypatch):
    run_id = _start_and_reach_triage_approval("INC-1")
    _save_raw_incident("INC-1", run_id)
    _approve_triage("INC-1", run_id)
    monkeypatch.setattr(sw, "run_threat_intel",
                        Mock(side_effect=RuntimeError("boom")))
    result = sw.resume_after_triage_approval("INC-1", run_id)
    assert result["status"] == "failed"
    state = wss.get_state("INC-1")
    assert state["threat_intel_status"] == "Failed"
    assert state["investigation_status"] == "Blocked"
    assert state["workflow_status"] == "Failed"
    assert state["last_error"]


# [FYP-FUNCTION] `test_full_failure_blocks_investigation` — verifies full failure blocks investigation behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_start_and_reach_triage_approval`, `get_state`, `raises`, `resume_after_triage_approval`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_full_failure_blocks_investigation(monkeypatch):
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    with pytest.raises(sw.StageClaimError):
        sw.resume_after_triage_approval("INC-1", "wrong-run-id")
    # A genuinely bad call never reaches Investigation.
    assert wss.get_state("INC-1")["investigation_status"] == "Pending"


# ══════════════════════════════════════════════════════════════════════════
# Retry
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_retry_threat_intel_reruns_only_threat_intel_then_investigation` — verifies retry threat intel reruns only threat intel then investigation behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `Mock`, `_approve_triage`, `_mock_all_ti_keys_absent`, `_save_raw_incident`, `_start_and_reach_triage_approval`, `assert_called_once_with`, `commit`, `db_connect`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_retry_threat_intel_reruns_only_threat_intel_then_investigation(monkeypatch):
    run_id = _start_and_reach_triage_approval("INC-1")
    _save_raw_incident("INC-1", run_id)
    _approve_triage("INC-1", run_id)
    with wss.db_connect() as con:
        con.execute("UPDATE incidents SET threat_intel_status='Failed', "
                   "investigation_status='Blocked', workflow_status='Failed' WHERE id=?",
                   ("INC-1",))
        con.commit()

    fake_run_investigation_stage = Mock(return_value={"status": "awaiting_approval"})
    monkeypatch.setattr(sw, "run_investigation_stage", fake_run_investigation_stage)
    _mock_all_ti_keys_absent(monkeypatch)

    wss.retry_threat_intel("INC-1", run_id)
    sw.run_stage_chain("INC-1", run_id)

    state = wss.get_state("INC-1")
    assert state["threat_intel_status"] in ("Complete", "Complete with Warnings")
    fake_run_investigation_stage.assert_called_once_with("INC-1", run_id)


# [FYP-FUNCTION] `test_retry_continues_to_investigation_exactly_once` — verifies retry continues to investigation exactly once behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `Mock`, `_approve_triage`, `_mock_all_ti_keys_absent`, `_save_raw_incident`, `_start_and_reach_triage_approval`, `commit`, `db_connect`, `execute`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_retry_continues_to_investigation_exactly_once(monkeypatch):
    run_id = _start_and_reach_triage_approval("INC-1")
    _save_raw_incident("INC-1", run_id)
    _approve_triage("INC-1", run_id)
    with wss.db_connect() as con:
        con.execute("UPDATE incidents SET threat_intel_status='Failed' WHERE id=?", ("INC-1",))
        con.commit()
    fake_inv = Mock(return_value={"status": "awaiting_approval"})
    monkeypatch.setattr(sw, "run_investigation_stage", fake_inv)
    _mock_all_ti_keys_absent(monkeypatch)

    wss.retry_threat_intel("INC-1", run_id)
    sw.run_stage_chain("INC-1", run_id)
    assert fake_inv.call_count == 1


# [FYP-FUNCTION] `test_rerun_threat_intel_invalidates_downstream` — verifies rerun threat intel invalidates downstream behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_start_and_reach_triage_approval`, `commit`, `db_connect`, `execute`, `get_state`, `rerun_stage`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_rerun_threat_intel_invalidates_downstream():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    with wss.db_connect() as con:
        con.execute(
            "UPDATE incidents SET threat_intel_status='Complete', "
            "threat_intel_result_json='{}', investigation_status='Approved', "
            "investigation_result_json='{}', reporting_status='Approved', "
            "reporting_result_json='{}', workflow_status='Complete' WHERE id=?",
            ("INC-1",))
        con.commit()
    wss.rerun_stage("INC-1", run_id, "threat_intel")
    state = wss.get_state("INC-1")
    assert state["threat_intel_status"] == "Processing"
    assert state["investigation_status"] == "Pending"
    assert state["investigation_result_json"] is None
    assert state["reporting_status"] == "Pending"
    assert state["reporting_result_json"] is None


# ══════════════════════════════════════════════════════════════════════════
# threat_intel.py — the VirusTotal / AbuseIPDB / AlienVault OTX engine
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `_ok_json_response` — implements the ok json response operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `payload`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tests/test_threat_intel_workflow.py:test_abuseipdb_ip_lookup_returns_reputation, tests/test_threat_intel_workflow.py:test_api_keys_read_at_call_time_not_import_time, tests/test_threat_intel_workflow.py:test_otx_domain_lookup_returns_pulse_data; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Mock`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _ok_json_response(payload: dict) -> Mock:
    r = Mock(status_code=200)
    r.json.return_value = payload
    return r


# [FYP-FUNCTION] `test_virustotal_file_hash_lookup_returns_reputation` — verifies virustotal file hash lookup returns reputation behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_ok_json_response`, `assert_called_once`, `patch`, `query_virustotal_file_hash`, `setenv`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_virustotal_file_hash_lookup_returns_reputation(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-vt-key")
    resp = _ok_json_response({"data": {"attributes": {
        "last_analysis_stats": {"malicious": 5, "suspicious": 1},
        "reputation": -10}}})
    with patch("requests.get", return_value=resp) as m:
        result = ti.query_virustotal_file_hash("a" * 64)
    assert result["status"] == "completed"
    assert result["malicious"] == 5
    assert result["reputation"] == -10
    m.assert_called_once()


# [FYP-FUNCTION] `test_virustotal_ip_lookup_returns_reputation` — verifies virustotal ip lookup returns reputation behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_ok_json_response`, `patch`, `query_virustotal_ip`, `setenv`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_virustotal_ip_lookup_returns_reputation(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-vt-key")
    resp = _ok_json_response({"data": {"attributes": {
        "last_analysis_stats": {"malicious": 0}, "country": "US"}}})
    with patch("requests.get", return_value=resp):
        result = ti.query_virustotal_ip("8.8.8.8")
    assert result["status"] == "completed"
    assert result["country"] == "US"


# [FYP-FUNCTION] `test_virustotal_domain_lookup_returns_reputation` — verifies virustotal domain lookup returns reputation behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_ok_json_response`, `patch`, `query_virustotal_domain`, `setenv`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_virustotal_domain_lookup_returns_reputation(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-vt-key")
    resp = _ok_json_response({"data": {"attributes": {
        "last_analysis_stats": {"malicious": 2}, "registrar": "Example Registrar"}}})
    with patch("requests.get", return_value=resp):
        result = ti.query_virustotal_domain("example.com")
    assert result["status"] == "completed"
    assert result["registrar"] == "Example Registrar"


# [FYP-FUNCTION] `test_abuseipdb_ip_lookup_returns_reputation` — verifies abuseipdb ip lookup returns reputation behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_ok_json_response`, `patch`, `query_abuseipdb`, `setenv`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_abuseipdb_ip_lookup_returns_reputation(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuse-key")
    resp = _ok_json_response({"data": {
        "abuseConfidenceScore": 92, "totalReports": 14, "countryCode": "RU",
        "isp": "Some ISP", "usageType": "Data Center/Web Hosting/Transit"}})
    with patch("requests.get", return_value=resp):
        result = ti.query_abuseipdb("1.2.3.4")
    assert result["status"] == "completed"
    assert result["abuse_confidence_score"] == 92
    assert result["isp"] == "Some ISP"


# [FYP-FUNCTION] `test_otx_file_hash_lookup_returns_pulse_data` — verifies otx file hash lookup returns pulse data behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_ok_json_response`, `patch`, `query_otx_indicator`, `setenv`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_otx_file_hash_lookup_returns_pulse_data(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-otx-key")
    resp = _ok_json_response({"pulse_info": {"count": 3, "pulses": [{"name": "p1"}]},
                              "sections": ["general", "analysis"]})
    with patch("requests.get", return_value=resp):
        result = ti.query_otx_indicator("file", "a" * 64)
    assert result["status"] == "completed"
    assert result["pulse_count"] == 3
    assert result["related_pulses"] == ["p1"]


# [FYP-FUNCTION] `test_otx_ip_lookup_returns_pulse_data` — verifies otx ip lookup returns pulse data behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_ok_json_response`, `patch`, `query_otx_indicator`, `setenv`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_otx_ip_lookup_returns_pulse_data(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-otx-key")
    resp = _ok_json_response({"pulse_info": {"count": 0, "pulses": []}, "sections": []})
    with patch("requests.get", return_value=resp):
        result = ti.query_otx_indicator("IPv4", "1.2.3.4")
    assert result["status"] == "completed"
    assert result["pulse_count"] == 0


# [FYP-FUNCTION] `test_otx_domain_lookup_returns_pulse_data` — verifies otx domain lookup returns pulse data behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_ok_json_response`, `patch`, `query_otx_indicator`, `setenv`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_otx_domain_lookup_returns_pulse_data(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-otx-key")
    resp = _ok_json_response({"pulse_info": {"count": 1, "pulses": [{"name": "p2"}]},
                              "sections": ["general"]})
    with patch("requests.get", return_value=resp):
        result = ti.query_otx_indicator("domain", "example.com")
    assert result["status"] == "completed"
    assert result["pulse_count"] == 1


# [FYP-FUNCTION] `test_missing_api_key_returns_skipped_not_crash` — verifies missing api key returns skipped not crash behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `assert_not_called`, `delenv`, `patch`, `query_abuseipdb`, `query_otx_indicator`, `query_virustotal_ip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_missing_api_key_returns_skipped_not_crash(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    with patch("requests.get") as m:
        assert ti.query_virustotal_ip("1.2.3.4")["status"] == "skipped"
        assert ti.query_abuseipdb("1.2.3.4")["status"] == "skipped"
        assert ti.query_otx_indicator("IPv4", "1.2.3.4")["status"] == "skipped"
    m.assert_not_called()   # no network attempted when the key is missing


# [FYP-FUNCTION] `test_private_ip_excluded_from_extraction` — verifies private ip excluded from extraction behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `extract_iocs`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_private_ip_excluded_from_extraction():
    iocs = ti.extract_iocs({"source_ip": "10.0.0.5", "destination_ip": "8.8.8.8"})
    assert "10.0.0.5" not in iocs["ip_indicators"]
    assert "8.8.8.8" in iocs["ip_indicators"]


# [FYP-FUNCTION] `test_public_ip_extracted` — verifies public ip extracted behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `extract_iocs`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_public_ip_extracted():
    iocs = ti.extract_iocs({"source_ip": "203.0.113.5"})
    assert iocs["ip_indicators"] == ["203.0.113.5"]


# [FYP-FUNCTION] `test_external_domain_extracted` — verifies external domain extracted behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `extract_iocs`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_external_domain_extracted():
    iocs = ti.extract_iocs({"event_domain": "malicious-example.com"})
    assert iocs["domain_indicators"] == ["malicious-example.com"]


# [FYP-FUNCTION] `test_internal_hostname_without_dot_ignored` — verifies internal hostname without dot ignored behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `extract_iocs`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_internal_hostname_without_dot_ignored():
    iocs = ti.extract_iocs({"event_domain": "CORPHOST01"})
    assert iocs["domain_indicators"] == []


# [FYP-FUNCTION] `test_url_derived_domain_extracted` — verifies url derived domain extracted behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `extract_iocs`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_url_derived_domain_extracted():
    iocs = ti.extract_iocs({"url": "https://bad.example.net/payload.exe"})
    assert iocs["url_indicators"] == ["https://bad.example.net/payload.exe"]
    assert "bad.example.net" in iocs["domain_indicators"]


# [FYP-FUNCTION] `test_powershell_iocs_preserved_through_flatten` — verifies powershell iocs preserved through flatten behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `extract_iocs`, `flatten_alert_for_enrichment`, `startswith`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_powershell_iocs_preserved_through_flatten():
    alert = {
        "source_ip": "203.0.113.9",
        "powershell_analysis": {
            "decode_status": "success",
            "extracted_iocs": {"domains": ["ps-c2.example.com"]},
        },
    }
    flat = ti.flatten_alert_for_enrichment(alert)
    assert flat["powershell_analysis"]["decode_status"] == "success"
    iocs = ti.extract_iocs(flat)
    assert "ps-c2.example.com" in iocs["domain_indicators"]
    assert iocs["powershell_enrichment_note"].startswith("Decoded PowerShell")


# [FYP-FUNCTION] `test_risk_scoring_produces_low_medium_high` — verifies risk scoring produces low medium high behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `calculate_enrichment_risk`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_risk_scoring_produces_low_medium_high():
    low = ti.calculate_enrichment_risk({})
    assert low["enrichment_risk_level"] == "Low"

    medium = ti.calculate_enrichment_risk({
        "virustotal": {"ip_results": [{"status": "completed", "indicator": "1.2.3.4",
                                       "malicious": 1, "suspicious": 0}]},
        "abuseipdb": {"ip_results": [{"status": "completed", "indicator": "1.2.3.4",
                                      "abuse_confidence_score": 50}]}})
    assert medium["enrichment_risk_level"] == "Medium"

    high = ti.calculate_enrichment_risk({
        "virustotal": {
            "file_hash": {"status": "completed", "malicious": 6, "suspicious": 0},
            "ip_results": [{"status": "completed", "indicator": "1.2.3.4",
                            "malicious": 1, "suspicious": 0}],
            "domain_results": [{"status": "completed", "indicator": "example.com",
                                "malicious": 1, "suspicious": 0}],
        }})
    assert high["enrichment_risk_level"] == "High"


# [FYP-FUNCTION] `test_no_adverse_findings_are_not_labelled_safe` — verifies no adverse findings are not labelled safe behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`, `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_mock_all_ti_keys_absent`, `join`, `lower`, `run_threat_intel_for_dashboard`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_no_adverse_findings_are_not_labelled_safe(monkeypatch, tmp_path):
    """No malicious/suspicious findings should read as Low risk with the
    engine's own generic reason — never as a fabricated 'clean'/'benign'
    claim about the indicator."""
    _mock_all_ti_keys_absent(monkeypatch)
    result = ti.run_threat_intel_for_dashboard(
        {"destination_ip": "8.8.8.8"}, output_dir=tmp_path)
    assert result["enrichment_risk_level"] == "Low"
    reasons = " ".join(result["enrichment_risk_reasons"]).lower()
    assert "benign" not in reasons and "clean" not in reasons and "safe" not in reasons
    assert "no confirmed malicious external intelligence" in reasons


# [FYP-FUNCTION] `test_provider_error_produces_warning_not_silent_failure` — verifies provider error produces warning not silent failure behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`, `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `Mock`, `any`, `delenv`, `patch`, `run_threat_intel_for_dashboard`, `setenv`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_provider_error_produces_warning_not_silent_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_API_KEY", "test-vt-key")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    resp = Mock(status_code=500, text="internal error")
    with patch("requests.get", return_value=resp):
        result = ti.run_threat_intel_for_dashboard(
            {"destination_ip": "8.8.8.8"}, output_dir=tmp_path)
    assert result["threat_intelligence"]["virustotal"]["ip_results"][0]["status"] == "error"
    assert any("VirusTotal" in w for w in result["warnings"])
    assert result["status"] == "completed_with_warnings"


# [FYP-FUNCTION] `test_missing_api_keys_produce_warnings_not_fabricated_results` — verifies missing api keys produce warnings not fabricated results behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`, `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_mock_all_ti_keys_absent`, `any`, `assert_not_called`, `patch`, `run_threat_intel_for_dashboard`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_missing_api_keys_produce_warnings_not_fabricated_results(monkeypatch, tmp_path):
    _mock_all_ti_keys_absent(monkeypatch)
    with patch("requests.get") as m:
        result = ti.run_threat_intel_for_dashboard(
            {"destination_ip": "8.8.8.8"}, output_dir=tmp_path)
    m.assert_not_called()
    assert any("VirusTotal" in w for w in result["warnings"])
    assert any("AbuseIPDB" in w for w in result["warnings"])
    assert any("AlienVault OTX" in w for w in result["warnings"])
    ti_block = result["threat_intelligence"]
    assert ti_block["virustotal"]["ip_results"][0]["status"] == "skipped"
    assert ti_block["abuseipdb"]["ip_results"][0]["status"] == "skipped"
    assert ti_block["alienvault_otx"]["otx_results"][0]["status"] == "skipped"


# [FYP-FUNCTION] `test_missing_key_warning_only_fires_for_applicable_provider` — verifies missing key warning only fires for applicable provider behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`, `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_mock_all_ti_keys_absent`, `any`, `run_threat_intel_for_dashboard`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_missing_key_warning_only_fires_for_applicable_provider(monkeypatch, tmp_path):
    """A domain-only alert never needs AbuseIPDB (IP-only provider) — no
    AbuseIPDB warning should fire even though its key is also unset."""
    _mock_all_ti_keys_absent(monkeypatch)
    result = ti.run_threat_intel_for_dashboard(
        {"event_domain": "example.com"}, output_dir=tmp_path)
    assert any("VirusTotal" in w for w in result["warnings"])
    assert any("AlienVault OTX" in w for w in result["warnings"])
    assert not any("AbuseIPDB" in w for w in result["warnings"])


# [FYP-FUNCTION] `test_informational_notes_never_counted_as_warnings` — verifies informational notes never counted as warnings behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `run_threat_intel_for_dashboard`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_informational_notes_never_counted_as_warnings(tmp_path):
    result = ti.run_threat_intel_for_dashboard({}, output_dir=tmp_path)
    assert result["threat_intelligence"]["notes"]   # "no usable IP/domain/hash..." etc.
    assert result["warnings"] == []
    assert result["status"] == "completed"


# [FYP-FUNCTION] `test_persisted_dashboard_and_disk_result_are_identical` — verifies persisted dashboard and disk result are identical behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`, `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_mock_all_ti_keys_absent`, `loads`, `read_text`, `run_threat_intel_for_dashboard`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_persisted_dashboard_and_disk_result_are_identical(monkeypatch, tmp_path):
    _mock_all_ti_keys_absent(monkeypatch)
    result = ti.run_threat_intel_for_dashboard(
        {"destination_ip": "8.8.8.8"}, output_dir=tmp_path)
    on_disk = json.loads((tmp_path / "threat_intel_result.json").read_text(encoding="utf-8"))
    assert on_disk == result
    on_disk_alert = json.loads((tmp_path / "enriched_alert.json").read_text(encoding="utf-8"))
    assert on_disk_alert == result["enriched_alert"]


# [FYP-FUNCTION] `test_agent_source_reflects_repo_path` — verifies agent source reflects repo path behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `run_threat_intel_for_dashboard`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_agent_source_reflects_repo_path(tmp_path):
    result = ti.run_threat_intel_for_dashboard({}, output_dir=tmp_path)
    assert result["agent_source"] == "threat_intel.py"
    assert result["enriched_alert"]["agent_source"] == "threat_intel.py"


# [FYP-FUNCTION] `test_api_keys_read_at_call_time_not_import_time` — verifies api keys read at call time not import time behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_ok_json_response`, `patch`, `query_virustotal_ip`, `setenv`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_api_keys_read_at_call_time_not_import_time(monkeypatch):
    # threat_intel is already imported (module-level `import threat_intel as ti`
    # above) — setting the env var now must still be picked up.
    monkeypatch.setenv("VT_API_KEY", "set-after-import")
    resp = _ok_json_response({"data": {"attributes": {"last_analysis_stats": {}}}})
    with patch("requests.get", return_value=resp):
        result = ti.query_virustotal_ip("1.2.3.4")
    assert result["status"] == "completed"


# [FYP-FUNCTION] `test_run_threat_intel_receives_correct_parsing_triage_and_incident_inputs` — verifies run threat intel receives correct parsing triage and incident inputs behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_mock_all_ti_keys_absent`, `_triage_result`, `assert_not_called`, `patch`, `run_threat_intel`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_run_threat_intel_receives_correct_parsing_triage_and_incident_inputs(monkeypatch):
    """The flat alert handed to enrich_alert() combines Parsing's
    processed_alert fields with the raw incident's alertMeta fallback."""
    incident = {"alertMeta": {"DestinationIp": ["8.8.4.4"]}}
    triage_result = _triage_result("INC-1")
    normalised_alert = {"source_ip": "1.2.3.4", "event_domain": "example.com"}
    _mock_all_ti_keys_absent(monkeypatch)
    with patch("requests.get") as m:
        result = sw.run_threat_intel(incident_id="INC-1", run_id="r1",
                                     normalised_alert=normalised_alert,
                                     triage_result=triage_result, incident=incident)
    m.assert_not_called()
    iocs = result["threat_intelligence"]["iocs"]
    assert iocs["domain_indicators"] == ["example.com"]
    assert "1.2.3.4" in iocs["ip_indicators"]
    assert "8.8.4.4" in iocs["ip_indicators"]


# [FYP-FUNCTION] `test_result_persisted_correctly_in_db` — verifies result persisted correctly in db behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_mock_all_ti_keys_absent`, `_save_raw_incident`, `_start_and_reach_triage_approval`, `get_state`, `loads`, `resume_after_triage_approval`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_result_persisted_correctly_in_db(monkeypatch):
    _mock_all_ti_keys_absent(monkeypatch)
    run_id = _start_and_reach_triage_approval("INC-1")
    _save_raw_incident("INC-1", run_id)
    _approve_triage("INC-1", run_id)
    sw.resume_after_triage_approval("INC-1", run_id)
    saved = json.loads(wss.get_state("INC-1")["threat_intel_result_json"])
    assert saved["stage"] == "threat_intelligence"
    assert "threat_intelligence" in saved
    assert "enrichment_risk_level" in saved


# [FYP-FUNCTION] `test_result_reaches_reporting_handoff` — verifies result reaches reporting handoff behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`, `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `__setitem__`, `_incident`, `_mock_all_ti_keys_absent`, `_triage_result`, `endswith`, `handoff_to_reporting`, `items`, `mkdir`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_result_reaches_reporting_handoff(monkeypatch, tmp_path):
    _mock_all_ti_keys_absent(monkeypatch)
    ti_result = sw.run_threat_intel(incident_id="INC-1", run_id="r1",
                                    normalised_alert=None,
                                    triage_result=_triage_result("INC-1"),
                                    incident=_incident("INC-1"))
    captured = {}
    monkeypatch.setattr(sw, "_write_json",
                        lambda path, data: captured.__setitem__(str(path), data))
    outputs_dir = tmp_path / "outputs"
    outputs_dir.mkdir()
    monkeypatch.setattr(sw, "REP_DIR", tmp_path)
    sw.handoff_to_reporting({"ticket": {}}, _incident("INC-1"),
                            {"status": "completed"}, threat_intel_result=ti_result)
    written = next(v for k, v in captured.items() if k.endswith("threat_intel_result.json"))
    assert written == ti_result


# ══════════════════════════════════════════════════════════════════════════
# Investigation handoff
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_investigation_receives_persisted_threat_intel_result` — verifies investigation receives persisted threat intel result behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_approve_triage`, `_mock_all_ti_keys_absent`, `_save_raw_incident`, `_start_and_reach_triage_approval`, `get_state`, `loads`, `resume_after_triage_approval`, `run_investigation_stage`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_investigation_receives_persisted_threat_intel_result(monkeypatch):
    run_id = _start_and_reach_triage_approval("INC-1")
    _save_raw_incident("INC-1", run_id)
    _approve_triage("INC-1", run_id)
    _mock_all_ti_keys_absent(monkeypatch)
    sw.resume_after_triage_approval("INC-1", run_id)

    captured = {}

    # [FYP-FUNCTION] `_fake_investigate_with_feedback` — implements the fake investigate with feedback operation used by the surrounding test and validation workflow.
    # [FYP-INPUT] Parameters: `triage_result`, `incident`, `incident_id`, `threat_intel_result`, `**kw`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: no nested function/service calls.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _fake_investigate_with_feedback(triage_result, incident, incident_id,
                                        threat_intel_result=None, **kw):
        captured["threat_intel_result"] = threat_intel_result
        return {"status": "completed", "incident_folder": "x"}

    monkeypatch.setattr(sw, "investigate_with_feedback", _fake_investigate_with_feedback)
    sw.run_investigation_stage("INC-1", run_id)

    saved_ti = json.loads(wss.get_state("INC-1")["threat_intel_result_json"])
    assert captured["threat_intel_result"] == saved_ti


# [FYP-FUNCTION] `test_investigation_completion_is_awaiting_approval_not_complete` — verifies investigation completion is awaiting approval not complete behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `Mock`, `_guarded_update`, `_save_raw_incident`, `_triage_result`, `get_state`, `run_investigation_stage`, `save_triage_result`, `setattr`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_investigation_completion_is_awaiting_approval_not_complete(monkeypatch):
    run_id = wss.start_run("INC-1")
    _save_raw_incident("INC-1", run_id)
    wss.save_triage_result("INC-1", run_id, _triage_result("INC-1"))
    wss._guarded_update("INC-1", run_id, {"investigation_status": "Processing",
                                          "workflow_status": "Processing"})
    monkeypatch.setattr(sw, "investigate_with_feedback",
                        Mock(return_value={"status": "completed", "incident_folder": "x"}))
    result = sw.run_investigation_stage("INC-1", run_id)
    assert result["status"] == "awaiting_approval"
    state = wss.get_state("INC-1")
    assert state["investigation_status"] == "Awaiting Approval"
    assert state["investigation_status"] != "Complete"
    assert state["workflow_status"] == "Awaiting Approval"
    assert state["approval_stage"] == "investigation"


# [FYP-FUNCTION] `test_investigation_failure_persists_actionable_last_error` — verifies investigation failure persists actionable last error behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `Mock`, `_guarded_update`, `_save_raw_incident`, `_triage_result`, `get_state`, `run_investigation_stage`, `save_triage_result`, `setattr`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_investigation_failure_persists_actionable_last_error(monkeypatch):
    run_id = wss.start_run("INC-1")
    _save_raw_incident("INC-1", run_id)
    wss.save_triage_result("INC-1", run_id, _triage_result("INC-1"))
    wss._guarded_update("INC-1", run_id, {"investigation_status": "Processing",
                                          "workflow_status": "Processing"})
    monkeypatch.setattr(
        sw,
        "investigate_with_feedback",
        Mock(return_value={
            "status": "failed",
            "error": "Traceback (most recent call last):\n"
                     "ValueError: embedding function conflict",
        }),
    )

    result = sw.run_investigation_stage("INC-1", run_id)

    assert result["status"] == "failed"
    state = wss.get_state("INC-1")
    assert state["investigation_status"] == "Failed"
    assert state["workflow_status"] == "Failed"
    assert state["last_error"] == (
        "investigation failed: ValueError: embedding function conflict"
    )
