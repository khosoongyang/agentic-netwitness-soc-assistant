# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, ast, case_view, datetime, json, pathlib, pytest, soc_workflow.
# =============================================================================
# File: tests/test_investigation_stage.py
# Purpose: This module implements test and validation behaviour for test investigation stage.
# Main functionality: _isolated_db, _triage_result, _incident, _run_to_investigation_processing, test_expired_unreassigned_worker_cannot_complete_stage, test_worker_id_alone_is_not_sufficient_after_lease_expiry.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis test and validation component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, ast, case_view, datetime, json, pathlib, pytest, soc_workflow.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: _isolated_db, _triage_result, _incident, _run_to_investigation_processing, test_expired_unreassigned_worker_cannot_complete_stage, test_worker_id_alone_is_not_sufficient_after_lease_expiry, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

"""
tests/test_investigation_stage.py — Investigation stage integration:
cross-process shared-workspace locking, the expired-worker completion fix,
audit-safe retry/rerun, atomic activity logging, persisted IOC correlation,
and case_view.py's builders (MITRE markdown parsing, Host/User precedence,
IOC-count deduplication, entity-graph relabeling, sanitized raw display).

Same conventions as tests/test_threat_intel_workflow.py: every test gets an
isolated tmp_path SQLite file and trusted artifact root (never soc_db/ or
outputs/); no live subprocess, no real LLM/OpenAI/network calls.
"""
from __future__ import annotations

import ast
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import workflow_state_store as wss
import soc_workflow as sw
import case_view as cv


ROOT = Path(__file__).resolve().parent.parent


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
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "test_investigation.db")
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
    ticket = {"incident_id": incident_id, "unc": "#001", "classification": "MEDIUM"}
    ticket.update(ticket_overrides)
    return {"ticket": ticket,
           "metakeys_payload": {"incident_id": incident_id, "metakey_values": {}}}


# [FYP-FUNCTION] `_incident` — implements the incident operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `incident_id`, `**overrides`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tests/test_investigation_stage.py:test_build_case_view_never_calls_investigation_stage_functions, tests/test_investigation_stage.py:test_entity_graph_never_labels_cooccurrence_as_connected_to, tests/test_investigation_stage.py:test_host_and_user_never_derived_from_narrative_prose; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `update`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _incident(incident_id: str = "INC-1", **overrides) -> dict:
    inc = {"id": incident_id, "title": "Test incident", "alertMeta": {}}
    inc.update(overrides)
    return inc


# [FYP-FUNCTION] `_run_to_investigation_processing` — orchestrates the run to investigation processing entry point and its ordered test and validation operations.
# [FYP-INPUT] Parameters: `incident_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tests/test_investigation_stage.py:test_expired_unreassigned_worker_cannot_complete_stage, tests/test_investigation_stage.py:test_investigation_stage_failure_blocks_reporting, tests/test_investigation_stage.py:test_investigation_stage_passes_persisted_threat_intel_explicitly; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_guarded_update`, `_triage_result`, `save_triage_result`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _run_to_investigation_processing(incident_id: str = "INC-1") -> str:
    """Fresh run, straight to investigation_status="Processing" — the state
    run_investigation_stage()/claim_stage() require."""
    run_id = wss.start_run(incident_id)
    wss.save_triage_result(incident_id, run_id, _triage_result(incident_id))
    wss._guarded_update(incident_id, run_id, {
        "triage_status": "Approved",
        "threat_intel_status": "Complete",
        "investigation_status": "Processing",
        "workflow_status": "Processing",
    })
    return run_id


# ══════════════════════════════════════════════════════════════════════════
# The expired-worker completion bug (fixed in complete_stage())
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_expired_unreassigned_worker_cannot_complete_stage` — verifies expired unreassigned worker cannot complete stage behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_run_to_investigation_processing`, `claim_stage`, `commit`, `complete_stage`, `db_connect`, `execute`, `get_state`, `isoformat`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_expired_unreassigned_worker_cannot_complete_stage():
    run_id = _run_to_investigation_processing("INC-1")
    worker_id, _attempt = wss.claim_stage(
        "INC-1", run_id, stage="investigation",
        status_column="investigation_status", expect_status="Processing")
    # Lease expires; NO other worker ever claims it.
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with wss.db_connect() as con:
        con.execute("UPDATE incidents SET worker_lease_expires_at=? WHERE id=?",
                   (past, "INC-1"))
        con.commit()

    ok = wss.complete_stage(
        "INC-1", run_id, worker_id, stage="investigation",
        result_column="investigation_result_json",
        result={"status": "completed", "severity": "High"},
        status_updates={"investigation_status": "Awaiting Approval",
                        "workflow_status": "Awaiting Approval"})
    assert ok is False
    state = wss.get_state("INC-1")
    assert state["investigation_status"] == "Processing"   # untouched
    assert state["investigation_result_json"] is None


# [FYP-FUNCTION] `test_worker_id_alone_is_not_sufficient_after_lease_expiry` — verifies worker id alone is not sufficient after lease expiry behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_run_to_investigation_processing`, `claim_stage`, `commit`, `complete_stage`, `db_connect`, `execute`, `get_state`, `isoformat`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_worker_id_alone_is_not_sufficient_after_lease_expiry():
    """Regression guard for the exact bug found in review: worker_id/
    worker_stage do NOT change merely because the lease expired — only the
    explicit lease-liveness check inside complete_stage() catches this."""
    run_id = _run_to_investigation_processing("INC-1")
    worker_id, _ = wss.claim_stage(
        "INC-1", run_id, stage="investigation",
        status_column="investigation_status", expect_status="Processing")
    state = wss.get_state("INC-1")
    assert state["worker_id"] == worker_id
    assert state["worker_stage"] == "investigation"
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with wss.db_connect() as con:
        con.execute("UPDATE incidents SET worker_lease_expires_at=? WHERE id=?",
                   (past, "INC-1"))
        con.commit()
    # Confirm identity fields are UNCHANGED by mere expiry (the false
    # assumption the earlier drafts made).
    state2 = wss.get_state("INC-1")
    assert state2["worker_id"] == worker_id
    assert state2["worker_stage"] == "investigation"
    # ... yet complete_stage() still refuses, because of the lease check.
    ok = wss.complete_stage(
        "INC-1", run_id, worker_id, stage="investigation",
        result_column="investigation_result_json", result={"status": "completed"},
        status_updates={"investigation_status": "Awaiting Approval"})
    assert ok is False


# ══════════════════════════════════════════════════════════════════════════
# Layering: workflow_state_store.py owns the DB, never threads/executes
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_workflow_state_store_has_no_threading_import` — verifies workflow state store has no threading import behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `any`, `isinstance`, `parse`, `read_text`, `walk`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_workflow_state_store_has_no_threading_import():
    tree = ast.parse((ROOT / "workflow_state_store.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any(a.name == "threading" for a in node.names), \
                "workflow_state_store.py must not import threading"
        if isinstance(node, ast.ImportFrom):
            assert node.module != "threading", \
                "workflow_state_store.py must not import from threading"


# [FYP-FUNCTION] `test_soc_workflow_has_no_streamlit_import` — verifies soc workflow has no streamlit import behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `any`, `isinstance`, `parse`, `read_text`, `walk`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_soc_workflow_has_no_streamlit_import():
    tree = ast.parse((ROOT / "soc_workflow.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any(a.name == "streamlit" for a in node.names), \
                "soc_workflow.py (the background worker) must remain UI-framework independent"
        if isinstance(node, ast.ImportFrom):
            assert node.module != "streamlit"


# ══════════════════════════════════════════════════════════════════════════
# Global execution lock (cross-process, cross-incident shared workspace)
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_two_incidents_cannot_use_investigation_workspace_concurrently` — verifies two incidents cannot use investigation workspace concurrently behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `acquire_global_lock`, `raises`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_two_incidents_cannot_use_investigation_workspace_concurrently():
    wss.acquire_global_lock("investigation_workspace", owner_id="worker-A",
                            incident_id="INC-1", run_id="run-A", ttl_seconds=30)
    with pytest.raises(wss.GlobalLockBusyError):
        wss.acquire_global_lock("investigation_workspace", owner_id="worker-B",
                                incident_id="INC-2", run_id="run-B", ttl_seconds=30)


# [FYP-FUNCTION] `test_global_lock_busy_error_is_a_stage_claim_error` — verifies global lock busy error is a stage claim error behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `issubclass`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_global_lock_busy_error_is_a_stage_claim_error():
    """run_stage_chain's existing `except StageClaimError: return` handling
    must cover shared-workspace contention without special-casing it."""
    assert issubclass(wss.GlobalLockBusyError, wss.StageClaimError)


# [FYP-FUNCTION] `test_stale_global_lock_expires_safely` — verifies stale global lock expires safely behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `acquire_global_lock`, `commit`, `db_connect`, `execute`, `fetchone`, `isoformat`, `now`, `timedelta`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_stale_global_lock_expires_safely():
    wss.acquire_global_lock("investigation_workspace", owner_id="worker-A",
                            incident_id="INC-1", run_id="run-A", ttl_seconds=30)
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with wss.db_connect() as con:
        con.execute("UPDATE global_execution_locks SET expires_at=? WHERE lock_name=?",
                   (past, "investigation_workspace"))
        con.commit()
    # A new owner can now acquire it — no GlobalLockBusyError.
    wss.acquire_global_lock("investigation_workspace", owner_id="worker-B",
                            incident_id="INC-2", run_id="run-B", ttl_seconds=30)
    with wss.db_connect() as con:
        row = con.execute("SELECT owner_id FROM global_execution_locks "
                          "WHERE lock_name=?", ("investigation_workspace",)).fetchone()
    assert row["owner_id"] == "worker-B"


# [FYP-FUNCTION] `test_renew_global_lock_fails_after_reassignment` — verifies renew global lock fails after reassignment behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `acquire_global_lock`, `commit`, `db_connect`, `execute`, `isoformat`, `now`, `renew_global_lock`, `timedelta`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_renew_global_lock_fails_after_reassignment():
    wss.acquire_global_lock("investigation_workspace", owner_id="worker-A",
                            incident_id="INC-1", run_id="run-A", ttl_seconds=30)
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with wss.db_connect() as con:
        con.execute("UPDATE global_execution_locks SET expires_at=? WHERE lock_name=?",
                   (past, "investigation_workspace"))
        con.commit()
    wss.acquire_global_lock("investigation_workspace", owner_id="worker-B",
                            incident_id="INC-2", run_id="run-B", ttl_seconds=30)
    # worker-A no longer owns it — its renewal must report failure, not
    # silently "succeed" against someone else's lock.
    assert wss.renew_global_lock("investigation_workspace", "worker-A") is False
    assert wss.renew_global_lock("investigation_workspace", "worker-B") is True


# [FYP-FUNCTION] `test_release_global_lock_is_owner_scoped` — verifies release global lock is owner scoped behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `acquire_global_lock`, `raises`, `release_global_lock`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_release_global_lock_is_owner_scoped():
    wss.acquire_global_lock("investigation_workspace", owner_id="worker-A",
                            incident_id="INC-1", run_id="run-A", ttl_seconds=30)
    # A different owner's release must be a no-op (never delete someone
    # else's live lock).
    wss.release_global_lock("investigation_workspace", "worker-B")
    with pytest.raises(wss.GlobalLockBusyError):
        wss.acquire_global_lock("investigation_workspace", owner_id="worker-C",
                                incident_id="INC-3", run_id="run-C", ttl_seconds=30)
    wss.release_global_lock("investigation_workspace", "worker-A")
    wss.acquire_global_lock("investigation_workspace", owner_id="worker-C",
                            incident_id="INC-3", run_id="run-C", ttl_seconds=30)


# ══════════════════════════════════════════════════════════════════════════
# reporting_status="Blocked" on Investigation failure/rejection
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_reject_investigation_blocks_reporting` — verifies reject investigation blocks reporting behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_guarded_update`, `get_state`, `reject_investigation`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_reject_investigation_blocks_reporting():
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {
        "triage_status": "Approved", "threat_intel_status": "Complete",
        "investigation_status": "Awaiting Approval", "reporting_status": "Pending",
        "workflow_status": "Awaiting Approval", "approval_stage": "investigation",
    })
    wss.reject_investigation("INC-1", run_id, rejected_by="tester", reason="not convincing")
    state = wss.get_state("INC-1")
    assert state["investigation_status"] == "Rejected"
    assert state["reporting_status"] == "Blocked"
    assert state["workflow_status"] == "Rejected"


# [FYP-FUNCTION] `test_investigation_stage_failure_blocks_reporting` — verifies investigation stage failure blocks reporting behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_run_to_investigation_processing`, `get_state`, `run_investigation_stage`, `setattr`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_investigation_stage_failure_blocks_reporting(monkeypatch):
    run_id = _run_to_investigation_processing("INC-1")
    monkeypatch.setattr(sw, "investigate_with_feedback",
                        lambda *a, **k: {"status": "failed", "error": "boom"})
    sw.run_investigation_stage("INC-1", run_id)
    state = wss.get_state("INC-1")
    assert state["investigation_status"] == "Failed"
    assert state["reporting_status"] == "Blocked"
    assert state["workflow_status"] == "Failed"


# ══════════════════════════════════════════════════════════════════════════
# Stage-attempt vs. approval-attempt; audit history is never deleted
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_retry_investigation_from_failed_has_nothing_to_delete` — verifies retry investigation from failed has nothing to delete behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_guarded_update`, `get_approval_history`, `get_state`, `rerun_stage`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_retry_investigation_from_failed_has_nothing_to_delete():
    """A Failed investigation never reached Awaiting Approval, so no
    approval_stage="investigation" row exists yet — retry-from-Failed is
    audit-safe by construction, not because anything was cleared."""
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {
        "triage_status": "Approved", "threat_intel_status": "Complete",
        "investigation_status": "Failed", "reporting_status": "Blocked",
        "workflow_status": "Failed",
    })
    assert wss.get_approval_history("INC-1", run_id) == []
    wss.rerun_stage("INC-1", run_id, "investigation")
    state = wss.get_state("INC-1")
    assert state["investigation_status"] == "Processing"
    assert state["investigation_result_json"] is None
    assert state["reporting_status"] == "Pending"
    assert wss.get_approval_history("INC-1", run_id) == []


# [FYP-FUNCTION] `test_rerun_approved_investigation_preserves_prior_decision` — verifies rerun approved investigation preserves prior decision behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_guarded_update`, `approve_investigation`, `get_approval_history`, `get_state`, `len`, `rerun_stage`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_rerun_approved_investigation_preserves_prior_decision():
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {
        "triage_status": "Approved", "threat_intel_status": "Complete",
        "investigation_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval", "approval_stage": "investigation",
    })
    wss.approve_investigation("INC-1", run_id, approved_by="analyst-1")
    history_before = wss.get_approval_history("INC-1", run_id)
    assert len(history_before) == 1
    assert history_before[0]["stage_attempt"] == 1
    assert history_before[0]["approval_attempt"] == 1

    # approve_investigation() only unlocks Reporting (workflow_status=
    # "Awaiting Action") — it never starts it, so rerun_stage()'s "not
    # while another stage is processing" guard is already satisfied here.
    # This explicit reset just keeps the state shape the same as before
    # Reporting's own approval-pending flow begins, which is what this
    # test is actually exercising.
    wss._guarded_update("INC-1", run_id, {"workflow_status": "Awaiting Approval"})
    wss.rerun_stage("INC-1", run_id, "investigation")
    state = wss.get_state("INC-1")
    assert state["investigation_attempt"] == 2

    # Prior decision must still be there — never deleted.
    assert wss.get_approval_history("INC-1", run_id) == history_before

    wss._guarded_update("INC-1", run_id, {
        "investigation_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval", "approval_stage": "investigation",
    })
    wss.approve_investigation("INC-1", run_id, approved_by="analyst-2")
    history_after = wss.get_approval_history("INC-1", run_id)
    assert len(history_after) == 2
    # The new decision is attributed to the SECOND execution (stage_attempt
    # 2), and is the first DECISION for that execution (approval_attempt 1)
    # — not "attempt 2" as a naive COUNT(*)+1 would have recorded it.
    assert history_after[1]["stage_attempt"] == 2
    assert history_after[1]["approval_attempt"] == 1


# [FYP-FUNCTION] `test_duplicate_investigation_approval_still_rejected_with_new_schema` — verifies duplicate investigation approval still rejected with new schema behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_guarded_update`, `approve_investigation`, `raises`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_duplicate_investigation_approval_still_rejected_with_new_schema():
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {
        "triage_status": "Approved", "threat_intel_status": "Complete",
        "investigation_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval", "approval_stage": "investigation",
    })
    wss.approve_investigation("INC-1", run_id, approved_by="analyst-1")
    with pytest.raises(wss.ApprovalConflictError):
        wss.approve_investigation("INC-1", run_id, approved_by="analyst-1")


# ══════════════════════════════════════════════════════════════════════════
# get_approval_history — previously write-only, now readable
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_get_approval_history_returns_all_decisions_in_order` — verifies get approval history returns all decisions in order behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_guarded_update`, `approve_triage`, `get_approval_history`, `reject_investigation`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_get_approval_history_returns_all_decisions_in_order():
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {
        "triage_status": "Awaiting Approval", "workflow_status": "Awaiting Approval",
        "approval_stage": "triage",
    })
    wss.approve_triage("INC-1", run_id, approved_by="analyst-1")
    wss._guarded_update("INC-1", run_id, {
        "threat_intel_status": "Complete", "investigation_status": "Awaiting Approval",
        "workflow_status": "Awaiting Approval", "approval_stage": "investigation",
    })
    wss.reject_investigation("INC-1", run_id, rejected_by="analyst-2", reason="x")

    history = wss.get_approval_history("INC-1", run_id)
    assert [h["approval_stage"] for h in history] == ["triage", "investigation"]
    assert [h["decision"] for h in history] == ["approved", "rejected"]
    assert history[1]["analyst"] == "analyst-2"
    assert history[1]["comments"] == "x"


# ══════════════════════════════════════════════════════════════════════════
# Investigation receives persisted Threat Intelligence explicitly
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_investigation_stage_passes_persisted_threat_intel_explicitly` — verifies investigation stage passes persisted threat intel explicitly behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_guarded_update`, `_run_to_investigation_processing`, `dumps`, `run_investigation_stage`, `setattr`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_investigation_stage_passes_persisted_threat_intel_explicitly(monkeypatch):
    run_id = _run_to_investigation_processing("INC-1")
    ti_payload = {"status": "completed", "risk_level": "high", "iocs": []}
    wss._guarded_update("INC-1", run_id,
                        {"threat_intel_result_json": json.dumps(ti_payload)})
    captured = {}

    # [FYP-FUNCTION] `_fake_investigate` — implements the fake investigate operation used by the surrounding test and validation workflow.
    # [FYP-INPUT] Parameters: `triage_result`, `incident`, `inc_id`, `**kwargs`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `get`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _fake_investigate(triage_result, incident, inc_id, **kwargs):
        captured["threat_intel_result"] = kwargs.get("threat_intel_result")
        return {"status": "awaiting_approval", "severity": "High", "summary": "ok"}

    monkeypatch.setattr(sw, "investigate_with_feedback", _fake_investigate)
    sw.run_investigation_stage("INC-1", run_id)
    assert captured["threat_intel_result"] == ti_payload


# [FYP-FUNCTION] `test_reporting_receives_persisted_threat_intel_result` — verifies reporting receives persisted threat intel result behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_incident`, `_triage_result`, `handoff_to_reporting`, `loads`, `read_text`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_reporting_receives_persisted_threat_intel_result():
    """handoff_to_reporting() writes threat_intel_result.json explicitly —
    Reporting no longer has to hope TI survived into investigation_result's
    prose."""
    ti_payload = {"status": "completed", "risk_level": "high", "iocs": []}
    ticket_id = sw.handoff_to_reporting(
        _triage_result("INC-1"), _incident("INC-1"),
        {"status": "completed", "severity": "High"},
        threat_intel_result=ti_payload)
    written = json.loads((sw.REP_DIR / "outputs" / "threat_intel_result.json")
                         .read_text(encoding="utf-8"))
    assert written == ti_payload
    assert ticket_id


# ══════════════════════════════════════════════════════════════════════════
# Persisted IOC correlation — computed once, never live during rendering
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_ioc_correlation_failure_produces_warning_without_failing_workflow` — verifies ioc correlation failure produces warning without failing workflow behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_incident`, `get_state`, `loads`, `run_until_triage_approval`, `setattr`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_ioc_correlation_failure_produces_warning_without_failing_workflow(monkeypatch):
    import ioc_correlation

    # [FYP-FUNCTION] `_boom` — implements the boom operation used by the surrounding test and validation workflow.
    # [FYP-INPUT] Parameters: `*a`, `**k`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `RuntimeError`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

    def _boom(*a, **k):
        raise RuntimeError("corpus db unreadable")

    monkeypatch.setattr(ioc_correlation, "correlate_iocs", _boom)
    incident = _incident("INC-1")
    result = sw.run_until_triage_approval(incident, use_mock_triage=True)
    assert result["stages"]["triage"] == "awaiting_approval"   # never fails Triage
    state = wss.get_state("INC-1")
    assert state["ioc_correlation_status"] == "Failed"
    assert json.loads(state["ioc_correlation_result_json"])["available"] is False


# [FYP-FUNCTION] `test_live_ioc_correlation_not_invoked_by_case_view` — verifies live ioc correlation not invoked by case view behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`, `tmp_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_data_availability`, `_guarded_update`, `_incident`, `_save_run_artifact`, `_triage_result`, `build_case_view`, `dumps`, `save_raw_incident_path`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_live_ioc_correlation_not_invoked_by_case_view(monkeypatch, tmp_path):
    import ioc_correlation

    # [FYP-FUNCTION] `_boom` — implements the boom operation used by the surrounding test and validation workflow.
    # [FYP-INPUT] Parameters: `*a`, `**k`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `AssertionError`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

    def _boom(*a, **k):
        raise AssertionError("case_view must never call correlate_iocs live")

    monkeypatch.setattr(ioc_correlation, "correlate_iocs", _boom)

    run_id = wss.start_run("INC-1")
    incident = _incident("INC-1", alerts=[])
    path = sw._save_run_artifact("INC-1", run_id, "raw_incident.json", "raw_incident",
                                 {"incident": incident, "data_availability":
                                  sw._data_availability(incident)})
    wss.save_raw_incident_path("INC-1", run_id, str(path))
    wss.save_triage_result("INC-1", run_id, _triage_result("INC-1"))
    wss._guarded_update("INC-1", run_id, {
        "ioc_correlation_status": "Complete",
        "ioc_correlation_result_json": json.dumps({"available": True, "results": []}),
    })
    result = cv.build_case_view("INC-1", run_id)
    assert result["incident_id"] == "INC-1"   # completed without calling correlate_iocs


# ══════════════════════════════════════════════════════════════════════════
# case_view.py — MITRE markdown parser
# ══════════════════════════════════════════════════════════════════════════

_MITRE_TABLE = (
    "| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | "
    "MITRE Technique Name | MITRE ID |\n"
    "| --- | --- | --- | --- | --- |\n"
    "| Lateral movement | SSH login to SERVER-02 | Lateral Movement | "
    "Remote Services: SSH | T1021.004 |\n"
)


# [FYP-FUNCTION] `test_mitre_markdown_parser_extracts_rows` — verifies mitre markdown parser extracts rows behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_parse_mitre_markdown_table`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_mitre_markdown_parser_extracts_rows():
    mappings, warnings = cv._parse_mitre_markdown_table(_MITRE_TABLE)
    assert warnings == []
    assert mappings == [{
        "tactic": "Lateral Movement", "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "evidence": ["SSH login to SERVER-02"],
        "timeline_phase": "Lateral movement",
        "origin": "investigation_agent_suggestion", "source": "investigation_agent",
    }]


# [FYP-FUNCTION] `test_mitre_markdown_parser_survives_reordered_columns` — verifies mitre markdown parser survives reordered columns behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_parse_mitre_markdown_table`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_mitre_markdown_parser_survives_reordered_columns():
    table = (
        "| MITRE ID | MITRE Technique Name | MITRE Tactic | Observed Evidence | "
        "Timeline Phase / Activity |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| T1071 | Application Layer Protocol | Command and Control | "
        "C2 beacon over HTTPS | C2 |\n"
    )
    mappings, warnings = cv._parse_mitre_markdown_table(table)
    assert warnings == []
    assert mappings[0]["technique_id"] == "T1071"
    assert mappings[0]["tactic"] == "Command and Control"


# [FYP-FUNCTION] `test_mitre_markdown_parser_handles_escaped_pipes` — verifies mitre markdown parser handles escaped pipes behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_parse_mitre_markdown_table`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_mitre_markdown_parser_handles_escaped_pipes():
    table = (
        "| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | "
        "MITRE Technique Name | MITRE ID |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| Initial access | Phishing email with \\| pipe | Initial Access | "
        "Phishing | T1566 |\n"
    )
    mappings, _ = cv._parse_mitre_markdown_table(table)
    assert mappings[0]["evidence"] == ["Phishing email with | pipe"]


# [FYP-FUNCTION] `test_mitre_markdown_parser_handles_missing_row_column` — verifies mitre markdown parser handles missing row column behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_parse_mitre_markdown_table`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_mitre_markdown_parser_handles_missing_row_column():
    table = (
        "| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | "
        "MITRE Technique Name | MITRE ID |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| Execution | | Execution | Command and Scripting Interpreter |\n"
    )
    mappings, _ = cv._parse_mitre_markdown_table(table)
    assert mappings[0]["technique_id"] == ""   # missing column -> "", never raises


# [FYP-FUNCTION] `test_mitre_markdown_parser_returns_empty_for_no_table` — verifies mitre markdown parser returns empty for no table behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_parse_mitre_markdown_table`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_mitre_markdown_parser_returns_empty_for_no_table():
    mappings, warnings = cv._parse_mitre_markdown_table("just some prose, no table here")
    assert mappings == [] and warnings == []


# [FYP-FUNCTION] `test_mitre_reads_investigation_result_not_raw_json` — verifies mitre reads investigation result not raw json behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_data_availability`, `_guarded_update`, `_incident`, `_save_run_artifact`, `_triage_result`, `build_mitre`, `dumps`, `get_state`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_mitre_reads_investigation_result_not_raw_json():
    """Regression guard for the original bug: MITRE mappings must come from
    the persisted investigation_result_json's narrative_report, never from
    raw_json.mitre_mappings (which never contained them)."""
    run_id = wss.start_run("INC-1")
    incident = _incident("INC-1")
    path = sw._save_run_artifact("INC-1", run_id, "raw_incident.json", "raw_incident",
                                 {"incident": incident, "data_availability":
                                  sw._data_availability(incident)})
    wss.save_raw_incident_path("INC-1", run_id, str(path))
    wss.save_triage_result("INC-1", run_id, _triage_result("INC-1"))
    wss._guarded_update("INC-1", run_id, {
        "investigation_status": "Awaiting Approval",
        "investigation_result_json": json.dumps({
            "status": "completed", "severity": "High",
            "narrative_report": _MITRE_TABLE,
        }),
    })
    state = wss.get_state("INC-1")
    result = cv.build_mitre(state, incident, "INC-1", run_id)
    origins = [m["origin"] for m in result["mappings"]]
    assert "investigation_agent_suggestion" in origins


# ══════════════════════════════════════════════════════════════════════════
# case_view.py — Host/User precedence, IOC count, entity graph
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_host_and_user_never_derived_from_narrative_prose` — verifies host and user never derived from narrative prose behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_data_availability`, `_guarded_update`, `_incident`, `_save_run_artifact`, `_triage_result`, `build_overview`, `dumps`, `get_state`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_host_and_user_never_derived_from_narrative_prose():
    run_id = wss.start_run("INC-1")
    incident = _incident("INC-1", alertMeta={
        "AlertTitles": ["Lateral Movement Via SSH - Joseph"],
    })
    path = sw._save_run_artifact("INC-1", run_id, "raw_incident.json", "raw_incident",
                                 {"incident": incident, "data_availability":
                                  sw._data_availability(incident)})
    wss.save_raw_incident_path("INC-1", run_id, str(path))
    wss.save_triage_result("INC-1", run_id, _triage_result("INC-1"))
    wss._guarded_update("INC-1", run_id, {
        "investigation_status": "Awaiting Approval",
        "investigation_result_json": json.dumps({
            "status": "completed", "severity": "High",
            "summary": "Joseph logged into SERVER-02 via SSH.",
            "narrative_report": "The attacker Joseph moved laterally.",
        }),
    })
    state = wss.get_state("INC-1")
    overview = cv.build_overview(state, incident, "INC-1", run_id)
    assert overview["case_context"]["user"]["value"] == "—"
    assert overview["case_context"]["user"]["evidence_status"] == "unavailable"
    assert "Joseph" not in str(overview["case_context"]["host"]["value"])


# [FYP-FUNCTION] `test_ioc_count_dedupes_and_splits_comma_joined_artifact` — verifies ioc count dedupes and splits comma joined artifact behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_incident`, `build_overview`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_ioc_count_dedupes_and_splits_comma_joined_artifact():
    incident = _incident("INC-1", alertMeta={
        "SourceIp": ["10.0.0.5"],
        "DestinationIp": ["10.0.0.6,10.0.0.7", "10.0.0.6"],
    })
    state = {"triage_result_json": None, "threat_intel_status": None,
            "investigation_status": None, "ioc_correlation_status": None,
            "severity": "LOW", "status": "New", "workflow_status": "Processing"}
    overview = cv.build_overview(state, incident, "INC-1", "run-1")
    assert overview["case_context"]["ioc_ip_count"]["value"] == 3


# [FYP-FUNCTION] `test_entity_graph_never_labels_cooccurrence_as_connected_to` — verifies entity graph never labels cooccurrence as connected to behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_incident`, `build_entity_graph`, `get`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_entity_graph_never_labels_cooccurrence_as_connected_to():
    incident = _incident("INC-1", alertMeta={
        "SourceIp": ["10.0.0.5", "10.0.0.9"],
        "DestinationIp": ["10.0.0.6", "10.0.0.7"],
    })
    graph = cv.build_entity_graph(incident, {"alerts_complete": True})
    for edge in graph["edges"]:
        if edge.get("evidence") == ["alertMeta co-occurrence"]:
            assert edge["relation"] == "possibly_related"
            assert edge["relation"] != "connected_to"


# ══════════════════════════════════════════════════════════════════════════
# Sanitized raw Investigation display
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_sanitize_redacts_secret_keys_at_any_depth` — verifies sanitize redacts secret keys at any depth behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `dumps`, `sanitize_investigation_result_for_display`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_sanitize_redacts_secret_keys_at_any_depth():
    result = {"status": "completed", "summary": "ok",
             "subprocess": {"stdout": "normal output",
                            "env": {"OPENAI_API_KEY": "sk-super-secret"}}}
    sanitized = cv.sanitize_investigation_result_for_display(result)
    blob = json.dumps(sanitized, ensure_ascii=False)
    assert "sk-super-secret" not in blob
    assert "«redacted»" in blob


# [FYP-FUNCTION] `test_sanitize_truncates_long_strings_and_total_size` — verifies sanitize truncates long strings and total size behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `len`, `sanitize_investigation_result_for_display`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_sanitize_truncates_long_strings_and_total_size():
    huge = "x" * (cv._MAX_STRING_LEN + 500)
    result = {"status": "completed", "narrative_report": huge}
    sanitized = cv.sanitize_investigation_result_for_display(result)
    assert len(sanitized["narrative_report"]) < len(huge)
    assert "truncated" in sanitized["narrative_report"]


# [FYP-FUNCTION] `test_sanitize_handles_circular_reference_safely` — verifies sanitize handles circular reference safely behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_sanitize_for_display`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_sanitize_handles_circular_reference_safely():
    node: dict = {"status": "completed"}
    node["self"] = node   # cyclic — must not infinite-loop
    sanitized = cv._sanitize_for_display(node)
    assert sanitized["self"] == "«circular reference»"


# [FYP-FUNCTION] `test_sanitize_drops_hidden_reasoning_fields` — verifies sanitize drops hidden reasoning fields behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `dumps`, `sanitize_investigation_result_for_display`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_sanitize_drops_hidden_reasoning_fields():
    result = {"status": "completed", "internal_notes": "private chain of thought"}
    sanitized = cv.sanitize_investigation_result_for_display(result)
    blob = json.dumps(sanitized)
    assert "private chain of thought" not in blob


# ══════════════════════════════════════════════════════════════════════════
# Full-incident completeness metadata
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_data_availability_distinguishes_empty_success_from_unavailable` — verifies data availability distinguishes empty success from unavailable behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_data_availability`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_data_availability_distinguishes_empty_success_from_unavailable():
    empty_success = sw._data_availability({"id": "INC-1", "alerts": []})
    assert empty_success["alerts_complete"] is True
    assert empty_success["alerts_count"] == 0

    fetch_failed = sw._data_availability(
        {"id": "INC-1", "alerts": [], "alerts_fetch_error": "HTTP 500"})
    assert fetch_failed["alerts_complete"] is False

    stripped = sw._data_availability({"id": "INC-1", "_alerts_stripped": 12})
    assert stripped["alerts_complete"] is False
    assert stripped["incident_source"] == "sqlite_slim"


# [FYP-FUNCTION] `test_load_raw_incident_for_run_backward_compatible_with_legacy_artifact` — verifies load raw incident for run backward compatible with legacy artifact behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_incident`, `_save_run_artifact`, `load_data_availability_for_run`, `load_raw_incident_for_run`, `save_raw_incident_path`, `start_run`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_load_raw_incident_for_run_backward_compatible_with_legacy_artifact():
    """Artifacts saved before the data_availability wrapper existed have the
    incident dict directly as the payload — load_raw_incident_for_run must
    still resolve them to the bare incident dict."""
    run_id = wss.start_run("INC-1")
    legacy_incident = _incident("INC-1", alerts=[{"id": "a1"}])
    path = sw._save_run_artifact("INC-1", run_id, "raw_incident.json",
                                 "raw_incident", legacy_incident)
    wss.save_raw_incident_path("INC-1", run_id, str(path))
    reloaded = sw.load_raw_incident_for_run("INC-1", run_id)
    assert reloaded == legacy_incident
    assert sw.load_data_availability_for_run("INC-1", run_id) is None


# [FYP-FUNCTION] `test_missing_full_alerts_produces_visible_warning_not_silent_empty` — verifies missing full alerts produces visible warning not silent empty behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_availability_warning`, `lower`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_missing_full_alerts_produces_visible_warning_not_silent_empty():
    graph_warning = cv._availability_warning({"alerts_complete": False})
    assert "unavailable" in graph_warning.lower()
    assert cv._availability_warning({"alerts_complete": True}) is None


# ══════════════════════════════════════════════════════════════════════════
# Output tab data does not rerun Investigation
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `test_build_case_view_never_calls_investigation_stage_functions` — verifies build case view never calls investigation stage functions behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: `monkeypatch`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_data_availability`, `_incident`, `_save_run_artifact`, `_triage_result`, `build_case_view`, `save_raw_incident_path`, `save_triage_result`, `setattr`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_build_case_view_never_calls_investigation_stage_functions(monkeypatch):
    # [FYP-FUNCTION] `_boom` — implements the boom operation used by the surrounding test and validation workflow.
    # [FYP-INPUT] Parameters: `*a`, `**k`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `AssertionError`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

    def _boom(*a, **k):
        raise AssertionError("build_case_view must be read-only")

    monkeypatch.setattr(sw, "run_investigation_stage", _boom)
    monkeypatch.setattr(sw, "investigate_with_feedback", _boom)

    run_id = wss.start_run("INC-1")
    incident = _incident("INC-1")
    path = sw._save_run_artifact("INC-1", run_id, "raw_incident.json", "raw_incident",
                                 {"incident": incident, "data_availability":
                                  sw._data_availability(incident)})
    wss.save_raw_incident_path("INC-1", run_id, str(path))
    wss.save_triage_result("INC-1", run_id, _triage_result("INC-1"))
    result = cv.build_case_view("INC-1", run_id)
    assert result["incident_id"] == "INC-1"


# [FYP-FUNCTION] `test_build_case_view_rejects_stale_run_id` — verifies build case view rejects stale run id behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `any`, `build_case_view`, `start_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_build_case_view_rejects_stale_run_id():
    run_id = wss.start_run("INC-1")
    result = cv.build_case_view("INC-1", "some-other-run-id-entirely")
    assert result["run_id"] == "some-other-run-id-entirely"
    assert any("does not match" in w for w in result["warnings"])
