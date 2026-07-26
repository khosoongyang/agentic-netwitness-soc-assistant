"""
tests/test_threat_intel_workflow.py — Threat Intelligence Enrichment stage:
durable resume, atomic stage claims/leases, honest IOC classification, and
the full Triage -> Threat Intelligence -> Investigation -> Reporting
approval chain.

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

@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """Every test gets its own SQLite file and its own trusted artifact
    root — never touches the real soc_db/ or outputs/ directories."""
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "test_incidents.db")
    monkeypatch.setattr(sw, "_TRUSTED_OUTPUT_ROOT", tmp_path / "artifacts")
    wss.db_init()
    yield


def _triage_result(incident_id: str, **ticket_overrides) -> dict:
    ticket = {"incident_id": incident_id, "unc": "#001", "classification": "high"}
    ticket.update(ticket_overrides)
    return {"ticket": ticket,
           "metakeys_payload": {"incident_id": incident_id, "metakey_values": {}}}


def _incident(incident_id: str = "INC-1") -> dict:
    return {"id": incident_id, "title": "Test incident", "alertMeta": {}}


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


def _approve_triage(incident_id: str, run_id: str) -> None:
    wss.approve_triage(incident_id, run_id, approved_by="tester")


def _save_raw_incident(incident_id: str, run_id: str, incident: dict | None = None) -> None:
    path = sw._save_run_artifact(incident_id, run_id, "raw_incident.json",
                                 "raw_incident", incident or _incident(incident_id))
    wss.save_raw_incident_path(incident_id, run_id, str(path))


# ══════════════════════════════════════════════════════════════════════════
# Approval atomicity
# ══════════════════════════════════════════════════════════════════════════

def test_approve_triage_starts_threat_intel_exactly_once():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    state = wss.get_state("INC-1")
    assert state["threat_intel_status"] == "Processing"
    assert state["triage_status"] == "Approved"
    assert state["workflow_status"] == "Processing"
    assert state["approval_stage"] is None


def test_duplicate_approve_click_raises_conflict():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    with pytest.raises(wss.ApprovalConflictError):
        _approve_triage("INC-1", run_id)


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


def test_rejection_is_atomic_and_blocks_downstream_stage():
    run_id = _start_and_reach_triage_approval("INC-1")
    wss.reject_triage("INC-1", run_id, rejected_by="tester", reason="not real")
    state = wss.get_state("INC-1")
    assert state["triage_status"] == "Rejected"
    assert state["threat_intel_status"] == "Blocked"
    assert state["workflow_status"] == "Rejected"
    with pytest.raises(wss.ApprovalConflictError):
        wss.reject_triage("INC-1", run_id, rejected_by="tester", reason="again")


def test_investigation_approval_routes_to_reporting_not_workflow_complete():
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {
        "workflow_status": "Awaiting Approval", "approval_stage": "investigation",
        "investigation_status": "Awaiting Approval"})
    wss.approve_investigation("INC-1", run_id, approved_by="tester")
    state = wss.get_state("INC-1")
    assert state["investigation_status"] == "Approved"
    assert state["reporting_status"] == "Processing"
    assert state["workflow_status"] == "Processing"
    assert state["workflow_status"] != "Complete"


def test_reporting_approval_is_required_for_workflow_complete():
    run_id = wss.start_run("INC-1")
    wss._guarded_update("INC-1", run_id, {
        "workflow_status": "Awaiting Approval", "approval_stage": "reporting",
        "reporting_status": "Awaiting Approval"})
    assert wss.get_state("INC-1")["workflow_status"] != "Complete"
    wss.approve_reporting("INC-1", run_id, approved_by="tester")
    state = wss.get_state("INC-1")
    assert state["reporting_status"] == "Approved"
    assert state["workflow_status"] == "Complete"


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


def test_approval_functions_do_not_start_threads_or_import_soc_workflow():
    src = (ROOT / "workflow_state_store.py").read_text(encoding="utf-8")
    assert "threading.Thread" not in src
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any(a.name == "soc_workflow" for a in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module != "soc_workflow"


def test_worker_never_touches_streamlit():
    src = (ROOT / "soc_workflow.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any(a.name == "streamlit" for a in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module != "streamlit"


# ══════════════════════════════════════════════════════════════════════════
# Stage claim / lease
# ══════════════════════════════════════════════════════════════════════════

def test_two_resume_actions_cannot_claim_the_same_stage():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    sw.claim_stage("INC-1", run_id, stage="threat_intel",
                   status_column="threat_intel_status", expect_status="Processing")
    with pytest.raises(sw.StageClaimError):
        sw.claim_stage("INC-1", run_id, stage="threat_intel",
                       status_column="threat_intel_status", expect_status="Processing")


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


def test_valid_heartbeat_prevents_false_interrupted_warning():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    sw.claim_stage("INC-1", run_id, stage="threat_intel",
                   status_column="threat_intel_status", expect_status="Processing")
    state = wss.get_state("INC-1")
    lease = state["worker_lease_expires_at"]
    assert lease and datetime.fromisoformat(lease) > datetime.now(timezone.utc)


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


def test_stage_result_and_status_transition_are_committed_atomically():
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    worker_id, _ = sw.claim_stage("INC-1", run_id, stage="threat_intel",
                                  status_column="threat_intel_status",
                                  expect_status="Processing")

    real_tx = wss._tx

    def _boom(fn):
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

def test_full_incident_reloadable_after_session_loss():
    run_id = wss.start_run("INC-1")
    incident = _incident("INC-1")
    _save_raw_incident("INC-1", run_id, incident)
    # "session loss" — nothing but incident_id/run_id survives.
    reloaded = sw.load_raw_incident_for_run("INC-1", run_id)
    assert reloaded == incident


def test_raw_incident_artifact_rejects_mismatched_run_id():
    run_id = wss.start_run("INC-1")
    _save_raw_incident("INC-1", run_id)
    assert sw.load_raw_incident_for_run("INC-1", "some-other-run-id") is None


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

def _mock_vt_and_abuseipdb_absent(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)


def test_resume_after_triage_approval_survives_fresh_state_reload(monkeypatch):
    _mock_vt_and_abuseipdb_absent(monkeypatch)
    run_id = _start_and_reach_triage_approval("INC-1")
    _save_raw_incident("INC-1", run_id)
    _approve_triage("INC-1", run_id)
    result = sw.resume_after_triage_approval("INC-1", run_id)
    assert result["status"] in ("completed", "completed_with_warnings")
    state = wss.get_state("INC-1")
    assert state["threat_intel_status"] in ("Complete", "Complete with Warnings")
    assert state["investigation_status"] == "Processing"


def test_new_process_can_resume_using_only_persisted_state(monkeypatch):
    """Simulates a fresh process: only incident_id/run_id are known, no
    shared in-memory object from the approval call."""
    _mock_vt_and_abuseipdb_absent(monkeypatch)
    run_id = _start_and_reach_triage_approval("INC-1")
    _save_raw_incident("INC-1", run_id)
    _approve_triage("INC-1", run_id)
    incident_id, run_id_copy = "INC-1", str(run_id)
    del run_id
    result = sw.resume_after_triage_approval(incident_id, run_id_copy)
    assert result["status"] in ("completed", "completed_with_warnings")


def test_resume_rejects_stale_run_id(monkeypatch):
    _mock_vt_and_abuseipdb_absent(monkeypatch)
    run_id = _start_and_reach_triage_approval("INC-1")
    _approve_triage("INC-1", run_id)
    # The run_id/status guard lives in _claim_stage() (raises StageClaimError) —
    # ThreatIntelValidationError is reserved for a triage_result whose OWN
    # embedded incident_id doesn't match (see
    # test_threat_intel_validation_error_on_incident_id_mismatch). Both close
    # the same "never resume a stale/mismatched run" requirement.
    with pytest.raises(sw.StageClaimError):
        sw.resume_after_triage_approval("INC-1", "stale-run-id")


def test_threat_intel_validation_error_on_incident_id_mismatch():
    mismatched_triage = _triage_result("INC-OTHER")
    with pytest.raises(sw.ThreatIntelValidationError):
        sw.run_threat_intel(incident_id="INC-1", run_id="r1",
                            normalised_alert=None, triage_result=mismatched_triage)


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


def test_frontend_polling_stops_at_approval_or_terminal_state():
    for terminal in ("Awaiting Approval", "Failed", "Rejected", "Complete"):
        assert terminal != "Processing"   # the polling loop's only trigger condition


# ══════════════════════════════════════════════════════════════════════════
# Failure handling
# ══════════════════════════════════════════════════════════════════════════

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
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    wss.retry_threat_intel("INC-1", run_id)
    sw.run_stage_chain("INC-1", run_id)

    state = wss.get_state("INC-1")
    assert state["threat_intel_status"] in ("Complete", "Complete with Warnings")
    fake_run_investigation_stage.assert_called_once_with("INC-1", run_id)


def test_retry_continues_to_investigation_exactly_once(monkeypatch):
    run_id = _start_and_reach_triage_approval("INC-1")
    _save_raw_incident("INC-1", run_id)
    _approve_triage("INC-1", run_id)
    with wss.db_connect() as con:
        con.execute("UPDATE incidents SET threat_intel_status='Failed' WHERE id=?", ("INC-1",))
        con.commit()
    fake_inv = Mock(return_value={"status": "awaiting_approval"})
    monkeypatch.setattr(sw, "run_investigation_stage", fake_inv)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    wss.retry_threat_intel("INC-1", run_id)
    sw.run_stage_chain("INC-1", run_id)
    assert fake_inv.call_count == 1


# ══════════════════════════════════════════════════════════════════════════
# Threat Intelligence: honest classification / no fabrication
# ══════════════════════════════════════════════════════════════════════════

def test_no_findings_is_not_labelled_benign(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    incident = {"alertMeta": {"DestinationIp": ["8.8.8.8"]}}
    triage_result = _triage_result("INC-1")

    fake_resp = Mock(status_code=200)
    fake_resp.json.return_value = {"status": "success", "country": "US", "as": "AS1",
                                   "isp": "x", "proxy": False, "hosting": False}
    fake_resp.raise_for_status = Mock()
    with patch("requests.get", return_value=fake_resp), \
         patch("socket.gethostbyaddr", side_effect=OSError("no ptr")):
        result = sw.run_threat_intel(incident_id="INC-1", run_id="r1",
                                     normalised_alert=None, triage_result=triage_result,
                                     incident=incident)
    assert "benign_iocs" not in result
    assert "no_findings_iocs" in result
    for r in result["iocs"]:
        assert r["verdict"] != "BENIGN"


def test_lookup_failed_requires_all_applicable_sources_to_fail(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-vt-key")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    incident = {"alertMeta": {"DestinationIp": ["8.8.8.8"]}}
    triage_result = _triage_result("INC-1")

    def _fake_get(url, *a, **kw):
        if "ip-api.com" in url:
            raise __import__("requests").exceptions.Timeout("timed out")
        r = Mock(status_code=200)
        r.raise_for_status = Mock()
        r.json.return_value = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}
        return r

    with patch("requests.get", side_effect=_fake_get), \
         patch("socket.gethostbyaddr", side_effect=OSError("no ptr")):
        result = sw.run_threat_intel(incident_id="INC-1", run_id="r1",
                                     normalised_alert=None, triage_result=triage_result,
                                     incident=incident)
    assert result["lookup_failed_iocs"] == []
    assert any("at least one source fail" in w for w in result["warnings"])


def test_missing_api_keys_produce_warnings_not_fabricated_results(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    incident = {"alertMeta": {"DestinationIp": ["8.8.8.8"]}}
    triage_result = _triage_result("INC-1")
    fake_resp = Mock(status_code=200)
    fake_resp.raise_for_status = Mock()
    fake_resp.json.return_value = {"status": "success", "country": "US", "as": "AS1",
                                   "isp": "x", "proxy": False, "hosting": False}
    with patch("requests.get", return_value=fake_resp), \
         patch("socket.gethostbyaddr", side_effect=OSError("no ptr")):
        result = sw.run_threat_intel(incident_id="INC-1", run_id="r1",
                                     normalised_alert=None, triage_result=triage_result,
                                     incident=incident)
    assert any("VT_API_KEY" in w for w in result["warnings"])
    assert any("ABUSEIPDB_API_KEY" in w for w in result["warnings"])
    for r in result["iocs"]:
        assert "virustotal" not in r["sources"]
        assert "abuseipdb" not in r["sources"]


def test_partial_source_failure_yields_completed_with_warnings(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    incident = {"alertMeta": {"DestinationIp": ["8.8.8.8"]}}
    triage_result = _triage_result("INC-1")
    with patch("requests.get", side_effect=OSError("network down")), \
         patch("socket.gethostbyaddr", side_effect=OSError("no ptr")):
        result = sw.run_threat_intel(incident_id="INC-1", run_id="r1",
                                     normalised_alert=None, triage_result=triage_result,
                                     incident=incident)
    assert result["status"] == "completed_with_warnings"


def test_run_threat_intel_receives_correct_parsing_triage_and_incident_inputs(monkeypatch):
    """extract_iocs (via enrich_iocs) should see IOCs from BOTH the
    normalised alert's processed_alert and the raw incident's alertMeta."""
    incident = {"alertMeta": {"DestinationIp": ["8.8.4.4"]}}
    triage_result = _triage_result("INC-1")
    normalised_alert = {"processed_alert": {"domain": "example.com",
                                            "source_ip": "1.2.3.4"}}
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    fake_resp = Mock(status_code=200)
    fake_resp.raise_for_status = Mock()
    fake_resp.json.return_value = {"status": "success"}
    with patch("requests.get", return_value=fake_resp), \
         patch("socket.gethostbyaddr", side_effect=OSError("no ptr")), \
         patch("socket.getaddrinfo", side_effect=OSError("no resolve")):
        result = sw.run_threat_intel(incident_id="INC-1", run_id="r1",
                                     normalised_alert=normalised_alert,
                                     triage_result=triage_result, incident=incident)
    values = {r["value"] for r in result["iocs"]}
    assert "example.com" in values
    assert "1.2.3.4" in values
    assert "8.8.4.4" in values


def test_private_ips_and_behavioral_iocs_are_retained_not_reported_missing(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    incident = {
        "alertMeta": {
            "DestinationIp": ["192.168.50.50", "192.168.50.54"],
            "SourceIp": ["192.168.50.52"],
        }
    }
    triage_result = _triage_result("INC-1", matched_ioc_count=3)
    triage_result["metakeys_payload"]["metakey_values"] = {
        "ip.dst": ["192.168.50.50,192.168.50.54"],
        "ip.src": "192.168.50.52",
    }
    triage_result["trace"] = [{
        "step": "IOC Checklist",
        "total_ioc_count": 3,
        "per_category": {
            "confidentiality": {
                "matched_ioc_names": ["Unknown traffic"],
            },
            "integrity": {
                "matched_ioc_names": [
                    "Odd device behaviour",
                    "Unexplained privileged-account changes",
                ],
            },
        },
    }]

    result = sw.run_threat_intel(
        incident_id="INC-1",
        run_id="r1",
        normalised_alert=None,
        triage_result=triage_result,
        incident=incident,
    )

    assert result["iocs"] == []
    assert [ioc["value"] for ioc in result["internal_iocs"]] == [
        "192.168.50.50",
        "192.168.50.54",
        "192.168.50.52",
    ]
    assert result["triage_behavioral_indicators"] == {
        "count": 3,
        "names": [
            "Unknown traffic",
            "Odd device behaviour",
            "Unexplained privileged-account changes",
        ],
        "disposition": "retained_for_investigation",
    }
    warning = " ".join(result["warnings"])
    assert "No externally enrichable IOCs" in warning
    assert "retained for Investigation" in warning
    assert "No IOCs found" not in warning
    assert result["thinking_process"]["private_internal_ips_retained"] == 3
    assert result["thinking_process"]["triage_behavioral_indicators"] == 3


def test_investigation_receives_persisted_threat_intel_result(monkeypatch):
    run_id = _start_and_reach_triage_approval("INC-1")
    _save_raw_incident("INC-1", run_id)
    _approve_triage("INC-1", run_id)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    fake_resp = Mock(status_code=200)
    fake_resp.raise_for_status = Mock()
    fake_resp.json.return_value = {"status": "success"}
    with patch("requests.get", return_value=fake_resp), \
         patch("socket.gethostbyaddr", side_effect=OSError("no ptr")):
        sw.resume_after_triage_approval("INC-1", run_id)

    captured = {}

    def _fake_investigate_with_feedback(triage_result, incident, incident_id,
                                        threat_intel_result=None, **kw):
        captured["threat_intel_result"] = threat_intel_result
        return {"status": "completed", "incident_folder": "x"}

    monkeypatch.setattr(sw, "investigate_with_feedback", _fake_investigate_with_feedback)
    sw.run_investigation_stage("INC-1", run_id)

    saved_ti = json.loads(wss.get_state("INC-1")["threat_intel_result_json"])
    assert captured["threat_intel_result"] == saved_ti


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
