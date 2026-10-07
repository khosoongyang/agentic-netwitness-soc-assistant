"""tests/test_triage_approval_attempt_r5.py -- canonical audit R5.

A Triage approval/rejection is bound to the exact Triage execution attempt it
decided: workflow_approvals.stage_attempt == incidents.triage_attempt at
commit time (read inside the decision's own transaction). Readiness, the
Phase 4 approval_context and available_actions only accept a decision on
(case, run, stage="triage", CURRENT triage_attempt); older attempts' and
other runs'/cases' decisions are history only. A stale decision made for an
older attempt is refused (STALE_ATTEMPT / approval_stage_attempt_mismatch),
never re-bound to the newer attempt.

Real state_store transitions and commands on a temporary workflow DB (root
conftest.py + the fixtures below); every sqlite3.connect aimed at the real
soc_db/ directory is redirected and recorded, and every socket connect is
refused. No LLM, no provider calls, no subprocess.
"""
from __future__ import annotations

import importlib.util
import json
import socket
import sqlite3
import sys
from pathlib import Path

import pytest

import canonical_seed as seed
import agents.investigation.skills_sidecar as skills_sidecar
from agents.reporting.reporting import export_context_enhancer as ece
from agents.reporting.reporting.context_builder import build_context
from workflow import commands
from workflow import engine as wf
from workflow import readiness as wr
from workflow import state_store as wss

CASE = "INC-R5-0001"
OTHER = "INC-R5-OTHER"
_REAL_SOC_DB = (Path(wf.ROOT) / "soc_db").resolve()
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_NOOP = lambda *a, **k: None   # noqa: E731 -- commands' executor: never spawn a worker


@pytest.fixture(autouse=True)
def real_db_attempts(tmp_path, monkeypatch):
    """Redirect (and record) any connect aimed at the real soc_db/ directory."""
    attempts: list[str] = []
    real_connect = sqlite3.connect

    def guarded(database, *args, **kwargs):
        text = str(database)
        text = text[5:].split("?", 1)[0] if text.startswith("file:") else text
        try:
            target = Path(text).resolve()
        except Exception:
            target = None
        if target is not None and _REAL_SOC_DB in target.parents:
            attempts.append(str(target))
            redirected = tmp_path / "redirected_soc_db" / target.name
            redirected.parent.mkdir(exist_ok=True)
            kwargs.pop("uri", None)
            return real_connect(str(redirected), *args, **kwargs)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", guarded)
    return attempts


@pytest.fixture(autouse=True)
def network_attempts(monkeypatch):
    attempts: list = []

    def refuse(self, address, *a, **k):
        attempts.append(address)
        raise OSError(f"network disabled in R5 tests: {address!r}")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    return attempts


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch, real_db_attempts, network_attempts):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    monkeypatch.setattr(wf, "PIPELINE_DB_FILE", tmp_path / "pipeline.db")
    monkeypatch.setattr(wf, "_TRUSTED_OUTPUT_ROOT", tmp_path / "trusted")
    monkeypatch.setattr(wf, "REP_DIR", tmp_path / "rep")
    monkeypatch.setattr(skills_sidecar, "build_skills_context", lambda *a, **k: {"available": False})
    monkeypatch.setattr(ece, "enhance_narrative", lambda context: {})        # no LLM path
    with commands._TASKS_LOCK:
        commands._TASKS.clear()
    wss.db_init()
    wf.pipeline_db_init()
    for case in (CASE, OTHER):
        with wss.db_connect() as con:
            con.execute("INSERT OR REPLACE INTO incidents (id, title, raw_json) VALUES (?, ?, ?)",
                        (case, f"Case {case}", json.dumps(_incident(case))))
            con.commit()
    yield
    with commands._TASKS_LOCK:
        commands._TASKS.clear()
    # T: no network, and no real runtime DB was touched. The only soc_db/
    # connect ever seen is agents/triage/soc_triage_agent.py's import-time
    # _ticket_db_init() (pre-existing, outside R5) when the backend app is
    # first imported -- redirected to tmp_path by the guard above.
    assert network_attempts == []
    assert all(Path(a).name == "soc_tickets.db" for a in real_db_attempts), real_db_attempts


# ── canonical builders (real transitions) ──────────────────────────────────

def _incident(case=CASE):
    return {"id": case, "title": f"Case {case}", "alertMeta": {"SourceIp": ["10.0.0.5"]}}


def _triage(case=CASE, run=None):
    return {"ticket": {"incident_id": case, "unc": "#00R5A", "classification": "HIGH", "title": "Case",
                       "incident_category": "Malware", "mitre_tactic": "Execution",
                       "mitre_technique": "T1059.001"},
            "metakeys_payload": {"incident_id": case, "incident_title": "Case"}, "run_id": run}


def _state(case=CASE):
    return wss.get_state(case)


def _new_run(case=CASE):
    run = wss.start_run(case, allow_retry=True)
    seed.seed_parsing_and_raw_incident(case, run, _incident(case))
    wss.set_workflow_status(case, run, "Awaiting Action")
    return run


def _execute_triage(run, case=CASE):
    """One Triage execution exactly as run_triage_stage persists it (claim ->
    complete at Awaiting Approval), minus the LLM. Starts it first when it
    is still Pending; a re-run is already Processing."""
    if _state(case)["triage_status"] == "Pending":
        commands.start_stage(case, "triage", executor=_NOOP)
    worker, attempt = wss.claim_stage(case, run, stage="triage", status_column="triage_status",
                                      expect_status="Processing")
    assert wss.complete_stage(case, run, worker, stage="triage", result_column="triage_result_json",
                              result=_triage(case, run),
                              status_updates={"triage_status": "Awaiting Approval",
                                              "workflow_status": "Awaiting Approval",
                                              "approval_stage": "triage"},
                              expected_stage_attempt=attempt)
    return attempt


def _rerun_triage(run, case=CASE):
    commands.rerun_stage(case, "triage", executor=_NOOP)
    return _execute_triage(run, case)


def _approve(comments="", analyst="alice", **kw):
    return commands.approve_stage(CASE, "triage", analyst=analyst, comments=comments, **kw)


def _reject(comments="needs rework", analyst="carol", **kw):
    return commands.reject_stage(CASE, "triage", analyst=analyst, comments=comments, **kw)


def _rows(run=None, case=CASE):
    return [r for r in wss.get_approval_history(case, run) if r["approval_stage"] == "triage"]


def _ti(**kw):
    return wr.evaluate_stage_readiness(CASE, "threat_intel", **kw)


def _ti_start(state=None):
    """The TI start action; a Blocked TI offers none (reported as disabled)."""
    actions = commands.available_actions(state or _state())["stages"]
    return next((a for a in actions["threat_intel"] if a["type"] == "start"),
                {"type": "start", "enabled": False, "reason_code": None, "absent": True})


def _insert_approval(case, run, stage_attempt, decision="approved", analyst="mallory"):
    """A raw workflow_approvals row (for foreign run/case/historical rows)."""
    with wss.db_connect() as con:
        con.execute(
            "INSERT INTO workflow_approvals (incident_id, run_id, approval_stage, decision, analyst, "
            "comments, decided_at, stage_attempt, approval_attempt) VALUES (?,?,?,?,?,?,?,?,?)",
            (case, run, "triage", decision, analyst, "", "2026-01-01T00:00:00+00:00", stage_attempt, 1))
        con.commit()


def _force_approved_status(run, case=CASE):
    """Status says Approved; only the approval audit trail can satisfy the gate."""
    wss._guarded_update(case, run, {"triage_status": "Approved", "threat_intel_status": "Pending",
                                    "workflow_status": "Awaiting Action", "approval_stage": None})


def _approval_context(run):
    """Run-scoped Reporting handoff -> build_context (as the Reporting agent does)."""
    wf.handoff_to_reporting(_triage(CASE, run), {"id": CASE}, {"incident_id": CASE, "investigated_for": CASE},
                            threat_intel_result={"incident_id": CASE, "status": "completed"},
                            incident_id=CASE, run_id=run, reporting_stage_attempt=1)
    inputs_dir = wf.reporting_attempt_dir(CASE, run, 1) / "inputs"
    read = lambda name: json.loads((inputs_dir / name).read_text(encoding="utf-8"))   # noqa: E731
    ctx = build_context({"approval_history": read("approval_history.json"),
                         "workflow_metadata": read("workflow_metadata.json")})
    return ctx["approval_context"]


# ── A / P: write-time binding, approval_attempt unchanged ──────────────────

def test_a_attempt_1_approval_is_stamped_stage_attempt_1():
    run = _new_run()
    assert _execute_triage(run) == 1
    result = _approve("Looks right")
    assert (result["stage_attempt"], result["approval_attempt"]) == (1, 1)
    [row] = _rows(run)
    assert (row["run_id"], row["stage_attempt"], row["approval_attempt"], row["decision"]) == (run, 1, 1, "approved")
    assert _ti()["ready"] is True


def test_p_approval_attempt_still_counts_decisions_within_one_stage_attempt():
    run = _new_run()
    _execute_triage(run)
    _approve()
    _rerun_triage(run)
    _approve()
    # Each Triage execution's first decision is approval_attempt 1 (the same
    # per-stage_attempt meaning Investigation/Reporting already use).
    assert [(r["stage_attempt"], r["approval_attempt"]) for r in _rows(run)] == [(1, 1), (2, 1)]
    # A second decision on the SAME stage_attempt still collides on the
    # unique index and is refused (nothing re-numbered or overwritten).
    wss._guarded_update(CASE, run, {"triage_status": "Awaiting Approval",
                                    "workflow_status": "Awaiting Approval", "approval_stage": "triage"})
    wss.approve_triage(CASE, run, approved_by="dave")
    assert [(r["stage_attempt"], r["approval_attempt"]) for r in _rows(run)] == [(1, 1), (2, 1), (2, 2)]


# ── B / C: the central rerun regression ───────────────────────────────────

def test_b_c_old_approval_never_authorises_a_rerun_until_the_new_attempt_is_approved():
    run = _new_run()
    _execute_triage(run)
    _approve("attempt 1 ok")
    assert _ti()["ready"] is True

    assert _rerun_triage(run) == 2
    assert _state()["triage_attempt"] == 2
    readiness = _ti()
    assert readiness["ready"] is False and readiness["reason_code"] == "triage_not_approved"
    assert _ti_start()["enabled"] is False
    with pytest.raises(commands.WorkflowCommandError) as locked:
        commands.start_stage(CASE, "threat_intel", executor=_NOOP)
    assert locked.value.code == "STAGE_LOCKED"

    result = _approve("attempt 2 ok")
    assert result["stage_attempt"] == 2
    assert [(r["stage_attempt"], r["comments"]) for r in _rows(run)] == [(1, "attempt 1 ok"), (2, "attempt 2 ok")]
    assert _ti()["ready"] is True
    start = _ti_start()
    assert (start["enabled"], start["reason_code"]) == (True, None)          # L
    commands.start_stage(CASE, "threat_intel", executor=_NOOP)
    assert _state()["threat_intel_status"] == "Processing"


# ── G: only an older attempt's approval exists ─────────────────────────────

def test_g_only_an_older_attempt_approval_does_not_satisfy_readiness():
    run = _new_run()
    _execute_triage(run)
    _approve()
    _rerun_triage(run)
    _force_approved_status(run)        # even if the status column says Approved
    readiness = _ti()
    assert (readiness["reason_code"], readiness["category"]) == ("triage_approval_not_recorded", wr.CATEGORY_APPROVAL)
    assert "attempt 2" in readiness["detail"] and "older attempt" in readiness["detail"]
    start = _ti_start()
    assert (start["enabled"], start["reason_code"]) == (False, "triage_approval_not_recorded")
    with pytest.raises(commands.WorkflowCommandError) as refused:
        commands.start_stage(CASE, "threat_intel", executor=_NOOP)
    assert refused.value.code == "STAGE_NOT_READY"
    assert refused.value.details["reason_code"] == "triage_approval_not_recorded"


# ── D / K: a newer rejection is never overridden by an older approval ──────

def test_d_k_attempt_1_approved_then_attempt_2_rejected_blocks_ti():
    run = _new_run()
    _execute_triage(run)
    _approve()
    _rerun_triage(run)
    _reject("attempt 2 misclassified")
    assert _rows(run)[-1]["stage_attempt"] == 2
    assert _ti()["reason_code"] == "triage_rejected"
    assert _state()["threat_intel_status"] == "Blocked" and _ti_start().get("absent") is True
    # Even if the status column were (wrongly) Approved, the current
    # attempt's rejection still decides.
    _force_approved_status(run)
    readiness = _ti()
    assert (readiness["reason_code"], readiness["category"]) == ("triage_rejected", wr.CATEGORY_APPROVAL)
    assert "attempt 2" in readiness["detail"]
    start = _ti_start()
    assert (start["enabled"], start["reason_code"]) == (False, "triage_rejected")


# ── E: a rejection is not inherited by the re-run ─────────────────────────

def test_e_rejection_of_attempt_1_is_not_inherited_by_attempt_2():
    run = _new_run()
    _execute_triage(run)
    _reject("wrong host")
    _rerun_triage(run)
    state = _state()
    assert (state["triage_status"], state["triage_attempt"]) == ("Awaiting Approval", 2)
    triage_actions = {a["type"]: a for a in commands.available_actions(state)["stages"]["triage"]}
    assert triage_actions["approve"]["enabled"] is True and triage_actions["reject"]["enabled"] is True
    assert triage_actions["approve"]["stage_attempt"] == 2
    assert _ti()["reason_code"] == "triage_not_approved"
    _force_approved_status(run)
    assert _ti()["reason_code"] == "triage_approval_not_recorded"           # not "triage_rejected"
    ctx = _approval_context(run)["triage"]
    assert (ctx["status"], ctx["stage_attempt"], ctx["actor"]) == ("Pending", 2, "Not recorded")
    assert [(p["decision"], p["stage_attempt"], p["comment"]) for p in ctx["previous_decisions"]] == \
        [("Rejected", 1, "wrong host")]


# ── F / M / N / O: approval_context reflects the current attempt ───────────

def test_f_m_n_o_three_approved_attempts_current_is_attempt_3_with_history():
    run = _new_run()
    _execute_triage(run)
    _approve("first look", analyst="alice")
    _rerun_triage(run)
    _approve("second look", analyst="bob")
    _rerun_triage(run)
    _approve("  final: ok  ", analyst="Erin O'Neil")
    rows = _rows(run)
    ctx = _approval_context(run)
    tri = ctx["triage"]
    assert (ctx["case_id"], ctx["run_id"]) == (CASE, run)
    assert (tri["status"], tri["stage_attempt"], tri["approval_attempt"], tri["run_id"]) == ("Approved", 3, 1, run)
    assert (tri["actor"], tri["comment"], tri["timestamp"]) == ("Erin O'Neil", "  final: ok  ", rows[2]["decided_at"])
    assert [(p["decision"], p["actor"], p["comment"], p["stage_attempt"], p["timestamp"])
            for p in tri["previous_decisions"]] == [
        ("Approved", "alice", "first look", 1, rows[0]["decided_at"]),
        ("Approved", "bob", "second look", 2, rows[1]["decided_at"])]


def test_f_mixed_history_approved_rejected_approved():
    run = _new_run()
    _execute_triage(run)
    _approve("ok", analyst="alice")
    _rerun_triage(run)
    _reject("no", analyst="carol")
    _rerun_triage(run)
    _approve("ok again", analyst="dave")
    assert _ti()["ready"] is True
    tri = _approval_context(run)["triage"]
    assert (tri["status"], tri["stage_attempt"], tri["actor"]) == ("Approved", 3, "dave")
    assert [(p["decision"], p["stage_attempt"]) for p in tri["previous_decisions"]] == \
        [("Approved", 1), ("Rejected", 2)]


# ── H / I / J: run and case binding remain ─────────────────────────────────

def test_h_current_attempt_approval_from_another_run_does_not_count():
    run = _new_run()
    _execute_triage(run)
    _approve()
    _rerun_triage(run)
    _insert_approval(CASE, f"{CASE}@other-run", 2)
    _force_approved_status(run)
    assert _ti()["reason_code"] == "triage_approval_not_recorded"


def test_i_current_attempt_approval_from_another_case_does_not_count():
    run = _new_run()
    _execute_triage(run)
    _approve()
    _rerun_triage(run)
    _insert_approval(OTHER, run, 2)
    _force_approved_status(run)
    assert _ti()["reason_code"] == "triage_approval_not_recorded"


def test_j_run_a_attempt_2_approval_never_counts_for_run_b():
    run_a = _new_run()
    _execute_triage(run_a)
    _approve()
    _rerun_triage(run_a)
    _approve()
    assert _ti()["ready"] is True
    run_b = _new_run()                                   # Parsing re-run mints a new run
    assert _state()["triage_attempt"] == 1               # every *_attempt resets with the run
    _execute_triage(run_b)
    assert _ti()["reason_code"] == "triage_not_approved"
    _force_approved_status(run_b)
    assert _ti()["reason_code"] == "triage_approval_not_recorded"
    # Run A's (attempt 2) approval is still history for run A only.
    assert [r["stage_attempt"] for r in _rows(run_a)] == [1, 2] and _rows(run_b) == []
    wss._guarded_update(CASE, run_b, {"triage_status": "Awaiting Approval",
                                      "workflow_status": "Awaiting Approval", "approval_stage": "triage"})
    _approve()
    assert [r["stage_attempt"] for r in _rows(run_b)] == [1] and _ti()["ready"] is True


# ── Historical (pre-R5) rows: interpreted conservatively, never rewritten ──

def test_historical_stage_attempt_1_row_still_counts_for_attempt_1_only():
    run = _new_run()
    _execute_triage(run)
    _insert_approval(CASE, run, 1, analyst="legacy")       # a pre-R5 row (always 1)
    _force_approved_status(run)
    assert _ti()["ready"] is True
    wss._guarded_update(CASE, run, {"triage_attempt": 2})  # Triage was re-run
    assert _ti()["reason_code"] == "triage_approval_not_recorded"
    [row] = _rows(run)
    assert (row["analyst"], row["stage_attempt"]) == ("legacy", 1)   # untouched


# ── 22: stale human action ─────────────────────────────────────────────────

def test_stale_attempt_1_approval_is_refused_once_attempt_2_exists():
    run = _new_run()
    _execute_triage(run)
    opened = next(a for a in commands.available_actions(_state())["stages"]["triage"] if a["type"] == "approve")
    assert opened["stage_attempt"] == 1                   # what the analyst opened
    _rerun_triage(run)                                    # meanwhile Triage re-ran
    before = _state()
    for submit in (_approve, _reject):
        with pytest.raises(commands.WorkflowCommandError) as stale:
            submit(expected_stage_attempt=opened["stage_attempt"])
        assert stale.value.code == "STALE_ATTEMPT"
        assert stale.value.details == {"reason_code": "approval_stage_attempt_mismatch", "stage": "triage",
                                       "expected_stage_attempt": 1, "current_stage_attempt": 2}
    assert _rows(run) == [] and _state() == before        # nothing written, no transition
    # The state-store transaction itself refuses it too (no command pre-check).
    with pytest.raises(wss.ApprovalAttemptMismatchError):
        wss.approve_triage(CASE, run, approved_by="alice", expected_stage_attempt=1)
    assert _rows(run) == []
    # The matching attempt is accepted and stamped from the row, not the client.
    assert _approve(expected_stage_attempt=2)["stage_attempt"] == 2
    assert _ti()["ready"] is True


def test_expected_stage_attempt_is_validated_and_triage_only():
    run = _new_run()
    _execute_triage(run)
    for bad in (0, -1, "x", True):
        with pytest.raises(commands.WorkflowCommandError) as invalid:
            _approve(expected_stage_attempt=bad)
        assert (invalid.value.code, invalid.value.status_code) == ("INVALID_REQUEST", 400)
    with pytest.raises(commands.WorkflowCommandError) as other_stage:
        commands.approve_stage(CASE, "investigation", analyst="a", expected_stage_attempt=1)
    assert other_stage.value.code == "INVALID_REQUEST"
    assert _rows(run) == []
    assert _approve(expected_stage_attempt="1")["stage_attempt"] == 1


def _load_backend():
    package_dir = _PROJECT_ROOT / "backend"
    spec = importlib.util.spec_from_file_location(
        "_aegis_r5_backend", package_dir / "__init__.py", submodule_search_locations=[str(package_dir)])
    module = importlib.util.module_from_spec(spec)
    sys.modules["_aegis_r5_backend"] = module
    spec.loader.exec_module(module)
    return module


def test_api_stale_attempt_conflict_and_unchanged_contract_without_it():
    run = _new_run()
    _execute_triage(run)
    _rerun_triage(run)
    app = _load_backend().create_app({"TESTING": True, "AEGIS_CASE_DB_PATH": wss.DB_FILE,
                                      "AEGIS_CASE_VIEW_BUILDER": lambda *_: {}})
    client = app.test_client()
    stale = client.post(f"/api/cases/{CASE}/approvals/triage",
                        json={"decision": "approve", "analyst": "alice", "expected_stage_attempt": 1})
    assert stale.status_code == 409
    error = stale.get_json()["error"]
    assert error["code"] == "STALE_ATTEMPT"
    assert error["details"]["reason_code"] == "approval_stage_attempt_mismatch"
    assert _rows(run) == []
    ok = client.post(f"/api/cases/{CASE}/approvals/triage", json={"decision": "approve", "analyst": "alice"})
    assert ok.status_code == 200 and ok.get_json()["stage_attempt"] == 2
    assert [r["stage_attempt"] for r in _rows(run)] == [2]
