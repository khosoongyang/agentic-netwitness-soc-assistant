"""tests/test_e2e_canonical_workflow.py -- canonical audit Phase 8.

One complete canonical workflow, end to end, through the REAL durable stage
workers, readiness, state-store transitions, approvals and the Reporting
attempt workspace:

    Parsing -> Triage -> Triage approval -> Threat Intelligence ->
    Investigation -> Investigation approval -> Reporting -> Reporting approval

plus the attempt invariants (an Investigation re-run waits for a NEW
approval; a rejected Reporting attempt is replaced by attempt 2) and the
fail-closed paths.

Real: Parsing (parser + Phase 5 validation), all stage workers, readiness,
commands, state store, TI (run_threat_intel with provider keys BLANK, so every
provider deterministically reports "missing key" -- no network), the Reporting
handoff / verification / approval.
Stubbed only at the external seams: the Triage LLM agent (run_triage), the
Investigation agent (investigate_with_feedback), the NetWitness fetch, the AI
summaries, and the Reporting/export subprocesses (fake scripts that read only
their attempt inputs). Temporary DBs and roots throughout; the IOC-correlation
snapshot is pointed at non-existent temporary DBs; sqlite3.connect aimed at
the real soc_db/ is redirected and recorded.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest

from agents.reporting import reporting_approval as ra
from test_reporting_workspace_isolation import FAKE_EXPORT, FAKE_RUN_REPORTING
from workflow import commands
from workflow import engine as wf
from workflow import readiness as wr
from workflow import state_store as wss

CASE = "INC-P8-E2E"
OTHER = "INC-P8-OTHER"
_REAL_SOC_DB = (Path(wf.ROOT) / "soc_db").resolve()
_PROVIDER_KEYS = ("VT_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY", "OPENAI_API_KEY",
                  "NETWITNESS_TOKEN", "NW_PASSWORD")


def _incident(case=CASE):
    # A bare NetWitness incident record WITHOUT an alerts list (see the
    # Phase 8 report: a record carrying alerts currently fails Parsing's
    # identity guard -- a known production bug, deliberately not exercised).
    return {"id": case, "title": "Suspicious PowerShell download on HOST-07", "severity": "High",
            "riskScore": 82, "created": "2026-10-04T08:00:00Z",
            "alertMeta": {"SourceIp": ["10.0.0.5"], "DestinationIp": ["203.0.113.45"],
                          "HostName": ["HOST-07"], "UserName": ["jdoe"]}}


# ── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def real_db_attempts(tmp_path, monkeypatch):
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


@pytest.fixture()
def e2e(tmp_path, monkeypatch, real_db_attempts):
    from agents.investigation.tools import ioc_correlation

    root = Path(tempfile.mkdtemp(prefix="p8-"))
    rep = root / "rep"
    (rep / "adapters").mkdir(parents=True)
    (rep / "adapters" / "run_reporting.py").write_text(FAKE_RUN_REPORTING, encoding="utf-8")
    (rep / "adapters" / "export_documents.py").write_text(FAKE_EXPORT, encoding="utf-8")
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    monkeypatch.setattr(wf, "PIPELINE_DB_FILE", tmp_path / "pipeline.db")
    monkeypatch.setattr(wf, "_TRUSTED_OUTPUT_ROOT", root / "t")
    monkeypatch.setattr(ra, "_TRUSTED_OUTPUT_ROOT", root / "t")
    monkeypatch.setattr(wf, "REP_DIR", rep)
    for name in ("_INCIDENTS_DB", "_PIPELINE_DB", "_TICKETS_DB"):
        monkeypatch.setattr(ioc_correlation, name, root / "absent" / f"{name}.db")
    for key in _PROVIDER_KEYS:
        monkeypatch.setenv(key, "")
    monkeypatch.setenv("FAKE_EXPORT_MODE", "ok")
    monkeypatch.delenv("FAKE_RESULT_CASE", raising=False)
    monkeypatch.delenv("REPORTING_WORKSPACE_MODE", raising=False)
    for fn in ("generate_parsing_ai_summary", "generate_triage_ai_summary", "generate_stage_ai_summary"):
        monkeypatch.setattr(wf, fn, lambda *a, **k: {})
    monkeypatch.setattr(wf, "enrich_incident_with_apiretrieval_fetch", lambda incident, **k: incident)

    calls: dict[str, list] = {"triage": [], "investigation": [], "reconcile": []}

    def fake_triage(incident, progress_fn=None, *, force=False, parsed_context=None, **kwargs):
        case = str(incident.get("id"))
        calls["triage"].append({"case": case, "parsed_context": parsed_context})
        return {"ticket": {"incident_id": case, "unc": "#00777A", "classification": "HIGH",
                           "title": incident.get("title"), "summary": "PowerShell download cradle.",
                           "mitre_tactic": "Execution", "mitre_technique": "T1059.001",
                           "risk_rating": "High", "created_at": "2026-10-04T08:05:00Z"},
                "metakeys_payload": {"incident_id": case, "incident_title": incident.get("title"),
                                     "ioc_summary": "203.0.113.45"},
                "trace": [], "used_parsed_context": parsed_context is not None}

    def fake_investigate(triage_result, incident, inc_id, **kwargs):
        calls["investigation"].append({"case": inc_id, "ti": kwargs.get("threat_intel_result"),
                                       "parsing": kwargs.get("parsing_result")})
        return {"agent": "Investigation Agent", "status": "completed", "incident_id": inc_id,
                "investigated_for": inc_id, "severity": "High", "confidence": "Medium",
                "summary": f"Investigation of {inc_id}: download cradle confirmed.",
                "findings": ["HOST-07 executed an encoded PowerShell command."],
                "workflow": {"investigation_source": "agent"}}

    monkeypatch.setattr(wf, "run_triage", fake_triage)
    monkeypatch.setattr(wf, "investigate_with_feedback", fake_investigate)
    monkeypatch.setattr(wf, "reconcile_incident_severity",
                        lambda *a, **k: calls["reconcile"].append(a))
    with commands._TASKS_LOCK:
        commands._TASKS.clear()
    wss.db_init()
    wf.pipeline_db_init()
    for case in (CASE, OTHER):
        with wss.db_connect() as con:
            con.execute("INSERT OR REPLACE INTO incidents (id, title, raw_json) VALUES (?, ?, ?)",
                        (case, f"Case {case}", json.dumps(_incident(case))))
            con.commit()
    yield {"root": root, "rep": rep, "calls": calls, "monkeypatch": monkeypatch}
    with commands._TASKS_LOCK:
        commands._TASKS.clear()
    shutil.rmtree(root, ignore_errors=True)


# ── drivers (real transitions; workers run synchronously) ───────────────────

def _noop(*_a, **_k):
    return None


def _state(case=CASE):
    return wss.get_state(case)


def _parse(case=CASE, *, allow_retry=False):
    ctx = wf.run_until_triage_approval(_incident(case), parsing_only=True, allow_retry=allow_retry)
    assert ctx["stages"]["parsing"] != "failed", ctx.get("errors")
    return _state(case)["run_id"]


def _start(stage, case=CASE, *, rerun=False):
    return (commands.rerun_stage if rerun else commands.start_stage)(case, stage, executor=_noop)


def _triage(run, case=CASE):
    _start("triage", case)
    return wf.run_triage_stage(case, run)


def _ti(run, case=CASE):
    _start("threat_intel", case)
    return wf.resume_after_triage_approval(case, run)


def _investigate(run, case=CASE, *, rerun=False):
    _start("investigation", case, rerun=rerun)
    return wf.run_investigation_stage(case, run)


def _report(run, case=CASE, *, rerun=False):
    _start("reporting", case, rerun=rerun)
    return wf.run_reporting_stage(case, run)


def _approve(stage, analyst, comments="", case=CASE):
    return commands.approve_stage(case, stage, analyst=analyst, comments=comments)


def _through_investigation_approval(case=CASE):
    run = _parse(case)
    _triage(run, case)
    _approve("triage", "Alice", "Ticket accurate", case)
    _ti(run, case)
    _investigate(run, case)
    _approve("investigation", "Bob", "Scope confirmed", case)
    return run


def _json(state, column):
    return json.loads(state[column] or "null")


def _not_ready(stage, code, case=CASE):
    r = wr.evaluate_stage_readiness(case, stage)
    assert (r["ready"], r["reason_code"]) == (False, code), r
    with pytest.raises(commands.WorkflowCommandError) as exc:
        _start(stage, case)
    assert exc.value.details["reason_code"] == code
    assert exc.value.code in ("STAGE_NOT_READY", "STAGE_LOCKED")
    return exc.value


# ── 9-12: the happy path, with case / run / attempt identity at every step ──

def test_canonical_workflow_end_to_end(e2e, real_db_attempts):
    calls = e2e["calls"]

    # Parsing
    run = _parse()
    s = _state()
    assert (s["run_id"], s["parsing_status"], s["triage_status"]) == (run, "Complete", "Pending")
    parsing = wf.load_parsing_result_for_run(CASE, run)
    assert parsing["incident_id"] == CASE and parsing["run_id"] == run
    assert parsing["case_identity"]["status"] == "match"
    assert isinstance(parsing["normalised_alert"], dict) and isinstance(parsing["processed_alert"], dict)
    assert "alert_summary" in parsing["normalised_alert"]                     # structured
    assert not isinstance(parsing["processed_alert"].get("alert_summary"), dict)  # flat
    raw = wf.load_raw_incident_for_run(CASE, run)
    assert raw["id"] == CASE

    # Triage (attempt 1) -> Awaiting Approval, run-bound, fed the canonical Parsing
    _triage(run)
    s = _state()
    assert (s["triage_status"], s["workflow_status"], s["approval_stage"], s["triage_attempt"]) \
        == ("Awaiting Approval", "Awaiting Approval", "triage", 1)
    triage = _json(s, "triage_result_json")
    assert (triage["ticket"]["incident_id"], triage["run_id"]) == (CASE, run)
    assert calls["triage"] == [{"case": CASE, "parsed_context": parsing["processed_alert"]}]
    _not_ready("threat_intel", "triage_not_approved")

    # Triage approval
    _approve("triage", "Alice", "Ticket accurate")
    s = _state()
    assert (s["triage_status"], s["threat_intel_status"]) == ("Approved", "Pending")

    # Threat Intelligence (real, providers without keys)
    _ti(run)
    s = _state()
    assert s["threat_intel_status"] in ("Complete", "Complete with Warnings")
    assert s["investigation_status"] == "Pending" and s["threat_intel_attempt"] == 1
    ti = _json(s, "threat_intel_result_json")
    assert (ti["incident_id"], ti["run_id"]) == (CASE, run)

    # Investigation attempt 1 -> approved
    _investigate(run)
    s = _state()
    assert (s["investigation_status"], s["investigation_attempt"]) == ("Awaiting Approval", 1)
    inv = _json(s, "investigation_result_json")
    assert (inv["incident_id"], inv["investigated_for"], inv["run_id"]) == (CASE, CASE, run)
    seen = calls["investigation"][-1]
    assert seen["case"] == CASE and seen["ti"]["run_id"] == run
    assert seen["parsing"]["processed_alert"] == parsing["processed_alert"]
    _not_ready("reporting", "investigation_not_approved")
    _approve("investigation", "Bob", "Scope confirmed")

    # Investigation attempt 2 -> Pending again: Reporting must NOT run
    _investigate(run, rerun=True)
    s = _state()
    assert (s["investigation_status"], s["investigation_attempt"]) == ("Awaiting Approval", 2)
    _not_ready("reporting", "investigation_not_approved")
    _approve("investigation", "Bob", "Re-run confirmed")
    assert wr.evaluate_stage_readiness(CASE, "reporting")["ready"] is True

    # Reporting attempt 1 -> rejected
    first = _report(run)
    s = _state()
    assert (s["reporting_status"], s["reporting_attempt"]) == ("Awaiting Approval", 1)
    assert first["incident_id"] == CASE and first["run_id"] == run and first["candidate_manifest_check"]["ok"]
    commands.reject_stage(CASE, "reporting", analyst="Carol", comments="Executive summary unclear")
    assert _state()["reporting_status"] == "Rejected"

    # Reporting attempt 2 -> its own workspace/candidate -> approved
    second = _report(run, rerun=True)
    s = _state()
    assert (s["reporting_status"], s["reporting_attempt"]) == ("Awaiting Approval", 2)
    a2 = wf.reporting_attempt_dir(CASE, run, 2)
    m2 = Path(second["document_exports"]["candidate_manifest_path"])
    assert a2.resolve() in m2.resolve().parents
    meta = json.loads((a2 / "inputs" / "workflow_metadata.json").read_text(encoding="utf-8"))
    assert (meta["incident_id"], meta["run_id"], meta["reporting_stage_attempt"]) == (CASE, run, 2)
    assert meta["investigation_attempt"] == 2
    history = json.loads((a2 / "inputs" / "approval_history.json").read_text(encoding="utf-8"))
    assert {h["run_id"] for h in history} == {run} and {h["incident_id"] for h in history} == {CASE}
    assert ra.current_attempt_materialised_set(CASE, run, 2) is None
    _approve("reporting", "Dana", "Final")

    s = _state()
    assert (s["reporting_status"], s["workflow_status"], s["approval_stage"]) == ("Approved", "Complete", None)
    approved = wss.get_latest_approved_reporting_set(CASE, run)
    assert approved["reporting_stage_attempt"] == 2
    assert approved["report_set_id"] == second["candidate_manifest_check"]["report_set_id"]

    # 10/11: one primary case and one run across every canonical record
    decisions = wss.get_approval_history(CASE, run)
    assert [(d["approval_stage"], d["decision"]) for d in decisions] == [
        ("triage", "approved"), ("investigation", "approved"), ("investigation", "approved"),
        ("reporting", "rejected"), ("reporting", "approved")]
    assert {d["run_id"] for d in decisions} == {run} and {d["incident_id"] for d in decisions} == {CASE}
    inv_attempts = [d["stage_attempt"] for d in decisions if d["approval_stage"] == "investigation"]
    assert inv_attempts == [1, 2]
    rep_attempts = [d["stage_attempt"] for d in decisions if d["approval_stage"] == "reporting"]
    assert rep_attempts == [1, 2]
    cases = {parsing["incident_id"], triage["ticket"]["incident_id"], ti["incident_id"],
             _json(s, "investigation_result_json")["investigated_for"], meta["incident_id"]}
    assert cases == {CASE}
    runs = {parsing["run_id"], triage["run_id"], ti["run_id"], _json(s, "investigation_result_json")["run_id"],
            meta["run_id"]}
    assert runs == {run}
    assert e2e["calls"]["reconcile"] == []          # never reached the real ticket DB writer
    assert _json(s, "reporting_result_json")["incident_id"] == CASE
    assert real_db_attempts == []                     # never touched the real soc_db/


# ── 21: re-run invalidation map ─────────────────────────────────────────────

def test_rerun_invalidation_map(e2e):
    run = _through_investigation_approval()
    _report(run)

    # Investigation re-run: clears its result + downstream Reporting, new attempt
    wss.rerun_stage(CASE, run, "investigation")
    s = _state()
    assert (s["investigation_status"], s["investigation_attempt"]) == ("Processing", 2)
    assert s["investigation_result_json"] is None and s["reporting_result_json"] is None
    assert s["reporting_status"] not in ("Awaiting Approval", "Approved")
    assert wr.evaluate_stage_readiness(CASE, "reporting")["ready"] is False

    # Threat Intelligence re-run: clears TI and everything after it
    wss._guarded_update(CASE, run, {"investigation_status": "Failed", "workflow_status": "Failed",
                                    "worker_id": None})
    wss.rerun_stage(CASE, run, "threat_intel")
    s = _state()
    assert (s["threat_intel_status"], s["threat_intel_attempt"]) == ("Processing", 2)
    assert s["threat_intel_result_json"] is None and s["investigation_result_json"] is None
    assert wr.evaluate_stage_readiness(CASE, "investigation")["ready"] is False

    # Parsing re-run (new run): no previous-run result or approval satisfies anything
    wss._guarded_update(CASE, run, {"threat_intel_status": "Failed", "workflow_status": "Failed",
                                    "worker_id": None})
    new_run = _parse(allow_retry=True)
    assert new_run != run
    s = _state()
    assert (s["triage_status"], s["triage_result_json"], s["threat_intel_result_json"]) == ("Pending", None, None)
    assert wss.get_approval_history(CASE, new_run) == []
    assert wr.evaluate_stage_readiness(CASE, "threat_intel")["reason_code"] == "triage_not_approved"


# ── 20: fail-closed paths ───────────────────────────────────────────────────

def _corrupt_parsing(run, **changes):
    s = _state()
    envelope = _json(s, "parsing_result_json")
    envelope.update(changes)
    wss._guarded_update(CASE, run, {"parsing_result_json": json.dumps(envelope)})


def test_fail_missing_parsing(e2e):
    run = _parse()
    wss._guarded_update(CASE, run, {"parsing_result_json": None})
    _not_ready("triage", "missing_parsing_result")
    assert e2e["calls"]["triage"] == [] and _state()["triage_status"] == "Pending"


def test_fail_parsing_wrong_case(e2e):
    run = _parse()
    _corrupt_parsing(run, incident_id=OTHER, case_identity={"status": "mismatch"},
                     raw_record_id=OTHER, processed_alert={"alert_id": OTHER},
                     normalised_alert={"alert_summary": {"alert_id": OTHER, "incident_id": OTHER}})
    _not_ready("triage", "parsing_identity_mismatch")
    assert e2e["calls"]["triage"] == []


def test_fail_parsing_wrong_run(e2e):
    run = _parse()
    _corrupt_parsing(run, run_id="run-from-somewhere-else")
    _not_ready("triage", "parsing_run_mismatch")
    assert e2e["calls"]["triage"] == []


def test_fail_triage_pending_approval(e2e):
    run = _parse()
    _triage(run)
    err = _not_ready("threat_intel", "triage_not_approved")
    assert err.code == "STAGE_LOCKED"
    assert _state()["threat_intel_status"] == "Pending"


def test_fail_triage_rejected(e2e):
    run = _parse()
    _triage(run)
    commands.reject_stage(CASE, "triage", analyst="Alice", comments="Wrong classification")
    _not_ready("threat_intel", "triage_rejected")


def test_fail_threat_intel_wrong_run(e2e):
    run = _parse()
    _triage(run)
    _approve("triage", "Alice")
    _ti(run)
    s = _state()
    ti = _json(s, "threat_intel_result_json")
    ti["run_id"] = "run-from-somewhere-else"
    wss._guarded_update(CASE, run, {"threat_intel_result_json": json.dumps(ti)})
    _not_ready("investigation", "threat_intel_run_mismatch")
    assert e2e["calls"]["investigation"] == []


def _tamper_investigation(run, **changes):
    s = _state()
    inv = _json(s, "investigation_result_json")
    inv.update(changes)
    wss._guarded_update(CASE, run, {"investigation_result_json": json.dumps(inv)})


def test_fail_investigation_wrong_case(e2e):
    run = _through_investigation_approval()
    _tamper_investigation(run, incident_id=OTHER, investigated_for=OTHER)
    _not_ready("reporting", "investigation_identity_mismatch")
    assert not wf.reporting_attempt_dir(CASE, run, 1).exists()


def test_fail_investigation_wrong_run(e2e):
    run = _through_investigation_approval()
    _tamper_investigation(run, run_id="run-from-somewhere-else")
    _not_ready("reporting", "investigation_run_mismatch")
    assert not wf.reporting_attempt_dir(CASE, run, 1).exists()


def test_fail_investigation_old_attempt_approval_only(e2e):
    run = _through_investigation_approval()
    _investigate(run, rerun=True)                    # attempt 2, not yet decided
    # even if the status column claimed Approved, only attempt 1 was decided
    wss._guarded_update(CASE, run, {"investigation_status": "Approved", "workflow_status": "Awaiting Action",
                                    "approval_stage": None, "reporting_status": "Pending"})
    _not_ready("reporting", "investigation_approval_not_recorded")


@pytest.mark.parametrize("mode,code", [("missing", "candidate_manifest_missing"),
                                       ("tamper_file", "candidate_file_hash_mismatch"),
                                       ("wrong_attempt", "candidate_manifest_attempt_mismatch")])
def test_fail_reporting_candidate_set(e2e, mode, code):
    run = _through_investigation_approval()
    e2e["monkeypatch"].setenv("FAKE_EXPORT_MODE", mode)
    result = _report(run)
    assert result["candidate_manifest_check"]["reason_code"] == code
    s = _state()
    assert (s["reporting_status"], s["workflow_status"], s["approval_stage"]) == ("Failed", "Failed", None)
    with pytest.raises(commands.WorkflowCommandError):
        _approve("reporting", "Dana")
    assert wss.get_latest_approved_reporting_set(CASE, run) is None


def test_stale_shared_reporting_files_have_no_effect(e2e):
    run = _through_investigation_approval()
    for folder in ("inputs", "outputs"):
        d = e2e["rep"] / folder
        d.mkdir(parents=True, exist_ok=True)
        for name in ("investigation_result.json", "threat_intel_result.json", "approval_result.json",
                     "final_report.json", "triage_result.json"):
            (d / name).write_text(json.dumps({"incident_id": OTHER, "marker": "STALE"}), encoding="utf-8")
    result = _report(run)
    assert result["candidate_manifest_check"]["ok"] and result["incident_id"] == CASE
    attempt = wf.reporting_attempt_dir(CASE, run, 1)
    blob = "".join(p.read_text(encoding="utf-8", errors="ignore") for p in attempt.rglob("*") if p.is_file())
    assert "STALE" not in blob and OTHER not in blob


def test_fail_approval_from_previous_run(e2e):
    old_run = _through_investigation_approval()
    wss._guarded_update(CASE, old_run, {"workflow_status": "Failed"})
    new_run = _parse(allow_retry=True)
    _triage(new_run)
    # Force the status column as if approved: the only Triage approval on
    # record belongs to the PREVIOUS run, which must never count.
    wss._guarded_update(CASE, new_run, {"triage_status": "Approved", "workflow_status": "Awaiting Action",
                                        "approval_stage": None, "threat_intel_status": "Pending"})
    assert [d["run_id"] for d in wss.get_approval_history(CASE, old_run)]
    _not_ready("threat_intel", "triage_approval_not_recorded")
