"""tests/test_stage_readiness.py -- canonical audit Phase 6.

One deterministic answer to "can stage X run for case C / run R now?"
(workflow/readiness.py), used by the commands before the atomic state-store
transition, by available_actions for the UI, and by every durable stage
worker after it has claimed its stage (which also covers resume).

Readiness checks a stage's PREREQUISITES -- upstream statuses, the canonical
upstream results (case AND run identity, result shape) and the analyst
approvals of the current run/attempt -- never object truthiness, wrappers or
placeholders. Raw incident is required for Triage only; elsewhere a missing
or foreign raw incident is degraded evidence that is never consumed.

Temporary workflow DB / artifact root (root conftest.py); every
sqlite3.connect aimed at the real soc_db/ directory is redirected and
recorded. No LLM, no provider calls, no subprocess.
"""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest

import canonical_seed as seed
from workflow import commands
from workflow import engine as wf
from workflow import readiness as wr
from workflow import state_store as wss
from workflow.parsing_canonical import evaluate_parsing_envelope

CASE = "INC-P6-0001"
OTHER = "INC-P6-OTHER"
_REAL_SOC_DB = (Path(wf.ROOT) / "soc_db").resolve()
_PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _db_target(database):
    text = str(database)
    if text.startswith("file:"):
        text = text[5:].split("?", 1)[0]
    try:
        return Path(text).resolve()
    except Exception:
        return None


@pytest.fixture(autouse=True)
def real_db_attempts(tmp_path, monkeypatch):
    """Redirect (and record) any connect aimed at the real soc_db/ directory."""
    attempts: list[str] = []
    real_connect = sqlite3.connect

    def guarded(database, *args, **kwargs):
        target = _db_target(database)
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
def _isolated(tmp_path, monkeypatch, real_db_attempts):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    monkeypatch.setattr(wf, "PIPELINE_DB_FILE", tmp_path / "pipeline.db")
    monkeypatch.setattr(wf, "_TRUSTED_OUTPUT_ROOT", tmp_path / "trusted")
    monkeypatch.setattr(wf, "REP_DIR", tmp_path / "rep")
    monkeypatch.setattr(wf, "generate_stage_ai_summary", lambda *a, **k: {})
    monkeypatch.setattr(wf, "generate_triage_ai_summary", lambda *a, **k: {})
    with commands._TASKS_LOCK:
        commands._TASKS.clear()
    wss.db_init()
    wf.pipeline_db_init()
    for case in (CASE, OTHER):
        _insert_case(case)
    yield
    with commands._TASKS_LOCK:
        commands._TASKS.clear()


# ── canonical workflow builders (real transitions wherever one exists) ──────

def _insert_case(case, raw_json="__default__"):
    raw = json.dumps(_incident(case)) if raw_json == "__default__" else raw_json
    with wss.db_connect() as con:
        con.execute("INSERT OR REPLACE INTO incidents (id, title, raw_json) VALUES (?, ?, ?)",
                    (case, f"Case {case}", raw))
        con.commit()


def _incident(case=CASE):
    return {"id": case, "title": f"Case {case}", "alertMeta": {"SourceIp": ["10.0.0.5"]}}


def _triage(case=CASE, run=None, unc="#00077A"):
    result = {"ticket": {"incident_id": case, "unc": unc, "classification": "HIGH", "title": "Case"},
              "metakeys_payload": {"incident_id": case, "incident_title": "Case"},
              "trace": [], "used_parsed_context": True}
    if run is not None:
        result["run_id"] = run
    return result


def _ti(case=CASE, run=None, status="completed"):
    return {"incident_id": case, "run_id": run, "stage": "threat_intelligence", "status": status,
            "enrichment_risk_level": "Low", "enrichment_risk_score": 5, "warnings": [],
            "enriched_alert": {"incident_id": case}, "threat_intelligence": {"indicators": []}}


def _inv(case=CASE, run=None):
    return {"agent": "Investigation Agent", "incident_id": case, "investigated_for": case,
            "status": "completed", "run_id": run}


def _set(run, **cols):
    wss._guarded_update(CASE, run, {k: (json.dumps(v) if k.endswith("_json") and not isinstance(v, (str, type(None))) else v)
                                    for k, v in cols.items()})


def _new_run():
    run = wss.start_run(CASE, allow_retry=True)
    seed.seed_parsing_and_raw_incident(CASE, run, _incident())
    wss.set_workflow_status(CASE, run, "Awaiting Action")
    return run


def _ready_for(stage):
    """Drive one canonical run to the point where `stage` is startable."""
    run = _new_run()
    if stage == "triage":
        return run
    wss.save_triage_result(CASE, run, _triage(run=run))
    _set(run, triage_status="Awaiting Approval", workflow_status="Awaiting Approval",
         approval_stage="triage")
    wss.approve_triage(CASE, run, approved_by="Analyst")
    if stage == "threat_intel":
        return run
    _set(run, threat_intel_status="Complete", threat_intel_result_json=_ti(run=run),
         investigation_status="Pending", workflow_status="Awaiting Action")
    if stage == "investigation":
        return run
    _set(run, investigation_status="Awaiting Approval", investigation_result_json=_inv(run=run),
         workflow_status="Awaiting Approval", approval_stage="investigation")
    wss.approve_investigation(CASE, run, approved_by="Analyst")
    return run


def _r(stage, **kw):
    return wr.evaluate_stage_readiness(CASE, stage, **kw)


def _code(stage, **kw):
    return _r(stage, **kw)["reason_code"]


def _state():
    return wss.get_state(CASE)


# ── 1-5 + 29: Parsing readiness (Phase 5 rules, unchanged) ──────────────────

@pytest.mark.parametrize("stage", ["triage", "threat_intel", "investigation", "reporting"])
def test_valid_parsing_permits_every_downstream_stage(stage):
    run = _ready_for(stage)
    readiness = _r(stage)
    assert readiness["ready"] is True, readiness
    assert readiness["reason_code"] is None
    assert readiness["inputs"]["parsing"] == wf.load_parsing_result_for_run(CASE, run)


@pytest.mark.parametrize("stage", ["triage", "threat_intel", "investigation", "reporting"])
def test_missing_parsing_blocks_every_downstream_stage(stage):
    run = _ready_for(stage)
    _set(run, parsing_result_json=None)
    readiness = _r(stage)
    assert (readiness["ready"], readiness["reason_code"], readiness["category"]) == \
        (False, "missing_parsing_result", wr.CATEGORY_INPUT)


@pytest.mark.parametrize("stage", ["triage", "threat_intel", "investigation", "reporting"])
def test_parsing_identity_mismatch_blocks(stage):
    run = _ready_for(stage)
    _set(run, parsing_result_json=seed.parsing_envelope(
        CASE, run, raw_record_id=OTHER, normalised_alert={"alert_summary": {"alert_id": OTHER}}))
    assert _code(stage) == "parsing_identity_mismatch"


@pytest.mark.parametrize("stage", ["triage", "threat_intel", "investigation", "reporting"])
def test_old_identityless_parsing_record_never_becomes_usable(stage):
    """A pre-Phase-5 envelope (run bound, alert_id == case, envelope even
    claiming the case) still has no verifiable identity: not ready, with the
    rerun hint -- no alert_id or envelope-claim fallback."""
    run = _ready_for(stage)
    legacy = seed.parsing_envelope(CASE, run)
    for key in ("input_shape", "raw_record_id", "normalised_alert_count"):
        legacy.pop(key)
    _set(run, parsing_result_json=legacy)
    readiness = _r(stage)
    assert readiness["reason_code"] == "parsing_identity_unverified"
    assert "canonical Parsing rerun required" in readiness["detail"]
    assert wf.load_parsing_result_for_run(CASE, run) is None
    if stage != "triage":
        with pytest.raises(commands.WorkflowCommandError) as refused:
            commands.rerun_stage(CASE, "triage", executor=lambda *a: None)
        assert refused.value.code == "STAGE_NOT_READY"
        assert refused.value.details["reason_code"] == "parsing_identity_unverified"


def test_stale_parsing_run_cannot_satisfy_the_current_run():
    run = _ready_for("triage")
    _set(run, parsing_result_json=seed.parsing_envelope(CASE, "INC-P6-0001@older-run"))
    assert _code("triage") == "parsing_run_mismatch"
    assert _r("triage")["category"] == wr.CATEGORY_RUN


def test_failed_parsing_blocks_triage():
    run = _ready_for("triage")
    _set(run, parsing_status="Failed")
    readiness = _r("triage")
    assert (readiness["reason_code"], readiness["category"]) == ("parsing_failed", wr.CATEGORY_STATUS)


def _phase5_loader(state, incident_id, run_id):
    """Verbatim Phase 5 load_parsing_result_for_run() body (a0dcaf9)."""
    from agents.parsing.parser_context_guard import CASE_IDENTITY_MATCH, resolve_case_identity
    if not state or state.get("run_id") != run_id:
        return None
    try:
        summary = json.loads(state.get("parsing_result_json") or "{}")
    except Exception:
        return None
    if summary.get("run_id") != run_id:
        return None
    case_identity = resolve_case_identity(summary, incident_id)
    if case_identity["status"] != CASE_IDENTITY_MATCH:
        return None
    out = dict(summary)
    out["case_identity"] = case_identity
    return out


def test_phase5_parsing_loader_behaviour_is_unchanged():
    run = _ready_for("triage")
    good = seed.parsing_envelope(CASE, run)
    legacy = {k: v for k, v in good.items() if k not in ("input_shape", "raw_record_id")}
    foreign = seed.parsing_envelope(CASE, run, raw_record_id=OTHER,
                                    normalised_alert={"alert_summary": {"alert_id": OTHER}})
    wrapped = seed.parsing_envelope(CASE, run, normalised_alert={"alert_summary": {"incident_id": CASE}})
    for envelope in (good, legacy, foreign, wrapped, seed.parsing_envelope(CASE, "other-run"), {}, None):
        _set(run, parsing_result_json=envelope)
        state = _state()
        expected = _phase5_loader(state, CASE, run)
        assert wf.load_parsing_result_for_run(CASE, run) == expected
        assert evaluate_parsing_envelope(state, CASE, run)[0] == expected
    _set(run, parsing_result_json="{not json")
    assert wf.load_parsing_result_for_run(CASE, run) is None


# ── raw incident (required for Triage, optional + never foreign elsewhere) ──

def test_triage_requires_this_runs_raw_incident():
    run = _ready_for("triage")
    _set(run, raw_incident_path=None)
    assert (_code("triage"), _r("triage")["category"]) == ("missing_raw_incident", wr.CATEGORY_INPUT)


def test_raw_incident_for_correct_case_but_wrong_run_is_not_ready_for_triage():
    run = _ready_for("triage")
    other_run_path = wf._save_run_artifact(CASE, "INC-P6-0001@other-run", "raw_incident.json",
                                           "raw_incident", {"incident": _incident(), "data_availability": {}})
    _set(run, raw_incident_path=str(other_run_path))
    readiness = _r("triage")
    assert (readiness["reason_code"], readiness["category"]) == ("raw_incident_run_mismatch", wr.CATEGORY_RUN)
    assert wf.load_raw_incident_for_run(CASE, run) is None


def test_foreign_raw_record_is_not_ready_for_triage():
    run = _ready_for("triage")
    seed.seed_raw_incident(CASE, run, _incident(OTHER))
    assert _code("triage") == "raw_incident_identity_mismatch"
    assert wf.load_raw_incident_for_run(CASE, run) is None


@pytest.mark.parametrize("stage", ["threat_intel", "investigation", "reporting"])
def test_missing_raw_incident_is_degraded_not_blocking_downstream(stage):
    run = _ready_for(stage)
    _set(run, raw_incident_path=None)
    readiness = _r(stage)
    assert readiness["ready"] is True
    assert readiness["degraded"] == ["raw_incident_unavailable"]
    assert readiness["inputs"]["raw_incident"] is None


@pytest.mark.parametrize("stage", ["threat_intel", "investigation", "reporting"])
def test_foreign_optional_raw_incident_is_degraded_and_never_handed_on(stage):
    run = _ready_for(stage)
    seed.seed_raw_incident(CASE, run, _incident(OTHER))
    readiness = _r(stage)
    assert readiness["ready"] is True
    assert readiness["degraded"] == ["raw_incident_unavailable"]
    assert "raw_incident_identity_mismatch" in readiness["degraded_details"]["raw_incident_unavailable"]
    assert readiness["inputs"]["raw_incident"] is None


def test_ti_worker_never_consumes_a_foreign_raw_incident(monkeypatch):
    run = _ready_for("threat_intel")
    seed.seed_raw_incident(CASE, run, _incident(OTHER))
    seen = {}

    def fake_ti(**kwargs):
        seen.update(kwargs)
        return _ti(run=run)

    monkeypatch.setattr(wf, "run_threat_intel", fake_ti)
    commands.start_stage(CASE, "threat_intel", executor=lambda *a: None)
    wf.resume_after_triage_approval(CASE, run)
    assert seen["incident"] == {}
    assert seen["triage_result"]["run_id"] == run
    assert _state()["threat_intel_status"] == "Complete"


# ── 6-9: Triage result + approval ───────────────────────────────────────────

def test_missing_triage_result_blocks_ti():
    run = _ready_for("threat_intel")
    _set(run, triage_result_json=None)
    assert _code("threat_intel") == "missing_triage_result"


def test_triage_pending_approval_blocks_downstream():
    run = _new_run()
    wss.save_triage_result(CASE, run, _triage(run=run))
    _set(run, triage_status="Awaiting Approval", workflow_status="Awaiting Approval", approval_stage="triage")
    for stage in ("threat_intel", "investigation", "reporting"):
        readiness = _r(stage)
        assert (readiness["reason_code"], readiness["category"]) == ("triage_not_approved", wr.CATEGORY_STATUS)
    with pytest.raises(commands.WorkflowCommandError) as locked:
        commands.start_stage(CASE, "threat_intel", executor=lambda *a: None)
    assert locked.value.code == "STAGE_LOCKED"
    assert locked.value.details["reason_code"] == "triage_not_approved"


def test_triage_rejection_blocks_downstream():
    run = _new_run()
    wss.save_triage_result(CASE, run, _triage(run=run))
    _set(run, triage_status="Awaiting Approval", workflow_status="Awaiting Approval", approval_stage="triage")
    wss.reject_triage(CASE, run, rejected_by="Analyst", reason="False positive")
    assert _code("threat_intel") == "triage_rejected"
    assert _state()["threat_intel_status"] == "Blocked"
    with pytest.raises(commands.WorkflowCommandError) as locked:
        commands.start_stage(CASE, "threat_intel", executor=lambda *a: None)
    assert locked.value.code == "STAGE_LOCKED"
    assert locked.value.details["reason_code"] == "triage_rejected"


def test_approved_triage_permits_ti():
    _ready_for("threat_intel")
    readiness = _r("threat_intel")
    assert readiness["ready"] is True
    assert readiness["inputs"]["triage"]["ticket"]["unc"] == "#00077A"


def test_triage_approved_status_without_a_recorded_approval_is_not_ready():
    run = _new_run()
    wss.save_triage_result(CASE, run, _triage(run=run))
    _set(run, triage_status="Approved")
    readiness = _r("threat_intel")
    assert (readiness["reason_code"], readiness["category"]) == ("triage_approval_not_recorded", wr.CATEGORY_APPROVAL)
    with pytest.raises(commands.WorkflowCommandError) as refused:
        commands.start_stage(CASE, "threat_intel", executor=lambda *a: None)
    assert refused.value.code == "STAGE_NOT_READY"


def test_triage_result_correct_case_but_wrong_run_is_not_ready():
    run = _ready_for("threat_intel")
    _set(run, triage_result_json=_triage(run="INC-P6-0001@other-run"))
    readiness = _r("threat_intel")
    assert (readiness["reason_code"], readiness["category"]) == ("triage_run_mismatch", wr.CATEGORY_RUN)
    _set(run, triage_result_json=_triage())          # no run binding at all
    assert _code("threat_intel") == "triage_run_mismatch"


def test_triage_result_for_another_case_is_not_ready():
    run = _ready_for("threat_intel")
    _set(run, triage_result_json=_triage(OTHER, run=run))
    assert _code("threat_intel") == "triage_identity_mismatch"


def test_failed_triage_result_is_not_ready():
    run = _ready_for("threat_intel")
    _set(run, triage_result_json={"error": "boom", "ticket": {}, "metakeys_payload": {}, "run_id": run})
    assert _code("threat_intel") == "triage_result_failed"


# ── 10-11: Threat Intelligence result ───────────────────────────────────────

def test_missing_ti_result_blocks_investigation():
    run = _ready_for("investigation")
    _set(run, threat_intel_result_json=None)
    assert _code("investigation") == "missing_threat_intel_result"


def test_ti_provider_degradation_permits_investigation_with_a_degraded_label():
    run = _ready_for("investigation")
    _set(run, threat_intel_status="Complete with Warnings",
         threat_intel_result_json=_ti(run=run, status="completed_with_warnings"))
    readiness = _r("investigation")
    assert readiness["ready"] is True
    assert readiness["degraded"] == ["threat_intel_degraded"]


def test_failed_ti_result_is_not_ready_even_if_status_says_complete():
    run = _ready_for("investigation")
    _set(run, threat_intel_result_json={"status": "failed", "errors": ["boom"]})
    assert _code("investigation") == "threat_intel_result_failed"


def test_ti_result_correct_case_but_wrong_run_is_not_ready():
    run = _ready_for("investigation")
    _set(run, threat_intel_result_json=_ti(run="INC-P6-0001@other-run"))
    readiness = _r("investigation")
    assert (readiness["reason_code"], readiness["category"]) == ("threat_intel_run_mismatch", wr.CATEGORY_RUN)


def test_ti_result_for_another_case_is_not_ready():
    run = _ready_for("investigation")
    _set(run, threat_intel_result_json=_ti(OTHER, run=run))
    assert _code("investigation") == "threat_intel_identity_mismatch"


# ── 12-18: Investigation result + approval for Reporting ────────────────────

def test_missing_investigation_blocks_reporting():
    run = _ready_for("reporting")
    _set(run, investigation_result_json=None)
    assert _code("reporting") == "missing_investigation_result"


def test_investigation_identity_mismatch_blocks_reporting():
    run = _ready_for("reporting")
    _set(run, investigation_result_json=_inv(OTHER, run=run))
    assert _code("reporting") == "investigation_identity_mismatch"


def test_investigation_result_correct_case_but_wrong_run_is_not_ready():
    run = _ready_for("reporting")
    _set(run, investigation_result_json=_inv(run="INC-P6-0001@other-run"))
    readiness = _r("reporting")
    assert (readiness["reason_code"], readiness["category"]) == ("investigation_run_mismatch", wr.CATEGORY_RUN)


def test_failed_investigation_result_is_not_ready():
    run = _ready_for("reporting")
    _set(run, investigation_result_json={"status": "failed", "error": "boom"})
    assert _code("reporting") == "investigation_result_failed"


def test_investigation_pending_approval_blocks_reporting():
    run = _ready_for("investigation")
    _set(run, investigation_status="Awaiting Approval", investigation_result_json=_inv(run=run),
         workflow_status="Awaiting Approval", approval_stage="investigation")
    readiness = _r("reporting")
    assert (readiness["reason_code"], readiness["category"]) == ("investigation_not_approved", wr.CATEGORY_STATUS)


def test_investigation_rejection_blocks_reporting():
    run = _ready_for("investigation")
    _set(run, investigation_status="Awaiting Approval", investigation_result_json=_inv(run=run),
         workflow_status="Awaiting Approval", approval_stage="investigation")
    wss.reject_investigation(CASE, run, rejected_by="Analyst", reason="Insufficient evidence")
    assert _code("reporting") == "investigation_rejected"
    with pytest.raises(commands.WorkflowCommandError) as locked:
        commands.start_stage(CASE, "reporting", executor=lambda *a: None)
    assert locked.value.code == "STAGE_LOCKED"
    assert locked.value.details["reason_code"] == "investigation_rejected"


def test_investigation_approved_on_the_current_attempt_permits_reporting():
    run = _ready_for("reporting")
    readiness = _r("reporting")
    assert readiness["ready"] is True
    assert readiness["inputs"]["investigation"]["run_id"] == run


def test_previous_investigation_attempt_approval_does_not_permit_reporting():
    run = _ready_for("reporting")                      # attempt 1 approved
    commands.rerun_stage(CASE, "investigation", executor=lambda *a: None)
    assert _state()["investigation_attempt"] == 2
    _set(run, investigation_status="Awaiting Approval", investigation_result_json=_inv(run=run),
         workflow_status="Awaiting Approval", approval_stage="investigation")
    assert _code("reporting") == "investigation_not_approved"
    _set(run, investigation_status="Approved", workflow_status="Awaiting Action", approval_stage=None)
    readiness = _r("reporting")
    assert (readiness["reason_code"], readiness["category"]) == \
        ("investigation_approval_not_recorded", wr.CATEGORY_APPROVAL)
    assert "older attempt" in readiness["detail"]


def test_previous_run_approvals_do_not_permit_the_current_run():
    _ready_for("reporting")                            # run 1: every gate approved
    run2 = _new_run()
    wss.save_triage_result(CASE, run2, _triage(run=run2))
    _set(run2, triage_status="Approved")
    assert _code("threat_intel") == "triage_approval_not_recorded"
    run3 = _ready_for("investigation")                 # run 3: triage approved for real
    _set(run3, investigation_status="Approved", investigation_result_json=_inv(run=run3))
    assert _code("reporting") == "investigation_approval_not_recorded"


# ── 19-20: {} and wrapper-only objects ──────────────────────────────────────

@pytest.mark.parametrize("column,stage,code", [
    ("triage_result_json", "threat_intel", "missing_triage_result"),
    ("threat_intel_result_json", "investigation", "missing_threat_intel_result"),
    ("investigation_result_json", "reporting", "missing_investigation_result"),
    ("parsing_result_json", "triage", "missing_parsing_result"),
])
def test_empty_object_cannot_satisfy_a_required_input(column, stage, code):
    run = _ready_for("reporting" if stage == "triage" else stage)
    _set(run, **{column: "{}"})
    assert _code(stage) == code


@pytest.mark.parametrize("column,stage,wrapper,code", [
    ("triage_result_json", "threat_intel",
     {"agent": "Triage Agent", "status": "not_recorded", "incident_id": CASE}, "triage_identity_unverified"),
    ("threat_intel_result_json", "investigation",
     {"agent": "Threat Intelligence", "status": "completed"}, "threat_intel_identity_unverified"),
    ("investigation_result_json", "reporting",
     {"agent": "Investigation Agent", "status": "needs_more_data",
      "investigation_result_source": "missing"}, "investigation_identity_unverified"),
])
def test_wrapper_with_only_injected_metadata_cannot_satisfy_a_required_input(column, stage, wrapper, code):
    run = _ready_for(stage)
    _set(run, **{column: wrapper})
    assert _code(stage) == code


# ── 21-22: placeholders ─────────────────────────────────────────────────────

def _written_text(root):
    return "".join(p.read_text(encoding="utf-8") for p in Path(root).rglob("*.json"))


def test_inc_0001_is_never_fabricated(monkeypatch):
    import agents.investigation.skills_sidecar as skills_sidecar
    monkeypatch.setattr(skills_sidecar, "build_skills_context", lambda *a, **k: {"available": False})
    run = _ready_for("reporting")
    no_ids = {"ticket": {"unc": "#00077A", "classification": "HIGH"}, "metakeys_payload": {}}
    wf.handoff_to_reporting(no_ids, {"id": CASE}, _inv(run=run), threat_intel_result=_ti(run=run),
                            incident_id=CASE, run_id=run, reporting_stage_attempt=1)
    attempt = wf.reporting_attempt_dir(CASE, run, 1)
    triage_doc = json.loads((attempt / "outputs" / "triage_result.json").read_text(encoding="utf-8"))
    assert triage_doc["incident_id"] == CASE
    assert "INC-0001" not in _written_text(attempt)
    with pytest.raises(ValueError, match="missing_case_identity"):
        wf.handoff_to_reporting(no_ids, {}, _inv(run=run), threat_intel_result=_ti(run=run))
    assert not (Path(wf.REP_DIR) / "outputs" / "triage_result.json").exists()


def test_missing_ticket_is_not_ready_and_never_becomes_tkt_unknown(monkeypatch):
    run = _ready_for("reporting")
    _set(run, triage_result_json=_triage(run=run, unc=""))
    assert (_code("reporting"), _r("reporting")["category"]) == ("missing_triage_ticket", wr.CATEGORY_INPUT)
    with pytest.raises(ValueError, match="missing_triage_ticket"):
        wf.handoff_to_reporting(_triage(run=run, unc=""), {"id": CASE}, _inv(run=run),
                                threat_intel_result=_ti(run=run),
                                incident_id=CASE, run_id=run, reporting_stage_attempt=1)
    assert not wf.reporting_attempt_dir(CASE, run, 1).exists()


def test_reporting_worker_rejects_unready_inputs_before_any_workspace_or_subprocess(monkeypatch):
    run = _ready_for("reporting")
    commands.start_stage(CASE, "reporting", executor=lambda *a: None)
    _set(run, triage_result_json=_triage(run=run, unc=""))   # prerequisite changes after the command
    calls = []
    monkeypatch.setattr(wf, "acquire_global_lock", lambda *a, **k: calls.append("lock"))
    monkeypatch.setattr(wf, "handoff_to_reporting", lambda *a, **k: calls.append("handoff"))
    monkeypatch.setattr(wf, "run_reporting", lambda *a, **k: calls.append("subprocess"))
    result = wf.run_reporting_stage(CASE, run)
    assert calls == []
    assert result["readiness"]["reason_code"] == "missing_triage_ticket"
    assert not wf.reporting_attempt_dir(CASE, run, 1).exists()
    state = _state()
    assert (state["reporting_status"], state["workflow_status"]) == ("Failed", "Failed")
    assert "missing_triage_ticket" in state["last_error"]
    assert json.loads(state["reporting_result_json"])["readiness"]["reason_code"] == "missing_triage_ticket"


def test_shared_reporting_folder_artefacts_cannot_satisfy_readiness(monkeypatch):
    run = _ready_for("reporting")
    _set(run, investigation_result_json=None)
    shared = Path(wf.REP_DIR)
    for folder in ("inputs", "outputs"):
        (shared / folder).mkdir(parents=True, exist_ok=True)
        for name, data in (("investigation_result.json", _inv(run=run)),
                           ("processed_alert.json", {"alert_id": CASE}),
                           ("triage_result.json", _triage(run=run)),
                           ("threat_intel_result.json", _ti(run=run))):
            (shared / folder / name).write_text(json.dumps(data), encoding="utf-8")
    assert _code("reporting") == "missing_investigation_result"
    monkeypatch.setattr(wf, "run_reporting", lambda *a, **k: pytest.fail("subprocess must not start"))
    _set(run, reporting_status="Processing", workflow_status="Processing")
    result = wf.run_reporting_stage(CASE, run)
    assert result["readiness"]["reason_code"] == "missing_investigation_result"


# ── 23: optional evidence missing still allows degraded execution ───────────

def test_investigation_worker_runs_degraded_without_raw_incident(monkeypatch):
    run = _ready_for("investigation")
    _set(run, raw_incident_path=None)
    seen = {}

    def fake_investigate(triage_result, incident, inc_id, **kwargs):
        seen.update(incident=incident, ti=kwargs["threat_intel_result"], parsing=kwargs["parsing_result"])
        return _inv()

    monkeypatch.setattr(wf, "investigate_with_feedback", fake_investigate)
    monkeypatch.setattr(wf, "pipeline_insert", lambda *a, **k: None)
    commands.start_stage(CASE, "investigation", executor=lambda *a: None)
    result = wf.run_investigation_stage(CASE, run)
    assert result["status"] == "awaiting_approval"
    assert seen["incident"] == {}
    assert seen["ti"]["run_id"] == run and seen["parsing"]["run_id"] == run
    persisted = json.loads(_state()["investigation_result_json"])
    assert persisted["run_id"] == run and persisted["incident_id"] == CASE


def test_investigation_worker_checks_prerequisites_before_the_workspace_lock(monkeypatch):
    run = _ready_for("investigation")
    commands.start_stage(CASE, "investigation", executor=lambda *a: None)
    _set(run, threat_intel_result_json=_ti(run="INC-P6-0001@other-run"))
    monkeypatch.setattr(wf, "acquire_global_lock", lambda *a, **k: pytest.fail("lock must not be taken"))
    monkeypatch.setattr(wf, "investigate_with_feedback", lambda *a, **k: pytest.fail("must not run"))
    result = wf.run_investigation_stage(CASE, run)
    assert result["readiness"]["reason_code"] == "threat_intel_run_mismatch"
    state = _state()
    assert (state["investigation_status"], state["reporting_status"]) == ("Failed", "Blocked")


# ── worker re-check is prerequisite-only (never self-invalidating) ──────────

def test_worker_readiness_holds_after_its_own_stage_became_processing(monkeypatch):
    run = _ready_for("threat_intel")
    commands.start_stage(CASE, "threat_intel", executor=lambda *a: None)
    assert _state()["threat_intel_status"] == "Processing"
    assert _r("threat_intel", run_id=run)["ready"] is True
    monkeypatch.setattr(wf, "run_threat_intel", lambda **k: _ti(run=run))
    result = wf.resume_after_triage_approval(CASE, run)
    assert result["status"] == "completed"
    assert _state()["threat_intel_status"] == "Complete"


def test_prerequisite_change_between_command_and_worker_is_caught_by_the_worker(monkeypatch):
    run = _ready_for("threat_intel")
    commands.start_stage(CASE, "threat_intel", executor=lambda *a: None)
    _set(run, triage_result_json=_triage(OTHER, run=run))
    monkeypatch.setattr(wf, "run_threat_intel", lambda **k: pytest.fail("TI must not run"))
    result = wf.resume_after_triage_approval(CASE, run)
    assert result["status"] == "failed"
    assert result["readiness"]["reason_code"] == "triage_identity_mismatch"
    state = _state()
    assert (state["threat_intel_status"], state["investigation_status"], state["workflow_status"]) == \
        ("Failed", "Blocked", "Failed")
    assert "triage_identity_mismatch" in state["last_error"]


def test_triage_worker_never_runs_with_missing_canonical_parsing(monkeypatch):
    import agents.investigation.tools.ioc_correlation as ioc
    monkeypatch.setattr(ioc, "correlate_iocs", lambda *a, **k: {"available": False})
    run = _ready_for("triage")
    commands.start_stage(CASE, "triage", executor=lambda *a: None)
    _set(run, parsing_result_json=None)
    monkeypatch.setattr(wf, "run_triage", lambda *a, **k: pytest.fail("Triage must not run"))
    result = wf.run_triage_stage(CASE, run)
    assert result["readiness"]["reason_code"] == "missing_parsing_result"
    assert _state()["triage_status"] == "Failed"


def test_triage_worker_binds_its_result_to_the_run(monkeypatch):
    import agents.investigation.tools.ioc_correlation as ioc
    monkeypatch.setattr(ioc, "correlate_iocs", lambda *a, **k: {"available": False})
    run = _ready_for("triage")
    commands.start_stage(CASE, "triage", executor=lambda *a: None)
    seen = {}

    def fake_triage(incident, parsed_context=None, force=False, **kwargs):
        seen.update(incident=incident, parsed_context=parsed_context)
        return _triage()

    monkeypatch.setattr(wf, "run_triage", fake_triage)
    wf.run_triage_stage(CASE, run)
    assert seen["parsed_context"] == {"alert_id": CASE}
    assert seen["incident"]["id"] == CASE
    assert json.loads(_state()["triage_result_json"])["run_id"] == run
    assert _state()["triage_status"] == "Awaiting Approval"


# ── 24: reruns invalidate downstream readiness ──────────────────────────────

def test_upstream_rerun_makes_downstream_not_ready():
    run = _ready_for("reporting")
    commands.rerun_stage(CASE, "triage", executor=lambda *a: None)
    state = _state()
    assert state["threat_intel_result_json"] is None and state["investigation_result_json"] is None
    for stage in ("threat_intel", "investigation", "reporting"):
        assert _r(stage)["ready"] is False
    assert _code("threat_intel") == "triage_not_approved"


def test_stale_downstream_result_left_behind_is_still_not_ready():
    run = _ready_for("investigation")
    stale = _ti(run="INC-P6-0001@previous-run")
    commands.rerun_stage(CASE, "threat_intel", executor=lambda *a: None)
    _set(run, threat_intel_status="Complete", threat_intel_result_json=stale, workflow_status="Awaiting Action")
    assert _code("investigation") == "threat_intel_run_mismatch"
    run2 = _new_run()                                   # a fresh Parsing run
    _set(run2, triage_status="Approved", triage_result_json=_triage(run=run))   # previous run's result
    assert _code("threat_intel") == "triage_run_mismatch"
    _set(run2, triage_result_json=_triage(run=run2))   # bound, but run 1's approval does not carry over
    assert _code("threat_intel") == "triage_approval_not_recorded"


# ── rejection semantics preserved ───────────────────────────────────────────

def test_reporting_rejection_keeps_the_workflow_incomplete_and_rerunnable():
    run = _ready_for("reporting")
    _set(run, reporting_status="Awaiting Approval", workflow_status="Awaiting Approval",
         approval_stage="reporting", reporting_result_json={"status": "completed"})
    wss.reject_reporting(CASE, run, rejected_by="Analyst", reason="Rewrite")
    state = _state()
    assert (state["reporting_status"], state["workflow_status"]) == ("Rejected", "Rejected")
    assert _r("reporting")["ready"] is True              # prerequisites still hold
    commands.rerun_stage(CASE, "reporting", executor=lambda *a: None)
    assert _state()["reporting_attempt"] == 2 and _state()["workflow_status"] != "Complete"


# ── 25-26: case and run identity constant ───────────────────────────────────

def test_case_and_run_identity_are_constant_across_the_chain():
    run = _ready_for("reporting")
    readiness = _r("reporting")
    assert (readiness["case_id"], readiness["run_id"]) == (CASE, run)
    inputs = readiness["inputs"]
    assert inputs["parsing"]["run_id"] == inputs["triage"]["run_id"] == \
        inputs["threat_intel"]["run_id"] == inputs["investigation"]["run_id"] == run
    assert inputs["parsing"]["case_identity"]["expected_case_id"] == CASE
    assert inputs["triage"]["ticket"]["incident_id"] == inputs["threat_intel"]["incident_id"] == \
        inputs["investigation"]["incident_id"] == CASE
    assert _code("reporting", run_id="INC-P6-0001@not-current") == "run_not_current"


# ── commands / API / available_actions ─────────────────────────────────────

def test_parsing_start_refuses_missing_or_foreign_raw_record():
    _insert_case(CASE, raw_json=json.dumps(_incident(OTHER)))
    with pytest.raises(commands.WorkflowCommandError) as foreign:
        commands.start_stage(CASE, "parsing", executor=lambda *a: pytest.fail("must not launch"))
    assert (foreign.value.code, foreign.value.details["reason_code"]) == \
        ("STAGE_NOT_READY", "raw_incident_identity_mismatch")
    _insert_case(CASE, raw_json=None)
    with pytest.raises(commands.WorkflowCommandError) as missing:
        commands.start_stage(CASE, "parsing", executor=lambda *a: pytest.fail("must not launch"))
    assert missing.value.details["reason_code"] == "missing_raw_incident"
    assert _state()["run_id"] is None


def test_available_actions_mirror_backend_readiness_with_reason_codes():
    from backend.services import case_service
    run = _ready_for("threat_intel")
    start = next(a for a in commands.available_actions(_state())["stages"]["threat_intel"] if a["type"] == "start")
    assert (start["enabled"], start["reason_code"], start["degraded"]) == (True, None, [])
    _set(run, raw_incident_path=None)
    start = next(a for a in commands.available_actions(_state())["stages"]["threat_intel"] if a["type"] == "start")
    assert (start["enabled"], start["degraded"]) == (True, ["raw_incident_unavailable"])
    _set(run, parsing_result_json=None)
    projection = {k: v for k, v in _state().items() if k in case_service._CASE_COLUMNS}
    for state in (_state(), projection):
        start = next(a for a in commands.available_actions(state)["stages"]["threat_intel"] if a["type"] == "start")
        assert (start["enabled"], start["reason_code"]) == (False, "missing_parsing_result")
        assert start["reason"].startswith("Not ready: missing_parsing_result")


def _load_backend():
    package_dir = _PROJECT_ROOT / "backend"
    spec = importlib.util.spec_from_file_location(
        "_aegis_phase6_backend", package_dir / "__init__.py",
        submodule_search_locations=[str(package_dir)])
    module = importlib.util.module_from_spec(spec)
    sys.modules["_aegis_phase6_backend"] = module
    spec.loader.exec_module(module)
    return module


def test_api_returns_stage_not_ready_with_reason_code(monkeypatch):
    run = _ready_for("threat_intel")
    _set(run, parsing_result_json=None)
    monkeypatch.setattr(commands, "_spawn_background", lambda *a, **k: pytest.fail("must not spawn"))
    app = _load_backend().create_app({"TESTING": True, "AEGIS_CASE_DB_PATH": wss.DB_FILE,
                                      "AEGIS_CASE_VIEW_BUILDER": lambda *_: {}})
    response = app.test_client().post(f"/api/cases/{CASE}/stages/threat_intel/runs")
    assert response.status_code == 409
    error = response.get_json()["error"]
    assert error["code"] == "STAGE_NOT_READY"
    assert error["details"]["reason_code"] == "missing_parsing_result"
    assert _state()["threat_intel_status"] == "Pending"


# ── 27-28: Phase 3 / Phase 4 handoff unchanged for canonical inputs ─────────

def test_phase3_and_phase4_handoff_contents_for_canonical_inputs(monkeypatch):
    import agents.investigation.skills_sidecar as skills_sidecar
    monkeypatch.setattr(skills_sidecar, "build_skills_context", lambda *a, **k: {"available": False})
    run = _ready_for("reporting")
    readiness = _r("reporting")
    inputs = readiness["inputs"]
    wf.handoff_to_reporting(inputs["triage"], {"id": CASE}, inputs["investigation"],
                            threat_intel_result=inputs["threat_intel"],
                            incident_id=CASE, run_id=run, reporting_stage_attempt=1)
    attempt = wf.reporting_attempt_dir(CASE, run, 1)
    load = lambda rel: json.loads((attempt / rel).read_text(encoding="utf-8"))
    triage_doc = load("outputs/triage_result.json")
    assert (triage_doc["incident_id"], triage_doc["triage_level"], triage_doc["status"]) == (CASE, "HIGH", "completed")
    assert "severity" not in triage_doc
    assert load("inputs/enriched_alert.json")["enriched_alert_source"] == "threat_intelligence"
    assert load("inputs/processed_alert.json") == inputs["parsing"]["processed_alert"]
    history = load("inputs/approval_history.json")
    assert [(r["approval_stage"], r["decision"], r["stage_attempt"]) for r in history] == \
        [("triage", "approved", 1), ("investigation", "approved", 1)]
    metadata = load("inputs/workflow_metadata.json")
    assert (metadata["run_id"], metadata["investigation_attempt"]) == (run, 1)


# ── 30 + side effects ───────────────────────────────────────────────────────

def _snapshot(tmp_path):
    with sqlite3.connect(str(wss.DB_FILE)) as con:
        dump = "\n".join(con.iterdump())
    files = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")
                   if p.is_file() and not p.name.endswith(("-wal", "-shm", "-journal")))
    return dump, files


def _evaluate_everything():
    for stage in wr.STAGES:
        wr.evaluate_stage_readiness(CASE, stage)
        wr.evaluate_stage_readiness(CASE, stage, run_id="someone-else")
    commands.available_actions(_state())


def test_readiness_evaluation_has_no_persistent_side_effects(tmp_path, real_db_attempts):
    run = _ready_for("reporting")
    for mutate in (lambda: None,                                   # ready, raw incident present
                   lambda: _set(run, raw_incident_path=None),      # ready, degraded
                   lambda: _set(run, parsing_result_json=None)):   # not ready
        mutate()
        before = _snapshot(tmp_path)
        _evaluate_everything()
        assert _snapshot(tmp_path) == before   # no DB row, status, approval, activity or file written
    assert real_db_attempts == []
