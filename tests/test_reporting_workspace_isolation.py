"""tests/test_reporting_workspace_isolation.py -- canonical audit Phase 7.

A canonical (run-scoped) Reporting attempt uses only CURRENT CASE + CURRENT
RUN + CURRENT REPORTING ATTEMPT: its own reporting_attempt_dir() inputs,
outputs, exports, manifests and LLM narrative cache. Shared
agents/reporting/inputs|outputs files have zero influence; the workspace
mode is explicit (REPORTING_WORKSPACE_MODE); nothing reaches Awaiting
Approval without a verified candidate set; approval and Approve-enablement
bind to the current attempt only.

Layers:
* engine level -- the real durable stage (handoff, verification, state
  transitions, approval) with FAKE Reporting/export subprocess scripts in a
  temporary REP_DIR that record what they were given;
* adapter in-process -- the real run-scoped/legacy adapter functions with a
  temporary "shared" PROJECT_ROOT full of stale files;
* one REAL run-scoped adapter subprocess (run_reporting.py ->
  reporting_agent.py, LLM and Postgres off) inside a SANDBOX copy of the
  Reporting package, so even its PROJECT_ROOT is temporary. (The real
  export_documents.py subprocess is NOT run: its report-set registration
  writes workflow_state_store's fixed, non-redirectable real DB path.)

Temporary DBs / roots only; sqlite3.connect aimed at the real soc_db/ is
redirected and recorded.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest

import canonical_seed as seed
from agents.reporting import reporting_approval as ra
from agents.reporting import report_editing as re_
from workflow import commands
from workflow import engine as wf
from workflow import state_store as wss

CASE = "INC-P7-A"
OTHER = "INC-P7-B"
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_REP_PKG = _PROJECT_ROOT / "agents" / "reporting"
_REAL_SOC_DB = (_PROJECT_ROOT / "soc_db").resolve()
_PLACEHOLDERS = ("INC-0001", "UNKNOWN-ALERT", "UNKNOWN-INCIDENT", "TKT-UNKNOWN")
STALE = "STALE-SHARED-INC-P7-B"


# ── fake subprocess scripts ────────────────────────────────────────────────

FAKE_RUN_REPORTING = textwrap.dedent(r'''
    import hashlib, json, os, sys
    from pathlib import Path

    here = Path.cwd()
    keys = ("REPORTING_WORKSPACE_MODE", "REPORTING_INPUT_DIR", "REPORTING_OUTPUT_DIR", "SOC_CASE_ID",
            "SOC_RUN_ID", "SOC_REPORTING_ATTEMPT", "SOC_TICKET_ID", "REPORTING_LLM_CACHE_DIR")
    rec = {"script": "run_reporting", "env": {k: os.environ.get(k) for k in keys}}
    if os.environ.get("REPORTING_WORKSPACE_MODE") != "run_scoped":
        with open(here / "observed.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        sys.exit(0)
    inp = Path(os.environ["REPORTING_INPUT_DIR"])
    out = Path(os.environ["REPORTING_OUTPUT_DIR"])
    case = os.environ["SOC_CASE_ID"]
    meta = json.loads((inp / "workflow_metadata.json").read_text(encoding="utf-8"))
    rec["inputs"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(inp.glob("*.json"))}
    cache_dir = Path(os.environ["REPORTING_LLM_CACHE_DIR"])
    cache = cache_dir / f"{case}_llm_report.json"
    rec["cache_preexisting"] = cache.exists()
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"attempt": meta["reporting_stage_attempt"]}), encoding="utf-8")
    with open(here / "observed.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    final = {"agent": "Reporting Agent", "status": "completed",
             "incident_id": os.environ.get("FAKE_RESULT_CASE") or case, "alert_id": case,
             "run_id": meta["run_id"], "reporting_stage_attempt": meta["reporting_stage_attempt"],
             "ticket_id": os.environ.get("SOC_TICKET_ID"), "summary": f"Report for {case}"}
    out.mkdir(parents=True, exist_ok=True)
    (out / "final_report.json").write_text(json.dumps(final), encoding="utf-8")
''')

FAKE_EXPORT = textwrap.dedent(r'''
    import hashlib, json, os, sys
    from pathlib import Path

    here = Path.cwd()
    mode = os.environ.get("FAKE_EXPORT_MODE", "ok")
    out = Path(os.environ["REPORTING_OUTPUT_DIR"])
    case = sys.argv[1]
    run_id = os.environ["SOC_RUN_ID"]
    attempt = int(os.environ["SOC_REPORTING_ATTEMPT"])
    attempt_dir = out.parent
    with open(here / "observed.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"script": "export_documents", "argv": sys.argv[1:],
                             "env": {k: os.environ.get(k) for k in ("REPORTING_WORKSPACE_MODE", "SOC_CASE_ID",
                                     "SOC_RUN_ID", "SOC_REPORTING_ATTEMPT", "REPORTING_OUTPUT_DIR")}}) + "\n")
    rep = out / case / "reports"
    rep.mkdir(parents=True, exist_ok=True)
    def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
    def write(name, text):
        p = rep / name
        p.write_bytes(text.encode("utf-8"))
        return p
    def entry(p): return {"path": p.relative_to(attempt_dir).as_posix(), "sha256": sha(p), "size": p.stat().st_size}
    reports, files = [], []
    for key in ("executive_summary", "technical_findings", "soc_analyst_review", "final_incident_report"):
        s = write(f"{key}.json", json.dumps({"report": key, "incident": case, "run": run_id, "attempt": attempt}))
        d = write(f"{key}.docx", f"DOCX {key} {case} {run_id} {attempt}")
        p = write(f"{key}.pdf", f"PDF {key} {case} {run_id} {attempt}")
        files += [d, p]
        reports.append({"report_type": key, "title": key, "structured_content": entry(s), "docx": entry(d),
                        "pdf": entry(p), "validation": {"status": "valid", "errors": [], "warnings": []}})
    result = {"incident_id": case, "docx": str(write("combined_incident_report.docx", f"DOCX {case}")),
              "pdf": str(write("combined_incident_report.pdf", f"PDF {case}"))}
    if mode == "missing":
        result["candidate_manifest_error"] = "FileNotFoundError: candidate manifest: 'technical_findings' pdf file missing"
        print("EXPORT_JSON:" + json.dumps(result))
        sys.exit(1)
    manifest = {"incident_id": "INC-P7-B" if mode == "wrong_case" else case,
                "run_id": "run-somewhere-else" if mode == "wrong_run" else run_id,
                "reporting_stage_attempt": attempt + (1 if mode == "wrong_attempt" else 0),
                "report_set_id": hashlib.sha256(f"{case}|{run_id}|{attempt}".encode()).hexdigest()[:32],
                "generated_at": "2026-10-04T09:00:00Z", "reports": [] if mode == "empty" else reports}
    manifest["candidate_manifest_sha256"] = hashlib.sha256(json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
    if mode == "manifest_altered":
        manifest["generated_at"] = "2030-01-01T00:00:00Z"
    mp = rep / "candidate_manifest.json"
    if mode == "outside":
        mp = Path(os.environ["FAKE_OUTSIDE_DIR"]) / "candidate_manifest.json"
        mp.parent.mkdir(parents=True, exist_ok=True)
    mp.write_text("{not json" if mode == "unreadable" else json.dumps(manifest), encoding="utf-8")
    if mode == "tamper_file":
        files[0].write_bytes(files[0].read_bytes() + b" tampered")
    if mode == "drop_file":
        files[1].unlink()
    if mode == "foreign":
        mp = Path(os.environ["FAKE_MANIFEST_PATH"])
    result.update(candidate_manifest_path=str(mp), report_set_id=manifest["report_set_id"],
                  candidate_manifest_sha256=manifest["candidate_manifest_sha256"])
    print("EXPORT_JSON:" + json.dumps(result))
''')


# ── fixtures ────────────────────────────────────────────────────────────────

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


@pytest.fixture()
def env(tmp_path, monkeypatch, real_db_attempts):
    # A short root: attempt paths nest deeply (Windows MAX_PATH).
    root = Path(tempfile.mkdtemp(prefix="p7-"))
    trusted = root / "t"
    rep = root / "rep"                      # the temporary "shared" REP_DIR
    (rep / "adapters").mkdir(parents=True)
    (rep / "adapters" / "run_reporting.py").write_text(FAKE_RUN_REPORTING, encoding="utf-8")
    (rep / "adapters" / "export_documents.py").write_text(FAKE_EXPORT, encoding="utf-8")
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    monkeypatch.setattr(wf, "PIPELINE_DB_FILE", tmp_path / "pipeline.db")
    monkeypatch.setattr(wf, "_TRUSTED_OUTPUT_ROOT", trusted)
    monkeypatch.setattr(ra, "_TRUSTED_OUTPUT_ROOT", trusted)
    monkeypatch.setattr(wf, "REP_DIR", rep)
    monkeypatch.setattr(wf, "generate_stage_ai_summary", lambda *a, **k: {})
    monkeypatch.setenv("FAKE_EXPORT_MODE", "ok")
    monkeypatch.delenv("FAKE_RESULT_CASE", raising=False)
    monkeypatch.delenv("REPORTING_WORKSPACE_MODE", raising=False)
    with commands._TASKS_LOCK:
        commands._TASKS.clear()
    wss.db_init()
    wf.pipeline_db_init()
    for case in (CASE, OTHER):
        with wss.db_connect() as con:
            con.execute("INSERT OR REPLACE INTO incidents (id, title, raw_json) VALUES (?, ?, ?)",
                        (case, f"Case {case}", json.dumps(_incident(case))))
            con.commit()
    yield {"root": root, "rep": rep, "trusted": trusted, "monkeypatch": monkeypatch}
    with commands._TASKS_LOCK:
        commands._TASKS.clear()
    shutil.rmtree(root, ignore_errors=True)


# ── canonical builders ──────────────────────────────────────────────────────

def _incident(case):
    return {"id": case, "title": f"Case {case}", "alertMeta": {"SourceIp": ["10.0.0.5"]}}


def _triage(case, run):
    return {"ticket": {"incident_id": case, "unc": f"#{case[-1]}0042A", "classification": "HIGH",
                       "title": f"Case {case}"},
            "metakeys_payload": {"incident_id": case, "incident_title": f"Case {case}"},
            "trace": [], "used_parsed_context": True, "run_id": run}


def _ti(case, run):
    return {"incident_id": case, "run_id": run, "stage": "threat_intelligence", "status": "completed",
            "enrichment_risk_level": "Low", "enrichment_risk_score": 5, "warnings": [],
            "enriched_alert": {"incident_id": case}, "threat_intelligence": {"indicators": []}}


def _inv(case, run):
    return {"agent": "Investigation Agent", "incident_id": case, "investigated_for": case,
            "status": "completed", "severity": "High", "summary": f"Investigation of {case}", "run_id": run}


def _set(case, run, **cols):
    wss._guarded_update(case, run, {k: (json.dumps(v) if k.endswith("_json") and not isinstance(v, (str, type(None))) else v)
                                    for k, v in cols.items()})


def _ready_for_reporting(case=CASE):
    """One canonical run of `case` whose Reporting is startable (real
    Parsing/raw/Triage/TI/Investigation data and real approvals)."""
    run = wss.start_run(case, allow_retry=True)
    seed.seed_parsing_and_raw_incident(case, run, _incident(case))
    wss.save_triage_result(case, run, _triage(case, run))
    _set(case, run, triage_status="Awaiting Approval", workflow_status="Awaiting Approval", approval_stage="triage")
    wss.approve_triage(case, run, approved_by="Analyst")
    _set(case, run, threat_intel_status="Complete", threat_intel_result_json=_ti(case, run),
         investigation_status="Awaiting Approval", investigation_result_json=_inv(case, run),
         workflow_status="Awaiting Approval", approval_stage="investigation")
    wss.approve_investigation(case, run, approved_by="Analyst")
    return run


def _run_reporting(case=CASE, run=None, *, rerun=False):
    run = run or _ready_for_reporting(case)
    (commands.rerun_stage if rerun else commands.start_stage)(case, "reporting", executor=lambda *a: None)
    result = wf.run_reporting_stage(case, run)
    return run, result


def _attempt(case, run, n=1):
    return wf.reporting_attempt_dir(case, run, n)


def _observed(env_, script=None):
    path = env_["rep"] / "observed.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
    return [r for r in rows if script is None or r["script"] == script]


def _tree(directory: Path) -> dict[str, str]:
    """relative path -> sha256 of every file under `directory`."""
    if not directory.exists():
        return {}
    return {p.relative_to(directory).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.rglob("*")) if p.is_file() and "__pycache__" not in p.parts}


def _text_of(directory: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="ignore")
                     for p in sorted(directory.rglob("*")) if p.is_file())


def _plant_stale_shared(base: Path) -> None:
    """Deliberately WRONG shared workflow files (another case, previous runs)."""
    foreign = {"incident_id": OTHER, "alert_id": OTHER, "marker": STALE}
    for folder in ("inputs", "outputs"):
        d = base / folder
        d.mkdir(parents=True, exist_ok=True)
        for name, data in (
                ("triage_result.json", {**foreign, "ticket": {"unc": "#STALE", "incident_id": OTHER}}),
                ("threat_intel_result.json", {**foreign, "status": "completed", "run_id": "old-run"}),
                ("investigation_result.json", {**foreign, "status": "completed", "reporting_mode": "standard"}),
                ("approval_result.json", {**foreign, "decision": "approved", "reporting_mode": "standard"}),
                ("investigation_approval_result.json", {**foreign, "decision": "approved"}),
                ("processed_alert.json", foreign),
                ("enriched_alert.json", foreign),
                ("workflow_metadata.json", {**foreign, "run_id": "old-run", "reporting_stage_attempt": 9}),
                ("final_report.json", {**foreign, "status": "completed"}),
                ("reporting_result.json", {**foreign, "status": "completed"})):
            (d / name).write_text(json.dumps(data), encoding="utf-8")
    stale_reports = base / "outputs" / CASE / "reports"
    stale_reports.mkdir(parents=True, exist_ok=True)
    (stale_reports / "candidate_manifest.json").write_text(json.dumps(
        {"incident_id": CASE, "run_id": "old-run", "reporting_stage_attempt": 1, "marker": STALE}), encoding="utf-8")
    (stale_reports / "report_manifest.json").write_text(json.dumps({"incident_id": OTHER, "marker": STALE}),
                                                        encoding="utf-8")
    cache = base / "outputs" / "report_cache"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / f"{CASE}_llm_report.json").write_text(json.dumps({"marker": STALE}), encoding="utf-8")


# ── 1-3 + C: explicit workspace mode, canonical identity to subprocesses ────

def test_run_scoped_subprocesses_get_explicit_mode_and_canonical_identity(env):
    run, result = _run_reporting()
    attempt = _attempt(CASE, run)
    rep_env = _observed(env, "run_reporting")[0]["env"]
    assert rep_env == {
        "REPORTING_WORKSPACE_MODE": "run_scoped",
        "REPORTING_INPUT_DIR": str(attempt / "inputs"),
        "REPORTING_OUTPUT_DIR": str(attempt / "outputs"),
        "SOC_CASE_ID": CASE, "SOC_RUN_ID": run, "SOC_REPORTING_ATTEMPT": "1",
        "SOC_TICKET_ID": "TKT-A0042A",
        "REPORTING_LLM_CACHE_DIR": str(attempt / "outputs" / "report_cache"),
    }
    export = _observed(env, "export_documents")[0]
    assert export["argv"] == [CASE]
    assert export["env"] == {"REPORTING_WORKSPACE_MODE": "run_scoped", "SOC_CASE_ID": CASE, "SOC_RUN_ID": run,
                             "SOC_REPORTING_ATTEMPT": "1", "REPORTING_OUTPUT_DIR": str(attempt / "outputs")}
    assert result["candidate_manifest_check"]["ok"] is True
    state = wss.get_state(CASE)
    assert (state["reporting_status"], state["workflow_status"]) == ("Awaiting Approval", "Awaiting Approval")


@pytest.mark.parametrize("missing", ["reporting_input_dir", "reporting_output_dir", "run_id",
                                     "reporting_stage_attempt", "incident_id"])
def test_partial_run_scoped_configuration_fails_before_any_subprocess(env, monkeypatch, missing):
    monkeypatch.setattr(wf, "_run_subprocess", lambda *a, **k: pytest.fail("no subprocess may start"))
    monkeypatch.setattr(wf, "_run_subprocess_streaming", lambda *a, **k: pytest.fail("no subprocess may start"))
    kwargs = {"reporting_input_dir": env["root"] / "i", "reporting_output_dir": env["root"] / "o",
              "run_id": "run-x", "reporting_stage_attempt": 1, "incident_id": CASE}
    kwargs[missing] = None
    with pytest.raises(ValueError, match="reporting_workspace_incomplete"):
        wf.run_reporting("TKT-1", **kwargs)
    with pytest.raises(ValueError, match="reporting_workspace_incomplete"):
        wf.export_report_documents(CASE, reporting_output_dir=env["root"] / "o", run_id=None,
                                   reporting_stage_attempt=1)


def test_legacy_mode_is_explicit_and_carries_no_run_scoped_identity(env):
    wf.run_reporting("TKT-LEGACY")
    legacy = _observed(env, "run_reporting")[0]["env"]
    assert legacy["REPORTING_WORKSPACE_MODE"] == "legacy"
    assert legacy["SOC_CASE_ID"] is None and legacy["SOC_REPORTING_ATTEMPT"] is None


# ── 4-11, 21: stale shared files have zero influence ─────────────────────────

def test_stale_shared_files_are_never_read_copied_or_written(env):
    _plant_stale_shared(env["rep"])
    shared_before = {f: _tree(env["rep"] / f) for f in ("inputs", "outputs")}
    run, result = _run_reporting()
    attempt = _attempt(CASE, run)

    # shared folders: byte-for-byte unchanged, nothing added or removed
    assert {f: _tree(env["rep"] / f) for f in ("inputs", "outputs")} == shared_before
    # nothing from them reached the attempt (inputs, outputs, manifest, cache)
    assert STALE not in _text_of(attempt) and OTHER not in _text_of(attempt / "inputs")
    assert _observed(env, "run_reporting")[0]["cache_preexisting"] is False
    # identity, approval state and candidate set are this case/run/attempt's
    assert result["incident_id"] == CASE and result["status"] == "completed"
    manifest_path = Path(result["document_exports"]["candidate_manifest_path"])
    assert attempt.resolve() in manifest_path.resolve().parents
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert (manifest["incident_id"], manifest["run_id"], manifest["reporting_stage_attempt"]) == (CASE, run, 1)
    history = json.loads((attempt / "inputs" / "approval_history.json").read_text(encoding="utf-8"))
    assert {h["run_id"] for h in history} == {run} and {h["incident_id"] for h in history} == {CASE}
    meta = json.loads((attempt / "inputs" / "workflow_metadata.json").read_text(encoding="utf-8"))
    assert (meta["incident_id"], meta["run_id"], meta["reporting_stage_attempt"]) == (CASE, run, 1)
    assert not (attempt / "inputs" / "approval_result.json").exists()
    assert not (attempt / "inputs" / "investigation_approval_result.json").exists()
    assert wss.get_state(CASE)["reporting_status"] == "Awaiting Approval"


def test_attempt_inputs_come_only_from_the_canonical_handoff(env):
    run, _ = _run_reporting()
    attempt = _attempt(CASE, run)
    handoff = json.loads((attempt / "inputs" / "handoff_manifest.json").read_text(encoding="utf-8"))
    assert (handoff["incident_id"], handoff["run_id"], handoff["reporting_stage_attempt"]) == (CASE, run, 1)
    for rel, meta in handoff["files"].items():
        assert hashlib.sha256((attempt / rel).read_bytes()).hexdigest() == meta["sha256"], rel
    seen_by_agent = _observed(env, "run_reporting")[0]["inputs"]
    expected = {Path(rel).name for rel in handoff["files"] if Path(rel).parts[0] == "inputs"} \
        | {"handoff_manifest.json"}
    assert {"processed_alert.json", "approval_history.json", "workflow_metadata.json",
            "threat_intel_result.json", "enriched_alert.json", "ticket_context.json"} <= expected
    assert set(seen_by_agent) == expected
    # Phase 5: processed_alert is the canonical Parsing result's own
    parsing = wf.load_parsing_result_for_run(CASE, run)
    assert json.loads((attempt / "inputs" / "processed_alert.json").read_text(encoding="utf-8")) \
        == parsing["processed_alert"]


def test_every_generated_artefact_stays_inside_the_attempt(env):
    run = _ready_for_reporting()
    before = _tree(env["trusted"])
    shared_before = _tree(env["rep"])
    _run_reporting(CASE, run)
    after = _tree(env["trusted"])
    assert {k: v for k, v in after.items() if k in before} == before      # nothing pre-existing changed
    new = set(after) - set(before)
    attempt_rel = _attempt(CASE, run).relative_to(env["trusted"]).as_posix()
    run_rel = wf._artifact_dir(CASE, run).relative_to(env["trusted"]).as_posix()
    assert new and all(p.startswith(attempt_rel + "/") for p in new), sorted(new)
    for name in ("reporting_handoff.json", "reporting_output.json"):
        assert f"{attempt_rel}/{name}" in new
        assert not (wf._artifact_dir(CASE, run) / name).exists()          # no run-level copy any more
    assert any(p.startswith(f"{attempt_rel}/outputs/report_cache/") for p in new)   # attempt-local cache
    assert any(p.startswith(f"{attempt_rel}/outputs/{CASE}/reports/") for p in new)  # exports + manifest
    # the only file the run adds to the (temporary) shared REP_DIR is the fakes' own log
    assert set(_tree(env["rep"])) - set(shared_before) == {"observed.jsonl"}
    assert run_rel  # (artifact dir exists for the run's other stages)


# ── 12-13, 22: Case A and Case B are isolated ───────────────────────────────

def test_two_cases_have_isolated_inputs_outputs_manifests_and_hashes(env):
    run_a, result_a = _run_reporting(CASE)
    a_dir = _attempt(CASE, run_a)
    a_tree = _tree(a_dir)
    run_b, result_b = _run_reporting(OTHER)
    b_dir = _attempt(OTHER, run_b)

    assert a_dir != b_dir and not str(b_dir).startswith(str(a_dir)) and not str(a_dir).startswith(str(b_dir))
    assert _tree(a_dir) == a_tree                                   # B never overwrote A
    assert OTHER not in _text_of(a_dir / "inputs") and CASE not in _text_of(b_dir / "inputs")
    check_a, check_b = result_a["candidate_manifest_check"], result_b["candidate_manifest_check"]
    assert check_a["ok"] and check_b["ok"]
    assert check_a["report_set_id"] != check_b["report_set_id"]
    assert check_a["candidate_manifest_sha256"] != check_b["candidate_manifest_sha256"]
    b_manifest = result_b["document_exports"]["candidate_manifest_path"]
    with pytest.raises(ra.CandidateSetError) as exc:
        ra.verify_candidate_set(b_manifest, incident_id=CASE, run_id=run_a, reporting_stage_attempt=1)
    assert exc.value.reason_code == "candidate_manifest_outside_attempt"


def test_case_a_cannot_publish_case_b_candidate_set(env, monkeypatch):
    run_b, result_b = _run_reporting(OTHER)
    monkeypatch.setenv("FAKE_EXPORT_MODE", "foreign")
    monkeypatch.setenv("FAKE_MANIFEST_PATH", result_b["document_exports"]["candidate_manifest_path"])
    run_a, result_a = _run_reporting(CASE)
    assert result_a["status"] == "failed"
    assert result_a["candidate_manifest_check"]["reason_code"] == "candidate_manifest_outside_attempt"
    assert wss.get_state(CASE)["reporting_status"] == "Failed"
    assert wss.get_state(OTHER)["reporting_status"] == "Awaiting Approval"


# ── 14-15, 22-23: consecutive attempts are isolated ─────────────────────────

def _attempt_one_rejected_then_rerun(env):
    run, first = _run_reporting()
    a1 = _attempt(CASE, run, 1)
    commands.reject_stage(CASE, "reporting", analyst="Analyst", comments="Redo the summary")
    return run, first, a1


def test_attempt_two_gets_a_new_workspace_and_never_reuses_attempt_one(env):
    run, first, a1 = _attempt_one_rejected_then_rerun(env)
    a1_tree = _tree(a1)
    _, second = _run_reporting(CASE, run, rerun=True)
    a2 = _attempt(CASE, run, 2)

    assert wss.get_state(CASE)["reporting_attempt"] == 2 and a2.exists()
    assert _tree(a1) == a1_tree                                     # history kept, untouched
    runs = _observed(env, "run_reporting")
    assert runs[1]["env"]["REPORTING_INPUT_DIR"] == str(a2 / "inputs")
    assert runs[1]["env"]["REPORTING_LLM_CACHE_DIR"] == str(a2 / "outputs" / "report_cache")
    assert runs[1]["cache_preexisting"] is False                    # attempt 1's cache never read
    assert second["candidate_manifest_check"]["ok"]
    assert second["candidate_manifest_check"]["report_set_id"] != first["candidate_manifest_check"]["report_set_id"]
    m2 = Path(second["document_exports"]["candidate_manifest_path"])
    assert a2.resolve() in m2.resolve().parents
    assert json.loads(m2.read_text(encoding="utf-8"))["reporting_stage_attempt"] == 2
    meta2 = json.loads((a2 / "inputs" / "workflow_metadata.json").read_text(encoding="utf-8"))
    assert meta2["reporting_stage_attempt"] == 2
    run_dir = wf._artifact_dir(CASE, run)
    assert (run_dir / "reporting" / "attempt_1" / "reporting_output.json").exists()
    assert (run_dir / "reporting" / "attempt_2" / "reporting_output.json").exists()


def test_attempt_two_cannot_reuse_attempt_one_manifest(env, monkeypatch):
    run, first, _ = _attempt_one_rejected_then_rerun(env)
    monkeypatch.setenv("FAKE_EXPORT_MODE", "foreign")
    monkeypatch.setenv("FAKE_MANIFEST_PATH", first["document_exports"]["candidate_manifest_path"])
    _, second = _run_reporting(CASE, run, rerun=True)
    assert second["status"] == "failed"
    assert second["candidate_manifest_check"]["reason_code"] == "candidate_manifest_outside_attempt"
    state = wss.get_state(CASE)
    assert (state["reporting_status"], state["workflow_status"]) == ("Failed", "Failed")
    assert "candidate_manifest_outside_attempt" in state["last_error"]


def _materialised_row(case, run, attempt_n, set_id):
    manifest = _attempt(case, run, attempt_n) / "outputs" / case / "reports" / "reviewed" / "candidate_manifest.json"
    wss.create_report_set(case, run, report_set_id=set_id, based_on_report_set_id=None,
                          manifest_path=str(manifest), manifest_sha256="x" * 64,
                          report_version_ids={}, status="materialised", created_by="Analyst")
    return manifest


def _approve_action(state):
    return next(a for a in commands.available_actions(state)["stages"]["reporting"] if a["type"] == "approve")


def test_attempt_one_materialised_set_never_enables_or_drives_attempt_two_approval(env):
    run, _, _ = _attempt_one_rejected_then_rerun(env)
    _materialised_row(CASE, run, 1, "reviewed-in-attempt-1")
    _, second = _run_reporting(CASE, run, rerun=True)
    state = wss.get_state(CASE)
    assert state["reporting_status"] == "Awaiting Approval" and state["reporting_attempt"] == 2

    assert ra.current_attempt_materialised_set(CASE, run, 2) is None
    approve = _approve_action(state)
    assert approve["enabled"] is False and "Submit the reviewed report set" in approve["reason"]
    _materialised_row(CASE, run, 2, "reviewed-in-attempt-2")
    assert ra.current_attempt_materialised_set(CASE, run, 2)["report_set_id"] == "reviewed-in-attempt-2"
    assert _approve_action(wss.get_state(CASE))["enabled"] is True


def test_approval_verifies_and_binds_the_current_attempt_candidate_only(env):
    run, _, _ = _attempt_one_rejected_then_rerun(env)
    _materialised_row(CASE, run, 1, "reviewed-in-attempt-1")      # stale; must be ignored
    _, second = _run_reporting(CASE, run, rerun=True)
    commands.approve_stage(CASE, "reporting", analyst="Analyst Two", comments="Looks right")
    approved = wss.get_latest_approved_reporting_set(CASE, run)
    assert approved["reporting_stage_attempt"] == 2
    assert approved["report_set_id"] == second["candidate_manifest_check"]["report_set_id"]
    assert approved["candidate_manifest_sha256"] == second["candidate_manifest_check"]["candidate_manifest_sha256"]
    assert (approved["approved_by"], approved["comments"]) == ("Analyst Two", "Looks right")
    state = wss.get_state(CASE)
    assert (state["reporting_status"], state["workflow_status"]) == ("Approved", "Complete")
    assert {r["report_set_id"]: r["status"] for r in wss.list_report_sets(CASE, run)} \
        == {"reviewed-in-attempt-1": "materialised"}             # never flipped


# ── 16-21: no Awaiting Approval without a verified candidate set ────────────

@pytest.mark.parametrize("mode,code", [
    ("missing", "candidate_manifest_missing"),
    ("unreadable", "candidate_manifest_unreadable"),
    ("outside", "candidate_manifest_outside_attempt"),
    ("wrong_case", "candidate_manifest_identity_mismatch"),
    ("wrong_run", "candidate_manifest_run_mismatch"),
    ("wrong_attempt", "candidate_manifest_attempt_mismatch"),
    ("empty", "candidate_manifest_empty"),
    ("drop_file", "candidate_file_missing"),
    ("tamper_file", "candidate_file_hash_mismatch"),
    ("manifest_altered", "candidate_manifest_hash_mismatch"),
])
def test_candidate_set_failures_fail_reporting_with_a_stable_reason(env, monkeypatch, mode, code):
    monkeypatch.setenv("FAKE_EXPORT_MODE", mode)
    monkeypatch.setenv("FAKE_OUTSIDE_DIR", str(env["rep"] / "outputs" / "elsewhere"))
    run, result = _run_reporting()
    assert result["status"] == "failed"
    assert result["candidate_manifest_check"]["ok"] is False
    assert result["candidate_manifest_check"]["reason_code"] == code
    assert result["error"].startswith(code + ": ")
    state = wss.get_state(CASE)
    assert (state["reporting_status"], state["workflow_status"]) == ("Failed", "Failed")
    assert state["approval_stage"] is None and code in state["last_error"]
    assert json.loads(state["reporting_result_json"])["candidate_manifest_check"]["reason_code"] == code
    assert not [a for a in wss.get_approval_history(CASE, run) if a["approval_stage"] == "reporting"]


def test_valid_candidate_set_reaches_awaiting_approval(env):
    run, result = _run_reporting()
    check = result["candidate_manifest_check"]
    assert check["ok"] is True and check["reports"] == 4 and check["report_set_id"]
    state = wss.get_state(CASE)
    assert (state["reporting_status"], state["workflow_status"], state["approval_stage"]) \
        == ("Awaiting Approval", "Awaiting Approval", "reporting")
    assert result["run_id"] == run and result["reporting_stage_attempt"] == 1


def test_foreign_case_result_is_refused_before_export(env, monkeypatch):
    monkeypatch.setenv("FAKE_RESULT_CASE", OTHER)
    run, result = _run_reporting()
    assert result["status"] == "failed" and result["error"].startswith("reporting_result_identity_mismatch")
    assert _observed(env, "export_documents") == []
    assert wss.get_state(CASE)["reporting_status"] == "Failed"


def test_verify_candidate_set_is_shared_by_stage_and_approval(env):
    run, result = _run_reporting()
    path = result["document_exports"]["candidate_manifest_path"]
    manifest = ra.verify_candidate_set(path, incident_id=CASE, run_id=run, reporting_stage_attempt=1)
    assert manifest == ra._verify_candidate_manifest(path, incident_id=CASE, run_id=run,
                                                     expected_reporting_attempt=1)
    for kwargs, code in ((dict(incident_id=CASE, run_id=run, reporting_stage_attempt=2),
                          "candidate_manifest_outside_attempt"),
                         (dict(incident_id=CASE, run_id=run, reporting_stage_attempt=1), None)):
        if code:
            with pytest.raises(ra.CandidateSetError) as exc:
                ra.verify_candidate_set(path, **kwargs)
            assert exc.value.reason_code == code
    with pytest.raises(ra.CandidateSetError) as exc:
        ra.verify_candidate_set(None, incident_id=CASE, run_id=run, reporting_stage_attempt=1)
    assert exc.value.reason_code == "candidate_manifest_missing"


# ── 23-25: placeholders never appear in run-scoped artefacts ────────────────

def test_run_scoped_attempt_artefacts_carry_no_placeholder_identity(env):
    run, result = _run_reporting()
    text = _text_of(_attempt(CASE, run)) + json.dumps(result)
    for placeholder in _PLACEHOLDERS:
        assert placeholder not in text, placeholder


# ── Phase 6: readiness still refuses before any workspace exists ────────────

def test_unready_reporting_is_refused_before_any_attempt_workspace(env, monkeypatch):
    run = _ready_for_reporting()
    commands.start_stage(CASE, "reporting", executor=lambda *a: None)
    _set(CASE, run, investigation_result_json=None)
    monkeypatch.setattr(wf, "run_reporting", lambda *a, **k: pytest.fail("subprocess must not start"))
    result = wf.run_reporting_stage(CASE, run)
    assert result["readiness"]["reason_code"] == "missing_investigation_result"
    assert not _attempt(CASE, run).exists()
    assert not (wf._artifact_dir(CASE, run) / "reporting").exists()


# ── O: stale reviewed versions are refused on submission ────────────────────

def _blocks(text):
    return [{"type": "paragraph", "text": text}]


def _review_components(run, source_set):
    for report_type in ("executive_summary", "technical_findings", "soc_analyst_review"):
        version = re_.save_report_edit(CASE, run, report_type, _blocks(f"{report_type} {source_set}"),
                                       "Analyst", source_report_set_id=source_set)
        re_.mark_reviewed(CASE, run, report_type, "Analyst", expected_report_version_id=version["id"])
    final = wss.get_latest_report_version(CASE, run, "final_incident_report")
    re_.mark_reviewed(CASE, run, "final_incident_report", "Analyst", expected_report_version_id=final["id"])


def _attempt_state(run, attempt_n, set_id):
    _set(CASE, run, reporting_attempt=attempt_n,
         reporting_result_json={"document_exports": {"report_set_id": set_id}} if set_id else {})


def test_versions_reviewed_in_an_earlier_attempt_are_refused(env):
    run = wss.start_run(CASE, allow_retry=True)
    _attempt_state(run, 1, "set-attempt-1")
    _review_components(run, "set-attempt-1")
    _attempt_state(run, 2, "set-attempt-2")                         # Reporting re-ran
    with pytest.raises(re_.StaleReviewedVersionError) as exc:
        re_.submit_for_approval(CASE, run, 2, analyst="Analyst")
    assert exc.value.reason_code == "reviewed_version_outdated" and "Outdated" in str(exc.value)
    assert wss.list_report_sets(CASE, run) == []                    # nothing materialised
    assert not _attempt(CASE, run, 2).exists()

    # The analyst explicitly replaces each with the current AI version and reviews again.
    for report_type in ("executive_summary", "technical_findings", "soc_analyst_review"):
        version = re_.discard_report_edit(CASE, run, report_type, "Analyst",
                                          ai_blocks=_blocks(f"AI {report_type} attempt 2"),
                                          ai_report_set_id="set-attempt-2")
        re_.mark_reviewed(CASE, run, report_type, "Analyst", expected_report_version_id=version["id"])
    final = wss.get_latest_report_version(CASE, run, "final_incident_report")
    re_.mark_reviewed(CASE, run, "final_incident_report", "Analyst", expected_report_version_id=final["id"])
    manifest = re_.submit_for_approval(CASE, run, 2, analyst="Analyst")
    assert manifest["reporting_stage_attempt"] == 2
    assert ra.current_attempt_materialised_set(CASE, run, 2)["report_set_id"] == manifest["report_set_id"]


def test_submission_needs_a_current_attempt_candidate_set(env):
    run = wss.start_run(CASE, allow_retry=True)
    _attempt_state(run, 1, None)
    _review_components(run, "set-attempt-1")
    with pytest.raises(re_.StaleReviewedVersionError) as exc:
        re_.submit_for_approval(CASE, run, 1, analyst="Analyst")
    assert exc.value.reason_code == "no_current_candidate_set"
    _attempt_state(run, 2, "set-attempt-1")
    with pytest.raises(re_.StaleReviewedVersionError) as exc:      # not the current attempt
        re_.submit_for_approval(CASE, run, 1, analyst="Analyst")
    assert exc.value.reason_code == "no_current_candidate_set"


# ── report manifest identity (finalize) ─────────────────────────────────────

def _editable_reports():
    if str(_REP_PKG) not in sys.path:
        sys.path.insert(0, str(_REP_PKG))
    from reporting import editable_reports
    return editable_reports


def test_finalize_never_uses_another_incidents_report_manifest(env):
    er = _editable_reports()
    output_dir = env["root"] / "o"
    other_dir = er.incident_report_dir(output_dir, OTHER)
    other_dir.mkdir(parents=True)
    (other_dir / "report_manifest.json").write_text(json.dumps({"incident_id": OTHER, "sections": {}}),
                                                    encoding="utf-8")
    assert er.load_manifest(output_dir, CASE)["incident_id"] == OTHER   # the unsafe fallback exists...
    with pytest.raises(FileNotFoundError, match="another incident's report manifest is never used"):
        er.finalize_candidate_manifest(output_dir, CASE, "run-1", 1)    # ...but finalize never uses it
    own_dir = er.incident_report_dir(output_dir, CASE)
    own_dir.mkdir(parents=True)
    (own_dir / "report_manifest.json").write_text(json.dumps({"incident_id": OTHER, "sections": {}}),
                                                  encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="report manifest identity mismatch"):
        er.finalize_candidate_manifest(output_dir, CASE, "run-1", 1)
    assert not er.candidate_manifest_path(output_dir, CASE).exists()


# ── the real adapter, in-process ────────────────────────────────────────────

def _adapter_modules():
    if str(_REP_PKG) not in sys.path:
        sys.path.insert(0, str(_REP_PKG))
    from adapters import common
    from adapters import run_reporting as rr
    return common, rr


@pytest.fixture()
def run_scoped_adapter(env, monkeypatch):
    """The real adapter module switched to run-scoped mode against a real
    canonical attempt workspace, with a temporary 'shared' PROJECT_ROOT full
    of stale files and ensure_reporting_inputs() turned into a tripwire."""
    common, rr = _adapter_modules()
    run = _ready_for_reporting()
    wf.handoff_to_reporting(_triage(CASE, run), _incident(CASE), _inv(CASE, run),
                            threat_intel_result=_ti(CASE, run),
                            incident_id=CASE, run_id=run, reporting_stage_attempt=1)
    attempt = _attempt(CASE, run)
    shared = env["root"] / "shared_pkg"
    _plant_stale_shared(shared)
    (attempt / "outputs" / "unknown").mkdir(parents=True)
    (attempt / "outputs" / "unknown" / "investigation_result.json").write_text(
        json.dumps({"incident_id": OTHER, "marker": STALE}), encoding="utf-8")
    (attempt / "outputs" / "investigation_approval_result.json").write_text(
        json.dumps({"decision": "approved", "reporting_mode": "MODE-FROM-STALE-APPROVAL-FILE",
                    "marker": STALE}), encoding="utf-8")
    for module in (common, rr):
        monkeypatch.setattr(module, "INPUTS_DIR", attempt / "inputs")
        monkeypatch.setattr(module, "OUTPUTS_DIR", attempt / "outputs")
    monkeypatch.setattr(rr, "RUN_SCOPED", True)
    monkeypatch.setattr(rr, "PROJECT_ROOT", shared)
    monkeypatch.setattr(rr, "ensure_reporting_inputs",
                        lambda *a, **k: pytest.fail("run-scoped mode must never call ensure_reporting_inputs"))
    for key, value in (("REPORTING_WORKSPACE_MODE", "run_scoped"), ("REPORTING_INPUT_DIR", str(attempt / "inputs")),
                       ("REPORTING_OUTPUT_DIR", str(attempt / "outputs")), ("SOC_CASE_ID", CASE),
                       ("SOC_RUN_ID", run), ("SOC_REPORTING_ATTEMPT", "1")):
        monkeypatch.setenv(key, value)
    return {"common": common, "rr": rr, "run": run, "attempt": attempt, "shared": shared}


def test_run_scoped_prepare_inputs_is_a_purely_local_copy(run_scoped_adapter):
    ctx = run_scoped_adapter
    shared_before = _tree(ctx["shared"])
    ctx["rr"]._prepare_inputs(ticket_id="TKT-A0042A")
    attempt = ctx["attempt"]
    for name in ("triage_result.json", "investigation_result.json"):
        assert (attempt / "inputs" / name).read_bytes() == (attempt / "outputs" / name).read_bytes()
    assert not (attempt / "inputs" / "approval_result.json").exists()
    assert STALE not in _text_of(attempt / "inputs")
    assert _tree(ctx["shared"]) == shared_before


def test_run_scoped_workspace_identity_is_verified_at_startup(run_scoped_adapter, monkeypatch):
    common = run_scoped_adapter["common"]
    assert common.verify_run_scoped_workspace() == {"case_id": CASE, "run_id": run_scoped_adapter["run"],
                                                    "reporting_attempt": 1}
    monkeypatch.setenv("SOC_RUN_ID", "some-other-run")
    with pytest.raises(common.WorkspaceConfigError) as exc:
        common.verify_run_scoped_workspace()
    assert exc.value.reason_code == "reporting_workspace_identity_mismatch"
    monkeypatch.setenv("SOC_RUN_ID", run_scoped_adapter["run"])
    monkeypatch.setenv("SOC_REPORTING_ATTEMPT", "2")
    with pytest.raises(common.WorkspaceConfigError) as exc:
        common.verify_run_scoped_workspace()
    assert exc.value.reason_code == "reporting_workspace_identity_mismatch"
    for key in ("SOC_CASE_ID", "REPORTING_OUTPUT_DIR", "SOC_REPORTING_ATTEMPT"):
        with monkeypatch.context() as m:
            m.delenv(key)
            with pytest.raises(common.WorkspaceConfigError) as exc:
                common.run_scoped_identity()
            assert exc.value.reason_code == "reporting_workspace_incomplete"


def _generated(attempt, case, **extra):
    target = attempt / "outputs" / case / "reporting_result.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"incident_id": case, "status": "completed", **extra}), encoding="utf-8")


_STARTED = {"success": True, "returncode": 0, "started_at": "2000-01-01T00:00:00+00:00"}


def test_run_scoped_result_takes_canonical_identity_and_attribution(run_scoped_adapter):
    ctx = run_scoped_adapter
    _generated(ctx["attempt"], CASE)
    identity = {"case_id": CASE, "run_id": ctx["run"], "reporting_attempt": 1}
    wrapper = ctx["rr"]._normalise_reporting_result(_STARTED, ticket_id="TKT-A0042A", identity=identity)
    assert (wrapper["incident_id"], wrapper["run_id"], wrapper["reporting_stage_attempt"]) == (CASE, ctx["run"], 1)
    assert wrapper["status"] == "completed" and wrapper["alert_id"] == CASE
    # never the planted approval file's mode; the canonical Investigation's
    inv = json.loads((ctx["attempt"] / "outputs" / "investigation_result.json").read_text(encoding="utf-8"))
    assert wrapper["reporting_mode"] == ctx["rr"]._resolve_reporting_mode(inv, {}, {"incident_id": CASE})
    assert wrapper["reporting_mode"] != "MODE-FROM-STALE-APPROVAL-FILE"
    assert not Path(wrapper["real_reporting_result_path"]).is_absolute()
    assert STALE not in json.dumps(wrapper)
    for placeholder in _PLACEHOLDERS:
        assert placeholder not in json.dumps(wrapper)


def test_run_scoped_result_for_another_case_fails_instead_of_relabelling(run_scoped_adapter):
    ctx = run_scoped_adapter
    _generated(ctx["attempt"], OTHER)
    identity = {"case_id": CASE, "run_id": ctx["run"], "reporting_attempt": 1}
    wrapper = ctx["rr"]._normalise_reporting_result(_STARTED, ticket_id="TKT-A0042A", identity=identity)
    assert wrapper["status"] == "failed" and wrapper["reason_code"] == "reporting_result_identity_mismatch"
    assert wrapper["incident_id"] == CASE


def test_run_scoped_result_without_alert_identity_fails_without_placeholder(run_scoped_adapter):
    ctx = run_scoped_adapter
    attempt = ctx["attempt"]
    for folder in ("inputs", "outputs"):
        for name in ("processed_alert.json", "enriched_alert.json", "triage_result.json", "investigation_result.json"):
            p = attempt / folder / name
            if p.exists():
                p.write_text(json.dumps({"status": "completed"}), encoding="utf-8")
    _generated(attempt, CASE)
    identity = {"case_id": CASE, "run_id": ctx["run"], "reporting_attempt": 1}
    wrapper = ctx["rr"]._normalise_reporting_result(_STARTED, identity=identity)
    assert wrapper["status"] == "failed" and wrapper["reason_code"] == "missing_alert_identity"
    assert wrapper["incident_id"] == CASE and not wrapper["alert_id"]
    assert "UNKNOWN-ALERT" not in json.dumps(wrapper) and "INC-0001" not in json.dumps(wrapper)


def test_legacy_prepare_inputs_uses_only_its_configured_roots(env, monkeypatch):
    common, rr = _adapter_modules()
    legacy_in, legacy_out = env["root"] / "legacy" / "inputs", env["root"] / "legacy" / "outputs"
    legacy_in.mkdir(parents=True)
    legacy_out.mkdir(parents=True)
    (legacy_out / "investigation_result.json").write_text(json.dumps({"status": "completed", "summary": "x",
                                                                      "findings": ["f"]}), encoding="utf-8")
    project = env["root"] / "legacy_project"
    _plant_stale_shared(project)
    project_before = _tree(project)
    calls = []
    real_ensure = rr.ensure_reporting_inputs
    monkeypatch.setattr(rr, "ensure_reporting_inputs",
                        lambda *a, **k: calls.append(k) or real_ensure(*a, **k))
    monkeypatch.setattr(rr, "RUN_SCOPED", False)
    monkeypatch.setattr(rr, "PROJECT_ROOT", project)
    monkeypatch.setattr(rr, "INPUTS_DIR", legacy_in)
    monkeypatch.setattr(rr, "OUTPUTS_DIR", legacy_out)
    rr._prepare_inputs(ticket_id=None)
    assert calls and calls[0]["inputs_dir"] == legacy_in and calls[0]["outputs_dir"] == legacy_out
    assert _tree(project) == project_before                 # PROJECT_ROOT never mixed in
    assert json.loads((legacy_in / "investigation_result.json").read_text(encoding="utf-8"))["summary"] == "x"


def test_export_adapter_requires_canonical_case_and_attempt_in_run_scoped_mode(env, monkeypatch):
    if str(_REP_PKG) not in sys.path:
        sys.path.insert(0, str(_REP_PKG))
    from adapters import export_documents as ex
    for key, value in (("REPORTING_OUTPUT_DIR", str(env["root"])), ("SOC_CASE_ID", CASE),
                       ("SOC_RUN_ID", "run-1"), ("SOC_REPORTING_ATTEMPT", "3")):
        monkeypatch.setenv(key, value)
    assert ex._run_scoped_identity(CASE) == ("run-1", 3, None)
    assert ex._run_scoped_identity(OTHER)[2].startswith("reporting_workspace_identity_mismatch")
    assert ex._run_scoped_identity(None)[2].startswith("reporting_workspace_incomplete")
    monkeypatch.delenv("SOC_REPORTING_ATTEMPT")                 # never defaulted to 1
    assert ex._run_scoped_identity(CASE)[2].startswith("reporting_workspace_incomplete")


# ── U: Agent Activity names the failed integrity rule ───────────────────────

def test_agent_activity_shows_the_failed_candidate_rule(env, monkeypatch, tmp_path):
    import observability
    from observability.store import query_events

    monkeypatch.setenv("FAKE_EXPORT_MODE", "tamper_file")
    assert observability.install(str(tmp_path / "activity.db"))["enabled"]
    try:
        run, _ = _run_reporting()
        store = observability.get_store()
        store.flush()
        events = query_events(case_id=CASE, run_id=run, stage="reporting", path=store.path)
    finally:
        observability.uninstall()
    rule = [e for e in events if e["event_type"] == "manifest_identity"]
    assert len(rule) == 1 and rule[0]["status"] == "failed"
    assert rule[0]["title"] == "Candidate report file hash mismatch"
    assert rule[0]["metadata"]["reason_code"] == "candidate_file_hash_mismatch"
    assert "check skipped" not in json.dumps(events)
    assert [e["status"] for e in events if e["event_type"] == "stage_result"] == ["failed"]


# ── 1-3, 32: the REAL run-scoped adapter, sandboxed ──────────────────────────

_SANDBOX_COPY = ("adapters", "agents", "backend", "config", "reporting", "report_templates", "report_assets")


def _real_shared_snapshot():
    """Read-only fingerprint of the REAL shared Reporting folders."""
    inputs = _tree(_REP_PKG / "inputs")
    outputs = {p.name: p.stat().st_mtime_ns for p in (_REP_PKG / "outputs").iterdir()
               if not p.name.startswith(".pytest-")}
    loose = {p.name: (p.stat().st_mtime_ns, p.stat().st_size) for p in (_REP_PKG / "outputs").glob("*.json")}
    return inputs, outputs, loose


def _make_sandbox() -> tuple[Path, Path]:
    """A temporary copy of the Reporting package CODE (no inputs/outputs/
    logs/runtime/testdata), so a real adapter subprocess's PROJECT_ROOT -- and
    therefore its legacy shared folders -- are temporary too."""
    sandbox = Path(tempfile.mkdtemp(prefix="p7sb-"))
    pkg = sandbox / "agents" / "reporting"
    pkg.mkdir(parents=True)
    shutil.copy2(_PROJECT_ROOT / "agents" / "__init__.py", sandbox / "agents" / "__init__.py")
    for name in _SANDBOX_COPY:
        shutil.copytree(_REP_PKG / name, pkg / name, ignore=shutil.ignore_patterns("__pycache__"))
    for p in _REP_PKG.glob("*.py"):
        shutil.copy2(p, pkg / p.name)
    return sandbox, pkg


def test_real_run_scoped_adapter_in_a_sandboxed_reporting_package(env, tmp_path):
    sandbox, pkg = _make_sandbox()
    try:
        _plant_stale_shared(pkg)                       # the sandbox's own "shared" folders
        sandbox_before = _tree(sandbox)
        real_before = _real_shared_snapshot()

        run = _ready_for_reporting()
        wf.handoff_to_reporting(_triage(CASE, run), _incident(CASE), _inv(CASE, run),
                                threat_intel_result=_ti(CASE, run),
                                incident_id=CASE, run_id=run, reporting_stage_attempt=1)
        attempt = _attempt(CASE, run)
        child_env = {k: v for k, v in os.environ.items()
                     if not k.startswith(("FAKE_", "SOC_", "REPORTING_WORKSPACE"))}
        child_env.update({
            "REPORTING_WORKSPACE_MODE": "run_scoped",
            "REPORTING_INPUT_DIR": str(attempt / "inputs"), "REPORTING_OUTPUT_DIR": str(attempt / "outputs"),
            "SOC_CASE_ID": CASE, "SOC_RUN_ID": run, "SOC_REPORTING_ATTEMPT": "1", "SOC_TICKET_ID": "TKT-A0042A",
            "REPORTING_LLM_CACHE_DIR": str(attempt / "outputs" / "report_cache"),
            "REPORTING_USE_LLM": "false", "OPENAI_API_KEY": "", "REPORTING_USE_POSTGRES": "false",
            "SOC_RUN_OUTPUT_DIR": str(tmp_path / "must-not-be-mirrored"),
            "PYTHONPATH": str(_PROJECT_ROOT),
        })
        proc = subprocess.run([sys.executable, str(pkg / "adapters" / "run_reporting.py")], cwd=str(pkg),
                              env=child_env, capture_output=True, text=True, timeout=300)
        assert proc.returncode == 0, (proc.stdout[-2000:], proc.stderr[-2000:])

        final = json.loads((attempt / "outputs" / "final_report.json").read_text(encoding="utf-8"))
        assert (final["incident_id"], final["run_id"], final["reporting_stage_attempt"]) == (CASE, run, 1)
        assert final["status"] in ("completed", "completed_with_warnings"), final.get("error_summary")
        assert final["alert_id"] == CASE
        attempt_text = _text_of(attempt)
        assert STALE not in attempt_text
        for placeholder in _PLACEHOLDERS:
            assert placeholder not in attempt_text, placeholder
        # sandbox "shared" folders and the rest of the sandbox: untouched
        after = _tree(sandbox)
        assert {k: v for k, v in after.items() if k in sandbox_before} == sandbox_before
        assert [k for k in after if k not in sandbox_before] == []
        assert not (tmp_path / "must-not-be-mirrored").exists()
        # the REAL shared Reporting folders: untouched
        assert _real_shared_snapshot() == real_before
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


def test_run_scoped_adapter_refuses_an_incomplete_configuration_without_writing(env, tmp_path):
    sandbox, pkg = _make_sandbox()
    try:
        _plant_stale_shared(pkg)
        sandbox_before = _tree(sandbox)
        out_dir = tmp_path / "attempt" / "outputs"
        child_env = {k: v for k, v in os.environ.items() if not k.startswith(("FAKE_", "SOC_"))}
        child_env.update({"REPORTING_WORKSPACE_MODE": "run_scoped",
                          "REPORTING_INPUT_DIR": str(tmp_path / "attempt" / "inputs"),
                          "REPORTING_OUTPUT_DIR": str(out_dir), "SOC_RUN_ID": "run-1",
                          "SOC_REPORTING_ATTEMPT": "1", "PYTHONPATH": str(_PROJECT_ROOT)})
        real_before = _real_shared_snapshot()
        proc = subprocess.run([sys.executable, str(pkg / "adapters" / "run_reporting.py")], cwd=str(pkg),
                              env=child_env, capture_output=True, text=True, timeout=120)
        assert proc.returncode == 2, (proc.stdout[-1500:], proc.stderr[-1500:])
        assert "reporting_workspace_incomplete" in proc.stderr and "SOC_CASE_ID" in proc.stderr
        assert not out_dir.exists() or not any(out_dir.rglob("*"))   # nothing written anywhere
        assert _tree(sandbox) == sandbox_before                        # no shared fall-back either
        assert _real_shared_snapshot() == real_before
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
