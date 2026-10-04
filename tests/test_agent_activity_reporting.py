"""Agent Activity - Reporting.

Runs the real durable stage runner (workflow.engine.run_reporting_stage):
real claim/lease, real shared Reporting workspace lock, the real run-scoped
hand-off (handoff_to_reporting) and its hash-verified manifest, the real
non-streaming subprocess runner (real child processes), real read-back of
final_report.json, the real DOCX/PDF export wrapper with its freshness
checks, the real candidate-manifest identity check, post-stage summary,
result persistence, and the real approval path
(agents.reporting.reporting_approval.approve_reporting_candidate, which
re-hashes every file of the candidate set).

The Reporting Agent itself needs OpenAI and the full template/export stack,
so ``engine.REP_DIR`` points at a temp folder holding FAKE
adapters/run_reporting.py and adapters/export_documents.py that honour the
real on-disk contract: run_reporting.py reads REPORTING_INPUT_DIR /
REPORTING_OUTPUT_DIR and writes final_report.json with the real result
fields; export_documents.py writes documents plus a candidate_manifest.json
that the real approval verifier accepts, and prints the EXPORT_JSON: line.
Behaviour is selected with FAKE_REP_MODE / FAKE_EXPORT_MODE.
"""

from __future__ import annotations

import copy
import json
import re
import textwrap
import threading
import time
from datetime import datetime
from pathlib import Path

import pytest

import observability
from agents.reporting import reporting_approval
from backend import create_app
from observability.store import query_events
from workflow import commands
from workflow import engine
from workflow import state_store as wss

CASE = "INC-REP-OBS"
SUMMARY = "Reporting produced the four core reports for analyst review."
NARRATIVE_TEXT = "UNIQUE-NARRATIVE-TEXT-7f3a: the attacker executed invoice_viewer.exe"
SECRET = "sk-abcdefghijklmnop1234"

FAKE_RUN_REPORTING = textwrap.dedent(r'''
    import json, os, sys, time
    from pathlib import Path

    MODE = os.environ.get("FAKE_REP_MODE", "ok")
    here = Path.cwd()
    inp = Path(os.environ["REPORTING_INPUT_DIR"])
    out = Path(os.environ["REPORTING_OUTPUT_DIR"])
    files = {}
    for d in (inp, out):
        for p in sorted(d.glob("*.json")):
            files[f"{d.name}/{p.name}"] = json.loads(p.read_text(encoding="utf-8"))
    keys = ("SOC_TICKET_ID", "REPORTING_USE_LLM", "REPORTING_LLM_PROVIDER", "REPORTING_LLM_TEMPERATURE",
            "REPORTING_LLM_SEED", "REPORTING_LLM_PARALLEL", "REPORTING_QUALITY_RETRY", "REPORTING_TIMEOUT",
            "SOC_RUN_ID", "SOC_REPORTING_ATTEMPT", "REPORTING_INPUT_DIR", "REPORTING_OUTPUT_DIR")
    with open(here / "observed.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"script": "run_reporting", "argv": sys.argv[1:], "cwd_name": here.name,
                             "env": {k: os.environ.get(k) for k in keys}, "files": files}) + "\n")
    print("[Reporting Adapter] Running original reporting agent with OpenAI settings from .env", flush=True)
    if MODE == "wait":
        deadline = time.time() + 30
        while not (here / "release.flag").exists() and time.time() < deadline:
            time.sleep(0.05)
    if MODE == "crash":
        print('Traceback (most recent call last):\n  File "reporting_agent.py", line 9\n'
              'RuntimeError: template engine unavailable (key sk-abcdefghijklmnop1234)', file=sys.stderr)
        sys.exit(1)

    meta = files.get("inputs/workflow_metadata.json") or {}
    inc = meta.get("incident_id") or "INC-0001"
    ticket = os.environ.get("SOC_TICKET_ID")
    FIELDS = ["executive_summary", "technical_analysis", "business_impact_explanation", "attack_narrative",
              "conclusion", "analyst_friendly_explanation", "soc_analyst_review_checklist"]

    def sr(status, hard=None, soft=None, repairs=None, retry=False):
        return {"status": status, "hard_fail_issues": hard or [], "soft_warnings": soft or [],
                "repair_actions": repairs or [], "retry_attempted": retry, "issues": (hard or []) + (soft or [])}

    sections = {k: sr("llm_used") for k in FIELDS}
    reports = {k: f"reports/editable/{k}.txt" for k in ("executive_summary", "technical_findings",
                                                         "soc_analyst_review", "soc_triage_review",
                                                         "final_incident_report")}
    reports.update({f"{k}_structured": f"reports/{k}.json" for k in list(reports)})
    reports.update({"final_report_text": "final_report.txt", "report_manifest": "reports/report_manifest.json"})
    final = {
        "agent": "Reporting Agent", "status": "completed", "report_status": "Generated for analyst review",
        "incident_id": inc, "ticket_id": ticket, "title": "Unsigned binary on HOST-07", "reporting_mode": "standard",
        "report_generation_mode": "deterministic_facts_plus_llm_narrative",
        "validation_status": "Requires analyst validation", "missing_required_fields": [],
        "recovered_fields": [{"field": "host", "recovered_from": "triage_result", "reason": "missing"}],
        "report_completeness_score": None, "report_completeness_status": "not_recorded",
        "quality_checks": {"conflicting_severity_values_detected": "Not Detected",
                           "conflicting_confidence_values_detected": "Not Detected",
                           "stale_context_detected": "Not Detected", "triage_result_available": "Yes",
                           "investigation_result_available": "Yes",
                           "threat_intelligence_result_available": "Yes", "fallback_logic_used": "No",
                           "fields_still_unavailable_from_source_telemetry": 12},
        "warnings": [], "data_consistency_status": "passed", "data_consistency": {},
        "rag_used": True, "rag_status": "Local template export context built",
        "llm_used": True, "llm_provider": "openai", "llm_model": "gpt-test-mini",
        "llm_status": "llm_enhancement_successful", "llm_quality_status": "accepted", "llm_quality_issues": [],
        "llm_section_results": sections, "llm_enhancement_score": 100, "llm_attempt_count": 7,
        "llm_cache_status": "cache_updated",
        "llm_enhanced_narrative": {k: "UNIQUE-NARRATIVE-TEXT-7f3a: the attacker executed invoice_viewer.exe"
                                   for k in FIELDS},
        "generated_reports": reports, "real_reporting_result_path": f"outputs/{inc}/reporting_result.json",
        "summary": f"Report generated for {inc}.", "subprocess": {"returncode": 0, "success": True},
    }
    if MODE == "warnings":
        sections["technical_analysis"] = sr("llm_used_with_warning", soft=["Uncertainty wording softened"])
        sections["analyst_friendly_explanation"] = sr("llm_used_after_sentence_repair",
                                                      repairs=["Trailing sentence completed"])
        sections["attack_narrative"] = sr("llm_retry_successful")
        sections["conclusion"] = sr("llm_retry_successful_after_repair_with_warning",
                                    soft=["Hedging wording"], repairs=["Trailing sentence completed"])
        final.update(llm_status="llm_enhancement_successful_with_warnings", llm_quality_status="accepted_with_warnings",
                     warnings=["Containment approval not recorded"])
    elif MODE == "fallback":
        sections["executive_summary"] = sr("deterministic_locked")
        sections["attack_narrative"] = sr("fallback_used", hard=["Prompt leakage detected"])
        sections["conclusion"] = sr("fallback_used_after_retry_failed", hard=["Output truncated"], retry=True)
        final.update(llm_status="partial_llm_enhancement_with_guardrails",
                     llm_quality_status="partial_fallback_used_due_to_hard_guardrail_failure",
                     llm_quality_issues=["conclusion: output truncated (key sk-abcdefghijklmnop1234)"])
    elif MODE == "llm_disabled":
        final.update(llm_used=False, llm_provider="not_used", llm_model="not_used",
                     llm_status="llm_disabled_deterministic_generation", llm_quality_status="not_used",
                     llm_section_results={k: sr("not_used") for k in FIELDS}, llm_attempt_count=0,
                     llm_cache_status="not_used", llm_enhancement_score=0)
    elif MODE == "cached":
        final.update(llm_section_results={k: sr("fallback_used", hard=["API error: 503"]) for k in FIELDS},
                     llm_cache_status="cached_report_used", llm_status="llm_failed_cached_report_used",
                     llm_quality_status="cached_fallback_used")
    elif MODE == "missing_fields":
        final.update(status="completed_with_warnings", missing_required_fields=["affected_host", "incident_time"],
                     data_consistency_status="failed",
                     data_consistency={"issues": [{"field": "severity", "issue": "Triage HIGH vs Investigation Medium"}]},
                     report_completeness_score=62, report_completeness_status="needs_review")
        final["quality_checks"]["conflicting_severity_values_detected"] = "Detected"
    elif MODE == "agent_failed":
        final = {"agent": "Reporting Agent", "status": "failed", "report_status": "failed", "incident_id": inc,
                 "ticket_id": ticket, "summary": "Reporting Agent failed before generating report sections.",
                 "error_summary": "KeyError: 'incident_id'", "real_reporting_result_path": None,
                 "subprocess": {"returncode": 1, "success": False}}
    elif MODE == "reconstructed":
        final = {"agent": "Reporting Agent", "status": "completed_with_warnings",
                 "report_status": "completed_with_warnings", "incident_id": inc, "ticket_id": ticket,
                 "reporting_mode": "standard", "generated_reports": reports,
                 "summary": "Reporting completed with warnings.", "subprocess": {"returncode": 1, "success": False}}
    out.mkdir(parents=True, exist_ok=True)
    (out / "final_report.json").write_text(json.dumps(final, indent=2), encoding="utf-8")
    print(f"[Reporting Adapter] Status: {final.get('status')}", flush=True)
''')

FAKE_EXPORT = textwrap.dedent(r'''
    import hashlib, json, os, sys
    from pathlib import Path

    MODE = os.environ.get("FAKE_EXPORT_MODE", "ok")
    here = Path.cwd()
    out = Path(os.environ["REPORTING_OUTPUT_DIR"])
    run_id = os.environ.get("SOC_RUN_ID")
    attempt = int(os.environ.get("SOC_REPORTING_ATTEMPT") or 1)
    inc = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    with open(here / "observed.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"script": "export_documents", "argv": sys.argv[1:], "cwd_name": here.name,
                             "env": {k: os.environ.get(k) for k in ("SOC_RUN_ID", "SOC_REPORTING_ATTEMPT",
                                                                    "REPORTING_OUTPUT_DIR")}}) + "\n")
    if MODE == "no_output":
        print("exporter crashed before writing anything", file=sys.stderr)
        sys.exit(1)
    rep = out / inc / "reports"
    rep.mkdir(parents=True, exist_ok=True)
    attempt_dir = out.parent

    def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
    def write(name, text):
        p = rep / name
        p.write_bytes(text.encode("utf-8"))
        return p
    def entry(p): return {"path": p.relative_to(attempt_dir).as_posix(), "sha256": sha(p), "size": p.stat().st_size}

    result = {"incident_id": inc}
    reports = []
    for key, title, tpl in (("executive_summary", "Executive Summary", "executive_summary_template.md.j2"),
                            ("technical_findings", "Technical Findings", "technical_findings_template.md.j2"),
                            ("soc_analyst_review", "SOC Analyst Review", "soc_analyst_review_template.md.j2"),
                            ("final_incident_report", "Final Incident Report", "incident_report_template.md.j2")):
        s = write(f"{key}.json", json.dumps({"report": key, "incident": inc}))
        d = write(f"{key}.docx", f"DOCX {key} {inc}")
        p = write(f"{key}.pdf", f"PDF {key} {inc}")
        validation = {"status": "valid", "errors": [], "warnings": []}
        if MODE == "validation_warning" and key == "technical_findings":
            validation["warnings"] = ["Evidence register contains placeholders"]
        reports.append({"report_type": key, "title": title, "filename": {"docx": d.name, "pdf": p.name},
                        "template": tpl, "structured_content": entry(s), "docx": entry(d), "pdf": entry(p),
                        "generated_at": "2026-10-03T09:00:00Z", "validation": validation})
        if key != "final_incident_report":
            result[f"{key}_docx"] = str(d)
            if MODE == "pdf_fail":
                result[f"{key}_pdf_error"] = "PDF converter not available"
            else:
                result[f"{key}_pdf"] = str(p)
    result["docx"] = str(write("combined_incident_report.docx", f"DOCX combined {inc}"))
    if MODE == "pdf_fail":
        result["pdf_error"] = "PDF converter not available"
    else:
        result["pdf"] = str(write("combined_incident_report.pdf", f"PDF combined {inc}"))
    if MODE == "manifest_error":
        result["candidate_manifest_error"] = "ReportIntegrityError: structured content missing"
        print("EXPORT_JSON:" + json.dumps(result))
        sys.exit(1)
    manifest = {"incident_id": inc, "run_id": run_id,
                "reporting_stage_attempt": attempt + (1 if MODE == "mismatch" else 0),
                "report_set_id": hashlib.sha256(inc.encode()).hexdigest()[:32],
                "generated_at": "2026-10-03T09:00:00Z", "reports": reports}
    manifest["candidate_manifest_sha256"] = hashlib.sha256(json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
    mp = rep / "candidate_manifest.json"
    mp.write_text(json.dumps(manifest), encoding="utf-8")
    result.update(candidate_manifest_path=str(mp), report_set_id=manifest["report_set_id"],
                  candidate_manifest_sha256=manifest["candidate_manifest_sha256"])
    print("EXPORT_JSON:" + json.dumps(result))
''')

MODEL_CALLS: list[dict] = []
_LOCK = threading.Lock()


def _fake_summary(prompt, *, system=None, model=None, temperature=None, max_output_tokens=None,
                  timeout=None, text_format=None):
    with _LOCK:
        MODEL_CALLS.append({"kind": "summary", "prompt": prompt, "model": model})
    return SUMMARY


TRIAGE = {"ticket": {"incident_id": CASE, "classification": "HIGH", "unc": "#00042A",
                     "incident_category": "Malware infection", "mitre_tactic": "Execution",
                     "mitre_technique": "T1204 User Execution", "summary": "Unsigned binary executed."},
          "metakeys_payload": {"incident_id": CASE, "incident_title": "Unsigned binary on HOST-07",
                               "mitre_tactic": "Execution"}}
TI = {"status": "completed", "enrichment_risk_level": "High", "enrichment_risk_score": 85,
      "threat_intelligence": {"iocs": {}}}
INV = {"status": "completed", "severity": "High", "confidence": "Medium", "incident_id": CASE,
       "summary": "Unsigned binary executed and contacted 203.0.113.45.", "indicators": ["203.0.113.45"]}


class _FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 10, 3, 9, 0, 0, tzinfo=tz)


class _FixedUUID:
    class _U:
        hex = "abc123def4567890"

    @staticmethod
    def uuid4():
        return _FixedUUID._U()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    import integrations.openai.client as openai_client

    MODEL_CALLS.clear()
    monkeypatch.setattr(openai_client, "invoke_openai_text", _fake_summary)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
    monkeypatch.setenv("FAKE_REP_MODE", "ok")
    monkeypatch.setenv("FAKE_EXPORT_MODE", "ok")
    monkeypatch.delenv("REPORTING_LLM_PARALLEL", raising=False)
    monkeypatch.delenv("REPORTING_QUALITY_RETRY", raising=False)

    def prepare(name: str, *, parsing: bool = True, fixed_run_id: bool = False) -> tuple[str, str, Path]:
        scenario = tmp_path / name
        rep_dir = scenario / "reporting"
        (rep_dir / "adapters").mkdir(parents=True)
        (rep_dir / "adapters" / "run_reporting.py").write_text(FAKE_RUN_REPORTING, encoding="utf-8")
        (rep_dir / "adapters" / "export_documents.py").write_text(FAKE_EXPORT, encoding="utf-8")
        monkeypatch.setattr(engine, "REP_DIR", rep_dir)
        monkeypatch.setattr(engine, "_TRUSTED_OUTPUT_ROOT", scenario / "artifacts")
        monkeypatch.setattr(reporting_approval, "_TRUSTED_OUTPUT_ROOT", scenario / "artifacts")
        monkeypatch.setattr(wss, "DB_FILE", scenario / "workflow.db")
        monkeypatch.setattr(engine, "PIPELINE_DB_FILE", scenario / "pipeline.db")
        engine.pipeline_db_init()
        if fixed_run_id:  # equivalence runs share one run_id so hashes are comparable
            with monkeypatch.context() as m:
                m.setattr(wss, "datetime", _FixedDateTime)
                m.setattr(wss, "uuid", _FixedUUID)
                run_id = wss.start_run(CASE)
        else:
            run_id = wss.start_run(CASE)
        raw = engine._save_run_artifact(CASE, run_id, "raw_incident.json", "raw_incident",
                                        {"incident": {"id": CASE, "title": "Unsigned binary on HOST-07",
                                                      "riskScore": 80, "alertMeta": {}},
                                         "data_availability": {}})
        wss.save_raw_incident_path(CASE, run_id, str(raw))
        if parsing:
            # Phase 5: Reporting takes processed_alert from the canonical,
            # identity-verified Parsing result for this run (parsing_result_json),
            # not from a file sitting in the parsing directory.
            wss.save_parsing_result(CASE, run_id, {
                "run_id": run_id,
                "processed_alert": {"incident_id": CASE, "source_ip": "10.20.30.41"},
            })
        wss.save_triage_result(CASE, run_id, copy.deepcopy(TRIAGE))
        wss._guarded_update(CASE, run_id, {"parsing_status": "Complete", "triage_status": "Approved",
                                           "threat_intel_status": "Complete",
                                           "threat_intel_result_json": json.dumps(TI),
                                           "investigation_status": "Approved",
                                           "investigation_result_json": json.dumps(INV),
                                           "reporting_status": "Processing",
                                           "workflow_status": "Processing"})
        return CASE, run_id, rep_dir

    return {"prepare": prepare, "monkeypatch": monkeypatch, "tmp": tmp_path}


@pytest.fixture()
def activity(tmp_path):
    state = observability.install(str(tmp_path / "agent_activity.db"))
    assert state["enabled"], state
    assert "reporting" in state["coverage"]
    yield observability.get_store()
    observability.uninstall()


def _events(store, run_id):
    assert store.flush()
    return query_events(case_id=CASE, run_id=run_id, stage="reporting", path=store.path)


def _top(events):
    return [e for e in events if not e["parent_span_id"]]


def _one(events, event_type, **match):
    found = [e for e in events if e["event_type"] == event_type
             and all(e.get(k) == v for k, v in match.items())]
    assert found, (event_type, match, [(e["event_type"], e["title"]) for e in events])
    return found[0]


_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")


def _normalise(value, scenario: Path) -> str:
    text = json.dumps(value, sort_keys=True, default=str)
    once = json.dumps(str(scenario))[1:-1]
    twice = json.dumps(once)[1:-1]  # paths inside JSON text that is itself a string value
    for form in (twice, once, str(scenario), scenario.as_posix()):
        text = text.replace(form, "<DIR>")
    text = re.sub(r'"started_at": "[^"]*"', '"started_at": "<TS>"', text)
    text = re.sub(r"\d{8}-\d{6}", "<STAMP>", text)  # run_stamp of archived exports
    # The skills sidecar's IOC correlation records its own wall-clock duration
    # (round(time.time() - t0, 2), timer started inside correlate_iocs) in the
    # hand-off; it jitters between 0.0 and 0.01 s from run to run.
    text = re.sub(r'(\\*"seconds\\*": )[\d.]+', r"\g<1>0", text)
    return _TS.sub("<TS>", text)


def _pipeline_rows(path: Path) -> list:
    import sqlite3

    con = sqlite3.connect(path)
    try:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return [(t, con.execute(f"SELECT * FROM {t} ORDER BY rowid").fetchall()) for t in tables
                if not t.startswith("sqlite_")]
    finally:
        con.close()


# Hand-off files whose bytes legitimately differ between two identical runs:
# workflow_metadata.json records a wall-clock start time, and the skills
# sidecar's investigation_result.json embeds a generation timestamp and a
# measured duration (see _normalise). Their hashes and sizes are masked;
# their content is compared after normalisation.
_VOLATILE_HANDOFF = {"inputs/workflow_metadata.json", "outputs/investigation_result.json"}


def _mask_volatile_hashes(files: dict) -> dict:
    return {rel: ({"sha256": "<varies>", "size": "<varies>"} if rel.replace("\\", "/") in _VOLATILE_HANDOFF else meta)
            for rel, meta in (files or {}).items()}


def _snapshot(case_id, run_id, rep_dir, result) -> dict:
    scenario = rep_dir.parent
    state = wss.get_state(case_id)
    observed = [json.loads(line) for line in (rep_dir / "observed.jsonl").read_text(encoding="utf-8").splitlines()] \
        if (rep_dir / "observed.jsonl").exists() else []
    for run in observed:
        manifest = (run.get("files") or {}).get("inputs/handoff_manifest.json")
        if manifest:
            manifest["files"] = _mask_volatile_hashes(manifest.get("files"))
    attempt_dir = engine.reporting_attempt_dir(case_id, run_id, int(state.get("reporting_attempt") or 1))
    manifest_path = attempt_dir / "inputs" / "handoff_manifest.json"
    handoff = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    hashes = _mask_volatile_hashes(handoff.get("files"))
    candidates = sorted(attempt_dir.rglob("candidate_manifest.json")) if attempt_dir.exists() else []
    artefacts = sorted(p.relative_to(attempt_dir).as_posix() for p in attempt_dir.rglob("*") if p.is_file()) \
        if attempt_dir.exists() else []
    return {
        "result": _normalise(result, scenario),
        "statuses": {k: state[k] for k in ("reporting_status", "workflow_status", "approval_stage",
                                           "reporting_attempt", "last_error")},
        "persisted": _normalise(json.loads(state["reporting_result_json"] or "null"), scenario),
        "ledger": [(r["stage"], r["action"]) for r in wss.get_activity(case_id)],
        "subprocess_runs": _normalise(observed, scenario),  # argv, env, every hand-off input file
        "handoff_hashes": hashes,
        "candidate_manifests": [p.read_text(encoding="utf-8") for p in candidates],
        "artefacts": _normalise(artefacts, scenario),
        "pipeline": _normalise(_pipeline_rows(engine.PIPELINE_DB_FILE), scenario),
        "model_calls": _normalise(MODEL_CALLS, scenario),
    }


# ── Equivalence ─────────────────────────────────────────────────────────────

_MODES = [("ok", "ok"), ("warnings", "ok"), ("fallback", "ok"), ("llm_disabled", "ok"), ("cached", "ok"),
          ("missing_fields", "ok"), ("agent_failed", "ok"), ("crash", "ok"), ("reconstructed", "ok"),
          ("ok", "mismatch"), ("ok", "pdf_fail"), ("ok", "manifest_error"), ("ok", "no_output"),
          ("ok", "validation_warning")]


@pytest.mark.parametrize("rep_mode,export_mode", _MODES)
def test_reporting_is_identical_with_observability_on_and_off(env, tmp_path, rep_mode, export_mode):
    env["monkeypatch"].setenv("FAKE_REP_MODE", rep_mode)
    env["monkeypatch"].setenv("FAKE_EXPORT_MODE", export_mode)

    case_id, run_off, rep_off = env["prepare"]("off", fixed_run_id=True)
    off = _snapshot(case_id, run_off, rep_off, engine.run_reporting_stage(case_id, run_off))
    MODEL_CALLS.clear()

    assert observability.install(str(tmp_path / f"eq-{rep_mode}-{export_mode}.db"))["enabled"]
    try:
        case_id, run_on, rep_on = env["prepare"]("on", fixed_run_id=True)
        on = _snapshot(case_id, run_on, rep_on, engine.run_reporting_stage(case_id, run_on))
        events = _events(observability.get_store(), run_on)
    finally:
        observability.uninstall()

    assert run_on == run_off
    assert on == off
    assert events, "observability was active for the 'on' run"
    runs = json.loads(on["subprocess_runs"].replace("<DIR>", "d").replace("<TS>", "t"))
    exported = rep_mode not in ("agent_failed", "crash")
    assert [r["script"] for r in runs] == ["run_reporting"] + (["export_documents"] if exported else [])
    expected = "Failed" if rep_mode in ("agent_failed", "crash") or export_mode == "mismatch" else "Awaiting Approval"
    assert off["statuses"]["reporting_status"] == expected


# ── Successful run ──────────────────────────────────────────────────────────

def test_successful_reporting_timeline(env, activity, tmp_path):
    case_id, run_id, rep_dir = env["prepare"]("ok")
    engine.run_reporting_stage(case_id, run_id)
    events = _events(activity, run_id)
    top = _top(events)
    shape = [(e["source"], e["event_type"], e["status"]) for e in top]
    assert shape == [
        ("orchestration", "stage_claimed", "completed"),
        ("orchestration", "workspace_lock", "completed"),
        ("system", "context_loaded", "completed"),       # raw incident
        ("system", "context_loaded", "completed"),       # triage
        ("system", "context_loaded", "completed"),       # investigation
        ("system", "context_loaded", "completed"),       # threat intelligence
        ("system", "handoff", "completed"),
        ("rule", "handoff_verification", "completed"),
        ("system", "agent_run", "running"),
        ("system", "agent_run", "completed"),
        ("system", "agent_result", "completed"),
        ("system", "deterministic_facts", "completed"),
        ("system", "rag_status", "info"),
        ("ai", "narrative_enhancement", "completed"),
        ("rule", "report_validation", "completed"),
        ("system", "templates_rendered", "completed"),
        ("system", "document_export", "running"),
        ("system", "document_export", "completed"),
        ("rule", "document_validation", "completed"),
        ("rule", "ticket_identity", "completed"),
        ("rule", "manifest_identity", "completed"),
        ("decision", "stage_result", "completed"),
        ("ai", "ai_summary", "running"),
        ("ai", "ai_summary", "completed"),
        ("orchestration", "stage_settled", "completed"),
        ("human", "approval_required", "waiting"),
    ]
    assert [e["sequence"] for e in events] == sorted(e["sequence"] for e in events)
    assert {e["stage"] for e in events} == {"reporting"}
    assert {e["stage_attempt"] for e in events} == {1}
    lock = _one(top, "workspace_lock")
    assert lock["title"] == "Reporting workspace acquired" and "no wait" in lock["detail"]
    titles = [e["title"] for e in top if e["event_type"] == "context_loaded"]
    assert titles == ["Loaded raw incident", "Loaded Triage result", "Loaded Investigation result",
                      "Loaded Threat Intelligence result"]
    handoff = _one(top, "handoff")
    text = json.dumps(handoff["metadata"]["details"])
    assert "inputs/processed_alert.json" in text and "inputs/threat_intel_result.json" in text
    assert "Parsing result (processed_alert.json) included" in text
    verify = _one(top, "handoff_verification")
    assert verify["title"] == "Hand-off manifest verified" and "re-hashed" in verify["detail"]
    running, finished = [e for e in top if e["event_type"] == "agent_run"]
    assert running["title"] == "Reporting Agent running" and running["span_id"] == finished["span_id"]
    assert finished["title"] == "Reporting Agent finished" and "exit code 0" in finished["detail"]
    settings = json.dumps(running["metadata"]["details"])
    assert '"AI narrative enhancement requested", "value": "yes"' in settings.replace('"label": ', '"')
    assert "Parallel narrative sections (max)" in settings
    decision = _one(top, "stage_result")
    assert decision["title"] == "Reporting completed" and decision["source"] == "decision"
    identity = _one(top, "manifest_identity")
    assert identity["title"] == "Candidate manifest identity verified"
    summary = [e for e in top if e["event_type"] == "ai_summary"][-1]
    assert summary["metadata"]["post_stage"] is True and summary["detail"] == SUMMARY
    assert "Generated after Reporting. Not used to construct or validate the report." in \
        json.dumps(summary["metadata"]["details"])
    llm = [e for e in events if e["event_type"] == "llm_call"]
    assert [e["status"] for e in llm] == ["running", "completed"]
    assert all(e["parent_span_id"] == summary["span_id"] for e in llm)
    waiting = _one(top, "approval_required")
    assert waiting["span_id"] == f"approval:{run_id}:reporting:1"


def test_running_view_shows_only_the_agent_running_row_while_the_agent_works(env, activity):
    env["monkeypatch"].setenv("FAKE_REP_MODE", "wait")
    case_id, run_id, rep_dir = env["prepare"]("running")
    worker = threading.Thread(target=engine.run_reporting_stage, args=(case_id, run_id))
    worker.start()
    try:
        deadline = time.time() + 20
        live: list = []
        while time.time() < deadline:
            live = _events(activity, run_id)
            if any(e["event_type"] == "agent_run" for e in live):
                break
            time.sleep(0.05)
        time.sleep(0.4)
        live = _events(activity, run_id)
    finally:
        (rep_dir / "release.flag").write_text("go", encoding="utf-8")
        worker.join(30)
    assert live[-1]["event_type"] == "agent_run" and live[-1]["status"] == "running"
    assert live[-1]["title"] == "Reporting Agent running"
    assert "not streamed" in live[-1]["detail"]
    # Nothing derived from the agent's result exists until it has finished.
    assert not [e for e in live if e["metadata"].get("result_derived")]
    assert not [e for e in live if e["source"] == "ai"]
    assert not re.search(r"\d+\s?%", json.dumps([e["title"] + e["detail"] for e in live]))
    after = _events(activity, run_id)
    first_derived = next(e for e in after if e["metadata"].get("result_derived"))
    finished = next(e for e in after if e["event_type"] == "agent_run" and e["status"] != "running")
    assert finished["sequence"] < first_derived["sequence"]


# ── AI narrative enhancement (result-derived) ──────────────────────────────

def test_ai_narrative_enhancement_is_one_grouped_result_derived_event(env, activity):
    case_id, run_id, _ = env["prepare"]("narrative")
    engine.run_reporting_stage(case_id, run_id)
    events = _events(activity, run_id)
    group = _one(events, "narrative_enhancement")
    assert group["source"] == "ai" and group["ai_content_kind"] == "explanation"
    assert group["metadata"]["result_derived"] is True
    assert group["metadata"]["group"] == "AI narrative enhancement (result-derived)"
    assert group["title"] == "AI narrative enhancement results"
    assert group["detail"] == "7 of 7 section(s) used AI-enhanced text"
    blob = json.dumps(group["metadata"]["details"])
    assert "may be enhanced in parallel" in blob and "not observable" in blob
    assert "gpt-test-mini" in blob and "Model attempts (all sections)" in blob
    children = [e for e in events if e["parent_span_id"] == group["span_id"]]
    # The agent's own field order - never a claimed completion order.
    assert [e["metadata"]["section"] for e in children] == [
        "executive_summary", "technical_analysis", "business_impact_explanation", "attack_narrative",
        "conclusion", "analyst_friendly_explanation", "soc_analyst_review_checklist"]
    assert all(e["metadata"]["result_derived"] for e in children)
    assert not [e for e in children if "duration_ms" in e["metadata"]]
    assert not [e for e in children if e["status"] == "running"]
    assert children[0]["title"] == "Executive summary: AI-enhanced text accepted"
    # No generated report text, prompt or knowledge-base content reaches the timeline.
    flat = json.dumps(events)
    assert NARRATIVE_TEXT not in flat and "UNIQUE-NARRATIVE" not in flat
    assert MODEL_CALLS and MODEL_CALLS[0]["prompt"][:60] not in flat


def test_section_fallbacks_and_warnings_are_visible(env, activity):
    env["monkeypatch"].setenv("FAKE_REP_MODE", "fallback")
    case_id, run_id, _ = env["prepare"]("fallback")
    engine.run_reporting_stage(case_id, run_id)
    events = _events(activity, run_id)
    group = _one(events, "narrative_enhancement")
    assert group["status"] == "warning"
    assert group["detail"] == "4 of 7 section(s) used AI-enhanced text · 2 kept deterministic text"
    children = {e["metadata"]["section"]: e for e in events if e["parent_span_id"] == group["span_id"]}
    assert children["executive_summary"]["source"] == "rule"
    assert children["executive_summary"]["title"] == "Executive summary: deterministic text (locked — no model call)"
    narrative = children["attack_narrative"]
    assert narrative["source"] == "system" and narrative["status"] == "warning"
    assert narrative["metadata"]["fallback"] is True
    assert "Prompt leakage detected" in json.dumps(narrative["metadata"]["details"])
    conclusion = children["conclusion"]
    assert "after a quality retry" in conclusion["detail"]
    assert "Quality retry attempted" in json.dumps(conclusion["metadata"]["details"])
    # Secrets inside recorded issues are redacted.
    assert SECRET not in json.dumps(events)


def test_section_warnings_and_repairs_are_labelled(env, activity):
    env["monkeypatch"].setenv("FAKE_REP_MODE", "warnings")
    case_id, run_id, _ = env["prepare"]("warn")
    engine.run_reporting_stage(case_id, run_id)
    events = _events(activity, run_id)
    group = _one(events, "narrative_enhancement")
    children = {e["metadata"]["section"]: e for e in events if e["parent_span_id"] == group["span_id"]}
    assert children["technical_analysis"]["status"] == "warning"
    assert children["technical_analysis"]["title"] == "Technical analysis: AI-enhanced text accepted with warnings"
    assert children["analyst_friendly_explanation"]["title"].endswith("after deterministic repair")
    # Real section statuses seen in a sandboxed run of the real agent.
    assert children["attack_narrative"]["title"] == "Attack narrative: AI-enhanced text accepted after a retry"
    assert children["attack_narrative"]["source"] == "ai" and children["attack_narrative"]["status"] == "completed"
    assert children["conclusion"]["title"] ==         "Conclusion: AI-enhanced text accepted after a retry after deterministic repair with warnings"
    assert children["conclusion"]["status"] == "warning"
    assert group["detail"] == "7 of 7 section(s) used AI-enhanced text · 2 accepted with warnings"
    validation = _one(events, "report_validation")
    assert validation["status"] == "warning" and "1 warning(s)" in validation["detail"]


def test_llm_disabled_is_a_deterministic_fallback_not_ai(env, activity):
    env["monkeypatch"].setenv("FAKE_REP_MODE", "llm_disabled")
    case_id, run_id, _ = env["prepare"]("nollm")
    engine.run_reporting_stage(case_id, run_id)
    events = _events(activity, run_id)
    fallback = _one(events, "fallback")
    assert fallback["title"] == "AI narrative enhancement disabled — deterministic narrative used"
    assert fallback["metadata"]["fallback"] is True and fallback["metadata"]["result_derived"] is True
    assert not [e for e in events if e["event_type"] in ("narrative_enhancement", "narrative_section")]
    assert {e["event_type"] for e in events if e["source"] == "ai"} == {"ai_summary", "llm_call"}


def test_cached_narrative_reuse_is_visible(env, activity):
    env["monkeypatch"].setenv("FAKE_REP_MODE", "cached")
    case_id, run_id, _ = env["prepare"]("cached")
    engine.run_reporting_stage(case_id, run_id)
    events = _events(activity, run_id)
    assert any(e["event_type"] == "fallback" and e["title"] == "Earlier cached AI narrative reused" for e in events)
    group = _one(events, "narrative_enhancement")
    assert group["status"] == "warning" and group["detail"].startswith("0 of 7")


def test_result_reconstructed_from_artefacts_is_a_visible_fallback(env, activity):
    env["monkeypatch"].setenv("FAKE_REP_MODE", "reconstructed")
    case_id, run_id, _ = env["prepare"]("reconstructed")
    engine.run_reporting_stage(case_id, run_id)
    events = _events(activity, run_id)
    fb = _one(events, "fallback")
    assert fb["title"] == "Result reconstructed from report artefacts" and fb["metadata"]["fallback"] is True
    assert not [e for e in events if e["event_type"] in ("narrative_enhancement", "report_validation")]
    assert _one(events, "stage_result")["title"] == "Reporting completed with warnings"


def test_rag_status_is_reported_verbatim_without_claiming_retrieval(env, activity):
    case_id, run_id, _ = env["prepare"]("rag")
    engine.run_reporting_stage(case_id, run_id)
    rag = _one(_events(activity, run_id), "rag_status")
    assert rag["source"] == "system" and rag["status"] == "info"
    assert rag["title"] == "RAG status recorded: Local template export context built"
    assert "Retrieval itself is not observable" in json.dumps(rag["metadata"]["details"])
    assert rag["metadata"]["result_derived"] is True


# ── Validation, completeness, documents ────────────────────────────────────

def test_validation_and_completeness_problems_are_rule_warnings(env, activity):
    env["monkeypatch"].setenv("FAKE_REP_MODE", "missing_fields")
    case_id, run_id, _ = env["prepare"]("missing")
    engine.run_reporting_stage(case_id, run_id)
    events = _events(activity, run_id)
    validation = _one(events, "report_validation")
    assert validation["source"] == "rule" and validation["status"] == "warning"
    assert "2 required field(s) missing" in validation["detail"]
    assert "data consistency failed" in validation["detail"] and "completeness 62/100" in validation["detail"]
    blob = json.dumps(validation["metadata"]["details"])
    assert "affected_host" in blob and "Conflicting severity values" in blob
    assert "severity: Triage HIGH vs Investigation Medium" in blob
    assert _one(events, "stage_result")["title"] == "Reporting completed with warnings"


def test_documents_exports_and_manifest_without_absolute_paths(env, activity):
    env["monkeypatch"].setenv("FAKE_EXPORT_MODE", "validation_warning")
    case_id, run_id, _ = env["prepare"]("docs")
    engine.run_reporting_stage(case_id, run_id)
    events = _events(activity, run_id)
    rendered = _one(events, "templates_rendered")
    assert rendered["title"] == "5 report document(s) rendered from Jinja2 templates"
    assert rendered["source"] == "system" and rendered["metadata"]["result_derived"] is True
    export = [e for e in events if e["event_type"] == "document_export"]
    assert [e["status"] for e in export] == ["running", "completed"]
    assert export[1]["detail"].startswith("8 document(s) generated · candidate manifest published")
    blob = json.dumps(export[1]["metadata"]["details"])
    assert "combined_incident_report.docx" in blob and "Candidate manifest SHA-256" in blob
    checks = _one(events, "document_validation")
    assert checks["status"] == "warning" and checks["title"] == "Exported documents validated: 4 of 4 valid"
    assert "technical_findings_template.md.j2" in json.dumps(checks["metadata"]["details"])
    flat = json.dumps(events)
    assert str(env["tmp"]) not in flat and json.dumps(str(env["tmp"]))[1:-1] not in flat


def test_pdf_export_failure_is_a_warning_with_the_reason(env, activity):
    env["monkeypatch"].setenv("FAKE_EXPORT_MODE", "pdf_fail")
    case_id, run_id, _ = env["prepare"]("pdf")
    engine.run_reporting_stage(case_id, run_id)
    export = [e for e in _events(activity, run_id) if e["event_type"] == "document_export"][-1]
    assert export["status"] == "warning" and "4 not generated" in export["detail"]
    assert "PDF converter not available" in json.dumps(export["metadata"]["details"])


def test_missing_candidate_manifest_is_shown_and_approval_is_blocked(env, activity):
    env["monkeypatch"].setenv("FAKE_EXPORT_MODE", "manifest_error")
    case_id, run_id, _ = env["prepare"]("noman")
    engine.run_reporting_stage(case_id, run_id)
    events = _events(activity, run_id)
    identity = _one(events, "manifest_identity")
    assert identity["status"] == "warning" and identity["title"] == "Candidate manifest identity check skipped"
    assert _one(events, "stage_result")["status"] == "warning"
    assert wss.get_state(CASE)["reporting_status"] == "Awaiting Approval"  # unchanged engine behaviour
    with pytest.raises(commands.WorkflowCommandError):
        commands.approve_stage(case_id, "reporting", analyst="Analyst One", comments="")
    blocked = [e for e in _events(activity, run_id) if e["event_type"] == "approval_decision"]
    assert blocked[-1]["status"] == "warning"
    assert blocked[-1]["title"] == "Reporting approval blocked by candidate-set validation"


def test_export_with_no_output_is_a_failed_export(env, activity):
    env["monkeypatch"].setenv("FAKE_EXPORT_MODE", "no_output")
    case_id, run_id, _ = env["prepare"]("noexport")
    engine.run_reporting_stage(case_id, run_id)
    export = [e for e in _events(activity, run_id) if e["event_type"] == "document_export"][-1]
    assert export["status"] == "failed" and export["title"] == "Document export produced no result"


# ── Failures ───────────────────────────────────────────────────────────────

def test_candidate_manifest_identity_mismatch_fails_the_stage(env, activity):
    env["monkeypatch"].setenv("FAKE_EXPORT_MODE", "mismatch")
    case_id, run_id, _ = env["prepare"]("mismatch")
    result = engine.run_reporting_stage(case_id, run_id)
    assert result["status"] == "failed"
    top = _top(_events(activity, run_id))
    identity = _one(top, "manifest_identity")
    assert identity["status"] == "failed" and identity["title"] == "Candidate manifest identity mismatch"
    assert "attempt 2" in identity["detail"] and "attempt 1" in identity["detail"]
    assert top[-2]["event_type"] == "stage_result" and top[-2]["status"] == "failed"
    assert top[-1]["event_type"] == "stage_settled" and top[-1]["status"] == "failed"
    assert not [e for e in top if e["source"] == "human" or e["event_type"] == "ai_summary"]


def test_handoff_verification_failure_never_launches_the_agent(env, activity):
    real = engine.handoff_to_reporting

    def tampering(triage_result, incident, investigation_result, threat_intel_result=None, *,
                  incident_id=None, run_id=None, reporting_stage_attempt=None):
        ticket = real(triage_result, incident, investigation_result, threat_intel_result,
                      incident_id=incident_id, run_id=run_id, reporting_stage_attempt=reporting_stage_attempt)
        target = engine.reporting_attempt_dir(incident_id, run_id, reporting_stage_attempt) / "outputs" / "triage_result.json"
        target.write_text(target.read_text(encoding="utf-8") + " ", encoding="utf-8")
        return ticket

    observability.uninstall()
    env["monkeypatch"].setattr(engine, "handoff_to_reporting", tampering)
    assert observability.install(str(env["tmp"] / "tamper.db"))["enabled"]
    try:
        case_id, run_id, rep_dir = env["prepare"]("tamper")
        result = engine.run_reporting_stage(case_id, run_id)
        events = _events(observability.get_store(), run_id)
    finally:
        observability.uninstall()
    assert result == {"status": "failed"}
    verify = _one(events, "handoff_verification")
    assert verify["status"] == "failed" and verify["title"] == "Hand-off manifest verification failed"
    assert "triage_result.json" in verify["detail"] and "not launched" in verify["detail"]
    assert not [e for e in events if e["event_type"] == "agent_run"]
    assert not (rep_dir / "observed.jsonl").exists()
    assert _one(events, "stage_result")["status"] == "failed"


def test_agent_crash_is_a_failed_reporting_with_a_sanitised_error(env, activity):
    env["monkeypatch"].setenv("FAKE_REP_MODE", "crash")
    case_id, run_id, _ = env["prepare"]("crash")
    result = engine.run_reporting_stage(case_id, run_id)
    assert result["status"] == "failed"
    events = _events(activity, run_id)
    top = _top(events)
    finished = [e for e in top if e["event_type"] == "agent_run"][-1]
    assert finished["status"] == "failed" and "exit code 1" in finished["detail"]
    assert finished["title"] == "Reporting Agent exited with an error"
    assert _one(top, "agent_result")["title"] == "No final_report.json produced by the Reporting Agent"
    flat = json.dumps(events)
    assert SECRET not in flat and "Traceback" not in flat and 'File \\"reporting_agent.py\\"' not in flat
    assert not [e for e in top if e["event_type"] == "document_export"]
    assert top[-2]["event_type"] == "stage_result" and top[-2]["status"] == "failed"
    assert not [e for e in top if e["source"] == "human"]


def test_agent_reported_failure_skips_export(env, activity):
    env["monkeypatch"].setenv("FAKE_REP_MODE", "agent_failed")
    case_id, run_id, _ = env["prepare"]("agentfail")
    engine.run_reporting_stage(case_id, run_id)
    events = _events(activity, run_id)
    result = _one(events, "agent_result")
    assert result["status"] == "failed" and result["title"] == "Reporting Agent reported a failure"
    assert "KeyError" in json.dumps(result["metadata"]["details"])
    assert not [e for e in events if e["event_type"] in ("document_export", "narrative_enhancement", "fallback")]
    decision = _one(events, "stage_result")
    assert decision["title"] == "Reporting failed" and decision["detail"] == "KeyError: 'incident_id'"


def test_missing_parsing_context_is_shown(env, activity):
    case_id, run_id, _ = env["prepare"]("noparse", parsing=False)
    engine.run_reporting_stage(case_id, run_id)
    handoff = [e for e in _events(activity, run_id) if e["event_type"] == "handoff"]
    assert [e["status"] for e in handoff] == ["completed", "warning"]
    assert handoff[1]["title"] == "Parsing result not included in the hand-off"


def test_stage_claim_failure_is_shown(env, activity):
    case_id, run_id, _ = env["prepare"]("claim")
    wss._guarded_update(case_id, run_id, {"reporting_status": "Pending"})
    with pytest.raises(engine.StageClaimError):
        engine.run_reporting_stage(case_id, run_id)
    events = _events(activity, run_id)
    assert events[0]["event_type"] == "stage_claimed" and events[0]["status"] == "warning"


def test_no_llm_key_is_shown_as_not_requested(env, activity):
    env["monkeypatch"].delenv("OPENAI_API_KEY", raising=False)
    env["monkeypatch"].setenv("FAKE_REP_MODE", "llm_disabled")
    case_id, run_id, _ = env["prepare"]("nokey")
    engine.run_reporting_stage(case_id, run_id)
    running = _one(_events(activity, run_id), "agent_run", status="running")
    assert '"AI narrative enhancement requested", "value": "no"' in \
        json.dumps(running["metadata"]["details"]).replace('"label": ', '"')


# ── Global lock ────────────────────────────────────────────────────────────

def test_global_lock_wait_is_shown_only_when_it_happens(env, activity):
    case_id, run_id, _ = env["prepare"]("lock")
    wss.acquire_global_lock("reporting_workspace", owner_id="other-worker", incident_id="INC-OTHER",
                            run_id="other-run", ttl_seconds=45)
    threading.Timer(2.5, lambda: wss.release_global_lock("reporting_workspace", "other-worker")).start()
    engine.run_reporting_stage(case_id, run_id)
    lock = [e for e in _events(activity, run_id) if e["event_type"] == "workspace_lock"]
    assert [e["status"] for e in lock] == ["running", "completed"]
    assert lock[0]["title"] == "Waiting for Reporting capacity"
    assert lock[1]["title"] == "Reporting capacity acquired" and lock[0]["span_id"] == lock[1]["span_id"]
    assert "busy check(s)" in lock[1]["detail"]


# ── Post-stage summary, labels, approval gate ──────────────────────────────

def test_post_stage_summary_failure_does_not_change_the_result(env, activity):
    import integrations.openai.client as openai_client

    def down(prompt, *, system=None, model=None, temperature=None, max_output_tokens=None,
             timeout=None, text_format=None):
        raise RuntimeError("summary endpoint unavailable")

    observability.uninstall()
    env["monkeypatch"].setattr(openai_client, "invoke_openai_text", down)
    assert observability.install(str(activity.path))["enabled"]
    store = observability.get_store()
    case_id, run_id, _ = env["prepare"]("sumfail")
    engine.run_reporting_stage(case_id, run_id)
    events = _events(store, run_id)
    summary = [e for e in events if e["event_type"] == "ai_summary"][-1]
    assert summary["status"] == "warning" and summary["metadata"]["post_stage"] is True
    decision = _one(events, "stage_result")
    assert decision["status"] == "completed" and decision["sequence"] < summary["sequence"]
    assert wss.get_state(CASE)["reporting_status"] == "Awaiting Approval"


def test_ai_only_for_narrative_enhancement_and_summary_and_no_reasoning_labels(env, activity):
    env["monkeypatch"].setenv("FAKE_REP_MODE", "fallback")
    case_id, run_id, _ = env["prepare"]("labels")
    engine.run_reporting_stage(case_id, run_id)
    events = _events(activity, run_id)
    ai = [e for e in events if e["source"] == "ai"]
    assert {e["ai_content_kind"] for e in ai} <= {"assessment", "explanation", "summary"}
    assert {e["event_type"] for e in ai} == {"narrative_enhancement", "narrative_section", "ai_summary", "llm_call"}
    deterministic = {"deterministic_facts", "report_validation", "templates_rendered", "document_export",
                     "document_validation", "manifest_identity", "handoff_verification", "ticket_identity"}
    assert not [e for e in ai if e["event_type"] in deterministic]
    assert {e["source"] for e in events if e["event_type"] in deterministic} <= {"system", "rule"}
    labels = json.dumps([e["title"] for e in events]).lower()
    assert "reasoning" not in labels and "thinking" not in labels
    assert "generating executive summary" not in labels


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_analyst_decision_resolves_the_approval_gate(env, activity, decision):
    case_id, run_id, _ = env["prepare"](f"human-{decision}")
    engine.run_reporting_stage(case_id, run_id)
    if decision == "approve":
        commands.approve_stage(case_id, "reporting", analyst="Analyst One", comments="Ready to send.")
    else:
        commands.reject_stage(case_id, "reporting", analyst="Analyst Two", comments="Executive summary unclear.")
    events = _events(activity, run_id)
    waiting = _one(events, "approval_required")
    done = _one(events, "approval_decision")
    assert done["span_id"] == waiting["span_id"] and done["source"] == "human"
    if decision == "approve":
        verify = _one(events, "approval_verification")
        assert verify["source"] == "rule" and verify["sequence"] < done["sequence"]
        assert done["title"] == "Reporting approved by Analyst One" and done["detail"] == "Ready to send."
        assert events[-1]["title"] == "Workflow status: Complete"
        assert wss.get_state(CASE)["workflow_status"] == "Complete"
    else:
        assert done["title"] == "Reporting rejected by Analyst Two"
        assert done["detail"] == "Executive summary unclear."


def test_tampered_candidate_set_blocks_approval_visibly(env, activity):
    case_id, run_id, _ = env["prepare"]("tampered")
    engine.run_reporting_stage(case_id, run_id)
    attempt_dir = engine.reporting_attempt_dir(case_id, run_id, 1)
    docx = next(attempt_dir.rglob("executive_summary.docx"))
    docx.write_bytes(docx.read_bytes() + b"tampered")
    with pytest.raises(commands.WorkflowCommandError):
        commands.approve_stage(case_id, "reporting", analyst="Analyst One", comments="")
    events = _events(activity, run_id)
    blocked = _one(events, "approval_decision")
    assert blocked["status"] == "warning" and "hash mismatch" in blocked["detail"]
    assert not [e for e in events if e["event_type"] == "approval_verification"]
    assert wss.get_state(CASE)["reporting_status"] == "Awaiting Approval"


def test_rerun_request_is_recorded(env, activity):
    case_id, run_id, _ = env["prepare"]("rerun")
    engine.run_reporting_stage(case_id, run_id)
    wss.reject_reporting(case_id, run_id, rejected_by="Analyst", reason="Redo")
    wss.rerun_stage(case_id, run_id, "reporting")
    events = query_events(case_id=CASE, run_id=run_id, stage="reporting", path=activity.path) \
        if activity.flush() else []
    request = [e for e in events if e["event_type"] == "stage_requested"]
    assert request and request[-1]["title"] == "Reporting re-run requested"
    assert request[-1]["stage_attempt"] == wss.get_state(CASE)["reporting_attempt"]


def test_observability_failures_never_change_the_reporting_result(env, tmp_path):
    from observability import emitter

    case_id, run_off, rep_off = env["prepare"]("broken-off", fixed_run_id=True)
    off = _snapshot(case_id, run_off, rep_off, engine.run_reporting_stage(case_id, run_off))
    MODEL_CALLS.clear()
    assert observability.install(str(tmp_path / "broken.db"))["enabled"]

    def boom(**kwargs):
        raise RuntimeError("activity store unavailable")

    env["monkeypatch"].setattr(emitter, "build_event", boom)
    try:
        case_id, run_on, rep_on = env["prepare"]("broken-on", fixed_run_id=True)
        on = _snapshot(case_id, run_on, rep_on, engine.run_reporting_stage(case_id, run_on))
    finally:
        observability.uninstall()
    assert on == off


# ── Transport and isolation ────────────────────────────────────────────────

def test_reporting_events_history_sse_and_isolation(env, activity):
    case_id, run_id, _ = env["prepare"]("sse")
    engine.run_reporting_stage(case_id, run_id)
    expected = _events(activity, run_id)
    client = create_app({"TESTING": True, "AGENT_ACTIVITY_DB_PATH": str(activity.path),
                         "AGENT_ACTIVITY_STREAM_SECONDS": 0.3}).test_client()
    history = client.get(f"/api/cases/{CASE}/activity?stage=reporting").get_json()
    assert [e["sequence"] for e in history["events"]] == [e["sequence"] for e in expected]
    body = client.get(f"/api/cases/{CASE}/activity/stream?stage=reporting").get_data(as_text=True)
    streamed = [json.loads(m) for m in re.findall(r"^data: (.*)$", body, re.M)]
    assert [e["sequence"] for e in streamed] == [e["sequence"] for e in expected]
    resumed = client.get(f"/api/cases/{CASE}/activity/stream?stage=reporting",
                         headers={"Last-Event-ID": str(streamed[-1]["sequence"])}).get_data(as_text=True)
    assert "event: activity" not in resumed
    every = query_events(case_id=CASE, run_id=run_id, path=activity.path)
    assert {e["stage"] for e in every} == {"reporting"}


def test_reporting_wrap_points_match_their_expected_signatures():
    from observability.adapters import reporting_adapter
    from observability.instrument import Patcher, actual_params

    recorded = []
    patcher = Patcher()
    patcher.wrap = lambda target, hooks: recorded.append(target) or True  # type: ignore[assignment]
    reporting_adapter.install(patcher)
    assert len(recorded) == 18
    for target in recorded:
        assert actual_params(target) == target.params, target.label
