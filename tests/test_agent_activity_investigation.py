"""Agent Activity - Investigation.

Runs the real durable stage runner (workflow.engine.run_investigation_stage):
real claim/lease, real shared-workspace lock, real handoff file, the real
streaming subprocess runner (a real child process whose output is read line
by line), real structured/Markdown result read-back, severity-divergence
check, rule-based evidence-gap detection, the in-process deep-triage
supplement (real LangChain chain over a fake chat model, so real callbacks
fire), the real feedback loop, post-stage summary and approval gate.

The Investigation agent itself (agents/investigation/main.py) needs ChromaDB,
OpenAI embeddings and live LLM passes, so ``engine.INV_DIR`` points at a temp
folder holding a FAKE main.py that honours the real agent's on-disk contract
(reads triaged_alerts/, writes incident_reports/Incident-*/incident_data.json,
final_analysis_report.md and investigation_analysis.json) and prints the real
agent's log templates verbatim (ANSI colours included). Its behaviour is
selected with FAKE_INV_MODE.
"""

from __future__ import annotations

import copy
import json
import re
import textwrap
import threading
from pathlib import Path

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

import observability
from agents.triage import soc_triage_agent
from backend import create_app
from observability.store import query_events
import canonical_seed as seed
from workflow import commands
from workflow import engine
from workflow import state_store as wss

CASE = "INC-INV-OBS"
SUMMARY = "Investigation concluded a high-severity execution incident on HOST-07."

FAKE_MAIN = textwrap.dedent(r'''
    import glob, json, os, shutil, sys, time

    MODE = os.environ.get("FAKE_INV_MODE", "ok")
    here = os.getcwd()
    counter = os.path.join(here, "fake_runs.txt")
    run = int(open(counter).read()) + 1 if os.path.exists(counter) else 1
    open(counter, "w").write(str(run))

    def info(m): print(f"\033[96m[*] {m}\033[0m", file=sys.stderr, flush=True)
    def ok(m): print(f"\033[92m[+] {m}\033[0m", file=sys.stderr, flush=True)
    def warn(m): print(f"\033[93m[~] {m}\033[0m", file=sys.stderr, flush=True)
    def err(m): print(f"\033[91m[!] ERROR: {m}\033[0m", file=sys.stderr, flush=True)

    files = sorted(glob.glob(os.path.join("triaged_alerts", "*.json")))
    with open(os.path.join(here, "observed.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"run": run, "argv": sys.argv[1:], "cwd_name": os.path.basename(here),
                             "env": {k: os.environ.get(k) for k in ("INVESTIGATION_SUBJECT_ID",
                                     "INVESTIGATION_FORCE_LLM", "OPENAI_SEED", "PYTHONUNBUFFERED")},
                             "alerts": [json.load(open(f, encoding="utf-8")) for f in files]}) + "\n")

    info("Initializing SOC Incident Response Pipeline...")
    if not files:
        warn("No alert files found in 'triaged_alerts/'. Ingestion skipped.")
        sys.exit(0)
    info(f"Starting Bulk Ingestion of {len(files)} raw alert logs...")
    ok(f"Bulk Ingestion completed. Vector store populated with {len(files)} items.")
    print("[+] CorrelationEngine: Loaded 0 active incidents into memory cache.", flush=True)
    alert = json.load(open(files[0], encoding="utf-8"))
    inc = alert["incident_id"]
    info(f"Evaluating remaining queue. Picked investigative Seed Alert: {os.path.basename(files[0])}")
    print(f"[*] CorrelationEngine: Processing alert {inc} through two-tier engine...", flush=True)
    print("[*] CorrelationEngine: Tier 1 took 2.41ms. Decision: NEW_INCIDENT (Score: 0.000)", flush=True)
    info("Auto-selected Privilege Escalation (endpoint) playbook for: 'Malware infection' / 'Execution'")
    info("Forming Standalone Incident -> Incident-001")
    info("Running parallel report generation and enrichment for 1 incidents...")
    print("debug: loaded key sk-abcdefghijklmnop1234 from C:\\Users\\analyst\\secrets\\creds.json", flush=True)
    if MODE == "malformed":
        print("\x00\x01 ][[ #### \x1b[31m", flush=True)
        print("[LLM CALL]", flush=True)
        print("[+]", flush=True)
        print("x" * 5000, flush=True)
    if MODE == "crash":
        print("Traceback (most recent call last):\n  File \"main.py\", line 1\nRuntimeError: chroma unavailable", flush=True)
        sys.exit(1)

    info(f"[LLM CALL] Pass 1: Lightweight Playbook Evaluation & Pivot Extraction for {inc}...")
    if MODE == "p1_fail":
        err("Pass 1 LLM call failed: Error code: 429 - rate limit reached")
    else:
        ok(f"[LLM RESPONSE] Pass 1 completed for {inc}. Suggested pivots: ['203.0.113.45', 'evil.exe']")
        ok("Dynamic retrieval matched alert INC-OLD-7 (RRF: 0.0312)")
    info(f"[LLM CALL] Pass 2: Re-evaluating playbook and compiling final report for {inc}...")
    gaps_first_run = MODE == "gaps" and run == 1
    if MODE == "p2_fail":
        err("Pass 2 LLM call failed: Request timed out.")
        severity, confidence = "Medium", "Low"
        sev_j, conf_j = "Fallback due to error: Request timed out.", "Fallback due to error"
    else:
        severity, confidence = "High", "Medium"
        sev_j = "Unsigned binary executed and contacted a known-bad external IP."
        conf_j = "Endpoint and network telemetry agree; no lineage data."
        ok(f"[LLM RESPONSE] Pass 2 completed for {inc} (Severity: {severity})")
    steps = [("step_1", "Identify the user and host", "MET"),
             ("step_2", "Check for lateral movement to other hosts", "NOT_MET" if gaps_first_run else "MET"),
             ("step_3", "Identify the spawning process chain", "NOT_MET" if gaps_first_run else "MET")]
    folder = os.path.join("incident_reports", "Incident-001")
    os.makedirs(folder, exist_ok=True)
    json.dump({"id": "Incident-001", "metadata": {"severity": severity}, "summary_text": f"Summary run {run}",
               "indicators": ["203.0.113.45"],
               "raw_alerts": [{"id": inc, "document": "doc", "metadata": {},
                               "triage": {"ticket_unc": "#00042A"}}]},
              open(os.path.join(folder, "incident_data.json"), "w", encoding="utf-8"))
    table = "\n".join(f"| `{s}` | {i} | {st} |" for s, i, st in steps)
    # Real main.py::write_markdown_report() header (canonical case + folder).
    open(os.path.join(folder, "final_analysis_report.md"), "w", encoding="utf-8").write(
        f"# INVESTIGATION SUMMARY: {inc} (Incident-001)\n\n"
        "| Step | Instruction | Status |\n|---|---|---|\n" + table + "\n")
    if MODE != "no_json":
        json.dump({"incident_id": inc, "severity": severity, "confidence": confidence,
                   "execution_trace": [{"step_id": s, "instruction": i, "status": st,
                                        "findings": f"Finding for {s}"} for s, i, st in steps],
                   "incident_summary": f"Summary run {run}", "actions_taken": ["Reviewed timeline"],
                   "recommended_containment": ["Isolate HOST-07"],
                   "business_impact_checklist": {"critical_system": "unknown", "essential_service": "no",
                                                 "data_sensitivity": "unknown", "operational_impact": "no"},
                   "severity_justification": sev_j, "confidence_justification": conf_j,
                   "mitre_mappings": [{"timeline_phase": "Execution", "observed_evidence": "evil.exe",
                                       "tactic": "Execution", "technique_name": "User Execution",
                                       "technique_id": "T1204"}]},
                  open(os.path.join(folder, "investigation_analysis.json"), "w", encoding="utf-8"))
    for f in files:
        shutil.move(f, os.path.join(folder, os.path.basename(f)))
    ok("Case report stored securely inside: C:\\Users\\analyst\\agent\\incident_reports\\Incident-001\\final_analysis_report.md")
    if MODE != "no_json":
        ok("Structured investigation analysis stored inside: C:\\Users\\analyst\\agent\\investigation_analysis.json")
    info("SOC Incident Response Pipeline shut down successfully.")
''')

DEEP_DIVE = {"gap_findings": {"step_2: Check for lateral movement to other hosts": "No lateral movement observed",
                              "step_3: Identify the spawning process chain": "not present in incident data"},
             "confidence_per_gap": {"step_2: Check for lateral movement to other hosts": "medium"},
             "actionable_queries": {"step_3": "process.parent = 'explorer.exe'"},
             "extracted_values": {}, "mitre_tactic": "Lateral Movement", "incident_category": "Malware",
             "classification": "CRITICAL", "deep_dive_summary": "One gap answered; process chain absent."}

MODEL_CALLS: list[dict] = []
_LOCK = threading.Lock()


class FakeDeepDiveModel(BaseChatModel):
    model_name: str = "fake-deep-dive-model"
    fail: bool = False

    @property
    def _llm_type(self) -> str:
        return "fake-deep-dive"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        with _LOCK:
            MODEL_CALLS.append({"kind": "deep_dive", "messages": [str(m.content) for m in messages],
                                "kwargs": dict(kwargs)})
        if self.fail:
            raise TimeoutError("deep-dive model timed out")
        message = AIMessage(content=json.dumps(DEEP_DIVE),
                            usage_metadata={"input_tokens": 900, "output_tokens": 300, "total_tokens": 1200,
                                            "output_token_details": {"reasoning": 64}},
                            response_metadata={"model_name": "fake-deep-dive-model-2026", "finish_reason": "stop"})
        return ChatResult(generations=[ChatGeneration(message=message)])


def _fake_summary(prompt, *, system=None, model=None, temperature=None, max_output_tokens=None,
                  timeout=None, text_format=None):
    with _LOCK:
        MODEL_CALLS.append({"kind": "summary", "prompt": prompt, "model": model})
    return SUMMARY


TRIAGE = {"ticket": {"incident_id": CASE, "classification": "HIGH", "unc": "#00042A",
                     "incident_category": "Malware infection", "mitre_tactic": "Execution",
                     "mitre_technique": "T1204 User Execution", "summary": "Unsigned binary executed."},
          "metakeys_payload": {"incident_id": CASE, "mitre_tactic": "Execution"}}
TI = {"status": "completed", "enrichment_risk_level": "High", "enrichment_risk_score": 85,
      "enrichment_risk_reasons": ["VirusTotal reported 61 malicious detection(s) for the file hash."],
      "threat_intelligence": {"iocs": {}}}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    import integrations.openai.client as openai_client

    MODEL_CALLS.clear()
    model = FakeDeepDiveModel()
    monkeypatch.setattr(soc_triage_agent, "build_llm", lambda cfg, json_mode=False: model)
    monkeypatch.setattr(openai_client, "invoke_openai_text", _fake_summary)
    monkeypatch.setattr(engine, "ROOT", tmp_path / "root")  # reconcile_incident_severity's ticket DBs
    monkeypatch.setattr(engine, "_TRUSTED_OUTPUT_ROOT", tmp_path / "artifacts")
    monkeypatch.setenv("FAKE_INV_MODE", "ok")

    def prepare(name: str) -> tuple[str, str, Path]:
        scenario = tmp_path / name
        inv_dir = scenario / "investigation"
        (inv_dir / "triaged_alerts").mkdir(parents=True)
        (inv_dir / "incident_reports").mkdir()
        (inv_dir / "main.py").write_text(FAKE_MAIN, encoding="utf-8")
        monkeypatch.setattr(engine, "INV_DIR", inv_dir)
        monkeypatch.setattr(wss, "DB_FILE", scenario / "workflow.db")
        monkeypatch.setattr(engine, "PIPELINE_DB_FILE", scenario / "pipeline.db")
        engine.pipeline_db_init()
        run_id = wss.start_run(CASE)
        raw = engine._save_run_artifact(CASE, run_id, "raw_incident.json", "raw_incident",
                                        {"incident": {"id": CASE, "title": "Unsigned binary on HOST-07",
                                                      "alertMeta": {}}, "data_availability": {}})
        wss.save_raw_incident_path(CASE, run_id, str(raw))
        wss.save_parsing_result(CASE, run_id, {"run_id": run_id, "status": "completed",
                                               "processed_alert": {"incident_id": CASE, "iocs": []}})
        # Phase 6: a run-bound Triage result with a recorded approval, and the
        # TI result with the case/run identity run_threat_intel() stamps.
        seed.approve_triage(CASE, run_id, copy.deepcopy(TRIAGE))
        wss._guarded_update(CASE, run_id, {"parsing_status": "Complete",
                                           "threat_intel_status": "Complete",
                                           "threat_intel_result_json": json.dumps(
                                               seed.threat_intel_result(CASE, run_id, TI)),
                                           "investigation_status": "Processing",
                                           "workflow_status": "Processing"})
        return CASE, run_id, inv_dir

    return {"prepare": prepare, "model": model, "monkeypatch": monkeypatch, "tmp": tmp_path}


@pytest.fixture()
def activity(tmp_path):
    state = observability.install(str(tmp_path / "agent_activity.db"))
    assert state["enabled"], state
    assert "investigation" in state["coverage"]
    yield observability.get_store()
    observability.uninstall()


def _events(store, run_id):
    assert store.flush()
    return query_events(case_id=CASE, run_id=run_id, stage="investigation", path=store.path)


def _top(events):
    return [e for e in events if not e["parent_span_id"]]


_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")


def _normalise(value, run_id, inv_dir) -> str:
    text = json.dumps(value, sort_keys=True, default=str)
    for form in (run_id, engine._safe(run_id), json.dumps(run_id)[1:-1],
                 json.dumps(str(inv_dir))[1:-1], str(inv_dir)):
        text = text.replace(form, "<X>")
    text = re.sub(r'"started_at": "[^"]*"', '"started_at": "<TS>"', text)
    return _TS.sub("<TS>", text)


def _snapshot(case_id, run_id, inv_dir, result) -> dict:
    state = wss.get_state(case_id)
    observed = [json.loads(line) for line in (inv_dir / "observed.jsonl").read_text(encoding="utf-8").splitlines()] \
        if (inv_dir / "observed.jsonl").exists() else []
    return {
        "result": _normalise(result, run_id, inv_dir),
        "statuses": {k: state[k] for k in ("investigation_status", "reporting_status", "workflow_status",
                                           "approval_stage", "last_error")},
        "persisted": _normalise(json.loads(state["investigation_result_json"] or "null"), run_id, inv_dir),
        "ledger": [(r["stage"], r["action"]) for r in wss.get_activity(case_id)],
        "subprocess_runs": _normalise(observed, run_id, inv_dir),  # argv, env, handoff files
        "model_calls": _normalise(MODEL_CALLS, run_id, inv_dir),
        "reports": sorted(p.name for p in (inv_dir / "incident_reports").rglob("*") if p.is_file()),
    }


# ── Equivalence ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("mode", ["ok", "gaps", "p1_fail", "p2_fail", "no_json", "crash", "deep_dive_fails"])
def test_investigation_is_identical_with_observability_on_and_off(env, tmp_path, mode):
    env["monkeypatch"].setenv("FAKE_INV_MODE", "gaps" if mode == "deep_dive_fails" else mode)
    env["model"].fail = mode == "deep_dive_fails"

    case_id, run_off, inv_off = env["prepare"]("off")
    off = _snapshot(case_id, run_off, inv_off, engine.run_investigation_stage(case_id, run_off))
    MODEL_CALLS.clear()

    assert observability.install(str(tmp_path / f"eq-{mode}.db"))["enabled"]
    try:
        case_id, run_on, inv_on = env["prepare"]("on")
        on = _snapshot(case_id, run_on, inv_on, engine.run_investigation_stage(case_id, run_on))
        events = _events(observability.get_store(), run_on)
    finally:
        observability.uninstall()

    assert on == off
    assert events, "observability was active for the 'on' run"
    runs = json.loads(on["subprocess_runs"].replace("<X>", "x").replace("<TS>", "t"))
    assert len(runs) == (2 if mode == "gaps" else 1)  # no extra Investigation run
    expected = {"crash": "Failed"}.get(mode, "Awaiting Approval")
    assert off["statuses"]["investigation_status"] == expected


# ── Successful run ──────────────────────────────────────────────────────────

def test_successful_investigation_timeline(env, activity):
    case_id, run_id, _ = env["prepare"]("ok")
    engine.run_investigation_stage(case_id, run_id)
    events = _events(activity, run_id)
    top = _top(events)
    shape = [(e["source"], e["event_type"], e["status"]) for e in top]
    assert shape == [
        ("orchestration", "stage_claimed", "completed"),
        ("orchestration", "workspace_lock", "completed"),
        ("system", "context_loaded", "completed"),
        ("system", "context_loaded", "completed"),
        ("system", "context_loaded", "completed"),
        ("system", "context_loaded", "completed"),
        ("system", "handoff", "completed"),
        ("system", "agent_run", "running"),
        ("rule", "playbook_selection", "completed"),
        ("ai", "ai_pass", "running"),
        ("ai", "ai_pass", "completed"),
        ("tool", "pivot_retrieval", "completed"),
        ("ai", "ai_pass", "running"),
        ("ai", "ai_pass", "completed"),
        ("system", "result_source", "completed"),
        ("rule", "severity_divergence", "completed"),
        ("system", "agent_run", "completed"),
        ("ai", "analysis_output", "completed"),
        ("rule", "evidence_gaps", "completed"),
        ("decision", "stage_result", "completed"),
        ("ai", "ai_summary", "running"),
        ("ai", "ai_summary", "completed"),
        ("orchestration", "stage_settled", "completed"),
        ("human", "approval_required", "waiting"),
    ]
    assert [e["sequence"] for e in events] == sorted(e["sequence"] for e in events)
    assert {e["stage"] for e in events} == {"investigation"}
    lock = next(e for e in top if e["event_type"] == "workspace_lock")
    assert lock["title"] == "Investigation workspace acquired" and "no wait" in lock["detail"]

    # Subprocess-observed events are labelled as such; children belong to the run.
    run_span = next(e for e in top if e["event_type"] == "agent_run")["span_id"]
    children = [e for e in events if e["parent_span_id"] == run_span]
    assert [e["title"] for e in children][:4] == [
        "Investigation agent started", "Ingesting 1 queued alert(s) into the vector store",
        "Vector store updated with 1 alert(s)", "Correlation engine loaded 0 active incident(s)"]
    assert all(e["origin"] == "subprocess_log" for e in children)
    passes = [e for e in top if e["event_type"] == "ai_pass"]
    assert [e["title"] for e in passes] == [
        "AI Pass 1 started — playbook evaluation and pivot extraction", "AI Pass 1 completed",
        "AI Pass 2 started — final analysis", "AI Pass 2 completed"]
    assert all(e["origin"] == "subprocess_log" for e in passes)
    assert passes[1]["detail"] == "2 suggested pivot(s): 203.0.113.45, evil.exe"
    assert "not observable from outside" in json.dumps(passes[1]["metadata"]["details"])
    assert next(e for e in top if e["event_type"] == "playbook_selection")["title"] == \
        "Playbook selected: Privilege Escalation (endpoint)"

    # Result-derived AI explanation: the fields the final pass returned.
    output = next(e for e in top if e["event_type"] == "analysis_output")
    assert output["origin"] == "wrapper"
    text = json.dumps(output["metadata"]["details"])
    assert "Unsigned binary executed and contacted a known-bad external IP." in text
    assert "T1204 User Execution (Execution)" in text and "3 of 3 playbook step(s) met" in output["detail"]

    decision = next(e for e in top if e["event_type"] == "stage_result")
    assert decision["title"] == "Investigation completed" and "Severity High" in decision["detail"]

    # Raw agent output: unclassified lines kept collapsed, sanitised.
    run_done = [e for e in top if e["event_type"] == "agent_run"][-1]
    log = next(b for b in run_done["metadata"]["details"] if b.get("type") == "log")
    joined = "\n".join(log["lines"])
    assert "debug: loaded key" in joined
    assert "sk-abcdefghijklmnop1234" not in joined and "analyst" not in joined
    flat = json.dumps(events)
    assert "sk-abcdefghijklmnop1234" not in flat and "C:\\\\Users\\\\analyst" not in flat


def test_no_ai_reasoning_labels_and_ai_only_where_models_run(env, activity):
    case_id, run_id, _ = env["prepare"]("labels")
    engine.run_investigation_stage(case_id, run_id)
    events = _events(activity, run_id)
    assert {e["ai_content_kind"] for e in events if e["source"] == "ai"} <= {"assessment", "explanation", "summary"}
    assert not [e for e in events if e["source"] == "ai" and e["event_type"] in
                ("correlation", "pivot_retrieval", "playbook_selection", "evidence_gaps", "ingestion")]
    labels = json.dumps([e["title"] for e in events]).lower()
    assert "reasoning" not in labels and "thinking" not in labels


# ── Evidence gaps, deep-dive, second run ───────────────────────────────────

def test_evidence_gap_loop_runs_a_second_investigation_with_deep_dive(env, activity):
    env["monkeypatch"].setenv("FAKE_INV_MODE", "gaps")
    case_id, run_id, _ = env["prepare"]("gaps")
    result = engine.run_investigation_stage(case_id, run_id)
    assert result["feedback_loop"]["triggered"] is True
    events = _events(activity, run_id)
    top = _top(events)
    gap_checks = [e for e in top if e["event_type"] == "evidence_gaps"]
    assert gap_checks[0]["status"] == "warning" and gap_checks[0]["title"] == "Evidence-gap check: 2 gap(s) detected"
    deep = [e for e in top if e["event_type"] == "deep_dive"]
    assert [e["status"] for e in deep] == ["running", "completed"]
    assert deep[1]["detail"].startswith("1 of 2 gap(s) answered")
    assert "never applied" in json.dumps(deep[1]["metadata"]["details"])
    llm = [e for e in events if e["event_type"] == "llm_call" and e["parent_span_id"] == deep[0]["span_id"]]
    assert [e["status"] for e in llm] == ["running", "completed"]
    assert llm[1]["origin"] == "langchain_callback" and llm[1]["metadata"]["usage"]["reasoning"] == 64
    handoffs = [e for e in top if e["event_type"] == "handoff"]
    assert handoffs[1]["title"] == "Investigation handoff rewritten with the triage deep-dive supplement"
    assert "'Execution' → 'Lateral Movement'" in json.dumps(handoffs[1]["metadata"]["details"], ensure_ascii=False)
    rerun = next(e for e in top if e["event_type"] == "feedback_rerun")
    runs = [e for e in top if e["event_type"] == "agent_run" and e["status"] == "running"]
    assert [e["title"] for e in runs] == ["Investigation agent run 1 started", "Investigation agent run 2 started"]
    assert runs[0]["sequence"] < deep[0]["sequence"] < rerun["sequence"] < runs[1]["sequence"]
    assert {e["metadata"].get("group") for e in events if e["metadata"].get("investigation_run") == 2} == \
        {"Investigation run 2 (evidence-gap feedback loop)"}
    decision = next(e for e in top if e["event_type"] == "stage_result")
    assert "1 feedback re-run(s)" in decision["detail"]
    assert "CRITICAL" in json.dumps(decision["metadata"]["details"])  # suggested, not applied


def test_deep_dive_failure_keeps_first_run_and_says_so(env, activity):
    env["monkeypatch"].setenv("FAKE_INV_MODE", "gaps")
    env["model"].fail = True
    case_id, run_id, inv_dir = env["prepare"]("deepfail")
    engine.run_investigation_stage(case_id, run_id)
    events = _events(activity, run_id)
    deep = [e for e in events if e["event_type"] == "deep_dive"]
    assert deep[-1]["status"] == "failed" and "deep-dive model timed out" in deep[-1]["detail"]
    assert any(e["event_type"] == "fallback" and "first run's findings are kept" in e["title"] for e in events)
    assert not [e for e in events if e["event_type"] == "feedback_rerun"]
    assert (inv_dir / "fake_runs.txt").read_text() == "1"


# ── AI failures and fallbacks ──────────────────────────────────────────────

def test_pass1_failure_is_shown_and_pass2_still_runs(env, activity):
    env["monkeypatch"].setenv("FAKE_INV_MODE", "p1_fail")
    case_id, run_id, _ = env["prepare"]("p1")
    engine.run_investigation_stage(case_id, run_id)
    top = _top(_events(activity, run_id))
    p1 = [e for e in top if e["event_type"] == "ai_pass"][:2]
    assert p1[1]["status"] == "failed" and "429" in p1[1]["detail"]
    fallback = next(e for e in top if e["event_type"] == "fallback")
    assert fallback["metadata"]["fallback"] is True and "without Pass 1 results" in fallback["title"]
    assert [e["title"] for e in top if e["event_type"] == "ai_pass"][2:] == [
        "AI Pass 2 started — final analysis", "AI Pass 2 completed"]


def test_pass2_failure_shows_deterministic_fallback_not_ai(env, activity):
    env["monkeypatch"].setenv("FAKE_INV_MODE", "p2_fail")
    case_id, run_id, _ = env["prepare"]("p2")
    engine.run_investigation_stage(case_id, run_id)
    top = _top(_events(activity, run_id))
    assert [e["status"] for e in top if e["event_type"] == "ai_pass"][-1] == "failed"
    fallbacks = [e for e in top if e["event_type"] == "fallback"]
    assert any("Deterministic fallback report used" in e["title"] for e in fallbacks)
    assert any("not an AI analysis" in e["title"] for e in fallbacks)
    assert not [e for e in top if e["event_type"] == "analysis_output"]  # never shown as AI output
    divergence = next(e for e in top if e["event_type"] == "severity_divergence")
    assert divergence["status"] == "warning" and "downgraded" in divergence["title"]
    assert any(e["event_type"] == "severity_recorded" for e in top)


def test_markdown_fallback_is_visible(env, activity):
    env["monkeypatch"].setenv("FAKE_INV_MODE", "no_json")
    case_id, run_id, _ = env["prepare"]("md")
    engine.run_investigation_stage(case_id, run_id)
    source = next(e for e in _events(activity, run_id) if e["event_type"] == "result_source")
    assert source["status"] == "warning" and source["metadata"]["fallback"] is True
    assert "reconstructed from the Markdown report" in source["title"]
    assert "was not written by the agent" in source["detail"]


def test_malformed_output_is_kept_raw_and_never_interpreted(env, activity):
    env["monkeypatch"].setenv("FAKE_INV_MODE", "malformed")
    case_id, run_id, _ = env["prepare"]("malformed")
    engine.run_investigation_stage(case_id, run_id)
    events = _events(activity, run_id)
    run_done = [e for e in events if e["event_type"] == "agent_run"][-1]
    log = next(b for b in run_done["metadata"]["details"] if b.get("type") == "log")
    assert "[LLM CALL]" in log["lines"] and "[+]" in log["lines"]
    assert all(len(line) <= 300 for line in log["lines"])
    # A bare "[LLM CALL]" line did not create a phantom AI event.
    assert len([e for e in events if e["event_type"] == "ai_pass"]) == 4
    assert wss.get_state(CASE)["investigation_status"] == "Awaiting Approval"


def test_agent_crash_is_a_failed_investigation(env, activity):
    env["monkeypatch"].setenv("FAKE_INV_MODE", "crash")
    case_id, run_id, _ = env["prepare"]("crash")
    result = engine.run_investigation_stage(case_id, run_id)
    assert result["status"] == "failed"
    top = _top(_events(activity, run_id))
    run_done = [e for e in top if e["event_type"] == "agent_run"][-1]
    assert run_done["status"] == "failed" and "exit code 1" in run_done["detail"]
    log = "\n".join(next(b for b in run_done["metadata"]["details"] if b.get("type") == "log")["lines"])
    # Stack traces never reach the analyst UI: frames dropped, final error line kept.
    assert "Traceback" not in log and 'File "main.py"' not in log
    assert "«stack trace removed»" in log and "RuntimeError: chroma unavailable" in log
    assert top[-2]["event_type"] == "stage_result" and top[-2]["status"] == "failed"
    assert top[-1]["event_type"] == "stage_settled" and top[-1]["status"] == "failed"
    assert not [e for e in top if e["source"] == "human"]


# ── Global lock ────────────────────────────────────────────────────────────

def test_global_lock_wait_is_shown_only_when_it_happens(env, activity):
    case_id, run_id, _ = env["prepare"]("lock")
    wss.acquire_global_lock("investigation_workspace", owner_id="other-worker", incident_id="INC-OTHER",
                            run_id="other-run", ttl_seconds=45)
    threading.Timer(2.5, lambda: wss.release_global_lock("investigation_workspace", "other-worker")).start()
    engine.run_investigation_stage(case_id, run_id)
    lock = [e for e in _events(activity, run_id) if e["event_type"] == "workspace_lock"]
    assert [e["status"] for e in lock] == ["running", "completed"]
    assert lock[0]["title"] == "Waiting for Investigation capacity"
    assert lock[1]["title"] == "Investigation capacity acquired" and lock[0]["span_id"] == lock[1]["span_id"]
    assert "busy check(s)" in lock[1]["detail"]


# ── Post-stage summary, approval gate ──────────────────────────────────────

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
    engine.run_investigation_stage(case_id, run_id)
    events = _events(store, run_id)
    summary = [e for e in events if e["event_type"] == "ai_summary"][-1]
    assert summary["status"] == "warning" and summary["metadata"]["post_stage"] is True
    assert next(e for e in events if e["event_type"] == "stage_result")["status"] == "completed"
    assert wss.get_state(CASE)["investigation_status"] == "Awaiting Approval"


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_analyst_decision_resolves_the_approval_gate(env, activity, decision):
    case_id, run_id, _ = env["prepare"](f"human-{decision}")
    engine.run_investigation_stage(case_id, run_id)
    if decision == "approve":
        commands.approve_stage(case_id, "investigation", analyst="Analyst One", comments="Escalate.")
    else:
        commands.reject_stage(case_id, "investigation", analyst="Analyst Two", comments="Needs endpoint data.")
    events = _events(activity, run_id)
    waiting = next(e for e in events if e["event_type"] == "approval_required")
    done = next(e for e in events if e["event_type"] == "approval_decision")
    assert done["span_id"] == waiting["span_id"]
    if decision == "approve":
        assert done["title"] == "Investigation approved by Analyst One" and done["detail"] == "Escalate."
        assert events[-1]["title"] == "Reporting unlocked"
    else:
        assert done["title"] == "Investigation rejected by Analyst Two"
        assert done["detail"] == "Needs endpoint data."


# ── Transport and isolation ────────────────────────────────────────────────

def test_investigation_events_history_sse_and_isolation(env, activity):
    case_id, run_id, _ = env["prepare"]("sse")
    # Phase 6: prepare() records the run's real Triage approval first.
    seeded = query_events(case_id=CASE, run_id=run_id, path=activity.path)
    engine.run_investigation_stage(case_id, run_id)
    expected = _events(activity, run_id)
    client = create_app({"TESTING": True, "AGENT_ACTIVITY_DB_PATH": str(activity.path),
                         "AGENT_ACTIVITY_STREAM_SECONDS": 0.3}).test_client()
    history = client.get(f"/api/cases/{CASE}/activity?stage=investigation").get_json()
    assert [e["sequence"] for e in history["events"]] == [e["sequence"] for e in expected]
    body = client.get(f"/api/cases/{CASE}/activity/stream?stage=investigation").get_data(as_text=True)
    streamed = [json.loads(m) for m in re.findall(r"^data: (.*)$", body, re.M)]
    assert [e["sequence"] for e in streamed] == [e["sequence"] for e in expected]
    resumed = client.get(f"/api/cases/{CASE}/activity/stream?stage=investigation",
                         headers={"Last-Event-ID": str(streamed[-1]["sequence"])}).get_data(as_text=True)
    assert "event: activity" not in resumed
    seeded_ids = {e["sequence"] for e in seeded}
    every = [e for e in query_events(case_id=CASE, run_id=run_id, path=activity.path)
             if e["sequence"] not in seeded_ids]
    assert {e["stage"] for e in seeded} <= {"triage"} and {e["stage"] for e in every} == {"investigation"}


def test_lines_captured_from_a_real_agent_run_are_classified_or_kept_raw(tmp_path):
    """Lines copied verbatim from a sandboxed run of the real agent."""
    from observability import context, emitter
    from observability.adapters.investigation_adapter import _LogReader
    from observability.store import ActivityStore

    store = ActivityStore(tmp_path / "a.db")
    emitter.attach_store(store)
    token = context.set_scope(context.RunScope(case_id="INC-R", run_id="run-r", stage="investigation",
                                               data={"run_no": 1}))
    try:
        reader = _LogReader(context.current_scope(), "runspan")
        for line in [
            "\x1b[96m[*] CorrelationEngine: Tier 1 took 560.12ms. Decision: UNRELATED (Score: -0.319)\x1b[0m",
            "[*] CorrelationEngine: Tier 2 took 0.00ms. Decision: STANDALONE. Total Latency: 560.12ms.",
            "\x1b[96m[*] Auto-selected Privilege Escalation (endpoint) playbook for: 'malware infection' / 'execution'\x1b[0m",
            "\x1b[92m[+] [LLM RESPONSE] Pass 1 completed for INC-R. Suggested pivots: ['jdoe', 'SANDBOX-WS07']\x1b[0m",
            "2026-10-03 11:44:22,541 - SyncEngine - INFO - [sync_engine.py:915] - IncidentSyncManager: "
            "Initiating creation of incident Incident-004",
        ]:
            reader.feed(line)
    finally:
        context.reset_scope(token)
    assert store.flush()
    events = query_events(case_id="INC-R", path=store.path)
    assert [e["title"] for e in events] == [
        "Correlation tier 1 decision: UNRELATED", "Correlation tier 2 decision: STANDALONE",
        "Playbook selected: Privilege Escalation (endpoint)", "AI Pass 1 completed"]
    assert events[0]["detail"].startswith("score -0.319")
    assert reader.unclassified == 1 and "SyncEngine" in reader.raw[0]
    emitter.detach_store()
    store.close()


def test_investigation_wrap_points_match_their_expected_signatures():
    from observability.adapters import investigation_adapter
    from observability.instrument import Patcher, actual_params

    recorded = []
    patcher = Patcher()
    patcher.wrap = lambda target, hooks: recorded.append(target) or True  # type: ignore[assignment]
    investigation_adapter.install(patcher)
    assert len(recorded) == 21   # + _require_stage_ready (Phase 6 readiness gate)
    for target in recorded:
        assert actual_params(target) == target.params, target.label
