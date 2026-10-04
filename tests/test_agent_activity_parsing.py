"""Agent Activity - Parsing & Normalisation.

Runs the real durable Parsing entry point
(workflow.engine.run_until_triage_approval(parsing_only=True)) with the real
rule-based parser, the real NetWitness export/live lookup logic
(get_comprehensive_incident_payload), the real data-availability recording
and the real workflow validation. Only the network edges are replaced: the
NetWitness auth/API functions and the raw-SDK model call used by the
post-parser AI summary. Fakes are installed BEFORE observability so the
observability wrappers wrap them exactly as they would wrap the real ones.

Everything is isolated under tmp_path: workflow/pipeline DBs, run artifacts,
parser output directory, NetWitness export directory and the activity DB.
"""

from __future__ import annotations

import copy
import json
import re
import threading
from pathlib import Path

import pytest

import observability
from backend import create_app
from integrations.netwitness import fetch_api
from observability.store import query_events
from workflow import engine
from workflow import state_store as wss

CASE = "INC-PARSE-OBS"
SUMMARY_REPLY = ("SUMMARY: A high-risk NetWitness endpoint alert on HOST-07 shows outbound traffic "
                 "to 203.0.113.45.\nTHINKING:\n- Host HOST-07\n- Destination IP 203.0.113.45")
INCIDENT = {
    "id": CASE,
    "title": "High Risk Alerts: NetWitness Endpoint for HOST-07",
    "riskScore": 80,
    "severity": "High",
    "alertCount": 1,
    "alertMeta": {"SourceIp": ["10.1.2.3"], "DestinationIp": ["203.0.113.45"]},
}
EXPORT_ALERTS = [{
    "id": "ALERT-1", "title": "Suspicious outbound connection", "receivedTime": "2026-09-30T10:00:00Z",
    "originalAlert": {"events": [{"ip_src": "10.1.2.3", "ip_dst": "203.0.113.45",
                                  "host_src": "HOST-07", "user_src": "jdoe"}]},
}]

MODEL_CALLS: list[dict] = []
_LOCK = threading.Lock()


def _fake_model(prompt, *, system=None, model=None, temperature=None, max_output_tokens=None,
                timeout=None, text_format=None):
    with _LOCK:
        MODEL_CALLS.append({"prompt": prompt, "system": system, "model": model,
                            "temperature": temperature, "max_output_tokens": max_output_tokens,
                            "timeout": timeout, "text_format": text_format})
    return SUMMARY_REPLY


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Per-test isolation plus network fakes. Returns a helper that switches
    to a fresh workflow DB for one scenario."""
    import integrations.openai.client as openai_client

    MODEL_CALLS.clear()
    monkeypatch.setattr(openai_client, "invoke_openai_text", _fake_model)
    monkeypatch.setattr(engine, "REP_DIR", tmp_path / "reporting")
    monkeypatch.setattr(engine, "_TRUSTED_OUTPUT_ROOT", tmp_path / "artifacts")
    monkeypatch.setattr(fetch_api, "_REPO_ROOT", tmp_path / "nw")
    (tmp_path / "nw" / "demo").mkdir(parents=True)
    # Default: no export, no token -> no live call can happen.
    monkeypatch.setattr(fetch_api, "get_auth_token", lambda host=None, token=None, force_refresh=False: None)

    def fresh(name: str) -> None:
        scenario = tmp_path / name
        scenario.mkdir()
        monkeypatch.setattr(wss, "DB_FILE", scenario / "workflow.db")
        monkeypatch.setattr(engine, "PIPELINE_DB_FILE", scenario / "pipeline.db")
        wss.db_init()

    def export(alerts=EXPORT_ALERTS) -> None:
        path = tmp_path / "nw" / "demo" / f"incident_{CASE}_respond_api_export.json"
        path.write_text(json.dumps({"incident": {"id": CASE}, "alerts": alerts}), encoding="utf-8")

    return {"fresh": fresh, "export": export, "tmp": tmp_path, "monkeypatch": monkeypatch}


@pytest.fixture()
def activity(tmp_path):
    state = observability.install(str(tmp_path / "agent_activity.db"))
    assert state["enabled"], state
    assert {"parsing", "triage"} <= set(state["coverage"])
    yield observability.get_store()
    observability.uninstall()


def _run(incident=None, **kwargs) -> dict:
    return engine.run_until_triage_approval(copy.deepcopy(incident or INCIDENT), parsing_only=True, **kwargs)


def _events(store, run_id=None):
    assert store.flush()
    run_id = run_id or wss.get_state(CASE)["run_id"]
    return query_events(case_id=CASE, run_id=run_id, stage="parsing", path=store.path)


def _top(events):
    return [e for e in events if not e["parent_span_id"]]


def _reinstall(store, monkeypatch, patches):
    """Swap in fakes for one test. Order matters: uninstall FIRST so the
    monkeypatch saves the real originals (its undo must never restore an
    observability wrapper), then patch, then install so the wrappers wrap
    the fakes exactly as they wrap the real functions."""
    observability.uninstall()
    for owner, name, value in patches:
        monkeypatch.setattr(owner, name, value)
    assert observability.install(str(store.path))["enabled"]
    return observability.get_store()


_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")


def _normalise(value, run_id: str) -> str:
    """Replace the run id (raw and filesystem-safe forms) and wall-clock
    timestamps, which legitimately differ between two runs."""
    text = json.dumps(value, sort_keys=True, default=str)
    for form in (run_id, engine._safe(run_id), json.dumps(run_id)[1:-1]):
        text = text.replace(form, "<RUN>")
    return _TS.sub("<TS>", text)


def _snapshot(ctx: dict) -> dict:
    run_id = ctx["run_id"]
    state = wss.get_state(CASE)
    return {
        "ctx": _normalise({k: v for k, v in ctx.items() if k != "run_id"}, run_id),
        "statuses": {k: state[k] for k in ("parsing_status", "triage_status", "workflow_status",
                                           "last_error")},
        "parsing_result_json": _normalise(json.loads(state["parsing_result_json"] or "null"), run_id),
        "raw_incident": _normalise(engine.load_raw_incident_for_run(CASE, run_id), run_id),
        "availability": engine.load_data_availability_for_run(CASE, run_id),
        "activity_ledger": [(r["stage"], r["action"]) for r in wss.get_activity(CASE)],
        "model_calls": [_normalise(call, run_id) for call in MODEL_CALLS],
    }


# ── 18/19/20. Equivalence ──────────────────────────────────────────────────

@pytest.mark.parametrize("scenario", ["no_telemetry", "local_export", "parser_failure"])
def test_parsing_is_identical_with_observability_on_and_off(env, tmp_path, scenario):
    if scenario == "local_export":
        env["export"]()
    if scenario == "parser_failure":
        import agents.parsing as parsing_pkg

        def broken(raw_alert, output_dir="x"):
            raise ValueError("unsupported incident structure")

        env["monkeypatch"].setattr(parsing_pkg, "run_parser_normalisation_for_dashboard", broken)

    env["fresh"]("off")
    off = _snapshot(_run())
    MODEL_CALLS.clear()

    assert observability.install(str(tmp_path / f"eq-{scenario}.db"))["enabled"]
    try:
        env["fresh"]("on")
        on = _snapshot(_run())
        events = _events(observability.get_store())
    finally:
        observability.uninstall()

    assert on == off
    assert events, "observability was active for the 'on' run"
    # "local_export" fails in BOTH runs: merging the export's alert records
    # makes the parser's own identity guard reject its output (pre-existing
    # behaviour, also seen on the live INC-53021 run) - observability does
    # not change it, and these tests must not either.
    expected = {"no_telemetry": "Complete", "local_export": "Failed", "parser_failure": "Failed"}
    assert off["statuses"]["parsing_status"] == expected[scenario]
    assert len(off["model_calls"]) == (1 if scenario == "no_telemetry" else 0)


# ── 1-8, 10-11, 13. The real Parsing timeline ──────────────────────────────

def test_successful_parsing_timeline_is_real_and_truthfully_labelled(env, activity):
    env["fresh"]("ok")
    ctx = _run()
    events = _events(activity, ctx["run_id"])
    top = _top(events)
    shape = [(e["source"], e["ai_content_kind"], e["event_type"], e["status"]) for e in top]
    assert shape == [
        ("orchestration", None, "stage_requested", "completed"),
        ("tool", None, "telemetry_fetch", "running"),
        ("tool", None, "telemetry_fetch", "warning"),
        ("system", None, "raw_incident_saved", "completed"),
        ("system", None, "parser", "running"),
        ("system", None, "parser", "completed"),
        ("ai", "summary", "ai_summary", "running"),
        ("ai", "summary", "ai_summary", "completed"),
        ("system", None, "result_saved", "completed"),
        ("orchestration", None, "status_update", "completed"),
        ("rule", None, "validation", "completed"),
        ("orchestration", None, "routing", "info"),
        ("decision", None, "stage_result", "completed"),
        ("orchestration", None, "stage_settled", "completed"),
    ]
    assert all(e["case_id"] == CASE and e["run_id"] == ctx["run_id"] and e["stage"] == "parsing"
               for e in events)
    assert [e["sequence"] for e in events] == sorted(e["sequence"] for e in events)

    # 13. AI appears only as the post-parser summary - never as parsing work.
    ai = [e for e in events if e["source"] == "ai"]
    assert {e["event_type"] for e in ai} == {"ai_summary", "llm_call"}
    assert all(e["ai_content_kind"] == "summary" for e in ai)
    parser_done = next(e for e in top if e["event_type"] == "parser" and e["status"] == "completed")
    assert all(e["sequence"] > parser_done["sequence"] for e in ai)
    assert "no AI" in next(e for e in top if e["event_type"] == "parser")["detail"]

    # 6. Parser facts come from the real returned result and are marked as such.
    parsing = ctx["parsing"]
    assert parser_done["metadata"]["result_derived"] is True
    fields = {f["label"]: f["value"] for f in parser_done["metadata"]["details"][1]["fields"]}
    assert fields["Parser status"] == "completed"
    assert fields["Input format"] == parsing["normalised_alert"]["parser_metadata"]["input_format"].replace("_", " ")
    assert fields["Observable indicators"] == str(len(parsing["processed_alert"]["iocs"]))
    assert fields["Identity guard"].startswith("passed")
    assert "Parser confidence (rule-based score)" not in fields
    assert "not observed as individually timed steps" in parser_done["metadata"]["details"][0]["text"]

    # 7. Validation is a RULE event carrying the real checks.
    validation = next(e for e in top if e["event_type"] == "validation")
    assert "parsing status completed" in validation["detail"]

    # 10/11. Post-stage summary: real model argument, real reply, explicit label.
    summary = [e for e in top if e["event_type"] == "ai_summary"]
    assert all(e["metadata"]["post_stage"] for e in summary)
    assert "Not used in parsing decisions" in summary[0]["detail"]
    assert summary[1]["detail"] == parsing["ai_summary"]
    bullets = json.dumps(summary[1]["metadata"]["details"])
    assert "model-written output" in bullets and "Destination IP 203.0.113.45" in bullets
    request = [e for e in events if e["event_type"] == "llm_call"]
    assert [e["status"] for e in request] == ["running", "completed"]
    assert all(e["parent_span_id"] == summary[0]["span_id"] for e in request)
    assert request[0]["metadata"]["model"] == (MODEL_CALLS[0]["model"] or "default (OPENAI_MODEL)")
    # Prompts are never recorded.
    assert "Parsed alert fields" not in json.dumps(events)


def test_parsing_events_never_label_anything_as_reasoning(env, activity):
    env["fresh"]("labels")
    flat = json.dumps(_events(activity, _run()["run_id"])).lower()
    assert "reasoning" not in flat and "thinking" not in flat


# ── 2-4. NetWitness telemetry ──────────────────────────────────────────────

def test_local_export_is_reported_as_a_local_file_not_a_live_call(env, activity):
    env["export"]()
    env["fresh"]("export")
    events = _events(activity, _run()["run_id"])
    children = [e for e in events if e["parent_span_id"]]
    assert [(e["source"], e["event_type"]) for e in children] == [("system", "telemetry_export")]
    done = next(e for e in events if e["event_type"] == "telemetry_fetch" and e["status"] != "running")
    assert done["status"] == "completed"
    assert "1 raw alert record(s)" in done["detail"] and "local NetWitness export" in done["detail"]


def test_live_netwitness_success_reports_each_real_api_call(env, activity):
    store = _reinstall(activity, env["monkeypatch"], [
        (fetch_api, "get_auth_token", lambda host=None, token=None, force_refresh=False: "session-token"),
        (fetch_api, "fetch_incident_via_fetch_api",
         lambda host, token, incident_id, auto_refresh=True: {"id": incident_id, "title": "x"}),
        (fetch_api, "fetch_alerts_via_fetch_api",
         lambda host, token, incident_id, count=1000, auto_refresh=True: list(EXPORT_ALERTS)),
    ])
    env["fresh"]("live")
    events = _events(store, _run()["run_id"])
    children = [(e["event_type"], e["status"], e["title"]) for e in events if e["parent_span_id"]]
    assert children == [
        ("netwitness_auth", "completed", "NetWitness session token available"),
        ("netwitness_api", "running", "NetWitness API: incident details (FETCH API)"),
        ("netwitness_api", "completed", "NetWitness API: incident details (FETCH API)"),
        ("netwitness_api", "running", "NetWitness API: alert records (FETCH API)"),
        ("netwitness_api", "completed", "NetWitness API: alert records (FETCH API)"),
    ]
    done = [e for e in events if e["event_type"] == "telemetry_fetch"][-1]
    assert done["status"] == "completed" and "live NetWitness API" in done["detail"]
    assert "session-token" not in json.dumps(events)


def test_live_netwitness_failure_is_shown_and_parsing_continues(env, activity):
    def failing(host, token, incident_id, count=1000, auto_refresh=True):
        raise ConnectionError("GET https://nw.internal/rest/api/alerts?token=SUPERSECRET timed out")

    store = _reinstall(activity, env["monkeypatch"], [
        (fetch_api, "get_auth_token", lambda host=None, token=None, force_refresh=False: "tok-123456789"),
        (fetch_api, "fetch_incident_via_fetch_api",
         lambda host, token, incident_id, auto_refresh=True: {"id": incident_id}),
        (fetch_api, "fetch_alerts_via_fetch_api", failing),
    ])
    env["fresh"]("livefail")
    ctx = _run()
    events = _events(store, ctx["run_id"])
    failed = [e for e in events if e["event_type"] == "netwitness_api" and e["status"] == "failed"]
    assert failed and "ConnectionError" in failed[0]["detail"]
    # 14. Sanitisation: the token in the provider error never reaches the event.
    assert "SUPERSECRET" not in json.dumps(events)
    done = [e for e in events if e["event_type"] == "telemetry_fetch"][-1]
    assert done["status"] == "warning" and "live NetWitness API call failed" in done["detail"]
    assert ctx["stages"]["parsing"] == "completed"
    assert _top(events)[-2]["event_type"] == "stage_result" and _top(events)[-2]["status"] == "completed"


def test_missing_token_is_reported_as_live_retrieval_not_attempted(env, activity):
    env["fresh"]("notoken")
    events = _events(activity, _run()["run_id"])
    auth = next(e for e in events if e["event_type"] == "netwitness_auth")
    assert auth["status"] == "warning" and auth["title"] == "No NetWitness session token available"
    done = [e for e in events if e["event_type"] == "telemetry_fetch"][-1]
    assert "no NetWitness session token" in done["detail"]
    assert not [e for e in events if e["event_type"] == "netwitness_api"]


# ── 9. Parsing failures ────────────────────────────────────────────────────

def test_parser_identity_guard_failure_reports_the_parsers_own_reason(env, activity):
    env["export"]()
    env["fresh"]("identity")
    ctx = _run()
    events = _events(activity, ctx["run_id"])
    parser = [e for e in _top(events) if e["event_type"] == "parser"][-1]
    assert parser["status"] == "failed" and parser["title"] == "Parser returned a failed result"
    assert parser["detail"] == ctx["parsing"]["summary"]
    assert "Identity guard" in json.dumps(parser["metadata"]["details"])
    decision = next(e for e in events if e["event_type"] == "stage_result")
    assert decision["status"] == "failed" and decision["detail"] == ctx["parsing"]["summary"]
    assert decision["metadata"]["workflow_error"] == ctx["errors"]["parsing"]
    assert not [e for e in events if e["source"] == "ai"]  # no summary for a failed parse

def test_parser_exception_is_a_failed_parsing_without_any_ai_summary(env, activity):
    import agents.parsing as parsing_pkg

    def broken(raw_alert, output_dir="x"):
        raise ValueError("unsupported incident structure")

    store = _reinstall(activity, env["monkeypatch"],
                       [(parsing_pkg, "run_parser_normalisation_for_dashboard", broken)])
    env["fresh"]("parserfail")
    ctx = _run()
    events = _events(store, ctx["run_id"])
    top = _top(events)
    parser = [e for e in top if e["event_type"] == "parser"]
    assert [e["status"] for e in parser] == ["running", "failed"]
    assert "unsupported incident structure" in parser[1]["detail"]
    assert not [e for e in events if e["source"] == "ai"]
    assert top[-2]["source"] == "decision" and top[-2]["status"] == "failed"
    assert top[-1]["event_type"] == "stage_settled" and top[-1]["status"] == "failed"
    assert wss.get_state(CASE)["parsing_status"] == "Failed"


def test_validation_failure_is_a_failed_rule_and_a_failed_parsing(env, activity, monkeypatch):
    import agents.parsing as parsing_pkg
    from observability.instrument import unwrapped

    real = unwrapped(parsing_pkg.run_parser_normalisation_for_dashboard)

    def mismatched(raw_alert, output_dir="x"):
        result = real(raw_alert, output_dir=output_dir)
        result["normalised_alert"].setdefault("alert_summary", {})["incident_id"] = "INC-SOMETHING-ELSE"
        return result

    store = _reinstall(activity, monkeypatch,
                       [(parsing_pkg, "run_parser_normalisation_for_dashboard", mismatched)])
    env["fresh"]("validationfail")
    events = _events(store, _run()["run_id"])
    validation = next(e for e in events if e["event_type"] == "validation")
    assert validation["source"] == "rule" and validation["status"] == "failed"
    assert "INC-SOMETHING-ELSE" in validation["detail"]
    decision = next(e for e in events if e["event_type"] == "stage_result")
    assert decision["status"] == "failed"


# ── 12. AI summary failure never looks like a parsing failure ──────────────

def test_ai_summary_failure_leaves_parsing_successful(env, activity, monkeypatch):
    import integrations.openai.client as openai_client

    # Same signature as the real call, so the observability wrapper (which
    # refuses to wrap a mismatched signature) wraps it like the real one.
    def down(prompt, *, system=None, model=None, temperature=None, max_output_tokens=None,
             timeout=None, text_format=None):
        raise RuntimeError("summary endpoint unavailable")

    store = _reinstall(activity, monkeypatch, [(openai_client, "invoke_openai_text", down)])
    env["fresh"]("aifail")
    ctx = _run()
    events = _events(store, ctx["run_id"])
    request = [e for e in events if e["event_type"] == "llm_call"]
    assert [e["status"] for e in request] == ["running", "failed"]
    summary = [e for e in events if e["event_type"] == "ai_summary"][-1]
    assert summary["status"] == "warning" and summary["title"] == "Post-stage AI summary unavailable"
    decision = next(e for e in events if e["event_type"] == "stage_result")
    assert decision["status"] == "completed" and decision["title"] == "Parsing & Normalisation completed"
    assert wss.get_state(CASE)["parsing_status"] == "Complete"


# ── 15/16. SSE delivery and history ────────────────────────────────────────

def test_parsing_events_are_served_by_history_and_sse(env, activity):
    env["fresh"]("sse")
    run_id = _run()["run_id"]
    assert activity.flush()
    app = create_app({"TESTING": True, "AGENT_ACTIVITY_DB_PATH": str(activity.path),
                      "AGENT_ACTIVITY_STREAM_SECONDS": 0.3})
    client = app.test_client()
    history = client.get(f"/api/cases/{CASE}/activity?stage=parsing").get_json()
    assert history["run_id"] == run_id and len(history["events"]) == len(_events(activity, run_id))
    body = client.get(f"/api/cases/{CASE}/activity/stream?stage=parsing").get_data(as_text=True)
    streamed = [json.loads(m) for m in re.findall(r"^data: (.*)$", body, re.M)]
    assert [e["sequence"] for e in streamed] == [e["sequence"] for e in history["events"]]
    # Reload/resume: nothing newer than the last seen id.
    resumed = client.get(f"/api/cases/{CASE}/activity/stream?stage=parsing",
                         headers={"Last-Event-ID": str(streamed[-1]["sequence"])}).get_data(as_text=True)
    assert "event: activity" not in resumed


# ── 17. Triage still works after a Parsing run ─────────────────────────────

def test_triage_after_parsing_keeps_its_own_timeline(env, activity, monkeypatch):
    from tests.test_agent_activity_triage import FakeTriageChatModel
    from agents.triage import soc_triage_agent
    from agents.investigation.tools import ioc_correlation

    env["fresh"]("thentriage")
    run_id = _run()["run_id"]
    monkeypatch.setattr(soc_triage_agent, "build_llm", lambda cfg, json_mode=False: FakeTriageChatModel())
    monkeypatch.setattr(soc_triage_agent, "_TICKET_DB", env["tmp"] / "tickets.db")
    soc_triage_agent._ticket_db_init()
    monkeypatch.setenv("NW_DISABLE_IOC_CORRELATION", "1")
    wss._guarded_update(CASE, run_id, {"triage_status": "Processing", "workflow_status": "Processing"})
    engine.run_triage_stage(CASE, run_id)
    assert activity.flush()
    parsing = query_events(case_id=CASE, run_id=run_id, stage="parsing", path=activity.path)
    triage = query_events(case_id=CASE, run_id=run_id, stage="triage", path=activity.path)
    assert parsing[-1]["event_type"] == "stage_settled"
    assert [e["event_type"] for e in _top(triage)][:2] == ["stage_claimed", "context_loaded"]
    assert _top(triage)[-1]["event_type"] == "approval_required"
    assert len([e for e in triage if e["event_type"] == "llm_call" and e["status"] == "completed"]) == 3
    # The parsing scope never leaks into Triage events or vice versa.
    assert {e["stage"] for e in parsing} == {"parsing"} and {e["stage"] for e in triage} == {"triage"}


def test_parsing_wrap_points_match_their_expected_signatures():
    from observability.adapters import parsing_adapter
    from observability.instrument import Patcher, actual_params

    recorded = []
    patcher = Patcher()
    patcher.wrap = lambda target, hooks: recorded.append(target) or True  # type: ignore[assignment]
    parsing_adapter.install(patcher)
    assert len(recorded) == 17
    for target in recorded:
        assert actual_params(target) == target.params, target.label
