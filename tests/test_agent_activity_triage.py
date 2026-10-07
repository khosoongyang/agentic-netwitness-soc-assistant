"""Agent Activity - Triage proof of concept, end to end.

The real durable entry point ``workflow.engine.run_triage_stage`` runs with
the real TriageAgent phases, real LangChain chains and real state store.
Only the network edges are replaced: the chat model is a local fake
LangChain BaseChatModel (so genuine LangChain callbacks fire), the post-stage
summary's raw-SDK call is stubbed, and the internal IOC-correlation corpus
is a temp DB. Everything is isolated under tmp_path (conftest redirects the
workflow DB; this module also redirects the ticket DB and the activity DB).

Covers: equivalence with observability on vs off, the real event sequence,
AI/rule/decision labelling, model metadata from callbacks, repair calls,
AI failure, post-stage summary labelling and failure, approval gate +
analyst decision, run requests, and two incidents running concurrently.
"""

from __future__ import annotations

import copy
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

import observability
from agents.triage import soc_triage_agent
from observability.store import query_events
from workflow import commands
from workflow import engine
from workflow import state_store as wss

_LOCK = threading.Lock()


class FakeTriageChatModel(BaseChatModel):
    """Answers each Triage phase by its system prompt; records every call."""

    model_name: str = "fake-triage-model"
    mode: str = "normal"   # normal | ioc_needs_repair | risk_fails

    @property
    def _llm_type(self) -> str:
        return "fake-triage"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        system = str(messages[0].content)
        with _LOCK:
            CALLS.append({"system": system, "messages": [str(m.content) for m in messages],
                          "kwargs": dict(kwargs), "stop": stop})
        if "JSON formatter" in system:
            content = json.dumps(IOC_JSON)
        elif "IOC triage" in system:
            content = ("I could not settle on a format." if self.mode == "ioc_needs_repair"
                       else json.dumps(IOC_JSON))
        elif "Risk Analyst" in system:
            if self.mode == "risk_fails":
                raise ConnectionError("upstream model endpoint unavailable")
            content = json.dumps(RISK_JSON)
        elif "Classification Template" in system:
            content = json.dumps(CLS_JSON)
        else:
            content = "{}"
        message = AIMessage(
            content=content,
            usage_metadata={"input_tokens": 812, "output_tokens": 240, "total_tokens": 1052,
                            "output_token_details": {"reasoning": 128}},
            response_metadata={"model_name": "fake-triage-model-2026-01-01", "finish_reason": "stop"},
        )
        return ChatResult(generations=[ChatGeneration(message=message)])


CALLS: list[dict[str, Any]] = []
IOC_JSON = {
    "availability": {"matched_iocs": [], "reasoning": "No service disruption is described.", "metakeys": []},
    "confidentiality": {"matched_iocs": [1, 2], "reasoning": "Outbound traffic from the host to an external IP.",
                        "metakeys": ["ip.dst"]},
    "integrity": {"matched_iocs": [1], "reasoning": "An unsigned binary ran from a user-writable path.",
                  "metakeys": ["file.name"]},
}
RISK_JSON = {"likelihood_initiation": "High", "likelihood_occurrence": "medium",
             "likelihood_adverse_impact": "High", "overall_risk": "High",
             "rationale": "Malware execution with outbound connections indicates a likely compromise."}
CLS_JSON = {"classification": "Medium", "incident_category": "Malware infection",
            "response_time": "4 hours", "summary": "A suspicious binary executed and contacted an external host.",
            "recommended_actions": ["Isolate the host", "Collect the binary for analysis"],
            "mitre_tactic": "execution", "mitre_technique": "T1204 User Execution"}

INCIDENT = {"id": "INC-OBS-1", "title": "Suspicious binary execution on HOST-01",
            "alerts": [{"id": "A-1", "title": "Unsigned binary executed", "hostSummary": "HOST-01",
                        "destinationIp": "203.0.113.10", "fileName": "evil.exe"}]}
PROCESSED = {"incident_id": "INC-OBS-1", "alert_title": "Unsigned binary executed",
             "iocs": [{"type": "ip", "value": "203.0.113.10"}, {"type": "file", "value": "evil.exe"}]}

SUMMARY_TEXT = "Triage classified a suspicious binary execution as HIGH risk."


@pytest.fixture()
def triage_env(tmp_path, monkeypatch):
    """Isolated ticket DB, fake chat model, stubbed summary call, empty
    correlation corpus. Returns a helper that prepares one fresh workflow
    DB + run per scenario."""
    CALLS.clear()
    model = FakeTriageChatModel()
    monkeypatch.setattr(soc_triage_agent, "build_llm", lambda cfg, json_mode=False: model)
    import integrations.openai.client as openai_client
    monkeypatch.setattr(openai_client, "invoke_openai_text", lambda *a, **k: SUMMARY_TEXT)
    from agents.investigation.tools import ioc_correlation
    corpus = tmp_path / "corpus.db"
    sqlite3.connect(corpus).close()
    monkeypatch.setattr(ioc_correlation, "_INCIDENTS_DB", corpus)
    monkeypatch.setattr(ioc_correlation, "_PIPELINE_DB", tmp_path / "no_pipeline.db")
    monkeypatch.setattr(ioc_correlation, "_TICKETS_DB", tmp_path / "no_tickets.db")

    def prepare(name: str, incident: dict | None = None) -> tuple[str, str]:
        incident = copy.deepcopy(incident or INCIDENT)
        scenario = tmp_path / name
        scenario.mkdir()
        monkeypatch.setattr(wss, "DB_FILE", scenario / "workflow.db")
        monkeypatch.setattr(engine, "PIPELINE_DB_FILE", scenario / "pipeline.db")
        # In a real run Parsing (run_until_triage_approval) has already
        # initialised the pipeline DB before Triage runs.
        engine.pipeline_db_init()
        monkeypatch.setattr(soc_triage_agent, "_TICKET_DB", scenario / "tickets.db")
        soc_triage_agent._ticket_db_init()
        case_id = incident["id"]
        run_id = wss.start_run(case_id)
        raw_path = engine._save_run_artifact(case_id, run_id, "raw_incident.json", "raw_incident",
                                             {"incident": incident, "data_availability": {}})
        wss.save_raw_incident_path(case_id, run_id, str(raw_path))
        wss.save_parsing_result(case_id, run_id, {"run_id": run_id, "status": "completed",
                                                  "parser_confidence": "High",
                                                  "processed_alert": dict(PROCESSED, incident_id=case_id)})
        wss._guarded_update(case_id, run_id, {"parsing_status": "Complete", "triage_status": "Processing",
                                              "workflow_status": "Processing"})
        return case_id, run_id

    return {"model": model, "prepare": prepare}


@pytest.fixture()
def activity(tmp_path):
    state = observability.install(str(tmp_path / "agent_activity.db"))
    assert state["enabled"], state
    yield observability.get_store()
    observability.uninstall()


def _events(store, case_id, run_id):
    assert store.flush()
    return query_events(case_id=case_id, run_id=run_id, path=store.path)


def _normalise(result: dict) -> dict:
    """Drop wall-clock fields that legitimately differ between two runs."""
    out = copy.deepcopy(result)
    out.get("metakeys_payload", {}).pop("timestamp", None)
    out.get("ticket", {}).pop("created_at", None)
    out.pop("ai_summary_generated_at", None)
    out.pop("run_id", None)   # Phase 6 run binding: each scenario has its own run
    return out


def _workflow_snapshot(case_id: str) -> dict:
    state = wss.get_state(case_id)
    return {
        "statuses": {k: state[k] for k in ("parsing_status", "triage_status", "threat_intel_status",
                                           "workflow_status", "approval_stage", "triage_attempt",
                                           "last_error")},
        "triage_result": _normalise(json.loads(state["triage_result_json"])),
        "ioc_correlation_status": state.get("ioc_correlation_status"),
        "activity_actions": [(r["stage"], r["action"]) for r in wss.get_activity(case_id)],
    }


# ── 20. Equivalence: identical workflow behaviour with and without observability ──

def test_triage_outputs_are_identical_with_observability_on_and_off(triage_env, tmp_path):
    case_off, run_off = triage_env["prepare"]("off")
    result_off = engine.run_triage_stage(case_off, run_off)
    snapshot_off = _workflow_snapshot(case_off)
    calls_off = copy.deepcopy(CALLS)

    CALLS.clear()
    assert observability.install(str(tmp_path / "eq_activity.db"))["enabled"]
    try:
        case_on, run_on = triage_env["prepare"]("on")
        result_on = engine.run_triage_stage(case_on, run_on)
        snapshot_on = _workflow_snapshot(case_on)
        calls_on = copy.deepcopy(CALLS)
        events = _events(observability.get_store(), case_on, run_on)
    finally:
        observability.uninstall()

    assert snapshot_off["statuses"]["triage_status"] == "Awaiting Approval"  # the success path
    assert _normalise(result_on) == _normalise(result_off)
    assert snapshot_on == snapshot_off
    # Same model requests: identical prompts/messages and request kwargs.
    assert calls_on == calls_off and len(calls_on) == 3
    # And observability really was active for the "on" run.
    assert len(events) > 15
    # Nothing written to the workflow's own activity ledger beyond normal behaviour.
    assert snapshot_on["activity_actions"] == snapshot_off["activity_actions"]


@pytest.mark.parametrize("mode", ["risk_fails", "ioc_needs_repair"])
def test_failure_and_repair_paths_are_identical_with_observability_on_and_off(triage_env, tmp_path, mode):
    triage_env["model"].mode = mode
    case_off, run_off = triage_env["prepare"](f"off-{mode}")
    result_off = engine.run_triage_stage(case_off, run_off)
    state_off = wss.get_state(case_off)
    calls_off = copy.deepcopy(CALLS)

    CALLS.clear()
    assert observability.install(str(tmp_path / f"eq-{mode}.db"))["enabled"]
    try:
        case_on, run_on = triage_env["prepare"](f"on-{mode}")
        result_on = engine.run_triage_stage(case_on, run_on)
        state_on = wss.get_state(case_on)
    finally:
        observability.uninstall()

    assert _normalise(result_on) == _normalise(result_off)
    assert CALLS == calls_off
    for key in ("triage_status", "workflow_status", "last_error", "approval_stage"):
        assert state_on[key] == state_off[key], key
    assert _normalise(json.loads(state_on["triage_result_json"])) == \
        _normalise(json.loads(state_off["triage_result_json"]))


# ── Real event sequence, labels and content ────────────────────────────────

def test_triage_run_emits_the_real_sequence_with_truthful_labels(triage_env, activity):
    case_id, run_id = triage_env["prepare"]("seq")
    result = engine.run_triage_stage(case_id, run_id)
    events = _events(activity, case_id, run_id)
    top = [e for e in events if not e["parent_span_id"]]
    shape = [(e["source"], e["ai_content_kind"], e["event_type"], e["status"]) for e in top]

    assert shape == [
        ("orchestration", None, "stage_claimed", "completed"),
        ("system", None, "context_loaded", "completed"),
        ("system", None, "context_loaded", "completed"),
        ("system", None, "cache_bypassed", "info"),
        ("ai", "assessment", "ai_phase", "running"),
        ("ai", "explanation", "ai_phase", "completed"),
        ("ai", "assessment", "ai_phase", "running"),
        ("ai", "explanation", "ai_phase", "completed"),
        ("rule", None, "overall_risk", "completed"),
        ("ai", "assessment", "ai_phase", "running"),
        ("ai", "explanation", "ai_phase", "completed"),
        ("rule", None, "classification_mapping", "completed"),
        ("rule", None, "mitre_normalisation", "completed"),
        ("system", None, "ticket_created", "completed"),
        ("decision", None, "stage_result", "completed"),
        ("ai", "summary", "ai_summary", "running"),
        ("ai", "summary", "ai_summary", "completed"),
        ("system", None, "thinking_narrative", "info"),
        ("tool", None, "ioc_correlation", "running"),
        ("tool", None, "ioc_correlation", "completed"),
        ("rule", None, "approval_policy", "completed"),
        ("orchestration", None, "routing", "info"),
        ("orchestration", None, "stage_settled", "completed"),
        ("human", None, "approval_required", "waiting"),
    ]
    sequences = [e["sequence"] for e in events]
    assert sequences == sorted(sequences)
    assert all(e["case_id"] == case_id and e["run_id"] == run_id and e["stage"] == "triage"
               for e in events)
    assert {e["stage_attempt"] for e in events} == {1}

    ticket = result["ticket"]
    decision = next(e for e in top if e["source"] == "decision")
    assert ticket["classification"] in decision["title"]
    # Triage has no "true positive" verdict and no confidence value.
    flat = json.dumps(events).lower()
    assert "true positive" not in flat and "confidence\"" not in flat.replace("parser_confidence", "")

    # AI explanation content is exactly what the model returned.
    ioc_done, risk_done, cls_done = [e for e in top if e["ai_content_kind"] == "explanation"]
    ioc_texts = json.dumps(ioc_done["metadata"]["details"])
    assert IOC_JSON["confidentiality"]["reasoning"] in ioc_texts
    assert IOC_JSON["integrity"]["reasoning"] in ioc_texts
    assert risk_done["detail"] == RISK_JSON["rationale"]
    assert cls_done["detail"] == CLS_JSON["summary"]

    # Code-derived values are labelled RULE, not AI, and reflect real values.
    overall = next(e for e in top if e["event_type"] == "overall_risk")
    assert f"Overall risk {ticket['risk_rating']['overall_risk'].upper()}" in overall["detail"]
    assert "not by the model" in overall["detail"]
    mapping = next(e for e in top if e["event_type"] == "classification_mapping")
    assert ticket["classification"] in mapping["detail"]
    assert "Medium" in mapping["detail"]  # the model's own (unused) proposal is disclosed
    mitre = next(e for e in top if e["event_type"] == "mitre_normalisation")
    assert "'execution' → 'Execution'" in mitre["detail"]

    # Post-stage summary is explicitly marked as not part of the decision.
    summary_done = [e for e in top if e["event_type"] == "ai_summary"][-1]
    assert summary_done["metadata"]["post_stage"] is True
    assert summary_done["detail"] == SUMMARY_TEXT
    assert "Not used in triage decisions" in json.dumps(summary_done["metadata"]["details"])

    # The approval wait and analyst decision share one span (row resolves in place).
    waiting = top[-1]
    assert waiting["span_id"] == f"approval:{run_id}:triage:1"


def test_model_call_metadata_comes_from_langchain_callbacks(triage_env, activity):
    case_id, run_id = triage_env["prepare"]("llm")
    engine.run_triage_stage(case_id, run_id)
    events = _events(activity, case_id, run_id)
    llm = [e for e in events if e["event_type"] == "llm_call"]
    assert [e["status"] for e in llm] == ["running", "completed"] * 3
    phases = {e["span_id"] for e in events if e["event_type"] == "ai_phase"}
    assert all(e["parent_span_id"] in phases and e["origin"] == "langchain_callback" for e in llm)
    done = llm[1]
    assert done["metadata"]["model"] == "fake-triage-model"
    assert done["metadata"]["response_model"] == "fake-triage-model-2026-01-01"
    assert done["metadata"]["usage"] == {"input": 812, "output": 240, "total": 1052, "reasoning": 128}
    assert done["metadata"]["duration_ms"] >= 0
    fields = {f["label"]: f["value"] for f in done["metadata"]["details"][0]["fields"]}
    assert fields["Reasoning tokens"].startswith("128")
    assert "content is not exposed" in fields["Reasoning tokens"]
    # Prompts and raw model output are never recorded.
    flat = json.dumps(events)
    assert "SOC Risk Analyst" not in flat and "IOC CHECKLIST" not in flat


def test_reasoning_unavailable_is_reported_as_unavailable(triage_env, activity, monkeypatch):
    """A provider that reports no reasoning tokens yields no reasoning field at all."""
    original = FakeTriageChatModel._generate

    def no_reasoning(self, messages, stop=None, run_manager=None, **kwargs):
        result = original(self, messages, stop, run_manager, **kwargs)
        result.generations[0].message.usage_metadata = {"input_tokens": 5, "output_tokens": 6,
                                                        "total_tokens": 11}
        return result

    monkeypatch.setattr(FakeTriageChatModel, "_generate", no_reasoning)
    case_id, run_id = triage_env["prepare"]("noreason")
    engine.run_triage_stage(case_id, run_id)
    done = [e for e in _events(activity, case_id, run_id)
            if e["event_type"] == "llm_call" and e["status"] == "completed"]
    assert done and all("reasoning" not in e["metadata"]["usage"] for e in done)
    assert all("Reasoning tokens" not in json.dumps(e["metadata"]["details"]) for e in done)


def test_repair_call_is_shown_when_model_output_lacks_fields(triage_env, activity):
    triage_env["model"].mode = "ioc_needs_repair"
    case_id, run_id = triage_env["prepare"]("repair")
    engine.run_triage_stage(case_id, run_id)
    events = _events(activity, case_id, run_id)
    repair = [e for e in events if e["event_type"] == "ai_repair"]
    assert [e["status"] for e in repair] == ["running", "completed"]
    ioc_phase = next(e for e in events if e["event_type"] == "ai_phase")
    assert all(e["parent_span_id"] == ioc_phase["span_id"] for e in repair)
    assert len([e for e in events if e["event_type"] == "llm_call" and e["status"] == "completed"]) == 4


def test_ai_failure_is_shown_and_never_disguised_as_success(triage_env, activity):
    triage_env["model"].mode = "risk_fails"
    case_id, run_id = triage_env["prepare"]("aifail")
    result = engine.run_triage_stage(case_id, run_id)
    assert result["status"] == "failed"
    events = _events(activity, case_id, run_id)
    failed_calls = [e for e in events if e["event_type"] == "llm_call" and e["status"] == "failed"]
    assert failed_calls and "ConnectionError" in failed_calls[0]["detail"]
    phase_failed = [e for e in events if e["event_type"] == "ai_phase" and e["status"] == "failed"]
    assert phase_failed and phase_failed[0]["title"] == "Risk rating assessment failed"
    assert not [e for e in events if e["event_type"] == "ai_phase" and "Classification" in e["title"]]
    settled = next(e for e in events if e["event_type"] == "stage_settled")
    assert settled["status"] == "failed"
    assert not [e for e in events if e["source"] == "human"]  # no approval gate on failure
    assert any(e["source"] == "decision" and e["status"] == "failed" for e in events)


def test_post_stage_summary_failure_is_a_visible_warning(triage_env, activity, monkeypatch):
    import integrations.openai.client as openai_client

    def boom(*args, **kwargs):
        raise RuntimeError("summary endpoint unavailable")

    monkeypatch.setattr(openai_client, "invoke_openai_text", boom)
    case_id, run_id = triage_env["prepare"]("sumfail")
    engine.run_triage_stage(case_id, run_id)
    summary = [e for e in _events(activity, case_id, run_id) if e["event_type"] == "ai_summary"]
    assert summary[-1]["status"] == "warning"
    assert summary[-1]["title"] == "AI summary unavailable"
    assert "summary endpoint unavailable" in summary[-1]["detail"]
    assert wss.get_state(case_id)["triage_status"] == "Awaiting Approval"  # workflow unaffected


def test_cached_result_is_reported_as_reused_without_model_calls(triage_env, activity):
    case_id, run_id = triage_env["prepare"]("cache")
    incident = engine.load_raw_incident_for_run(case_id, run_id)
    engine.run_triage(incident, force=False)          # populate the agent's own cache
    CALLS.clear()
    engine.run_triage(incident, force=False)          # second call: cache hit
    assert CALLS == []
    events = _events(activity, case_id, run_id)
    assert any(e["event_type"] == "cache_hit" for e in events)


# ── Human-in-the-loop and orchestration ────────────────────────────────────

def test_run_request_and_analyst_approval_are_recorded(triage_env, activity):
    case_id, run_id = triage_env["prepare"]("approve")
    wss._guarded_update(case_id, run_id, {"triage_status": "Pending", "workflow_status": "Awaiting Action"})
    commands.start_stage(case_id, "triage", executor=lambda *args: None)
    engine.run_triage_stage(case_id, run_id)
    commands.approve_stage(case_id, "triage", analyst="Analyst One", comments="Escalate to IR.")
    events = _events(activity, case_id, run_id)

    requested = events[0]
    assert (requested["source"], requested["event_type"], requested["title"]) == (
        "orchestration", "stage_requested", "Triage run requested")
    waiting = next(e for e in events if e["event_type"] == "approval_required")
    decision = next(e for e in events if e["event_type"] == "approval_decision")
    assert decision["span_id"] == waiting["span_id"]
    assert decision["title"] == "Triage approved by Analyst One"
    assert decision["detail"] == "Escalate to IR."
    unlocked = events[-1]
    assert unlocked["source"] == "orchestration" and "Pending" in unlocked["detail"]


def test_analyst_rejection_is_recorded_with_reason(triage_env, activity):
    case_id, run_id = triage_env["prepare"]("reject")
    engine.run_triage_stage(case_id, run_id)
    commands.reject_stage(case_id, "triage", analyst="Analyst Two", comments="Benign admin tool.")
    decision = [e for e in _events(activity, case_id, run_id) if e["event_type"] == "approval_decision"][-1]
    assert decision["title"] == "Triage rejected by Analyst Two"
    assert decision["detail"] == "Benign admin tool."


def test_rerun_events_are_grouped_by_attempt(triage_env, activity):
    case_id, run_id = triage_env["prepare"]("rerun")
    engine.run_triage_stage(case_id, run_id)
    commands.rerun_stage(case_id, "triage", executor=lambda *args: None)
    engine.run_triage_stage(case_id, run_id)
    events = _events(activity, case_id, run_id)
    assert {e["stage_attempt"] for e in events} == {1, 2}
    rerun = next(e for e in events if e["event_type"] == "stage_requested")
    assert rerun["title"] == "Triage re-run requested" and rerun["stage_attempt"] == 2
    waits = [e["span_id"] for e in events if e["event_type"] == "approval_required"]
    assert waits == [f"approval:{run_id}:triage:1", f"approval:{run_id}:triage:2"]


def test_rerun_approval_decision_names_the_attempt_it_decided(triage_env, activity):
    # Canonical audit R5: the decision event and the workflow_approvals row
    # both identify the Triage attempt that was actually approved.
    case_id, run_id = triage_env["prepare"]("rerun-approve")
    engine.run_triage_stage(case_id, run_id)
    commands.approve_stage(case_id, "triage", analyst="Analyst One")
    commands.rerun_stage(case_id, "triage", executor=lambda *args: None)
    engine.run_triage_stage(case_id, run_id)
    commands.approve_stage(case_id, "triage", analyst="Analyst Two", comments="Re-checked.")
    decisions = [e for e in _events(activity, case_id, run_id) if e["event_type"] == "approval_decision"]
    assert [(e["stage_attempt"], e["span_id"]) for e in decisions] == [
        (1, f"approval:{run_id}:triage:1"), (2, f"approval:{run_id}:triage:2")]
    rows = [r for r in wss.get_approval_history(case_id, run_id) if r["approval_stage"] == "triage"]
    assert [(r["analyst"], r["stage_attempt"]) for r in rows] == [("Analyst One", 1), ("Analyst Two", 2)]


def test_two_incidents_triaged_concurrently_are_attributed_independently(triage_env, activity, tmp_path):
    first = triage_env["prepare"]("c1", dict(INCIDENT, id="INC-C1"))
    # Both runs share one workflow DB for this test.
    second_incident = dict(INCIDENT, id="INC-C2")
    run2 = wss.start_run("INC-C2")
    raw = engine._save_run_artifact("INC-C2", run2, "raw_incident.json", "raw_incident",
                                    {"incident": second_incident, "data_availability": {}})
    wss.save_raw_incident_path("INC-C2", run2, str(raw))
    # Phase 6: the same canonical Parsing result prepare() persists for INC-C1.
    wss.save_parsing_result("INC-C2", run2, {"run_id": run2, "status": "completed",
                                             "parser_confidence": "High",
                                             "processed_alert": dict(PROCESSED, incident_id="INC-C2")})
    wss._guarded_update("INC-C2", run2, {"parsing_status": "Complete", "triage_status": "Processing",
                                         "workflow_status": "Processing"})
    runs = [first, ("INC-C2", run2)]
    threads = [threading.Thread(target=engine.run_triage_stage, args=pair) for pair in runs]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    for case_id, run_id in runs:
        events = _events(activity, case_id, run_id)
        assert events and all(e["case_id"] == case_id and e["run_id"] == run_id for e in events)
        assert len([e for e in events if e["event_type"] == "llm_call" and e["status"] == "completed"]) == 3
        assert events[-1]["event_type"] == "approval_required"


def test_unobserved_paths_emit_nothing(triage_env, activity):
    """Model calls outside an observed stage scope (e.g. Ask Aegis chat
    building its own chains) attach no handler and record nothing."""
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.messages import SystemMessage, HumanMessage

    chain = ChatPromptTemplate.from_messages([SystemMessage(content="IOC triage"),
                                              HumanMessage(content="x")]) | triage_env["model"]
    chain.invoke({})
    assert activity.flush()
    assert activity.latest_sequence == 0


def test_attaching_the_handler_never_switches_a_model_to_streaming():
    from langchain_core.callbacks.manager import CallbackManagerForLLMRun
    from observability import context as ctx
    from observability.adapters.langchain_adapter import AgentActivityCallbackHandler

    llm = soc_triage_agent.build_llm(soc_triage_agent.OpenAILLMConfig(api_key="sk-test-not-used"),
                                     json_mode=True)
    handler = AgentActivityCallbackHandler(ctx.RunScope(case_id="X", run_id="r", stage="triage"))
    manager = CallbackManagerForLLMRun(run_id=__import__("uuid").uuid4(), handlers=[handler],
                                       inheritable_handlers=[])
    assert llm._should_stream(async_api=False, run_manager=manager) is False
    assert llm._should_stream(async_api=False, run_manager=None) is False
