"""tests/test_chat_triage_parity.py -- audit T-07.

Ask Aegis (soc_triage_chat_respond) used to run a full, unpersisted 3-LLM
re-triage whenever a question merely contained words like "ticket", "ioc" or
"classification" -- without baseline_db_path, data_availability,
suppressions or provenance, burning a ticket UNC and able to show a second,
different verdict next to the analyst-reviewed one.

Chat is now read-only with respect to triage: no message ever constructs a
TriageAgent. An explicit re-triage request is answered with a pointer to the
durable workflow control; everything else goes to the grounded Q&A path.
"""
from __future__ import annotations

import pytest

from agents.triage import soc_triage_agent as sta

INCIDENT = {"id": "INC-CHAT-T07", "title": "Suspicious logon", "alerts": []}


class _Boom:
    def __init__(self, *a, **k):
        raise AssertionError("chat must never construct a TriageAgent")


class _FakeQA:
    def __init__(self, sink):
        self.sink = sink

    def invoke(self, payload):
        self.sink.append(payload["user_input"])
        return "grounded answer"


@pytest.fixture
def qa(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(sta, "TriageAgent", _Boom)
    monkeypatch.setattr(sta, "build_llm", lambda *a, **k: object())
    monkeypatch.setattr(sta, "_build_qa_chain", lambda llm: _FakeQA(seen))
    return seen


@pytest.mark.parametrize("msg", [
    "What does this ticket say?", "Explain the IOC list", "is the classification right?",
    "can you investigate the source IP?", "give me an analysis of this", "triage summary please",
])
def test_ordinary_questions_go_to_grounded_qa(qa, msg):
    out = sta.soc_triage_chat_respond(msg, INCIDENT, llm_config=sta.OpenAILLMConfig(api_key="sk-x"),
                                      case_context={"available": True})
    assert out == "grounded answer"
    assert qa and msg in qa[0]


@pytest.mark.parametrize("msg", ["retriage", "re-triage this incident", "/retriage", "Please retriage again"])
def test_explicit_retriage_points_to_workflow_and_runs_nothing(qa, msg):
    sink: dict = {}
    out = sta.soc_triage_chat_respond(msg, INCIDENT, llm_config=sta.OpenAILLMConfig(api_key="sk-x"),
                                      result_sink=sink, case_context={"available": True})
    assert "Re-run Triage" in out
    assert "result" not in sink          # nothing to hand downstream
    assert not qa                        # no LLM call at all


def test_trigger_regex_no_longer_matches_ordinary_words():
    for word in ("ticket", "ioc", "classification", "analysis", "investigate", "triage"):
        assert not sta._TRIAGE_TRIGGER.search(f"tell me about the {word}")
    assert sta._TRIAGE_TRIGGER.search("retriage")
