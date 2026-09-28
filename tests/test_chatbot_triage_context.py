"""tests/test_chatbot_triage_context.py -- regression coverage for the
Triage-stage restoration work.

ChatbotService.ask_case() (backend/services/chatbot_service.py) forwards a
"parsed_context" into agents.triage.soc_triage_agent.soc_triage_chat_respond()
-- the same parameter agents.triage.soc_triage_agent.TriageAgent.triage()
documents (and the canonical workflow/engine.py::run_until_triage_approval()
path actually supplies) as Parsing's FLAT `processed_alert` compatibility
view, not the whole persisted parsing_result wrapper (which also carries
top-level `normalised_alert`/`parser_confidence`/`status`/... alongside
`processed_alert`). Before this fix, ask_case() passed the whole wrapper,
so the Ask Aegis chat-triggered ad hoc "retriage" branch
(soc_triage_agent.py::soc_triage_chat_respond's _TRIAGE_TRIGGER branch) fed
TriageAgent.triage() a differently-shaped parsed_alert_context than a real
workflow run ever sees.

This module only exercises the parsed_context plumbing (via a stub
responder), not soc_triage_chat_respond()/TriageAgent.triage() themselves
(covered by tests/test_triage_result_contract.py and
tests/test_triage_cache_hardening.py) -- no live OpenAI call is made here.
"""
from __future__ import annotations

import json

import pytest

from workflow import state_store as wss
from backend.services.chatbot_service import ChatbotService, ChatServiceError
from backend.services.sync_service import upsert_incidents


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "test_chatbot_triage_context.db")
    wss.db_init()
    yield


def _seed_case(case_id: str, *, parsing_result: dict | None = None) -> str:
    upsert_incidents([{"id": case_id, "title": "Suspicious privileged logon"}])
    run_id = wss.start_run(case_id)
    if parsing_result is not None:
        wss._guarded_update(case_id, run_id, {"parsing_result_json": json.dumps(parsing_result)})
    return run_id


def _stub_context(*args, **kwargs) -> dict:
    return {"available": True}


def _capturing_responder(captured: dict):
    def responder(message, incident, parsed, context) -> str:
        captured["message"] = message
        captured["incident"] = incident
        captured["parsed"] = parsed
        captured["context"] = context
        return "stubbed answer"
    return responder


def test_ask_case_passes_processed_alert_not_the_whole_parsing_wrapper(monkeypatch):
    processed_alert = {"source_ip": "10.0.0.5", "host": "WIN-01", "mitre_tactic": "Credential Access"}
    parsing_result = {
        "status": "completed",
        "parser_confidence": "Medium",
        "normalised_alert": {"schema_version": 1},
        "processed_alert": processed_alert,
    }
    run_id = _seed_case("INC-CHAT-1", parsing_result=parsing_result)
    assert run_id

    monkeypatch.setattr("backend.services.case_view_service.build_aegis_context", _stub_context)

    captured: dict = {}
    service = ChatbotService(responder=_capturing_responder(captured))
    result = service.ask_case("INC-CHAT-1", "please triage this")

    assert result["available"] is True
    # The exact processed_alert dict, not the wrapper it lives inside.
    assert captured["parsed"] == processed_alert
    assert "normalised_alert" not in captured["parsed"]
    assert "status" not in captured["parsed"]


def test_ask_case_parsed_context_is_none_when_parsing_has_not_run(monkeypatch):
    run_id = _seed_case("INC-CHAT-2", parsing_result=None)
    assert run_id

    monkeypatch.setattr("backend.services.case_view_service.build_aegis_context", _stub_context)

    captured: dict = {}
    service = ChatbotService(responder=_capturing_responder(captured))
    service.ask_case("INC-CHAT-2", "what do we know so far?")

    assert captured["parsed"] is None


def test_ask_case_raises_when_context_unavailable(monkeypatch):
    _seed_case("INC-CHAT-3", parsing_result={"processed_alert": {"host": "X"}})
    monkeypatch.setattr(
        "backend.services.case_view_service.build_aegis_context",
        lambda *a, **k: {"available": False},
    )

    captured: dict = {}
    service = ChatbotService(responder=_capturing_responder(captured))
    with pytest.raises(ChatServiceError):
        service.ask_case("INC-CHAT-3", "triage this")
    assert captured == {}
