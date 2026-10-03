"""tests/test_ask_aegis_security_and_tools.py -- Tests for Ask Aegis security, scope, epistemic reasoning, and case tools."""

from __future__ import annotations

import json
import pytest

from workflow import state_store as wss
from backend.services.sync_service import upsert_incidents
from backend.services import chatbot_tools
from agents.triage.soc_triage_agent import _TRIAGE_TRIGGER, ASK_AEGIS_SYSTEM_PROMPT


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "test_aegis_sec.db")
    wss.db_init()
    yield


def test_triage_trigger_does_not_intercept_informational_questions():
    """Verify that asking questions about triage/classification does NOT trigger ad-hoc retriage."""
    informational_questions = [
        "How did the triage agent come to its conclusion?",
        "Why did the triage agent classify this as high severity?",
        "How did the triage agent know an external IP address should be classified as known-bad?",
        "What was the classification rationale?",
        "Can you explain the triage findings?",
        "What iocs were found during analysis?",
        "How does the investigation stage work?",
    ]
    for q in informational_questions:
        assert not _TRIAGE_TRIGGER.match(q.strip()), f"Query '{q}' should NOT match _TRIAGE_TRIGGER"


def test_triage_trigger_matches_explicit_retriage_commands():
    """Verify that only explicit retriage commands trigger the ad-hoc retriage branch."""
    explicit_commands = [
        "retriage",
        "re-triage",
        "force triage",
        "run triage again",
        "fresh triage",
        "please retriage",
    ]
    for cmd in explicit_commands:
        assert _TRIAGE_TRIGGER.match(cmd.strip()), f"Command '{cmd}' should match _TRIAGE_TRIGGER"


def test_system_prompt_contains_security_scope_and_epistemic_grounding():
    """Verify that the system prompt strictly defines scope, anti-injection, and agent roles."""
    assert "STRICT SCOPE ENFORCEMENT" in ASK_AEGIS_SYSTEM_PROMPT
    assert "MANDATORY REFUSAL OF OFF-TOPIC QUERIES" in ASK_AEGIS_SYSTEM_PROMPT
    assert "PROMPT INJECTION RESISTANCE" in ASK_AEGIS_SYSTEM_PROMPT
    assert "Parsing Agent" in ASK_AEGIS_SYSTEM_PROMPT
    assert "Triage Agent" in ASK_AEGIS_SYSTEM_PROMPT
    assert "Threat Intelligence Agent" in ASK_AEGIS_SYSTEM_PROMPT
    assert "Investigation Agent" in ASK_AEGIS_SYSTEM_PROMPT
    assert "Reporting Agent" in ASK_AEGIS_SYSTEM_PROMPT
    assert "does NOT query live external threat intelligence" in ASK_AEGIS_SYSTEM_PROMPT


def test_chatbot_tools_raw_incident_retrieval(monkeypatch):
    case_id = "INC-TEST-100"
    raw_payload = {"id": case_id, "src_ip": "192.168.1.50", "alert_type": "Brute Force"}
    
    # Mock _get_case_row
    monkeypatch.setattr(
        "backend.services.chatbot_tools._get_case_row",
        lambda cid: {"id": cid, "raw_json": json.dumps(raw_payload), "title": "Brute Force Attack"}
    )
    
    res = chatbot_tools.get_raw_incident_data(case_id)
    assert res["case_id"] == case_id
    assert res["raw_incident"]["src_ip"] == "192.168.1.50"
    assert res["title"] == "Brute Force Attack"


def test_chatbot_tools_stage_details():
    case_id = "INC-TEST-200"
    upsert_incidents([{"id": case_id, "title": "Suspicious PowerShell"}])
    run_id = wss.start_run(case_id)
    
    triage_output = {
        "ticket": {"classification": "HIGH", "summary": "PowerShell encoded payload", "risk_rating": {"rationale": "High risk detected"}},
        "trace": [{"step": "IOC Checklist", "status": "ok"}],
    }
    wss._guarded_update(case_id, run_id, {
        "triage_status": "Complete",
        "triage_result_json": json.dumps(triage_output),
    })
    
    res = chatbot_tools.get_stage_details(case_id, "triage")
    assert res["case_id"] == case_id
    assert res["stage"] == "triage"
    assert res["status"] == "Complete"
    assert res["stage_result"]["ticket"]["classification"] == "HIGH"
    assert res["stage_result"]["ticket"]["risk_rating"]["rationale"] == "High risk detected"


def test_chatbot_tools_threat_intel_iocs():
    case_id = "INC-TEST-300"
    upsert_incidents([{"id": case_id, "title": "C2 Beaconing"}])
    run_id = wss.start_run(case_id)
    
    ti_output = {
        "enrichment_risk_level": "High",
        "enrichment_risk_score": 88,
        "enrichment_risk_reasons": ["Known Cobalt Strike C2 IP"],
        "threat_intelligence": {"iocs": {"ip": ["198.51.100.2"]}},
    }
    wss._guarded_update(case_id, run_id, {
        "threat_intel_status": "Complete",
        "threat_intel_result_json": json.dumps(ti_output),
    })
    
    res = chatbot_tools.get_threat_intel_iocs(case_id)
    assert res["case_id"] == case_id
    assert res["enrichment_risk_score"] == 88
    assert "Known Cobalt Strike C2 IP" in res["enrichment_risk_reasons"]
