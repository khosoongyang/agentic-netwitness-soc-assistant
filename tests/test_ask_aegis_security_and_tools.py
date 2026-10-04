"""tests/test_ask_aegis_security_and_tools.py -- Tests for Ask Aegis security, scope, epistemic reasoning, and case tools."""

from __future__ import annotations

import json
import pytest

from workflow import state_store as wss
from backend.services.sync_service import upsert_incidents
from backend.services import chatbot_tools
from agents.triage.soc_triage_agent import (
    _TRIAGE_TRIGGER,
    ASK_AEGIS_SYSTEM_PROMPT,
    _is_asking_about_other_cases,
    _format_scope_refusal,
    _strip_unsolicited_case_report,
    soc_triage_chat_respond,
)


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
    assert "SCOPE LIMITATION TO CURRENT ACTIVE CASE" in ASK_AEGIS_SYSTEM_PROMPT
    assert "DO NOT OUTPUT CURRENT CASE REPORT" in ASK_AEGIS_SYSTEM_PROMPT
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


def test_asking_about_other_cases_detection():
    """Verify that queries about other cases or incidents are properly flagged."""
    curr_case = "INC-TEST-100"

    # Queries asking about other cases / incidents
    other_case_queries = [
        "Tell me about case INC-102",
        "What about case INC-999?",
        "Can you check other cases?",
        "Tell me about cases beyond the current one",
        "What other incidents are in the queue?",
        "Show me previous cases",
        "Can you compare this case to other cases?",
        "Are there any other incidents in the system?",
        "Tell me about another incident",
        "What about case 45?",
        "What other cases do we have?",
    ]
    for q in other_case_queries:
        assert _is_asking_about_other_cases(q, curr_case), f"Query '{q}' should be identified as asking about other cases"

    # Queries focused strictly on the current case
    current_case_queries = [
        "Summarise the investigation on this case.",
        "Explain the key findings for this case.",
        "What requires analyst attention on this case?",
        f"Tell me about case {curr_case}",
        f"What is the severity of {curr_case}?",
        "What iocs were found during analysis?",
        "Why did the triage agent classify this as high severity?",
        "What was the classification rationale?",
        "Can you explain the investigation stage?",
    ]
    for q in current_case_queries:
        assert not _is_asking_about_other_cases(q, curr_case), f"Query '{q}' should NOT be flagged as asking about other cases"


def test_chat_respond_refuses_queries_beyond_current_case_without_report():
    """Verify that soc_triage_chat_respond politely informs the user of scope limitation
    and does NOT output the current case's report or findings when asked about other cases."""
    case_id = "INC-TEST-400"
    case_context = {
        "incident_id": case_id,
        "run_id": "run-400",
        "available": True,
        "case_summary": {
            "netwitness_severity": {"value": "Critical"},
            "triage_classification": {"value": "HIGH"},
        },
        "key_findings": [
            {"title": "Ransomware Execution", "desc": "WannaCry binary detected in temp dir"}
        ],
        "confirmed_facts": {
            "triage": {"label": "done", "ticket_id": "TIC-400"},
            "reporting": {"label": "done", "executive_summary": "Full confidential breach report"},
        },
    }

    # Ask about another case
    response = soc_triage_chat_respond(
        user_msg="Can you tell me about case INC-999 and show me its report?",
        case_context=case_context,
    )

    # Must politely state that scope is limited to the current case
    assert "scope is strictly limited to only the currently worked on case" in response
    assert case_id in response

    # MUST NOT output the current case's report, key findings, or confidential facts
    assert "Full confidential breach report" not in response
    assert "Ransomware Execution" not in response
    assert "WannaCry" not in response
    assert "TIC-400" not in response
    assert "Critical" not in response


def test_strip_unsolicited_case_report():
    """Verify that if an LLM response acknowledges scope refusal but appends an unsolicited
    case report, the report section is stripped."""
    llm_output_with_report = (
        "I am Aegis, an incident response assistant. My scope is strictly limited to only the "
        "currently worked on case (INC-TEST-100). I do not have access to other cases.\n\n"
        "Here is the report for the current case:\n"
        "### Executive Summary\n"
        "The incident involves brute force activity on host WIN-01 with critical severity."
    )
    cleaned = _strip_unsolicited_case_report(llm_output_with_report)
    assert "scope is strictly limited" in cleaned
    assert "Executive Summary" not in cleaned
    assert "brute force activity" not in cleaned
    assert "Please let me know if you have questions regarding the current case." in cleaned
