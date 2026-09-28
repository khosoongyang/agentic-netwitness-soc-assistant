"""tests/test_triage_stage_workflow_view.py -- Triage-stage restoration
coverage for the read-only API surface the case-workspace frontend actually
renders the Triage stage from.

GET /api/cases/<id>/workflow (backend/routes/cases.py -> case_service.
get_case_workflow -> case_service.build_workflow_stages) is the frontend's
sole source for a stage's persisted result (frontend/js/pages/workspace.js's
stage.result). This module locks in that build_workflow_stages() forwards
the FULL canonical TriageAgentSuccessOutput shape for the "triage" stage --
the nested ticket.risk_rating dict, the per-category IOC trace, MITRE
fields, recommended_actions -- unflattened and unrenamed, since
backend/services/case_service.py::_safe_stage_result only redacts secrets /
truncates long strings (case_view_service._sanitize_for_display) and never
reshapes structure. This is a regression guard for the frontend rendering
fix in workspace.js's renderTriageStage(), which reads exactly these nested
fields.
"""
from __future__ import annotations

import json

from backend.services.case_service import build_workflow_stages


def _full_triage_result() -> dict:
    return {
        "metakeys_payload": {
            "incident_id": "INC-1", "incident_title": "Suspicious privileged logon",
            "timestamp": "2026-08-20T10:00:00.000000",
            "matched_metakeys": ["ip.dst", "port.dst"], "metakey_values": {},
            "ioc_summary": "[CONFIDENTIALITY] Unknown traffic — HTTP to internal host",
            "risk_level": "high", "classification": "high",
            "mitre_tactic": "Execution", "mitre_technique": "T1059 Command and Scripting Interpreter",
        },
        "ticket": {
            "unc": "#00059A", "incident_id": "INC-1", "title": "Suspicious privileged logon",
            "incident_time": "2025-07-21 06:20:39 UTC", "created_at": "2026-07-26T16:56:30.739456",
            "classification": "HIGH",
            "risk_rating": {
                "likelihood_initiation": "High", "likelihood_occurrence": "Medium",
                "likelihood_adverse_impact": "High", "overall_risk": "High",
                "rationale": "Suspicious execution with a privileged user context.",
            },
            "incident_category": "Compromised asset (non-critical)",
            "mitre_tactic": "Execution", "mitre_technique": "T1059 Command and Scripting Interpreter",
            "initial_response_time": "30 to 60 minutes",
            "summary": "Suspicious execution of a masqueraded binary.",
            "recommended_actions": ["Isolate the affected host.",
                                    "Validate the legitimacy of the binary."],
            "matched_ioc_count": 6, "metakeys": ["ip.dst", "port.dst", "process.name"],
        },
        "trace": [
            {"step": "IOC Checklist", "status": "ok", "total_ioc_count": 6,
             "ioc_summary": "[CONFIDENTIALITY] Unknown traffic — HTTP to internal host",
             "matched_metakeys": ["ip.dst", "port.dst"],
             "per_category": {
                 "confidentiality": {
                     "matched_ioc_names": ["Unknown traffic originating from/terminating on the device"],
                     "reasoning": "Unusual HTTP traffic to an internal host on port 8888."},
                 "integrity": {
                     "matched_ioc_names": ["Odd device/platform behaviour", "Unknown binaries installed"],
                     "reasoning": "splunkd.exe running from C:\\Users\\Public with an atypical command line."},
             }},
            {"step": "Risk Rating", "status": "ok",
             "data": {"likelihood_initiation": "High", "overall_risk": "High"}},
            {"step": "SOC Classification", "status": "ok",
             "data": {"classification": "High"}},
        ],
        "used_parsed_context": True, "error": None,
        "ai_summary": "Suspicious splunkd.exe execution with HTTP callback on an internal host.",
        "ai_thinking": "The IOC checklist matched 6 indicator(s)...",
        "ai_summary_model": "gpt-5.4-mini",
        "ai_summary_generated_at": "2026-07-26T16:56:31.000000",
    }


def _state_with_triage(triage_result: dict, *, status: str = "Approved") -> dict:
    return {
        "triage_status": status,
        "triage_result_json": json.dumps(triage_result),
        "parsing_status": "Complete", "parsing_result_json": None,
        "threat_intel_status": None, "threat_intel_result_json": None,
        "investigation_status": None, "investigation_result_json": None,
        "reporting_status": None, "reporting_result_json": None,
        "workflow_updated_at": "2026-07-26T16:56:31.000000",
        "threat_intel_updated_at": None, "investigation_updated_at": None,
        "reporting_updated_at": None,
        "investigation_attempt": None, "threat_intel_attempt": None, "reporting_attempt": None,
    }


def _triage_stage(triage_result: dict, *, status: str = "Approved") -> dict:
    stages = build_workflow_stages(_state_with_triage(triage_result, status=status))
    triage = next(stage for stage in stages if stage["key"] == "triage")
    return triage


def test_triage_stage_is_marked_completed_when_approved():
    stage = _triage_stage(_full_triage_result())
    assert stage["completed"] is True
    assert stage["state"] == "completed"


def test_triage_stage_result_exposes_full_ticket_with_nested_risk_rating():
    stage = _triage_stage(_full_triage_result())
    ticket = stage["result"]["ticket"]
    assert ticket["classification"] == "HIGH"
    assert ticket["incident_category"] == "Compromised asset (non-critical)"
    assert ticket["mitre_tactic"] == "Execution"
    assert ticket["mitre_technique"] == "T1059 Command and Scripting Interpreter"
    assert ticket["initial_response_time"] == "30 to 60 minutes"
    assert ticket["matched_ioc_count"] == 6
    # risk_rating stays a nested dict -- not flattened, renamed, or stringified.
    assert isinstance(ticket["risk_rating"], dict)
    assert ticket["risk_rating"]["likelihood_initiation"] == "High"
    assert ticket["risk_rating"]["overall_risk"] == "High"
    assert ticket["recommended_actions"] == [
        "Isolate the affected host.", "Validate the legitimacy of the binary."]
    assert ticket["metakeys"] == ["ip.dst", "port.dst", "process.name"]


def test_triage_stage_result_exposes_ioc_checklist_per_category_trace():
    stage = _triage_stage(_full_triage_result())
    trace = stage["result"]["trace"]
    ioc_step = next(step for step in trace if step["step"] == "IOC Checklist")
    assert ioc_step["total_ioc_count"] == 6
    per_category = ioc_step["per_category"]
    assert "confidentiality" in per_category
    assert "integrity" in per_category
    assert per_category["confidentiality"]["matched_ioc_names"] == [
        "Unknown traffic originating from/terminating on the device"]
    assert per_category["integrity"]["matched_ioc_names"] == [
        "Odd device/platform behaviour", "Unknown binaries installed"]
    assert "atypical command line" in per_category["integrity"]["reasoning"]


def test_triage_stage_result_exposes_ai_summary_fields():
    stage = _triage_stage(_full_triage_result())
    result = stage["result"]
    assert result["ai_summary"].startswith("Suspicious splunkd.exe")
    assert "ai_thinking" in result
    assert result["ai_summary_model"] == "gpt-5.4-mini"


def test_triage_stage_result_is_none_before_any_run():
    stage = _triage_stage({}, status="")
    assert stage["result"] is None
    assert stage["state"] == "not_started"


def test_triage_stage_result_survives_for_rejected_status():
    # A rejected run's ticket must still be visible to the analyst -- it was
    # generated, just not approved.
    stage = _triage_stage(_full_triage_result(), status="Rejected")
    assert stage["result"]["ticket"]["classification"] == "HIGH"
