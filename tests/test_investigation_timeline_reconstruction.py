"""tests/test_investigation_timeline_reconstruction.py -- tests for the
Investigation-stage attack chain and security event timeline reconstruction.
"""
from __future__ import annotations

import json
import pytest

from workflow import state_store as wss
import backend.services.case_view_service as cv


ALERT_ID = "INC-TEST-001"
RUN_ID = "run-test-1"


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    wss.db_init()
    yield


def test_timeline_never_includes_workflow_milestones_or_approvals():
    """Verify that internal workflow stage updates (e.g. 'Parsing completed',
    'Threat Intel completed') and analyst approvals are NEVER returned in
    build_timeline()."""
    state = {
        "incident_id": ALERT_ID,
        "run_id": RUN_ID,
        "parsing_status": "Completed",
        "threat_intel_status": "Completed",
        "threat_intel_updated_at": 1752492000,
        "investigation_status": "Completed",
        "investigation_updated_at": 1752493000,
        "reporting_status": "Completed",
        "reporting_updated_at": 1752494000,
    }
    incident = {
        "id": ALERT_ID,
        "title": "High Risk Alert: Test Incident",
        "firstAlertTime": "2025-07-14T11:21:34.000Z",
    }
    data_availability = {"alerts_fetch_succeeded": True}

    timeline = cv.build_timeline(state, incident, ALERT_ID, RUN_ID, data_availability)

    # Must NOT contain any workflow stage completion strings
    for item in timeline:
        event_str = str(item.get("event") or "").lower()
        desc_str = str(item.get("description") or "").lower()
        assert "parsing completed" not in event_str
        assert "threat intel completed" not in event_str
        assert "investigation completed" not in event_str
        assert "reporting completed" not in event_str
        assert "approved" not in event_str
        assert item.get("event_type") != "workflow"


def test_timeline_reconstructs_attack_chain_from_mitre_mappings():
    """Verify that structured MITRE mappings and investigation findings are
    reconstructed into an attack chain sequence with tactic, technique,
    phase, and evidence tokens."""
    mitre_mappings = [
        {
            "timeline_phase": "Initial suspicious execution on compromised host",
            "observed_evidence": "Host BETHANYCHUCHU executed vmtoolsd.exe as NT AUTHORITY\\SYSTEM with hash 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c.",
            "tactic": "Execution",
            "technique_name": "System Services: Service Execution",
            "technique_id": "T1569.002",
        },
        {
            "timeline_phase": "UAC weakening / privilege elevation preparation",
            "observed_evidence": "Command line cmd.exe reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f.",
            "tactic": "Privilege Escalation",
            "technique_name": "Abuse Elevation Control Mechanism: Bypass User Account Control",
            "technique_id": "T1548.002",
        },
        {
            "timeline_phase": "Outbound command-and-control over web protocols",
            "observed_evidence": "vmtoolsd.exe on BETHANYCHUCHU generated outbound HTTPS traffic to 4.145.79.81:443.",
            "tactic": "Command and Control",
            "technique_name": "Application Layer Protocol: Web Protocols",
            "technique_id": "T1071.001",
        },
    ]

    inv_result = {
        "incident_id": ALERT_ID,
        "severity": "High",
        "confidence": "Medium",
        "mitre_mappings": mitre_mappings,
        "incident_summary": "On 2025-07-14T11:21:34+00:00, NetWitness generated an alert for vmtoolsd.exe...",
    }

    state = {
        "incident_id": ALERT_ID,
        "run_id": RUN_ID,
        "investigation_status": "Approved",
        "investigation_result_json": json.dumps(inv_result),
    }
    incident = {
        "id": ALERT_ID,
        "title": "High Risk Alerts: NetWitness Endpoint for BETHANYCHUCHU",
        "firstAlertTime": "2025-07-14T11:21:34.000Z",
    }
    data_availability = {"alerts_fetch_succeeded": True}

    timeline = cv.build_timeline(state, incident, ALERT_ID, RUN_ID, data_availability)

    assert len(timeline) == 3
    
    # Step 1: Execution
    assert timeline[0]["phase"] == "Initial suspicious execution on compromised host"
    assert timeline[0]["tactic"] == "Execution"
    assert timeline[0]["technique_id"] == "T1569.002"
    assert "vmtoolsd.exe" in timeline[0]["evidence"]
    assert "8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c" in timeline[0]["evidence"]
    assert timeline[0]["event_type"] == "attack_chain"

    # Step 2: Privilege Escalation
    assert timeline[1]["phase"] == "UAC weakening / privilege elevation preparation"
    assert timeline[1]["tactic"] == "Privilege Escalation"
    assert timeline[1]["technique_id"] == "T1548.002"
    assert any("EnableLUA" in str(e) or "reg.exe" in str(e) for e in timeline[1]["evidence"])

    # Step 3: C2
    assert timeline[2]["phase"] == "Outbound command-and-control over web protocols"
    assert timeline[2]["tactic"] == "Command and Control"
    assert timeline[2]["technique_id"] == "T1071.001"
    assert any("4.145.79.81" in str(e) for e in timeline[2]["evidence"])


def test_timeline_reconstructs_from_summary_narrative_when_mitre_absent():
    """Verify that narrative chronology sentences are parsed into attack chain
    steps when mitre_mappings are not provided."""
    inv_result = {
        "incident_id": ALERT_ID,
        "severity": "Medium",
        "confidence": "Medium",
        "incident_summary": (
            "On 2025-07-15T09:38:52+00:00, NetWitness generated incident INC-52970 for host 192.168.10.200. "
            "Traffic from 192.168.10.200 to 8.8.8.8 over UDP/53 was observed. "
            "The host 192.168.10.200 connected to 4.145.79.81:443, identified as external Azure infrastructure."
        ),
    }

    state = {
        "incident_id": ALERT_ID,
        "run_id": RUN_ID,
        "investigation_status": "Approved",
        "investigation_result_json": json.dumps(inv_result),
    }
    incident = {
        "id": ALERT_ID,
        "title": "High Risk Alerts: ESA for 192.168.10.200",
        "firstAlertTime": "2025-07-15T09:38:52.000Z",
    }
    data_availability = {"alerts_fetch_succeeded": True}

    timeline = cv.build_timeline(state, incident, ALERT_ID, RUN_ID, data_availability)

    assert len(timeline) == 3
    assert timeline[0]["event_type"] == "attack_chain"
    assert any("192.168.10.200" in e for e in timeline[0]["evidence"])
    assert any("8.8.8.8" in e for e in timeline[1]["evidence"])
    assert any("4.145.79.81" in e for e in timeline[2]["evidence"])


def test_timeline_raw_alerts_fallback_when_investigation_not_run():
    """Verify that raw alert telemetry events are returned when investigation
    has not run yet."""
    state = {
        "incident_id": ALERT_ID,
        "run_id": RUN_ID,
        "parsing_status": "Completed",
    }
    incident = {
        "id": ALERT_ID,
        "title": "Suspicious PowerShell Execution",
        "firstAlertTime": "2025-07-14T10:00:00.000Z",
        "alerts": [
            {
                "id": "ALERT-1",
                "title": "Encoded PowerShell Detected",
                "created": "2025-07-14T10:00:00.000Z",
                "sourceIp": "192.168.1.50",
                "processName": "powershell.exe",
                "userName": "Alice",
            },
            {
                "id": "ALERT-2",
                "title": "Outbound Connection to Suspicious IP",
                "created": "2025-07-14T10:05:00.000Z",
                "sourceIp": "192.168.1.50",
                "destinationIp": "203.0.113.5",
            },
        ],
    }
    data_availability = {"alerts_fetch_succeeded": True}

    timeline = cv.build_timeline(state, incident, ALERT_ID, RUN_ID, data_availability)

    assert len(timeline) == 2
    assert timeline[0]["event"] == "Encoded PowerShell Detected"
    assert timeline[0]["event_type"] == "telemetry"
    assert "powershell.exe" in timeline[0]["evidence"]
    assert timeline[1]["event"] == "Outbound Connection to Suspicious IP"
    assert "203.0.113.5" in timeline[1]["evidence"]
