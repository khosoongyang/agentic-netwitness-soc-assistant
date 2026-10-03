"""tests/test_multi_incident_entity_graph.py -- test coverage for multi-incident
entity graph construction, stage outputs ingestion (triage, threat intel,
investigation, ioc correlation), and color coding.
"""
from __future__ import annotations

import pytest

from agents.investigation.tools.incident_map import build_incident_map, to_dot, map_caption, PRIMARY_INCIDENT_COLOR
from backend.services.case_view_service import build_entity_graph


def test_build_incident_map_basic():
    incident = {
        "id": "INC-100",
        "title": "High Risk Alerts: NetWitness Endpoint for HOST-ALPHA",
        "alertMeta": {
            "SourceIp": ["10.0.0.5"],
            "DestinationIp": ["198.51.100.10"],
        },
        "alerts": [],
    }
    imap = build_incident_map(incident)
    assert imap["incident_id"] == "INC-100"
    assert imap["primary_incident_color"] == PRIMARY_INCIDENT_COLOR
    
    node_ids = {n["id"] for n in imap["nodes"]}
    assert "incident:INC-100" in node_ids
    assert "host:HOST-ALPHA" in node_ids
    assert "ip:10.0.0.5" in node_ids
    assert "ip:198.51.100.10" in node_ids


def test_build_incident_map_with_all_stages():
    incident = {
        "id": "INC-200",
        "title": "Suspicious PowerShell Execution for SRV-FINANCE",
        "alertMeta": {
            "SourceIp": ["10.0.1.20"],
        }
    }
    triage_result = {
        "ticket": {
            "classification": "high",
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059.001",
        },
        "metakeys_payload": {
            "metakey_values": {
                "user.dst": ["admin_user"],
                "filename": ["payload.exe"],
                "checksum": ["d41d8cd98f00b204e9800998ecf8427e"],
            }
        }
    }
    threat_intel_result = {
        "threat_intelligence": {
            "virustotal": {
                "ip_results": [
                    {"indicator": "198.51.100.99", "status": "completed", "malicious": 14}
                ],
                "file_hash": {
                    "indicator": "d41d8cd98f00b204e9800998ecf8427e", "status": "completed", "malicious": 42
                }
            },
            "abuseipdb": {
                "ip_results": [
                    {"indicator": "198.51.100.99", "status": "completed", "abuse_confidence_score": 100, "total_reports": 25}
                ]
            }
        }
    }
    investigation_result = {
        "incident_summary": "Observed powershell.exe spawning cmd.exe and executing reg.exe ADD HKLM\\Software\\Policies\\Test",
        "execution_trace": [
            {
                "step_id": "step_3",
                "findings": "Suspicious process execution: powershell.exe spawned cmd.exe and vmtoolsd.exe."
            }
        ],
        "mitre_mappings": [
            {
                "tactic": "Execution",
                "technique_name": "PowerShell",
                "technique_id": "T1059.001",
                "timeline_phase": "Execution"
            }
        ]
    }
    ioc_correlation_result = {
        "results": [
            {
                "value": "198.51.100.99",
                "type": "ip",
                "related": [
                    {"id": "INC-CORR-300", "title": "C2 Traffic on Host B", "severity": "HIGH", "status": "New"}
                ]
            }
        ]
    }

    imap = build_incident_map(
        incident=incident,
        triage_result=triage_result,
        threat_intel_result=threat_intel_result,
        investigation_result=investigation_result,
        ioc_correlation_result=ioc_correlation_result,
    )

    node_dict = {n["id"]: n for n in imap["nodes"]}
    assert "incident:INC-200" in node_dict
    assert "incident:INC-CORR-300" in node_dict
    assert "user:admin_user" in node_dict
    assert "process:powershell.exe" in node_dict
    assert "process:cmd.exe" in node_dict
    assert "ip:198.51.100.99" in node_dict

    # Check threat disposition
    vt_ip_node = node_dict["ip:198.51.100.99"]
    assert vt_ip_node["disposition"] == "malicious"
    assert vt_ip_node["props"]["abuse_score"] == 100
    assert vt_ip_node["props"]["is_shared_pivot"] is True

    # Check hash disposition
    hash_node = node_dict["hash:d41d8cd98f00b204e9800998ecf8427e"]
    assert hash_node["disposition"] == "malicious"

    # Check correlated incidents
    assert len(imap["correlated_incidents"]) == 1
    assert imap["correlated_incidents"][0]["id"] == "INC-CORR-300"

    # Check edge between powershell and cmd
    spawn_edge = next((e for e in imap["edges"] if e["src"] == "process:powershell.exe" and e["dst"] == "process:cmd.exe"), None)
    assert spawn_edge is not None
    assert spawn_edge["relation"] == "spawned"

    # Check cross-incident edge
    corr_edge = next((e for e in imap["edges"] if e["dst"] == "incident:INC-CORR-300"), None)
    assert corr_edge is not None
    assert corr_edge["is_cross_incident"] is True


def test_build_entity_graph_service():
    incident = {"id": "INC-999", "title": "Test Incident for HOST-1"}
    data_avail = {"alerts_complete": True}
    res = build_entity_graph(incident, data_avail)
    assert "nodes" in res
    assert "edges" in res
    assert "stats" in res
    assert "primary_incident_color" in res
    assert "correlated_incidents" in res


def test_to_dot_and_map_caption():
    incident = {"id": "INC-123", "title": "Alert for HOST-Z", "alertMeta": {"SourceIp": ["10.1.1.1"]}}
    imap = build_incident_map(incident)
    dot = to_dot(imap)
    assert "digraph incident {" in dot
    assert "incident:INC-123" in dot
    caption = map_caption(imap)
    assert "relationships" in caption
