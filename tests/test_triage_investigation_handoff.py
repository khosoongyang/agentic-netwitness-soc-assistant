"""tests/test_triage_investigation_handoff.py -- Phase 2 of the canonical
Triage Result contract migration: the Triage -> Investigation handoff.

Covers workflow/engine.py::build_investigation_alert()/handoff_to_investigation()
and the exact Investigation-side consumers of the resulting alert JSON:
  - agents/investigation/ingest_pipeline.py::process_log_file() (ChromaDB
    metadata extraction: tactic/technique, and -- since this phase -- the
    forwarded Triage severity signal)
  - agents/investigation/main.py::select_playbook_automatically() (reads
    classification.alert_type / incident_details.mitre_att&ck.tactic
    directly off the raw queued alert JSON)
  - agents/investigation/main.py::generate_local_standalone_report() (reads
    alert["metadata"]["severity"] as Investigation's own pre-investigation
    severity input, then computes its OWN final severity independently)

No OpenAI calls are made anywhere in this file.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from workflow import engine as wf

REPO_ROOT = Path(__file__).resolve().parent.parent
INV_DIR = REPO_ROOT / "agents" / "investigation"

sys.path.insert(0, str(INV_DIR))
from agents.investigation import ingest_pipeline  # noqa: E402
from agents.investigation import main as inv_main  # noqa: E402


# =============================================================================
# Fixture payloads -- a realistic canonical Triage result (post-Phase-1
# contract) and a raw source incident.
# =============================================================================

def _risk_rating_kwargs() -> dict:
    return dict(
        likelihood_initiation="High",
        likelihood_occurrence="Medium",
        likelihood_adverse_impact="High",
        overall_risk="High",
        rationale="Repeated failed logons followed by a privileged success.",
    )


def _triage_result_kwargs(classification="HIGH", incident_category="Internal Hacking (attempted)",
                          mitre_tactic="Credential Access", mitre_technique="Brute Force",
                          metakey_values=None) -> dict:
    if metakey_values is None:
        metakey_values = {"ip.src": "10.0.0.5", "user.name": "jdoe", "host.name": "WIN-01"}
    return {
        "metakeys_payload": {
            "incident_id": "INC-1001", "incident_title": "Suspicious privileged logon",
            "timestamp": "2026-08-20T10:00:00.000000",
            "matched_metakeys": list(metakey_values.keys()),
            "metakey_values": metakey_values,
            "ioc_summary": "[NETWORK] 10.0.0.5 — brute-force pattern",
            "risk_level": classification.lower(), "classification": classification.lower(),
            "mitre_tactic": mitre_tactic, "mitre_technique": mitre_technique,
        },
        "ticket": {
            "unc": "#00042A", "incident_id": "INC-1001", "title": "Suspicious privileged logon",
            "incident_time": "2026-08-20 10:00:00 UTC", "created_at": "2026-08-20T10:00:05.123456",
            "classification": classification,
            "risk_rating": _risk_rating_kwargs(),
            "incident_category": incident_category,
            "mitre_tactic": mitre_tactic, "mitre_technique": mitre_technique,
            "initial_response_time": "<= 30 minutes",
            "summary": "Repeated failed logons from 10.0.0.5 preceded a successful "
                       "privileged logon for user jdoe.",
            "recommended_actions": ["Isolate the affected host",
                                    "Reset the targeted account credentials"],
            "matched_ioc_count": 3, "metakeys": list(metakey_values.keys()),
        },
        "trace": [], "used_parsed_context": False, "error": None,
    }


def _incident_kwargs(risk_score=87) -> dict:
    return {"id": "INC-1001", "title": "Suspicious privileged logon", "riskScore": risk_score}


# =============================================================================
# 1 & 2. classification -> classification.severity; incident_category ->
#        classification.alert_type
# =============================================================================

def test_classification_maps_to_classification_severity():
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs())
    assert alert["classification"]["severity"] == "HIGH"


def test_incident_category_maps_to_classification_alert_type():
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs())
    assert alert["classification"]["alert_type"] == "Internal Hacking (attempted)"


# =============================================================================
# 3 & 4. MITRE tactic/technique reach incident_details.mitre_att&ck, and
#        from there reach Investigation's ingest metadata (ChromaDB).
# =============================================================================

def test_mitre_tactic_and_technique_reach_incident_details():
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs())
    mitre = alert["incident_details"]["mitre_att&ck"]
    assert mitre["tactic"] == "Credential Access"
    assert mitre["technique"] == "Brute Force"


def test_mitre_fields_reach_investigation_ingest_metadata(tmp_path):
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs())
    alert_path = tmp_path / "seed_alert.json"
    alert_path.write_text(json.dumps(alert))

    ingested = ingest_pipeline.process_log_file(str(alert_path))
    assert ingested["metadata"]["tactic"] == "Credential Access"
    assert ingested["metadata"]["technique"] == "Brute Force"


# =============================================================================
# 5. Playbook selection still receives the expected alert_type/tactic
#    (select_playbook_automatically() reads these directly off the queued
#    raw JSON, independent of ingest_pipeline's metadata).
# =============================================================================

def test_playbook_selection_receives_expected_alert_type_and_tactic(tmp_path, monkeypatch):
    # select_playbook_automatically()'s PLAYBOOKS_FOLDER is a relative path
    # ("playbooks/"), resolved against the process cwd -- match its own
    # subsystem's working directory so the existence check behaves as it
    # does in production, independent of pytest's invocation directory.
    monkeypatch.chdir(INV_DIR)
    triage_result = _triage_result_kwargs(
        incident_category="Phishing (spearphishing attachment)",
        mitre_tactic="Initial Access", mitre_technique="Spearphishing Attachment",
    )
    alert = wf.build_investigation_alert(triage_result, _incident_kwargs())
    alert_path = tmp_path / "seed_alert.json"
    alert_path.write_text(json.dumps(alert))

    selected = inv_main.select_playbook_automatically(str(alert_path))
    assert selected.endswith("phishing.yaml")


def test_playbook_selection_defaults_to_endpoint_for_non_phishing(tmp_path, monkeypatch):
    monkeypatch.chdir(INV_DIR)
    triage_result = _triage_result_kwargs(
        incident_category="Internal Hacking (attempted)",
        mitre_tactic="Privilege Escalation", mitre_technique="Valid Accounts",
    )
    alert = wf.build_investigation_alert(triage_result, _incident_kwargs())
    alert_path = tmp_path / "seed_alert.json"
    alert_path.write_text(json.dumps(alert))

    selected = inv_main.select_playbook_automatically(str(alert_path))
    assert selected.endswith("privilegeEscalation.yaml")


# =============================================================================
# 6. metakey_values still produce the same network/endpoint indicators.
# =============================================================================

def test_metakey_values_produce_network_and_endpoint_indicators():
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs())
    assert alert["network_indicators"]["source"]["ip_address"] == "10.0.0.5"
    assert alert["endpoint_indicators"]["user"] == "jdoe"
    assert alert["endpoint_indicators"]["hostname"] == "WIN-01"


# =============================================================================
# 7, 8 & 9. risk_rating remains a dict under its own field; the
# source/raw risk score remains scalar under a separate field; neither can
# alternate between dict and numeric types depending on which is truthy.
# =============================================================================

def test_triage_risk_rating_is_a_dict_under_its_own_field():
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs())
    assert isinstance(alert["classification"]["triage_risk_rating"], dict)
    assert alert["classification"]["triage_risk_rating"] == _risk_rating_kwargs()


def test_source_risk_score_is_scalar_under_its_own_field():
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(risk_score=87))
    assert alert["classification"]["source_risk_score"] == 87
    assert isinstance(alert["classification"]["source_risk_score"], (int, float))


def test_risk_score_no_longer_conflated_regardless_of_which_side_is_present():
    # Old behaviour: `ticket.get("risk_rating") or incident.get("riskScore")`
    # meant the same "risk_score" key could be a dict OR a number depending
    # on which side happened to be truthy. Now each concept has its own key,
    # so the type of each is fixed no matter what the other side contains.
    alert_both = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(risk_score=42))
    assert isinstance(alert_both["classification"]["triage_risk_rating"], dict)
    assert isinstance(alert_both["classification"]["source_risk_score"], (int, float))

    # No source-system numeric score at all -- triage_risk_rating must still
    # be the dict, not silently replaced/absent because of the other field.
    alert_no_source_score = wf.build_investigation_alert(_triage_result_kwargs(), {"id": "INC-1001"})
    assert isinstance(alert_no_source_score["classification"]["triage_risk_rating"], dict)
    assert "source_risk_score" not in alert_no_source_score["classification"]


# =============================================================================
# 10. Investigation's final severity ownership is unchanged: it is computed
# from Investigation's own report.severity (main.py:783-800), not simply
# copied from the Triage signal -- Triage only supplies an *input* that
# feeds the standalone heuristic, never the final value directly.
# =============================================================================

def test_investigation_final_severity_is_computed_not_copied_verbatim(tmp_path):
    triage_result = _triage_result_kwargs(classification="CRITICAL")
    alert = wf.build_investigation_alert(triage_result, _incident_kwargs())
    # The raw handoff carries Triage's own upper-case value...
    assert alert["classification"]["severity"] == "CRITICAL"

    alert_path = tmp_path / "seed_alert.json"
    alert_path.write_text(json.dumps(alert))
    ingested = ingest_pipeline.process_log_file(str(alert_path))

    playbook_path = str(INV_DIR / "playbooks" / "privilegeEscalation.yaml")
    result = inv_main.generate_local_standalone_report(ingested, playbook_path, "Incident-TEST-SEV")
    # ...but Investigation's own FinalIncidentAnalysis.severity is a
    # normalized, title-cased, independently-typed value (Literal[...]),
    # not Triage's raw "CRITICAL" string passed through untouched.
    assert result["report"].severity == "Critical"


# =============================================================================
# 11. Standalone Investigation severity plumbing bug: alert["metadata"]
# ["severity"] previously never existed (ingest_pipeline.process_log_file()
# never set it), so generate_local_standalone_report() always fell through
# to its hardcoded "High" default regardless of the real Triage
# classification. Confirmed and fixed: a non-HIGH classification must now
# actually reach the standalone report's severity.
# =============================================================================

@pytest.mark.parametrize("classification,expected", [
    ("LOW", "Low"), ("MEDIUM", "Medium"), ("HIGH", "High"), ("CRITICAL", "Critical"),
])
def test_standalone_severity_no_longer_always_falls_through_to_high(tmp_path, classification, expected):
    triage_result = _triage_result_kwargs(classification=classification)
    alert = wf.build_investigation_alert(triage_result, _incident_kwargs())
    alert_path = tmp_path / "seed_alert.json"
    alert_path.write_text(json.dumps(alert))
    ingested = ingest_pipeline.process_log_file(str(alert_path))

    assert ingested["metadata"]["severity"] == classification

    playbook_path = str(INV_DIR / "playbooks" / "privilegeEscalation.yaml")
    result = inv_main.generate_local_standalone_report(ingested, playbook_path, f"Incident-TEST-{classification}")
    assert result["report"].severity == expected


def test_standalone_severity_still_defaults_to_high_when_no_triage_signal(tmp_path):
    # A raw, non-Triage-sourced log with no "classification" key at all --
    # the pre-existing "High" default must still apply unchanged.
    raw_log = {"incident_id": "INC-RAW", "some_field": "value"}
    alert_path = tmp_path / "raw_log.json"
    alert_path.write_text(json.dumps(raw_log))
    ingested = ingest_pipeline.process_log_file(str(alert_path))

    assert "severity" not in ingested["metadata"]

    playbook_path = str(INV_DIR / "playbooks" / "privilegeEscalation.yaml")
    result = inv_main.generate_local_standalone_report(ingested, playbook_path, "Incident-TEST-RAW")
    assert result["report"].severity == "High"


# =============================================================================
# 12. recommended_actions behaviour is unchanged: Triage's ticket.
# recommended_actions do NOT enter build_investigation_alert()'s output --
# Investigation continues to produce its own recommendations/containment.
# =============================================================================

def test_recommended_actions_do_not_enter_the_investigation_handoff():
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs())
    flat = json.dumps(alert)
    assert "recommended_actions" not in flat
    assert "Isolate the affected host" not in flat
    assert "Reset the targeted account credentials" not in flat


# =============================================================================
# 13. Malformed/missing optional Triage fields degrade safely.
# =============================================================================

def test_missing_optional_fields_degrade_safely():
    triage_result = _triage_result_kwargs()
    # Simulate a ticket that never got a risk_rating populated somehow.
    triage_result["ticket"]["risk_rating"] = {}
    alert = wf.build_investigation_alert(triage_result, {"id": "INC-1001"})
    # prune_empty() strips the now-empty dict entirely -- no crash, no
    # half-populated garbage key.
    assert "triage_risk_rating" not in alert["classification"]
    assert "source_risk_score" not in alert["classification"]
    assert alert["classification"]["severity"] == "HIGH"


def test_missing_incident_category_degrades_safely():
    triage_result = _triage_result_kwargs()
    triage_result["ticket"]["incident_category"] = ""
    alert = wf.build_investigation_alert(triage_result, _incident_kwargs())
    assert "alert_type" not in alert["classification"]


def test_ingest_pipeline_handles_missing_classification_block(tmp_path):
    alert = {"incident_id": "INC-X", "incident_details": {}}
    alert_path = tmp_path / "no_classification.json"
    alert_path.write_text(json.dumps(alert))
    ingested = ingest_pipeline.process_log_file(str(alert_path))
    assert "severity" not in ingested["metadata"]
    assert ingested["metadata"]["tactic"] == "Unknown"
    assert ingested["metadata"]["technique"] == "Unknown"


# =============================================================================
# 14. Incident identity is preserved end to end.
# =============================================================================

def test_incident_identity_is_preserved(tmp_path):
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs())
    assert alert["incident_id"] == "INC-1001"

    alert_path = tmp_path / "seed_alert.json"
    alert_path.write_text(json.dumps(alert))
    ingested = ingest_pipeline.process_log_file(str(alert_path))
    assert ingested["id"] == "INC-1001"
    assert ingested["metadata"]["incident_id"] == "INC-1001"


# =============================================================================
# handoff_to_investigation(): file-queue write, isolated from the real
# agents/investigation/triaged_alerts/ directory.
# =============================================================================

def test_handoff_to_investigation_writes_expected_alert_shape(tmp_path, monkeypatch):
    monkeypatch.setattr(wf, "INV_DIR", tmp_path)
    triage_result = _triage_result_kwargs()
    path = wf.handoff_to_investigation(triage_result, _incident_kwargs())

    assert path.exists()
    written = json.loads(path.read_text())
    assert written["classification"]["severity"] == "HIGH"
    assert written["classification"]["alert_type"] == "Internal Hacking (attempted)"
    assert isinstance(written["classification"]["triage_risk_rating"], dict)
    assert isinstance(written["classification"]["source_risk_score"], (int, float))
    assert "risk_score" not in written["classification"]
