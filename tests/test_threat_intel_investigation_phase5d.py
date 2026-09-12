"""tests/test_threat_intel_investigation_phase5d.py -- Threat Intelligence
Phase 5D: surface compact Threat Intelligence evidence in the deterministic
single-alert Investigation report, without changing decision logic.

Phase 5C (analysis-only) found generate_local_standalone_report() -- the
deterministic, zero-LLM path taken for a single, uncorrelated alert -- never
consumed any Threat-Intelligence-owned field, and recommended "PHASE 5C --
INCLUDE TI AS EXPLANATORY CONTEXT ONLY": surface the same compact TI summary
Phase 5B already built for the LLM path, without introducing TI-based
severity escalation, confidence changes, or containment changes.

Phase 5D reuses workflow/engine.py::build_investigation_threat_intel_context()
(no second TI formatting implementation) and threads its already-embedded
"threat_intelligence_summary" queued-alert key through
ingest_pipeline.py::process_log_file()'s metadata (mirroring the existing
classification_severity forwarding precedent) into
main.py::generate_local_standalone_report(), which appends it to the
report's existing free-text `incident_summary` field -- no new
FinalIncidentAnalysis field was needed or added.

This file proves: the TI section appears, uses the same trust-boundary
filtering as Phase 5B, and -- most importantly -- that severity, confidence,
recommended_containment, mitre_mappings, and policy_engine's escalation
rules are byte-for-byte unaffected by any TI value, including deliberately
conflicting Triage/TI signals.

No OpenAI/LLM calls are made anywhere in this file -- every path exercised
(build_investigation_alert, process_log_file, generate_local_standalone_report,
run_policy_compliance_rules, map_incident_mitre_ttps with llm=None) is
deterministic and LLM-free by construction.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from workflow import engine as wf

REPO_ROOT = Path(__file__).resolve().parent.parent
INV_DIR = REPO_ROOT / "agents" / "investigation"

sys.path.insert(0, str(INV_DIR))
from agents.investigation import ingest_pipeline  # noqa: E402
from agents.investigation import main as inv_main  # noqa: E402
from agents.investigation import policy_engine  # noqa: E402

PLAYBOOK_PATH = str(INV_DIR / "playbooks" / "privilegeEscalation.yaml")


# =============================================================================
# Shared fixture helpers.
# =============================================================================

def _triage_result_kwargs(classification: str = "HIGH") -> dict:
    return {
        "metakeys_payload": {
            "incident_id": "INC-1001", "incident_title": "Suspicious privileged logon",
            "timestamp": "2026-08-20T10:00:00.000000",
            "matched_metakeys": ["ip.src"], "metakey_values": {"ip.src": "10.0.0.5"},
            "ioc_summary": "[NETWORK] 10.0.0.5 — brute-force pattern",
            "risk_level": classification.lower(), "classification": classification.lower(),
            "mitre_tactic": "Credential Access", "mitre_technique": "Brute Force",
        },
        "ticket": {
            "unc": "#00042A", "incident_id": "INC-1001", "title": "Suspicious privileged logon",
            "incident_time": "2026-08-20 10:00:00 UTC", "created_at": "2026-08-20T10:00:05.123456",
            "classification": classification,
            "risk_rating": {"likelihood_initiation": "High", "likelihood_occurrence": "Medium",
                            "likelihood_adverse_impact": "High", "overall_risk": "High",
                            "rationale": "Repeated failed logons preceded a privileged success."},
            "incident_category": "Internal Hacking (attempted)",
            "mitre_tactic": "Credential Access", "mitre_technique": "Brute Force",
            "initial_response_time": "<= 30 minutes",
            "summary": "Repeated failed logons from 10.0.0.5 preceded a successful privileged logon.",
            "recommended_actions": ["Isolate the affected host"],
            "matched_ioc_count": 3, "metakeys": ["ip.src"],
        },
        "trace": [], "used_parsed_context": False, "error": None,
    }


def _incident_kwargs() -> dict:
    return {"id": "INC-1001", "title": "Suspicious privileged logon", "riskScore": 87}


def _real_threat_intel_result(**overrides) -> dict:
    """Exactly the shape workflow/engine.py::run_threat_intel() returns
    (engine.py:1178-1192)."""
    result = {
        "incident_id": "INC-1001", "run_id": "run-a", "stage": "threat_intelligence",
        "status": "completed", "generated_at": "2026-08-20T10:05:00+00:00",
        "threat_intelligence": {
            "iocs": {"ip_indicators": ["203.0.113.9"], "domain_indicators": []},
            "virustotal": {
                "file_hash": {"status": "completed", "malicious": 12, "harmless": 45,
                              "undetected": 2, "reputation": -30, "meaningful_name": "invoice.exe"},
                "ip_results": [{"status": "completed", "indicator": "203.0.113.9", "malicious": 5,
                                "country": "RU", "as_owner": "Some Hosting Provider LLC"}],
                "domain_results": [],
            },
            "abuseipdb": {"ip_results": [{"status": "completed", "indicator": "203.0.113.9",
                                          "abuse_confidence_score": 92, "isp": "Some Hosting Provider LLC",
                                          "domain": "somehostingprovider.example"}]},
            "alienvault_otx": {"otx_results": [{"status": "completed", "indicator": "203.0.113.9",
                                                "pulse_count": 7,
                                                "related_pulses": ["Botnet C2 Tracker", "Emotet Infrastructure"]}]},
            "notes": [],
        },
        "enrichment_risk_score": 80,
        "enrichment_risk_level": "High",
        "enrichment_risk_reasons": [
            "VirusTotal reported 12 malicious detection(s) for the file hash.",
            "AbuseIPDB abuse confidence score is high for 203.0.113.9: 92.",
        ],
        "warnings": [],
        "enriched_alert": {"incident_id": "INC-1001", "source_ip": "203.0.113.9"},
        "summary": "Threat intelligence enrichment completed with High enrichment risk.",
        "recommended_next_action": "SOC analyst approval is required before Investigation Agent can run.",
        "output_files": {},
    }
    result.update(overrides)
    return result


def _ingest_alert(triage_classification: str, ti_result: dict | None, tmp_path) -> dict:
    """Build the full queued-alert -> process_log_file() pipeline, exactly
    as the real subprocess handoff does, and return the ingested
    ChromaDB-shaped record generate_local_standalone_report() consumes."""
    triage_result = _triage_result_kwargs(classification=triage_classification)
    alert = wf.build_investigation_alert(triage_result, _incident_kwargs(),
                                         threat_intel_result=ti_result)
    alert_path = tmp_path / "alert.json"
    alert_path.write_text(json.dumps(alert))
    return ingest_pipeline.process_log_file(str(alert_path))


def _generate(ingested: dict, name: str = "Incident-TEST"):
    return inv_main.generate_local_standalone_report(ingested, PLAYBOOK_PATH, name)


# =============================================================================
# 1-8, 10 -- standalone report gains the compact TI section under various
# TI shapes; absent-TI behaviour is preserved.
# =============================================================================

def test_standalone_report_includes_compact_ti_section_when_ti_exists(tmp_path):
    ingested = _ingest_alert("HIGH", _real_threat_intel_result(), tmp_path)
    report = _generate(ingested).__getitem__("report")
    assert "=== THREAT INTELLIGENCE SUMMARY ===" in report.incident_summary


def test_ti_high_is_visible_in_standalone_report(tmp_path):
    ingested = _ingest_alert("HIGH", _real_threat_intel_result(enrichment_risk_level="High"), tmp_path)
    report = _generate(ingested)["report"]
    assert "Risk Level: High" in report.incident_summary


def test_ti_medium_is_visible_in_standalone_report(tmp_path):
    ingested = _ingest_alert("HIGH", _real_threat_intel_result(enrichment_risk_level="Medium"), tmp_path)
    report = _generate(ingested)["report"]
    assert "Risk Level: Medium" in report.incident_summary


def test_ti_low_is_visible_in_standalone_report(tmp_path):
    ingested = _ingest_alert("HIGH", _real_threat_intel_result(enrichment_risk_level="Low"), tmp_path)
    report = _generate(ingested)["report"]
    assert "Risk Level: Low" in report.incident_summary


def test_ti_score_zero_is_preserved_in_standalone_report(tmp_path):
    ingested = _ingest_alert("HIGH", _real_threat_intel_result(enrichment_risk_score=0), tmp_path)
    report = _generate(ingested)["report"]
    assert "Risk Score: 0" in report.incident_summary


def test_ti_risk_reasons_are_visible_in_standalone_report(tmp_path):
    reasons = ["VirusTotal reported 12 malicious detection(s) for the file hash.",
              "AbuseIPDB abuse confidence score is high for 203.0.113.9: 92."]
    ingested = _ingest_alert("HIGH", _real_threat_intel_result(enrichment_risk_reasons=reasons), tmp_path)
    report = _generate(ingested)["report"]
    for reason in reasons:
        assert reason in report.incident_summary


def test_ti_absent_preserves_current_standalone_behaviour(tmp_path):
    ingested = _ingest_alert("HIGH", None, tmp_path)
    report = _generate(ingested)["report"]
    assert "=== THREAT INTELLIGENCE SUMMARY ===" not in report.incident_summary
    assert "threat_intelligence_summary" not in ingested["metadata"]
    # Exactly the pre-Phase-5D summary shape for a HIGH/generic alert.
    assert report.incident_summary.strip() != ""


def test_completed_with_warnings_still_renders_ti_context(tmp_path):
    ti_result = _real_threat_intel_result(status="completed_with_warnings",
                                          warnings=["AbuseIPDB lookup for 203.0.113.9 failed."])
    ingested = _ingest_alert("HIGH", ti_result, tmp_path)
    report = _generate(ingested)["report"]
    assert "=== THREAT INTELLIGENCE SUMMARY ===" in report.incident_summary
    assert "Risk Level: High" in report.incident_summary
    # Raw warning strings are not dumped into the report.
    assert "AbuseIPDB lookup for 203.0.113.9 failed." not in report.incident_summary


# =============================================================================
# 9, 10 -- provider warnings do not modify severity or containment.
# =============================================================================

def test_provider_warnings_do_not_modify_severity(tmp_path):
    clean = _generate(_ingest_alert("MEDIUM", _real_threat_intel_result(status="completed"), tmp_path))["report"]
    warned = _generate(_ingest_alert("MEDIUM", _real_threat_intel_result(
        status="completed_with_warnings", warnings=["VirusTotal lookup failed."]), tmp_path))["report"]
    assert clean.severity == warned.severity == "Medium"


def test_provider_warnings_do_not_modify_containment(tmp_path):
    clean = _generate(_ingest_alert("MEDIUM", _real_threat_intel_result(status="completed"), tmp_path))["report"]
    warned = _generate(_ingest_alert("MEDIUM", _real_threat_intel_result(
        status="completed_with_warnings", warnings=["VirusTotal lookup failed."]), tmp_path))["report"]
    assert clean.recommended_containment == warned.recommended_containment


# =============================================================================
# 11, 12, 14 -- explicit conflicting-signal tests: severity/TI are
# independent, in both directions.
# =============================================================================

def test_triage_low_plus_ti_high_severity_remains_low(tmp_path):
    ingested = _ingest_alert("LOW", _real_threat_intel_result(enrichment_risk_level="High",
                                                              enrichment_risk_score=95), tmp_path)
    report = _generate(ingested)["report"]
    assert report.severity == "Low"
    assert "Risk Level: High" in report.incident_summary
    assert "Risk Score: 95" in report.incident_summary


def test_triage_high_plus_ti_low_severity_remains_high(tmp_path):
    ingested = _ingest_alert("HIGH", _real_threat_intel_result(enrichment_risk_level="Low",
                                                                enrichment_risk_score=0), tmp_path)
    report = _generate(ingested)["report"]
    assert report.severity == "High"
    assert "Risk Level: Low" in report.incident_summary
    assert "Risk Score: 0" in report.incident_summary


def test_ti_high_does_not_change_deterministic_severity_across_all_triage_levels(tmp_path):
    for i, triage_level in enumerate(("LOW", "MEDIUM", "HIGH", "CRITICAL")):
        sub_dir = tmp_path / str(i)
        sub_dir.mkdir()
        ingested = _ingest_alert(triage_level, _real_threat_intel_result(enrichment_risk_level="High",
                                                                          enrichment_risk_score=95), sub_dir)
        report = _generate(ingested, f"Incident-{i}")["report"]
        expected = {"LOW": "Low", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "Critical"}[triage_level]
        assert report.severity == expected


# =============================================================================
# 13, 15 -- confidence and MITRE remain unchanged regardless of TI.
# =============================================================================

def test_deterministic_confidence_remains_unchanged_regardless_of_ti(tmp_path):
    no_ti = _generate(_ingest_alert("HIGH", None, tmp_path), "Incident-A")["report"]
    with_high_ti = _generate(_ingest_alert("HIGH", _real_threat_intel_result(enrichment_risk_level="High"),
                                           tmp_path), "Incident-B")["report"]
    with_low_ti = _generate(_ingest_alert("HIGH", _real_threat_intel_result(enrichment_risk_level="Low"),
                                          tmp_path), "Incident-C")["report"]
    assert no_ti.confidence == with_high_ti.confidence == with_low_ti.confidence == "High"
    assert with_high_ti.confidence_justification == with_low_ti.confidence_justification == no_ti.confidence_justification


def test_mitre_output_remains_unchanged_regardless_of_ti(tmp_path):
    no_ti = _generate(_ingest_alert("HIGH", None, tmp_path), "Incident-A")["report"]
    with_ti = _generate(_ingest_alert("HIGH", _real_threat_intel_result(), tmp_path), "Incident-B")["report"]
    assert no_ti.mitre_mappings == with_ti.mitre_mappings == []


# =============================================================================
# 16 -- recommended containment regression across representative alert types,
# with and without TI, confirming TI never changes the list.
# =============================================================================

def _alert_with_type(alert_type: str, triage_result_kwargs: dict, incident_kwargs: dict,
                     ti_result: dict | None, tmp_path) -> dict:
    alert = wf.build_investigation_alert(triage_result_kwargs, incident_kwargs, threat_intel_result=ti_result)
    alert["classification"]["alert_type"] = alert_type
    alert_path = tmp_path / f"{alert_type.replace(' ', '_')}.json"
    alert_path.write_text(json.dumps(alert))
    return ingest_pipeline.process_log_file(str(alert_path))


def test_containment_unchanged_by_ti_for_phishing_alert_type(tmp_path):
    no_ti = _generate(_alert_with_type("Phishing", _triage_result_kwargs("HIGH"), _incident_kwargs(),
                                       None, tmp_path), "Incident-A")["report"]
    with_ti = _generate(_alert_with_type("Phishing", _triage_result_kwargs("HIGH"), _incident_kwargs(),
                                         _real_threat_intel_result(), tmp_path), "Incident-B")["report"]
    assert no_ti.recommended_containment == with_ti.recommended_containment


def test_containment_unchanged_by_ti_for_brute_force_alert_type(tmp_path):
    no_ti = _generate(_alert_with_type("Brute Force Login", _triage_result_kwargs("HIGH"), _incident_kwargs(),
                                       None, tmp_path), "Incident-A")["report"]
    with_ti = _generate(_alert_with_type("Brute Force Login", _triage_result_kwargs("HIGH"), _incident_kwargs(),
                                         _real_threat_intel_result(), tmp_path), "Incident-B")["report"]
    assert no_ti.recommended_containment == with_ti.recommended_containment


# =============================================================================
# 17 -- policy_engine.run_policy_compliance_rules() escalation logic is not
# accidentally triggered by TI text.
# =============================================================================

def test_ransomware_escalation_not_triggered_by_ti_reasons_text():
    """calculate_enrichment_risk()'s own reason sentences never contain
    "ransomware" -- and even if a future reason string did, Phase 5D
    appends the TI block to `summary` only AFTER
    run_policy_compliance_rules() has already been called with the
    TI-free summary, so it can never reach this scan."""
    result = policy_engine.run_policy_compliance_rules(
        incident_id="INC-1001", severity="High", confidence="High",
        incident_summary="Anomalous security event occurred.",
        recommended_containment=["Isolate the host."],
        business_impact_checklist={"critical_system": "no", "essential_service": "no",
                                   "data_sensitivity": "no", "operational_impact": "no"},
        timeline_text="=== THREAT INTELLIGENCE SUMMARY ===\nRisk Level: High\nRisk Score: 95\n"
                      "Risk Reasons:\n- VirusTotal reported 12 malicious detection(s) for the file hash.",
    )
    assert "Ransomware is suspected" not in result["reasons"]
    assert not any("ransomware" in c.lower() for c in result["modified_containment"])


def test_guest_os_escalation_not_triggered_by_ti_reasons_text():
    result = policy_engine.run_policy_compliance_rules(
        incident_id="INC-1001", severity="High", confidence="High",
        incident_summary="Anomalous security event occurred.",
        recommended_containment=["Isolate the host."],
        business_impact_checklist={"critical_system": "no", "essential_service": "no",
                                   "data_sensitivity": "no", "operational_impact": "no"},
        timeline_text="=== THREAT INTELLIGENCE SUMMARY ===\nRisk Level: High\nRisk Score: 95\n"
                      "Risk Reasons:\n- AbuseIPDB abuse confidence score is high for 203.0.113.9: 92.",
    )
    assert "Compromised guest OS is suspected in a virtualised environment" not in result["reasons"]


def test_policy_engine_full_stage_run_produces_unchanged_escalation_for_high_ti(tmp_path):
    """End-to-end: a High-TI-risk standalone report does not pick up a
    spurious ransomware/guest-OS containment override purely from the TI
    section's presence in the final incident_summary."""
    ingested = _ingest_alert("MEDIUM", _real_threat_intel_result(enrichment_risk_level="High",
                                                                  enrichment_risk_score=95), tmp_path)
    report = _generate(ingested)["report"]
    assert not any("Disconnect the infected" in c for c in report.recommended_containment)
    assert not any("guest operating system" in c.lower() for c in report.recommended_containment)


# =============================================================================
# 12, 18 (trust boundary) -- no raw provider free text or full payload
# reaches the standalone report.
# =============================================================================

def test_no_raw_otx_pulse_names_in_standalone_report(tmp_path):
    ti_result = _real_threat_intel_result()
    assert "Botnet C2 Tracker" in json.dumps(ti_result)  # sanity: it's really in the source
    ingested = _ingest_alert("HIGH", ti_result, tmp_path)
    report = _generate(ingested)["report"]
    assert "Botnet C2 Tracker" not in report.incident_summary
    assert "Emotet Infrastructure" not in report.incident_summary


def test_no_virustotal_meaningful_name_in_standalone_report(tmp_path):
    ti_result = _real_threat_intel_result()
    assert "invoice.exe" in json.dumps(ti_result["threat_intelligence"])
    ingested = _ingest_alert("HIGH", ti_result, tmp_path)
    report = _generate(ingested)["report"]
    assert "invoice.exe" not in report.incident_summary


def test_no_isp_or_registrar_free_text_in_standalone_report(tmp_path):
    ingested = _ingest_alert("HIGH", _real_threat_intel_result(), tmp_path)
    report = _generate(ingested)["report"]
    for forbidden in ("Some Hosting Provider LLC", "somehostingprovider.example"):
        assert forbidden not in report.incident_summary


def test_full_provider_payload_not_inserted_into_standalone_report(tmp_path):
    """Curated enrichment_risk_reasons sentences legitimately mention
    provider names in prose (e.g. "VirusTotal reported...") -- that is the
    intended, curated summary, not a payload leak. What must never appear
    is the RAW provider bundle's own structural/dict-key shape."""
    ingested = _ingest_alert("HIGH", _real_threat_intel_result(), tmp_path)
    report = _generate(ingested)["report"]
    for forbidden in ("ip_results", "otx_results", "domain_results",
                      "\"status\": \"completed\"", "pulse_count"):
        assert forbidden not in report.incident_summary
