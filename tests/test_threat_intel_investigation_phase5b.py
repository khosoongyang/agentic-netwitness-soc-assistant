"""tests/test_threat_intel_investigation_phase5b.py -- Threat Intelligence
Phase 5B: compact, prioritized Threat Intelligence context for the main
Investigation LLM.

Phase 5A captured two demonstrated weaknesses as baseline (regression) tests:
TI's risk verdict can be pushed past ingest_pipeline.py's 12,000-character
narrative truncation by a large correlated-alert set, and the full raw
provider bundle (threat_intelligence_enrichment) is the single largest
contributor to that truncation pressure.

Phase 5B adds workflow/engine.py::build_investigation_threat_intel_context()
-- a small, deterministic, bounded projection of the canonical
ThreatIntelResult (enrichment_risk_level/score/reasons only) -- embedded as
a new, additive "threat_intelligence_summary" key on the queued Investigation
alert, and rendered by ingest_pipeline.py::serialize_json_to_narrative()
ahead of the unbounded correlated-alerts block, so its survival past
truncation is deterministic rather than dependent on incident size.

This file does NOT re-litigate the Phase 5A baseline tests (still green,
unmodified, in tests/test_threat_intel_investigation_baseline.py) -- it
proves the NEW behaviour: the compact block exists, is bounded, is
trustworthy (no raw/free-text provider fields promoted into it), and now
survives exactly the large-correlation scenario Phase 5A demonstrated as
lossy for the old verbose representation.

No OpenAI/LLM calls are made anywhere in this file -- every path exercised
(build_investigation_threat_intel_context, build_investigation_alert,
serialize_json_to_narrative, process_log_file) is deterministic and
LLM-free by construction. Provider collection, ThreatIntelResult, and
calculate_enrichment_risk() are not touched by this phase and are not
exercised here beyond passing already-computed dicts through.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from workflow import engine as wf
from workflow.engine import build_investigation_threat_intel_context

REPO_ROOT = Path(__file__).resolve().parent.parent
INV_DIR = REPO_ROOT / "agents" / "investigation"

sys.path.insert(0, str(INV_DIR))
from agents.investigation import ingest_pipeline  # noqa: E402


# =============================================================================
# Shared fixture helpers (same shapes as the Phase 5A baseline file).
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
                "file_hash": {"status": "completed", "malicious": 5, "harmless": 58,
                              "undetected": 3, "reputation": -12, "meaningful_name": "invoice.exe"},
                "ip_results": [{"status": "completed", "indicator": "203.0.113.9", "malicious": 5,
                                "harmless": 58, "undetected": 3, "country": "RU",
                                "as_owner": "Some Hosting Provider LLC"}],
                "domain_results": [],
            },
            "abuseipdb": {"ip_results": [{"status": "completed", "indicator": "203.0.113.9",
                                          "abuse_confidence_score": 92, "isp": "Some Hosting Provider LLC",
                                          "domain": "somehostingprovider.example",
                                          "usage_type": "Data Center/Web Hosting/Transit"}]},
            "alienvault_otx": {"otx_results": [{"status": "completed", "indicator": "203.0.113.9",
                                                "pulse_count": 7,
                                                "related_pulses": ["Botnet C2 Tracker", "Emotet Infrastructure"],
                                                "sections_available": ["general", "reputation"]}]},
            "notes": [],
        },
        "enrichment_risk_score": 80,
        "enrichment_risk_level": "High",
        "enrichment_risk_reasons": [
            "VirusTotal reported 5 malicious detection(s) for IP 203.0.113.9.",
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


def _sub_alert(i: int) -> dict:
    return {
        "alert_id": f"A-{i}", "title": "Suspicious PowerShell Execution Detected on Endpoint",
        "timestamp": f"2026-08-20T09:{i % 60:02d}:00Z", "severity": "Medium",
        "user": f"user{i}", "hostname": f"HOST-{i:03d}",
        "source_ip": f"10.0.{i // 256}.{i % 256}", "destination_ip": "203.0.113.9",
        "description": "Encoded PowerShell command line observed launching a child "
                       "process with outbound network activity.",
    }


# =============================================================================
# Section 16 -- compact projection helper, tested directly.
# =============================================================================

def test_high_risk_renders_high():
    block = build_investigation_threat_intel_context(_real_threat_intel_result(enrichment_risk_level="High"))
    assert "Risk Level: High" in block


def test_medium_risk_renders_medium():
    block = build_investigation_threat_intel_context(_real_threat_intel_result(enrichment_risk_level="Medium"))
    assert "Risk Level: Medium" in block


def test_low_risk_renders_low():
    block = build_investigation_threat_intel_context(_real_threat_intel_result(enrichment_risk_level="Low"))
    assert "Risk Level: Low" in block


def test_score_zero_is_preserved_not_treated_as_missing():
    block = build_investigation_threat_intel_context(_real_threat_intel_result(enrichment_risk_score=0))
    assert "Risk Score: 0" in block
    assert "Risk Score: Unknown" not in block


def test_enrichment_risk_reasons_are_preserved_verbatim():
    reasons = ["VirusTotal reported 5 malicious detection(s) for IP 203.0.113.9.",
              "AbuseIPDB abuse confidence score is high for 203.0.113.9: 92."]
    block = build_investigation_threat_intel_context(_real_threat_intel_result(enrichment_risk_reasons=reasons))
    for reason in reasons:
        assert reason in block


def test_empty_reasons_degrade_cleanly():
    block = build_investigation_threat_intel_context(_real_threat_intel_result(enrichment_risk_reasons=[]))
    assert "Risk Reasons: None recorded." in block


def test_missing_threat_intel_result_returns_none():
    assert build_investigation_threat_intel_context(None) is None
    assert build_investigation_threat_intel_context({}) is None


def test_no_raw_otx_pulse_names_appear():
    ti = _real_threat_intel_result()
    # Sanity: the pulse names really are present somewhere in the full
    # ThreatIntelResult, so their absence below is a real assertion.
    assert "Botnet C2 Tracker" in json.dumps(ti)
    block = build_investigation_threat_intel_context(ti)
    assert "Botnet C2 Tracker" not in block
    assert "Emotet Infrastructure" not in block


def test_no_virustotal_meaningful_name_appears():
    ti = _real_threat_intel_result()
    assert "invoice.exe" in json.dumps(ti)
    block = build_investigation_threat_intel_context(ti)
    assert "invoice.exe" not in block


def test_no_isp_registrar_or_provider_free_text_appears():
    ti = _real_threat_intel_result()
    block = build_investigation_threat_intel_context(ti)
    for forbidden in ("Some Hosting Provider LLC", "somehostingprovider.example",
                      "Data Center/Web Hosting/Transit", "RU"):
        assert forbidden not in block


def test_no_harmless_undetected_or_verbose_provider_metadata_appears():
    ti = _real_threat_intel_result()
    block = build_investigation_threat_intel_context(ti)
    for forbidden in ("harmless", "undetected", "sections_available", "reputation"):
        assert forbidden not in block.lower()


def test_deterministic_output_for_identical_threat_intel_result():
    ti = _real_threat_intel_result()
    block_a = build_investigation_threat_intel_context(ti)
    block_b = build_investigation_threat_intel_context(ti)
    assert block_a == block_b


def test_reasons_are_bounded_regardless_of_ioc_count():
    many_reasons = [f"VirusTotal reported malicious detections for indicator {i}." for i in range(50)]
    block = build_investigation_threat_intel_context(_real_threat_intel_result(enrichment_risk_reasons=many_reasons))
    assert block.count("- VirusTotal reported malicious detections") <= 10
    assert "(+40 more reason(s) recorded)" in block


def test_uses_repository_prompt_section_convention():
    """Matches the "=== X ===" section-header convention already used by
    agents/investigation/orchestrator.py's own ChatPromptTemplate human
    messages (e.g. "=== INCIDENT ID ===")."""
    block = build_investigation_threat_intel_context(_real_threat_intel_result())
    assert block.startswith("=== THREAT INTELLIGENCE SUMMARY ===")


# =============================================================================
# Additive queued-alert integration: threat_intelligence_summary alongside
# the four unchanged, pre-existing TI-owned keys.
# =============================================================================

def test_queued_alert_gains_summary_key_without_touching_existing_ti_keys():
    ti_result = _real_threat_intel_result()
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    assert alert["threat_intelligence_summary"].startswith("=== THREAT INTELLIGENCE SUMMARY ===")
    # Pre-existing Phase 1-5A keys remain present and unchanged in shape.
    assert alert["enrichment_risk_score"] == 80
    assert alert["enrichment_risk_level"] == "High"
    assert alert["enrichment_risk_reasons"] == ti_result["enrichment_risk_reasons"]
    assert "threat_intelligence_enrichment" in alert


def test_queued_alert_has_no_summary_key_when_no_threat_intel_result():
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=None)
    assert "threat_intelligence_summary" not in alert
    assert "threat_intelligence_enrichment" not in alert


# =============================================================================
# The headline fix: the exact Phase 5A large-correlation scenario, now with
# the compact block surviving where the old verbose representation did not
# (and still does not -- that representation is unchanged in this phase).
# =============================================================================

def test_compact_summary_survives_the_same_large_correlation_scenario_phase5a_showed_as_lossy(tmp_path):
    ti_result = _real_threat_intel_result()
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    alert["alerts"] = [_sub_alert(i) for i in range(80)]  # same count Phase 5A used to show loss

    alert_path = tmp_path / "large_correlated_alert.json"
    alert_path.write_text(json.dumps(alert))
    ingested = ingest_pipeline.process_log_file(str(alert_path))
    document = ingested["document"]

    assert document.endswith("[TRUNCATED]")  # still truncated -- the limit itself is unchanged
    # NEW (Phase 5B): the compact, bounded block survives regardless.
    assert "=== THREAT INTELLIGENCE SUMMARY ===" in document
    assert "Risk Level: High" in document
    assert "Risk Score: 80" in document
    assert "VirusTotal reported 5 malicious detection(s) for IP 203.0.113.9." in document
    # UNCHANGED (Phase 5A baseline still holds): the old, verbose,
    # generically-flattened enrichment_risk_* keys are still lost -- this
    # phase did not touch those keys or their position in the document.
    assert "enrichment risk level" not in document.lower()
    assert "enrichment risk score" not in document.lower()


def test_compact_summary_appears_exactly_once_not_duplicated_by_generic_recursion():
    ti_result = _real_threat_intel_result()
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    document = ingest_pipeline.serialize_json_to_narrative(alert)
    assert document.count("=== THREAT INTELLIGENCE SUMMARY ===") == 1


def test_compact_summary_positioned_before_correlated_alerts_block():
    ti_result = _real_threat_intel_result()
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    alert["alerts"] = [_sub_alert(i) for i in range(5)]
    document = ingest_pipeline.serialize_json_to_narrative(alert)

    ti_offset = document.find("=== THREAT INTELLIGENCE SUMMARY ===")
    correlated_offset = document.find("correlated alert(s)")
    assert ti_offset != -1 and correlated_offset != -1
    assert ti_offset < correlated_offset


# =============================================================================
# Section 15 -- behavioural safeguards around the input change: prove
# availability, no fabrication, and that Investigation's own severity is
# not silently overwritten by this new input.
# =============================================================================

def test_full_provider_bundle_remains_in_queued_alert_json_unchanged():
    """The full ThreatIntelResult-derived provider bundle remains available
    on the queued alert (this phase is additive, not a replacement) -- only
    the LLM-facing narrative gained a new prioritized section."""
    ti_result = _real_threat_intel_result()
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    assert alert["threat_intelligence_enrichment"]["virustotal"]["ip_results"][0]["malicious"] == 5
    assert alert["threat_intelligence_enrichment"]["abuseipdb"]["ip_results"][0]["abuse_confidence_score"] == 92


def test_no_fabricated_ti_evidence_when_reasons_absent():
    ti_result = _real_threat_intel_result(enrichment_risk_reasons=[])
    block = build_investigation_threat_intel_context(ti_result)
    # Must say reasons are absent, not invent plausible-sounding findings.
    assert "None recorded" in block
    assert "VirusTotal" not in block
    assert "AbuseIPDB" not in block


def test_ti_summary_does_not_overwrite_or_appear_as_investigation_severity_field():
    """The compact block is narrative text embedded in the document, not a
    structured field Investigation's own severity assignment reads from --
    confirm it is namespaced under its own key, distinct from any severity/
    classification field build_investigation_alert() already produces."""
    ti_result = _real_threat_intel_result()
    alert = wf.build_investigation_alert(_triage_result_kwargs(classification="LOW"), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    assert alert["classification"]["severity"] == "LOW"
    assert alert["threat_intelligence_summary"] != alert["classification"]["severity"]
    assert "threat_intelligence_summary" != "classification"


# =============================================================================
# Section 1 preservation checks: provider collection / scoring untouched.
# =============================================================================

def test_calculate_enrichment_risk_and_provider_functions_untouched():
    from agents.threat_intelligence import threat_intel as ti_module

    # Same behaviour as before this phase: deterministic, rule-based,
    # untouched by the Investigation-facing projection added here.
    result = ti_module.calculate_enrichment_risk({})
    assert result == {
        "enrichment_risk_score": 0, "enrichment_risk_level": "Low",
        "enrichment_risk_reasons": [
            "No confirmed malicious external intelligence was found, or no usable IOC was available.",
        ],
    }
    for fn_name in ("query_virustotal_file_hash", "query_virustotal_ip", "query_virustotal_domain",
                    "query_abuseipdb", "query_otx_indicator"):
        assert hasattr(ti_module, fn_name)
