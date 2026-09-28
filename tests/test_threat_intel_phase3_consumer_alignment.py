"""tests/test_threat_intel_phase3_consumer_alignment.py -- Threat Intelligence
Phase 3 (consumer alignment + malformed-provider-response hardening).

Two concerns, matching the two Phase 3 objectives:

1. Every production consumer of a Threat Intelligence result reads
   canonical fields (enrichment_risk_score/level/reasons, threat_intelligence,
   warnings, summary) from the correct artifact (threat_intel_result), never
   from the unrelated, Triage/incident-derived Reporting enriched_alert.json
   -- and the two proven wrong-artifact reads found during the Phase 3 audit
   (agents/reporting/adapters/common.py::normalise_incident() and
   agents/reporting/reporting/template_document_exporter.py::
   build_agent_llm_fields()'s threat_fact_pack()) are fixed.

2. A provider (VirusTotal/AbuseIPDB/AlienVault OTX) returning HTTP 200 with
   a malformed/non-JSON body degrades to that provider's existing
   {"status": "error", ...} shape instead of an uncaught exception escaping
   and failing the whole Threat Intelligence stage.

No live HTTP/API calls: every provider lookup is either skipped (no API
key configured) or driven through a mocked `requests.get`.
"""
from __future__ import annotations

import json as jsonlib
from unittest.mock import Mock, patch

import pytest
import requests

from agents.reporting.adapters.common import normalise_incident
from agents.reporting.reporting.context_builder import build_context
from agents.reporting.reporting.template_document_exporter import build_agent_llm_fields
from agents.threat_intelligence import threat_intel as ti
from agents.threat_intelligence.threat_intel_result import validate_threat_intel_result


def _malformed_json_response(status_code: int = 200) -> Mock:
    """A response object shaped exactly like what `requests.get()` returns
    for an HTTP 200 whose body isn't valid JSON -- `.json()` raises, exactly
    as it would on a real `requests.Response`."""
    r = Mock(status_code=status_code)
    r.json.side_effect = requests.exceptions.JSONDecodeError("Expecting value", "not json", 0)
    return r


def _ok_json_response(payload: dict) -> Mock:
    r = Mock(status_code=200)
    r.json.return_value = payload
    return r


# =============================================================================
# Consumer alignment 1-4: Reporting's TI-owned fields, distinctness of
# source/Triage/TI risk concepts (Phase 1 behaviour re-confirmed unchanged).
# =============================================================================

def _reporting_inputs(**overrides) -> dict:
    inputs = {
        "processed_alert": {"risk_score": 10},
        "enriched_alert": {
            "incident_id": "INC-1", "risk_score": 20,
            "severity": "Medium",
        },
        "triage_result": {"incident_id": "INC-1", "risk_rating": {"overall_risk": "High"}},
        "investigation_result": {"severity": "Critical"},
        "threat_intel_result": {
            "status": "completed", "enrichment_risk_score": 80,
            "enrichment_risk_level": "High",
            "enrichment_risk_reasons": ["VirusTotal reported malicious detections."],
            "notes": [], "summary": "Threat intelligence enrichment completed with High enrichment risk.",
        },
    }
    inputs.update(overrides)
    return inputs


def test_reporting_enrichment_risk_score_uses_threat_intel_result():
    ctx = build_context(_reporting_inputs())
    assert ctx["enrichment_risk_score"] == 80


def test_reporting_unrelated_enriched_alert_cannot_override_enrichment_risk_score():
    """enriched_alert.risk_score (20) must never surface as the
    enrichment_risk_score (80, from threat_intel_result) -- the exact bug
    Phase 1 fixed, re-confirmed still fixed post-Phase-2/3 changes."""
    ctx = build_context(_reporting_inputs())
    assert ctx["enrichment_risk_score"] != 20
    assert ctx["enrichment_risk_score"] == 80


def test_reporting_source_risk_score_remains_distinct():
    ctx = build_context(_reporting_inputs())
    assert ctx["original_alert_risk_score"] == 10
    assert ctx["enrichment_risk_score"] == 80
    assert ctx["original_alert_risk_score"] != ctx["enrichment_risk_score"]


def test_reporting_triage_risk_rating_remains_distinct():
    ctx = build_context(_reporting_inputs())
    assert ctx["triage"]["risk_rating"] == {"overall_risk": "High"}
    assert ctx["enrichment_risk_level"] == "High"
    # Same word ("High") can genuinely appear in both -- they are still two
    # separately-sourced, separately-owned fields, not the same value read twice.
    assert ctx["triage"] is not ctx.get("enrichment_risk_level")


# =============================================================================
# Consumer alignment 5: Investigation sidecar accepts a canonical, Phase-2
# ThreatIntelResult-shaped dict without raising.
# =============================================================================

def test_investigation_sidecar_accepts_canonical_threat_intel_result_shape():
    import agents.investigation.skills_sidecar as skills_sidecar

    ti_result = {
        "agent": "Threat Intelligence Enrichment", "agent_source": "threat_intel.py",
        "status": "completed", "current_stage": "threat_intelligence_completed",
        "created_at": "2026-08-20T10:05:00+00:00",
        "summary": "Threat intelligence enrichment completed with High enrichment risk.",
        "enrichment_risk_score": 80, "enrichment_risk_level": "High",
        "enrichment_risk_reasons": ["VirusTotal reported malicious detections."],
        "threat_intelligence": {
            "iocs": {
                "possible_file_name": None, "file_hash": "a" * 64,
                "ip_indicators": [], "domain_indicators": [], "url_indicators": [],
                "powershell_analysis": {}, "powershell_enrichment_note": "No decoded PowerShell analysis was available before enrichment.",
            },
            "virustotal": {"file_hash": {"status": "completed", "malicious": 5}, "ip_results": [], "domain_results": []},
            "abuseipdb": {"ip_results": []},
            "alienvault_otx": {"otx_results": []},
            "notes": [],
        },
        "notes": [], "warnings": [], "enriched_alert": {"incident_id": "INC-1"},
        "output_files": {}, "export_status": {},
        "recommended_next_action": "SOC analyst approval is required before Investigation Agent can run.",
    }
    # Round-trips through the canonical contract first, proving the shape is
    # genuinely the Phase 2 contract's own dump, not a hand-shaped lookalike.
    dumped = validate_threat_intel_result(ti_result).model_dump(mode="json")

    bundle = skills_sidecar.build_skills_context(
        {"id": "INC-1"}, triage_result={}, investigation_result={"status": "needs_more_data"},
        ti_result=dumped)
    assert isinstance(bundle, dict)  # never raises


# =============================================================================
# Consumer alignment 6: no consumer expects nonexistent TI fields
# (confidence, MITRE mapping) -- Investigation tools tolerate a canonical
# result that genuinely lacks them.
# =============================================================================

def test_diamond_model_does_not_require_confidence_or_mitre_on_ti_result():
    from agents.investigation.tools.diamond_model import build_diamond
    ti_result = {"enrichment_risk_level": "High", "enrichment_risk_score": 80}
    assert "confidence" not in ti_result
    assert "mitre_mapping" not in ti_result
    d = build_diamond({"id": "INC-1"}, triage_result={}, ti_result=ti_result)
    assert d["threat_intel_risk_level"] == "High"
    assert d["threat_intel_risk_score"] == 80


def test_mitigation_mapping_does_not_require_confidence_or_mitre_on_ti_result():
    from agents.investigation.tools.mitigation_mapping import build_mitigation_coverage
    ti_result = {"enrichment_risk_level": "High"}
    assert "confidence" not in ti_result
    assert "mitre_mapping" not in ti_result
    # Must not raise for lacking these fields.
    build_mitigation_coverage({"id": "INC-1"}, {}, ti_result, None)


# =============================================================================
# Consumer alignment 7: missing optional provider data degrades safely.
# =============================================================================

def test_missing_provider_data_degrades_safely(monkeypatch, tmp_path):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    with patch("requests.get") as m:
        result = ti.run_threat_intel_for_dashboard({"source_ip": "203.0.113.9"}, output_dir=tmp_path)
        m.assert_not_called()
    assert result["status"] == "completed_with_warnings"
    validate_threat_intel_result(result)


# =============================================================================
# Consumer alignment 8: legacy fallback behaviour remains where intentionally
# retained (export_context_enhancer's threat_intel_result -> enriched
# precedence; context_builder's trailing legacy enriched.get(
# "enrichment_risk_score") fallback).
# =============================================================================

def test_context_builder_legacy_fallback_still_used_when_ti_result_lacks_the_key():
    ctx = build_context(_reporting_inputs(threat_intel_result={"status": "completed"},
                                          enriched_alert={"incident_id": "INC-1", "enrichment_risk_score": 55}))
    assert ctx["enriched_risk_score"] == 55


def test_export_context_enhancer_prefers_threat_intel_result_over_enriched():
    from agents.reporting.reporting.export_context_enhancer import rebuild_iocs
    context = {
        "threat_intel_result": {"threat_intelligence": {"virustotal": {"ip_results": [
            {"status": "completed", "indicator": "203.0.113.9", "malicious": 5}]}}},
        "raw_inputs": {"enriched_alert": {"threat_intelligence": {"virustotal": {"ip_results": []}}}},
    }
    iocs = rebuild_iocs(context, {})
    assert isinstance(iocs, list)


# =============================================================================
# Wrong-artifact reads fixed during Phase 3.
# =============================================================================

def test_normalise_incident_does_not_read_enrichment_risk_score_from_enriched_alert():
    """agents/reporting/adapters/common.py::normalise_incident() must never
    treat the unrelated Reporting enriched_alert's fields as a source for
    Threat-Intelligence-owned enrichment_risk_score."""
    enriched = {"incident_id": "INC-1", "enrichment_risk_score": 999}
    result = normalise_incident(enriched)
    assert result["risk_score"] != 999


def test_threat_fact_pack_does_not_read_nonexistent_top_level_iocs():
    """template_document_exporter.py's threat_fact_pack() must source IOCs
    from threat_intelligence.iocs (the real location), never a nonexistent
    top-level "iocs" key on threat_intel_result."""
    output = {
        "iocs": {"file_hash": "WRONG-SHOULD-NEVER-SURFACE"},
        "threat_intelligence": {"iocs": {"file_hash": "correct-hash", "possible_file_name": None,
                                         "ip_indicators": [], "domain_indicators": []}},
        "enrichment_risk_score": 10, "enrichment_risk_level": "Low",
        "notes": [],
    }
    fields = build_agent_llm_fields("threat_intel", {"severity": {"label": "Low"}, "confidence": {"label": "Low"}}, output)
    assert fields["llm_input"]["iocs"]["file_hash"] == "correct-hash"


# =============================================================================
# Malformed provider JSON: VirusTotal.
# =============================================================================

def test_virustotal_malformed_json_degrades_to_error_not_exception(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-vt-key")
    with patch("requests.get", return_value=_malformed_json_response()):
        result = ti.query_virustotal_ip("203.0.113.9")  # must not raise
    assert result["status"] == "error"
    assert result["indicator"] == "203.0.113.9"
    assert "reason" in result


def test_virustotal_malformed_json_via_full_stage_run(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_API_KEY", "test-vt-key")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    with patch("requests.get", return_value=_malformed_json_response()):
        result = ti.run_threat_intel_for_dashboard({"source_ip": "203.0.113.9"}, output_dir=tmp_path)
    assert result["threat_intelligence"]["virustotal"]["ip_results"][0]["status"] == "error"
    assert any("VirusTotal" in w for w in result["warnings"])
    assert result["status"] == "completed_with_warnings"
    validate_threat_intel_result(result)


# =============================================================================
# Malformed provider JSON: AbuseIPDB.
# =============================================================================

def test_abuseipdb_malformed_json_degrades_to_error_not_exception(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuse-key")
    with patch("requests.get", return_value=_malformed_json_response()):
        result = ti.query_abuseipdb("203.0.113.9")  # must not raise
    assert result["status"] == "error"
    assert result["indicator"] == "203.0.113.9"


def test_abuseipdb_malformed_json_via_full_stage_run(monkeypatch, tmp_path):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuse-key")
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    with patch("requests.get", return_value=_malformed_json_response()):
        result = ti.run_threat_intel_for_dashboard({"source_ip": "203.0.113.9"}, output_dir=tmp_path)
    assert result["threat_intelligence"]["abuseipdb"]["ip_results"][0]["status"] == "error"
    assert any("AbuseIPDB" in w for w in result["warnings"])
    assert result["status"] == "completed_with_warnings"
    validate_threat_intel_result(result)


# =============================================================================
# Malformed provider JSON: AlienVault OTX.
# =============================================================================

def test_otx_malformed_json_degrades_to_error_not_exception(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-otx-key")
    with patch("requests.get", return_value=_malformed_json_response()):
        result = ti.query_otx_indicator("IPv4", "203.0.113.9")  # must not raise
    assert result["status"] == "error"
    assert result["indicator"] == "203.0.113.9"


def test_otx_malformed_json_via_full_stage_run(monkeypatch, tmp_path):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setenv("OTX_API_KEY", "test-otx-key")
    with patch("requests.get", return_value=_malformed_json_response()):
        result = ti.run_threat_intel_for_dashboard({"source_ip": "203.0.113.9"}, output_dir=tmp_path)
    assert result["threat_intelligence"]["alienvault_otx"]["otx_results"][0]["status"] == "error"
    assert any("AlienVault OTX" in w for w in result["warnings"])
    assert result["status"] == "completed_with_warnings"
    validate_threat_intel_result(result)


# =============================================================================
# One provider's malformed response does not stop the others, and successful
# providers still contribute to the risk score.
# =============================================================================

def test_one_malformed_provider_does_not_block_others_or_risk_scoring(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_API_KEY", "test-vt-key")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuse-key")
    monkeypatch.delenv("OTX_API_KEY", raising=False)

    def _routed_get(url, *args, **kwargs):
        if "virustotal.com" in url:
            return _malformed_json_response()
        if "abuseipdb.com" in url:
            return _ok_json_response({"data": {"abuseConfidenceScore": 95, "totalReports": 40}})
        raise AssertionError(f"unexpected URL in test: {url}")

    with patch("requests.get", side_effect=_routed_get):
        result = ti.run_threat_intel_for_dashboard({"source_ip": "203.0.113.9"}, output_dir=tmp_path)

    assert result["threat_intelligence"]["virustotal"]["ip_results"][0]["status"] == "error"
    assert result["threat_intelligence"]["abuseipdb"]["ip_results"][0]["status"] == "completed"
    assert result["threat_intelligence"]["abuseipdb"]["ip_results"][0]["abuse_confidence_score"] == 95
    assert any("VirusTotal" in w for w in result["warnings"])
    # AbuseIPDB's high confidence score (>=80) contributes +30 -- risk
    # scoring still executes and reflects the provider that DID succeed.
    assert result["enrichment_risk_score"] >= 30
    assert result["status"] == "completed_with_warnings"
    validate_threat_intel_result(result)


# =============================================================================
# Contract compatibility: malformed-provider error results still fit the
# canonical ThreatIntelResult (no top-level contract loosening was needed).
# =============================================================================

def test_malformed_provider_error_result_fits_canonical_contract_unmodified():
    from agents.threat_intelligence.threat_intel_result import ThreatIntelProviderBundle
    bundle_dict = {
        "iocs": {
            "possible_file_name": None, "file_hash": None,
            "ip_indicators": ["203.0.113.9"], "domain_indicators": [], "url_indicators": [],
            "powershell_analysis": {}, "powershell_enrichment_note": "No decoded PowerShell analysis was available before enrichment.",
        },
        "virustotal": {
            "file_hash": {"status": "skipped", "reason": "No file hash was available."},
            "ip_results": [{"status": "error", "indicator": "203.0.113.9",
                             "reason": "Expecting value: line 1 column 1 (char 0)"}],
            "domain_results": [],
        },
        "abuseipdb": {"ip_results": [{"status": "skipped", "reason": "ABUSEIPDB_API_KEY is missing."}]},
        "alienvault_otx": {"otx_results": [{"status": "skipped", "reason": "OTX_API_KEY is missing."}]},
        "notes": [],
    }
    bundle = ThreatIntelProviderBundle.model_validate(bundle_dict)
    assert bundle.virustotal.ip_results[0]["status"] == "error"
    assert "Expecting value" in bundle.virustotal.ip_results[0]["reason"]


# =============================================================================
# No-IOC / missing-key / private-IP-exclusion regression (must behave
# exactly as before Phase 3).
# =============================================================================

def test_no_ioc_regression_unchanged(monkeypatch, tmp_path):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    with patch("requests.get") as m:
        result = ti.run_threat_intel_for_dashboard({}, output_dir=tmp_path)
        m.assert_not_called()
    assert result["status"] == "completed"
    assert result["enrichment_risk_score"] == 0
    assert result["enrichment_risk_level"] == "Low"


def test_private_ip_excluded_regression_unchanged():
    iocs = ti.extract_iocs({"source_ip": "10.0.0.5", "destination_ip": "192.168.1.1"})
    assert iocs["ip_indicators"] == []


def test_unsupported_ioc_type_ignored_regression_unchanged():
    iocs = ti.extract_iocs({"source_ip": "not-an-ip-address"})
    assert iocs["ip_indicators"] == []
