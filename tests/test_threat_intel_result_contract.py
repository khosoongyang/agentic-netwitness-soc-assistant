"""tests/test_threat_intel_result_contract.py -- Threat Intelligence Phase 2
(canonical result contract migration).

Verifies agents/threat_intelligence/threat_intel_result.py's Pydantic
contract against the REAL shape agents/threat_intelligence/threat_intel.py::
run_threat_intel_for_dashboard() produces, and that the contract is now
wired at that function's return boundary (validate -> dump -> persist ->
return, mirroring the successful Triage migration's
validate_triage_agent_output()/dump_triage_agent_output() pattern).

No live HTTP/API calls: every provider lookup is either skipped (no API
key configured) or driven through a mocked `requests.get`, exactly like
tests/test_threat_intel_workflow.py's existing convention.
"""
from __future__ import annotations

import json
from unittest.mock import Mock, patch

import pytest
from pydantic import ValidationError

from agents.threat_intelligence import threat_intel as ti
from agents.threat_intelligence.threat_intel_result import (
    AbuseIPDBResults,
    AlienVaultOTXResults,
    ThreatIntelIOCs,
    ThreatIntelProviderBundle,
    ThreatIntelResult,
    VirusTotalResults,
    dump_threat_intel_result,
    validate_threat_intel_result,
)


def _ok_json_response(payload: dict) -> Mock:
    r = Mock(status_code=200)
    r.json.return_value = payload
    return r


def _full_iocs(**overrides) -> dict:
    iocs = {
        "possible_file_name": "payload.exe",
        "file_hash": "a" * 64,
        "ip_indicators": ["203.0.113.9"],
        "domain_indicators": ["malicious.example.com"],
        "url_indicators": ["http://malicious.example.com/payload"],
        "powershell_analysis": {},
        "powershell_enrichment_note": "No decoded PowerShell analysis was available before enrichment.",
    }
    iocs.update(overrides)
    return iocs


def _full_provider_bundle(**overrides) -> dict:
    """A complete, real-shaped threat_intelligence dict -- one lookup per
    provider, each in its real "completed" shape (threat_intel.py:401-459,
    591-646, 657-711)."""
    bundle = {
        "iocs": _full_iocs(),
        "virustotal": {
            "file_hash": {
                "status": "completed", "indicator": "a" * 64,
                "malicious": 5, "suspicious": 1, "harmless": 54, "undetected": 0,
                "reputation": -10, "meaningful_name": "payload.exe",
                "first_submission_date": 1600000000, "last_analysis_date": 1700000000,
            },
            "ip_results": [{
                "status": "completed", "indicator": "203.0.113.9",
                "malicious": 3, "suspicious": 0, "harmless": 57, "undetected": 0,
                "reputation": -5, "country": "US", "as_owner": "Example ISP",
            }],
            "domain_results": [{
                "status": "completed", "indicator": "malicious.example.com",
                "malicious": 2, "suspicious": 1, "harmless": 57, "undetected": 0,
                "reputation": -3, "registrar": "Example Registrar", "creation_date": 1500000000,
            }],
        },
        "abuseipdb": {
            "ip_results": [{
                "status": "completed", "indicator": "203.0.113.9",
                "abuse_confidence_score": 92, "total_reports": 40,
                "country_code": "US", "isp": "Example ISP", "domain": "example.com",
                "usage_type": "Data Center/Web Hosting/Transit", "last_reported_at": "2026-08-01T00:00:00+00:00",
            }],
        },
        "alienvault_otx": {
            "otx_results": [{
                "status": "completed", "indicator": "203.0.113.9", "indicator_type": "IPv4",
                "pulse_count": 4, "related_pulses": ["Botnet C2 tracker"],
                "sections_available": ["general", "reputation"],
            }],
        },
        "notes": [],
    }
    bundle.update(overrides)
    return bundle


def _full_result(**overrides) -> dict:
    """A complete, real-shaped run_threat_intel_for_dashboard() return dict
    -- exactly threat_intel.py:1250-1275's key set."""
    result = {
        "agent": "Threat Intelligence Enrichment",
        "agent_source": "threat_intel.py",
        "status": "completed",
        "current_stage": "threat_intelligence_completed",
        "created_at": "2026-08-20T10:05:00+00:00",
        "summary": "Threat intelligence enrichment completed with High enrichment risk.",
        "enrichment_risk_score": 80,
        "enrichment_risk_level": "High",
        "enrichment_risk_reasons": [
            "VirusTotal reported 5 malicious detection(s) for the file hash.",
        ],
        "threat_intelligence": _full_provider_bundle(),
        "notes": [],
        "warnings": [],
        "enriched_alert": {"incident_id": "INC-1", "source_ip": "203.0.113.9"},
        "output_files": {
            "enriched_alert_json": "/tmp/outputs/threat_intel/enriched_alert.json",
            "docx": "generate_on_download",
            "pdf": "generate_on_download",
        },
        "export_status": {
            "docx": "generate_on_download",
            "pdf": "generate_on_download",
            "csv": "not_generated",
        },
        "recommended_next_action": "SOC analyst approval is required before Investigation Agent can run.",
    }
    result.update(overrides)
    return result


# =============================================================================
# 1. Real successful TI result validates.
# =============================================================================

def test_real_successful_result_validates():
    output = validate_threat_intel_result(_full_result())
    assert isinstance(output, ThreatIntelResult)
    assert output.status == "completed"
    assert output.enrichment_risk_score == 80
    assert output.enrichment_risk_level == "High"


# =============================================================================
# 2. completed_with_warnings result validates.
# =============================================================================

def test_completed_with_warnings_result_validates():
    raw = _full_result(
        status="completed_with_warnings",
        warnings=["VirusTotal lookup for 203.0.113.9 failed."],
    )
    output = validate_threat_intel_result(raw)
    assert output.status == "completed_with_warnings"
    assert output.warnings == ["VirusTotal lookup for 203.0.113.9 failed."]


# =============================================================================
# 3. enrichment_risk_score requires the correct type.
# =============================================================================

def test_enrichment_risk_score_wrong_type_rejected():
    # A dict/list is never int-coercible, unlike a numeric string ("80"),
    # which Pydantic v2's default (non-strict) int validation accepts.
    raw = _full_result(enrichment_risk_score={"value": 80})
    with pytest.raises(ValidationError):
        validate_threat_intel_result(raw)


def test_enrichment_risk_score_non_numeric_string_rejected():
    raw = _full_result(enrichment_risk_score="high")
    with pytest.raises(ValidationError):
        validate_threat_intel_result(raw)


# =============================================================================
# 4. Invalid enrichment_risk_level is rejected.
# =============================================================================

def test_invalid_enrichment_risk_level_rejected():
    raw = _full_result(enrichment_risk_level="Critical")
    with pytest.raises(ValidationError):
        validate_threat_intel_result(raw)


def test_unknown_enrichment_risk_level_rejected():
    raw = _full_result(enrichment_risk_level="Unknown")
    with pytest.raises(ValidationError):
        validate_threat_intel_result(raw)


# =============================================================================
# 5. warnings must be list[str].
# =============================================================================

def test_warnings_must_be_a_list():
    raw = _full_result(warnings="VirusTotal lookup failed.")
    with pytest.raises(ValidationError):
        validate_threat_intel_result(raw)


def test_warnings_entries_must_be_strings():
    raw = _full_result(warnings=[{"provider": "VirusTotal"}])
    with pytest.raises(ValidationError):
        validate_threat_intel_result(raw)


# =============================================================================
# 6. enrichment_risk_reasons must be list[str].
# =============================================================================

def test_enrichment_risk_reasons_must_be_a_list():
    raw = _full_result(enrichment_risk_reasons="VirusTotal reported malicious detections.")
    with pytest.raises(ValidationError):
        validate_threat_intel_result(raw)


def test_enrichment_risk_reasons_entries_must_be_strings():
    raw = _full_result(enrichment_risk_reasons=[42])
    with pytest.raises(ValidationError):
        validate_threat_intel_result(raw)


# =============================================================================
# 7. Unknown top-level fields are rejected.
# =============================================================================

def test_unknown_top_level_field_rejected():
    raw = _full_result(ioc_summary="[NETWORK] 203.0.113.9 flagged")
    with pytest.raises(ValidationError):
        validate_threat_intel_result(raw)


def test_unknown_top_level_field_incident_id_rejected():
    """incident_id/run_id/stage/generated_at are workflow-added by
    workflow/engine.py::run_threat_intel()'s re-keying -- they are not part
    of this producer's own return shape and must not silently validate."""
    raw = _full_result(incident_id="INC-1", run_id="run-a", stage="threat_intelligence")
    with pytest.raises(ValidationError):
        validate_threat_intel_result(raw)


# =============================================================================
# 8. Missing required top-level field is rejected.
# =============================================================================

@pytest.mark.parametrize("missing_field", [
    "agent", "agent_source", "status", "current_stage", "created_at", "summary",
    "enrichment_risk_score", "enrichment_risk_level", "enrichment_risk_reasons",
    "threat_intelligence", "notes", "warnings", "enriched_alert",
    "output_files", "export_status", "recommended_next_action",
])
def test_missing_required_top_level_field_rejected(missing_field):
    raw = _full_result()
    del raw[missing_field]
    with pytest.raises(ValidationError):
        validate_threat_intel_result(raw)


# =============================================================================
# 9-11. Provider bundle accepts the real VirusTotal / AbuseIPDB / OTX shapes.
# =============================================================================

def test_provider_bundle_accepts_real_virustotal_shape():
    bundle = ThreatIntelProviderBundle.model_validate(_full_provider_bundle())
    assert isinstance(bundle.virustotal, VirusTotalResults)
    assert bundle.virustotal.file_hash["malicious"] == 5
    assert bundle.virustotal.ip_results[0]["country"] == "US"
    assert bundle.virustotal.domain_results[0]["registrar"] == "Example Registrar"


def test_provider_bundle_accepts_real_abuseipdb_shape():
    bundle = ThreatIntelProviderBundle.model_validate(_full_provider_bundle())
    assert isinstance(bundle.abuseipdb, AbuseIPDBResults)
    assert bundle.abuseipdb.ip_results[0]["abuse_confidence_score"] == 92


def test_provider_bundle_accepts_real_otx_shape():
    bundle = ThreatIntelProviderBundle.model_validate(_full_provider_bundle())
    assert isinstance(bundle.alienvault_otx, AlienVaultOTXResults)
    assert bundle.alienvault_otx.otx_results[0]["pulse_count"] == 4


# =============================================================================
# 12. Provider skipped/error result shapes still validate (heterogeneous
# per-lookup payloads are intentionally dict[str, Any]).
# =============================================================================

def test_provider_skipped_and_error_shapes_still_validate():
    bundle_dict = _full_provider_bundle(
        virustotal={
            "file_hash": {"status": "skipped", "reason": "No file hash was available."},
            "ip_results": [{"status": "error", "indicator": "203.0.113.9",
                             "status_code": 503, "response": "Service Unavailable"}],
            "domain_results": [],
        },
        abuseipdb={"ip_results": [{"status": "skipped", "reason": "ABUSEIPDB_API_KEY is missing."}]},
        alienvault_otx={"otx_results": [{"status": "not_found", "indicator": "x", "indicator_type": "domain"}]},
    )
    bundle = ThreatIntelProviderBundle.model_validate(bundle_dict)
    assert bundle.virustotal.file_hash["status"] == "skipped"
    assert bundle.virustotal.ip_results[0]["status"] == "error"
    assert bundle.abuseipdb.ip_results[0]["status"] == "skipped"


# =============================================================================
# 13. No-IOC result validates (real run_threat_intel_for_dashboard() call,
# every provider skipped -- no API keys, no network).
# =============================================================================

def test_no_ioc_result_validates(monkeypatch, tmp_path):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    with patch("requests.get") as m:
        result = ti.run_threat_intel_for_dashboard({}, output_dir=tmp_path)
        m.assert_not_called()
    assert result["status"] == "completed"
    assert result["enrichment_risk_score"] == 0
    assert result["enrichment_risk_level"] == "Low"
    validate_threat_intel_result(result)


# =============================================================================
# 14. enriched_alert remains compatible with the current rich dict (loose
# dict[str, Any], not modelled field-by-field).
# =============================================================================

def test_enriched_alert_accepts_arbitrary_rich_shape():
    raw = _full_result(enriched_alert={
        "incident_id": "INC-1", "source_ip": "203.0.113.9",
        "powershell_analysis": {"decode_status": "success", "nested": {"a": [1, 2, 3]}},
        "raw_incident": {"alertMeta": {"AnyField": "AnyValue"}},
    })
    output = validate_threat_intel_result(raw)
    assert output.enriched_alert["powershell_analysis"]["nested"]["a"] == [1, 2, 3]


# =============================================================================
# 15. Serialization preserves the pre-contract external dict shape.
# =============================================================================

def test_dump_preserves_exact_key_set():
    raw = _full_result()
    dumped = dump_threat_intel_result(validate_threat_intel_result(raw))
    assert set(dumped.keys()) == set(raw.keys())
    assert set(dumped["threat_intelligence"].keys()) == set(raw["threat_intelligence"].keys())
    assert set(dumped["threat_intelligence"]["virustotal"].keys()) == set(raw["threat_intelligence"]["virustotal"].keys())


def test_dump_round_trips_values_unchanged():
    raw = _full_result()
    dumped = dump_threat_intel_result(validate_threat_intel_result(raw))
    assert dumped == raw
    # JSON round-trip must also be lossless (no type drift through model_dump).
    assert json.loads(json.dumps(dumped)) == raw


def test_run_threat_intel_for_dashboard_return_shape_matches_contract_field_set(monkeypatch, tmp_path):
    """End-to-end: the real producer's return value, post-Phase-2 wiring,
    has exactly the ThreatIntelResult field set -- no more, no less."""
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    result = ti.run_threat_intel_for_dashboard({"source_ip": "10.0.0.5"}, output_dir=tmp_path)
    assert set(result.keys()) == set(ThreatIntelResult.model_fields.keys())


# =============================================================================
# 16. Workflow still persists the same result shape (disk round-trip).
# =============================================================================

def test_persisted_threat_intel_result_json_round_trips_through_contract(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_API_KEY", "test-vt-key")
    # AbuseIPDB/OTX keys deliberately left unset: with an IP indicator
    # present, both are "applicable" but unconfigured, so the real producer
    # correctly reports status="completed_with_warnings" here -- this test
    # is about the disk/return-value shape staying identical, not about
    # forcing a particular status value.
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    resp = _ok_json_response({"data": {"attributes": {
        "last_analysis_stats": {"malicious": 5, "suspicious": 0}, "reputation": -10}}})
    with patch("requests.get", return_value=resp):
        result = ti.run_threat_intel_for_dashboard(
            {"source_ip": "203.0.113.9"}, output_dir=tmp_path)

    on_disk = json.loads((tmp_path / "threat_intel_result.json").read_text())
    assert on_disk == result
    # The persisted file itself must validate against the same contract.
    validate_threat_intel_result(on_disk)
    assert result["status"] in ("completed", "completed_with_warnings")
    assert result["enrichment_risk_score"] > 0


# =============================================================================
# Bonus: the IOC bucket model matches extract_iocs()'s real return shape
# directly (not only through the full result).
# =============================================================================

def test_ioc_bucket_model_matches_extract_iocs_output():
    real_iocs = ti.extract_iocs({
        "source_ip": "203.0.113.9",
        "event_domain": "malicious.example.com",
        "possible_file_name": None,
        "file_hash": None,
    })
    parsed = ThreatIntelIOCs.model_validate(real_iocs)
    assert parsed.possible_file_name is None
    assert parsed.file_hash is None
    assert parsed.ip_indicators == ["203.0.113.9"]
