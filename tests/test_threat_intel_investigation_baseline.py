"""tests/test_threat_intel_investigation_baseline.py -- Threat Intelligence
Phase 5A: baseline Investigation/TI integration coverage.

The Threat Intelligence Phase 4 audit (analysis-only, no code changed) found
six things worth locking down as regression tests BEFORE any future change
to how Threat Intelligence reaches Investigation:

  1. workflow/engine.py::build_investigation_alert() forwards TI-owned
     fields (threat_intelligence_enrichment/enrichment_risk_score/
     enrichment_risk_level/enrichment_risk_reasons) into the queued alert.
  2. agents/investigation/ingest_pipeline.py::serialize_json_to_narrative()
     recursively flattens the queued alert into generic prose; TI's labels
     survive as readable text but with no special framing.
  3. agents/investigation/ingest_pipeline.py::process_log_file() truncates
     that narrative at 12,000 characters.
  4. Real historical fixtures showed TI content CAN be pushed past that
     12,000-character boundary by a large correlated-alert set.
  5. agents/investigation/main.py::generate_local_standalone_report() (the
     deterministic, zero-LLM path taken for a single, uncorrelated alert)
     never reads any TI-owned field -- its severity comes from Triage's
     classification only.
  6. workflow/engine.py::handoff_to_reporting()'s deterministic skills
     sidecar reads the full persisted ThreatIntelResult structurally, with
     no truncation exposure.

This file is a BASELINE/regression suite: every test captures CURRENT
behaviour (including the two known weaknesses -- truncation loss and
single-alert TI-blindness) as-is. None of them assert desired future
behaviour, and this phase makes no runtime change to Investigation or
Threat Intelligence.

No OpenAI/LLM calls are made anywhere in this file -- every code path
exercised here (build_investigation_alert, serialize_json_to_narrative,
process_log_file, generate_local_standalone_report, the skills sidecar
tools) is deterministic and LLM-free by construction.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from workflow import engine as wf

REPO_ROOT = Path(__file__).resolve().parent.parent
INV_DIR = REPO_ROOT / "agents" / "investigation"

# agents/investigation/main.py and its siblings (ingest_pipeline, orchestrator,
# policy_engine, mitre_mapper, ...) import each other by bare module name
# (e.g. "import orchestrator"), so agents/investigation/ itself must be on
# sys.path for those internal imports to resolve -- same pattern already
# used by tests/test_triage_investigation_handoff.py.
sys.path.insert(0, str(INV_DIR))
from agents.investigation import ingest_pipeline  # noqa: E402
from agents.investigation import main as inv_main  # noqa: E402


# =============================================================================
# Shared fixture helpers
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
    (see engine.py:1178-1192) -- the object build_investigation_alert()'s
    threat_intel_result parameter actually receives in production."""
    result = {
        "incident_id": "INC-1001", "run_id": "run-a", "stage": "threat_intelligence",
        "status": "completed", "generated_at": "2026-08-20T10:05:00+00:00",
        "threat_intelligence": {
            "iocs": {"ip_indicators": ["203.0.113.9"], "domain_indicators": []},
            "virustotal": {"file_hash": None, "ip_results": [
                {"status": "completed", "indicator": "203.0.113.9", "malicious": 5}],
                "domain_results": []},
            "abuseipdb": {"ip_results": [
                {"status": "completed", "indicator": "203.0.113.9", "abuse_confidence_score": 92}]},
            "alienvault_otx": {"otx_results": []},
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


PLAYBOOK_PATH = str(INV_DIR / "playbooks" / "privilegeEscalation.yaml")


# =============================================================================
# Section 2 -- Queued-alert handoff baseline.
# =============================================================================

def test_handoff_forwards_all_four_ti_owned_fields_with_exact_values():
    ti_result = _real_threat_intel_result()
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    # threat_intelligence_enrichment passes through prune_empty() (workflow/
    # engine.py), which recursively strips empty sub-values (e.g. an empty
    # domain_results list, a None file_hash placeholder) -- so this is not
    # asserted as byte-identical to the source dict; the real, non-empty
    # provider findings that matter must still survive intact.
    ti_block = alert["threat_intelligence_enrichment"]
    assert ti_block["iocs"]["ip_indicators"] == ["203.0.113.9"]
    assert ti_block["virustotal"]["ip_results"][0]["malicious"] == 5
    assert ti_block["abuseipdb"]["ip_results"][0]["abuse_confidence_score"] == 92
    assert alert["enrichment_risk_score"] == 80
    assert alert["enrichment_risk_level"] == "High"
    assert alert["enrichment_risk_reasons"] == ti_result["enrichment_risk_reasons"]


def test_handoff_without_threat_intel_result_does_not_fabricate_ti_fields():
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=None)
    assert "threat_intelligence_enrichment" not in alert
    assert "enrichment_risk_score" not in alert
    assert "enrichment_risk_level" not in alert
    assert "enrichment_risk_reasons" not in alert


def test_handoff_preserves_zero_enrichment_risk_score():
    """0 is a real, meaningful value (no risk found) -- prune_empty() must
    not treat it as empty/falsy and strip it."""
    ti_result = _real_threat_intel_result(enrichment_risk_score=0, enrichment_risk_level="Low",
                                          enrichment_risk_reasons=["No confirmed malicious "
                                          "external intelligence was found, or no usable IOC "
                                          "was available."])
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    assert alert["enrichment_risk_score"] == 0
    assert "enrichment_risk_score" in alert


def test_handoff_preserves_low_enrichment_risk_level():
    ti_result = _real_threat_intel_result(enrichment_risk_level="Low")
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    assert alert["enrichment_risk_level"] == "Low"


def test_handoff_empty_reasons_list_is_pruned_per_current_prune_empty_semantics():
    """CURRENT baseline behaviour, not a desired outcome: prune_empty()
    (workflow/engine.py) strips any value equal to [] (or None/""/{}/
    "Unknown"), so an empty enrichment_risk_reasons list does not survive
    onto the queued alert at all -- the key is simply absent, not present
    as an empty list."""
    ti_result = _real_threat_intel_result(enrichment_risk_reasons=[])
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    assert "enrichment_risk_reasons" not in alert
    # The other three TI fields are unaffected by one field being pruned.
    assert alert["enrichment_risk_score"] == 80
    assert alert["enrichment_risk_level"] == "High"


# =============================================================================
# Section 3 -- Narrative serialization baseline.
# =============================================================================

def test_narrative_serialization_contains_recognizable_ti_labels():
    ti_result = _real_threat_intel_result()
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    document = ingest_pipeline.serialize_json_to_narrative(alert)

    doc_lower = document.lower()
    assert "enrichment risk score" in doc_lower
    assert "enrichment risk level" in doc_lower
    assert "enrichment risk reasons" in doc_lower
    assert "high" in doc_lower  # the enrichment_risk_level value itself
    # The actual reason text (not just the label) is present, not summarised away.
    assert "abuseipdb abuse confidence score is high for 203.0.113.9" in doc_lower


# =============================================================================
# Section 4 -- Truncation regression baseline.
# =============================================================================

def _sub_alert(i: int) -> dict:
    return {
        "alert_id": f"A-{i}", "title": "Suspicious PowerShell Execution Detected on Endpoint",
        "timestamp": f"2026-08-20T09:{i % 60:02d}:00Z", "severity": "Medium",
        "user": f"user{i}", "hostname": f"HOST-{i:03d}",
        "source_ip": f"10.0.{i // 256}.{i % 256}", "destination_ip": "203.0.113.9",
        "description": "Encoded PowerShell command line observed launching a child "
                       "process with outbound network activity.",
    }


def test_truncation_baseline_small_alert_ti_fields_survive(tmp_path):
    """A. Small alert: TI score/level/reasons must survive well under the
    12,000-character truncation boundary."""
    ti_result = _real_threat_intel_result()
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    alert_path = tmp_path / "small_alert.json"
    alert_path.write_text(json.dumps(alert))
    ingested = ingest_pipeline.process_log_file(str(alert_path))
    document = ingested["document"]

    assert len(document) <= 12000 + len(" [TRUNCATED]")
    assert "[TRUNCATED]" not in document
    doc_lower = document.lower()
    assert "enrichment risk level" in doc_lower
    assert "enrichment risk score" in doc_lower


def test_truncation_baseline_large_correlated_alert_pushes_ti_past_boundary(tmp_path):
    """B. CURRENT WEAKNESS, captured as baseline (not fixed here): a large
    set of correlated sub-alerts is rendered before the generic
    key-by-key serialization pass (which is where enrichment_risk_* sorts
    alphabetically), so enough correlated alerts push TI's risk fields past
    the 12,000-character truncation cutoff entirely. This mirrors the
    mechanism confirmed against this repo's own real historical
    Investigation fixtures during the Phase 4 audit (e.g. INC-52825,
    INC-51772, INC-50573)."""
    ti_result = _real_threat_intel_result()
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    # 80 correlated sub-alerts is enough to reproduce the loss deterministically
    # (confirmed during the Phase 4 audit: ~40 sits at the edge, ~80 fails).
    alert["alerts"] = [_sub_alert(i) for i in range(80)]

    alert_path = tmp_path / "large_correlated_alert.json"
    alert_path.write_text(json.dumps(alert))
    ingested = ingest_pipeline.process_log_file(str(alert_path))
    document = ingested["document"]

    assert document.endswith("[TRUNCATED]")
    assert len(document) == 12000 + len(" [TRUNCATED]")
    doc_lower = document.lower()
    # The demonstrated weakness: TI's risk verdict is gone from what
    # Investigation's LLM-facing document actually contains.
    assert "enrichment risk level" not in doc_lower
    assert "enrichment risk score" not in doc_lower
    assert "enrichment risk reasons" not in doc_lower


def test_truncation_baseline_moderate_correlation_still_survives(tmp_path):
    """Confirms the boundary is genuinely about volume, not a hard rule
    that TI always dies alongside any correlation -- a moderate sub-alert
    count still leaves TI's risk fields intact."""
    ti_result = _real_threat_intel_result()
    alert = wf.build_investigation_alert(_triage_result_kwargs(), _incident_kwargs(),
                                         threat_intel_result=ti_result)
    alert["alerts"] = [_sub_alert(i) for i in range(10)]

    alert_path = tmp_path / "moderate_correlated_alert.json"
    alert_path.write_text(json.dumps(alert))
    ingested = ingest_pipeline.process_log_file(str(alert_path))
    document = ingested["document"]

    assert "[TRUNCATED]" not in document
    assert "enrichment risk level" in document.lower()


# =============================================================================
# Section 5 -- Provider-detail volume baseline.
# =============================================================================

def test_provider_bundle_detail_is_materially_larger_than_compact_ti_fields():
    """Structural point (no arbitrary percentage asserted): serializing the
    full threat_intelligence_enrichment provider bundle (VirusTotal +
    AbuseIPDB + AlienVault OTX raw lookup results) produces materially more
    narrative text than serializing just the compact
    enrichment_risk_score/level/reasons decision fields alone."""
    provider_bundle = {
        "iocs": {"possible_file_name": "invoice.exe", "file_hash": "a" * 64,
                 "ip_indicators": ["203.0.113.1", "203.0.113.2", "203.0.113.3"],
                 "domain_indicators": ["malicious-1.example.com", "malicious-2.example.com"],
                 "url_indicators": [], "powershell_analysis": {}, "powershell_enrichment_note": "n/a"},
        "virustotal": {
            "file_hash": {"status": "completed", "malicious": 12, "suspicious": 3, "harmless": 45,
                          "undetected": 2, "reputation": -30, "meaningful_name": "invoice.exe",
                          "first_submission_date": 1690000000, "last_analysis_date": 1700000000},
            "ip_results": [{"status": "completed", "indicator": ip, "malicious": 1, "suspicious": 1,
                            "harmless": 58, "undetected": 3, "reputation": -12, "country": "RU",
                            "as_owner": "Some Hosting Provider LLC"}
                           for ip in ["203.0.113.1", "203.0.113.2", "203.0.113.3"]],
            "domain_results": [{"status": "completed", "indicator": d, "malicious": 1, "suspicious": 0,
                                "harmless": 58, "undetected": 3, "reputation": -8,
                                "registrar": "Example Registrar Inc.", "creation_date": 1500000000}
                               for d in ["malicious-1.example.com", "malicious-2.example.com"]],
        },
        "abuseipdb": {"ip_results": [{"status": "completed", "indicator": ip,
                                      "abuse_confidence_score": 92, "total_reports": 40,
                                      "country_code": "RU", "isp": "Some Hosting Provider LLC",
                                      "domain": "somehostingprovider.example",
                                      "usage_type": "Data Center/Web Hosting/Transit",
                                      "last_reported_at": "2026-08-01T00:00:00+00:00"}
                                     for ip in ["203.0.113.1", "203.0.113.2", "203.0.113.3"]]},
        "alienvault_otx": {"otx_results": [{"status": "completed", "indicator": ip,
                                            "indicator_type": "IPv4", "pulse_count": 7,
                                            "related_pulses": ["Botnet C2 Tracker", "Emotet Infrastructure"],
                                            "sections_available": ["general", "reputation"]}
                                           for ip in ["203.0.113.1", "203.0.113.2", "203.0.113.3"]]},
        "notes": [],
    }
    compact_fields_alert = {
        "incident_id": "INC-1001",
        "enrichment_risk_score": 95,
        "enrichment_risk_level": "High",
        "enrichment_risk_reasons": [
            "VirusTotal reported 12 malicious detection(s) for the file hash.",
            "AbuseIPDB abuse confidence score is high for 203.0.113.1: 92.",
        ],
    }
    provider_alert = {
        "incident_id": "INC-1001",
        "threat_intelligence_enrichment": provider_bundle,
    }

    compact_doc = ingest_pipeline.serialize_json_to_narrative(compact_fields_alert)
    provider_doc = ingest_pipeline.serialize_json_to_narrative(provider_alert)

    assert len(provider_doc) > len(compact_doc)
    # Not a fixed percentage, just "materially larger" -- at least several
    # times the size, which is what makes it the dominant contributor to
    # truncation pressure once both are present in the same document.
    assert len(provider_doc) > len(compact_doc) * 3


# =============================================================================
# Section 6 -- Sidecar baseline (the enrichment_risk_reasons -> "detail" gap
# not already covered by tests/test_investigation_ti_sidecar_wiring.py,
# which already directly proves enrichment_risk_score/level reach
# diamond_model.build_diamond() and triage_verdict._ti_signal()).
# =============================================================================

def test_sidecar_ti_signal_carries_enrichment_risk_reasons_in_detail():
    from agents.investigation.tools.triage_verdict import _ti_signal

    ti_result = _real_threat_intel_result()
    signal = _ti_signal(ti_result)
    assert signal["level"] == 3
    assert signal["label"] == "high"
    # enrichment_risk_reasons (joined, first two) must reach the sidecar's
    # structured signal -- untruncated, unflattened, read directly off the
    # persisted ThreatIntelResult, unlike the main LLM's narrative path.
    assert "VirusTotal reported 5 malicious detection(s) for IP 203.0.113.9." in signal["detail"]
    assert "AbuseIPDB abuse confidence score is high for 203.0.113.9: 92." in signal["detail"]


# =============================================================================
# Section 7 -- Single-alert deterministic-path baseline (CURRENT
# TI-blindness, not a desired end state). This is deliberately separate
# from the truncation tests above: this path never even reaches
# serialize_json_to_narrative()'s TI content in a meaningful way for its
# OWN decision -- it is architecturally blind to TI regardless of document
# size or truncation.
# =============================================================================

def test_CURRENT_BASELINE_single_alert_standalone_severity_ignores_high_ti_risk(tmp_path):
    """CURRENT baseline behaviour (Phase 4 finding #5), NOT desired final
    behaviour: generate_local_standalone_report() -- the deterministic,
    zero-LLM path taken for a single, uncorrelated queued alert -- computes
    its severity solely from Triage's forwarded classification
    (alert["metadata"]["severity"]). A high-risk Threat Intelligence
    enrichment verdict present in the SAME queued alert has no effect on
    that severity today. This test exists to separate "LLM truncation
    problem" from "single-alert deterministic TI-blindness" -- a future
    phase closing the truncation gap (Phase 4 Option B/D) would NOT, by
    itself, fix what this test captures."""
    ti_result = _real_threat_intel_result(enrichment_risk_score=95, enrichment_risk_level="High")
    triage_result = _triage_result_kwargs(classification="LOW")
    alert = wf.build_investigation_alert(triage_result, _incident_kwargs(),
                                         threat_intel_result=ti_result)
    assert alert["enrichment_risk_level"] == "High"
    assert alert["classification"]["severity"] == "LOW"

    alert_path = tmp_path / "single_alert.json"
    alert_path.write_text(json.dumps(alert))
    ingested = ingest_pipeline.process_log_file(str(alert_path))
    # TI content IS present in the queued alert Investigation ingested...
    assert "enrichment risk level" in ingested["document"].lower()
    # ...but the standalone deterministic path's severity input is Triage's
    # signal only -- confirmed below by main.py's own metadata key.
    assert ingested["metadata"]["severity"] == "LOW"

    result = inv_main.generate_local_standalone_report(ingested, PLAYBOOK_PATH, "Incident-TEST-TI-BLIND")
    # CURRENT (unfixed) behaviour: severity tracks Triage's "LOW" ->
    # "Low", NOT Threat Intelligence's "High" enrichment_risk_level.
    assert result["report"].severity == "Low"
