"""IOC-coverage phase of the Threat Intelligence Enrichment stage.

Covers: every eligible indicator enriched (not only the first per type),
roles/origins preserved, non-global exclusion with reasons, the per-type
enrichment limit with visible skips, honest URL handling, retention of
existing provider-response fields, the IOC-centric result contract, and —
mandatory for this phase — that the risk calculation is unchanged.

Provider HTTP is faked by tests/ti_provider_mocks.py.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agents.threat_intelligence import indicators as iv
from agents.threat_intelligence import threat_intel as ti
from agents.threat_intelligence.threat_intel_result import (
    ThreatIntelResult, dump_threat_intel_result, validate_threat_intel_result,
)
import ti_provider_mocks as mocks

GOLDEN = json.loads((Path(__file__).parent / "golden_threat_intel_risk_baseline.json").read_text(encoding="utf-8"))


def _run(monkeypatch, tmp_path, alert, spec=None, keys=None):
    mocks.apply_keys(monkeypatch, keys)
    router = mocks.provider_router(spec)
    with patch("requests.get", side_effect=router):
        result = ti.run_threat_intel_for_dashboard(alert, output_dir=tmp_path)
    return result, router.calls


def _by_value(result):
    return {r["value"]: r for r in result["threat_intelligence"]["indicators"]}


def _parsed(network=None, **sections):
    """A flattened-path alert, shaped like Parsing's normalised_alert."""
    return {"normalised_alert": {"network_indicators": network or {}, **sections}}


# ══════════════════════════════════════════════════════════════════════════
# Phase A — extraction, eligibility, roles, caps
# ══════════════════════════════════════════════════════════════════════════

def test_one_public_ip(monkeypatch, tmp_path):
    result, calls = _run(monkeypatch, tmp_path, {"destination_ip": "188.40.170.197"})
    record = _by_value(result)["188.40.170.197"]
    assert record["status"] == "enriched" and record["roles"] == ["destination"]
    assert record["origins"] == ["Alert field"]
    assert calls == [("vt", "188.40.170.197"), ("abuse", "188.40.170.197"), ("otx", "188.40.170.197")]


def test_multiple_public_ips_are_all_enriched_not_only_the_first(monkeypatch, tmp_path):
    alert = _parsed({"destination_ips": ["8.8.8.8", "20.189.173.28", "149.154.167.99"]})
    result, calls = _run(monkeypatch, tmp_path, alert)
    assert result["threat_intelligence"]["iocs"]["ip_indicators"] == ["8.8.8.8", "20.189.173.28", "149.154.167.99"]
    assert {c[1] for c in calls} == {"8.8.8.8", "20.189.173.28", "149.154.167.99"}
    assert len(result["threat_intelligence"]["virustotal"]["ip_results"]) == 3
    assert result["threat_intelligence"]["coverage"]["enriched"] == 3


def test_source_and_destination_roles_and_origins(monkeypatch, tmp_path):
    alert = _parsed({"source_ips": ["45.33.32.156"], "destination_ips": ["188.40.170.197"]},
                    powershell_analysis={"extracted_iocs": {"public_ips": ["198.51.100.7"]}})
    records = _by_value(_run(monkeypatch, tmp_path, alert)[0])
    assert records["45.33.32.156"]["roles"] == ["source"]
    assert records["188.40.170.197"]["roles"] == ["destination"]
    # A PowerShell-derived IP is never given a source/destination role it did not have.
    assert records["198.51.100.7"]["roles"] == []
    assert records["198.51.100.7"]["origins"] == ["Decoded PowerShell"]


def test_duplicate_indicators_are_merged_with_all_origins(monkeypatch, tmp_path):
    alert = _parsed({"destination_ips": ["188.40.170.197"], "external_ips": ["188.40.170.197"]},
                    ioc_summary={"ips": ["188.40.170.197"], "domains": ["Evil.Example.com", "evil.example.com."]})
    result, calls = _run(monkeypatch, tmp_path, alert)
    records = result["threat_intelligence"]["indicators"]
    assert [r["value"] for r in records].count("188.40.170.197") == 1
    ip = _by_value(result)["188.40.170.197"]
    assert ip["origins"] == ["Parsed network indicators", "Parsed IOC summary"]
    assert [r["value"] for r in records if r["type"] == "domain"] == ["evil.example.com"]
    assert calls.count(("vt", "188.40.170.197")) == 1


@pytest.mark.parametrize("address, category, reason_fragment", [
    ("192.168.10.202", "private", "Private/internal"),
    ("10.0.0.5", "private", "Private/internal"),
    ("224.0.0.251", "multicast", "Multicast"),
    ("239.255.255.250", "multicast", "Multicast"),
    ("255.255.255.255", "broadcast", "Broadcast"),
    ("127.0.0.1", "loopback", "Loopback"),
    ("169.254.10.1", "link_local", "Link-local"),
    ("0.0.0.0", "non_global", "Unspecified"),
    ("100.64.1.1", "private", "Carrier-grade NAT"),
    ("240.0.0.1", "reserved", "Reserved"),
    ("fe80::1", "link_local", "Link-local"),
    ("ff02::1", "multicast", "Multicast"),
    ("fd12:3456::1", "private", "Private/internal"),
    ("::1", "loopback", "Loopback"),
])
def test_non_global_addresses_are_excluded_with_a_reason(monkeypatch, tmp_path, address, category, reason_fragment):
    result, calls = _run(monkeypatch, tmp_path, _parsed({"destination_ips": [address]}))
    record = _by_value(result)[address]
    assert record["status"] == "excluded" and record["eligible"] is False
    assert record["status_category"] == category
    assert reason_fragment in record["status_reason"]
    assert calls == []  # never sent to an external provider


def test_multicast_is_excluded_even_though_ipaddress_calls_it_global():
    import ipaddress
    assert ipaddress.ip_address("224.0.0.251").is_global  # why the explicit multicast check exists
    assert iv.classify_ip("224.0.0.251")[1] == "multicast"


def test_documentation_ranges_stay_eligible_as_before():
    # Kept eligible deliberately (fixtures/demo stand-ins) — see indicators._DOCUMENTATION_NETWORKS.
    for address in ("203.0.113.5", "198.51.100.7", "192.0.2.1", "2001:db8::1"):
        assert iv.classify_ip(address)[1] is None


def test_ipv6_global_is_enriched_through_existing_endpoints(monkeypatch, tmp_path):
    result, calls = _run(monkeypatch, tmp_path, _parsed({"destination_ips": ["2606:4700:4700::1111"]}))
    assert _by_value(result)["2606:4700:4700::1111"]["status"] == "enriched"
    assert ("otx", "2606:4700:4700::1111") in calls
    otx = result["threat_intelligence"]["alienvault_otx"]["otx_results"][0]
    assert otx["indicator_type"] == "IPv6"


def test_multiple_domains(monkeypatch, tmp_path):
    alert = _parsed(web_indicators={"domains": ["evil.example.com", "c2.example.net"]},
                    user_and_host_indicators={"domains": ["CORPDOMAIN", "dc01.corp.local"]})
    result, calls = _run(monkeypatch, tmp_path, alert)
    records = _by_value(result)
    assert records["evil.example.com"]["status"] == "enriched"
    assert records["c2.example.net"]["status"] == "enriched"
    assert records["corpdomain"]["status_category"] == "internal_hostname"
    assert records["dc01.corp.local"]["status_category"] == "internal_domain"
    assert ("vt", "dc01.corp.local") not in calls


def test_multiple_hashes_keep_file_hash_as_the_first(monkeypatch, tmp_path):
    h1, h2 = "a" * 64, "b" * 40
    alert = _parsed(file_indicators={"file_hashes": [h1, h2, "not-a-hash"]})
    result, calls = _run(monkeypatch, tmp_path, alert, {h2: {"vt": {"malicious": 3}}})
    vt = result["threat_intelligence"]["virustotal"]
    assert vt["file_hash"]["indicator"] == h1  # single value read by calculate_enrichment_risk()
    assert [r["indicator"] for r in vt["file_hash_results"]] == [h1, h2]
    assert result["threat_intelligence"]["iocs"]["file_hashes"] == [h1, h2]
    records = _by_value(result)
    assert records[h2]["hash_type"] == "sha1"
    assert records["not-a-hash"]["status_category"] == "invalid"
    assert ("otx", h2) in calls


def test_url_is_extracted_but_honestly_not_enriched(monkeypatch, tmp_path):
    url = "https://bad.example.net/payload.exe"
    result, calls = _run(monkeypatch, tmp_path, {"url": url})
    records = _by_value(result)
    assert records[url]["status"] == "excluded" and records[url]["status_category"] == "unsupported_type"
    assert "URL reputation lookups are not implemented" in records[url]["status_reason"]
    assert records["bad.example.net"]["origins"] == ["Derived from URL"]
    assert records["bad.example.net"]["status"] == "enriched"
    assert not any(url in c[1] for c in calls)
    assert any("URL(s) extracted but not enriched" in g for g in result["threat_intelligence"]["intelligence_gaps"])


def test_enrichment_limit_records_skipped_indicators_and_sends_no_request(monkeypatch, tmp_path):
    monkeypatch.setenv("TI_MAX_INDICATORS_PER_TYPE", "2")
    ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "149.154.167.99"]
    alert = _parsed({"destination_ips": ips + ["192.168.1.5"]})
    result, calls = _run(monkeypatch, tmp_path, alert)
    records = _by_value(result)
    assert [records[ip]["status"] for ip in ips] == ["enriched", "enriched", "skipped", "skipped"]
    assert records["9.9.9.9"]["status_category"] == "limit"
    assert "Enrichment limit reached" in records["9.9.9.9"]["status_reason"]
    assert {c[1] for c in calls} == {"8.8.8.8", "1.1.1.1"}
    cov = result["threat_intelligence"]["coverage"]
    assert (cov["extracted"], cov["eligible"], cov["enriched"], cov["skipped_by_limit"], cov["excluded"]) == (5, 4, 2, 2, 1)
    assert cov["limit_per_type"] == 2
    assert any("enrichment limit of 2" in g for g in result["threat_intelligence"]["intelligence_gaps"])


def test_invalid_limit_falls_back_to_default(monkeypatch):
    for raw in ("0", "-3", "abc", ""):
        monkeypatch.setenv("TI_MAX_INDICATORS_PER_TYPE", raw)
        assert iv.max_indicators_per_type() == iv.DEFAULT_MAX_INDICATORS_PER_TYPE


def test_alert_meta_multi_values_are_all_collected():
    flat = ti._build_flat_alert({"alertMeta": {"DestinationIp": ["8.8.8.8", "1.1.1.1"]}}, {}, {})
    flat = ti.flatten_alert_for_enrichment(flat)
    assert flat["destination_ip"] == "8.8.8.8"  # unchanged scalar for existing consumers
    assert ti.extract_iocs(flat)["ip_indicators"] == ["8.8.8.8", "1.1.1.1"]


# ══════════════════════════════════════════════════════════════════════════
# Phase B — provider results retained from the existing responses
# ══════════════════════════════════════════════════════════════════════════

def test_virustotal_ip_detail_extraction(monkeypatch, tmp_path):
    result, calls = _run(monkeypatch, tmp_path, {"destination_ip": "188.40.170.197"},
                         {"188.40.170.197": {"vt": {"malicious": 9, "tags": ["scanner"]}}})
    assert calls.count(("vt", "188.40.170.197")) == 1  # no extra request for the extra fields
    vt = _by_value(result)["188.40.170.197"]["providers"]["virustotal"]
    assert (vt["malicious"], vt["analysed_vendors"]) == (9, 99)
    assert vt["tags"] == ["scanner"]
    assert len(vt["top_detections"]) == 8 and vt["detecting_engine_count"] == 9
    assert vt["last_analysed_at"].startswith("2024-05-29")
    context = {r["label"]: r for r in _by_value(result)["188.40.170.197"]["context"]}
    assert context["ASN"]["value"] == "AS24940" and context["AS owner"]["value"] == "Hetzner Online GmbH"
    assert context["Country"]["sources"] == ["VirusTotal", "AbuseIPDB"]


def test_virustotal_domain_and_file_detail_extraction(monkeypatch, tmp_path):
    result, _ = _run(monkeypatch, tmp_path, {"event_domain": "evil.example.com", "file_hash": "c" * 64},
                     {"evil.example.com": {"vt": {"malicious": 2}}, "c" * 64: {"vt": {"malicious": 40}}})
    records = _by_value(result)
    domain_ctx = {r["label"]: r["value"] for r in records["evil.example.com"]["context"]}
    assert domain_ctx["Registrar"] == "Example Registrar"
    assert domain_ctx["Domain registered"].startswith("2023-11-14")
    assert domain_ctx["Domain age (at enrichment)"].endswith("days")
    file_vt = records["c" * 64]["providers"]["virustotal"]
    assert file_vt["popular_threat_label"] == "trojan.emotet/heodo"
    assert file_vt["popular_threat_names"] == ["emotet", "heodo"]
    assert file_vt["first_submitted_at"].startswith("2020-09-13")
    labels = [r["label"] for r in records["c" * 64]["freshness"]]
    assert "First submitted to VirusTotal" in labels and "First seen" not in labels


def test_abuseipdb_detail_extraction_without_reporter_data(monkeypatch, tmp_path):
    spec = {"188.40.170.197": {"abuse": {"score": 89, "reports": 412, "users": 37, "tor": True,
                                         "report_categories": [[18, 22], [14], [18]]}}}
    result, _ = _run(monkeypatch, tmp_path, {"destination_ip": "188.40.170.197"}, spec)
    abuse = _by_value(result)["188.40.170.197"]["providers"]["abuseipdb"]
    assert (abuse["abuse_confidence_score"], abuse["total_reports"], abuse["is_tor"]) == (89, 412, True)
    assert abuse["report_categories"][0] == {"id": 18, "name": "Brute-Force", "count": 2}
    raw = json.dumps(result)
    assert "PRIVATE COMMENT" not in raw and "4242" not in raw  # no reporter identity / comments retained


def test_otx_detail_extraction(monkeypatch, tmp_path):
    result, _ = _run(monkeypatch, tmp_path, {"destination_ip": "188.40.170.197"},
                     {"188.40.170.197": {"otx": {"pulses": 7}}})
    otx = _by_value(result)["188.40.170.197"]["providers"]["otx"]
    assert otx["pulse_count"] == 7 and len(otx["pulses"]) == 5
    assert otx["malware_families"] == ["Emotet"] and otx["adversaries"] == ["TA542"]
    assert otx["attack_ids"] == ["T1071"] and "c2" in otx["pulse_tags"]
    assert otx["latest_pulse_modified"].startswith("2026-07")


@pytest.mark.parametrize("provider, mode", [("vt", "error"), ("abuse", "rate_limited"), ("otx", "raise")])
def test_provider_failures_are_recorded_per_indicator(monkeypatch, tmp_path, provider, mode):
    result, _ = _run(monkeypatch, tmp_path, {"destination_ip": "188.40.170.197"},
                     {"188.40.170.197": {provider: mode}})
    key = {"vt": "virustotal", "abuse": "abuseipdb", "otx": "otx"}[provider]
    evidence = _by_value(result)["188.40.170.197"]["providers"][key]
    assert evidence["status"] == "error"
    assert result["status"] == "completed_with_warnings"
    coverage = result["threat_intelligence"]["provider_coverage"][key]
    assert (coverage["failed"], coverage["state"]) == (1, "failed")
    assert any("lookup failed for 1 indicator" in g for g in result["threat_intelligence"]["intelligence_gaps"])


def test_virustotal_not_found_is_a_gap_not_a_failure(monkeypatch, tmp_path):
    result, _ = _run(monkeypatch, tmp_path, {"file_hash": "d" * 64}, {"d" * 64: {"vt": "not_found"}})
    cov = result["threat_intelligence"]["provider_coverage"]["virustotal"]
    assert (cov["not_found"], cov["failed"]) == (1, 0)
    assert any("VirusTotal had no record for 1 indicator" in g for g in result["threat_intelligence"]["intelligence_gaps"])


def test_no_provider_credentials(monkeypatch, tmp_path):
    result, calls = _run(monkeypatch, tmp_path, {"destination_ip": "188.40.170.197"}, keys=[])
    record = _by_value(result)["188.40.170.197"]
    assert calls == []
    assert record["status"] == "skipped" and record["status_category"] == "no_provider"
    assert record["providers"]["virustotal"]["status"] == "not_configured"
    assert all(p["state"] == "not_configured" for p in result["threat_intelligence"]["provider_coverage"].values())
    assert result["threat_intelligence"]["coverage"]["enriched"] == 0


def test_partial_provider_coverage(monkeypatch, tmp_path):
    result, _ = _run(monkeypatch, tmp_path, {"destination_ip": "188.40.170.197", "event_domain": "evil.example.com"},
                     keys=["VT_API_KEY", "OTX_API_KEY"])
    cov = result["threat_intelligence"]["provider_coverage"]
    assert (cov["virustotal"]["queried"], cov["virustotal"]["applicable"], cov["virustotal"]["state"]) == (2, 2, "available")
    assert (cov["abuseipdb"]["applicable"], cov["abuseipdb"]["state"], cov["abuseipdb"]["configured"]) == (1, "not_configured", False)
    assert any("AbuseIPDB was not queried for 1 applicable indicator" in g
               for g in result["threat_intelligence"]["intelligence_gaps"])


def test_provider_not_applicable_when_nothing_to_look_up(monkeypatch, tmp_path):
    result, _ = _run(monkeypatch, tmp_path, {"event_domain": "evil.example.com"})
    assert result["threat_intelligence"]["provider_coverage"]["abuseipdb"]["state"] == "not_applicable"
    assert _by_value(result)["evil.example.com"]["providers"]["abuseipdb"] == {"status": "not_applicable"}


def test_no_eligible_indicators(monkeypatch, tmp_path):
    result, calls = _run(monkeypatch, tmp_path, _parsed({"source_ips": ["192.168.10.20"],
                                                         "destination_ips": ["224.0.0.251"]}))
    block = result["threat_intelligence"]
    assert calls == [] and block["coverage"]["provider_requests"] == 0
    assert block["coverage"]["eligible"] == 0 and block["coverage"]["excluded"] == 2
    assert "No eligible external indicators were available — no provider requests were made." in block["intelligence_gaps"]
    # Existing contract preserved: no data still reads as the engine's Low/0.
    assert (result["enrichment_risk_level"], result["enrichment_risk_score"]) == ("Low", 0)


# ══════════════════════════════════════════════════════════════════════════
# Phase C — contract and backwards compatibility
# ══════════════════════════════════════════════════════════════════════════

def test_new_result_validates_against_extended_contract(monkeypatch, tmp_path):
    result, _ = _run(monkeypatch, tmp_path, _parsed({"destination_ips": ["8.8.8.8", "224.0.0.251"]}))
    parsed = validate_threat_intel_result(result)
    assert isinstance(parsed, ThreatIntelResult)
    assert parsed.threat_intelligence.coverage.enriched == 1
    assert dump_threat_intel_result(parsed) == result


def test_pre_phase_result_round_trips_with_its_original_key_set():
    legacy = json.loads((Path(__file__).parent / "golden_threat_intel_risk_baseline.json").read_text(encoding="utf-8"))
    assert legacy  # sanity: fixture present
    old = {
        "agent": "Threat Intelligence Enrichment", "agent_source": "threat_intel.py", "status": "completed",
        "current_stage": "threat_intelligence_completed", "created_at": "2026-01-01T00:00:00+00:00",
        "summary": "s", "enrichment_risk_score": 0, "enrichment_risk_level": "Low", "enrichment_risk_reasons": [],
        "threat_intelligence": {
            "iocs": {"possible_file_name": None, "file_hash": None, "ip_indicators": [], "domain_indicators": [],
                     "url_indicators": [], "powershell_analysis": {}, "powershell_enrichment_note": "n"},
            "virustotal": {"file_hash": {"status": "skipped"}, "ip_results": [], "domain_results": []},
            "abuseipdb": {"ip_results": []}, "alienvault_otx": {"otx_results": []}, "notes": []},
        "notes": [], "warnings": [], "enriched_alert": {}, "output_files": {}, "export_status": {},
        "recommended_next_action": "x",
    }
    assert dump_threat_intel_result(validate_threat_intel_result(old)) == old


def test_existing_fields_keep_their_shapes(monkeypatch, tmp_path):
    result, _ = _run(monkeypatch, tmp_path, {"destination_ip": "188.40.170.197", "event_domain": "evil.example.com"})
    block = result["threat_intelligence"]
    assert all(isinstance(v, str) for v in block["iocs"]["ip_indicators"] + block["iocs"]["domain_indicators"])
    assert isinstance(block["virustotal"]["file_hash"], dict)
    assert all(isinstance(r, dict) for r in block["virustotal"]["ip_results"] + block["alienvault_otx"]["otx_results"])
    assert "sections_available" in block["alienvault_otx"]["otx_results"][0]  # retained (removal needs approval)


def test_new_keys_survive_the_display_sanitiser(monkeypatch, tmp_path):
    from backend.services.case_view_service import _sanitize_for_display
    result, _ = _run(monkeypatch, tmp_path, {"destination_ip": "188.40.170.197"})
    shown = _sanitize_for_display(result)["threat_intelligence"]
    assert "«redacted»" not in json.dumps(shown)
    assert shown["indicators"] == result["threat_intelligence"]["indicators"]
    assert shown["provider_coverage"] == result["threat_intelligence"]["provider_coverage"]


def test_engine_envelope_carries_the_ioc_view_to_investigation_and_reporting(monkeypatch, tmp_path):
    from workflow import engine
    mocks.apply_keys(monkeypatch, None)
    monkeypatch.setattr(engine, "REP_DIR", tmp_path)
    with patch("requests.get", side_effect=mocks.provider_router()):
        envelope = engine.run_threat_intel("INC-T", "run-1", {"destination_ip": "8.8.8.8"}, {"ticket": {}})
    assert envelope["threat_intelligence"]["indicators"][0]["value"] == "8.8.8.8"
    context = engine.build_investigation_threat_intel_context(envelope)
    assert "Risk Level: Low" in context


# ══════════════════════════════════════════════════════════════════════════
# Risk regression — the scoring algorithm is unchanged (mandatory)
# ══════════════════════════════════════════════════════════════════════════

# SHA-256 of inspect.getsource(calculate_enrichment_risk) at git HEAD 948abf9,
# before this phase. Any edit to the function — weights, thresholds, levels,
# reasons — changes it.
_RISK_SOURCE_SHA256 = "4fe68deb85c19037a38b9b70d63f207faa8c0520971770ef3a87f1b75ffde420"


def test_calculate_enrichment_risk_source_is_byte_for_byte_unchanged():
    digest = hashlib.sha256(inspect.getsource(ti.calculate_enrichment_risk).encode("utf-8")).hexdigest()
    assert digest == _RISK_SOURCE_SHA256


@pytest.mark.parametrize("name", sorted(mocks.RISK_REGRESSION_SCENARIOS))
def test_risk_output_identical_to_pre_phase_engine(monkeypatch, tmp_path, name):
    scenario = mocks.RISK_REGRESSION_SCENARIOS[name]
    result, calls = _run(monkeypatch, tmp_path, scenario["alert"], scenario["spec"], scenario["keys"])
    golden = GOLDEN["scenarios"][name]
    for field in mocks.RISK_FIELDS:
        assert result[field] == golden[field], field
    # Same provider requests. Compared as a multiset: the pre-phase engine
    # built ip_indicators with list(set(...)), so its order between two IPs
    # depended on the process hash seed; the new order is deterministic.
    assert sorted(map(tuple, golden["provider_calls"])) == sorted(calls)


@pytest.mark.parametrize("evidence, expected", [
    ({}, (0, "Low")),
    ({"abuseipdb": {"ip_results": [{"status": "completed", "indicator": "x", "abuse_confidence_score": 29}]}}, (0, "Low")),
    ({"abuseipdb": {"ip_results": [{"status": "completed", "indicator": "x", "abuse_confidence_score": 30}]}}, (15, "Low")),
    ({"abuseipdb": {"ip_results": [{"status": "completed", "indicator": "x", "abuse_confidence_score": 80}]}}, (30, "Medium")),
    ({"virustotal": {"file_hash": {"status": "completed", "malicious": 1, "suspicious": 0}}}, (40, "Medium")),
    ({"virustotal": {"file_hash": {"status": "completed", "malicious": 60, "suspicious": 0}}}, (40, "Medium")),
    ({"virustotal": {"file_hash": {"status": "completed", "malicious": 1, "suspicious": 1},
                     "ip_results": [{"status": "completed", "indicator": "x", "malicious": 1, "suspicious": 0}]}},
     (80, "High")),
    ({"alienvault_otx": {"otx_results": [{"status": "completed", "indicator": "x", "pulse_count": 1}] * 3}}, (60, "Medium")),
    ({"alienvault_otx": {"otx_results": [{"status": "completed", "indicator": "x", "pulse_count": 1}] * 14}}, (280, "High")),
])
def test_threshold_behaviour_unchanged(evidence, expected):
    """1 vs 60 detections still score the same, thresholds stay 30/70,
    and the score stays additive and uncapped — exactly as before."""
    risk = ti.calculate_enrichment_risk(evidence)
    assert (risk["enrichment_risk_score"], risk["enrichment_risk_level"]) == expected


def test_extra_hashes_do_not_feed_the_unchanged_risk_calculation(monkeypatch, tmp_path):
    """calculate_enrichment_risk() reads only virustotal.file_hash, so a
    second hash's VirusTotal detections are shown but not scored — a known
    consequence of leaving the algorithm untouched (recorded for the Risk
    phase). OTX results for every hash are scored, as for every other OTX
    lookup."""
    h1, h2 = "a" * 64, "b" * 64
    result, _ = _run(monkeypatch, tmp_path, _parsed(file_indicators={"file_hashes": [h1, h2]}),
                     {h2: {"vt": {"malicious": 30}}})
    assert result["enrichment_risk_score"] == 0
    assert _by_value(result)[h2]["providers"]["virustotal"]["malicious"] == 30


def test_previously_dropped_evidence_now_reaches_the_unchanged_algorithm(monkeypatch, tmp_path):
    """Documented, legitimate difference: before this phase only the first
    destination IP (8.8.8.8) was looked up and the case scored Low/0. The
    same unchanged algorithm now sees 149.154.167.99's evidence."""
    alert = _parsed({"source_ips": ["192.168.10.201"],
                     "destination_ips": ["8.8.8.8", "224.0.0.251", "149.154.167.99"]})
    result, calls = _run(monkeypatch, tmp_path, alert,
                         {"149.154.167.99": {"vt": {"malicious": 9}, "abuse": {"score": 89, "reports": 412}}})
    assert (result["enrichment_risk_score"], result["enrichment_risk_level"]) == (55, "Medium")
    assert result["enrichment_risk_reasons"] == [
        "VirusTotal reported 9 malicious detection(s) for IP 149.154.167.99.",
        "AbuseIPDB abuse confidence score is high for 149.154.167.99: 89.",
    ]
    assert ("vt", "224.0.0.251") not in calls
