"""Whole-enrichment AI summary for the Threat Intelligence stage.

The summary is generated from a compact, indicator-attributed fact packet
(workflow/stage_summaries.py::_threat_intel_summary_packet) instead of a raw
dump of the bundle cut at 9,000 characters — so every provider result is
listed under its own indicator, warnings/gaps/next action always reach the
model, and the packet stays small however many indicators a case has.
Results persisted before the IOC view existed keep the original packet.
"""

from __future__ import annotations

import json
import sys
import types
from unittest.mock import patch

from agents.threat_intelligence import threat_intel as ti
from workflow import stage_summaries as ss
import ti_provider_mocks as mocks


def _fake_openai(monkeypatch, response: str, calls: list) -> None:
    pkg = types.ModuleType("integrations.openai")
    client = types.ModuleType("integrations.openai.client")

    def _invoke(prompt, **kwargs):
        calls.append({"prompt": prompt, **kwargs})
        return response

    client.invoke_openai_text = _invoke
    pkg.client = client
    monkeypatch.setitem(sys.modules, "integrations.openai", pkg)
    monkeypatch.setitem(sys.modules, "integrations.openai.client", client)


def _result(monkeypatch, tmp_path, alert, spec=None, keys=None):
    mocks.apply_keys(monkeypatch, keys)
    with patch("requests.get", side_effect=mocks.provider_router(spec)):
        return ti.run_threat_intel_for_dashboard(alert, output_dir=tmp_path)


MULTI = {"normalised_alert": {"network_indicators": {
    "source_ips": ["192.168.10.201"],
    "destination_ips": ["8.8.8.8", "224.0.0.251", "149.154.167.99", "20.189.173.28"]}}}
SPEC = {"149.154.167.99": {"vt": {"malicious": 9, "as_owner": "Telegram Messenger Inc", "asn": 62041,
                                  "country": "GB"},
                           "abuse": {"score": 89, "reports": 412}, "otx": {"pulses": 50}},
        "20.189.173.28": {"otx": "error"}}


def test_packet_attributes_each_provider_result_to_its_own_indicator(monkeypatch, tmp_path):
    packet = ss._threat_intel_summary_packet(_result(monkeypatch, tmp_path, MULTI, SPEC))
    flagged = packet["enriched_indicators_with_provider_results"]
    assert [f["indicator"] for f in flagged] == ["149.154.167.99"]
    assert flagged[0]["provider_results"]["VirusTotal"] == "9/99 vendors malicious"
    assert flagged[0]["provider_results"]["AbuseIPDB"].startswith("89% abuse confidence, 412 reports")
    assert flagged[0]["owner"] == "Telegram Messenger Inc / AS62041 / GB"
    # 8.8.8.8 had no detections, reports or pulses — it is listed as such,
    # never next to another indicator's findings.
    assert "8.8.8.8" in packet["enriched_indicators_with_no_detections_reports_or_pulses"]
    assert packet["lookup_failures"] == ["AlienVault OTX for 20.189.173.28: HTTP 500"]
    assert packet["excluded_indicators_by_reason"] == {
        "Private/internal address": 1,
        "Multicast address — group/local traffic, not a public host": 1}
    assert packet["indicator_coverage"]["enriched"] == 3


def test_packet_always_carries_warnings_gaps_and_next_action(monkeypatch, tmp_path):
    result = _result(monkeypatch, tmp_path, MULTI, SPEC)
    context = ss._stage_ai_summary_context("Threat Intelligence Enrichment", result)
    packet = json.loads(context)
    assert packet["warnings"] == result["warnings"]
    assert packet["intelligence_gaps"] == result["threat_intelligence"]["intelligence_gaps"]
    assert packet["recommended_next_action"] == result["recommended_next_action"]
    assert (packet["enrichment_risk_score"], packet["enrichment_risk_level"]) == (
        result["enrichment_risk_score"], result["enrichment_risk_level"])


def test_packet_stays_bounded_on_large_cases(monkeypatch, tmp_path):
    ips = [f"45.33.{i // 200}.{i % 200 + 1}" for i in range(60)]
    spec = {ip: {"vt": {"malicious": 3}, "otx": {"pulses": 7}} for ip in ips}
    monkeypatch.setenv("TI_MAX_INDICATORS_PER_TYPE", "40")
    result = _result(monkeypatch, tmp_path, {"normalised_alert": {"network_indicators": {"destination_ips": ips}}}, spec)
    context = ss._stage_ai_summary_context("Threat Intelligence Enrichment", result)
    assert len(context) < 9000  # never reaches the generic truncation point
    packet = json.loads(context)  # i.e. complete, valid JSON — not cut mid-way
    assert len(packet["enriched_indicators_with_provider_results"]) == 15
    assert packet["more_enriched_indicators_with_provider_results"] == 25
    assert packet["indicator_coverage"]["skipped_by_limit"] == 20
    assert "recommended_next_action" in packet


def test_ti_summary_uses_the_whole_enrichment_instructions_and_longer_cap(monkeypatch, tmp_path):
    calls: list = []
    reply = ("Three of six indicators were enriched. 149.154.167.99 was flagged by 9 of 99 VirusTotal "
             "vendors. One OTX lookup failed. Review the failure before closing. A fifth sentence is cut.")
    _fake_openai(monkeypatch, reply, calls)
    result = _result(monkeypatch, tmp_path, MULTI, SPEC)
    generated = ss.generate_stage_ai_summary("Threat Intelligence Enrichment", result, model="test-model")
    system = calls[0]["system"]
    assert "two to four" in system and "120 words" in system
    assert "only to the indicator it is listed under" in system
    assert calls[0]["max_output_tokens"] == 300
    assert '"enriched_indicators_with_provider_results"' in calls[0]["prompt"]
    assert generated["ai_summary"].endswith("Review the failure before closing.")
    assert "fifth sentence" not in generated["ai_summary"]


def test_pre_phase_ti_results_keep_the_original_summary_path(monkeypatch):
    calls: list = []
    _fake_openai(monkeypatch, "Done.", calls)
    legacy = {"status": "completed", "enrichment_risk_score": 25, "enrichment_risk_level": "Low",
              "threat_intelligence": {"iocs": {}, "virustotal": {}, "abuseipdb": {}, "alienvault_otx": {}}}
    ss.generate_stage_ai_summary("Threat Intelligence Enrichment", legacy, model="m")
    assert "one or two" in calls[0]["system"] and calls[0]["max_output_tokens"] == 180
    assert '"threat_intelligence"' in calls[0]["prompt"]  # original packet shape


def test_other_stages_are_unchanged(monkeypatch):
    calls: list = []
    _fake_openai(monkeypatch, "Done.", calls)
    for stage in ("Parsing", "Triage", "Investigation", "Reporting"):
        ss.generate_stage_ai_summary(stage, {"status": "completed"}, model="m")
    assert all("one or two" in c["system"] and c["max_output_tokens"] == 180 for c in calls)
