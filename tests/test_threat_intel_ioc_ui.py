"""IOC-centric Threat Intelligence UI, rendered from REAL engine results.

Each test produces a result with the real enrichment engine (provider HTTP
faked by tests/ti_provider_mocks.py), then renders it with the exported
workspace.js renderers in Node — so the frontend is exercised against the
actual result contract, not a hand-written approximation of it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from agents.threat_intelligence import threat_intel as ti
import ti_provider_mocks as mocks

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_JS = ROOT / "frontend" / "js" / "pages" / "workspace.js"
COMPONENTS_CSS = ROOT / "frontend" / "css" / "components.css"
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")

_JS = """
const ws = await import(__WORKSPACE__);
let input = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) input += chunk;
const { result, workflow } = JSON.parse(input);
const block = result.threat_intelligence || {};
process.stdout.write(JSON.stringify({
  assessment: ws.tiAssessment(result, block),
  overview: ws.tiIndicatorOverview(block),
  skippedExcluded: ws.tiSkippedExcluded(block),
  gaps: ws.tiIntelligenceGaps(result, block),
  raw: ws.tiProviderResults(block),
}));
"""


def _render(result: dict, workflow: dict | None = None) -> dict:
    script = _JS.replace("__WORKSPACE__", json.dumps(WORKSPACE_JS.as_uri()))
    completed = subprocess.run([NODE, "--input-type=module", "-e", script],
                               input=json.dumps({"result": result, "workflow": workflow}),
                               capture_output=True, text=True, encoding="utf-8", timeout=60, check=False)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _result(monkeypatch, tmp_path, alert, spec=None, keys=None, envelope=True):
    mocks.apply_keys(monkeypatch, keys)
    with patch("requests.get", side_effect=mocks.provider_router(spec)):
        result = ti.run_threat_intel_for_dashboard(alert, output_dir=tmp_path)
    if envelope:
        # Shape the frontend actually receives: workflow/engine.py re-keys the
        # result (no top-level `notes`) and stage_summaries adds ai_summary.
        result = {k: result[k] for k in ("status", "threat_intelligence", "enrichment_risk_score",
                                         "enrichment_risk_level", "enrichment_risk_reasons", "warnings",
                                         "summary", "recommended_next_action")}
        result.update(generated_at="2026-10-03T10:00:00+00:00", ai_summary="Post-stage summary text.",
                      ai_summary_model="gpt-test")
    return result


MULTI = {"normalised_alert": {
    "network_indicators": {"source_ips": ["192.168.10.202"],
                           "destination_ips": ["188.40.170.197", "224.0.0.251", "255.255.255.255"]},
    "web_indicators": {"domains": ["evil.example.com"], "urls": ["https://evil.example.com/a.ps1"]},
    "file_indicators": {"file_hashes": ["c" * 64]},
}}
MULTI_SPEC = {"188.40.170.197": {"vt": {"malicious": 9, "tags": ["scanner"]},
                                 "abuse": {"score": 89, "reports": 412, "tor": True, "report_categories": [[22, 18]]},
                                 "otx": {"pulses": 50}},
              "evil.example.com": {"vt": "error"},
              "c" * 64: {"vt": {"malicious": 40}, "otx": "not_found"}}


def test_overall_assessment_header(monkeypatch, tmp_path):
    result = _result(monkeypatch, tmp_path, MULTI, MULTI_SPEC)
    workflow = {"stages": [{"key": "investigation", "state": "not_started"}]}
    html = _render(result, workflow)["assessment"]
    head = html
    # The card is titled "Summary", before everything else in it.
    assert html.startswith('<section class="panel assessment-card ti-assessment"><h3>Summary</h3>')
    # Existing engine values, shown verbatim.
    level = result["enrichment_risk_level"]
    assert f'{result["enrichment_risk_score"]} <span class="ti-risk-level ti-risk-{level.lower()}">({level.upper()})</span>' in head
    # Indicator counts from coverage (actual values).
    cov = result["threat_intelligence"]["coverage"]
    for label in ("Extracted", "Enriched", "Excluded", "Skipped"):
        value = cov[label.lower()]
        assert f"<dt>{label}</dt><dd>{value}</dd>" in head, label
    # Provider coverage from the lookups actually issued.
    assert "Provider Coverage" in head
    assert "3 / 3 queried · 2 returned data · 1 failed" in head  # VirusTotal: IP, domain(error), hash
    assert "1 / 1 queried · 1 returned data" in head  # AbuseIPDB
    # Not shown on the card: recommended action, workflow line, scoring factors.
    assert "<details" not in html
    assert result["recommended_next_action"] not in html
    assert "Investigation has not started yet." not in html
    assert not any(reason in html for reason in result["enrichment_risk_reasons"])


def test_indicator_overview_row(monkeypatch, tmp_path):
    html = _render(_result(monkeypatch, tmp_path, MULTI, MULTI_SPEC))["overview"]
    row = html.split('class="ti-ioc-row"', 2)[2] if html.count('class="ti-ioc-row"') > 1 else html
    ip_row = next(r for r in html.split('<tr class="ti-ioc-row">')[1:] if "188.40.170.197" in r.split("</tr>")[0])
    first = ip_row.split("</tr>", 1)[0]
    assert "Destination" in first
    assert "9 / 99 malicious" in first
    assert "89% · 412 reports" in first and "Tor exit node" in first
    assert "50 pulses" in first
    assert "Hetzner Online GmbH · AS24940 · DE" in first
    assert 'aria-expanded="false"' in first
    # Only enriched indicators appear in the overview.
    for value in ("192.168.10.202", "224.0.0.251", "https://evil.example.com/a.ps1"):
        assert value not in html, value
    assert row  # sanity


def test_overview_cells_distinguish_failure_no_record_and_not_applicable(monkeypatch, tmp_path):
    html = _render(_result(monkeypatch, tmp_path, MULTI, MULTI_SPEC))["overview"]
    rows = {r.split("</tr>", 1)[0].split("title=\"", 1)[1].split("\"", 1)[0]: r.split("</tr>", 1)[0]
            for r in html.split('<tr class="ti-ioc-row">')[1:]}
    domain, hash_row = rows["evil.example.com"], rows["c" * 64]
    assert "Failed" in domain and "state-failed" in domain           # VirusTotal error
    assert "Not applicable" in domain                                # AbuseIPDB never applies to domains
    # The existing OTX lookup reports any non-200 (including 404) as an
    # error, so it is shown as a failure with its HTTP status — never as 0.
    assert "Failed" in hash_row and "HTTP 404" in hash_row
    assert "40 / 130 malicious" in hash_row


def test_indicator_detail_panel(monkeypatch, tmp_path):
    html = _render(_result(monkeypatch, tmp_path, MULTI, MULTI_SPEC))["overview"]
    detail = next(d for d in html.split('class="ti-ioc-detail-row"')[1:] if "188.40.170.197" in d[:400])
    detail = detail.split('<tr class="ti-ioc-row">', 1)[0]
    assert "hidden" in detail.split(">", 1)[0]  # collapsed until Details is selected
    for text in ("Indicator Context", "AS owner", "Hetzner Online GmbH", "Usage type", "Hostnames",
                 "Freshness", "Last VirusTotal analysis", "Last AbuseIPDB report",
                 "Provider Evidence", "not Aegis conclusions",
                 "9 / 99 vendors flagged malicious", "Top detecting vendors (8 of 9)",
                 "Recent report categories", "SSH", "Brute-Force",
                 "Malware families", "Emotet", "TA542", "T1071", "Pulses (5 of 50)",
                 "Found in: Parsed network indicators"):
        assert text in detail, text
    assert "N/A" not in detail


def test_excluded_and_skipped_sections(monkeypatch, tmp_path):
    monkeypatch.setenv("TI_MAX_INDICATORS_PER_TYPE", "1")
    alert = {"normalised_alert": {"network_indicators": {
        "destination_ips": ["188.40.170.197", "45.33.32.156", "224.0.0.251", "255.255.255.255"],
        "source_ips": ["192.168.10.202"]}}}
    html = _render(_result(monkeypatch, tmp_path, alert))["skippedExcluded"]
    skipped, excluded = html.split("Excluded Indicators", 1)
    assert "Skipped Indicators (1)" in skipped and "45.33.32.156" in skipped
    assert "Enrichment limit reached" in skipped
    assert "Excluded Indicators (3)" in "Excluded Indicators" + excluded
    for value, reason in (("192.168.10.202", "Private/internal address"),
                          ("224.0.0.251", "Multicast address"),
                          ("255.255.255.255", "Broadcast address")):
        row = next(r for r in excluded.split("<tr>") if value in r)
        assert reason in row, value
    assert "45.33.32.156" not in excluded


def test_intelligence_gaps_from_real_state_only(monkeypatch, tmp_path):
    result = _result(monkeypatch, tmp_path, MULTI, MULTI_SPEC)
    html = _render(result)["gaps"]
    assert "Intelligence Gaps &amp; Limitations" in html
    assert "VirusTotal lookup for evil.example.com failed." in html          # stage warning, verbatim
    assert "VirusTotal lookup failed for 1 indicator(s) (HTTP 500)." in html
    assert "AlienVault OTX lookup failed for 1 indicator(s) (HTTP 404)." in html
    assert "1 URL(s) extracted but not enriched" in html
    assert "Enrichment engine notes" not in html
    assert "not configured" not in html.lower()  # no credential problem occurred, none claimed


def test_no_eligible_indicators_is_not_presented_as_safe(monkeypatch, tmp_path):
    alert = {"normalised_alert": {"network_indicators": {"source_ips": ["192.168.10.20"],
                                                         "destination_ips": ["224.0.0.251"]}}}
    result = _result(monkeypatch, tmp_path, alert)
    assert (result["enrichment_risk_level"], result["enrichment_risk_score"]) == ("Low", 0)  # contract kept
    out = _render(result)
    head = out["assessment"].split("<details", 1)[0]
    assert "No eligible external indicators were available for enrichment, so no provider requests were made." in head
    assert "not a determination that the incident is safe" in head
    assert "No indicators were enriched in this run" in out["overview"]
    assert "Excluded Indicators (2)" in out["skippedExcluded"]
    assert "No eligible external indicators were available — no provider requests were made." in out["gaps"]


def test_missing_credentials_are_explained(monkeypatch, tmp_path):
    out = _render(_result(monkeypatch, tmp_path, {"destination_ip": "188.40.170.197"}, keys=[]))
    head = out["assessment"].split("<details", 1)[0]
    assert "No provider requests were sent for the eligible indicators" in head
    assert head.count("Not configured") == 3
    assert "Skipped Indicators (1)" in out["skippedExcluded"]
    assert "no applicable provider is configured" in out["skippedExcluded"]
    assert "ABUSEIPDB_API_KEY is not configured" in out["gaps"]


def test_raw_provider_details_collapsed(monkeypatch, tmp_path):
    out = _render(_result(monkeypatch, tmp_path, MULTI, MULTI_SPEC))
    assert out["raw"].startswith('<details class="parsing-field-list ti-raw-details">')
    assert "Available sections" not in out["raw"]
    assert "<th>Harmless</th>" in out["raw"]


def test_ai_summary_is_shown_in_the_assessment_card(monkeypatch, tmp_path):
    result = _result(monkeypatch, tmp_path, MULTI, MULTI_SPEC)
    html = _render(result)["assessment"]
    summary = html.split('class="ti-assessment-cell ti-ai-summary">', 1)[1]
    assert summary.startswith("<h4>AI Summary</h4><p class=\"\">Post-stage summary text.</p>")
    assert "AI-generated after enrichment by gpt-test. Not used in risk scoring." in summary
    # It sits below the score / indicators / coverage boxes.
    assert html.index("Provider Coverage") < html.index("AI Summary")
    # Only once on the page: the separate bottom section stays removed.
    source = WORKSPACE_JS.read_text(encoding="utf-8")
    body = source[source.index("function renderThreatIntelStage"):]
    assert "ai_summary" not in body[:body.index("\n}\n")]


def test_ai_summary_absent_or_unavailable(monkeypatch, tmp_path):
    result = _result(monkeypatch, tmp_path, MULTI, MULTI_SPEC)
    assert "AI Summary" not in _render({**result, "ai_summary": ""})["assessment"]
    failed = _render({**result, "ai_summary": "AI summary unavailable — LLM call failed: timeout"})["assessment"]
    assert '<p class="ti-muted">AI summary unavailable — LLM call failed: timeout</p>' in failed


def test_provider_values_are_escaped(monkeypatch, tmp_path):
    spec = {"188.40.170.197": {"vt": {"tags": ["<img src=x onerror=alert(1)>"], "as_owner": "<b>Evil</b> AS"}}}
    out = _render(_result(monkeypatch, tmp_path, {"destination_ip": "188.40.170.197"}, spec))
    assert "<img src=x" not in out["overview"] and "<b>Evil</b>" not in out["overview"]
    assert "&lt;b&gt;Evil&lt;/b&gt; AS" in out["overview"]


def test_legacy_results_render_without_indicator_sections():
    legacy = {"enrichment_risk_level": "Low", "enrichment_risk_score": 0, "enrichment_risk_reasons": [],
              "recommended_next_action": "x", "warnings": [],
              "threat_intelligence": {"iocs": {}, "virustotal": {"file_hash": {"status": "skipped"},
                                                                 "ip_results": [], "domain_results": []},
                                      "abuseipdb": {"ip_results": []}, "alienvault_otx": {"otx_results": []},
                                      "notes": ["Legacy note."]}}
    out = _render(legacy)
    assert out["overview"] == "" and out["skippedExcluded"] == ""
    assert "Legacy note." not in out["gaps"]
    assert "Provider Coverage" not in out["assessment"]


def test_ioc_table_is_responsive_without_page_scroll():
    css = COMPONENTS_CSS.read_text(encoding="utf-8")
    block = css.split("/* Narrow: each table row becomes a labelled card. */", 1)[1]
    assert "@container (max-width: 56rem)" in block
    assert ".ti-ioc-table td[data-label]::before" in block
    assert ".ti-ioc-detail-row[hidden]" in block  # card mode must not unhide collapsed details
    assert "container-type: inline-size" in css.split(".ti-overview,", 1)[1].split("}", 1)[0]


def test_threat_intel_no_longer_shows_a_duplicate_key_findings_panel():
    source = WORKSPACE_JS.read_text(encoding="utf-8")
    assert 'const KEY_FINDINGS_STAGES = new Set(["investigation"]);' in source


def test_engine_notes_are_not_shown_in_the_gaps_panel(monkeypatch, tmp_path):
    """The engine's informational notes stay in the result (and the Agent
    Activity timeline) but are not repeated in Intelligence Gaps."""
    result = _result(monkeypatch, tmp_path, {"event_domain": "evil.example.com"})
    assert result["threat_intelligence"]["notes"]
    html = _render(result)["gaps"]
    assert "Enrichment engine notes" not in html
    assert "No usable public IP indicators were found." not in html
