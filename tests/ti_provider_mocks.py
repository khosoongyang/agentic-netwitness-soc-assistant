"""Shared, deterministic fakes for the Threat Intelligence provider APIs.

Used by tests/test_threat_intel_ioc_coverage.py and by the risk-regression
golden file (tests/golden_threat_intel_risk_baseline.json), which was
captured from the pre-change engine with exactly these fakes — so a risk
regression test compares the unchanged scoring algorithm on identical
provider evidence before and after the IOC-coverage phase.

`provider_router(spec)` returns a `requests.get` replacement. `spec` maps an
indicator value to per-provider behaviour:

    {"188.40.170.197": {"vt": {"malicious": 9}, "abuse": {"score": 89},
                         "otx": {"pulses": 2}},
     "evil.example.com": {"vt": "error"}}

Any provider not listed for an indicator returns a clean (zero) result.
"error" -> HTTP 500, "not_found" -> HTTP 404, "raise" -> RequestException.
Every call is appended to `router.calls` as (provider, indicator).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import Mock
from urllib.parse import unquote

import requests

ALL_KEYS = {"VT_API_KEY": "test-vt", "ABUSEIPDB_API_KEY": "test-abuse", "OTX_API_KEY": "test-otx"}


def set_keys(monkeypatch, *present: str) -> None:
    """Configure exactly the named provider keys (all three when none given)."""
    wanted = present or tuple(ALL_KEYS)
    for name, value in ALL_KEYS.items():
        if name in wanted:
            monkeypatch.setenv(name, value)
        else:
            monkeypatch.delenv(name, raising=False)


def _response(status: int, payload: Any = None, text: str = "") -> Mock:
    response = Mock(status_code=status, text=text or ("error body" if status >= 400 else ""))
    response.json.return_value = payload if payload is not None else {}
    return response


def _vt_payload(cfg: dict) -> dict:
    malicious = cfg.get("malicious", 0)
    suspicious = cfg.get("suspicious", 0)
    harmless = cfg.get("harmless", 60)
    undetected = cfg.get("undetected", 30)
    engines = {}
    for i in range(malicious):
        engines[f"Engine{i:02d}"] = {"category": "malicious", "engine_name": f"Engine{i:02d}",
                                     "result": cfg.get("label", "malware")}
    for i in range(suspicious):
        engines[f"Susp{i:02d}"] = {"category": "suspicious", "engine_name": f"Susp{i:02d}", "result": "suspicious"}
    engines["CleanAV"] = {"category": "harmless", "engine_name": "CleanAV", "result": "clean"}
    attributes = {
        "last_analysis_stats": {"malicious": malicious, "suspicious": suspicious, "harmless": harmless,
                                "undetected": undetected, "timeout": 0},
        "last_analysis_results": engines,
        "reputation": cfg.get("reputation", 0),
        "last_analysis_date": 1_717_000_000,
        "tags": cfg.get("tags", []),
        "total_votes": {"harmless": 1, "malicious": cfg.get("votes_malicious", 0)},
        # IP fields
        "country": cfg.get("country", "DE"), "as_owner": cfg.get("as_owner", "Hetzner Online GmbH"),
        "asn": cfg.get("asn", 24940), "network": cfg.get("network", "188.40.0.0/16"),
        # domain fields
        "registrar": "Example Registrar", "creation_date": 1_700_000_000,
        "categories": {"Forcepoint ThreatSeeker": "malicious web sites", "Sophos": "malware callhome"},
        # file fields
        "meaningful_name": "invoice.exe", "first_submission_date": 1_600_000_000,
        "type_description": "Win32 EXE",
        "popular_threat_classification": {
            "suggested_threat_label": "trojan.emotet/heodo",
            "popular_threat_category": [{"value": "trojan", "count": 20}],
            "popular_threat_name": [{"value": "emotet", "count": 15}, {"value": "heodo", "count": 5}],
        },
    }
    return {"data": {"attributes": attributes}}


def _abuse_payload(indicator: str, cfg: dict) -> dict:
    return {"data": {
        "ipAddress": indicator, "abuseConfidenceScore": cfg.get("score", 0),
        "totalReports": cfg.get("reports", 0), "numDistinctUsers": cfg.get("users", 0),
        "countryCode": cfg.get("country", "DE"), "isp": cfg.get("isp", "Hetzner Online GmbH"),
        "domain": "hetzner.com", "usageType": cfg.get("usage", "Data Center/Web Hosting/Transit"),
        "hostnames": cfg.get("hostnames", ["static.197.170.40.188.clients.your-server.de"]),
        "isTor": cfg.get("tor", False), "isWhitelisted": False,
        "lastReportedAt": "2026-09-30T10:00:00+00:00" if cfg.get("reports") else None,
        "reports": [{"reportedAt": "2026-09-30T10:00:00+00:00", "comment": "PRIVATE COMMENT",
                     "reporterId": 4242, "categories": cats}
                    for cats in cfg.get("report_categories", [])],
    }}


def _otx_payload(cfg: dict) -> dict:
    count = cfg.get("pulses", 0)
    pulses = [{
        "name": f"Pulse {i}", "created": "2026-01-0%dT00:00:00" % (i % 9 + 1),
        "modified": "2026-0%d-01T00:00:00" % (i % 9 + 1), "tags": ["c2", "emotet", f"tag{i}"],
        "malware_families": [{"id": "Emotet", "display_name": "Emotet"}],
        "adversary": "TA542" if i == 0 else "", "attack_ids": [{"id": "T1071", "display_name": "App Layer"}],
        "TLP": "white",
    } for i in range(min(count, 7))]
    return {"pulse_info": {"count": count, "pulses": pulses, "related": {}},
            "sections": ["general", "geo"], "country_name": "Germany", "asn": "AS24940 Hetzner"}


def provider_router(spec: dict | None = None):
    spec = spec or {}

    def router(url, headers=None, params=None, timeout=None):
        if "virustotal.com" in url:
            provider, indicator = "vt", unquote(url.rstrip("/").rsplit("/", 1)[-1])
        elif "abuseipdb.com" in url:
            provider, indicator = "abuse", (params or {}).get("ipAddress")
        else:
            provider, indicator = "otx", unquote(url.split("/indicators/", 1)[1].split("/")[1])
        router.calls.append((provider, indicator))
        cfg = (spec.get(indicator) or {}).get(provider, {})
        if cfg == "error":
            return _response(500, text="internal error")
        if cfg == "not_found":
            return _response(404, text="not found")
        if cfg == "rate_limited":
            return _response(429, text="quota exceeded")
        if cfg == "raise":
            raise requests.ConnectionError("connection reset")
        if provider == "vt":
            return _response(200, _vt_payload(cfg))
        if provider == "abuse":
            return _response(200, _abuse_payload(indicator, cfg))
        return _response(200, _otx_payload(cfg))

    router.calls = []
    return router


# Scenarios whose provider evidence is identical before and after the
# IOC-coverage phase (each indicator type appears at most once, and only in
# the alert fields the pre-change engine read), so the unchanged risk
# algorithm must produce identical output for them.
RISK_REGRESSION_SCENARIOS = {
    "single_ip_vt_9_detections": {
        "alert": {"destination_ip": "188.40.170.197"},
        "spec": {"188.40.170.197": {"vt": {"malicious": 9}}}, "keys": None},
    "single_ip_abuse_high_otx_pulses": {
        "alert": {"destination_ip": "34.107.243.93"},
        "spec": {"34.107.243.93": {"abuse": {"score": 89, "reports": 412}, "otx": {"pulses": 50}}}, "keys": None},
    "ip_abuse_moderate": {
        "alert": {"source_ip": "45.33.32.156"},
        "spec": {"45.33.32.156": {"abuse": {"score": 45, "reports": 3}}}, "keys": None},
    "domain_malicious_and_suspicious": {
        "alert": {"event_domain": "evil.example.com"},
        "spec": {"evil.example.com": {"vt": {"malicious": 3, "suspicious": 1}, "otx": {"pulses": 2}}}, "keys": None},
    "hash_malicious": {
        "alert": {"file_hash": "a" * 64},
        "spec": {"a" * 64: {"vt": {"malicious": 40, "suspicious": 2}, "otx": {"pulses": 5}}}, "keys": None},
    "hash_ip_domain_all_flagged_high": {
        "alert": {"file_hash": "b" * 64, "destination_ip": "188.40.170.197", "event_domain": "evil.example.com"},
        "spec": {"b" * 64: {"vt": {"malicious": 6}},
                 "188.40.170.197": {"vt": {"malicious": 1}, "abuse": {"score": 95, "reports": 10}},
                 "evil.example.com": {"vt": {"malicious": 2}}}, "keys": None},
    "source_and_destination_public": {
        "alert": {"source_ip": "45.33.32.156", "destination_ip": "188.40.170.197"},
        "spec": {"45.33.32.156": {"otx": {"pulses": 1}}, "188.40.170.197": {"vt": {"malicious": 2}}}, "keys": None},
    "url_derived_domain": {
        "alert": {"url": "https://bad.example.net/payload.exe"},
        "spec": {"bad.example.net": {"vt": {"malicious": 4}}}, "keys": None},
    "no_indicators": {"alert": {"source_ip": "unknown"}, "spec": {}, "keys": None},
    "private_ip_only": {"alert": {"source_ip": "192.168.10.202", "destination_ip": "10.0.0.5"},
                        "spec": {}, "keys": None},
    "virustotal_errors": {
        "alert": {"destination_ip": "188.40.170.197"},
        "spec": {"188.40.170.197": {"vt": "error", "otx": {"pulses": 3}}}, "keys": None},
    "no_provider_credentials": {"alert": {"destination_ip": "188.40.170.197"}, "spec": {}, "keys": []},
    "partial_credentials_vt_only": {
        "alert": {"destination_ip": "188.40.170.197"},
        "spec": {"188.40.170.197": {"vt": {"malicious": 5}}}, "keys": ["VT_API_KEY"]},
}


def apply_keys(monkeypatch, keys) -> None:
    if keys is None:
        set_keys(monkeypatch)
    else:
        for name in ALL_KEYS:
            monkeypatch.delenv(name, raising=False)
        for name in keys:
            monkeypatch.setenv(name, ALL_KEYS[name])


RISK_FIELDS = ("enrichment_risk_score", "enrichment_risk_level", "enrichment_risk_reasons",
               "recommended_next_action", "status", "warnings")
