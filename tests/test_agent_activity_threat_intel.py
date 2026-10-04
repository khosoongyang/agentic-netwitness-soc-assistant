"""Agent Activity - Threat Intelligence Enrichment.

Runs the real durable stage runner (workflow.engine.resume_after_triage_approval)
with the real enrichment engine (agents.threat_intelligence.threat_intel):
real input assembly, IOC extraction, provider query functions (URL/header/
parameter construction, status handling, response parsing), risk scoring,
warnings and recommended next action. Only the network edge is replaced:
``requests.get`` answers from canned provider responses and records every
request; the post-stage summary's raw-SDK call is a signature-identical
recorder. Provider API keys are fake values that must never appear in events.

Everything is isolated under tmp_path (workflow/pipeline DBs, run artifacts,
the stage's output directory and the activity DB).
"""

from __future__ import annotations

import copy
import json
import re
import threading

import pytest
import requests

import observability
from backend import create_app
from observability.store import query_events
import canonical_seed as seed
from workflow import engine
from workflow import state_store as wss

CASE = "INC-TI-OBS"
FILE_HASH = "a" * 60 + "91ff"
PUBLIC_IP = "203.0.113.45"
DOMAIN = "evil-updates.example"
KEYS = {"VT_API_KEY": "vt-key-SECRET-0001", "ABUSEIPDB_API_KEY": "abuse-key-SECRET-0002",
        "OTX_API_KEY": "otx-key-SECRET-0003"}
SUMMARY = "Enrichment found a malicious file hash and a high-confidence abusive IP."

REQUESTS: list[dict] = []
MODEL_CALLS: list[dict] = []
_LOCK = threading.Lock()


class _Response:
    def __init__(self, status_code: int, body: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._body = body or {}
        self.text = text or json.dumps(self._body)

    def json(self):
        return self._body


# provider -> "ok" | "timeout" | "http429" | "notfound"
MODES: dict[str, str] = {}


def _fake_get(url, headers=None, params=None, timeout=None, **kwargs):
    with _LOCK:
        REQUESTS.append({"url": url, "header_names": sorted((headers or {}).keys()),
                         "params": dict(params or {}), "timeout": timeout})
    provider = ("virustotal" if "virustotal" in url else "abuseipdb" if "abuseipdb" in url
                else "otx")
    mode = MODES.get(provider, "ok")
    if mode == "timeout":
        raise requests.Timeout(f"HTTPSConnectionPool: read timed out ({url}?apikey={KEYS['VT_API_KEY']})")
    if mode == "http429":
        return _Response(429, text=f"rate limit exceeded for key {KEYS['ABUSEIPDB_API_KEY']}")
    if mode == "notfound":
        return _Response(404, text="not found")
    if provider == "virustotal":
        malicious = 66 if "/files/" in url else 3
        return _Response(200, {"data": {"attributes": {
            "last_analysis_stats": {"malicious": malicious, "suspicious": 2, "harmless": 50, "undetected": 4},
            "reputation": -45, "meaningful_name": "evil.exe", "country": "NL", "as_owner": "Example AS"}}})
    if provider == "abuseipdb":
        return _Response(200, {"data": {"abuseConfidenceScore": 87, "totalReports": 42,
                                        "countryCode": "NL", "isp": "Example ISP", "usageType": "Hosting"}})
    return _Response(200, {"pulse_info": {"count": 3, "pulses": [{"name": "Pulse A"}, {"name": "Pulse B"}]},
                           "sections": ["general"]})


def _fake_model(prompt, *, system=None, model=None, temperature=None, max_output_tokens=None,
                timeout=None, text_format=None):
    with _LOCK:
        MODEL_CALLS.append({"prompt": prompt, "system": system, "model": model,
                            "max_output_tokens": max_output_tokens})
    return SUMMARY


PROCESSED = {"incident_id": CASE, "alert_title": "Suspicious binary with outbound traffic",
             "source_ip": "10.1.2.3", "destination_ip": PUBLIC_IP, "file_hash": FILE_HASH,
             "event_domain": DOMAIN, "possible_file_name": "evil.exe"}
# Multiple indicators of every type, with excluded and limit-skipped ones
# (run with TI_MAX_INDICATORS_PER_TYPE=2): 2 hashes x 2 + 2 IPs x 3 +
# 2 domains x 2 = 14 provider requests.
SECOND_HASH = "b" * 64
MULTI = {"incident_id": CASE, "alert_title": "Multi-indicator alert",
         "network_indicators": {"source_ips": ["10.1.2.3"],
                                "destination_ips": [PUBLIC_IP, "198.51.100.7", "224.0.0.251", "192.0.2.9"]},
         "web_indicators": {"domains": [DOMAIN, "c2.example.net", "dc01.corp.local"]},
         "file_indicators": {"file_hashes": [FILE_HASH, SECOND_HASH]}}
INCIDENT = {"id": CASE, "title": "Suspicious binary with outbound traffic", "alertMeta": {}}
TRIAGE = {"ticket": {"incident_id": CASE, "classification": "HIGH", "unc": "#00001A"},
          "metakeys_payload": {"incident_id": CASE}}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    import integrations.openai.client as openai_client

    REQUESTS.clear()
    MODEL_CALLS.clear()
    MODES.clear()
    for key, value in KEYS.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(requests, "get", _fake_get)
    monkeypatch.setattr(openai_client, "invoke_openai_text", _fake_model)
    monkeypatch.setattr(engine, "REP_DIR", tmp_path / "reporting")
    monkeypatch.setattr(engine, "_TRUSTED_OUTPUT_ROOT", tmp_path / "artifacts")

    def prepare(name: str, processed=None, triage=None) -> tuple[str, str]:
        scenario = tmp_path / name
        scenario.mkdir()
        monkeypatch.setattr(wss, "DB_FILE", scenario / "workflow.db")
        monkeypatch.setattr(engine, "PIPELINE_DB_FILE", scenario / "pipeline.db")
        engine.pipeline_db_init()
        run_id = wss.start_run(CASE)
        raw = engine._save_run_artifact(CASE, run_id, "raw_incident.json", "raw_incident",
                                        {"incident": copy.deepcopy(INCIDENT), "data_availability": {}})
        wss.save_raw_incident_path(CASE, run_id, str(raw))
        wss.save_parsing_result(CASE, run_id, {"run_id": run_id, "status": "completed",
                                               "processed_alert": dict(processed or PROCESSED)})
        # Phase 6: a run-bound Triage result with a real recorded approval
        # (not a bare "Approved" label).
        seed.approve_triage(CASE, run_id, copy.deepcopy(triage or TRIAGE))
        wss._guarded_update(CASE, run_id, {"parsing_status": "Complete",
                                           "threat_intel_status": "Processing",
                                           "workflow_status": "Processing"})
        return CASE, run_id

    return {"prepare": prepare, "monkeypatch": monkeypatch, "tmp": tmp_path}


@pytest.fixture()
def activity(tmp_path):
    state = observability.install(str(tmp_path / "agent_activity.db"))
    assert state["enabled"], state
    assert {"parsing", "triage", "threat_intel"} <= set(state["coverage"])
    yield observability.get_store()
    observability.uninstall()


def _events(store, run_id):
    assert store.flush()
    return query_events(case_id=CASE, run_id=run_id, stage="threat_intel", path=store.path)


def _top(events):
    return [e for e in events if not e["parent_span_id"]]


def _lookups(events):
    return [e for e in events if e["event_type"] == "provider_lookup"]


_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")


def _normalise(value, run_id) -> str:
    text = json.dumps(value, sort_keys=True, default=str)
    for form in (run_id, engine._safe(run_id), json.dumps(run_id)[1:-1]):
        text = text.replace(form, "<RUN>")
    return _TS.sub("<TS>", text)


def _snapshot(case_id, run_id, result) -> dict:
    state = wss.get_state(case_id)
    return {
        "result": _normalise(result, run_id),
        "statuses": {k: state[k] for k in ("threat_intel_status", "investigation_status",
                                           "workflow_status", "last_error")},
        "persisted": _normalise(json.loads(state["threat_intel_result_json"] or "null"), run_id),
        "ledger": [(r["stage"], r["action"]) for r in wss.get_activity(case_id)],
        "requests": copy.deepcopy(REQUESTS),
        "model_calls": [_normalise(c, run_id) for c in MODEL_CALLS],
    }


# ── 30-33. Equivalence ─────────────────────────────────────────────────────

@pytest.mark.parametrize("scenario", ["all_ok", "provider_failures", "no_keys", "no_iocs", "stage_failure",
                                      "multi_ioc"])
def test_threat_intel_is_identical_with_observability_on_and_off(env, tmp_path, scenario):
    mp = env["monkeypatch"]
    processed, triage = None, None
    if scenario == "provider_failures":
        MODES.update({"virustotal": "timeout", "abuseipdb": "http429"})
    if scenario == "no_keys":
        for key in KEYS:
            mp.delenv(key)
    if scenario == "no_iocs":
        processed = {"incident_id": CASE, "source_ip": "10.0.0.5", "destination_ip": "192.168.1.9"}
    if scenario == "stage_failure":
        triage = {"ticket": {"incident_id": "INC-SOMEONE-ELSE"}, "metakeys_payload": {}}
    if scenario == "multi_ioc":
        processed = MULTI
        mp.setenv("TI_MAX_INDICATORS_PER_TYPE", "2")

    case_id, run_off = env["prepare"]("off", processed, triage)
    off = _snapshot(case_id, run_off, engine.resume_after_triage_approval(case_id, run_off))
    REQUESTS.clear()
    MODEL_CALLS.clear()

    assert observability.install(str(tmp_path / f"eq-{scenario}.db"))["enabled"]
    try:
        case_id, run_on = env["prepare"]("on", processed, triage)
        on = _snapshot(case_id, run_on, engine.resume_after_triage_approval(case_id, run_on))
        events = _events(observability.get_store(), run_on)
    finally:
        observability.uninstall()

    assert on == off
    assert events, "observability was active for the 'on' run"
    expected_status = {"all_ok": "Complete", "provider_failures": "Complete with Warnings",
                       "no_keys": "Complete with Warnings", "no_iocs": "Complete",
                       "stage_failure": "Failed", "multi_ioc": "Complete"}[scenario]
    assert off["statuses"]["threat_intel_status"] == expected_status
    expected_requests = {"all_ok": 7, "provider_failures": 7, "no_keys": 0, "no_iocs": 0, "stage_failure": 0,
                         "multi_ioc": 14}
    assert len(off["requests"]) == expected_requests[scenario]
    assert len(off["model_calls"]) == (0 if scenario == "stage_failure" else 1)


# ── 1-2, 4-5, 7-8, 10-11, 13-14, 16, 18-19, 22-23. Successful enrichment ───

def test_successful_enrichment_timeline_is_real_and_in_execution_order(env, activity):
    case_id, run_id = env["prepare"]("ok")
    result = engine.resume_after_triage_approval(case_id, run_id)
    events = _events(activity, run_id)
    top = _top(events)
    assert [(e["source"], e["event_type"], e["status"]) for e in top] == [
        ("orchestration", "stage_claimed", "completed"),
        ("system", "context_loaded", "completed"),
        ("system", "context_loaded", "completed"),
        ("system", "input_assembled", "completed"),
        ("system", "ioc_extraction", "completed"),
        ("tool", "provider_lookups", "running"),
        ("rule", "risk_scoring", "completed"),
        ("tool", "provider_lookups", "completed"),
        ("system", "enrichment_recorded", "completed"),
        ("rule", "recommended_action", "completed"),
        ("decision", "stage_result", "completed"),
        ("ai", "ai_summary", "running"),
        ("ai", "ai_summary", "completed"),
        ("orchestration", "stage_settled", "completed"),
    ]
    assert all(e["stage"] == "threat_intel" and e["run_id"] == run_id for e in events)

    # 2. Extraction reports the real indicators (hash abbreviated; private IP excluded).
    extraction = next(e for e in top if e["event_type"] == "ioc_extraction")
    assert extraction["detail"] == "1 file hash · 1 public IP address(es) · 1 external domain(s) · 1 excluded"
    extraction_text = json.dumps(extraction["metadata"]["details"], ensure_ascii=False)
    assert "SHA-256 aaaaaaaa…91ff" in extraction_text and FILE_HASH not in extraction_text
    # Listed as not looked up, with the engine's own exclusion reason.
    assert "10.1.2.3 — Private/internal address" in extraction_text

    # 4-14. One event pair per real request, in the engine's real order:
    # file hash (VT, OTX) -> each IP (VT, AbuseIPDB, OTX) -> each domain (VT, OTX).
    done = [e for e in _lookups(events) if e["status"] != "running"]
    assert [e["title"] for e in done] == [
        "VirusTotal · SHA-256 aaaaaaaa…91ff",
        "AlienVault OTX · SHA-256 aaaaaaaa…91ff",
        f"VirusTotal · IP address {PUBLIC_IP}",
        f"AbuseIPDB · IP address {PUBLIC_IP}",
        f"AlienVault OTX · IP address {PUBLIC_IP}",
        f"VirusTotal · domain {DOMAIN}",
        f"AlienVault OTX · domain {DOMAIN}",
    ]
    assert len(done) == len(REQUESTS)  # nothing claimed that was not requested
    assert [e["status"] for e in _lookups(events)] == ["running", "completed"] * 7
    group = next(e for e in top if e["event_type"] == "provider_lookups")
    assert all(e["parent_span_id"] == group["span_id"] for e in _lookups(events))
    assert done[0]["detail"].startswith("66 malicious · 2 suspicious · reputation -45")
    assert done[3]["detail"].startswith("abuse confidence 87 · 42 report(s)")
    assert done[1]["detail"].startswith("3 related pulse(s)")

    # 16. Deterministic risk scoring is RULE, with the real score and factors.
    risk = next(e for e in top if e["event_type"] == "risk_scoring")
    assert (f"Risk score {result['enrichment_risk_score']} → level {result['enrichment_risk_level']}"
            in risk["detail"])
    factors = next(b for b in risk["metadata"]["details"] if b.get("type") == "list")["items"]
    assert factors == result["enrichment_risk_reasons"]

    # 18-19. Next action and outcome are the engine's own values.
    assert next(e for e in top if e["event_type"] == "recommended_action")["detail"] == \
        result["recommended_next_action"]
    decision = next(e for e in top if e["event_type"] == "stage_result")
    assert decision["title"] == "Threat Intelligence enrichment completed"
    assert f"Enrichment risk {result['enrichment_risk_level']}" in decision["detail"]

    # 22-23. AI only as the post-stage summary, after the decision.
    ai = [e for e in events if e["source"] == "ai"]
    assert {e["ai_content_kind"] for e in ai} == {"summary"}
    assert all(e["sequence"] > decision["sequence"] for e in ai)
    assert ai[-1]["detail"] == SUMMARY or [e for e in ai if e["event_type"] == "ai_summary"][-1]["detail"] == SUMMARY
    assert "Not used in provider queries, risk scoring or enrichment decisions" in json.dumps(ai)
    request = [e for e in ai if e["event_type"] == "llm_call"]
    assert [e["status"] for e in request] == ["running", "completed"]

    settled = top[-1]
    assert "Investigation status: Pending" in settled["detail"]


def test_no_reasoning_or_thinking_labels_in_threat_intel(env, activity):
    _, run_id = env["prepare"]("labels")
    engine.resume_after_triage_approval(CASE, run_id)
    flat = json.dumps(_events(activity, run_id)).lower()
    assert "reasoning" not in flat and "thinking" not in flat


# ── 3. No IOCs ─────────────────────────────────────────────────────────────

def test_zero_iocs_shows_no_provider_lookups(env, activity):
    _, run_id = env["prepare"]("noiocs", {"incident_id": CASE, "source_ip": "10.0.0.5",
                                          "destination_ip": "192.168.1.9"})
    engine.resume_after_triage_approval(CASE, run_id)
    events = _events(activity, run_id)
    extraction = next(e for e in events if e["event_type"] == "ioc_extraction")
    assert extraction["title"] == "No supported observable indicators found"
    assert not _lookups(events) and REQUESTS == []
    group = [e for e in events if e["event_type"] == "provider_lookups"][-1]
    assert group["title"] == "No provider lookups were run"
    assert next(e for e in events if e["event_type"] == "stage_result")["status"] == "completed"


# ── 6, 9, 12, 17, 20, 26. Failures, warnings and sanitisation ──────────────

def test_provider_failures_are_shown_and_enrichment_continues(env, activity):
    MODES.update({"virustotal": "timeout", "abuseipdb": "http429", "otx": "notfound"})
    _, run_id = env["prepare"]("fail")
    result = engine.resume_after_triage_approval(CASE, run_id)
    events = _events(activity, run_id)
    done = [e for e in _lookups(events) if e["status"] != "running"]
    vt = [e for e in done if e["title"].startswith("VirusTotal")]
    # The provider function itself catches the timeout and returns its message.
    assert vt and all(e["status"] == "warning" and "read timed out" in e["detail"] for e in vt)
    assert all(e["title"].startswith("VirusTotal lookup failed") for e in vt)
    abuse = next(e for e in done if e["title"].startswith("AbuseIPDB"))
    assert abuse["status"] == "warning" and "HTTP 429" in abuse["detail"]
    otx = [e for e in done if e["title"].startswith("AlienVault OTX")]
    assert all(e["status"] == "warning" and "HTTP 404" in e["detail"] for e in otx)
    group = [e for e in events if e["event_type"] == "provider_lookups"][-1]
    assert group["status"] == "warning" and group["title"] == "Provider lookups finished — 0 of 7 answered"
    recorded = next(e for e in events if e["event_type"] == "enrichment_recorded")
    assert recorded["status"] == "warning" and recorded["title"] == "Enrichment completed with warnings"
    assert len(next(b for b in recorded["metadata"]["details"] if b["label"] == "Warnings")["items"]) == \
        len(result["warnings"])
    decision = next(e for e in events if e["event_type"] == "stage_result")
    assert decision["status"] == "warning" and "with warnings" in decision["title"]
    assert wss.get_state(CASE)["threat_intel_status"] == "Complete with Warnings"
    # 26. No provider key ever reaches an event (they appear in the raw errors).
    flat = json.dumps(events)
    assert all(value not in flat for value in KEYS.values())


def test_missing_provider_credentials_are_reported_as_skipped_without_requests(env, activity):
    env["monkeypatch"].delenv("ABUSEIPDB_API_KEY")
    _, run_id = env["prepare"]("nokey")
    engine.resume_after_triage_approval(CASE, run_id)
    events = _events(activity, run_id)
    abuse = [e for e in _lookups(events) if e["title"].startswith("AbuseIPDB") and e["status"] != "running"]
    assert len(abuse) == 1 and abuse[0]["status"] == "warning"
    assert abuse[0]["title"].startswith("AbuseIPDB lookup skipped")
    assert "No request sent" in abuse[0]["detail"] and "ABUSEIPDB_API_KEY is missing" in abuse[0]["detail"]
    assert not [r for r in REQUESTS if "abuseipdb" in r["url"]]
    group = [e for e in events if e["event_type"] == "provider_lookups"][-1]
    assert "1 skipped (no API key)" in group["detail"]


# ── 21. Stage failure ──────────────────────────────────────────────────────

def test_stage_failure_names_the_rule_that_failed(env, activity):
    _, run_id = env["prepare"]("stagefail", triage={"ticket": {"incident_id": "INC-SOMEONE-ELSE"},
                                                    "metakeys_payload": {}})
    result = engine.resume_after_triage_approval(CASE, run_id)
    assert result["status"] == "failed"
    events = _events(activity, run_id)
    top = _top(events)
    validation = next(e for e in top if e["event_type"] == "input_validation")
    assert validation["source"] == "rule" and validation["status"] == "failed"
    assert "INC-SOMEONE-ELSE" in validation["detail"]
    decisions = [e for e in top if e["event_type"] == "stage_result"]
    assert len(decisions) == 1 and decisions[0]["status"] == "failed"
    assert top[-1]["event_type"] == "stage_settled" and top[-1]["status"] == "failed"
    assert not _lookups(events) and not [e for e in events if e["source"] == "ai"]


# ── 24-25. AI summary failure does not alter the enrichment result ─────────

def test_ai_summary_failure_does_not_change_the_enrichment_result(env, activity):
    import integrations.openai.client as openai_client

    def down(prompt, *, system=None, model=None, temperature=None, max_output_tokens=None,
             timeout=None, text_format=None):
        raise RuntimeError("summary endpoint unavailable")

    observability.uninstall()
    env["monkeypatch"].setattr(openai_client, "invoke_openai_text", down)
    assert observability.install(str(activity.path))["enabled"]
    store = observability.get_store()
    _, run_id = env["prepare"]("aifail")
    result = engine.resume_after_triage_approval(CASE, run_id)
    events = _events(store, run_id)
    summary = [e for e in events if e["event_type"] == "ai_summary"][-1]
    assert summary["status"] == "warning" and summary["title"] == "Post-stage AI summary unavailable"
    assert [e["status"] for e in events if e["event_type"] == "llm_call"] == ["running", "failed"]
    decision = next(e for e in events if e["event_type"] == "stage_result")
    assert decision["status"] == "completed"
    assert wss.get_state(CASE)["threat_intel_status"] == "Complete"
    assert result["status"] == "completed"


# ── Multiple indicators, exclusions and the enrichment limit ────────────────

def test_multiple_iocs_with_exclusions_and_limit_skips(env, activity):
    env["monkeypatch"].setenv("TI_MAX_INDICATORS_PER_TYPE", "2")
    _, run_id = env["prepare"]("multi", MULTI)
    result = engine.resume_after_triage_approval(CASE, run_id)
    events = _events(activity, run_id)

    extraction = next(e for e in events if e["event_type"] == "ioc_extraction")
    assert extraction["detail"] == ("2 file hashes · 2 public IP address(es) · 2 external domain(s) · "
                                    "3 excluded · 1 skipped by enrichment limit")
    text = json.dumps(extraction["metadata"]["details"], ensure_ascii=False)
    for line in ("10.1.2.3 — Private/internal address",
                 "224.0.0.251 — Multicast address",
                 "dc01.corp.local — Internal/non-public domain suffix",
                 "192.0.2.9 — Enrichment limit reached"):
        assert line in text, line
    assert FILE_HASH not in text and SECOND_HASH not in text  # hashes abbreviated

    # One completed event per real request, in the engine's order, nothing for
    # excluded or skipped indicators.
    done = [e for e in _lookups(events) if e["status"] != "running"]
    assert len(done) == len(REQUESTS) == 14
    titles = [e["title"] for e in done]
    assert titles[:4] == ["VirusTotal · SHA-256 aaaaaaaa…91ff", "AlienVault OTX · SHA-256 aaaaaaaa…91ff",
                          "VirusTotal · SHA-256 bbbbbbbb…bbbb", "AlienVault OTX · SHA-256 bbbbbbbb…bbbb"]
    assert not any(ip in t for t in titles for ip in ("192.0.2.9", "224.0.0.251", "10.1.2.3"))
    assert not any("dc01.corp.local" in t for t in titles)
    group = [e for e in events if e["event_type"] == "provider_lookups"][-1]
    assert group["title"] == "Provider lookups finished — 14 of 14 answered"

    # The persisted result carries the same accounting the timeline shows.
    coverage = result["threat_intelligence"]["coverage"]
    assert (coverage["enriched"], coverage["excluded"], coverage["skipped_by_limit"]) == (6, 3, 1)

    client = create_app({"TESTING": True, "AGENT_ACTIVITY_DB_PATH": str(activity.path),
                         "AGENT_ACTIVITY_STREAM_SECONDS": 0.3}).test_client()
    history = client.get(f"/api/cases/{CASE}/activity?stage=threat_intel").get_json()
    assert [e["sequence"] for e in history["events"]] == [e["sequence"] for e in events]
    body = client.get(f"/api/cases/{CASE}/activity/stream?stage=threat_intel").get_data(as_text=True)
    streamed = [json.loads(m) for m in re.findall(r"^data: (.*)$", body, re.M)]
    assert [e["sequence"] for e in streamed] == [e["sequence"] for e in events]


# ── 27-29. Transport, history, isolation ───────────────────────────────────

def test_threat_intel_events_are_served_by_history_and_sse(env, activity):
    _, run_id = env["prepare"]("sse")
    engine.resume_after_triage_approval(CASE, run_id)
    expected = _events(activity, run_id)
    client = create_app({"TESTING": True, "AGENT_ACTIVITY_DB_PATH": str(activity.path),
                         "AGENT_ACTIVITY_STREAM_SECONDS": 0.3}).test_client()
    history = client.get(f"/api/cases/{CASE}/activity?stage=threat_intel").get_json()
    assert [e["sequence"] for e in history["events"]] == [e["sequence"] for e in expected]
    body = client.get(f"/api/cases/{CASE}/activity/stream?stage=threat_intel").get_data(as_text=True)
    streamed = [json.loads(m) for m in re.findall(r"^data: (.*)$", body, re.M)]
    assert [e["sequence"] for e in streamed] == [e["sequence"] for e in expected]
    resumed = client.get(f"/api/cases/{CASE}/activity/stream?stage=threat_intel",
                         headers={"Last-Event-ID": str(streamed[-1]["sequence"])}).get_data(as_text=True)
    assert "event: activity" not in resumed


def test_threat_intel_is_isolated_from_parsing_and_triage_events(env, activity):
    _, run_id = env["prepare"]("isolation")
    # Phase 6: prepare() records the run's real Triage approval (a Triage-gate
    # event); isolation is about what the Threat Intelligence run emits.
    seeded = query_events(case_id=CASE, run_id=run_id, path=activity.path)
    seeded_ids = {e["sequence"] for e in seeded}
    from workflow import commands

    wss._guarded_update(CASE, run_id, {"threat_intel_status": "Pending", "workflow_status": "Awaiting Action"})
    commands.start_stage(CASE, "threat_intel", executor=lambda *args: None)
    engine.resume_after_triage_approval(CASE, run_id)
    assert activity.flush()
    all_events = [e for e in query_events(case_id=CASE, run_id=run_id, path=activity.path)
                  if e["sequence"] not in seeded_ids]
    assert {e["stage"] for e in seeded} <= {"triage"} and {e["stage"] for e in all_events} == {"threat_intel"}
    assert all_events[0]["title"] == "Threat Intelligence run requested"
    for stage in ("parsing", "triage"):
        assert [e for e in query_events(case_id=CASE, run_id=run_id, stage=stage, path=activity.path)
                if e["sequence"] not in seeded_ids] == []


def test_threat_intel_wrap_points_match_their_expected_signatures():
    from observability.adapters import threat_intel_adapter
    from observability.instrument import Patcher, actual_params

    recorded = []
    patcher = Patcher()
    patcher.wrap = lambda target, hooks: recorded.append(target) or True  # type: ignore[assignment]
    threat_intel_adapter.install(patcher)
    # 20 original wrap points + select_indicators (IOC-coverage phase)
    # + _require_stage_ready (canonical audit Phase 6 readiness gate).
    assert len(recorded) == 22
    for target in recorded:
        assert actual_params(target) == target.params, target.label
