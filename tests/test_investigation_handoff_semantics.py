"""tests/test_investigation_handoff_semantics.py -- canonical audit Phase 2A.

Investigation handoff mapping/semantic correctness:
  * user / hostname reach Investigation ingest metadata;
  * a DNS name is never an endpoint hostname;
  * the endpoint hostname is never claimed as the network SOURCE hostname;
  * each NetWitness sub-alert carries only its OWN id/title/severity/host/
    user/IPs -- nothing fabricated, nothing inherited from the case;
  * genuinely multi-valued evidence (IPs, users) is preserved;
  * the evidence-gap feedback pass keeps the canonical Parsing evidence.
No LLM, no subprocess, no network.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from workflow import engine as wf

INV_DIR = Path(__file__).resolve().parent.parent / "agents" / "investigation"
if str(INV_DIR) not in sys.path:
    sys.path.insert(0, str(INV_DIR))
import ingest_pipeline as ip  # noqa: E402


def _triage(metakey_values=None, case="INC-1001"):
    mkv = {"ip.src": "10.0.0.5", "user.name": "jdoe", "host.name": "WIN-01"} \
        if metakey_values is None else metakey_values
    return {
        "metakeys_payload": {"incident_id": case, "incident_title": "Case",
                             "metakey_values": mkv, "mitre_tactic": "Execution"},
        "ticket": {"incident_id": case, "classification": "HIGH", "title": "Case",
                   "incident_category": "Malware", "summary": "Triage summary."},
    }


def _nw_alert(*, alert_id="687621a8bfd6a31e1df7e244", name="Chu Wen - Lateral Move Detected",
              severity=7, src="192.168.10.200", dst="8.8.8.8", user="", hostname="",
              alias_host=""):
    """Real NetWitness Respond alert shape (as fetched for INC-52970)."""
    event = {
        "source": {"device": {"ip_address": src, "port": 53539, "dns_hostname": hostname},
                   "user": {"username": user, "ad_username": ""}},
        "destination": {"device": {"ip_address": dst, "port": 53},
                        "user": {"username": "", "ad_username": ""}},
        "alias_host": alias_host, "domain": "", "hostname": "", "user_src": "",
        "timestamp": 1752569283000,
    }
    return {
        "_id": alert_id, "receivedTime": 1752572328509, "status": "GROUPED_IN_INCIDENT",
        "originalHeaders": {"name": name, "severity": severity, "timestamp": 1752569351244,
                            "deviceProduct": "Event Stream Analysis"},
        "originalAlert": {"severity": severity, "moduleName": name, "events": [event]},
        "alert": {"name": name, "type": ["Network"], "source": "Event Stream Analysis",
                  "host_summary": f"{src}:53539 to {dst}:53", "events": [event]},
        "incidentId": "INC-1001",
    }


# ── user / hostname reach ingest metadata ───────────────────────────────────

def test_username_reaches_investigation_ingest_metadata():
    alert = wf.build_investigation_alert(_triage(), {"id": "INC-1001"})
    assert alert["endpoint_indicators"]["user"] == "jdoe"
    assert ip.extract_mapped_fields(alert)["username"] == "jdoe"


def test_hostname_reaches_investigation_ingest_metadata():
    alert = wf.build_investigation_alert(_triage(), {"id": "INC-1001"})
    assert alert["endpoint_indicators"]["hostname"] == "WIN-01"
    assert ip.extract_mapped_fields(alert)["hostname"] == "WIN-01"


# ── domains are not endpoint hostnames ──────────────────────────────────────

def test_domain_never_becomes_endpoint_hostname():
    """INC-52970: triage "host.name" carried the CONTACTED domains."""
    alert = wf.build_investigation_alert(
        _triage({"ip.src": "192.168.10.200", "host.name": ["ctldl.windowsupdate.com", "ocsp.digicert.com"]}),
        {"id": "INC-1001", "hostname": "ctldl.windowsupdate.com"})
    ep = alert.get("endpoint_indicators") or {}
    assert "hostname" not in ep and "hostnames" not in ep
    assert alert["network_indicators"]["observed_domains"] == ["ctldl.windowsupdate.com", "ocsp.digicert.com"]
    assert ip.extract_mapped_fields(alert)["hostname"] == "Unknown"


@pytest.mark.parametrize("value, expected", [
    ("ctldl.windowsupdate.com", True), ("ocsp.digicert.com", True), ("WIN-01", False),
    ("BETHANYCHUCHU", False), ("192.168.10.200", False), ("", False),
])
def test_domain_shape_classifier(value, expected):
    assert wf._is_domain_shaped(value) is expected


def test_endpoint_hostname_is_not_network_source_hostname():
    alert = wf.build_investigation_alert(_triage(), {"id": "INC-1001"})
    assert "hostname" not in alert["network_indicators"]["source"]
    assert alert["network_indicators"]["source"]["ip_address"] == "10.0.0.5"


# ── sub-alerts: own values only ──────────────────────────────────────────────

def test_sub_alert_uses_its_real_title_severity_and_id():
    alert = wf.build_investigation_alert(_triage(), {"id": "INC-1001", "alerts": [_nw_alert()]})
    sub = alert["alerts"][0]
    assert sub["alert_id"] == "687621a8bfd6a31e1df7e244"
    assert sub["title"] == "Chu Wen - Lateral Move Detected"
    assert sub["severity"] == 7
    assert sub["source_ips"] == ["192.168.10.200"]
    assert sub["destination_ips"] == ["8.8.8.8"]
    assert sub["connection_summary"] == "192.168.10.200:53539 to 8.8.8.8:53"
    assert sub["timestamp"].startswith("2025-07-15T09:38:48")


def test_missing_sub_alert_fields_stay_missing_and_are_not_fabricated():
    bare = {"receivedTime": 1752572328509}
    alert = wf.build_investigation_alert(_triage(), {"id": "INC-1001", "alerts": [bare]})
    sub = alert["alerts"][0]
    for key in ("alert_id", "title", "severity", "users", "hostnames", "source_ips", "destination_ips"):
        assert key not in sub, key
    line = ip._render_sub_alert(1, sub)
    assert "Medium" not in line and "Security Alert" not in line and "alert_1" not in line
    assert "NetWitness severity: not provided" in line
    assert "User: not provided" in line and "Host: not provided" in line


def test_sub_alerts_do_not_inherit_case_level_user_host_or_ips():
    """Case has user jdoe / host WIN-01 / src 10.0.0.5; the alert carries none."""
    alert = wf.build_investigation_alert(
        _triage(), {"id": "INC-1001", "alerts": [_nw_alert(src="", dst="")]})
    sub = alert["alerts"][0]
    assert "users" not in sub and "hostnames" not in sub
    assert "source_ips" not in sub and "destination_ips" not in sub


def test_sub_alert_domain_routed_to_domains_not_hostnames():
    alert = wf.build_investigation_alert(
        _triage(), {"id": "INC-1001", "alerts": [_nw_alert(hostname="WS-7", alias_host="evil.example.com")]})
    sub = alert["alerts"][0]
    assert sub["hostnames"] == ["WS-7"]
    assert sub["domains"] == ["evil.example.com"]


def test_sub_alert_severity_is_netwitness_not_triage():
    alert = wf.build_investigation_alert(_triage(), {"id": "INC-1001", "alerts": [_nw_alert(severity=3)]})
    assert alert["alerts"][0]["severity"] == 3
    assert alert["classification"]["severity"] == "HIGH"   # Triage level stays separate
    assert "NetWitness severity: 3" in ip._render_sub_alert(1, alert["alerts"][0])


def test_legacy_flat_sub_alert_keys_still_render():
    line = ip._render_sub_alert(1, {"alert_id": "A1", "title": "T", "user": "bob", "hostname": "H",
                                    "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2"})
    assert "User: bob" in line and "Host: H" in line and "SrcIP: 10.0.0.1" in line


# ── multi-valued evidence ────────────────────────────────────────────────────

def test_multiple_ips_are_preserved_with_documented_precedence():
    parsing = {"processed_alert": {"network_indicators": {
        "source_ips": ["10.0.0.5", "10.0.0.6"], "destination_ips": ["20.42.65.93", "8.8.4.4"]}}}
    alert = wf.build_investigation_alert(
        _triage({"ip.src": "10.0.0.5", "ip.dst": ["20.42.65.93", "23.50.87.128"]}),
        {"id": "INC-1001"}, parsing_result=parsing)
    net = alert["network_indicators"]
    assert net["source"]["ip_addresses"] == ["10.0.0.5", "10.0.0.6"]
    assert net["destination"]["ip_addresses"] == ["20.42.65.93", "23.50.87.128", "8.8.4.4"]
    assert net["destination"]["ip_address"] == "20.42.65.93"     # unchanged primary


def test_multiple_users_are_preserved():
    parsing = {"processed_alert": {"user_and_host_indicators": {"all_usernames": ["jdoe", "svc-backup"]}}}
    alert = wf.build_investigation_alert(
        _triage({"user.name": ["jdoe", "admin"]}), {"id": "INC-1001", "username": "jdoe"},
        parsing_result=parsing)
    assert alert["endpoint_indicators"]["users"] == ["jdoe", "admin", "svc-backup"]
    assert alert["endpoint_indicators"]["user"] == "jdoe"


def test_entity_provenance_is_recorded():
    parsing = {"processed_alert": {"network_indicators": {"destination_ips": ["8.8.4.4"]}}}
    ents = wf._collect_case_entities(
        {"metakey_values": {"ip.dst": "8.8.4.4"}}, {"alertMeta": {"DestinationIp": ["8.8.4.4", "1.2.3.4"]}},
        parsing, {})
    assert ents["destination_ips"]["8.8.4.4"] == [wf.ENTITY_ORIGIN_TRIAGE, wf.ENTITY_ORIGIN_PARSING,
                                                  wf.ENTITY_ORIGIN_ALERT_META]
    assert ents["destination_ips"]["1.2.3.4"] == [wf.ENTITY_ORIGIN_ALERT_META]


# ── feedback pass keeps Parsing ──────────────────────────────────────────────

def test_parsing_context_survives_the_feedback_pass(monkeypatch):
    calls = []
    monkeypatch.setattr(wf, "handoff_to_investigation",
                        lambda tri, inc, **kw: calls.append(kw))
    results = iter([
        {"status": "completed", "narrative_report": "", "missing_evidence": ["process tree"],
         "execution_trace": [{"step_id": "step_1", "instruction": "process chain", "status": "NOT_MET"}]},
        {"status": "completed", "narrative_report": "", "execution_trace": []},
    ])
    monkeypatch.setattr(wf, "run_investigation", lambda *a, **k: next(results))
    import agents.triage as triage_pkg
    monkeypatch.setattr(triage_pkg, "deep_triage_supplement",
                        lambda inc, gaps: {"gap_findings": {g: "answered" for g in gaps}})
    parsing = {"processed_alert": {"command_line": "powershell -enc AAA"}}

    wf.investigate_with_feedback(_triage(), {"id": "INC-1001"}, "INC-1001",
                                 parsing_result=parsing, max_passes=1)

    assert len(calls) == 2
    assert calls[0]["parsing_result"] is parsing
    assert calls[1]["parsing_result"] is parsing          # feedback pass
    assert calls[1]["supplement"]["feedback_pass"] == 1


def test_feedback_handoff_command_lines_come_from_parsing():
    parsing = {"processed_alert": {"command_line": "powershell -enc AAA"}}
    alert = wf.build_investigation_alert(_triage(), {"id": "INC-1001"},
                                         supplement={"feedback_pass": 1}, parsing_result=parsing)
    assert alert["endpoint_indicators"]["processes"]["command_line"] == "powershell -enc AAA"
