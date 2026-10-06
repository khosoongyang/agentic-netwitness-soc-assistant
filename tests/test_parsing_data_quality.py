"""tests/test_parsing_data_quality.py -- Parsing data-quality regressions
surfaced by INC-53021 after R1.

1. List-valued NetWitness metakeys (filename_src: ["splunkd.exe"]) used to be
   str()-ed into "['splunkd.exe']"; [""] became "['']" and extensions "exe']".
2. A Respond alert carries every event twice (originalAlert.events[] raw meta
   + alert.events[] Respond view), so 6 alerts produced 12 "events".
3. Respond's reduced `domain` (copied from alias.host) and endpoint host
   names were written into the domain fields.
4. Every file name was copied into email_indicators.attachment_names.

Real parser, temporary output dirs, the tracked demo INC-53021 export (read
only); no LLM, no provider calls, outbound sockets refused.
"""
from __future__ import annotations

import copy
import json
import socket
from pathlib import Path

import pytest

import agents.parsing.parser_normaliser as pn
from agents.threat_intelligence import threat_intel as ti
from agents.triage import soc_triage_agent

ROOT = Path(__file__).resolve().parents[1]
_REAL_EXPORT = ROOT / "demo" / "incident_INC-53021_respond_api_export.json"
SERVICE = "ba15c6b9-5dfe-49a5-99c1-ac91470557d3:50005"
SHA_A = "4854484a90704cff48d94f6f55238d965f4820803a674d8a46959866420fc607"
MD5_A = "0ddcc6af9a1d9e91f6f5f2e7cad26cb0"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def refuse(self, address, *args, **kwargs):
        raise OSError(f"network blocked in parsing data-quality tests: {address!r}")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)


def _rich_event(session="1548923", **overrides):
    """originalAlert.events[] -- raw NetWitness Endpoint meta (list-valued)."""
    event = {
        "event_source_id": f"{SERVICE}:{session}", "sessionid": int(session), "device_type": "nwendpoint",
        "agent_id": "8B929051", "ip_src": "192.168.10.204", "ip_dst": "192.168.10.202",
        "port_src": 49888, "port_dst": 8888, "event_time": 1764573566, "time": 1764571147000,
        "alias_host": ["KELLYWANG"], "user_src": "KELLYWANG\\Kelly Wang",
        "filename_src": ["splunkd.exe"], "directory_src": ["C:\\Users\\Public\\"],
        "checksum_src": [SHA_A, MD5_A],
        "param_src": ["splunkd.exe -server http://192.168.10.202:8888 -group red"],
    }
    event.update(overrides)
    return event


def _reduced_event(session="1548923", **overrides):
    """alert.events[] -- Respond's reduced view of the same event."""
    event = {
        "event_source": SERVICE, "event_source_id": session, "device_type": "nwendpoint",
        "agent_id": "8B929051", "port_src": "49888", "port_dst": "8888", "event_time": 1764573566,
        "timestamp": 1764571147000, "hostname": "KELLYWANG", "domain": "KELLYWANG",
        "source": {"filename": "splunkd.exe", "path": "C:\\Users\\Public\\", "file_SHA256": SHA_A,
                   "device": {"ip_address": "192.168.10.204"}, "user": {"username": "KELLYWANG\\Kelly Wang"}},
        "destination": {"device": {"ip_address": "192.168.10.202"}},
        "related_links": [{"type": "investigate_destination_domain",
                           "url": "/investigation/x/navigate/query/alias.host%3D'KELLYWANG'"}],
    }
    event.update(overrides)
    return event


def _incident(*children, case="INC-DQ-0001"):
    return {"id": case, "title": "Data quality case", "riskScore": 70, "alerts": list(children)}


def _child(tag, rich_events=(), reduced_events=(), case="INC-DQ-0001"):
    return {"_id": f"ALERT-{tag}", "incidentId": case, "originalHeaders": {"name": f"Alert {tag}"},
            "originalAlert": {"events": list(rich_events)}, "alert": {"events": list(reduced_events)}}


def _parse(raw, tmp_path, name="out"):
    return pn.build_standard_alert(copy.deepcopy(raw), output_dir=str(tmp_path / name))


def _real_inc_53021():
    export = json.loads(_REAL_EXPORT.read_text(encoding="utf-8"))
    return dict(export["incident"], alerts=export["alerts"])   # the workflow's bare shape


# ── A-E: list / scalar normalisation ─────────────────────────────────────────

def test_a_scalar_field_input_is_unchanged():
    event = pn.normalise_event({"filename_src": "splunkd.exe", "alias_host": "HOST-1",
                                "directory_src": "C:\\Temp\\", "boc": "beaconing"}, 0)
    assert (event["file_name"], event["process_name"], event["hostname"]) == ("splunkd.exe", "splunkd.exe", "HOST-1")
    assert (event["file_path"], event["action"]) == ("C:\\Temp\\", "beaconing")
    assert pn.meta_values("splunkd.exe") == ["splunkd.exe"]


def test_b_one_element_list_becomes_its_scalar():
    event = pn.normalise_event(_rich_event(boc=["evasive powershell used over network"] * 2), 0)
    assert event["file_name"] == event["process_name"] == "splunkd.exe"
    assert event["file_path"] == event["process_path"] == "C:\\Users\\Public\\"
    assert event["hostname"] == "KELLYWANG"
    assert event["action"] == "evasive powershell used over network"
    assert "process_names" not in event and "actions" not in event     # one genuine value only


def test_c_multi_element_list_keeps_every_value(tmp_path):
    event = pn.normalise_event({"filename_src": ["a.exe", "b.exe"]}, 0)
    assert event["file_name"] == "a.exe"
    assert event["file_names"] == event["process_names"] == ["a.exe", "b.exe"]
    result = _parse(_incident(_child("A", [{"filename_src": ["a.exe", "b.exe"], "ip_src": "10.0.0.1"}])), tmp_path)
    normalised = result["normalised_alert"]
    assert normalised["process_indicators"]["process_names"] == ["a.exe", "b.exe"]
    assert normalised["file_indicators"]["file_names"] == ["a.exe", "b.exe"]


@pytest.mark.parametrize("empty", [[], [""], ["", "  "], None, ""])
def test_d_empty_list_values_never_become_strings(empty, tmp_path):
    assert pn.meta_values(empty) == []
    event = pn.normalise_event({"filename_src": empty, "directory_src": empty, "boc": empty,
                                "alias_host": empty, "ip_src": "10.0.0.1"}, 0)
    for field in ("file_name", "file_path", "process_name", "process_path", "action", "hostname", "domain"):
        assert event[field] is None, field
    # An empty first candidate does not hide a genuine later one.
    assert pn.normalise_event({"filename_src": [""], "filename": "real.exe"}, 0)["file_name"] == "real.exe"
    raw = _incident(_child("A", [{"ip_src": "10.0.0.1", "filename_src": empty, "directory_src": empty}]))
    blob = json.dumps(_parse(raw, tmp_path)["normalised_alert"])
    assert "['" not in blob and '"[]"' not in blob


def test_e_extension_is_derived_from_the_clean_file_name(tmp_path):
    result = _parse(_incident(_child("A", [_rich_event()])), tmp_path)
    assert result["normalised_alert"]["file_indicators"]["file_extensions"] == ["exe"]


# ── F-G: hostname vs domain semantics ───────────────────────────────────────

def test_f_endpoint_host_name_is_a_hostname_only(tmp_path):
    result = _parse(_incident(_child("A", [_rich_event()], [_reduced_event()])), tmp_path)
    users = result["normalised_alert"]["user_and_host_indicators"]
    assert users["hostnames"] == ["KELLYWANG"]
    assert "domains" not in users
    assert "domains" not in result["normalised_alert"]["ioc_summary"]
    # Even a dotted name on endpoint telemetry is the machine, not an IOC domain.
    hosts, domains = pn.event_host_and_domain_values(_rich_event(alias_host=["kellywang.corp.example.com"]))
    assert (hosts, domains) == (["kellywang.corp.example.com"], [])


def test_g_legitimate_domains_remain_domains(tmp_path):
    network_event = {"ip_src": "10.0.0.5", "ip_dst": "93.184.216.34", "domain": "example.com",
                     "alias_host": ["ctldl.windowsupdate.com", "WORKSTATION7"]}
    result = _parse(_incident(_child("A", [network_event])), tmp_path)
    normalised = result["normalised_alert"]
    assert set(normalised["user_and_host_indicators"]["domains"]) == {"example.com", "ctldl.windowsupdate.com"}
    assert "WORKSTATION7" in normalised["user_and_host_indicators"]["hostnames"]
    assert "WORKSTATION7" not in normalised["ioc_summary"]["domains"]
    # Respond's reduced `domain` on packet telemetry: a DNS name stays a domain.
    hosts, domains = pn.event_host_and_domain_values({"event_source": "svc:1", "domain": "evil.example.net"})
    assert (hosts, domains) == (["evil.example.net"], ["evil.example.net"])


# ── H-I: attachment evidence ────────────────────────────────────────────────

def test_h_legitimate_email_attachment_stays_under_email_indicators(tmp_path):
    email_event = {"email_src": ["attacker@evil.example"], "email_dst": ["victim@corp.example"],
                   "subject": ["Invoice due"], "attachment": ["invoice.docm"], "ip_src": "203.0.113.9"}
    result = _parse(_incident(_child("A", [email_event])), tmp_path)
    email = result["normalised_alert"]["email_indicators"]
    assert email["attachment_names"] == ["invoice.docm"]
    assert email["attachment_extensions"] == ["docm"]
    # File names on an email event are attachments even without the attachment metakey.
    other = {"email_src": "a@evil.example", "filename": ["payload.zip"]}
    assert _parse(_incident(_child("B", [other])), tmp_path, "b")["normalised_alert"][
        "email_indicators"]["attachment_names"] == ["payload.zip"]


def test_i_endpoint_file_and_process_evidence_is_not_an_attachment(tmp_path):
    result = _parse(_incident(_child("A", [_rich_event()], [_reduced_event()])), tmp_path)
    normalised = result["normalised_alert"]
    assert "email_indicators" not in normalised
    assert normalised["file_indicators"]["file_names"] == ["splunkd.exe"]
    assert normalised["process_indicators"]["process_names"] == ["splunkd.exe"]
    assert normalised["observed_data_context"]["has_email_data"] is False
    # An address merely seen in a web session (generic `email` metakey) does
    # not turn that session's downloaded file into an attachment.
    web = {"ip_src": "10.0.0.5", "ip_dst": "93.184.216.34", "email": ["someone@example.com"], "filename": ["setup.exe"]}
    assert "email_indicators" not in _parse(_incident(_child("W", [web])), tmp_path, "w")["normalised_alert"]


# ── J-L: event deduplication ────────────────────────────────────────────────

def test_j_rich_and_reduced_copies_of_one_event_are_one_event(tmp_path):
    raw = _incident(_child("A", [_rich_event("1548923")], [_reduced_event("1548923")]),
                    _child("B", [_rich_event("1548860", port_src=49885, event_time=1764573563)],
                           [_reduced_event("1548860", port_src="49885", event_time=1764573563)]))
    result = _parse(raw, tmp_path)
    normalised = result["normalised_alert"]
    assert result["event_count"] == 2
    assert normalised["alert_summary"]["raw_event_count"] == 2
    assert len(normalised["normalised_events"]) == 2
    assert normalised["identifiers"]["event_source_ids"] == [f"{SERVICE}:1548923", f"{SERVICE}:1548860"]
    assert normalised["parser_metadata"]["event_deduplication"] == {
        "raw_event_records": 4, "unique_events": 2, "merged_duplicate_records": 2,
        "identity_basis": "netwitness_event_source_id"}
    assert [e["event_index"] for e in normalised["normalised_events"]] == [0, 1]


def test_k_different_events_with_the_same_timestamp_stay_separate(tmp_path):
    same_time = dict(event_time=1764573566)
    raw = _incident(_child("A", [_rich_event("1"), _rich_event("2", port_src=50000)]),
                    _child("B", [{"ip_src": "10.0.0.1", **same_time}, {"ip_src": "10.0.0.1", "port_src": 1, **same_time}]))
    result = _parse(raw, tmp_path)
    assert result["event_count"] == 4                              # distinct ids / no identity: never merged
    # A shared id with conflicting evidence is not merged either.
    conflicting = _incident(_child("C", [_rich_event("7")], [_reduced_event("7", port_src="1234")]))
    assert _parse(conflicting, tmp_path, "c")["event_count"] == 2
    # A bare id with no service merges only when it is unambiguous.
    ambiguous = _incident(_child("D", [_rich_event("9"), _rich_event("9", event_source_id="other-svc:50005:9")],
                                 [{"event_source_id": "9", "event_time": 1764573566}]))
    assert _parse(ambiguous, tmp_path, "d")["event_count"] == 3
    serviceless = _incident(_child("E", [{"event_source_id": "11", "ip_src": "10.0.0.1", "user_src": "a"},
                                         {"event_source_id": "11", "ip_src": "10.0.0.1", "user_src": "b"}]))
    assert _parse(serviceless, tmp_path, "e")["event_count"] == 2
    # ...but resolves when exactly one service carries that id.
    resolved, _ = pn.normalise_unique_events(
        [{"raw_event": _rich_event("12")}, {"raw_event": {"event_source_id": "12", "event_time": 1764573566}}])
    assert len(resolved) == 1 and resolved[0]["event_source_id"] == f"{SERVICE}:12"


def test_l_richer_representation_wins_and_one_sided_evidence_is_kept(tmp_path):
    rich = _rich_event("5")
    del rich["param_src"]                                          # only the reduced copy has the command line
    reduced = _reduced_event("5", source={**_reduced_event()["source"], "launch_argument": "splunkd.exe -group blue"},
                             user_agent="nw-agent/1.0")
    events, summary = pn.normalise_unique_events(
        [{"raw_event": reduced}, {"raw_event": rich}], "Endpoint")   # reduced seen first
    assert summary["unique_events"] == 1
    event = events[0]
    assert event["event_source_id"] == f"{SERVICE}:5"
    assert event["file_hashes"] == [SHA_A, MD5_A]                  # rich-only md5 kept
    assert event["file_path"] == "C:\\Users\\Public\\"
    assert event["command_line"] == "splunkd.exe -group blue"      # reduced-only evidence kept
    assert event["user_agent"] == "nw-agent/1.0"
    assert event["source_ip"] == "192.168.10.204"
    # Deterministic: the same input always produces the same result.
    again, _ = pn.normalise_unique_events([{"raw_event": reduced}, {"raw_event": rich}], "Endpoint")
    assert again == events


# ── real INC-53021 (tracked demo export) ────────────────────────────────────

@pytest.mark.skipif(not _REAL_EXPORT.is_file(), reason="real INC-53021 export not present")
def test_real_inc_53021_is_six_clean_unique_events(tmp_path):
    raw = _real_inc_53021()
    pairs = [(len(a["originalAlert"]["events"]), len(a["alert"]["events"])) for a in raw["alerts"]]
    assert pairs == [(1, 1)] * 6                                   # each event is carried twice
    result = pn.run_parser_normalisation_for_dashboard(raw, output_dir=tmp_path, expected_case_id="INC-53021")
    normalised, processed = result["normalised_alert"], result["processed_alert"]
    assert result["status"] == "completed" and result["case_identity"]["status"] == "match"
    assert result["event_count"] == 6
    assert normalised["alert_summary"]["raw_event_count"] == len(normalised["normalised_events"]) == 6
    assert normalised["identifiers"]["event_source_ids"] == [
        f"{SERVICE}:{sid}" for sid in ("1548923", "1548860", "1550016", "1549914", "1549842", "1549952")]
    assert normalised["process_indicators"]["process_names"] == ["splunkd.exe", "powershell.exe"]
    assert normalised["process_indicators"]["process_paths"] == [
        "C:\\Users\\Public\\", "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\"]
    assert normalised["file_indicators"]["file_names"] == ["splunkd.exe", "powershell.exe"]
    assert normalised["file_indicators"]["file_extensions"] == ["exe"]
    assert len(normalised["file_indicators"]["file_hashes"]) == 4
    assert normalised["user_and_host_indicators"]["hostnames"] == ["KELLYWANG"]
    assert "domains" not in normalised["user_and_host_indicators"]
    assert "email_indicators" not in normalised
    assert normalised["alert_summary"]["primary_action"] == "evasive powershell used over network"
    assert normalised["ioc_summary"] == {
        "ips": ["192.168.10.204", "192.168.10.202"], "hostnames": ["KELLYWANG"],
        "files": ["splunkd.exe", "powershell.exe"], "hashes": normalised["file_indicators"]["file_hashes"]}
    assert (processed["hostname"], processed["process_name"], processed["file_name"]) == (
        "KELLYWANG", "splunkd.exe", "splunkd.exe")
    assert "domain" not in processed and "event_domain" not in processed
    assert "['" not in json.dumps([normalised, processed])


# ── M: R1 identity invariants on the real export ────────────────────────────

@pytest.mark.skipif(not _REAL_EXPORT.is_file(), reason="real INC-53021 export not present")
def test_m_r1_identity_is_unchanged(tmp_path):
    raw = _real_inc_53021()
    result = pn.run_parser_normalisation_for_dashboard(raw, output_dir=tmp_path / "ok", expected_case_id="INC-53021")
    assert result["identity_validation"]["hard_failures"] == []
    assert result["incident_id"] == result["selected_alert_id"] == "INC-53021"
    assert result["input_identity"]["child_alert_ids"] == [a["_id"] for a in raw["alerts"]]
    assert result["normalised_alert_count"] == 1
    wrong = pn.run_parser_normalisation_for_dashboard(raw, output_dir=tmp_path / "bad", expected_case_id="INC-99999")
    assert wrong["status"] == "failed" and wrong["case_identity"]["status"] == "mismatch"
    foreign = copy.deepcopy(raw)
    foreign["alerts"][0]["incidentId"] = "INC-OTHER"
    warned = pn.run_parser_normalisation_for_dashboard(foreign, output_dir=tmp_path / "w", expected_case_id="INC-53021")
    assert warned["status"] == "completed"
    assert warned["identity_validation"]["hard_failures"] == []


# ── N-O: downstream inputs ──────────────────────────────────────────────────

@pytest.mark.skipif(not _REAL_EXPORT.is_file(), reason="real INC-53021 export not present")
def test_n_triage_receives_cleaned_parsing_values(tmp_path):
    raw = _real_inc_53021()
    processed = pn.run_parser_normalisation_for_dashboard(
        raw, output_dir=tmp_path, expected_case_id="INC-53021")["processed_alert"]
    prompt = soc_triage_agent._compact_incident(raw, processed)
    context = json.dumps(processed)
    assert '"parsed_alert_context"' in prompt
    assert "['" not in prompt and "['" not in context
    assert processed["process_name"] == "splunkd.exe" and processed["hostname"] == "KELLYWANG"


@pytest.mark.skipif(not _REAL_EXPORT.is_file(), reason="real INC-53021 export not present")
def test_o_threat_intel_input_has_no_python_list_strings(tmp_path):
    raw = _real_inc_53021()
    processed = pn.run_parser_normalisation_for_dashboard(
        raw, output_dir=tmp_path, expected_case_id="INC-53021")["processed_alert"]
    flat = ti.flatten_alert_for_enrichment(ti._build_flat_alert(raw, None, processed))
    candidates = ti.select_indicators(flat)["candidates"]
    assert not any("['" in str(c["value"]) or "']" in str(c["value"]) for c in candidates)
    hashes = [c["value"] for c in candidates if c["type"] == "hash" and not c["exclusion_category"]]
    assert len(hashes) == 4
    # Parsing itself no longer offers KELLYWANG as a domain anywhere.
    domain_origins = [o for c in candidates if c["type"] == "domain" for o in c["origins"]]
    assert all(origin == "Related IOCs" for origin in domain_origins)   # only TI's own hostname->domain mapping
    file_names = sorted(c["value"] for c in candidates if c["type"] == "file_name")
    assert file_names == ["powershell.exe", "splunkd.exe"]
