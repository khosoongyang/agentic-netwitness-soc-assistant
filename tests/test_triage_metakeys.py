"""tests/test_triage_metakeys.py -- audit T-17.

29 of the 38 IOC-checklist meta keys never yielded a value on any real
incident (demo exports + stored incidents), yet the ticket's "Matched
Meta-Keys" listed every key the matched checklist rows implied. Now:
  * checklist meta keys are mapped to the NetWitness field names that
    actually occur in the data (port_dst, ip_proto, filename_src, ...);
  * ticket.metakeys / matched_metakeys list only keys OBSERVED in the
    incident (a value was extracted); the checklist-implied keys stay
    visible per category in the IOC trace (category_metakeys) and as
    implied_metakeys on the trace step.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.triage import soc_triage_agent as sta

ROOT = Path(__file__).resolve().parents[1]


def _export(name: str) -> dict:
    d = json.loads((ROOT / "demo" / name).read_text(encoding="utf-8"))
    inc = dict(d["incident"])
    inc["alerts"] = d["alerts"]
    return inc


def _checklist_keys() -> list[str]:
    return sorted({k for lst in (sta.IOC_AVAILABILITY, sta.IOC_CONFIDENTIALITY, sta.IOC_INTEGRITY)
                   for e in lst for k in e["metakeys"]})


def test_every_checklist_key_has_an_extraction_mapping():
    missing = [k for k in _checklist_keys() if not sta._METAKEY_MAP.get(k)]
    assert missing == []


@pytest.mark.parametrize("key,expected", [
    ("port.dst", True), ("protocol", True), ("file.name", True), ("file.hash", True),
    ("file.path", True), ("cert.hash", True), ("device.type", True), ("event.time", True),
    ("user.name", True), ("host.name", True), ("ip.src", True),
])
def test_real_netwitness_fields_are_extracted(key, expected):
    found = any(key in sta._extract_metakey_values(_export(n), [key])
                for n in ("incident_INC-52825_respond_api_export.json",
                          "incident_INC-53021_respond_api_export.json"))
    assert found is expected


def test_observed_metakeys_keeps_only_keys_with_values():
    inc = {"alerts": [{"events": [{"port_dst": 443, "filename_src": "a.exe"}]}]}
    observed, values = sta._observed_metakeys(inc, ["port.dst", "cpu.usage", "file.name", "packets.malformed"])
    assert observed == ["file.name", "port.dst"]
    assert set(values) == {"file.name", "port.dst"}


def test_ticket_lists_only_observed_metakeys(tmp_path, monkeypatch):
    from test_triage_step1_agent_integration import FakeLLM, _history_db, _incident
    monkeypatch.setattr(sta, "_TICKET_DB", tmp_path / "t.db")
    sta._ticket_db_init()
    a = sta.TriageAgent(baseline_db_path=_history_db(tmp_path / "h.db"))

    class Fake(FakeLLM):
        def __call__(self, messages, phase_label):
            if phase_label == "IOC Checklists":   # AVA 2 "High CPU usage" + CON 2 "Unknown traffic"
                return json.dumps({"availability": {"matched_iocs": [2]},
                                   "confidentiality": {"matched_iocs": [2]},
                                   "integrity": {"matched_iocs": []}})
            return super().__call__(messages, phase_label)

    monkeypatch.setattr(a, "_call", Fake())
    inc = _incident(id="INC-MK", alerts=[{"events": [{"ip_src": "10.0.0.5", "port_dst": 443}]}])
    res = a.triage(inc, force=True)
    mk = res["ticket"]["metakeys"]
    assert "cpu.usage" not in mk and "network.service" not in mk
    assert set(mk) <= set(res["metakeys_payload"]["metakey_values"])
    assert {"ip.src", "port.dst"} <= set(mk)
    step = next(s for s in res["trace"] if s["step"] == "IOC Checklist")
    assert "cpu.usage" in step["implied_metakeys"]
    assert step["matched_metakeys"] == mk
