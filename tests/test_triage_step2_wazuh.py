"""tests/test_triage_step2_wazuh.py -- Triage Step 2 / X8: Wazuh lab replay
converter (scripts/wazuh_alert_to_incident.py).

The lab path lets the intern run Atomic Red Team techniques in an isolated
Wazuh lab, export the alerts, convert them to the NetWitness-like shape and
evaluate Triage on them as lab_ground_truth. Uses the small hand-written
fixture tests/fixtures/wazuh_sysmon_certutil_alerts.json.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "wazuh_sysmon_certutil_alerts.json"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_sysmon_process_creation_maps_to_netwitness_fields():
    wz = _load("wazuh_alert_to_incident")
    alerts = wz.load_wazuh_alerts(FIXTURE)
    ev = wz.wazuh_alert_to_event(alerts[0])
    # parent = acting process (*_src), image = created process (*_dst)
    assert ev["filename_src"] == ["cmd.exe"] and ev["directory_src"] == ["C:\\Windows\\System32\\"]
    assert ev["param_src"][0].startswith("cmd /c certutil -urlcache")
    assert ev["filename_dst"] == ["certutil.exe"]
    assert ev["param_dst"][0].startswith("certutil  -urlcache -split -f https://")
    assert ev["checksum_dst"][0] == "8e3c1f0b2a4d6e8f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f"
    assert len(ev["checksum_dst"]) == 3          # sha256, md5, sha1 (imphash dropped)
    assert ev["user_src"] == "LAB-WIN10\\labuser" and ev["alias_host"] == ["LAB-WIN10"]
    assert ev["attack_tactic"] == "command and control" and ev["mitre_technique"] == ["T1105"]
    assert "wazuh.sysmon" in ev["context"]
    assert "cert_thumbprint" not in ev           # unknown, never assumed signed
    net = wz.wazuh_alert_to_event(alerts[1])
    assert net["ip_dst"] == "185.199.108.133" and net["port_dst"] == "443"
    assert net["filename_src"] == ["certutil.exe"]


def test_incident_shape_and_detection_source():
    wz = _load("wazuh_alert_to_incident")
    inc = wz.convert(wz.load_wazuh_alerts(FIXTURE), "LAB-1")
    assert inc["createdBy"] == "Wazuh (lab replay)" and inc["sources"] == ["Wazuh"]
    assert inc["alertCount"] == 2 and inc["priority"] == "CRITICAL" and inc["riskScore"] == 80
    assert inc["tactics"] == ["Command and Control"] and inc["techniques"] == ["T1105"]
    assert inc["title"] == "Wazuh Lab Alerts for LAB-WIN10"
    assert inc["created"] == "2026-09-30T02:20:11.000Z"
    a0 = inc["alerts"][0]
    assert a0["_id"] == "wazuh-1759198811.4412345"
    assert a0["originalHeaders"]["deviceVendor"] == "Wazuh"
    assert a0["originalAlert"]["events"][0]["filename_dst"] == ["certutil.exe"]


def test_converted_incident_flows_through_triage_evidence():
    """The converted shape is read by the SAME raw-alert digest and LOLBAS
    matcher as NetWitness exports."""
    wz = _load("wazuh_alert_to_incident")
    from agents.triage.evidence_packet import build_evidence_packet
    from triage_step1_payloads import SAMPLE_PARSED_CONTEXT, measured_baseline
    case = wz.build_case(wz.load_wazuh_alerts(FIXTURE), "lab_T1105_certutil", "true_positive",
                         "intern", "T1105", None)
    p = build_evidence_packet(case["incident"], SAMPLE_PARSED_CONTEXT, measured_baseline(),
                              case["data_availability"])
    assert p["raw_alerts"]["available"]["value"] is True
    assert "lolbas:certutil.exe Download" in p["rule_signals"]["lolbas"]["value"]["floor_labels"]
    procs = {i["name"] for i in p["raw_alerts"]["processes"]["value"]["items"]}
    assert {"cmd.exe", "certutil.exe"} <= procs


def test_cli_writes_lab_ground_truth_case(tmp_path):
    wz = _load("wazuh_alert_to_incident")
    ev = _load("eval_triage")
    code = wz.main([str(FIXTURE), "--name", "lab_T1105_certutil", "--label", "true_positive",
                    "--technique", "T1105", "--labeller", "Intern X", "--host", "lab-win10",
                    "--out-dir", str(tmp_path)])
    assert code == 0
    cases = ev.load_cases([str(tmp_path / "*.json")])
    case = cases[0]
    assert case["label"]["source"] == "lab_ground_truth" and case["label"]["labeller"] == "Intern X"
    assert case["expected"]["must_not"] == ["false_positive", "benign_expected"]
    assert case["canary"] == {"role": "malicious", "technique": "T1105", "pair": None, "source": "wazuh_lab"}
    assert ev.is_malicious_canary(case)


def test_filters_and_input_shapes(tmp_path):
    wz = _load("wazuh_alert_to_incident")
    alerts = wz.load_wazuh_alerts(FIXTURE)
    assert wz._filter(alerts, "OTHER-HOST", None, None) == []
    assert len(wz._filter(alerts, None, "2026-09-30T02:20:12Z", None)) == 1
    # OpenSearch search response and NDJSON are both accepted
    os_resp = tmp_path / "os.json"
    os_resp.write_text(json.dumps({"hits": {"hits": [{"_source": a} for a in alerts]}}), encoding="utf-8")
    assert len(wz.load_wazuh_alerts(os_resp)) == 2
    nd = tmp_path / "alerts.ndjson"
    nd.write_text("\n".join(json.dumps(a) for a in alerts), encoding="utf-8")
    assert len(wz.load_wazuh_alerts(nd)) == 2
    assert wz.main([str(FIXTURE), "--name", "x", "--label", "true_positive", "--labeller", "y",
                    "--host", "nope", "--out-dir", str(tmp_path)]) == 1
