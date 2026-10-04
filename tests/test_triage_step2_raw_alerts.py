"""tests/test_triage_step2_raw_alerts.py -- Triage Step 2 / P1: raw-alert
evidence in triage ("pull the raw log, never trust the alert summary alone").

Covers agents/triage/raw_alerts.py (digest + signatures + ranking), the
`raw_alerts` evidence-packet section, the new mandatory evidence
`raw_alerts_available`, ranked compaction in _compact_incident() replacing
"first 12 alerts by position", and data_availability None vs present
through TriageAgent.triage() and workflow/engine.py. Offline: real demo
exports, no LLM, no network.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from agents.triage import raw_alerts as ra
from agents.triage import soc_triage_agent
from agents.triage.evidence_packet import build_evidence_packet, get_leaf, render_packet_for_prompt
from agents.triage.guards import build_assessment, missing_mandatory_evidence
from agents.triage.triage_result import EvidencePacket
from triage_step1_payloads import (
    SAMPLE_DATA_AVAILABILITY,
    SAMPLE_INCIDENT,
    SAMPLE_PARSED_CONTEXT,
    evidence_packet,
    measured_baseline,
)

ROOT = Path(__file__).resolve().parents[1]
LIVE = {"incident_source": "netwitness_live", "alerts_fetch_attempted": True,
        "alerts_fetch_succeeded": True, "alerts_complete": True}


def _load_export(name: str) -> dict:
    data = json.loads((ROOT / "demo" / name).read_text(encoding="utf-8"))
    inc = dict(data["incident"])
    inc["alerts"] = data["alerts"]
    return inc


@pytest.fixture(scope="module")
def inc_52825() -> dict:
    return _load_export("incident_INC-52825_respond_api_export.json")


@pytest.fixture(scope="module")
def inc_53021() -> dict:
    return _load_export("incident_INC-53021_respond_api_export.json")


def _da(inc: dict) -> dict:
    return dict(LIVE, alerts_count=len(inc["alerts"]))


def _section(inc: dict, da: dict | None) -> dict:
    return build_evidence_packet(inc, SAMPLE_PARSED_CONTEXT, measured_baseline(), da)["raw_alerts"]


# =============================================================================
# Digest over ALL alerts (INC-52825: 1,000 alerts, 998 the same rule)
# =============================================================================

def test_52825_digest_covers_all_alerts(inc_52825):
    sec = _section(inc_52825, _da(inc_52825))
    assert sec["available"] == {"value": True, "status": "measured", "source": sec["available"]["source"]}
    assert sec["events_digested"]["value"] == 1000
    names = sec["alert_names"]["value"]
    assert names["total_unique"] == 2
    assert {i["alert_name"]: i["count"] for i in names["items"]} == {
        "Chu Wen - Lateral Move Detected": 998, "Disables UAC": 2}
    # 1000 of 1558 alerts NetWitness counted were returned by the fetch.
    assert sec["coverage_ratio"]["value"] == pytest.approx(0.642)
    assert "1000/1558" in sec["coverage_ratio"]["source"]


def test_52825_dedups_to_signatures_with_counts(inc_52825):
    sigs = ra.group_signatures(inc_52825["alerts"])
    assert sum(s["count"] for s in sigs) == 1000
    # 1,000 alerts collapse to roughly a hundred (name + process + cmdline)
    # signatures -- an order of magnitude fewer things to read.
    assert len(sigs) < 150
    uac = [s for s in sigs if s["alert_name"] == "Disables UAC"]
    assert len(uac) == 1 and uac[0]["count"] == 2
    assert uac[0]["child_processes"] == ["reg.exe"]
    assert "EnableLUA" in uac[0]["child_command_lines"][0]
    assert len(uac[0]["example_alert_ids"]) == 2


def test_52825_truncation_is_explicit(inc_52825):
    sec = _section(inc_52825, _da(inc_52825))
    cl = sec["command_lines"]["value"]
    assert cl["truncated"] is True and cl["shown"] == ra.MAX_COMMAND_LINES
    assert cl["note"] == f"showing {ra.MAX_COMMAND_LINES} of {cl['total_unique']} unique command lines"
    sig = sec["signatures"]["value"]
    assert sig["note"].startswith(f"showing {ra.MAX_SIGNATURES} of ")
    assert sig["alerts_covered_by_shown"] <= 1000


def test_52825_signer_is_recorded_not_trusted(inc_52825):
    signers = _section(inc_52825, _da(inc_52825))["signers"]["value"]
    assert signers["signed_events"] > 900
    assert "never treated as evidence of benign" in signers["note"]


def test_52825_behaviours_and_context_tags(inc_52825):
    sec = _section(inc_52825, _da(inc_52825))
    tags = {i["tag"]: i["count"] for i in sec["context_tags"]["value"]["items"]}
    assert tags["network.offHour"] == 99
    behaviors = {i["behavior"] for i in sec["behaviors"]["value"]["items"]}
    assert "disables uac" in behaviors


# =============================================================================
# INC-53021: splunkd.exe from C:\Users\Public with a trojan threat_desc
# =============================================================================

def test_53021_threat_desc_and_process_directory(inc_53021):
    sec = _section(inc_53021, _da(inc_53021))
    td = sec["threat_desc"]["value"]["items"]
    assert td[0]["threat_desc"] == "Win64.Trojan.Goldera"
    assert td[0]["processes"] == ["splunkd.exe"]
    assert td[0]["count"] == 3
    procs = {(p["name"], p["directory"]) for p in sec["processes"]["value"]["items"]}
    assert ("splunkd.exe", "C:\\Users\\Public\\") in procs
    unsigned = {i["process"] for i in sec["signers"]["value"]["unsigned_processes"]["items"]}
    assert "splunkd.exe" in unsigned
    assert any(i["tag"] == "network.offHour" for i in sec["context_tags"]["value"]["items"])


def test_53021_mitre_from_events(inc_53021):
    mitre = _section(inc_53021, _da(inc_53021))["mitre"]["value"]
    assert any(t["tactic"] == "execution" for t in mitre["tactics"]["items"])


# =============================================================================
# Leaves are citable dot-paths; contract
# =============================================================================

def test_raw_alert_leaves_are_citable(inc_53021):
    p = build_evidence_packet(inc_53021, SAMPLE_PARSED_CONTEXT, measured_baseline(), _da(inc_53021))
    EvidencePacket.model_validate(p)
    for key in ("available", "threat_desc", "signatures", "processes", "command_lines"):
        leaf = get_leaf(p, f"raw_alerts.{key}")
        assert leaf is not None and leaf["status"] == "measured", key
    text = render_packet_for_prompt(p)
    assert "raw_alerts.threat_desc [measured]" in text
    assert "Win64.Trojan.Goldera" in text
    json.dumps(p)


def test_extra_raw_alert_key_is_rejected_by_contract():
    p = evidence_packet()
    p["raw_alerts"]["surprise"] = {"value": 1, "status": "measured", "source": "x"}
    with pytest.raises(Exception):
        EvidencePacket.model_validate(p)
    q = evidence_packet()
    del q["raw_alerts"]
    with pytest.raises(Exception):
        EvidencePacket.model_validate(q)


# =============================================================================
# Fetch status -> missing (unknown, not safe)
# =============================================================================

@pytest.mark.parametrize("da, alerts, reason", [
    ({"incident_source": "sqlite_slim", "alerts_fetch_succeeded": False, "alerts_count": 0},
     [], "sqlite_slim"),
    (dict(LIVE, alerts_fetch_succeeded=False, alerts_count=0), [], "did not succeed"),
    (dict(LIVE, alerts_count=0), [], "no raw alerts"),
    (None, SAMPLE_INCIDENT["alerts"], "unknown"),
])
def test_unavailable_raw_alerts_are_missing(da, alerts, reason):
    inc = dict(SAMPLE_INCIDENT, alerts=list(alerts))
    sec = _section(inc, da)
    assert sec["available"]["status"] == "missing"
    assert reason in sec["available"]["source"]


def test_sqlite_slim_marker_without_data_availability():
    inc = dict(SAMPLE_INCIDENT)
    inc.pop("alerts")
    inc["_alerts_stripped"] = 3
    sec = _section(inc, None)
    assert sec["incident_source"] == {"value": "sqlite_slim", "status": "inferred",
                                      "source": sec["incident_source"]["source"]}
    assert sec["available"]["status"] == "missing"
    for key in ("threat_desc", "signatures", "processes"):
        assert sec[key]["status"] == "missing"
        assert "never triage on the alert summary alone" in sec[key]["source"]


def test_data_availability_none_vs_present():
    """None = unknown: same alerts, but no recorded fetch outcome -> the
    digest is still measured from the alerts in hand, availability is not."""
    present = _section(SAMPLE_INCIDENT, SAMPLE_DATA_AVAILABILITY)
    absent = _section(SAMPLE_INCIDENT, None)
    assert present["available"]["value"] is True
    assert present["fetch_succeeded"] == {"value": True, "status": "measured",
                                          "source": present["fetch_succeeded"]["source"]}
    assert absent["available"]["status"] == "missing"
    assert absent["fetch_succeeded"]["status"] == "missing"
    assert absent["alert_names"]["status"] == "measured"
    assert absent["alerts_count"]["value"] == 3


# =============================================================================
# Mandatory evidence: raw_alerts_available (intended consequence)
# =============================================================================

def _benign(disposition: str) -> dict:
    return {"proposed_disposition": disposition,
            "hypotheses": {"benign": {"evidence_for": [
                {"claim": "rule misfire", "cites": ["detection.ruleId", "data_quality.parser_status"]}]}}}


def test_slim_sqlite_incident_cannot_be_closed_benign():
    slim = {"incident_source": "sqlite_slim", "alerts_fetch_succeeded": False, "alerts_count": 0}
    inc = dict(SAMPLE_INCIDENT, alerts=[])
    packet = evidence_packet(incident=inc, data_availability=slim)
    assert missing_mandatory_evidence(packet) == ["raw_alerts_available"]
    a = build_assessment(_benign("false_positive"), packet)
    assert a["disposition"] == "needs_info"
    assert a["guard_actions"][0]["rule"] == "a_missing_mandatory_evidence"
    assert "raw_alerts_available" in a["guard_actions"][0]["reason"]
    assert a["uncertainty"] == "high"


def test_same_close_passes_with_raw_alerts():
    a = build_assessment(_benign("false_positive"), evidence_packet())
    assert a["disposition"] == "false_positive"


def test_unknown_fetch_outcome_blocks_benign_but_not_true_positive():
    from triage_step1_payloads import true_positive_model_output
    packet = evidence_packet(data_availability=None)
    assert build_assessment(_benign("false_positive"), packet)["disposition"] == "needs_info"
    assert build_assessment(true_positive_model_output(), packet)["disposition"] == "true_positive"


# =============================================================================
# Ranking replaces positional truncation
# =============================================================================

def test_ranking_order_rules():
    base = {"alert_name": "A", "process": "p.exe", "command_line": None, "child_processes": [],
            "child_command_lines": [], "threat_desc": [], "max_risk_score": 50.0,
            "context_tags": [], "count": 10}
    sigs = [
        dict(base, signature_id="plain", alert_name="N1"),
        dict(base, signature_id="offhour", alert_name="N2", context_tags=["network.offHour"]),
        dict(base, signature_id="rare", alert_name="N3", count=1),
        dict(base, signature_id="risky", alert_name="N4", max_risk_score=90.0),
        dict(base, signature_id="threat", alert_name="N5", threat_desc=["Trojan.X"]),
        dict(base, signature_id="lolbas", alert_name="N6"),
    ]
    ranked = ra.rank_signatures(sigs, (), {"lolbas": ["certutil.exe Download"]})
    assert [s["signature_id"] for s in ranked] == ["lolbas", "threat", "risky", "rare",
                                                    "offhour", "plain"]
    assert [s["rank"] for s in ranked] == [1, 2, 3, 4, 5, 6]


def test_compact_incident_surfaces_rare_alert_instead_of_first_12(inc_52825):
    # Positional truncation would have shown 12 "Lateral Move Detected" alerts.
    first12 = {ra.alert_name(a) for a in inc_52825["alerts"][:12]}
    assert first12 == {"Chu Wen - Lateral Move Detected"}
    text = soc_triage_agent._compact_incident(inc_52825)
    data = json.loads(text) if not text.endswith("(truncated)") else None
    assert data is not None, "compact incident must fit the prompt budget"
    sigs = data["alert_signatures"]
    assert sigs[0]["alert_name"] == "Disables UAC" and sigs[0]["count"] == 2
    assert "first 12" not in data["alerts_note"]
    n_shown = len(sigs)
    covered = sum(s["count"] for s in sigs)
    n_total = len(ra.group_signatures(inc_52825["alerts"]))
    assert data["alerts_note"].startswith(
        f"{n_shown} of {n_total} signatures ({covered} of 1000 alerts) shown")


def test_compact_incident_53021_puts_trojan_first(inc_53021):
    data = json.loads(soc_triage_agent._compact_incident(inc_53021))
    top = data["alert_signatures"][0]
    assert top["process"] == "splunkd.exe"
    assert top["threat_desc"] == ["Win64.Trojan.Goldera"]
    assert data["alerts_note"].startswith("2 of 2 signatures (6 of 6 alerts) shown")


def test_compact_incident_without_alerts_unchanged_shape():
    data = json.loads(soc_triage_agent._compact_incident({"id": "X", "title": "t"}))
    assert "alert_signatures" not in data and "alerts_sample" not in data


# =============================================================================
# data_availability threading: TriageAgent + workflow
# =============================================================================

def test_fingerprint_changes_with_data_availability():
    inc = {"id": "INC-FPDA"}
    a = soc_triage_agent._incident_fingerprint(inc, model="m")
    b = soc_triage_agent._incident_fingerprint(inc, model="m", data_availability=LIVE)
    assert a != b
    assert a == soc_triage_agent._incident_fingerprint(inc, model="m", data_availability=None)


def test_triage_agent_threads_data_availability(tmp_path, monkeypatch):
    from test_triage_step1_agent_integration import FakeLLM, _history_db, _incident
    monkeypatch.setattr(soc_triage_agent, "_TICKET_DB", tmp_path / "t.db")
    soc_triage_agent._ticket_db_init()
    agent = soc_triage_agent.TriageAgent(baseline_db_path=_history_db(tmp_path / "h.db"))
    monkeypatch.setattr(agent, "_call", FakeLLM())
    inc = _incident(alerts=SAMPLE_INCIDENT["alerts"])
    with_da = agent.triage(inc, force=True, parsed_context=SAMPLE_PARSED_CONTEXT,
                           data_availability=SAMPLE_DATA_AVAILABILITY)
    without = agent.triage(inc, force=True, parsed_context=SAMPLE_PARSED_CONTEXT)
    assert with_da["evidence_packet"]["raw_alerts"]["available"]["value"] is True
    assert without["evidence_packet"]["raw_alerts"]["available"]["status"] == "missing"
    prompt = "\n".join(m.content for m in agent._call.prompts["SOC Classification"])
    assert "raw_alerts.available" in prompt


def test_run_triage_forwards_data_availability(monkeypatch):
    from workflow import engine as sw
    import agents.triage as triage_pkg
    captured = {}

    class StubAgent:
        def __init__(self, cfg=None, progress_fn=None, baseline_db_path=None):
            pass

        def triage(self, incident, force=False, parsed_context=None, data_availability=None):
            captured["da"] = data_availability
            return {"ok": True}

    monkeypatch.setattr(triage_pkg, "TriageAgent", StubAgent)
    sw.run_triage({"id": "X"}, data_availability=LIVE)
    assert captured["da"] == LIVE
    sw.run_triage({"id": "X"})
    assert captured["da"] is None


def test_mock_triage_result_uses_data_availability():
    from workflow import engine as sw
    inc = dict(SAMPLE_INCIDENT, id="INC-MOCK-DA")
    with_da = sw.mock_triage_result(inc, data_availability=SAMPLE_DATA_AVAILABILITY)
    assert with_da["evidence_packet"]["raw_alerts"]["available"]["value"] is True
    without = sw.mock_triage_result(inc)
    assert without["evidence_packet"]["raw_alerts"]["available"]["status"] == "missing"


def test_combined_workflow_passes_recorded_availability(monkeypatch):
    """run_until_triage_approval() hands Triage the SAME data_availability it
    persisted next to the raw incident (no new network call)."""
    from workflow import engine as sw
    captured = {}
    monkeypatch.setattr(sw, "enrich_incident_with_apiretrieval_fetch",
                        lambda inc, host=None, token=None: inc)

    def fake_mock(incident, data_availability=None):
        captured["da"] = data_availability
        raise RuntimeError("stop after capture")

    monkeypatch.setattr(sw, "mock_triage_result", fake_mock)
    inc = copy.deepcopy(dict(SAMPLE_INCIDENT, id="INC-WF-DA"))
    sw.run_until_triage_approval(inc, use_mock_triage=True)
    assert captured["da"]["incident_source"] == "netwitness_live"
    assert captured["da"]["alerts_fetch_succeeded"] is True
    assert captured["da"]["alerts_count"] == 3
    assert sw.load_data_availability_for_run is not None


def test_large_parsed_context_cannot_crowd_out_raw_alert_signatures(inc_52825):
    """Found on the real path (scripts/acceptance_triage_step2.py): Parsing's
    processed_alert for INC-52825 embeds the whole normalised_alert (~1 MB);
    when it was placed first, the hard prompt cap cut off every signature."""
    big = {"parser_status": "completed", "alert_id": "INC-52825",
           "normalised_alert": {"blob": "x" * 1_000_000}, "iocs": ["1.2.3.4"] * 2000}
    text = soc_triage_agent._compact_incident(inc_52825, big)
    assert not text.endswith("(truncated)")
    data = json.loads(text)
    assert data["alert_signatures"][0]["alert_name"] == "Disables UAC"
    ctx = data["parsed_alert_context"]
    assert ctx["parser_status"] == "completed"
    assert "normalised_alert" not in ctx and "normalised_alert" in ctx["_omitted_for_prompt_budget"]
    assert len(text) <= soc_triage_agent._MAX_PROMPT_CHARS


def test_packet_prompt_render_fits_its_budget_on_1000_alert_incident(inc_52825):
    """Audit T-19: the rendered packet (9,782 chars) exceeded the documented
    cap and was not budgeted. It now fits _PACKET_PROMPT_BUDGET_CHARS by
    shrinking only raw_alerts.* list renders: every leaf / dot-path is still
    present and rule signals are untouched."""
    from agents.triage import evidence_packet as ep
    p = build_evidence_packet(inc_52825, None, measured_baseline(), _da(inc_52825))
    text = render_packet_for_prompt(p)
    assert len(text) <= ep._PACKET_PROMPT_BUDGET_CHARS
    paths = [path for path, _ in ep.iter_leaves(p)]
    assert all(f"{path} [" in text for path in paths)
    full = dict(ep.iter_leaves(p))["rule_signals.lolbas"]
    assert ep._render_value("rule_signals.lolbas", full["value"]) in text
    # the old constant name still works and names the incident-block cap
    assert soc_triage_agent._MAX_PROMPT_CHARS == soc_triage_agent._MAX_INCIDENT_BLOCK_CHARS


def test_small_packet_render_is_unchanged_by_budget():
    from agents.triage import evidence_packet as ep
    p = build_evidence_packet(SAMPLE_INCIDENT, SAMPLE_PARSED_CONTEXT, measured_baseline(), LIVE)
    text = render_packet_for_prompt(p)
    lines = []
    for path, leaf in ep.iter_leaves(p):
        v = "—" if leaf["status"] == "missing" else ep.defang_prompt_delimiters(ep._render_value(path, leaf["value"]))
        lines.append(f"{path} [{leaf['status']}] = {v}")
    assert text == "\n".join(lines)


def _phase_prompts(tmp_path, monkeypatch, inc, **kw):
    from test_triage_step1_agent_integration import FakeLLM, _history_db
    monkeypatch.setattr(soc_triage_agent, "_TICKET_DB", tmp_path / "t.db")
    soc_triage_agent._ticket_db_init()
    a = soc_triage_agent.TriageAgent(baseline_db_path=_history_db(tmp_path / "h.db"))
    fake = FakeLLM()
    monkeypatch.setattr(a, "_call", fake)
    a.triage(inc, force=True, data_availability=dict(LIVE, alerts_count=len(inc.get("alerts") or [])), **kw)
    return {k: "".join(m.content for m in v) for k, v in fake.prompts.items()}


def test_every_llm_call_fits_the_total_prompt_budget(inc_52825, tmp_path, monkeypatch):
    """Audit T-19 remainder: per-call prompts were ~18-21k chars and
    unbounded. Each call now fits _MAX_CALL_PROMPT_CHARS, even with a maximal
    analyst note, and the top-ranked signature still reaches the model."""
    note = {"note": "x" * 2000, "analyst": "A", "created_at": "t"}
    for i, kw in enumerate(({}, {"analyst_note": note})):
        sub = tmp_path / str(i)
        sub.mkdir()
        prompts = _phase_prompts(sub, monkeypatch, inc_52825, **kw)
        assert set(prompts) == {"IOC Checklists", "Risk Rating", "SOC Classification"}
        for phase, text in prompts.items():
            assert len(text) <= soc_triage_agent._MAX_CALL_PROMPT_CHARS, (phase, len(text), kw.keys())
        assert "Disables UAC" in prompts["SOC Classification"]


def test_small_incident_block_is_not_squeezed(tmp_path, monkeypatch):
    from test_triage_step1_agent_integration import _incident
    inc = _incident(id="INC-SMALL")
    prompts = _phase_prompts(tmp_path, monkeypatch, inc)
    full = soc_triage_agent._untrusted_block(soc_triage_agent._compact_incident(inc, None))
    for phase in ("Risk Rating", "SOC Classification"):
        assert full in prompts[phase]
