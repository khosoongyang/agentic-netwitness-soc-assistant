"""tests/test_triage_step2_canaries.py -- Triage Step 2 / X8: canary property
test (the DETERMINISTIC guarantee).

Canary testing principle: run known abused-tool (LOLBin) techniques; if any
is ever closed as benign, the thresholds are broken. The live evaluation
(scripts/eval_triage.py --mode live) checks what the LLM itself proposes;
THIS test proves that even a model that proposes false_positive or
benign_expected for every malicious canary, with as many valid citations as
it can muster, is forced to needs_info by the Python guards.

Runs through the REAL TriageAgent.triage() (LLM replaced at _call), with the
self-authored LOLBAS fixture AND with no LOLBAS cache at all.
"""
from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from agents.triage import lolbas, soc_triage_agent
from agents.triage.evidence_packet import build_evidence_packet, iter_leaves
from agents.triage.guards import build_assessment
from triage_step1_payloads import SAMPLE_PARSED_CONTEXT, measured_baseline

ROOT = Path(__file__).resolve().parents[1]
CANARY_DIR = ROOT / "tests" / "triage_eval" / "canaries"
BENIGN_SIDE = ("false_positive", "benign_expected")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


CANARIES = sorted(CANARY_DIR.glob("*.json"))
MALICIOUS = [p for p in CANARIES if _load(p)["canary"]["role"] == "malicious"]
BENIGN_PAIRS = [p for p in CANARIES if _load(p)["canary"]["role"] == "benign_pair"]


def test_canary_set_is_complete_and_paired():
    techs = {_load(p)["canary"]["technique"] for p in MALICIOUS}
    assert techs == {"T1053.005", "T1105", "T1218.011"}
    names = {p.stem for p in CANARIES}
    for p in CANARIES:
        case = _load(p)
        assert case["canary"]["pair"] in names, p.name
        assert case["label"]["source"] == "synthetic"
        if case["canary"]["role"] == "malicious":
            assert case["expected"]["must_not"] == ["false_positive", "benign_expected"]
            assert set(case["expected"]["disposition_acceptable"]) == {"true_positive", "needs_info"}
            assert case["canary"]["atomic_ref"].startswith("https://github.com/redcanaryco/")
        else:
            assert set(case["expected"]["disposition_acceptable"]) == {"needs_info", "benign_expected"}


def _packet(case: dict) -> dict:
    return build_evidence_packet(case["incident"], SAMPLE_PARSED_CONTEXT, measured_baseline(),
                                 case["data_availability"])


def _max_benign_proposals(packet: dict):
    """Adversarial model outputs: every benign-side disposition, citing every
    valid (non-missing) leaf it could (detection.*, data_quality.*, baseline.*,
    raw_alerts.*), plus a 'ruled-out' lookalike and invalid context cites."""
    valid = [p for p, leaf in iter_leaves(packet) if leaf["status"] != "missing"]
    det = [p for p in valid if p.startswith(("detection.", "data_quality."))]
    ctx = ["context.asset_context", "context.change_context", "context.confirmed_benign_history"]
    cite_sets = [det[:3], valid, det + ctx, ["raw_alerts.signers", "baseline.is_known_noisy"] + det[:1]]
    for disposition, cites in itertools.product(BENIGN_SIDE, cite_sets):
        yield {
            "proposed_disposition": disposition,
            "hypotheses": {
                "benign": {"evidence_for": [{"claim": "Signed Microsoft binary doing routine admin work.",
                                             "cites": cites}]},
                "malicious": {"evidence_against": [{"claim": "Binary is Microsoft-signed.",
                                                    "cites": ["raw_alerts.signers"]}]},
            },
            "lookalike_ruled_out": {"lookalike": "LOLBin abuse", "ruled_out": True,
                                    "reason": "signed", "cites": cites},
            "fn_cost_if_wrong": "low",
            "evidence_checked": valid,
        }


@pytest.mark.parametrize("path", MALICIOUS, ids=lambda p: p.stem)
def test_guards_never_let_a_malicious_canary_close_as_benign(path):
    case = _load(path)
    packet = _packet(case)
    for raw in _max_benign_proposals(packet):
        a = build_assessment(raw, packet)
        assert a["disposition"] == "needs_info", (raw["proposed_disposition"], a["guard_actions"])
        assert any(g["rule"] == "b_strong_signal_floor" for g in a["guard_actions"])


@pytest.mark.parametrize("path", MALICIOUS, ids=lambda p: p.stem)
def test_malicious_canary_floor_holds_without_lolbas_cache(path, monkeypatch, tmp_path):
    """Missing evidence = unknown, not safe: no LOLBAS cache must not open
    the door (abused_tool_check_unavailable joins the floor)."""
    monkeypatch.setenv(lolbas.LOLBAS_PATH_ENV, str(tmp_path / "absent.json"))
    case = _load(path)
    packet = _packet(case)
    assert packet["rule_signals"]["lolbas"]["status"] == "missing"
    for raw in _max_benign_proposals(packet):
        assert build_assessment(raw, packet)["disposition"] == "needs_info"


@pytest.mark.parametrize("path", MALICIOUS, ids=lambda p: p.stem)
def test_malicious_canary_has_a_strong_abused_tool_hit(path):
    packet = _packet(_load(path))
    labels = packet["rule_signals"]["lolbas"]["value"]["floor_labels"]
    tech = _load(path)["canary"]["technique"]
    binary = {"T1053.005": "schtasks.exe", "T1105": "certutil.exe", "T1218.011": "rundll32.exe"}[tech]
    assert any(l.startswith(f"lolbas:{binary}") for l in labels), labels


@pytest.mark.parametrize("path", BENIGN_PAIRS, ids=lambda p: p.stem)
def test_benign_lookalike_has_no_strong_abused_tool_hit(path):
    """The paired lookalike shares the binary but not the abuse argument."""
    packet = _packet(_load(path))
    assert packet["rule_signals"]["lolbas"]["value"]["floor_labels"] == []
    assert packet["rule_signals"]["masquerade"]["value"]["floor_labels"] == []


@pytest.mark.parametrize("path", BENIGN_PAIRS, ids=lambda p: p.stem)
def test_benign_pair_guards_only_ever_downgrade(path):
    """The guarantee for the benign lookalikes is weaker by design: guards
    never UPGRADE (a benign proposal ends as itself or needs_info, never
    true_positive). Whether the proposal is in the acceptable set
    [needs_info, benign_expected] is what the eval harness measures
    (acceptable-hit rate) -- a well-cited false_positive on a lookalike is a
    miss there, not a guard failure, because false_positive is not in the
    benign pair's must_not list."""
    case = _load(path)
    packet = _packet(case)
    for raw in _max_benign_proposals(packet):
        out = build_assessment(raw, packet)["disposition"]
        assert out in (raw["proposed_disposition"], "needs_info")
        assert out not in case["expected"]["must_not"]
    # With business context absent, benign_expected itself is unreachable
    # (Step-1 guard c), so the only acceptable benign-pair outcome today is
    # needs_info: still acceptable, never a closed alert.
    be = build_assessment(next(r for r in _max_benign_proposals(packet)
                               if r["proposed_disposition"] == "benign_expected"), packet)
    assert be["disposition"] == "needs_info"


# =============================================================================
# The same guarantee through the REAL TriageAgent.triage() path
# =============================================================================

class _AlwaysBenignLLM:
    def __init__(self, disposition: str):
        self.disposition = disposition

    def __call__(self, messages, phase_label):
        if phase_label == "IOC Checklists":
            return json.dumps({"availability": {"matched_iocs": []},
                               "confidentiality": {"matched_iocs": []},
                               "integrity": {"matched_iocs": []}})
        if phase_label == "Risk Rating":
            return json.dumps({"likelihood_initiation": "Low", "likelihood_occurrence": "Low",
                               "likelihood_adverse_impact": "Low", "overall_risk": "Low",
                               "rationale": "routine admin"})
        return json.dumps({
            "classification": "Low", "incident_category": "Unknown Source IP",
            "summary": "Routine signed Windows tool use.", "recommended_actions": ["Close"],
            "mitre_tactic": "Execution", "mitre_technique": "Unknown",
            "proposed_disposition": self.disposition,
            "hypotheses": {"benign": {"evidence_for": [
                {"claim": "Microsoft-signed binary, rule is noisy.",
                 "cites": ["detection.ruleId", "data_quality.parser_status", "raw_alerts.signers"]}]}},
            "lookalike_ruled_out": {"lookalike": "LOLBin abuse", "ruled_out": True,
                                    "reason": "signed", "cites": ["raw_alerts.signers"]},
            "fn_cost_if_wrong": "minimal", "evidence_checked": ["raw_alerts.signers"]})


@pytest.mark.parametrize("disposition", BENIGN_SIDE)
@pytest.mark.parametrize("path", MALICIOUS, ids=lambda p: p.stem)
def test_triage_agent_forces_needs_info_on_canary(path, disposition, tmp_path, monkeypatch):
    monkeypatch.setattr(soc_triage_agent, "_TICKET_DB", tmp_path / "t.db")
    soc_triage_agent._ticket_db_init()
    agent = soc_triage_agent.TriageAgent(baseline_db_path=tmp_path / "no-history.db")
    monkeypatch.setattr(agent, "_call", _AlwaysBenignLLM(disposition))
    case = _load(path)
    result = agent.triage(case["incident"], force=True, parsed_context=SAMPLE_PARSED_CONTEXT,
                          data_availability=case["data_availability"])
    assert result.get("error") is None
    assert result["assessment"]["proposed_disposition"] == disposition
    assert result["assessment"]["disposition"] == "needs_info"
    assert result["ticket"]["disposition"] == "needs_info"


def test_unchecked_abused_tool_floor_only_when_there_is_something_to_check(monkeypatch, tmp_path):
    """No LOLBAS cache + command lines present -> abused_tool_check_unavailable
    joins the floor. No command lines (meta-only ESA alerts) -> nothing to
    check, so the Step-1 behaviour is unchanged."""
    from triage_step1_payloads import evidence_packet
    from agents.triage.guards import strong_rule_signals
    monkeypatch.setenv(lolbas.LOLBAS_PATH_ENV, str(tmp_path / "absent.json"))
    case = _load(MALICIOUS[0])
    assert lolbas.UNCHECKED_FLOOR_LABEL in strong_rule_signals(_packet(case))
    assert lolbas.UNCHECKED_FLOOR_LABEL not in strong_rule_signals(evidence_packet())


def test_ticket_db_env_override_keeps_soc_db_untouched(tmp_path):
    """AEGIS_TICKET_DB (used by scripts/eval_triage.py) redirects the ticket
    and triage-cache DB at import time."""
    import os
    import subprocess
    import sys
    target = tmp_path / "eval_tickets.db"
    env = dict(os.environ, AEGIS_TICKET_DB=str(target), OPENAI_API_KEY="sk-offline-dummy")
    out = subprocess.run(
        [sys.executable, "-c",
         "from agents.triage import soc_triage_agent as s; print(s._TICKET_DB)"],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == str(target)
    assert target.exists()
