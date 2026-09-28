# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# =============================================================================
# File: scripts/demo_triage_step1.py
# Purpose: Offline demonstration of Triage Step 1 (measured baseline ->
#   evidence packet -> cited hypotheses -> citation verification -> Python
#   guards) on the demo incidents, with the LLM replaced by a canned,
#   deliberately imperfect model answer. Prints the evidence packet and the
#   final assessment. With --live and OPENAI_API_KEY set, also runs one real
#   triage.
# Inputs: demo/sample_incident.json, demo/incident_INC-53021_respond_api_export.json,
#   soc_db/soc_incidents.db (read-only, baseline only).
# Outputs: stdout only. Tickets/cache rows go to a temp DB. (Importing
#   soc_triage_agent still runs its pre-existing import-time
#   _ticket_db_init() CREATE-IF-NOT-EXISTS on soc_db/soc_tickets.db, as any
#   import of the triage agent always has; this script adds no writes.)
# Key evaluator search terms: demo_triage_step1, [FYP-TRIAGE-STEP1].
# =============================================================================
"""Usage:  python scripts/demo_triage_step1.py [--live]"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("OPENAI_API_KEY", "")  # never needed for the mocked run

from agents.triage import soc_triage_agent  # noqa: E402
from agents.triage.evidence_packet import render_packet_for_prompt  # noqa: E402

SOC_DB = ROOT / "soc_db" / "soc_incidents.db"

# What a (sloppy) model might answer for the SOC Classification phase: one
# well-cited malicious claim, one benign claim citing a MISSING context field,
# one claim citing a path that does not exist, and a benign proposal.
CANNED_MODEL_ASSESSMENT = {
    "proposed_disposition": "benign_expected",
    "hypotheses": {
        "malicious": {
            "evidence_for": [
                {"claim": "NetWitness scored the incident high risk.",
                 "cites": ["detection.riskScore", "detection.priority"]},
                {"claim": "The deterministic scorer found strong indicators.",
                 "cites": ["rule_signals.malware", "rule_signals.privilege_escalation"]},
            ],
            "evidence_against": [
                {"claim": "This detection has fired on this entity before.",
                 "cites": ["baseline.same_source_entity_90d", "baseline.is_first_occurrence"]},
            ],
        },
        "benign": {
            "evidence_for": [
                {"claim": "The host is an admin jump box doing routine maintenance.",
                 "cites": ["context.asset_context", "context.change_context"]},
                {"claim": "The user is an approved service account.",
                 "cites": ["entity.owner_role"]},
            ],
            "evidence_against": [],
        },
    },
    "lookalike_ruled_out": {
        "lookalike": "Credential theft followed by hands-on-keyboard activity",
        "ruled_out": True,
        "reason": "Change window covers it.",
        "cites": ["context.change_context"],
    },
    "fn_cost_if_wrong": "An active intrusion would be closed without response.",
    "evidence_checked": ["baseline.status", "context.asset_context", "detection.riskScore"],
}


# A disciplined model answer: every claim cites measured evidence.
CANNED_TRUE_POSITIVE = {
    "proposed_disposition": "true_positive",
    "hypotheses": {
        "malicious": {
            "evidence_for": [
                {"claim": "Endpoint alerts name a C2 connection and a trojan detection.",
                 "cites": ["rule_signals.malware"]},
                {"claim": "NetWitness risk score 70, priority HIGH, 6 alerts.",
                 "cites": ["detection.riskScore", "detection.priority", "detection.alertCount"]},
            ],
            "evidence_against": [
                {"claim": "The same detection fired on this host 4 times in the prior 30 days.",
                 "cites": ["baseline.same_source_entity_30d"]},
            ],
        },
        "benign": {
            "evidence_for": [],
            "evidence_against": [
                {"claim": "The host is not a known-noisy source for this rule.",
                 "cites": ["baseline.is_known_noisy"]},
            ],
        },
    },
    "lookalike_ruled_out": {
        "lookalike": "Real C2 beaconing from KELLYWANG", "ruled_out": False,
        "reason": "No asset or change context exists to explain the activity.",
        "cites": ["rule_signals.malware"]},
    "fn_cost_if_wrong": "An active C2 channel on a workstation would stay open.",
    "evidence_checked": ["baseline.status", "rule_signals.malware", "context.asset_context",
                         "context.change_context"],
}


def make_fake_llm(assessment: dict):
    def fake(messages, phase_label):
        return _fake_llm(messages, phase_label, assessment)
    return fake


def _fake_llm(messages, phase_label, assessment):
    if phase_label == "IOC Checklists":
        return json.dumps({"availability": {"matched_iocs": []},
                           "confidentiality": {"matched_iocs": [2], "reasoning": "mock"},
                           "integrity": {"matched_iocs": [6], "reasoning": "mock"}})
    if phase_label == "Risk Rating":
        return json.dumps({"likelihood_initiation": "High", "likelihood_occurrence": "Medium",
                           "likelihood_adverse_impact": "High", "overall_risk": "High",
                           "rationale": "MOCK: occurrence taken from the measured baseline."})
    answer = {"classification": "High", "incident_category": "Unauthorized access",
              "summary": "MOCK summary.", "recommended_actions": ["MOCK: review the host"],
              "mitre_tactic": "Command and Control", "mitre_technique": "T1071"}
    answer.update(assessment)
    return json.dumps(answer)


def load_demo(name: str) -> dict:
    data = json.loads((ROOT / "demo" / name).read_text(encoding="utf-8"))
    if "incident" in data and isinstance(data["incident"], dict):   # Respond-API export
        inc = dict(data["incident"])
        inc["alerts"] = data.get("alerts") or []
        return inc
    return data


def parse(inc: dict, tmp: Path) -> dict | None:
    """Run the REAL Parsing stage (rule-based, no LLM) into a temp dir.
    Like workflow/engine.py, its processed_alert is only handed to Triage
    when Parsing completed; otherwise data_quality.* stays missing."""
    try:
        from agents.parsing import run_parser_normalisation_for_dashboard
        res = run_parser_normalisation_for_dashboard(inc, output_dir=tmp / "parsing")
    except Exception as exc:   # parsing is optional for the demo
        print(f"(Parsing stage raised: {exc})")
        return None
    print(f"Parsing stage status for {inc.get('id')}: {res.get('status')} "
          f"({res.get('summary')})")
    return res.get("processed_alert") if res.get("status") == "completed" else None


def run(inc: dict, label: str, live: bool = False, parsed_context: dict | None = None,
        assessment: dict | None = None) -> None:
    agent = soc_triage_agent.TriageAgent(baseline_db_path=SOC_DB)
    if not live:
        agent._call = make_fake_llm(assessment or CANNED_MODEL_ASSESSMENT)
    result = agent.triage(inc, force=True, parsed_context=parsed_context)
    if result.get("error"):
        print(f"ERROR: {result['error']}")
        return
    print("=" * 78)
    print(f"{label}: {inc.get('id')}  --  {inc.get('title') or inc.get('name')}")
    print("=" * 78)
    print("\n--- EVIDENCE PACKET (dot.path [status] = value) ---")
    print(render_packet_for_prompt(result["evidence_packet"]))
    print("\n--- SEVERITY (unchanged) ---")
    t = result["ticket"]
    print(f"classification={t['classification']}  risk={t['risk_rating']}")
    print("\n--- FINAL ASSESSMENT ---")
    print(json.dumps(result["assessment"], indent=2, ensure_ascii=False))
    print(f"\nticket.disposition={t['disposition']}  ticket.uncertainty={t['uncertainty']}\n")


def main() -> None:
    live = "--live" in sys.argv
    with tempfile.TemporaryDirectory() as tmp:
        soc_triage_agent._TICKET_DB = Path(tmp) / "demo_tickets.db"   # never write soc_db/
        soc_triage_agent._ticket_db_init()
        run(load_demo("sample_incident.json"),
            "[1] MOCKED LLM (sloppy benign_expected proposal) - sample_incident.json")
        export = load_demo("incident_INC-53021_respond_api_export.json")
        parsed = parse(export, Path(tmp))
        run(export, "[2] MOCKED LLM (sloppy benign_expected proposal) - INC-53021",
            parsed_context=parsed)
        run(export, "[3] MOCKED LLM (well-cited true_positive proposal) - INC-53021",
            parsed_context=parsed, assessment=CANNED_TRUE_POSITIVE)
        if live:
            if os.environ.get("OPENAI_API_KEY", "").strip():
                run(export, "LIVE LLM - INC-53021", live=True, parsed_context=parsed)
            else:
                print("--live requested but OPENAI_API_KEY is not set; skipped.")


if __name__ == "__main__":
    main()
