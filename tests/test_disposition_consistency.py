"""tests/test_disposition_consistency.py -- audit T-03 / T-04 / T-05 / T-06.

Every downstream consumer must show the SAME canonical verdict: the
analyst's reviewed disposition (triage_review.final_disposition) when one
exists, else the AI's guarded disposition (assessment.disposition). Severity
(classification) is a different axis and is never relabelled as a verdict.

T-03 final_verdict / triage_verdict (investigation sidecar -> report) emitted
     their own "Confirmed -- True Positive" label from substantiation only.
T-04 generate_triage_ai_summary's LLM context had no disposition,
     uncertainty or guard actions.
T-05 the SOC Triage Review report never showed the analyst verdict.
T-06 case facts / Ask Aegis grounding had no disposition or analyst verdict.
"""
from __future__ import annotations

import json

import pytest

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agents.triage.review import canonical_disposition

_TEMPLATES = Path(__file__).resolve().parents[1] / "agents" / "reporting" / "report_templates"


def _render_triage_review(ctx: dict) -> str:
    # Same Environment options as report_renderer.render_reports().
    env = Environment(loader=FileSystemLoader(str(_TEMPLATES)),
                      autoescape=select_autoescape(enabled_extensions=()),
                      keep_trailing_newline=True)
    return env.get_template("soc_triage_review_template.md.j2").render(**ctx)


def _triage(ai="benign_expected", analyst=None, *, flattened=False):
    assessment = {"disposition": ai, "proposed_disposition": "true_positive", "uncertainty": "medium",
                  "guard_actions": [{"rule": "c", "from": "true_positive", "to": ai,
                                     "reason": "measured prior high", "extra": "x"}]}
    tri = {"ticket": {"classification": "High", "summary": "s", "disposition": ai, "uncertainty": "medium",
                      "recommended_actions": ["a"]},
           "metakeys_payload": {"classification": "high"}}
    if not flattened:
        tri["assessment"] = assessment
    if analyst:
        tri["triage_review"] = {"final_disposition": analyst, "final_disposition_source": "analyst",
                                "ai_disposition": ai, "analyst": "Alice", "decision": "approve",
                                "agrees_with_ai": analyst == ai}
    return tri


# ── helper ──────────────────────────────────────────────────────────────────

def test_canonical_prefers_analyst_then_ai():
    c = canonical_disposition(_triage("needs_info", "benign_expected"))
    assert (c["disposition"], c["source"], c["ai_disposition"]) == ("benign_expected", "analyst", "needs_info")
    assert c["label"] == "Benign-expected"
    assert c["ai_to_analyst"] == "AI: Needs-info -> Analyst: Benign-expected"
    c = canonical_disposition(_triage("needs_info"))
    assert (c["disposition"], c["source"], c["ai_to_analyst"]) == ("needs_info", "ai", None)
    assert c["guard_actions"] == [{"rule": "c", "from": "true_positive", "to": "needs_info",
                                   "reason": "measured prior high"}]
    # flattened handoff doc (triage_result.json): ticket.disposition fallback
    assert canonical_disposition(_triage("false_positive", flattened=True))["disposition"] == "false_positive"
    c = canonical_disposition({})
    assert c["disposition"] is None and c["source"] is None and c["guard_actions"] == []
    assert canonical_disposition(_triage("bogus"))["disposition"] is None


# ── T-03 ────────────────────────────────────────────────────────────────────

def _strong_investigation():
    return {"status": "completed", "severity": "Critical", "confidence": "High",
            "iocs": [{"value": "203.0.113.9"}, {"value": "evil.example.com"}],
            "mitre_tactic": "Command and Control"}


@pytest.mark.parametrize("analyst", ["benign_expected", "false_positive"])
def test_final_verdict_never_contradicts_analyst_verdict(analyst):
    from agents.investigation.tools.final_verdict import build_final_verdict, format_final_verdict
    inc = {"id": "INC-T03", "title": "C2", "severity": "Critical", "mitre_tactic": "Command and Control"}
    v = build_final_verdict(inc, _triage("true_positive", analyst), _strong_investigation(), {})
    assert v["available"]
    assert v["analyst_disposition"] == analyst
    assert v["disposition"].startswith("Analyst verdict:")
    assert "True Positive" not in v["disposition"]
    text = format_final_verdict(v)
    assert "Analyst verdict" in text and "True Positive" not in text
    if v["stats"]["substantiation"] >= 2:
        assert v["disposition_conflict"] is True
        assert "conflict" in text.lower()


def test_final_verdict_without_review_uses_substantiation_wording():
    from agents.investigation.tools.final_verdict import build_final_verdict
    inc = {"id": "INC-T03b", "title": "x", "severity": "Low"}
    v = build_final_verdict(inc, {"ticket": {"classification": "Low"}}, {}, {})
    assert v["analyst_disposition"] is None and v["disposition_conflict"] is False
    assert "True Positive" not in v["disposition"] and "false positive" not in v["disposition"].lower()


def test_triage_verdict_carries_canonical_disposition():
    from agents.investigation.tools.triage_verdict import aggregate_verdict, format_verdict
    v = aggregate_verdict({"id": "INC-T03c", "severity": "High"}, _triage("needs_info", "benign_expected"))
    assert v["disposition"]["disposition"] == "benign_expected"
    assert "Benign-expected (analyst)" in format_verdict(v)


# ── T-04 ────────────────────────────────────────────────────────────────────

def test_triage_ai_summary_context_carries_disposition(monkeypatch):
    import integrations.openai.client as client
    from workflow import stage_summaries
    seen = {}

    def fake(prompt, system=None, **kw):
        seen["prompt"], seen["system"] = prompt, system
        return "summary"

    monkeypatch.setattr(client, "invoke_openai_text", fake)
    stage_summaries.generate_triage_ai_summary(_triage("needs_info"))
    ctx = json.loads(seen["prompt"].split("\n", 1)[1])
    assert ctx["disposition"] == "needs_info" and ctx["disposition_label"] == "Needs-info"
    assert ctx["uncertainty"] == "medium"
    assert ctx["guard_actions"][0]["rule"] == "c"
    assert "disposition" in seen["system"] and "severity" in seen["system"].lower()


# ── T-05 ────────────────────────────────────────────────────────────────────

def test_reporting_context_and_triage_review_report_show_analyst_verdict(tmp_path):
    from agents.reporting.reporting.context_builder import build_context
    tri = _triage("needs_info", "benign_expected", flattened=True)
    tri.update({"incident_id": "INC-T05", "alert_id": "INC-T05", "severity": "HIGH", "classification": "HIGH"})
    ctx = build_context({"processed_alert": {"incident_id": "INC-T05", "alert_id": "A"}, "enriched_alert": {},
                         "triage_result": tri, "investigation_result": {}, "threat_intel_result": {}})
    assert ctx["triage_disposition"]["disposition"] == "benign_expected"
    assert ctx["triage_disposition"]["source"] == "analyst"
    text = _render_triage_review(ctx)
    assert "| Disposition | Benign-expected (analyst) |" in text
    assert "AI: Needs-info -> Analyst: Benign-expected" in text
    assert "| Severity |" in text   # severity row unchanged
    # the header table stays one contiguous Markdown table (no blank rows)
    table = text[text.index("| Field |"):text.index("## 1.")].strip()
    assert "\n\n" not in table
    assert ("| Disposition | Benign-expected (analyst) |\n"
            "| Analyst Review | AI: Needs-info -> Analyst: Benign-expected |\n"
            "| Triage Uncertainty | medium |\n| Confidence |") in table


def test_triage_review_report_without_disposition_says_not_recorded():
    from agents.reporting.reporting.context_builder import build_context
    ctx = build_context({"processed_alert": {"incident_id": "I", "alert_id": "A"}, "enriched_alert": {},
                         "triage_result": {"ticket": {}, "classification": "LOW"},
                         "investigation_result": {}, "threat_intel_result": {}})
    text = _render_triage_review(ctx)
    assert "| Disposition | Not recorded |\n| Confidence |" in text


# ── T-06 ────────────────────────────────────────────────────────────────────

def test_case_facts_carry_disposition_and_analyst_verdict():
    from backend.services import case_view_service as cvs
    state = {"triage_result_json": json.dumps(_triage("needs_info", "benign_expected"))}
    stages = [{"name": n, "state": "done"} for n in cvs._NAME_TO_KEY]
    facts = cvs._confirmed_facts_block(state, stages)["triage"]
    assert facts["classification"] == "High"
    assert facts["disposition"] == "Benign-expected (analyst)"
    assert facts["ai_disposition"] == "Needs-info"
    assert facts["uncertainty"] == "medium"
    assert facts["analyst_verdict"] == "AI: Needs-info -> Analyst: Benign-expected"
