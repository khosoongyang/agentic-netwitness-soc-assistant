"""tests/test_triage_constrained_citations.py -- improvement #1.

Live gpt-4o-mini runs still invented citation paths in roughly 1 run in 7
(e.g. "raw_alerts.alertCount", "IOC FINDINGS"); code then deleted those
claims, so some runs lost their strongest evidence. For OpenAI hosts the
SOC Classification call now uses a strict JSON schema in which every
`cites` / `evidence_checked` item is an ENUM of the packet paths that are
actually citable (present and not [missing]). The model cannot emit an
invented or [missing] path at all. The guards stay as the second line of
defence, and providers without json_schema support keep the old behaviour.
"""
from __future__ import annotations

import json

import pytest

from agents.triage import soc_triage_agent as sta
from agents.triage.evidence_packet import build_evidence_packet, get_leaf, iter_leaves

from triage_step1_payloads import (SAMPLE_DATA_AVAILABILITY, SAMPLE_INCIDENT, SAMPLE_PARSED_CONTEXT,
                                   measured_baseline)


def _packet():
    return build_evidence_packet(SAMPLE_INCIDENT, SAMPLE_PARSED_CONTEXT, measured_baseline(),
                                 SAMPLE_DATA_AVAILABILITY)


def test_citable_paths_are_exactly_the_non_missing_leaves():
    p = _packet()
    paths = sta._citable_paths(p)
    expected = sorted(path for path, leaf in iter_leaves(p) if leaf["status"] != "missing")
    assert paths == expected and paths
    assert "context.analyst_note" not in paths           # [missing] in this packet
    assert all(get_leaf(p, x) is not None for x in paths)


def _walk(node, out):
    if isinstance(node, dict):
        if node.get("type") == "array" and isinstance(node.get("items"), dict) and "enum" in node["items"]:
            out.append(node["items"]["enum"])
        for v in node.values():
            _walk(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk(v, out)


def test_classification_schema_restricts_every_cite_to_citable_paths():
    p = _packet()
    schema = sta._classification_response_format(p)
    assert schema["type"] == "json_schema" and schema["json_schema"]["strict"] is True
    enums = []
    _walk(schema["json_schema"]["schema"], enums)
    # hypotheses x4 claim lists, lookalike cites, evidence_checked
    assert len(enums) >= 6
    for e in enums:
        assert e == sta._citable_paths(p)
    props = schema["json_schema"]["schema"]["properties"]
    assert props["proposed_disposition"]["enum"] == ["true_positive", "false_positive",
                                                     "benign_expected", "needs_info"]
    assert props["classification"]["enum"] == ["Critical", "High", "Medium", "Low"]


def _strict_ok(node):
    """OpenAI strict mode: every object lists all its properties as required
    and sets additionalProperties false."""
    if isinstance(node, dict):
        if node.get("type") == "object":
            assert node.get("additionalProperties") is False, node
            assert sorted(node.get("required") or []) == sorted(node.get("properties") or {}), node
        for v in node.values():
            _strict_ok(v)
    elif isinstance(node, list):
        for v in node:
            _strict_ok(v)


def test_schema_is_valid_for_openai_strict_mode():
    _strict_ok(sta._classification_response_format(_packet())["json_schema"]["schema"])


def test_classification_call_binds_schema_only_for_openai_hosts(tmp_path, monkeypatch):
    from test_triage_step1_agent_integration import FakeLLM, _history_db, _incident
    monkeypatch.setattr(sta, "_TICKET_DB", tmp_path / "t.db")
    sta._ticket_db_init()
    for base_url, expect in (("https://api.openai.com/v1", True), ("http://localhost:11434/v1", False)):
        a = sta.TriageAgent(cfg=sta.OpenAILLMConfig(api_key="sk-x", base_url=base_url),
                            baseline_db_path=_history_db(tmp_path / f"h{expect}.db"))
        seen = {}

        def fake_call(messages, phase_label, response_format=None, _seen=seen, _f=FakeLLM()):
            _seen[phase_label] = response_format
            return _f(messages, phase_label)

        monkeypatch.setattr(a, "_call", fake_call)
        a.triage(_incident(id=f"INC-CC-{expect}"), force=True)
        rf = seen["SOC Classification"]
        assert (rf is not None and rf["type"] == "json_schema") is expect, base_url
        assert seen["IOC Checklists"] is None and seen["Risk Rating"] is None


def test_constrained_output_still_flows_through_the_guards(tmp_path, monkeypatch):
    """A schema-valid answer is still verified: guards are unchanged."""
    from test_triage_step1_agent_integration import FakeLLM, _history_db, _incident
    monkeypatch.setattr(sta, "_TICKET_DB", tmp_path / "t.db")
    sta._ticket_db_init()
    a = sta.TriageAgent(baseline_db_path=_history_db(tmp_path / "h.db"))
    monkeypatch.setattr(a, "_call", lambda m, label, response_format=None: FakeLLM()(m, label))
    res = a.triage(_incident(id="INC-CC-G"), force=True)
    assert res["assessment"]["disposition"] in ("true_positive", "false_positive", "benign_expected", "needs_info")


def test_two_argument_harness_replacements_keep_working(tmp_path, monkeypatch):
    """Acceptance / eval scripts replace TriageAgent._call (class level) with
    fake_call(self, messages, phase_label); they must not receive the new
    keyword."""
    from test_triage_step1_agent_integration import FakeLLM, _history_db, _incident
    monkeypatch.setattr(sta, "_TICKET_DB", tmp_path / "t.db")
    sta._ticket_db_init()
    fake = FakeLLM()

    def fake_call(self, messages, phase_label):
        return fake(messages, phase_label)

    monkeypatch.setattr(sta.TriageAgent, "_call", fake_call)
    a = sta.TriageAgent(cfg=sta.OpenAILLMConfig(api_key="sk-x"), baseline_db_path=_history_db(tmp_path / "h.db"))
    res = a.triage(_incident(id="INC-CC-H"), force=True)
    assert not res.get("error"), res.get("error")
