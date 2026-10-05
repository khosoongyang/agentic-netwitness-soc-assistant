"""tests/test_triage_citation_prompt.py -- live finding after the audit fixes.

Live gpt-4o-mini runs on INC-52825 (1,000 alerts) cited the decisive "Disables
UAC" / lateral-movement alerts as `raw_alerts.alert_signatures[0].alert_name`
-- a field of the INCIDENT block, with an index and a sub-field -- which is not
an evidence-packet leaf. Code correctly deleted those claims, and 2 of 3 runs
fell to needs_info although the evidence WAS in the packet
(raw_alerts.alert_names, rule_signals.privilege_escalation). It also cited
[missing] leaves (context.analyst_note). The disposition method now says
exactly what a citable path is and maps the incident-block fields to the
packet paths that carry the same evidence.
"""
from __future__ import annotations

import re

from agents.triage import soc_triage_agent as sta
from agents.triage.evidence_packet import build_evidence_packet, get_leaf

from triage_step1_payloads import (SAMPLE_DATA_AVAILABILITY, SAMPLE_INCIDENT, SAMPLE_PARSED_CONTEXT,
                                   measured_baseline)


def test_method_defines_a_citable_path_exactly():
    m = sta._DISPOSITION_METHOD
    assert "exactly as it appears at the start of an EVIDENCE PACKET line" in m
    assert "no [index]" in m and "no sub-field" in m
    assert "INCIDENT block" in m and "not citable" in m
    assert "Never cite a [missing] path" in m


def test_every_path_the_method_recommends_is_a_real_packet_leaf():
    """The method must never teach the model a path that does not exist."""
    packet = build_evidence_packet(SAMPLE_INCIDENT, SAMPLE_PARSED_CONTEXT, measured_baseline(),
                                   SAMPLE_DATA_AVAILABILITY)
    recommended = set(re.findall(r"\b((?:raw_alerts|rule_signals|baseline|detection|entity|data_quality|context)"
                                 r"\.[a-z_]+)\b", sta._DISPOSITION_METHOD))
    assert {"raw_alerts.alert_names", "raw_alerts.signatures", "raw_alerts.processes",
            "raw_alerts.command_lines"} <= recommended
    # rule_signals.<label> leaves exist only when that rule fired, so those
    # examples must be real labels of the rule scanner (or the two abused-tool
    # leaves); every other recommended path must exist in any packet.
    from agents.triage.evidence_packet import STRONG_SIGNAL_LABELS
    dynamic = {f"rule_signals.{l}" for l in STRONG_SIGNAL_LABELS} | {"rule_signals.lolbas", "rule_signals.masquerade"}
    rule_examples = {p for p in recommended if p.startswith("rule_signals.")}
    assert rule_examples and rule_examples <= dynamic, rule_examples - dynamic
    unknown = sorted(p for p in recommended - rule_examples if get_leaf(packet, p) is None)
    assert unknown == []


def test_prompt_version_bumped_for_the_method_change():
    assert sta.TRIAGE_PROMPT_VERSION in ("2026-10-citation-paths", "2026-10-constrained-citations")
