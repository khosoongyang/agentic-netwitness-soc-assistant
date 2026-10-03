"""tests/test_triage_guard_decisions.py -- audit T-18 (decision pinned).

context.analyst_note / context.suppression_match make benign_expected
reachable (guard rules b/c) but deliberately do NOT count toward evidence
completeness / uncertainty: uncertainty describes machine-measured evidence,
and a human claim must not come back to the reviewer as AI certainty.
"""
from __future__ import annotations

from agents.triage import guards
from agents.triage.evidence_packet import build_evidence_packet

from triage_step1_payloads import (SAMPLE_DATA_AVAILABILITY, SAMPLE_INCIDENT, SAMPLE_PARSED_CONTEXT,
                                   measured_baseline)


def test_human_context_is_not_core_evidence():
    assert "context.analyst_note" not in guards.CORE_EVIDENCE
    assert "context.suppression_match" not in guards.CORE_EVIDENCE


def test_analyst_note_does_not_change_uncertainty():
    args = (SAMPLE_INCIDENT, SAMPLE_PARSED_CONTEXT, measured_baseline(), SAMPLE_DATA_AVAILABILITY)
    without = build_evidence_packet(*args)
    with_note = build_evidence_packet(*args, analyst_note={"note": "CHG-1 approved", "analyst": "A",
                                                           "created_at": "t"})
    assert guards.evidence_completeness(with_note) == guards.evidence_completeness(without)
    assert guards.compute_uncertainty(with_note) == guards.compute_uncertainty(without)


def test_stale_unreachable_claim_removed():
    from pathlib import Path
    root = Path(guards.__file__).resolve().parents[2]
    assert "unreachable by design" not in (root / "docs/triage-evaluation.md").read_text(encoding="utf-8")
    assert "makes benign_expected unreachable while" not in Path(guards.__file__).read_text(encoding="utf-8")


def test_core_docs_describe_current_triage():
    """Audit T-23: the four core docs mention the evidence-first triage."""
    from pathlib import Path
    root = Path(guards.__file__).resolve().parents[2]
    need = {"README.md": ["disposition", "triage-review.md"],
            "docs/architecture.md": ["evidence_packet", "canonical_disposition"],
            "docs/workflow.md": ["triage_reviews", "analyst_note"],
            "docs/configuration.md": ["AEGIS_LOLBAS_PATH", "AEGIS_TICKET_DB", "TRIAGE_JSON_MODE",
                                      "suppression_proposals"]}
    for doc, words in need.items():
        text = (root / doc).read_text(encoding="utf-8")
        for w in words:
            assert w in text, (doc, w)
