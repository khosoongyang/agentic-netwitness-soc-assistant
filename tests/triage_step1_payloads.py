"""tests/triage_step1_payloads.py -- shared, offline fixture builders for the
Triage Step 1 contract additions (evidence_packet / assessment /
ticket.disposition / ticket.uncertainty).

Not a test module (no ``test_`` prefix, so pytest does not collect it).
Everything here runs the REAL deterministic builders
(agents/triage/evidence_packet.py, agents/triage/guards.py) on synthetic
input -- no database, no LLM, no network.
"""
from __future__ import annotations

from agents.triage.evidence_packet import build_evidence_packet
from agents.triage.guards import build_assessment

SAMPLE_INCIDENT = {
    "id": "INC-1001",
    "title": "High Risk Alerts: ESA for 10.0.0.5",
    "created": "2026-07-20T10:00:00.000Z",
    "createdBy": "High Risk Alerts: ESA",
    "ruleId": "6618e5a2dddef60d6853bec1",
    "riskScore": 70,
    "priority": "High",
    "alertCount": 3,
    "eventCount": 3,
    "sources": ["Event Stream Analysis"],
}

SAMPLE_PARSED_CONTEXT = {
    "parser_status": "completed",
    "parser_metadata": {"parser_confidence": "High", "missing_fields": []},
    "data_quality": {"parser_confidence": "High", "parser_confidence_score": 90},
}


def measured_baseline(**overrides) -> dict:
    """A compute_baseline()-shaped dict with status "measured"."""
    base = {
        "status": "measured", "reason": "measured from 12 prior incident(s)",
        "db_source": "soc_incidents.db:incidents", "as_of": "2026-07-20T10:00:00",
        "as_of_field": "incident.created", "incident_id": "INC-1001",
        "entity": "10.0.0.5", "entity_kind": "ip_internal", "entity_source": "incident.title",
        "created_by": "High Risk Alerts: ESA", "rule_id": "6618e5a2dddef60d6853bec1",
        "same_source_entity": {"7d": 1, "30d": 4, "90d": 10, "all_time": 12},
        "same_entity_any_source": {"7d": 1, "30d": 4, "90d": 10, "all_time": 12},
        "window_complete": {"7d": True, "30d": True, "90d": True},
        "first_seen": "2025-01-01T00:00:00", "last_seen": "2026-07-19T09:00:00",
        "is_first_occurrence": False, "is_known_noisy": False,
        "known_noisy_threshold_30d": 30,
        "coverage_start": "2024-07-22T08:31:23", "coverage_end": "2026-07-27T07:37:48",
    }
    base.update(overrides)
    return base


def unknown_baseline(reason: str = "baseline database not found (x.db)") -> dict:
    return {"status": "unknown", "reason": reason, "db_source": "x.db:incidents"}


def evidence_packet(incident: dict | None = None, parsed_context: dict | None = None,
                    baseline: dict | None = None) -> dict:
    return build_evidence_packet(
        incident if incident is not None else SAMPLE_INCIDENT,
        parsed_context if parsed_context is not None else SAMPLE_PARSED_CONTEXT,
        baseline if baseline is not None else measured_baseline(),
    )


def true_positive_model_output() -> dict:
    """A well-cited model proposal of true_positive."""
    return {
        "proposed_disposition": "true_positive",
        "hypotheses": {
            "malicious": {
                "evidence_for": [{"claim": "NetWitness risk score is 70.",
                                  "cites": ["detection.riskScore"]}],
                "evidence_against": [{"claim": "The detection fires on this entity regularly.",
                                      "cites": ["baseline.same_source_entity_30d"]}],
            },
            "benign": {
                "evidence_for": [],
                "evidence_against": [{"claim": "No change record explains it.",
                                      "cites": ["detection.alertCount"]}],
            },
        },
        "lookalike_ruled_out": {"lookalike": "Credential brute force", "ruled_out": False,
                                "reason": "Not excluded by the evidence.",
                                "cites": ["detection.createdBy"]},
        "fn_cost_if_wrong": "An active intrusion on 10.0.0.5 would be missed.",
        "evidence_checked": ["detection.riskScore", "baseline.status", "context.asset_context"],
    }


def assessment(packet: dict | None = None, raw: dict | None = None) -> dict:
    return build_assessment(raw if raw is not None else true_positive_model_output(),
                            packet if packet is not None else evidence_packet())
