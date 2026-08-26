"""tests/test_investigation_result_contract.py -- Phase 1 of the canonical
Investigation Result contract migration.

Pure model tests for `agents.investigation.investigation_result`: field
shape, required/optional semantics, enum constraints, and round-trip
serialization. No production execution path (orchestrator.py, main.py,
workflow/engine.py) is imported or exercised here -- this module has zero
production callers yet.
"""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agents.investigation.investigation_result import (
    BusinessImpactAssessment,
    InvestigationAgentOutput,
    MilestoneExecutionRecord,
    MitreMappingRecord,
    PolicyAuditRecordSummary,
)


def _minimal_agent_output_kwargs() -> dict:
    """A minimal, valid payload covering every required field."""
    return dict(
        incident_id="Incident-001",
        severity="High",
        confidence="Medium",
        execution_trace=[
            {
                "step_id": "step_1",
                "instruction": "Check for lateral movement",
                "status": "MET",
                "findings": "No lateral movement observed.",
            }
        ],
        incident_summary="A phishing email led to a single compromised host.",
        actions_taken=["Isolated host", "Reset user credentials"],
        recommended_containment=["Block sender domain", "Force password reset"],
        business_impact_checklist={
            "critical_system": "no",
            "essential_service": "no",
            "data_sensitivity": "unknown",
            "operational_impact": "no",
        },
        severity_justification="Single host, contained quickly.",
        confidence_justification="Strong correlation across all evidence sources.",
    )


# =============================================================================
# Required / optional semantics
# =============================================================================

def test_minimal_required_fields_validate():
    output = InvestigationAgentOutput.model_validate(_minimal_agent_output_kwargs())
    assert output.incident_id == "Incident-001"
    assert output.mitre_mappings == []
    assert output.policy_audit_logs == []
    assert output.mitre_attack_table is None


@pytest.mark.parametrize(
    "missing_field",
    [
        "incident_id",
        "severity",
        "confidence",
        "execution_trace",
        "incident_summary",
        "actions_taken",
        "recommended_containment",
        "business_impact_checklist",
        "severity_justification",
        "confidence_justification",
    ],
)
def test_required_field_missing_is_rejected(missing_field):
    payload = _minimal_agent_output_kwargs()
    del payload[missing_field]
    with pytest.raises(ValidationError):
        InvestigationAgentOutput.model_validate(payload)


def test_optional_fields_may_be_omitted():
    payload = _minimal_agent_output_kwargs()
    assert "mitre_mappings" not in payload
    assert "mitre_attack_table" not in payload
    assert "policy_audit_logs" not in payload
    InvestigationAgentOutput.model_validate(payload)  # must not raise


# =============================================================================
# Enum / literal constraints (mirrors FinalIncidentAnalysis's Literal types)
# =============================================================================

@pytest.mark.parametrize("bad_severity", ["low", "Extreme", "", "MEDIUM"])
def test_invalid_severity_literal_is_rejected(bad_severity):
    payload = _minimal_agent_output_kwargs()
    payload["severity"] = bad_severity
    with pytest.raises(ValidationError):
        InvestigationAgentOutput.model_validate(payload)


@pytest.mark.parametrize("bad_confidence", ["low", "Certain", ""])
def test_invalid_confidence_literal_is_rejected(bad_confidence):
    payload = _minimal_agent_output_kwargs()
    payload["confidence"] = bad_confidence
    with pytest.raises(ValidationError):
        InvestigationAgentOutput.model_validate(payload)


@pytest.mark.parametrize("bad_status", ["met", "PARTIAL", ""])
def test_invalid_milestone_status_literal_is_rejected(bad_status):
    payload = _minimal_agent_output_kwargs()
    payload["execution_trace"][0]["status"] = bad_status
    with pytest.raises(ValidationError):
        InvestigationAgentOutput.model_validate(payload)


# =============================================================================
# Nested model shapes
# =============================================================================

def test_milestone_execution_record_shape():
    record = MilestoneExecutionRecord(
        step_id="step_2", instruction="Check DNS logs", status="NOT_MET", findings="No data."
    )
    assert record.model_dump() == {
        "step_id": "step_2",
        "instruction": "Check DNS logs",
        "status": "NOT_MET",
        "findings": "No data.",
    }


def test_mitre_mapping_record_shape():
    record = MitreMappingRecord(
        timeline_phase="Initial Access",
        observed_evidence="Phishing email with malicious link",
        tactic="Initial Access",
        technique_name="Phishing: Spearphishing Link",
        technique_id="T1566.002",
    )
    assert record.technique_id == "T1566.002"


def test_policy_audit_record_summary_default_agent_name_and_optional_reviewer():
    record = PolicyAuditRecordSummary(
        audit_id="AUD-1",
        incident_id="Incident-001",
        policy_reference="POL-4.2",
        decision_point="Containment Approval",
        input_summary="Automated containment recommended.",
        result="Pass",
        decision_made="Contain",
        timestamp=1700000000.0,
        evidence_reference="EVID-1",
        human_review_required=False,
    )
    assert record.agent_name == "Investigation Agent"
    assert record.final_reviewer is None


def test_business_impact_assessment_requires_all_four_fields():
    with pytest.raises(ValidationError):
        BusinessImpactAssessment(critical_system="no", essential_service="no")


# =============================================================================
# Round-trip serialization
# =============================================================================

def _full_agent_output_kwargs() -> dict:
    payload = _minimal_agent_output_kwargs()
    payload["mitre_mappings"] = [
        {
            "timeline_phase": "Initial Access",
            "observed_evidence": "Phishing email received",
            "tactic": "Initial Access",
            "technique_name": "Phishing: Spearphishing Link",
            "technique_id": "T1566.002",
        }
    ]
    payload["mitre_attack_table"] = "| Phase | Tactic | Technique |\n| --- | --- | --- |\n"
    payload["policy_audit_logs"] = [
        {
            "audit_id": "AUD-1",
            "incident_id": "Incident-001",
            "agent_name": "Investigation Agent",
            "policy_reference": "POL-4.2",
            "decision_point": "Containment Approval",
            "input_summary": "Automated containment recommended.",
            "result": "Pass",
            "decision_made": "Contain",
            "timestamp": 1700000000.0,
            "evidence_reference": "EVID-1",
            "human_review_required": True,
            "final_reviewer": "analyst@example.com",
        }
    ]
    return payload


def test_full_payload_round_trips_through_json():
    payload = _full_agent_output_kwargs()
    output = InvestigationAgentOutput.model_validate(payload)

    dumped = output.model_dump(mode="json")
    reparsed_from_json_text = json.loads(json.dumps(dumped))
    round_tripped = InvestigationAgentOutput.model_validate(reparsed_from_json_text)

    assert round_tripped == output
    assert round_tripped.model_dump(mode="json") == dumped


def test_round_trip_preserves_incident_identity():
    payload = _full_agent_output_kwargs()
    payload["incident_id"] = "Incident-042"
    output = InvestigationAgentOutput.model_validate(payload)
    dumped = output.model_dump(mode="json")
    assert dumped["incident_id"] == "Incident-042"

    round_tripped = InvestigationAgentOutput.model_validate(dumped)
    assert round_tripped.incident_id == "Incident-042"


def test_json_serializable_via_json_dumps():
    output = InvestigationAgentOutput.model_validate(_full_agent_output_kwargs())
    text = json.dumps(output.model_dump(mode="json"))
    assert json.loads(text)["policy_audit_logs"][0]["human_review_required"] is True
