"""Canonical, dependency-light Pydantic contract for the Investigation
Agent's structured output.

This module intentionally imports nothing from `orchestrator.py` (or the
heavy modules it pulls in transitively at import time -- `ingest_pipeline`,
`vector_engine` [which opens a real ChromaDB client/collection on import],
`chroma_compat`, `langchain_openai`) so that a future consumer of this
contract (workflow orchestration, Reporting) can parse and validate a
persisted investigation result without loading the Investigation Agent's
LLM/RAG machinery. Only `pydantic` and `typing` are required.

`InvestigationAgentOutput` mirrors `orchestrator.FinalIncidentAnalysis`
field-for-field, including its nested `MilestoneExecution`,
`BusinessImpactChecklist`, `mitre_mapper.MitreTTPMapping`, and
`policy_engine.PolicyAuditRecord` models. Field names, types, nesting, and
required/optional semantics are preserved exactly.

The one deliberate, harmless difference from the originals: the `Field(...)`
`description=` metadata is dropped. That metadata exists solely to steer the
LLM's structured-output generation (it feeds the JSON schema handed to
`with_structured_output()`); it has no effect on validation, on
required/optional semantics, or on the serialized JSON shape, so omitting it
does not change the contract in any observable way.

Workflow-owned metadata (execution status, run_id, artifact paths,
evidence-gap bookkeeping, etc.) is deliberately NOT part of this module --
it belongs to the Investigation Agent alone, not to workflow orchestration.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class MilestoneExecutionRecord(BaseModel):
    """Mirrors orchestrator.MilestoneExecution exactly."""

    step_id: str
    instruction: str
    status: Literal["MET", "NOT_MET", "SKIPPED"]
    findings: str


class BusinessImpactAssessment(BaseModel):
    """Mirrors orchestrator.BusinessImpactChecklist exactly."""

    critical_system: str
    essential_service: str
    data_sensitivity: str
    operational_impact: str


class MitreMappingRecord(BaseModel):
    """Mirrors mitre_mapper.MitreTTPMapping exactly."""

    timeline_phase: str
    observed_evidence: str
    tactic: str
    technique_name: str
    technique_id: str


class PolicyAuditRecordSummary(BaseModel):
    """Mirrors policy_engine.PolicyAuditRecord exactly."""

    audit_id: str
    incident_id: str
    agent_name: str = "Investigation Agent"
    policy_reference: str
    decision_point: str
    input_summary: str
    result: str
    decision_made: str
    timestamp: float
    evidence_reference: str
    human_review_required: bool
    final_reviewer: Optional[str] = None


class InvestigationAgentOutput(BaseModel):
    """Mirrors orchestrator.FinalIncidentAnalysis exactly, field-for-field.

    This is the canonical, machine-readable form of what the Investigation
    Agent itself determined -- nothing added, nothing dropped, nothing
    renamed relative to FinalIncidentAnalysis.
    """

    incident_id: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    confidence: Literal["Low", "Medium", "High"]
    execution_trace: List[MilestoneExecutionRecord]
    incident_summary: str
    actions_taken: List[str]
    recommended_containment: List[str]
    business_impact_checklist: BusinessImpactAssessment
    severity_justification: str
    confidence_justification: str
    mitre_mappings: List[MitreMappingRecord] = Field(default_factory=list)
    mitre_attack_table: Optional[str] = None
    policy_audit_logs: List[PolicyAuditRecordSummary] = Field(default_factory=list)
