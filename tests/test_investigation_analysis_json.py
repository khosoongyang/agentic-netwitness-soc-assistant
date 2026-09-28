"""tests/test_investigation_analysis_json.py -- Phase 2 of the canonical
Investigation Result contract migration.

Verifies that agents/investigation/main.py's write_investigation_analysis_json()
produces a structured investigation_analysis.json that losslessly captures a
real orchestrator.FinalIncidentAnalysis instance, is additive alongside the
existing final_analysis_report.md / incident_data.json outputs, and preserves
incident identity exactly. Nothing reads investigation_analysis.json yet --
these tests only exercise the write side.

Loading agents/investigation/main.py pulls in orchestrator.py, which in turn
imports ingest_pipeline/vector_engine/chroma_compat. vector_engine.py opens a
real ChromaDB PersistentClient and an OpenAI embedding function at *import
time*, and main.py itself creates "triaged_alerts/"/"incident_reports/"
relative to the current working directory at import time. Neither belongs in
a unit test, so this module injects lightweight stub modules for
ingest_pipeline/vector_engine/chroma_compat (orchestrator.py only imports
them at module scope; nothing under test here exercises their real
behaviour) and loads main.py fresh with cwd redirected to a tmp_path.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

from agents.investigation.investigation_result import (
    BusinessImpactAssessment,
    InvestigationAgentOutput,
    MilestoneExecutionRecord,
    MitreMappingRecord,
    PolicyAuditRecordSummary,
)


INV_DIR = Path(__file__).resolve().parent.parent / "agents" / "investigation"


def _install_stub(monkeypatch, name: str, **attrs):
    stub = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(stub, key, value)
    monkeypatch.setitem(sys.modules, name, stub)
    return stub


@pytest.fixture
def investigation_main(monkeypatch, tmp_path):
    """Loads a fresh agents/investigation/main.py with its heavy ChromaDB/RAG
    dependencies stubbed out and its cwd redirected to tmp_path, so importing
    it neither opens a real ChromaDB client nor creates
    triaged_alerts//incident_reports/ inside the repository."""
    _install_stub(monkeypatch, "ingest_pipeline")
    _install_stub(monkeypatch, "vector_engine")
    _install_stub(
        monkeypatch, "chroma_compat",
        open_persistent_collection=lambda *a, **k: (None, False),
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(INV_DIR))

    spec = importlib.util.spec_from_file_location(
        "_investigation_main_under_test", INV_DIR / "main.py"
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def _build_final_incident_analysis(investigation_main, incident_id="Incident-007"):
    orch = investigation_main.orchestrator
    milestone = orch.MilestoneExecution(
        step_id="step_1",
        instruction="Check auth logs for anomalous access",
        status="MET",
        findings="Single failed login from a known-good IP.",
    )
    impact = orch.BusinessImpactChecklist(
        critical_system="no",
        essential_service="no",
        data_sensitivity="unknown",
        operational_impact="no",
    )
    mitre = investigation_main.mitre_mapper.MitreTTPMapping(
        timeline_phase="Initial Access",
        observed_evidence="Phishing email received by target user",
        tactic="Initial Access",
        technique_name="Phishing: Spearphishing Link",
        technique_id="T1566.002",
    )
    audit = investigation_main.policy_engine.PolicyAuditRecord(
        audit_id="AUD-1",
        incident_id=incident_id,
        policy_reference="POL-4.2",
        decision_point="Containment Approval",
        input_summary="Automated containment recommended.",
        result="Pass",
        decision_made="Contain",
        timestamp=1700000000.0,
        evidence_reference="EVID-1",
        human_review_required=True,
        final_reviewer="analyst@example.com",
    )
    return orch.FinalIncidentAnalysis(
        incident_id=incident_id,
        severity="High",
        confidence="Medium",
        execution_trace=[milestone],
        incident_summary="A phishing email led to a single compromised host.",
        actions_taken=["Isolated host", "Reset user credentials"],
        recommended_containment=["Block sender domain", "Force password reset"],
        business_impact_checklist=impact,
        severity_justification="Single host, contained quickly.",
        confidence_justification="Strong correlation across all evidence sources.",
        mitre_mappings=[mitre],
        mitre_attack_table="| Phase | Tactic | Technique |\n| --- | --- | --- |\n",
        policy_audit_logs=[audit],
    )


# =============================================================================
# Schema-level "no field lost" guarantees against the real production models
# =============================================================================

def test_no_finalincidentanalysis_field_is_lost(investigation_main):
    final_fields = set(investigation_main.orchestrator.FinalIncidentAnalysis.model_fields.keys())
    contract_fields = set(InvestigationAgentOutput.model_fields.keys())
    assert final_fields == contract_fields


def test_nested_model_field_sets_match_exactly(investigation_main):
    orch = investigation_main.orchestrator
    assert set(orch.MilestoneExecution.model_fields.keys()) == set(
        MilestoneExecutionRecord.model_fields.keys()
    )
    assert set(orch.BusinessImpactChecklist.model_fields.keys()) == set(
        BusinessImpactAssessment.model_fields.keys()
    )
    assert set(investigation_main.mitre_mapper.MitreTTPMapping.model_fields.keys()) == set(
        MitreMappingRecord.model_fields.keys()
    )
    assert set(investigation_main.policy_engine.PolicyAuditRecord.model_fields.keys()) == set(
        PolicyAuditRecordSummary.model_fields.keys()
    )


# =============================================================================
# Value-level round trip through the real write path
# =============================================================================

def test_write_investigation_analysis_json_preserves_every_field(investigation_main, tmp_path):
    report = _build_final_incident_analysis(investigation_main)
    dest_dir = tmp_path / "Incident-007"
    dest_dir.mkdir()

    output = investigation_main.write_investigation_analysis_json(str(dest_dir), report)
    # `investigation_main` is loaded as a throwaway module name (see the
    # fixture docstring), so its `investigation_result` submodule is a
    # distinct module object from the one imported at the top of this file
    # even though both come from the same file -- compare against that one.
    assert isinstance(output, investigation_main.investigation_result.InvestigationAgentOutput)

    analysis_path = dest_dir / "investigation_analysis.json"
    assert analysis_path.exists()
    on_disk = json.loads(analysis_path.read_text(encoding="utf-8"))

    assert on_disk == report.model_dump(mode="json")


def test_incident_identity_preserved_exactly(investigation_main, tmp_path):
    report = _build_final_incident_analysis(investigation_main, incident_id="Incident-999")
    dest_dir = tmp_path / "Incident-999"
    dest_dir.mkdir()

    output = investigation_main.write_investigation_analysis_json(str(dest_dir), report)

    assert output.incident_id == "Incident-999" == report.incident_id
    on_disk = json.loads((dest_dir / "investigation_analysis.json").read_text(encoding="utf-8"))
    assert on_disk["incident_id"] == "Incident-999"


# =============================================================================
# Additive-only guarantees
# =============================================================================

def test_does_not_touch_existing_outputs(investigation_main, tmp_path):
    report = _build_final_incident_analysis(investigation_main)
    dest_dir = tmp_path / "Incident-007"
    dest_dir.mkdir()
    markdown_path = dest_dir / "final_analysis_report.md"
    data_path = dest_dir / "incident_data.json"
    markdown_path.write_text("preexisting markdown", encoding="utf-8")
    data_path.write_text('{"preexisting": true}', encoding="utf-8")

    investigation_main.write_investigation_analysis_json(str(dest_dir), report)

    assert markdown_path.read_text(encoding="utf-8") == "preexisting markdown"
    assert json.loads(data_path.read_text(encoding="utf-8")) == {"preexisting": True}


def test_write_markdown_report_unaffected_by_new_json_write(investigation_main, tmp_path):
    """Confirms the new call site added alongside write_markdown_report()
    doesn't disturb its existing, unrelated output."""
    report = _build_final_incident_analysis(investigation_main)
    dest_dir = tmp_path / "Incident-007"
    dest_dir.mkdir()

    investigation_main.write_markdown_report(str(dest_dir), "007", report)
    investigation_main.write_investigation_analysis_json(str(dest_dir), report)

    markdown_path = dest_dir / "final_analysis_report.md"
    assert markdown_path.exists()
    assert "INVESTIGATION SUMMARY: Incident-007" in markdown_path.read_text(encoding="utf-8")
    assert (dest_dir / "investigation_analysis.json").exists()
