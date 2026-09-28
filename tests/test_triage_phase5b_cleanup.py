"""tests/test_triage_phase5b_cleanup.py -- Phase 5B of the Triage Result
migration: safe documentation and confirmed-dead-code cleanup.

Covers:
  1-3. The regenerated schemas/reporting/triage_result_schema.json reference
       schema (generated from agents.triage.triage_result's Pydantic models)
       structurally matches a real success/error TriageAgent.triage() payload
       and no longer resurrects stale, nonexistent fields.
  4-8. agents.triage.alert_triage.normalize_to_incident() still derives
       priority/MITRE/IOC-backed alertMeta from analyze_alert()/
       _extract_iocs(), while no longer storing the unused
       "_analyze_alert"/"_extracted_iocs" debug payloads.
  9.   File-upload ingest (backend.services.import_service) still normalizes
       non-NetWitness alerts end-to-end.
  10.  reporting.report_validator still imports and runs cleanly with
       schema_normaliser.py removed (its only prior consumer, the dead
       validate_required_fields()/build_missing_field_gaps() chain, is gone
       too).
"""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from agents.triage.alert_triage import normalize_to_incident
from agents.triage.triage_result import (
    TriageAgentErrorOutput,
    TriageAgentSuccessOutput,
    dump_triage_agent_output,
    validate_triage_agent_output,
)

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "reporting" / "triage_result_schema.json"

STALE_NONEXISTENT_FIELDS = [
    "confidence",
    "likely_scenario",
    "containment_action",
    "missing_evidence",
    "evidence_gaps",
    "current_stage",
    "next_action",
    "recommended_next_action",
]


def _risk_rating_kwargs() -> dict:
    return dict(
        likelihood_initiation="High",
        likelihood_occurrence="Medium",
        likelihood_adverse_impact="High",
        overall_risk="High",
        rationale="Repeated failed logons followed by a privileged success.",
    )


def _ticket_kwargs() -> dict:
    return dict(
        unc="#00042A",
        incident_id="INC-1001",
        title="Suspicious privileged logon",
        incident_time="2026-08-20 10:00:00 UTC",
        created_at="2026-08-20T10:00:05.123456",
        classification="HIGH",
        risk_rating=_risk_rating_kwargs(),
        incident_category="Internal Hacking (attempted)",
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force",
        initial_response_time="<= 30 minutes",
        summary="Repeated failed logons from 10.0.0.5 preceded a successful "
                "privileged logon for user jdoe.",
        recommended_actions=["Isolate the affected host",
                              "Reset the targeted account credentials"],
        matched_ioc_count=3,
        metakeys=["ip.src", "user.name", "host.name"],
    )


def _metakeys_payload_kwargs() -> dict:
    return dict(
        incident_id="INC-1001",
        incident_title="Suspicious privileged logon",
        timestamp="2026-08-20T10:00:00.000000",
        matched_metakeys=["ip.src", "user.name", "host.name"],
        metakey_values={"ip.src": "10.0.0.5", "user.name": "jdoe"},
        ioc_summary="[NETWORK] 10.0.0.5 — brute-force pattern",
        risk_level="high",
        classification="high",
        mitre_tactic="Credential Access",
        mitre_technique="Brute Force",
    )


def _success_payload() -> dict:
    return dump_triage_agent_output(
        validate_triage_agent_output(
            dict(
                metakeys_payload=_metakeys_payload_kwargs(),
                ticket=_ticket_kwargs(),
                trace=[{"step": "IOC Checklist", "status": "ok"}],
                used_parsed_context=False,
                error=None,
            )
        )
    )


def _error_payload() -> dict:
    return dump_triage_agent_output(
        validate_triage_agent_output(
            dict(error="LLM call failed", metakeys_payload={}, ticket={}, trace=[])
        )
    )


# =============================================================================
# 1-3: regenerated reference schema
# =============================================================================

def test_reference_schema_is_valid_json_and_doc_only():
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema["title"] == "triage_result_schema.json"
    # Documentation/reference schema convention: present, but not a runtime gate.
    assert "$comment" in schema or "description" in schema


def test_reference_schema_accepts_canonical_success_payload():
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.validate(_success_payload(), schema)


def test_reference_schema_accepts_canonical_error_payload():
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.validate(_error_payload(), schema)


def test_reference_schema_omits_stale_nonexistent_fields():
    schema_text = SCHEMA_PATH.read_text()
    schema = json.loads(schema_text)
    all_properties: set[str] = set()
    for definition in schema.get("$defs", {}).values():
        all_properties.update(definition.get("properties", {}))
    for stale_field in STALE_NONEXISTENT_FIELDS:
        assert stale_field not in all_properties, (
            f"stale field {stale_field!r} should not appear in any schema definition"
        )
        assert f'"{stale_field}"' not in schema_text


def test_success_and_error_are_the_only_modelled_shapes():
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema["oneOf"] == [
        {"$ref": "#/$defs/TriageAgentSuccessOutput"},
        {"$ref": "#/$defs/TriageAgentErrorOutput"},
    ]
    assert set(schema["$defs"]) == {
        "TriageMetakeysPayload",
        "TriageRiskRating",
        "TriageTicket",
        "TriageAgentSuccessOutput",
        "TriageAgentErrorOutput",
    }


# =============================================================================
# 4-8: alert_triage.py cleanup — keep the live derivations, drop the storage
# =============================================================================

def test_normalize_to_incident_derives_priority_from_analyze_alert_verdict():
    alert = {
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "edr",
        "message": "ransomware detected on endpoint HOST01",
    }
    inc = normalize_to_incident(alert, "edr")
    assert inc["priority"] == "High"


def test_normalize_to_incident_derives_mitre_tactic_and_technique():
    alert = {
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "edr",
        "message": "ransomware detected on endpoint HOST01",
    }
    inc = normalize_to_incident(alert, "edr")
    assert inc["mitre_tactic"] == "Execution"
    assert inc["mitre_technique"] == "T1059"


def test_normalize_to_incident_derives_ioc_backed_alertmeta_fields():
    alert = {
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "siem",
        "message": "connection observed",
        "src_ip": "192.168.1.50",
        "dst_ip": "8.8.8.8",
    }
    inc = normalize_to_incident(alert, "siem")
    assert inc["alertMeta"]["SourceIp"] == ["192.168.1.50"]
    assert inc["alertMeta"]["DestinationIp"] == ["8.8.8.8"]


def test_normalize_to_incident_no_longer_stores_analyze_alert_debug_payload():
    alert = {
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "edr",
        "message": "ransomware detected on endpoint HOST01",
    }
    inc = normalize_to_incident(alert, "edr")
    assert "_analyze_alert" not in inc


def test_normalize_to_incident_no_longer_stores_extracted_iocs_debug_payload():
    alert = {
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "siem",
        "message": "connection observed",
        "src_ip": "192.168.1.50",
        "dst_ip": "8.8.8.8",
    }
    inc = normalize_to_incident(alert, "siem")
    assert "_extracted_iocs" not in inc


def test_format_analysis_no_longer_exists():
    import agents.triage.alert_triage as alert_triage_module

    assert not hasattr(alert_triage_module, "format_analysis")


# =============================================================================
# 9: file-upload ingest still works end-to-end through normalize_to_incident
# =============================================================================

def test_file_upload_ingest_still_normalizes_non_netwitness_alerts(tmp_path, monkeypatch):
    from workflow import state_store

    monkeypatch.setattr(state_store, "DB_FILE", tmp_path / "cases.db")

    import importlib.util
    import sys

    project_root = Path(__file__).resolve().parents[1]
    package_name = "_aegis_phase5b_backend"
    if package_name not in sys.modules:
        package_dir = project_root / "backend"
        spec = importlib.util.spec_from_file_location(
            package_name, package_dir / "__init__.py",
            submodule_search_locations=[str(package_dir)],
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[package_name] = module
        spec.loader.exec_module(module)

    import_service_module = __import__(
        f"{package_name}.services.import_service", fromlist=["ImportService"]
    )
    ImportService = import_service_module.ImportService

    service = ImportService(tmp_path / "uploads")
    result = service.import_file(
        "incident.log", b"2026-01-01 malware detected on endpoint"
    )
    assert result["incident_id"]
    assert result["summary"]["added"] == 1


# =============================================================================
# 10: report_validator still works with schema_normaliser.py removed
# =============================================================================

def test_report_validator_imports_cleanly_without_schema_normaliser():
    import agents.reporting.reporting.report_validator as report_validator

    assert not hasattr(report_validator, "validate_required_fields")
    assert not hasattr(report_validator, "build_missing_field_gaps")
    assert not hasattr(report_validator, "REQUIRED_FIELDS")
    assert hasattr(report_validator, "validate_generated_report")


def test_schema_normaliser_module_is_gone():
    # agents.reporting's __init__ inserts its directory onto sys.path so the
    # bare `reporting` top-level package (as report_validator.py's own
    # `from reporting.structured_report import ...` expects) resolves.
    import agents.reporting  # noqa: F401

    with pytest.raises(ModuleNotFoundError):
        import reporting.schema_normaliser  # noqa: F401
