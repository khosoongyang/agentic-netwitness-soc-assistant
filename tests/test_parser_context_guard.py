"""Unit tests for agents/parsing/parser_context_guard.py.

Covers the input/output identity fingerprint (extract_alert_identity,
extract_parser_output_identity) and the pass/warn/fail verdicts of
validate_parser_identity() -- the guard that
agents/parsing/parser_normaliser.py::run_parser_normalisation_for_dashboard()
now calls before returning a result (see workflow/engine.py::run_parsing()
for the live caller)."""
from __future__ import annotations

from pathlib import Path

from agents.parsing.parser_context_guard import (
    clear_stale_parser_outputs,
    extract_alert_identity,
    extract_parser_output_identity,
    validate_parser_identity,
)


def test_extract_alert_identity_reads_incident_with_alerts_shape():
    raw_alert = {
        "incident": {"id": "INC-1001", "title": "Suspicious Activity"},
        "alerts": [
            {
                "id": "ALERT-9",
                "title": "PowerShell Execution",
                "originalAlert": {
                    "events": [{"alias_host": "WIN-HOST-1", "username": "jdoe",
                                "ip_src": "10.0.0.5", "ip_dst": "8.8.8.8"}]
                },
            }
        ],
    }
    identity = extract_alert_identity(raw_alert)
    assert identity["incident_id"] == "INC-1001"
    assert identity["incident_title"] == "Suspicious Activity"
    assert identity["alert_id"] == "ALERT-9"
    assert identity["alert_title"] == "PowerShell Execution"
    assert identity["hostname"] == "WIN-HOST-1"
    assert identity["username"] == "jdoe"
    assert identity["source_ip"] == "10.0.0.5"
    assert identity["destination_ip"] == "8.8.8.8"


def test_extract_alert_identity_falls_back_to_wrapper_fields_for_bare_incident():
    # Matches the real production shape: a case's raw_json is just the bare
    # NetWitness incident object, no "alerts" list at all.
    raw_alert = {"id": "INC-53040", "title": "High Risk Alerts: ESA for 192.168.0.19"}
    identity = extract_alert_identity(raw_alert)
    assert identity["alert_id"] == "INC-53040"
    assert identity["alert_title"] == "High Risk Alerts: ESA for 192.168.0.19"


def test_extract_alert_identity_prefers_true_raw_object_under_dashboard_wrapper():
    wrapper = {
        "alert_id": "WRAPPER-ALERT",
        "raw": {
            "incident": {"id": "INC-REAL", "title": "Real Incident"},
            "alerts": [{"id": "ALERT-REAL", "title": "Real Alert"}],
        },
    }
    identity = extract_alert_identity(wrapper)
    assert identity["incident_id"] == "INC-REAL"
    assert identity["alert_id"] == "ALERT-REAL"


def test_extract_parser_output_identity_reads_dashboard_result_shape():
    parser_result = {
        "selected_alert_id": "ALERT-9",
        "important_extracted_fields": {"incident_id": "INC-1001", "alert_name": "PowerShell Execution",
                                        "hosts": ["WIN-HOST-1"], "users": ["jdoe"],
                                        "source_ips": ["10.0.0.5"], "destination_ips": ["8.8.8.8"]},
        "normalised_alert": {"alert_summary": {"incident_id": "INC-1001", "alert_id": "ALERT-9"}},
    }
    identity = extract_parser_output_identity(parser_result)
    assert identity["incident_id"] == "INC-1001"
    assert identity["alert_id"] == "ALERT-9"
    assert identity["alert_title"] == "PowerShell Execution"
    assert identity["hostname"] == "WIN-HOST-1"


def test_validate_parser_identity_passes_on_matching_identities():
    input_identity = {"alert_id": "ALERT-9", "incident_id": "INC-1001", "alert_title": "PowerShell Execution",
                       "hostname": "WIN-HOST-1", "username": "jdoe", "source_ip": "10.0.0.5",
                       "destination_ip": "8.8.8.8"}
    parser_result = {
        "selected_alert_id": "ALERT-9",
        "important_extracted_fields": {"incident_id": "INC-1001", "alert_name": "PowerShell Execution",
                                        "hosts": ["WIN-HOST-1"], "users": ["jdoe"],
                                        "source_ips": ["10.0.0.5"], "destination_ips": ["8.8.8.8"]},
    }
    result = validate_parser_identity(input_identity, parser_result)
    assert result["passed"] is True
    assert result["status"] == "passed"
    assert result["hard_failures"] == []
    assert result["warnings"] == []


def test_validate_parser_identity_hard_fails_on_alert_id_mismatch():
    input_identity = {"alert_id": "ALERT-9", "incident_id": "INC-1001"}
    parser_result = {"selected_alert_id": "ALERT-DIFFERENT",
                      "important_extracted_fields": {"incident_id": "INC-1001"}}
    result = validate_parser_identity(input_identity, parser_result)
    assert result["passed"] is False
    assert result["status"] == "failed"
    assert "alert_id" in result["hard_failures"]
    assert "does not match" in result["message"]


def test_validate_parser_identity_hard_fails_on_incident_id_mismatch():
    input_identity = {"alert_id": "ALERT-9", "incident_id": "INC-1001"}
    parser_result = {"selected_alert_id": "ALERT-9",
                      "important_extracted_fields": {"incident_id": "INC-STALE"}}
    result = validate_parser_identity(input_identity, parser_result)
    assert result["passed"] is False
    assert "incident_id" in result["hard_failures"]


def test_validate_parser_identity_soft_fields_only_warn_never_block():
    # hostname/username/ip/title differ but alert_id + incident_id match --
    # these differences are logged as warnings, never a hard failure, since
    # they can legitimately differ between incident- and alert-level data.
    input_identity = {"alert_id": "ALERT-9", "incident_id": "INC-1001",
                       "hostname": "HOST-A", "username": "alice"}
    parser_result = {"selected_alert_id": "ALERT-9",
                      "important_extracted_fields": {"incident_id": "INC-1001",
                                                      "hosts": ["HOST-B"], "users": ["bob"]}}
    result = validate_parser_identity(input_identity, parser_result)
    assert result["passed"] is True
    assert result["status"] == "passed_with_warnings"
    assert set(result["warnings"]) == {"hostname", "username"}


def test_validate_parser_identity_missing_fields_are_not_enough_information():
    input_identity = {"alert_id": None, "incident_id": None}
    parser_result = {"selected_alert_id": None, "important_extracted_fields": {}}
    result = validate_parser_identity(input_identity, parser_result)
    assert result["passed"] is True
    assert result["hard_failures"] == []
    reasons = {check["field"]: check.get("reason") for check in result["checks"]}
    assert reasons["alert_id"] == "not_enough_information"
    assert reasons["incident_id"] == "not_enough_information"


def test_clear_stale_parser_outputs_removes_known_targets(tmp_path: Path):
    outputs = tmp_path / "outputs"
    (outputs / "TICKET-1" / "parsing").mkdir(parents=True)
    (outputs / "TICKET-1" / "parsing" / "leftover.json").write_text("{}")
    (outputs / "parser_result.json").write_text("{}")

    removed = clear_stale_parser_outputs(tmp_path, ticket_id="TICKET-1")

    assert not (outputs / "TICKET-1" / "parsing").exists()
    assert not (outputs / "parser_result.json").exists()
    assert len(removed) == 2
