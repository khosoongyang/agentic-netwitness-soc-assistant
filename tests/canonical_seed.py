"""Minimal REAL canonical prerequisites for workflow tests (canonical audit Phase 6).

Since Phase 6 a downstream stage only runs on canonical, identity-checked,
run-bound upstream results (workflow/readiness.py). Tests that drive the
workflow by setting stage statuses directly use these helpers to persist the
same canonical data the production workflow persists for that case/run --
never to bypass readiness:

* the Phase 5 Parsing envelope for a bare NetWitness record whose own id is
  the case (case identity basis ``bare_incident_record_id``), saved through
  wss.save_parsing_result() with Parsing marked Complete;
* the run's raw-incident artifact, saved through the engine's own
  identity-enveloped writer (_save_run_artifact) and wss.save_raw_incident_path();
* run binding for a stage result (the run_id the production workers stamp).

The workflow DB and artifact root are the per-test temporary ones the root
conftest.py installs.
"""
from __future__ import annotations

import json

from workflow import engine as wf
from workflow import state_store as wss


def parsing_envelope(case: str, run_id: str, **overrides) -> dict:
    """The canonical Parsing envelope run_until_triage_approval() persists
    for a bare NetWitness incident record whose own id is `case`."""
    envelope = {
        "run_id": run_id,
        "incident_id": case,
        "status": "completed",
        "input_shape": "generic_dictionary",
        "raw_record_id": case,
        "normalised_alert_count": 1,
        "normalised_alert": {"alert_summary": {"alert_id": case, "raw_event_count": 1}},
        "processed_alert": {"alert_id": case},
        "missing_important_fields": [],
        "warnings": [],
        "parser_confidence": "High",
    }
    envelope.update(overrides)
    return envelope


def seed_parsing(case: str, run_id: str, **overrides) -> dict:
    envelope = parsing_envelope(case, run_id, **overrides)
    wss.save_parsing_result(case, run_id, envelope)
    wss.set_parsing_status(case, run_id, "Complete")
    return envelope


def seed_raw_incident(case: str, run_id: str, incident: dict | None = None) -> dict:
    incident = incident if incident is not None else {"id": case, "title": f"Incident {case}"}
    path = wf._save_run_artifact(
        case, run_id, "raw_incident.json", "raw_incident",
        {"incident": incident, "data_availability": wf._data_availability(incident)})
    wss.save_raw_incident_path(case, run_id, str(path))
    return incident


def seed_parsing_and_raw_incident(case: str, run_id: str, incident: dict | None = None) -> dict:
    seed_parsing(case, run_id)
    return seed_raw_incident(case, run_id, incident)


def bind_run(result: dict, run_id: str) -> dict:
    """A stage result carrying the run binding its production worker stamps."""
    return {**result, "run_id": run_id}


def threat_intel_result(case: str, run_id: str, result: dict) -> dict:
    """run_threat_intel() always returns incident_id + run_id; a TI fixture
    without them is given the identity its producer would have stamped
    (an identity the fixture sets itself is kept)."""
    return {"incident_id": case, **result, "run_id": run_id}


def approve_triage(case: str, run_id: str, triage: dict, *, analyst: str = "Analyst") -> dict:
    """Persist the run-bound Triage result and record a real approval
    through the atomic transition (workflow_approvals row)."""
    triage = bind_run(triage, run_id)
    wss.save_triage_result(case, run_id, triage)
    wss._guarded_update(case, run_id, {"triage_status": "Awaiting Approval",
                                       "workflow_status": "Awaiting Approval",
                                       "approval_stage": "triage"})
    wss.approve_triage(case, run_id, approved_by=analyst)
    return triage


def approve_investigation(case: str, run_id: str, investigation: dict, *,
                          analyst: str = "Analyst") -> dict:
    """Persist the run-bound Investigation result and record a real approval
    on the current investigation attempt."""
    investigation = bind_run(investigation, run_id)
    wss._guarded_update(case, run_id, {"investigation_status": "Awaiting Approval",
                                       "investigation_result_json": json.dumps(investigation),
                                       "workflow_status": "Awaiting Approval",
                                       "approval_stage": "investigation"})
    wss.approve_investigation(case, run_id, approved_by=analyst)
    return investigation
