"""Direct coverage for the Reporting-context resolver bridge.

agents/reporting/backend/reporting_context_resolver.resolve_investigation_context /
resolve_investigation_approval_context / ensure_reporting_inputs bridge the
dashboard's ticket-context investigation result (or a legacy filesystem
artifact) into the inputs/outputs JSON files the Reporting agent's adapter
actually reads (agents/reporting/backend/app.py, adapters/run_reporting.py's
_prepare_inputs()). Both functions delegate usability to
reporting_eligibility.is_investigation_usable_for_reporting(), covered
directly by test_reporting_eligibility.py; this file exercises the resolver
layer itself -- ticket-dict-first resolution, filesystem candidate-path
scanning, and the ensure_reporting_inputs() side effect of writing
investigation_result.json into inputs/ -- across the same completed_limited /
completed_with_evidence_gaps / needs_more_data / failed / missing scenarios.

Phase 6A (Canonical Investigation Result migration audit, Part 5): this
module converts scripts/test_reporting_context_resolution.py's five
run_case()-driven scenarios into real pytest functions. That script had a
pytest-collectible-looking filename but defined zero `test_*` functions
(only `main()`, invoked as `python scripts/test_reporting_context_resolution.py`),
so it was never actually run by `pytest`/CI -- it is retained unchanged as a
standalone manual script (see Phase 6A audit note in that file's header) and
this file is now the automated, pytest-collected equivalent for the resolver
layer.
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.reporting.backend.reporting_context_resolver import (
    ensure_reporting_inputs,
    resolve_investigation_approval_context,
    resolve_investigation_context,
)

TICKET_ID = "TKT-TEST-001"


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _prepare_root(tmp_path: Path) -> Path:
    (tmp_path / "outputs").mkdir()
    (tmp_path / "inputs").mkdir()
    return tmp_path


def test_ticket_completed_limited_unlocks_reporting_with_approval(tmp_path):
    root = _prepare_root(tmp_path)
    ticket = {
        "investigation_result": {
            "status": "completed_limited",
            "summary": "Investigation completed with limited endpoint telemetry.",
            "missing_evidence": [{"gap": "process_tree", "priority": "High"}],
        },
        "investigation_approval_result": {"decision": "approved", "analyst": "SOC Analyst"},
    }

    resolved = resolve_investigation_context(root, ticket_id=TICKET_ID, ticket=ticket)
    approval = resolve_investigation_approval_context(root, ticket_id=TICKET_ID, ticket=ticket)
    ensure_reporting_inputs(root, ticket_id=TICKET_ID, ticket=ticket)

    assert resolved.exists is True
    assert resolved.usable is True
    assert approval.usable is True
    assert (root / "inputs" / "investigation_result.json").exists()


def test_outputs_completed_with_evidence_gaps_is_discovered(tmp_path):
    root = _prepare_root(tmp_path)
    _write_json(root / "outputs" / "investigation_result.json", {
        "status": "completed_with_evidence_gaps",
        "summary": "Investigation produced usable findings, but DNS telemetry is missing.",
        "findings": ["Host executed suspicious binary."],
    })
    _write_json(root / "outputs" / "investigation_approval_result.json", {"decision": "approved"})

    resolved = resolve_investigation_context(root, ticket_id=TICKET_ID, ticket=None)
    approval = resolve_investigation_approval_context(root, ticket_id=TICKET_ID, ticket=None)
    ensure_reporting_inputs(root, ticket_id=TICKET_ID, ticket=None)

    assert resolved.exists is True
    assert resolved.usable is True
    assert approval.usable is True
    assert (root / "inputs" / "investigation_result.json").exists()


def test_outputs_unknown_needs_more_data_with_summary_is_discovered(tmp_path):
    root = _prepare_root(tmp_path)
    _write_json(root / "outputs" / "unknown" / "investigation_result.json", {
        "status": "needs_more_data",
        "summary": "Playbook could not be fully answered due to missing network telemetry.",
        "missing_fields": ["netflow", "dns_logs"],
    })
    _write_json(root / "inputs" / "investigation_approval_result.json", {"status": "completed"})

    resolved = resolve_investigation_context(root, ticket_id=TICKET_ID, ticket=None)
    approval = resolve_investigation_approval_context(root, ticket_id=TICKET_ID, ticket=None)
    ensure_reporting_inputs(root, ticket_id=TICKET_ID, ticket=None)

    assert resolved.exists is True
    assert resolved.usable is True
    assert approval.usable is True
    assert (root / "inputs" / "investigation_result.json").exists()


def test_failed_investigation_remains_blocked(tmp_path):
    root = _prepare_root(tmp_path)
    _write_json(root / "outputs" / "investigation_result.json", {
        "status": "failed",
        "summary": "Investigation adapter crashed.",
    })
    _write_json(root / "outputs" / "investigation_approval_result.json", {"decision": "approved"})

    resolved = resolve_investigation_context(root, ticket_id=TICKET_ID, ticket=None)
    approval = resolve_investigation_approval_context(root, ticket_id=TICKET_ID, ticket=None)

    assert resolved.exists is True
    assert resolved.usable is False
    assert approval.usable is True


def test_missing_investigation_remains_blocked(tmp_path):
    root = _prepare_root(tmp_path)

    resolved = resolve_investigation_context(root, ticket_id=TICKET_ID, ticket=None)
    approval = resolve_investigation_approval_context(root, ticket_id=TICKET_ID, ticket=None)

    assert resolved.exists is False
    assert resolved.usable is False
    assert approval.exists is False
    assert approval.usable is False
