"""Direct coverage for the live Reporting-eligibility decision.

agents/reporting/backend/reporting_eligibility.is_investigation_usable_for_reporting
is reached by every real Reporting run: workflow/engine.py::run_reporting()
subprocess-launches agents/reporting/adapters/run_reporting.py, whose
_prepare_inputs() calls reporting_context_resolver.ensure_reporting_inputs(),
which calls this function via resolve_investigation_context()/
resolve_investigation_approval_context(). These cases replace the manual
harness previously in scripts/test_reporting_gate_with_limited_investigation.py.
"""

from __future__ import annotations

from agents.reporting.backend import reporting_eligibility


def test_completed_investigation_is_usable():
    result = {"status": "completed", "summary": "Investigation complete.", "findings": ["Finding A"]}
    assert reporting_eligibility.is_investigation_usable_for_reporting(result) is True


def test_completed_limited_investigation_is_usable():
    result = {
        "status": "completed_limited",
        "summary": "Investigation ran with limited telemetry.",
        "missing_evidence": [{"gap": "dns_logs"}],
    }
    assert reporting_eligibility.is_investigation_usable_for_reporting(result) is True


def test_completed_with_evidence_gaps_is_usable():
    result = {
        "status": "completed_with_evidence_gaps",
        "summary": "Playbook could not be fully answered.",
        "missing_fields": ["alert_timestamp"],
    }
    assert reporting_eligibility.is_investigation_usable_for_reporting(result) is True


def test_needs_more_data_with_findings_is_usable():
    result = {
        "status": "needs_more_data",
        "summary": "Missing telemetry is an evidence gap, not a crash.",
        "findings": ["Affected host observed"],
        "missing_evidence": [{"gap": "endpoint_process_tree"}],
    }
    assert reporting_eligibility.is_investigation_usable_for_reporting(result) is True


def test_needs_more_data_without_content_is_not_usable():
    result = {"status": "needs_more_data", "summary": "", "findings": []}
    assert reporting_eligibility.is_investigation_usable_for_reporting(result) is False


def test_failed_investigation_blocks_reporting():
    result = {"status": "failed", "summary": "Investigation crashed.", "error": "invalid JSON"}
    assert reporting_eligibility.is_investigation_usable_for_reporting(result) is False


def test_empty_result_blocks_reporting():
    assert reporting_eligibility.is_investigation_usable_for_reporting({}) is False
    assert reporting_eligibility.is_investigation_usable_for_reporting(None) is False
