# ==============================================================================
# File: agents/reporting/backend/reporting_eligibility.py
#
# Purpose:
#   Decides whether a completed (possibly limited) Investigation result is
#   usable as input to the Reporting stage. This is the one piece of
#   decision logic from the former ticket_workflow.py that is actually
#   reached by a live production code path: every real Reporting run
#   subprocess-launches adapters/run_reporting.py, whose _prepare_inputs()
#   calls reporting_context_resolver.ensure_reporting_inputs(), which calls
#   is_investigation_usable_for_reporting() below via
#   resolve_investigation_context()/resolve_investigation_approval_context().
#
# Policy:
#   Allow Reporting when Investigation is limited but usable. Block only
#   true execution/context failures. Evidence gaps such as needs_more_data,
#   waiting_for_telemetry, or insufficient_telemetry should be carried into
#   Reporting and clearly documented rather than blocking it outright.
#
# Called by:
#   - agents/reporting/backend/reporting_context_resolver.py
#     (resolve_investigation_context / resolve_investigation_approval_context).
# ==============================================================================

from __future__ import annotations

from typing import Any

COMPLETED_STATUSES = {"completed", "completed_limited", "completed_with_warnings", "completed_with_evidence_gaps", "generated_with_warnings", "success", "passed", "ready"}
USABLE_LIMITED_INVESTIGATION_STATUSES = {"completed", "completed_limited", "completed_with_warnings", "completed_with_evidence_gaps", "needs_more_data", "waiting_for_telemetry", "insufficient_telemetry", "needs_analyst_review", "partial", "partial_success"}
BLOCKING_INVESTIGATION_STATUSES = {"failed", "crashed", "invalid_output", "not_started", "missing_required_context", "execution_error", "timed_out", "timeout", "error"}


def norm(value: Any) -> str:
    """Normalise any value to a lowercase, underscore-separated string for tolerant status comparisons."""
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _has_result(result: dict[str, Any]) -> bool:
    """True when a stage result dict exists and is non-empty."""
    return bool(result and isinstance(result, dict))


def _has_usable_investigation_content(result: dict[str, Any]) -> bool:
    """Return True when Investigation produced enough information to report with limitations.

    Missing telemetry is an evidence gap, not a workflow failure. Reporting
    should continue when an investigation result contains a summary,
    findings, missing-evidence records, or available evidence, even if the
    selected playbook could not be fully answered.
    """
    if not _has_result(result):
        return False
    for key in ("summary", "investigation_summary", "classification", "likely_scenario", "recommended_next_action"):
        if result.get(key) not in (None, "", [], {}):
            return True
    for key in ("findings", "missing_evidence", "missing_fields", "available_evidence", "observed_evidence", "iocs"):
        value = result.get(key)
        if value not in (None, "", [], {}):
            return True
    return False


def is_investigation_usable_for_reporting(result: dict[str, Any]) -> bool:
    """Allow Reporting when Investigation is limited but usable.

    Block only true execution/context failures. Evidence gaps such as
    needs_more_data, waiting_for_telemetry, or insufficient_telemetry should
    be carried into Reporting and clearly documented.
    """
    if not _has_result(result):
        return False
    status = norm(result.get("status") or result.get("report_status") or result.get("workflow_decision"))
    if status in BLOCKING_INVESTIGATION_STATUSES:
        return False
    if status in USABLE_LIMITED_INVESTIGATION_STATUSES:
        return _has_usable_investigation_content(result) or status in COMPLETED_STATUSES
    return _has_usable_investigation_content(result)
