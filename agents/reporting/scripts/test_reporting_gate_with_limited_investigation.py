# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, backend, json, pathlib, sys.
# =============================================================================
# File: soc_reporting_agent/scripts/test_reporting_gate_with_limited_investigation.py
# Purpose: This module implements test and validation behaviour for test reporting gate with limited investigation.
# Main functionality: ticket_with, run_case, main.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis test and validation component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, backend, json, pathlib, sys.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: ticket_with, run_case, main, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend import ticket_workflow

OUT = ROOT / "testdata" / "workflow_gating" / "test_results.json"

BASE_TICKET = {
    "ticket_id": "TKT-GATE-TEST",
    "parsing_result": {"status": "completed", "summary": "Parser output ready."},
    "triage_result": {"status": "completed", "summary": "Triage complete."},
    "threat_intel_result": {"status": "completed", "summary": "Threat intel complete."},
    "approval_result": {"decision": "approved", "status": "completed"},
    "investigation_approval_result": {"decision": "approved", "status": "completed"},
}


# =============================================================================
# [FYP-SECTION] TEST SETUP, FIXTURES, AND ASSERTIONS
# =============================================================================

# [FYP-FUNCTION] `ticket_with` — implements the ticket with operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `inv`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/scripts/test_reporting_gate_with_limited_investigation.py:run_case; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `dict`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def ticket_with(inv: dict) -> dict:
    t = dict(BASE_TICKET)
    t["investigation_result"] = inv
    return t


# [FYP-FUNCTION] `run_case` — orchestrates the run case entry point and its ordered test and validation operations.
# [FYP-INPUT] Parameters: `name`, `inv`, `expected_allowed`, `expected_label_contains`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/scripts/test_reporting_context_resolution.py:main, soc_reporting_agent/scripts/test_reporting_gate_with_limited_investigation.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `can_run_agent`, `get`, `is_investigation_usable_for_reporting`, `lower`, `next_agent`, `str`, `ticket_with`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def run_case(name: str, inv: dict, expected_allowed: bool, expected_label_contains: str | None = None) -> dict:
    ticket = ticket_with(inv)
    allowed, reason = ticket_workflow.can_run_agent(ticket, "reporting")
    next_step = ticket_workflow.next_agent(ticket)
    usable = ticket_workflow.is_investigation_usable_for_reporting(inv)
    ok = allowed == expected_allowed
    if expected_label_contains:
        ok = ok and expected_label_contains.lower() in str(next_step.get("label", "")).lower()
    return {
        "name": name,
        "passed": ok,
        "expected_allowed": expected_allowed,
        "actual_allowed": allowed,
        "reason": reason,
        "next_step": next_step,
        "usable_for_reporting": usable,
    }


# [FYP-FUNCTION] `main` — orchestrates the main entry point and its ordered test and validation operations.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:<module>, eval_harness.py:<module>, soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `dumps`, `mkdir`, `print`, `run_case`, `sum`, `write_text`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def main() -> int:
    cases = [
        run_case(
            "completed investigation unlocks reporting",
            {"status": "completed", "summary": "Investigation complete.", "findings": ["Finding A"]},
            True,
            "Generate Report",
        ),
        run_case(
            "completed_limited unlocks reporting with limitations",
            {"status": "completed_limited", "summary": "Investigation ran with limited telemetry.", "missing_evidence": [{"gap": "dns_logs"}]},
            True,
            "Limitations",
        ),
        run_case(
            "completed_with_evidence_gaps unlocks reporting with limitations",
            {"status": "completed_with_evidence_gaps", "summary": "Playbook could not be fully answered.", "missing_fields": ["alert_timestamp"]},
            True,
            "Limitations",
        ),
        run_case(
            "needs_more_data with findings unlocks reporting with limitations",
            {"status": "needs_more_data", "summary": "Missing telemetry is an evidence gap, not a crash.", "findings": ["Affected host observed"], "missing_evidence": [{"gap": "endpoint_process_tree"}]},
            True,
            "Limitations",
        ),
        run_case(
            "failed investigation still blocks reporting",
            {"status": "failed", "summary": "Investigation crashed.", "error": "invalid JSON"},
            False,
        ),
    ]
    result = {"passed": sum(1 for c in cases if c["passed"]), "failed": sum(1 for c in cases if not c["passed"]), "cases": cases}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
