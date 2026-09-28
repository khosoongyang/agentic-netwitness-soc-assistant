# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, adapters, json, pathlib, shutil, sys.
# =============================================================================
# File: agents/reporting/scripts/test_evidence_gap_branch_and_reporting_wrapper.py
# Purpose: Regression coverage for adapters.run_reporting._normalise_reporting_result(),
#   the reporting subprocess's ticket-specific reporting_result.json wrapper
#   backfill. (Phase 9: this file previously also tested the donor Flask
#   app's own evidence-gap decision tracking via backend.casework_store and
#   backend.ticket_workflow.decorate_ticket/can_run_agent - dashboard
#   presentation logic never wired into the canonical Aegis application.
#   That test was one of the project's known pre-existing baseline failures
#   and exercised no live code path; removed along with
#   backend/casework_store.py, its sole remaining consumer.)
# Main functionality: assert_true, test_reporting_wrapper_backfill, main.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis test and validation component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, adapters, json, pathlib, shutil, sys.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: assert_true, test_reporting_wrapper_backfill, main, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from adapters import run_reporting
from adapters.common import OUTPUTS_DIR, INPUTS_DIR


# =============================================================================
# [FYP-SECTION] TEST SETUP, FIXTURES, AND ASSERTIONS
# =============================================================================

# [FYP-FUNCTION] `assert_true` — implements the assert true operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `cond`, `msg`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/scripts/test_evidence_gap_branch_and_reporting_wrapper.py:test_decision_buttons_and_branches, soc_reporting_agent/scripts/test_evidence_gap_branch_and_reporting_wrapper.py:test_reporting_wrapper_backfill, soc_reporting_agent/scripts/test_export_cache.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `AssertionError`.
# [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

def assert_true(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


# [FYP-FUNCTION] `test_reporting_wrapper_backfill` — verifies reporting wrapper backfill behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/scripts/test_evidence_gap_branch_and_reporting_wrapper.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_normalise_reporting_result`, `assert_true`, `dumps`, `exists`, `mkdir`, `rmtree`, `str`, `write_text`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_reporting_wrapper_backfill() -> dict:
    ticket_id = "TKT-EG-WRAPPER"
    ticket_dir = OUTPUTS_DIR / ticket_id / "reporting"
    if ticket_dir.exists():
        shutil.rmtree(ticket_dir)
    ticket_dir.mkdir(parents=True, exist_ok=True)

    # Simulate report artefacts existing but no reporting_result.json wrapper.
    manifest_dir = OUTPUTS_DIR / "INC-EG-0001" / "reports"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / "report_manifest.json").write_text(json.dumps({
        "incident_id": "INC-EG-0001",
        "sections": {"executive_summary": {"status": "draft", "title": "Executive Summary"}},
    }), encoding="utf-8")
    (INPUTS_DIR / "processed_alert.json").write_text(json.dumps({"incident_id": "INC-EG-0001", "alert_id": "ALERT-EG-0001", "alert_title": "Endpoint malware evidence gap test"}), encoding="utf-8")
    (INPUTS_DIR / "investigation_result.json").write_text(json.dumps({"status": "completed_with_evidence_gaps", "missing_evidence": [{"gap": "email_subject"}]}), encoding="utf-8")
    (INPUTS_DIR / "investigation_approval_result.json").write_text(json.dumps({"decision": "approved", "evidence_gap_decision": "continue_to_reporting", "reporting_mode": "with_limitations"}), encoding="utf-8")

    result = run_reporting._normalise_reporting_result({"success": True, "returncode": 0}, ticket_id=ticket_id)
    wrapper_path = ticket_dir / "reporting_result.json"
    assert_true(wrapper_path.exists(), "Ticket-specific reporting_result.json wrapper was not written")
    assert_true(result["status"] in {"completed_with_warnings", "completed", "completed_limited"}, f"Unexpected wrapper status: {result['status']}")
    assert_true(result["incident_id"] == "INC-EG-0001", "Wrapper did not recover incident ID")
    assert_true(result["alert_id"] == "ALERT-EG-0001", "Wrapper did not recover alert ID")
    assert_true(result["reporting_mode"] == "with_limitations", "Wrapper did not preserve reporting_mode")
    return {"reporting_wrapper": "passed", "wrapper_path": str(wrapper_path)}


# [FYP-FUNCTION] `main` — orchestrates the main entry point and its ordered test and validation operations.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:<module>, eval_harness.py:<module>, soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `dumps`, `mkdir`, `print`, `test_decision_buttons_and_branches`, `test_reporting_wrapper_backfill`, `write_text`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def main() -> int:
    results = {
        **test_reporting_wrapper_backfill(),
    }
    out = Path("testdata/evidence_gap_branching/test_results.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"passed": True, "results": results}, indent=2), encoding="utf-8")
    print(json.dumps({"passed": True, "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
