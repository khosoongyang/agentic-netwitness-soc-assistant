# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, backend, json, pathlib, shutil, sys, tempfile.
# =============================================================================
# File: soc_reporting_agent/scripts/test_reporting_context_resolution.py
# Purpose: This module implements test and validation behaviour for test reporting context resolution.
# Main functionality: write_json, run_case, case_ticket_limited, case_outputs_completed_with_gaps, case_unknown_needs_more_data, case_failed_blocks.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis test and validation component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, backend, json, pathlib, shutil, sys, tempfile.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: write_json, run_case, case_ticket_limited, case_outputs_completed_with_gaps, case_unknown_needs_more_data, case_failed_blocks, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================
# [Phase 6A note, Canonical Investigation Result migration audit] Despite its
# test_*.py filename, this module defines no `test_*` function -- only a
# `main()` invoked via `python scripts/test_reporting_context_resolution.py`
# -- so pytest never collects it; it is not exercised by the project's
# `pytest` run or by any CI workflow (confirmed: no CI config references it).
# Its five scenarios (ticket-completed_limited, outputs-completed_with_gaps,
# outputs/unknown-needs_more_data, failed-blocks, missing-blocks) were
# converted into real pytest tests at
# agents/reporting/tests/test_reporting_context_resolver.py. This script is
# left unchanged and may still be run standalone for manual/ad-hoc
# verification; it is no longer this repo's only coverage of the resolver
# layer for those statuses.
# =============================================================================

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.reporting.backend.reporting_context_resolver import (  # noqa: E402
    ensure_reporting_inputs,
    resolve_investigation_approval_context,
    resolve_investigation_context,
)


# =============================================================================
# [FYP-SECTION] TEST SETUP, FIXTURES, AND ASSERTIONS
# =============================================================================

# [FYP-FUNCTION] `write_json` — persists or updates write json state used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `path`, `data`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/adapters/run_parser_normalisation.py:main, soc_reporting_agent/adapters/run_reporting.py:_copy_report_artifacts, soc_reporting_agent/adapters/run_reporting.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `dumps`, `mkdir`, `write_text`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# [FYP-FUNCTION] `run_case` — orchestrates the run case entry point and its ordered test and validation operations.
# [FYP-INPUT] Parameters: `name`, `setup_fn`, `expected_exists`, `expected_usable`, `expected_approval`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/scripts/test_reporting_context_resolution.py:main, soc_reporting_agent/scripts/test_reporting_gate_with_limited_investigation.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `TemporaryDirectory`, `ensure_reporting_inputs`, `exists`, `mkdir`, `resolve_investigation_approval_context`, `resolve_investigation_context`, `setup_fn`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def run_case(name: str, setup_fn, expected_exists: bool, expected_usable: bool, expected_approval: bool | None = None) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "outputs").mkdir()
        (root / "inputs").mkdir()
        ticket = setup_fn(root)
        resolved = resolve_investigation_context(root, ticket_id="TKT-TEST-001", ticket=ticket)
        approval = resolve_investigation_approval_context(root, ticket_id="TKT-TEST-001", ticket=ticket)
        ensure_result = ensure_reporting_inputs(root, ticket_id="TKT-TEST-001", ticket=ticket)
        copied_input = (root / "inputs" / "investigation_result.json").exists()
        passed = (
            resolved.exists == expected_exists
            and resolved.usable == expected_usable
            and (expected_approval is None or approval.usable == expected_approval)
            and ((not expected_usable) or copied_input)
        )
        return {
            "name": name,
            "passed": passed,
            "resolved_exists": resolved.exists,
            "resolved_usable": resolved.usable,
            "resolved_source": resolved.source,
            "approval_usable": approval.usable,
            "input_copied": copied_input,
            "ensure_result": ensure_result,
        }


# [FYP-FUNCTION] `case_ticket_limited` — implements the case ticket limited operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `root`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: no nested function/service calls.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def case_ticket_limited(root: Path) -> dict:
    return {
        "investigation_result": {
            "status": "completed_limited",
            "summary": "Investigation completed with limited endpoint telemetry.",
            "missing_evidence": [{"gap": "process_tree", "priority": "High"}],
        },
        "investigation_approval_result": {"decision": "approved", "analyst": "SOC Analyst"},
    }


# [FYP-FUNCTION] `case_outputs_completed_with_gaps` — implements the case outputs completed with gaps operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `root`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `write_json`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def case_outputs_completed_with_gaps(root: Path) -> dict:
    write_json(root / "outputs" / "investigation_result.json", {
        "status": "completed_with_evidence_gaps",
        "summary": "Investigation produced usable findings, but DNS telemetry is missing.",
        "findings": ["Host executed suspicious binary."],
    })
    write_json(root / "outputs" / "investigation_approval_result.json", {"decision": "approved"})
    return {}


# [FYP-FUNCTION] `case_unknown_needs_more_data` — implements the case unknown needs more data operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `root`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `write_json`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def case_unknown_needs_more_data(root: Path) -> dict:
    write_json(root / "outputs" / "unknown" / "investigation_result.json", {
        "status": "needs_more_data",
        "summary": "Playbook could not be fully answered due to missing network telemetry.",
        "missing_fields": ["netflow", "dns_logs"],
    })
    write_json(root / "inputs" / "investigation_approval_result.json", {"status": "completed"})
    return {}


# [FYP-FUNCTION] `case_failed_blocks` — implements the case failed blocks operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `root`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `write_json`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def case_failed_blocks(root: Path) -> dict:
    write_json(root / "outputs" / "investigation_result.json", {
        "status": "failed",
        "summary": "Investigation adapter crashed.",
    })
    write_json(root / "outputs" / "investigation_approval_result.json", {"decision": "approved"})
    return {}


# [FYP-FUNCTION] `case_missing_blocks` — implements the case missing blocks operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `root`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: no nested function/service calls.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def case_missing_blocks(root: Path) -> dict:
    return {}


# [FYP-FUNCTION] `main` — orchestrates the main entry point and its ordered test and validation operations.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:<module>, eval_harness.py:<module>, soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `len`, `mkdir`, `print`, `run_case`, `sum`, `write_json`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def main() -> int:
    tests = [
        ("ticket completed_limited unlocks reporting with approval", case_ticket_limited, True, True, True),
        ("outputs completed_with_evidence_gaps is discovered", case_outputs_completed_with_gaps, True, True, True),
        ("outputs/unknown needs_more_data with summary is discovered", case_unknown_needs_more_data, True, True, True),
        ("failed investigation remains blocked", case_failed_blocks, True, False, True),
        ("missing investigation remains blocked", case_missing_blocks, False, False, None),
    ]
    results = [run_case(*case) for case in tests]
    out_dir = PROJECT_ROOT / "testdata" / "reporting_context_resolution"
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "test_results.json", {"results": results, "passed": sum(1 for r in results if r["passed"]), "failed": sum(1 for r in results if not r["passed"])})
    for result in results:
        print(("PASS" if result["passed"] else "FAIL") + " - " + result["name"])
    failed = [r for r in results if not r["passed"]]
    print(f"Passed: {len(results) - len(failed)}")
    print(f"Failed: {len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
