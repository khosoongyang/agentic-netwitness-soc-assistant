# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, json, pathlib, shutil, subprocess, sys.
# =============================================================================
# File: soc_reporting_agent/scripts/test_reporting_appendix_context.py
# Purpose: This module implements test and validation behaviour for test reporting appendix context.
# Main functionality: write_json, reset_io, seed_inputs, test_context_and_templates, test_adapter_success_wrapper, test_failed_subprocess_not_completed.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis test and validation component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, json, pathlib, shutil, subprocess, sys.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: write_json, reset_io, seed_inputs, test_context_and_templates, test_adapter_success_wrapper, test_failed_subprocess_not_completed, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
INPUTS = ROOT / "inputs"
OUTPUTS = ROOT / "outputs"


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


# [FYP-FUNCTION] `reset_io` — persists or updates reset io state used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/scripts/test_reporting_appendix_context.py:main, soc_reporting_agent/scripts/test_reporting_appendix_context.py:test_failed_subprocess_not_completed; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `exists`, `mkdir`, `rmtree`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def reset_io() -> None:
    for path in (INPUTS, OUTPUTS):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True, exist_ok=True)


# [FYP-FUNCTION] `seed_inputs` — implements the seed inputs operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/scripts/test_merged_report_context.py:main, soc_reporting_agent/scripts/test_reporting_appendix_context.py:main, soc_reporting_agent/scripts/test_reporting_appendix_context.py:test_failed_subprocess_not_completed; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `write_json`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def seed_inputs() -> None:
    write_json(INPUTS / "processed_alert.json", {
        "incident_id": "INC-TI-RAW-0001",
        "alert_id": "ALERT-TI-RAW-0001",
        "alert_title": "Suspicious File Execution with External DNS Lookup",
        "incident_title": "Raw Endpoint Malware Alert with External IOC Context",
        "severity": "High",
        "risk_score": 88,
        "timestamp": "2026-06-18T10:15:00+00:00",
        "hostname": "wkstn-sg-ti-raw-001",
        "source_ip": "10.20.30.41",
        "destination_ip": "8.8.8.8",
        "file_hash": "44d88612fea8a8f36de82e1278abb02f",
        "event_domain": "example.com",
        "url": "https://example.com/download/eicar_test_file.exe",
        "iocs": [
            {"type": "ip", "value": "8.8.8.8"},
            {"type": "file_hash", "value": "44d88612fea8a8f36de82e1278abb02f"},
        ],
    })
    write_json(INPUTS / "enriched_alert.json", {
        "incident_id": "INC-TI-RAW-0001",
        "alert_id": "ALERT-TI-RAW-0001",
        "severity": "High",
        "confidence": "High",
        "iocs": [{"type": "domain", "value": "example.com"}],
    })
    write_json(INPUTS / "triage_result.json", {
        "incident_id": "INC-TI-RAW-0001",
        "alert_id": "ALERT-TI-RAW-0001",
        "severity": "High",
        "confidence": "High",
        "classification": "Suspicious endpoint malware activity",
        "likely_scenario": "Endpoint malware execution with external DNS/HTTPS activity",
    })
    write_json(INPUTS / "investigation_result.json", {
        "status": "completed_with_evidence_gaps",
        "incident_id": "unknown",
        "severity": "High",
        "confidence": "High",
        "classification": "Investigation completed with evidence gaps",
        "likely_scenario": "Endpoint malware execution",
        "summary": "Investigation completed with evidence gaps. Reporting can continue with limitations.",
        "findings": ["Affected host: wkstn-sg-ti-raw-001"],
        "missing_evidence": [
            {"gap": "email_datetime", "priority": "High", "reason": "Email datetime is missing."},
            {"gap": "sender_or_receiver_email", "priority": "High", "reason": "Sender/receiver is missing."},
            {"gap": "email_subject", "priority": "High", "reason": "Subject is missing."},
        ],
        "reporting_allowed": True,
        "reporting_mode": "with_limitations",
    })
    write_json(INPUTS / "approval_result.json", {
        "decision": "continue_to_reporting",
        "approval_status": "approved",
        "reporting_mode": "with_limitations",
        "analyst_comments": "Continue to reporting with limitations.",
    })


# [FYP-FUNCTION] `test_context_and_templates` — verifies context and templates behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `Path`, `build_context`, `get`, `len`, `load_reporting_inputs`, `read_text`, `render_reports`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_context_and_templates() -> None:
    from reporting.input_loader import load_reporting_inputs
    from reporting.context_builder import build_context
    from reporting.report_renderer import render_reports

    inputs, warnings = load_reporting_inputs(INPUTS)
    context = build_context(inputs, warnings, output_dir=OUTPUTS)
    assert "appendix_summaries" in context, "appendix_summaries missing from context"
    assert context["appendix_summaries"].get("raw_alert"), "raw alert appendix missing"
    assert context["reporting_mode"] == "with_limitations", context["reporting_mode"]
    assert len(context["investigation_limitations"]) == 3, context["investigation_limitations"]
    generated = render_reports(context, output_dir=OUTPUTS)
    assert generated.get("final_incident_report"), "final incident report not generated"
    final_text = Path(generated["final_incident_report"]).read_text(encoding="utf-8")
    assert "Appendix A" in final_text, "final report appendix missing"


# [FYP-FUNCTION] `test_adapter_success_wrapper` — verifies adapter success wrapper behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `__import__`, `dict`, `exists`, `get`, `len`, `loads`, `read_text`, `run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_adapter_success_wrapper() -> None:
    result = subprocess.run(
        [sys.executable, "adapters/run_reporting.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env={**dict(), **__import__("os").environ, "REPORTING_USE_LLM": "false", "SOC_TICKET_ID": "TKT-2026-00127"},
        timeout=240,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    wrapper_path = OUTPUTS / "TKT-2026-00127" / "reporting" / "reporting_result.json"
    assert wrapper_path.exists(), "ticket reporting_result.json not created"
    wrapper = json.loads(wrapper_path.read_text(encoding="utf-8"))
    assert wrapper["status"] == "completed", wrapper
    assert wrapper["reporting_mode"] == "with_limitations", wrapper
    assert wrapper["incident_id"] == "INC-TI-RAW-0001", wrapper
    assert wrapper["alert_id"] == "ALERT-TI-RAW-0001", wrapper
    assert wrapper.get("generated_reports"), wrapper
    assert len(wrapper.get("investigation_limitations") or []) == 3, wrapper


# [FYP-FUNCTION] `test_failed_subprocess_not_completed` — verifies failed subprocess not completed behaviour and protects the related test and validation code path.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_normalise_reporting_result`, `get`, `len`, `reset_io`, `seed_inputs`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def test_failed_subprocess_not_completed() -> None:
    from adapters.run_reporting import _normalise_reporting_result
    reset_io()
    seed_inputs()
    # Use a future start time so any accidental old artefact is ignored.
    failed = {
        "success": False,
        "returncode": 1,
        "started_at": "2099-01-01T00:00:00+00:00",
        "stderr": "jinja2.exceptions.UndefinedError: 'appendix_summaries' is undefined",
        "stdout": "",
        "script": "agents/reporting_agent.py",
    }
    wrapper = _normalise_reporting_result(failed, ticket_id="TKT-FAIL")
    assert wrapper["status"] == "failed", wrapper
    assert wrapper["report_status"] == "failed", wrapper
    assert wrapper.get("error_summary"), wrapper
    assert wrapper["reporting_mode"] == "with_limitations", wrapper
    assert len(wrapper.get("investigation_limitations") or []) == 3, wrapper


# [FYP-FUNCTION] `main` — orchestrates the main entry point and its ordered test and validation operations.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:<module>, eval_harness.py:<module>, soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `dumps`, `len`, `mkdir`, `print`, `reset_io`, `seed_inputs`, `str`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def main() -> int:
    reset_io()
    seed_inputs()
    tests = [
        test_context_and_templates,
        test_adapter_success_wrapper,
        test_failed_subprocess_not_completed,
    ]
    results = []
    for test in tests:
        try:
            test()
            results.append({"test": test.__name__, "status": "passed"})
        except Exception as exc:
            results.append({"test": test.__name__, "status": "failed", "error": str(exc)})
    passed = sum(1 for r in results if r["status"] == "passed")
    failed = len(results) - passed
    out = {"passed": passed, "failed": failed, "results": results}
    out_path = ROOT / "testdata" / "reporting_appendix_context" / "test_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
