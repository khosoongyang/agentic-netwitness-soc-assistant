# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: pathlib.
# =============================================================================
# File: soc_reporting_agent/scripts/test_agent_rerun_ui_static.py
# Purpose: This module implements test and validation behaviour for test agent rerun ui static.
# Main functionality: check.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis test and validation component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: pathlib.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: check, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
app = (ROOT / "dashboard" / "app.js").read_text(encoding="utf-8")
backend = (ROOT / "backend" / "app.py").read_text(encoding="utf-8")

checks = []


# =============================================================================
# [FYP-SECTION] TEST SETUP, FIXTURES, AND ASSERTIONS
# =============================================================================

# [FYP-FUNCTION] `check` — implements the check operation used by the surrounding test and validation workflow.
# [FYP-INPUT] Parameters: `name`, `condition`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/scripts/test_agent_rerun_ui_static.py:<module>, soc_reporting_agent/scripts/test_reporting_workspace_ui_static.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `bool`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def check(name, condition):
    checks.append((name, bool(condition)))


check("frontend stores per-agent rerun guards", "agentRunGuards" in app and "agentRunGuardSequence" in app)
check("rerun marks guard before awaiting backend", 'markAgentRunStarting(agentKey, ticketId, "rerun")' in app and 'render();\n  const res = await api(`/api/tickets/${encodeURIComponent(ticketId)}/agents/${encodeURIComponent(agentKey)}/rerun`' in app)
check("run marks guard before awaiting backend", 'markAgentRunStarting(agentKey, ticketId, "run")' in app and 'render();\n  const endpoint = ticketId' in app)
check("currentAgentRun prefers guarded state", "const guarded = guardedRunForAgent(agent);" in app and "if (guarded) return guarded;" in app)
check("summary payload masks old output while guarded", "shouldMaskAgentOutput(ticket, agent.key || agentKey)" in app and "rawOutput = !shouldMaskAgentOutput" in app)
check("summary downloads disable without fresh output", "disabledDownloadButton(\"Download JSON\"" in app and "if (!hasOutput)" in app)
check("reporting workspace masks old reports while rerunning", "reporting-rerun-placeholder" in app and "if (shouldMaskAgentOutput(ticket, \"reporting\"))" in app)
check("view output blocks guarded stale output", "The latest run is still in progress or failed. Active output is not available yet." in app)
check("polling uses currentAgentRun instead of first stale run", "const run = agent ? currentAgentRun(agent) : null;" in app and "const updated = currentAgentRun(agent);" in app)
check("failed run states are not treated as completed", '"execution_error", "timed_out", "timeout", "paused"' in app and "run.success === false" in app)
check("backend start response includes started_at", '"started_at": run_record["started_at"]' in backend)
check("backend existing-run response includes progress metadata", '"progress_percent": current.get("progress_percent")' in backend and '"progress_percent": existing_active.get("progress_percent")' in backend)

failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
if failed:
    raise SystemExit(f"Failed checks: {failed}")
print(f"\nPassed {len(checks)} agent rerun UI checks.")
