# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, json, os, pathlib, sys, tempfile.
# =============================================================================
# File: eval_harness.py
# Purpose: This module runs repeatable evaluation scenarios and records pipeline quality results.
# Main functionality: _triage_result, _c_tactic, _c_verdict, _c_diamond, _c_sop, _c_sidecar.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis SOC analysis support component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, json, os, pathlib, sys, tempfile.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: _triage_result, _c_tactic, _c_verdict, _c_diamond, _c_sop, _c_sidecar, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

"""
eval_harness.py — offline golden-set evaluation for the SOC agent/skill pipeline.

WHY
    The ~18 deterministic skills + the triage→investigation handoff had no
    regression net: a change could silently degrade a verdict band, break the
    endpoint-vs-phishing playbook routing, or drop a MITRE inference and nobody
    would notice until a live run. This harness runs the DETERMINISTIC surfaces
    over a small golden set (tests/golden_incidents.json) and asserts the
    expected outcome band — fast, no LLM, no network, no VPN.

WHAT IT CHECKS  (per golden incident, only the keys present in its `expect`)
    tactic_inference  — availability + inferred tactic + confidence
    verdict           — unified triage verdict band (CRITICAL/HIGH/MEDIUM/LOW)
    diamond           — Diamond Model availability + completeness floor
    sop               — Response-SOP validity + approval gate + scenario
    sidecar           — skills_sidecar availability + which skills ran
    playbook          — the investigation agent's endpoint-vs-phishing routing
                        (guards the lateral-movement→endpoint fix; auto-skipped
                        if the revised agent isn't importable)

USAGE
    python eval_harness.py            # run all goldens, print table, exit 0/1
    python eval_harness.py -v         # also print each expectation's detail
    (importable: run_evals() -> (results:list, all_passed:bool))

It reads ONLY; it never triages/investigates for real and never writes to any
DB or agent state. Safe to run any time, including in CI.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_GOLDEN = _ROOT / "tests" / "golden_incidents.json"


# ── triage_result synthesis (deterministic, from the golden's `triage` block) ─

# =============================================================================
# [FYP-SECTION] SOC ANALYSIS SUPPORT EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `_triage_result` — implements the triage result operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `case`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include eval_harness.py:run_evals, tests/test_investigation_stage.py:_run_to_investigation_processing, tests/test_investigation_stage.py:test_build_case_view_never_calls_investigation_stage_functions; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`, `lower`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _triage_result(case: dict) -> dict | None:
    t = case.get("triage")
    if not t:
        return None
    cls = t.get("classification", "Medium")
    tac = t.get("mitre_tactic", "")
    tech = t.get("mitre_technique", "")
    return {
        "metakeys_payload": {"classification": cls.lower(), "risk_level": cls.lower(),
                             "mitre_tactic": tac, "mitre_technique": tech,
                             "metakey_values": {}},
        "ticket": {"classification": cls, "mitre_tactic": tac, "mitre_technique": tech,
                   "incident_category": t.get("incident_category", ""), "unc": "#EVAL"},
    }


# ── per-check evaluators: return (ok: bool|None, detail: str). None = skipped ──

# [FYP-FUNCTION] `_c_tactic` — implements the c tactic operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `inc`, `tri`, `exp`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `get`, `infer_tactics`, `lower`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _c_tactic(inc, tri, exp):
    from tactic_inference import infer_tactics
    r = infer_tactics(inc)
    if r.get("available") != exp.get("available"):
        return False, f"available={r.get('available')} want {exp.get('available')}"
    if exp.get("tactic_contains"):
        got = str(r.get("tactic") or "").lower()
        if exp["tactic_contains"] not in got:
            return False, f"tactic={got!r} lacks {exp['tactic_contains']!r}"
    if exp.get("confidence") and r.get("confidence") != exp["confidence"]:
        return False, f"confidence={r.get('confidence')} want {exp['confidence']}"
    return True, f"available={r.get('available')} tactic={r.get('tactic')!r}"


# [FYP-FUNCTION] `_c_verdict` — implements the c verdict operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `inc`, `tri`, `exp`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `aggregate_verdict`, `get`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _c_verdict(inc, tri, exp):
    from triage_verdict import aggregate_verdict
    v = aggregate_verdict(inc, tri)
    lvl = v.get("level")
    if lvl not in exp["level_in"]:
        return False, f"level={lvl} not in {exp['level_in']}"
    return True, f"level={lvl}"


# [FYP-FUNCTION] `_c_diamond` — implements the c diamond operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `inc`, `tri`, `exp`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `build_diamond`, `get`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _c_diamond(inc, tri, exp):
    from diamond_model import build_diamond
    d = build_diamond(inc, tri)
    if d.get("available") != exp.get("available", True):
        return False, f"available={d.get('available')}"
    comp = d.get("stats", {}).get("completeness_pct", 0)
    if comp < exp.get("completeness_min", 0):
        return False, f"completeness={comp} < {exp['completeness_min']}"
    return True, f"available={d.get('available')} completeness={comp}"


# [FYP-FUNCTION] `_c_sop` — implements the c sop operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `inc`, `tri`, `exp`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `build_incident_sop`, `get`, `lower`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _c_sop(inc, tri, exp):
    from reporting_sop import build_incident_sop
    s = build_incident_sop(inc, tri)
    if not s.get("available"):
        return False, "sop unavailable"
    val = s.get("validation", {}).get("valid")
    if "valid" in exp and val != exp["valid"]:
        return False, f"valid={val} want {exp['valid']}"
    if "approval_required" in exp:
        ar = s.get("stats", {}).get("approval_required")
        if ar != exp["approval_required"]:
            return False, f"approval_required={ar} want {exp['approval_required']}"
    if exp.get("scenario_contains"):
        sc = str(s.get("meta", {}).get("scenario") or "").lower()
        if exp["scenario_contains"] not in sc:
            return False, f"scenario={sc!r} lacks {exp['scenario_contains']!r}"
    return True, f"valid={val} scenario={s.get('meta', {}).get('scenario')!r}"


# [FYP-FUNCTION] `_c_sidecar` — implements the c sidecar operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `inc`, `tri`, `exp`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `build_skills_context`, `get`, `set`, `sorted`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _c_sidecar(inc, tri, exp):
    from skills_sidecar import build_skills_context
    b = build_skills_context(inc, tri)
    if b.get("available") != exp.get("available", True):
        return False, f"available={b.get('available')}"
    ran = set(b.get("skills_ran") or [])
    missing = [s for s in exp.get("skills_include", []) if s not in ran]
    if missing:
        return False, f"skills_ran missing {missing} (ran={sorted(ran)})"
    return True, f"ran={sorted(ran)}"


# lazily-loaded investigation-agent selector (endpoint-vs-phishing router)
_SELECTOR = "unloaded"


# [FYP-FUNCTION] `_selector` — implements the selector operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include eval_harness.py:_c_playbook; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `exec_module`, `insert`, `module_from_spec`, `spec_from_file_location`, `str`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _selector():
    global _SELECTOR
    if _SELECTOR != "unloaded":
        return _SELECTOR
    agent = _ROOT / "agents" / "investigation"
    try:
        import importlib.util
        if str(agent) not in sys.path:
            sys.path.insert(0, str(agent))
        spec = importlib.util.spec_from_file_location("inv_main_eval", str(agent / "main.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _SELECTOR = (mod, agent)
    except Exception as exc:  # heavy deps absent, etc. — skip the router checks
        _SELECTOR = (None, str(exc)[:80])
    return _SELECTOR


# [FYP-FUNCTION] `_c_playbook` — implements the c playbook operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `inc`, `tri`, `exp`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `NamedTemporaryFile`, `_selector`, `basename`, `build_investigation_alert`, `chdir`, `close`, `dump`, `getcwd`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _c_playbook(inc, tri, exp):
    if tri is None:
        return None, "no triage block -> playbook check skipped"
    mod, agent = _selector()
    if mod is None:
        return None, f"selector unavailable ({agent}) -> skipped"
    from workflow import engine as wf
    alert = wf.build_investigation_alert(tri, inc)
    cwd = os.getcwd()
    try:
        os.chdir(agent)                      # PLAYBOOKS_FOLDER is relative
        f = tempfile.NamedTemporaryFile("w", suffix=".json", dir=str(agent),
                                        delete=False, encoding="utf-8")
        json.dump(alert, f)
        f.close()
        pb = os.path.basename(mod.select_playbook_automatically(f.name))
        os.unlink(f.name)
    finally:
        os.chdir(cwd)
    if pb != exp:
        return False, f"playbook={pb} want {exp}"
    return True, f"playbook={pb}"


_CHECKS = {
    "tactic_inference": _c_tactic,
    "verdict":          _c_verdict,
    "diamond":          _c_diamond,
    "sop":              _c_sop,
    "sidecar":          _c_sidecar,
    "playbook":         _c_playbook,
}


# [FYP-FUNCTION] `run_evals` — orchestrates the run evals entry point and its ordered SOC analysis support operations.
# [FYP-INPUT] Parameters: `path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include eval_harness.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `_triage_result`, `all`, `append`, `fn`, `get`, `items`, `loads`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def run_evals(path: Path = _GOLDEN):
    """Run every golden case. Returns (results, all_passed). results is a list of
    (case_name, check_name, status, detail) where status ∈ PASS|FAIL|SKIP."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    results: list[tuple[str, str, str, str]] = []
    for case in data.get("cases", []):
        inc = case["incident"]
        tri = _triage_result(case)
        for check, exp in case.get("expect", {}).items():
            fn = _CHECKS.get(check)
            if not fn:
                results.append((case["name"], check, "SKIP", "unknown check"))
                continue
            try:
                ok, detail = fn(inc, tri, exp)
            except Exception as exc:
                ok, detail = False, f"EXCEPTION: {type(exc).__name__}: {exc}"
            status = "PASS" if ok is True else ("SKIP" if ok is None else "FAIL")
            results.append((case["name"], check, status, detail))
    all_passed = all(s != "FAIL" for _, _, s, _ in results)
    return results, all_passed


# [FYP-FUNCTION] `main` — orchestrates the main entry point and its ordered SOC analysis support operations.
# [FYP-INPUT] Parameters: `argv`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:<module>, eval_harness.py:<module>, soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `print`, `run_evals`, `sum`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    verbose = "-v" in argv or "--verbose" in argv
    results, ok = run_evals()
    passed = sum(1 for _, _, s, _ in results if s == "PASS")
    failed = sum(1 for _, _, s, _ in results if s == "FAIL")
    skipped = sum(1 for _, _, s, _ in results if s == "SKIP")

    icon = {"PASS": "", "FAIL": "", "SKIP": ""}
    cur = None
    for name, check, status, detail in results:
        if name != cur:
            print(f"\n{name}")
            cur = name
        if status == "FAIL" or verbose or status == "SKIP":
            print(f"  {icon[status]} {check:<16} {detail}")
        else:
            print(f"  {icon[status]} {check}")
    print(f"\n── {passed} passed · {failed} failed · {skipped} skipped ──")
    print("GOLDEN EVAL: PASS" if ok else "GOLDEN EVAL: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
