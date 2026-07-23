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

_ROOT = Path(__file__).resolve().parent
_GOLDEN = _ROOT / "tests" / "golden_incidents.json"


# ── triage_result synthesis (deterministic, from the golden's `triage` block) ─

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


def _c_verdict(inc, tri, exp):
    from triage_verdict import aggregate_verdict
    v = aggregate_verdict(inc, tri)
    lvl = v.get("level")
    if lvl not in exp["level_in"]:
        return False, f"level={lvl} not in {exp['level_in']}"
    return True, f"level={lvl}"


def _c_diamond(inc, tri, exp):
    from diamond_model import build_diamond
    d = build_diamond(inc, tri)
    if d.get("available") != exp.get("available", True):
        return False, f"available={d.get('available')}"
    comp = d.get("stats", {}).get("completeness_pct", 0)
    if comp < exp.get("completeness_min", 0):
        return False, f"completeness={comp} < {exp['completeness_min']}"
    return True, f"available={d.get('available')} completeness={comp}"


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


def _selector():
    global _SELECTOR
    if _SELECTOR != "unloaded":
        return _SELECTOR
    agent = _ROOT / "soc_investigation_agent_revised"
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


def _c_playbook(inc, tri, exp):
    if tri is None:
        return None, "no triage block -> playbook check skipped"
    mod, agent = _selector()
    if mod is None:
        return None, f"selector unavailable ({agent}) -> skipped"
    import soc_workflow as wf
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


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    verbose = "-v" in argv or "--verbose" in argv
    results, ok = run_evals()
    passed = sum(1 for _, _, s, _ in results if s == "PASS")
    failed = sum(1 for _, _, s, _ in results if s == "FAIL")
    skipped = sum(1 for _, _, s, _ in results if s == "SKIP")

    icon = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭️"}
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
