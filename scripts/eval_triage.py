# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: argparse, json, os, shutil, sqlite3, tempfile, time,
#   agents.parsing, agents.triage (imported lazily, after the ticket-DB
#   redirect).
# =============================================================================
# File: scripts/eval_triage.py
# Purpose: Triage Step 2 (X7) -- evaluate the REAL triage path (Parsing ->
#   TriageAgent.triage) on labelled cases, repeatedly, and report accuracy
#   against labels WITH their provenance, run-to-run consistency, must_not
#   violations, canary results, uncertainty, guard actions, citation errors,
#   latency and token use. "Measure before you claim."
# Modes: offline (scripted LLM, for CI -- tests the harness itself) and
#   live (real OpenAI via .env OPENAI_API_KEY).
# Inputs: tests/triage_eval/{cases,canaries,lab}/*.json (see docs/triage-evaluation.md),
#   soc_db/soc_incidents.db (READ-ONLY, measured baseline).
# Outputs: runtime/eval_reports/<timestamp>.json + .md (git-ignored).
# Safety: NEVER writes to soc_db/: the triage ticket/cache DB is redirected to
#   a temp copy (AEGIS_TICKET_DB + module patch), parser output goes to a temp
#   dir, the baseline DB is opened mode=ro, and soc_db/*.db size+mtime are
#   checked before/after (a change fails the run).
# Exit codes: 0 ok; 1 any must_not violation, canary failure or soc_db change;
#   2 configuration error (e.g. --mode live without OPENAI_API_KEY).
# Key evaluator search terms: eval_triage, must_not, canary, [FYP-TRIAGE-STEP2].
# =============================================================================
"""Usage:
  python scripts/eval_triage.py --mode offline
  python scripts/eval_triage.py --mode live --repeats 3 [--cases "tests/triage_eval/cases/*.json"] [--max-cases 5]
  python scripts/eval_triage.py --mode live --dry-run      # print the planned LLM call count only
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import statistics
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_CASE_GLOBS = (
    "tests/triage_eval/cases/*.json",
    "tests/triage_eval/canaries/*.json",
    "tests/triage_eval/lab/*.json",
)
SOC_DB_DIR = ROOT / "soc_db"
BASELINE_DB = SOC_DB_DIR / "soc_incidents.db"
DEFAULT_REPORT_DIR = ROOT / "runtime" / "eval_reports"
LLM_CALLS_PER_TRIAGE = 3          # IOC Checklists, Risk Rating, SOC Classification
DISPOSITIONS = ("true_positive", "false_positive", "benign_expected", "needs_info")
BENIGN_SIDE = ("false_positive", "benign_expected")
LABEL_SOURCES = ("lab_ground_truth", "public_dataset", "analyst", "mentor_reviewed", "synthetic")


# =============================================================================
# [FYP-SECTION] CASES
# =============================================================================

def load_incident(case: dict, root: Path = ROOT) -> dict:
    """The case's incident: inline `incident`, or `incident_file` (a Respond-API
    export {incident, alerts[]} is merged into one incident with `alerts`)."""
    if isinstance(case.get("incident"), dict):
        return case["incident"]
    path = Path(case["incident_file"])
    path = path if path.is_absolute() else root / path
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("incident"), dict):
        inc = dict(data["incident"])
        if isinstance(data.get("alerts"), list):
            inc["alerts"] = data["alerts"]
        return inc
    return data


def is_labelled(case: dict) -> bool:
    label = case.get("label") or {}
    return bool(label.get("value")) and bool(label.get("source")) and isinstance(case.get("expected"), dict)


def validate_case(case: dict) -> list[str]:
    """Schema problems for one case (empty list = valid)."""
    errs = []
    if not case.get("name"):
        errs.append("missing name")
    if not isinstance(case.get("incident"), dict) and not case.get("incident_file"):
        errs.append("needs incident or incident_file")
    da = case.get("data_availability")
    if da is not None and not isinstance(da, dict):
        errs.append("data_availability must be an object or null")
    exp = case.get("expected")
    if exp is not None:
        for key in ("disposition_acceptable", "must_not"):
            vals = exp.get(key)
            if not isinstance(vals, list) or any(v not in DISPOSITIONS for v in vals):
                errs.append(f"expected.{key} must be a list of {DISPOSITIONS}")
        if set(exp.get("disposition_acceptable") or []) & set(exp.get("must_not") or []):
            errs.append("a disposition cannot be both acceptable and must_not")
    label = case.get("label")
    if not isinstance(label, dict):
        errs.append("missing label object (use value/source null for unlabelled)")
    elif label.get("value") is not None:
        if label.get("value") not in DISPOSITIONS:
            errs.append(f"label.value must be one of {DISPOSITIONS}")
        if label.get("source") not in LABEL_SOURCES:
            errs.append(f"label.source must be one of {LABEL_SOURCES}")
        for key in ("labeller", "date", "rationale"):
            if not label.get(key):
                errs.append(f"label.{key} is required for a labelled case")
        if exp is None:
            errs.append("a labelled case needs expected{disposition_acceptable, must_not}")
    return errs


def load_cases(globs_: list[str] | tuple[str, ...], root: Path = ROOT,
               max_cases: int | None = None) -> list[dict]:
    paths: list[Path] = []
    for pattern in globs_:
        for part in str(pattern).split(","):
            part = part.strip()
            if not part:
                continue
            full = part if os.path.isabs(part) else str(root / part)
            paths.extend(Path(p) for p in sorted(glob.glob(full)))
    seen, cases = set(), []
    for p in paths:
        if p.resolve() in seen:
            continue
        seen.add(p.resolve())
        case = json.loads(p.read_text(encoding="utf-8"))
        case.setdefault("name", p.stem)
        case["_path"] = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)
        errs = validate_case(case)
        if errs:
            raise ValueError(f"invalid case {p}: {'; '.join(errs)}")
        cases.append(case)
    return cases[:max_cases] if max_cases else cases


def is_malicious_canary(case: dict) -> bool:
    return (case.get("canary") or {}).get("role") == "malicious"


# =============================================================================
# [FYP-SECTION] SAFETY: ticket DB redirect + soc_db snapshot
# =============================================================================

def soc_db_snapshot(db_dir: Path = SOC_DB_DIR) -> dict[str, tuple[int, int]]:
    """size + mtime of soc_db/*.db (SQLite -wal/-shm sidecars excluded: WAL
    readers legitimately touch the shared-memory index)."""
    return {p.name: (p.stat().st_size, p.stat().st_mtime_ns)
            for p in sorted(db_dir.glob("*.db")) if p.is_file()}


def redirect_ticket_db(workdir: Path) -> Path:
    """Point the triage ticket + cache DB at a temp COPY. Sets
    AEGIS_TICKET_DB for a fresh import and patches an already-imported
    module (tests)."""
    target = workdir / "soc_tickets.eval.db"
    src = SOC_DB_DIR / "soc_tickets.db"
    if src.exists() and not target.exists():
        shutil.copy2(src, target)
    os.environ["AEGIS_TICKET_DB"] = str(target)
    mod = sys.modules.get("agents.triage.soc_triage_agent")
    if mod is not None:
        mod._TICKET_DB = target
        mod._ticket_db_init()
    return target


# =============================================================================
# [FYP-SECTION] OFFLINE SCRIPTED MODEL
# =============================================================================

class ScriptedLLM:
    """Deterministic stand-in for the 3 LLM phases (offline mode / CI).

    It reads the evidence packet the agent built in Phase 0 and plays a
    plausible-but-imperfect analyst:
      * strong deterministic signals or a threat_desc -> true_positive, citing them;
      * otherwise a "lazy closer": false_positive citing the rule id and alert
        names, plus one non-existent path -- so the citation checks and the
        guards (mandatory evidence, floors) are exercised by the harness.
    policy="always_benign" proposes benign_expected for everything (an
    adversarial model: the guards alone must keep canaries out of the benign
    side). It never sees the case label.
    """

    def __init__(self, agent, policy: str = "heuristic"):
        self.agent = agent
        self.policy = policy
        self.prompt_chars = 0

    def __call__(self, messages, phase_label):
        self.prompt_chars += sum(len(getattr(m, "content", "") or "") for m in messages)
        if phase_label == "IOC Checklists":
            return json.dumps({"availability": {"matched_iocs": []},
                               "confidentiality": {"matched_iocs": [], "reasoning": "scripted"},
                               "integrity": {"matched_iocs": [], "reasoning": "scripted"}})
        if phase_label == "Risk Rating":
            return json.dumps({"likelihood_initiation": "Medium", "likelihood_occurrence": "Medium",
                               "likelihood_adverse_impact": "Medium", "overall_risk": "Medium",
                               "rationale": "SCRIPTED offline model"})
        return json.dumps(self._classification())

    def _classification(self) -> dict:
        from agents.triage.evidence_packet import get_leaf
        from agents.triage.guards import strong_rule_signals
        packet = self.agent._evidence_packet or {}
        base = {"classification": "Medium", "incident_category": "Policy violations",
                "summary": "SCRIPTED offline model output.", "recommended_actions": ["Review"],
                "mitre_tactic": "Execution", "mitre_technique": "Unknown",
                "fn_cost_if_wrong": "scripted", "evidence_checked": ["raw_alerts.available"]}
        strong = strong_rule_signals(packet)
        td = get_leaf(packet, "raw_alerts.threat_desc") or {}
        has_threat = td.get("status") == "measured" and (td.get("value") or {}).get("total_unique")
        if self.policy == "heuristic" and (strong or has_threat):
            cites = []
            for label in strong:
                key = label if get_leaf(packet, f"rule_signals.{label}") else (
                    "masquerade" if label.startswith("masquerade:") else "lolbas")
                cites.append(f"rule_signals.{key}")
            if has_threat:
                cites.append("raw_alerts.threat_desc")
            base.update({"proposed_disposition": "true_positive",
                         "hypotheses": {"malicious": {"evidence_for": [
                             {"claim": "Deterministic strong signals present.",
                              "cites": sorted(set(cites)) or ["detection.riskScore"]}]}},
                         "lookalike_ruled_out": {"lookalike": "admin activity", "ruled_out": False,
                                                 "reason": "not excluded", "cites": cites[:1]}})
            return base
        disposition = "benign_expected" if self.policy == "always_benign" else "false_positive"
        base.update({"proposed_disposition": disposition,
                     "hypotheses": {"benign": {"evidence_for": [
                         {"claim": "The rule fires routinely; looks like normal operations.",
                          "cites": ["detection.ruleId", "raw_alerts.alert_names", "raw_alerts.signers",
                                    "entity.owner_role"]}]}},
                     "lookalike_ruled_out": {"lookalike": "LOLBin abuse", "ruled_out": True,
                                             "reason": "signed binaries", "cites": ["raw_alerts.signers"]}})
        return base


# =============================================================================
# [FYP-SECTION] RUNNERS
# =============================================================================

def parse_incident(incident: dict, workdir: Path) -> tuple[dict | None, str]:
    """The Parsing stage, in-process, writing only into a temp dir. (The
    workflow's run_parsing() wraps the same function but also asks an LLM
    for a display summary that Triage never reads, and writes under the
    repo -- both skipped here.)"""
    from agents.parsing import run_parser_normalisation_for_dashboard
    out = Path(tempfile.mkdtemp(prefix="parse-", dir=str(workdir)))
    try:
        result = run_parser_normalisation_for_dashboard(incident, output_dir=out)
    except Exception as exc:  # parsing failure is recorded, triage still runs
        return None, f"error: {type(exc).__name__}: {exc}"[:300]
    return (result.get("processed_alert") or None), str(result.get("status"))


def make_runner(mode: str, baseline_db: Path, policy: str = "heuristic") -> Callable:
    """Returns run(incident, parsed_context, data_availability) -> (result, meta)."""
    from agents.triage import soc_triage_agent

    def run(incident: dict, parsed_context: dict | None, data_availability: dict | None):
        agent = soc_triage_agent.TriageAgent(baseline_db_path=baseline_db)
        meta: dict[str, Any] = {"tokens": None, "prompt_chars": None}
        if mode == "offline":
            scripted = ScriptedLLM(agent, policy)
            agent._call = scripted
            t0 = time.perf_counter()
            result = agent.triage(incident, force=True, parsed_context=parsed_context,
                                  data_availability=data_availability)
            meta["latency_s"] = round(time.perf_counter() - t0, 3)
            meta["prompt_chars"] = scripted.prompt_chars
            return result, meta
        original = agent._call
        chars = {"n": 0}

        def counting_call(messages, phase_label):
            chars["n"] += sum(len(getattr(m, "content", "") or "") for m in messages)
            return original(messages, phase_label)

        agent._call = counting_call
        t0 = time.perf_counter()
        try:
            from langchain_core.callbacks import get_usage_metadata_callback
            with get_usage_metadata_callback() as cb:
                result = agent.triage(incident, force=True, parsed_context=parsed_context,
                                      data_availability=data_availability)
            usage = {}
            for model_usage in (cb.usage_metadata or {}).values():
                for k in ("input_tokens", "output_tokens", "total_tokens"):
                    usage[k] = usage.get(k, 0) + int(model_usage.get(k) or 0)
            meta["tokens"] = usage or None
        except ImportError:
            result = agent.triage(incident, force=True, parsed_context=parsed_context,
                                  data_availability=data_availability)
        meta["latency_s"] = round(time.perf_counter() - t0, 3)
        meta["prompt_chars"] = chars["n"]
        return result, meta

    return run


# =============================================================================
# [FYP-SECTION] EVALUATION + METRICS
# =============================================================================

def _run_record(result: dict, meta: dict) -> dict:
    if not isinstance(result, dict) or result.get("error"):
        return {"disposition": None, "proposed_disposition": None, "uncertainty": None,
                "guard_rules": [], "citation_errors": [], "error": str((result or {}).get("error"))[:300],
                **meta}
    a = result.get("assessment") or {}
    return {"disposition": a.get("disposition"),
            "proposed_disposition": a.get("proposed_disposition"),
            "uncertainty": a.get("uncertainty"),
            "guard_rules": [g.get("rule") for g in a.get("guard_actions") or []],
            "citation_errors": [e.get("error", "").split(":")[0] for e in a.get("citation_errors") or []],
            "severity": (result.get("ticket") or {}).get("classification"),
            "error": None, **meta}


def evaluate(cases: list[dict], repeats: int, runner: Callable, workdir: Path,
             parse: Callable = parse_incident, log: Callable = print) -> dict:
    case_results = []
    for i, case in enumerate(cases, 1):
        incident = load_incident(case)
        da = case.get("data_availability")
        t0 = time.perf_counter()
        parsed, parse_status = parse(incident, workdir)
        parse_s = round(time.perf_counter() - t0, 3)
        runs = []
        for r in range(repeats):
            try:
                result, meta = runner(incident, parsed, da)
            except Exception as exc:
                result, meta = {"error": f"{type(exc).__name__}: {exc}"}, {"latency_s": None}
            runs.append(_run_record(result, meta))
        labelled = is_labelled(case)
        exp = case.get("expected") or {}
        disps = [r["disposition"] for r in runs]
        acceptable = [d in (exp.get("disposition_acceptable") or []) for d in disps] if labelled else []
        # [IMPROVEMENT #3] needs_info is "acceptable" for every label, so a
        # model that never decides would score 1.0 on acceptable hits alone.
        label_value = (case.get("label") or {}).get("value") if labelled else None
        exact = [d == label_value for d in disps] if labelled else []
        decisive = [d is not None and d != "needs_info" for d in disps] if labelled else []
        da_ = da if isinstance(da, dict) else {}
        without_raw = da_.get("incident_source") == "sqlite_slim" or (
            bool(da_) and da_.get("alerts_fetch_succeeded") is False)
        violations = [d for d in disps if d in (exp.get("must_not") or [])]
        canary_fail = is_malicious_canary(case) and any(d in BENIGN_SIDE for d in disps)
        latencies = [r["latency_s"] for r in runs if r.get("latency_s") is not None]
        cr = {
            "name": case["name"], "path": case.get("_path"),
            "labelled": labelled, "label": case.get("label"), "expected": case.get("expected"),
            "canary": case.get("canary"),
            "data_availability_supplied": da is not None,
            "parse_status": parse_status, "parse_latency_s": parse_s,
            "runs": runs, "dispositions": disps,
            "consistent": len(set(disps)) == 1,
            "acceptable_hits": sum(acceptable), "must_not_violations": len(violations),
            "exact_hits": sum(exact), "decisive_runs": sum(decisive),
            "without_raw_alerts": without_raw,
            "canary_failed": canary_fail,
            "latency_s_median": statistics.median(latencies) if latencies else None,
        }
        case_results.append(cr)
        log(f"[eval] {i}/{len(cases)} {case['name']}: {disps}"
            + (" MUST_NOT VIOLATION" if violations else "") + (" CANARY FAIL" if canary_fail else ""))
    return {"cases": case_results, "metrics": compute_metrics(case_results)}


def _rate(n: int, d: int) -> float | None:
    return round(n / d, 4) if d else None


def compute_metrics(case_results: list[dict]) -> dict:
    all_runs = [r for c in case_results for r in c["runs"]]
    lab = [c for c in case_results if c["labelled"]]
    lab_runs = sum(len(c["runs"]) for c in lab)
    by_source: dict[str, dict] = {}
    for c in lab:
        src = c["label"]["source"]
        s = by_source.setdefault(src, {"cases": 0, "runs": 0, "acceptable_hits": 0,
                                       "exact_hits": 0, "decisive_runs": 0})
        s["cases"] += 1
        s["runs"] += len(c["runs"])
        s["acceptable_hits"] += c["acceptable_hits"]
        s["exact_hits"] += c.get("exact_hits", 0)
        s["decisive_runs"] += c.get("decisive_runs", 0)
    for s in by_source.values():
        s["acceptable_hit_rate"] = _rate(s["acceptable_hits"], s["runs"])
        s["exact_match_rate"] = _rate(s["exact_hits"], s["runs"])
        s["decisive_rate"] = _rate(s["decisive_runs"], s["runs"])
    canaries = [c for c in case_results if c.get("canary")]
    tokens = [r["tokens"]["total_tokens"] for r in all_runs
              if isinstance(r.get("tokens"), dict) and r["tokens"].get("total_tokens")]
    return {
        "n_cases": len(case_results), "n_labelled_cases": len(lab),
        "n_unlabelled_cases": len(case_results) - len(lab), "n_runs": len(all_runs),
        "acceptable_hit_rate": _rate(sum(c["acceptable_hits"] for c in lab), lab_runs),
        # [IMPROVEMENT #3] exact = final disposition equals the label;
        # decisive = anything but needs_info (on labelled runs).
        "exact_match_rate": _rate(sum(c.get("exact_hits", 0) for c in lab), lab_runs),
        "decisive_rate": _rate(sum(c.get("decisive_runs", 0) for c in lab), lab_runs),
        "n_labelled_cases_without_raw_alerts": sum(bool(c.get("without_raw_alerts")) for c in lab),
        "acceptable_hit_rate_by_label_source": by_source,
        "must_not_violation_count": sum(c["must_not_violations"] for c in case_results),
        "consistency_rate": _rate(sum(c["consistent"] for c in case_results), len(case_results)),
        "inconsistent_cases": [c["name"] for c in case_results if not c["consistent"]],
        "needs_info_rate": _rate(sum(r["disposition"] == "needs_info" for r in all_runs), len(all_runs)),
        "disposition_distribution": dict(Counter(r["disposition"] for r in all_runs)),
        "proposed_disposition_distribution": dict(Counter(r["proposed_disposition"] for r in all_runs)),
        "uncertainty_distribution": dict(Counter(r["uncertainty"] for r in all_runs)),
        "guard_actions_frequency": dict(Counter(g for r in all_runs for g in r["guard_rules"])),
        "runs_with_guard_override": sum(bool(r["guard_rules"]) for r in all_runs),
        "citation_errors_frequency": dict(Counter(e for r in all_runs for e in r["citation_errors"])),
        "runs_with_citation_errors": sum(bool(r["citation_errors"]) for r in all_runs),
        "triage_errors": sum(r["error"] is not None for r in all_runs),
        "canaries": {
            "malicious": [{"name": c["name"], "technique": c["canary"].get("technique"),
                           "dispositions": c["dispositions"], "passed": not c["canary_failed"]}
                          for c in canaries if c["canary"].get("role") == "malicious"],
            "benign_pairs": [{"name": c["name"], "technique": c["canary"].get("technique"),
                              "dispositions": c["dispositions"],
                              "acceptable_hits": c["acceptable_hits"], "runs": len(c["runs"])}
                             for c in canaries if c["canary"].get("role") != "malicious"],
            "failures": [c["name"] for c in canaries if c["canary_failed"]],
        },
        "latency_s_median": (statistics.median([r["latency_s"] for r in all_runs if r.get("latency_s")])
                             if any(r.get("latency_s") for r in all_runs) else None),
        "total_tokens": sum(tokens) if tokens else None,
    }


# =============================================================================
# [FYP-SECTION] REPORT
# =============================================================================

def render_markdown(report: dict) -> str:
    m, meta = report["metrics"], report["meta"]
    L = [f"# Triage evaluation report ({meta['mode']})", "",
         f"- Started: {meta['started_at']}  |  repeats: {meta['repeats']}  |  model: {meta['model']}",
         f"- Prompt version: `{meta['triage_prompt_version']}`  |  LOLBAS: {meta['lolbas_source']}",
         f"- Planned LLM calls: {meta['planned_llm_calls']}"
         + (" (scripted, no API)" if meta["mode"] == "offline" else ""),
         f"- soc_db untouched: **{meta['soc_db_untouched']}**", "",
         f"**Result: {'FAIL' if report['exit_code'] else 'PASS'}** "
         f"(must_not violations: {m['must_not_violation_count']}, "
         f"canary failures: {len(m['canaries']['failures'])})", "",
         "## Summary", "", "| metric | value |", "|---|---|"]
    for key in ("n_cases", "n_labelled_cases", "n_unlabelled_cases", "n_runs", "acceptable_hit_rate",
                "exact_match_rate", "decisive_rate", "n_labelled_cases_without_raw_alerts",
                "must_not_violation_count", "consistency_rate", "needs_info_rate",
                "runs_with_guard_override", "runs_with_citation_errors", "triage_errors",
                "latency_s_median", "total_tokens"):
        L.append(f"| {key} | {m.get(key)} |")
    L += ["", "Distributions:", "",
          f"- final disposition: `{m['disposition_distribution']}`",
          f"- proposed (model) disposition: `{m['proposed_disposition_distribution']}`",
          f"- uncertainty: `{m['uncertainty_distribution']}`",
          f"- guard actions: `{m['guard_actions_frequency']}`",
          f"- citation errors: `{m['citation_errors_frequency']}`", "",
          "## Accuracy by label source (beware circular labels)", "",
          "| label source | cases | runs | acceptable-hit rate | exact-match rate | decisive rate |",
          "|---|---|---|---|---|---|"]
    for src, s in sorted(m["acceptable_hit_rate_by_label_source"].items()):
        L.append(f"| {src} | {s['cases']} | {s['runs']} | {s['acceptable_hit_rate']} | "
                 f"{s.get('exact_match_rate')} | {s.get('decisive_rate')} |")
    L += ["", "`synthetic` and implementer-written `analyst` labels measure consistency with the "
          "design, not real-world accuracy; only `lab_ground_truth`, `public_dataset` and "
          "`mentor_reviewed` labels are independent evidence.", "",
          "needs_info is acceptable for every label, so read the acceptable-hit rate together "
          "with the exact-match rate (final disposition == label) and the decisive rate "
          "(not needs_info). "
          f"{m.get('n_labelled_cases_without_raw_alerts', 0)} labelled case(s) ran without raw alerts "
          "(synthetic, or the slim SQLite copy the labelling sheet imports): the guards force "
          "needs_info there, so they cannot score exact matches. For mentor cases, replace the "
          "slim incident with a Respond-API export (`incident_file`).", "",
          "## Canaries (abused-tool techniques must never be closed as benign)", "",
          "| canary | technique | dispositions | result |", "|---|---|---|---|"]
    for c in m["canaries"]["malicious"]:
        L.append(f"| {c['name']} | {c['technique']} | {c['dispositions']} | "
                 f"{'PASS' if c['passed'] else '**FAIL**'} |")
    for c in m["canaries"]["benign_pairs"]:
        L.append(f"| {c['name']} (benign pair) | {c['technique']} | {c['dispositions']} | "
                 f"{c['acceptable_hits']}/{c['runs']} acceptable |")
    L += ["", "## Per case", "",
          "| case | label (source) | dispositions | consistent | acceptable | must_not | uncertainty | guard rules | median s |",
          "|---|---|---|---|---|---|---|---|---|"]
    for c in report["cases"]:
        lab = c["label"] or {}
        label = f"{lab.get('value')} ({lab.get('source')})" if c["labelled"] else "UNLABELLED"
        unc = sorted({r["uncertainty"] for r in c["runs"] if r["uncertainty"]})
        rules = sorted({g for r in c["runs"] for g in r["guard_rules"]})
        acc = f"{c['acceptable_hits']}/{len(c['runs'])}" if c["labelled"] else "n/a"
        L.append(f"| {c['name']} | {label} | {c['dispositions']} | {c['consistent']} | {acc} | "
                 f"{c['must_not_violations']} | {unc} | {rules} | {c['latency_s_median']} |")
    return "\n".join(L) + "\n"


def write_report(report: dict, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    base = out_dir / f"{stamp}_{report['meta']['mode']}"
    jpath, mpath = base.with_suffix(".json"), base.with_suffix(".md")
    jpath.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    mpath.write_text(render_markdown(report), encoding="utf-8")
    return jpath, mpath


# =============================================================================
# [FYP-SECTION] CLI
# =============================================================================

def _load_dotenv() -> None:
    env = ROOT / ".env"
    if env.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env, override=False)
        except ImportError:
            pass


def main(argv: list[str] | None = None, *, runner: Callable | None = None,
         parse: Callable = parse_incident) -> int:
    ap = argparse.ArgumentParser(description="Evaluate the real Triage path on labelled cases.")
    ap.add_argument("--mode", choices=("offline", "live"), default="offline")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--cases", action="append", default=None,
                    help="glob (repeatable or comma-separated); default: cases + canaries + lab")
    ap.add_argument("--max-cases", type=int, default=None)
    ap.add_argument("--offline-policy", choices=("heuristic", "always_benign"), default="heuristic")
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_REPORT_DIR)
    ap.add_argument("--baseline-db", type=Path, default=BASELINE_DB)
    ap.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    args = ap.parse_args(argv)

    cases = load_cases(args.cases or list(DEFAULT_CASE_GLOBS), max_cases=args.max_cases)
    planned = len(cases) * args.repeats * LLM_CALLS_PER_TRIAGE
    print(f"[eval] {len(cases)} case(s) x {args.repeats} repeat(s) x {LLM_CALLS_PER_TRIAGE} calls = "
          f"{planned} planned LLM call(s)"
          + (" (scripted offline model, no API calls)" if args.mode == "offline"
             else " to the real OpenAI API (repair calls may add a few)"))
    if args.dry_run:
        return 0
    if args.mode == "live":
        _load_dotenv()
        if not os.environ.get("OPENAI_API_KEY", "").strip():
            print("[eval] --mode live needs OPENAI_API_KEY (in .env or the environment)", file=sys.stderr)
            return 2
    else:
        os.environ.setdefault("OPENAI_API_KEY", "sk-offline-not-used")

    workdir = Path(tempfile.mkdtemp(prefix="aegis-eval-"))
    before = soc_db_snapshot()
    redirect_ticket_db(workdir)
    from agents.triage import lolbas, soc_triage_agent
    from agents.triage.soc_triage_agent import OpenAILLMConfig

    ds, reason = lolbas.load_lolbas_dataset()
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    run = runner or make_runner(args.mode, args.baseline_db, args.offline_policy)
    try:
        result = evaluate(cases, args.repeats, run, workdir, parse=parse)
    finally:
        after = soc_db_snapshot()
    untouched = before == after
    m = result["metrics"]
    exit_code = 1 if (m["must_not_violation_count"] or m["canaries"]["failures"] or not untouched) else 0
    report = {
        "meta": {
            "mode": args.mode, "offline_policy": args.offline_policy if args.mode == "offline" else None,
            "started_at": started, "repeats": args.repeats, "case_globs": args.cases or list(DEFAULT_CASE_GLOBS),
            "planned_llm_calls": planned,
            "model": OpenAILLMConfig().model if args.mode == "live" else "scripted-offline",
            "triage_prompt_version": soc_triage_agent.TRIAGE_PROMPT_VERSION,
            "baseline_db": str(args.baseline_db), "ticket_db": str(soc_triage_agent._TICKET_DB),
            "lolbas_source": ds.source if ds else f"MISSING ({reason})",
            "soc_db_untouched": untouched, "soc_db_before": before, "soc_db_after": after,
        },
        **result, "exit_code": exit_code,
    }
    jpath, mpath = write_report(report, args.out_dir)
    print(f"[eval] acceptable-hit rate {m['acceptable_hit_rate']} | must_not violations "
          f"{m['must_not_violation_count']} | consistency {m['consistency_rate']} | needs_info rate "
          f"{m['needs_info_rate']} | canary failures {m['canaries']['failures'] or 'none'} | "
          f"soc_db untouched {untouched}")
    print(f"[eval] report: {jpath}\n[eval] report: {mpath}")
    shutil.rmtree(workdir, ignore_errors=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
