# ==============================================================================
# [FYP-FILE] triage_verdict.py
# Important dependencies: __future__, os, typing.
# Key evaluator search terms: _sev_to_level, _base_severity, _asset_signal, _ioc_signal, _investigation_signal, _ti_signal, [FYP-FUNCTION].
# ------------------------------------------------------------------------------
# File: triage_verdict.py (repo root)
# Purpose: Deterministic, rule-based capstone that rolls up every triage-side
#   skill's individual signal (base severity, asset criticality, internal IOC
#   correlation, external threat intel, investigation severity) into ONE
#   prioritized incident verdict, with every contributing signal kept visible
#   underneath as transparent evidence. Decision SUPPORT only — it shows every
#   input but never overwrites the triage agent's own classification.
# Main functionalities:
#   - aggregate_verdict(): [FYP-PROCESS] Unified Triage Verdict Aggregation /
#     Severity Banding — combines up to five optional signal collectors into
#     a single CRITICAL/HIGH/MEDIUM/LOW band + priority 1-5 + recommended
#     action. 100% deterministic, no LLM, no network of its own.
#   - _base_severity / _asset_signal / _ioc_signal / _ti_signal /
#     _investigation_signal: individual [FYP-FUNCTION] signal collectors,
#     each independently optional and fault-tolerant — a missing or broken
#     skill degrades that one signal to "unavailable", never a crash.
#   - format_verdict(): plain-text rendering of a verdict for the Map panel.
# Inputs: incident (dict), plus optional already-persisted stage outputs —
#   triage_result, ti_result, investigation_result, ioc_correlation_result.
#   Never re-runs a stage itself; a signal is simply omitted if its result
#   wasn't passed in.
# Outputs: aggregate_verdict() -> {available, level, priority, action,
#   signals, rationale, missing, stats}.
# Workflow position: capstone sitting ABOVE the triage-side skills
#   (asset_criticality.py, ioc_correlation.py, threat_intel.py). Consumed by
#   the Map/Overview panel and reused by final_verdict.py as the triage-time
#   baseline it refines with investigation-side substantiation.
# Called by [FYP-USED-BY]: case_view.py (`from triage_verdict import
#   aggregate_verdict`, Overview builder), app.py (`_build_case_findings`
#   Key Findings builder and the Map panel's Unified Verdict card — both
#   confirmed via grep), eval_harness.py (`_c_verdict` regression check),
#   skills_sidecar.py (`_collect_verdict`, feeds the reporting agent's
#   Automated Analytical Intelligence section), final_verdict.py
#   (`_triage_base`, as the pre-investigation baseline it escalates/holds).
# Calls [FYP-CALLS]: asset_criticality.assess_incident(), ioc_correlation.
#   correlate_iocs() (only when the caller doesn't already supply a
#   persisted ioc_correlation_result) — both imported inside a try/except so
#   this module still degrades gracefully if either skill file is missing.
# Kill switch: NW_DISABLE_TRIAGE_VERDICT=1 env var short-circuits straight to
#   {"available": False, "reason": "disabled via NW_DISABLE_TRIAGE_VERDICT"}.
# Key evaluator search terms [FYP-EVALUATOR]: "Unified Triage Verdict
#   Aggregation" / "Severity Banding" (aggregate_verdict's band/priority
#   if/elif ladder), "Signal Collector" (the five _*_signal helper
#   functions), "True-Positive-style corroboration rule" (CRITICAL requires
#   ≥2 strong signals or a critical base incident, not just one high signal).
# ==============================================================================
"""
triage_verdict.py — unified triage verdict aggregator (roadmap #1, standalone).

A CAPSTONE that sits ON TOP of the existing triage-side skills. It does NOT move,
merge, or edit any of them — each skill stays in its own standalone file. This
module *imports and calls* them, reads their individual outputs for one incident,
and rolls them into a SINGLE prioritized incident risk verdict, with every
contributing signal shown underneath as transparent evidence.

Signals aggregated (each optional — a missing/broken skill degrades to "signal
unavailable", never a crash):
  * base severity        — from the triage result's classification, else the
                           incident's own priority/severity field.
  * asset criticality    — asset_criticality.assess_incident (highest asset tier).
  * internal IOC corr.   — ioc_correlation.correlate_iocs (best internal
                           frequency/severity/case confidence).
  * external threat intel— threat_intel enrichment IF a pre-computed result is
                           passed in (it hits the network, so it is opt-in and
                           never triggered from here); otherwise noted as not-run.

The verdict is a deterministic function of those signals — transparent, no LLM,
no network of its own. It is decision SUPPORT (it shows every input); it does not
overwrite the triage agent's classification, and it makes NO edits to
soc_triage_agent/ or to any skill file (the standalone rule).

  CRITICAL / HIGH / MEDIUM / LOW  +  priority 1-5  +  recommended action.

Kill switch: NW_DISABLE_TRIAGE_VERDICT=1 disables it.

Usage:
    v = aggregate_verdict(incident, triage_result)
    print(format_verdict(v))
"""

from __future__ import annotations

import os
from typing import Any

# base-severity string -> level 0-3
_SEV_LEVEL = {
    "CRITICAL": 3, "CRIT": 3,
    "HIGH": 2,
    "MEDIUM": 1, "MED": 1, "MODERATE": 1,
    "LOW": 0, "INFO": 0, "INFORMATIONAL": 0, "": 0,
}
_LEVEL_BAND = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}


# =============================================================================
# [FYP-SECTION] TRIAGE EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================


def _sev_to_level(s: Any) -> int:
    """[FYP-FUNCTION] Map a free-text severity/classification string onto the
    0-3 numeric level scale (via _SEV_LEVEL) that every signal collector in
    this file scores on. Unrecognised/blank input defaults to 0 (LOW) rather
    than raising, so a malformed upstream field degrades this one signal
    instead of crashing aggregate_verdict()."""
    return _SEV_LEVEL.get(str(s or "").strip().upper(), 0)


def _base_severity(incident: dict, triage_result: dict | None) -> tuple[int, str, str]:
    """[FYP-FUNCTION] Base Severity Signal.
    (level, label, source) from the triage agent's own classification when a
    persisted triage_result is supplied, else falls back to the raw
    incident's own priority/severity field, else "UNRATED"/level 0. This is
    always signals[0] in aggregate_verdict() — the anchor signal every other
    signal corroborates or escalates against."""
    tr = triage_result or {}
    cls = ((tr.get("ticket") or {}).get("classification")
           or (tr.get("metakeys_payload") or {}).get("classification"))
    if cls:
        return _sev_to_level(cls), str(cls).upper(), "triage classification"
    raw = incident.get("priority") or incident.get("severity")
    if raw:
        return _sev_to_level(raw), str(raw).upper(), "incident severity"
    return 0, "UNRATED", "no severity on incident"


def _asset_signal(incident: dict, triage_result: dict | None) -> dict | None:
    """[FYP-FUNCTION] Asset Criticality Signal [FYP-CALLS]
    asset_criticality.assess_incident() -> level 0-3 mapped from the
    incident's highest-ranked affected asset tier (4=crit .. 0=none rank ->
    3=CRITICAL .. 0=LOW level). Returns None (signal simply omitted) if the
    asset_criticality module can't be imported; returns an {"error": True}
    stub (excluded from scoring but still shown) if assess_incident() itself
    raises — either way aggregate_verdict() never crashes on this signal."""
    try:
        from asset_criticality import assess_incident
    except Exception:
        return None
    cls = ((triage_result or {}).get("ticket") or {}).get("classification")
    try:
        a = assess_incident(incident, triage_classification=cls)
    except Exception as exc:
        return {"name": "asset criticality", "level": 0,
                "label": f"unavailable ({exc})", "detail": "", "error": True}
    rank = int(a.get("highest_rank", 0))          # 4 crit,3 high,2 med,1 low,0 none
    level = {4: 3, 3: 2, 2: 1, 1: 0, 0: 0}.get(rank, 0)
    tier = a.get("highest_tier", "unclassified")
    detail = a.get("escalation") or a.get("response_urgency") or ""
    return {"name": "asset criticality", "level": level,
            "label": f"{tier} asset", "detail": detail}


def _ioc_signal(incident: dict, triage_result: dict | None,
                ioc_correlation_result: dict | None = None) -> dict | None:
    """[FYP-FUNCTION] Internal IOC Correlation Signal [FYP-CALLS]
    ioc_correlation.correlate_iocs(). Best internal confidence across the incident's IOCs. When
    ioc_correlation_result is supplied (the persisted, run-scoped snapshot
    computed once by soc_workflow.run_until_triage_approval — see
    workflow_state_store.save_ioc_correlation_result), it is used AS-IS
    instead of calling ioc_correlation.correlate_iocs() live — a live corpus
    scan on every call would let this signal (and the Unified Verdict
    downstream) change with no workflow stage ever running, purely because
    the corpus DB changed underneath an already-completed run. Live
    calling remains the fallback ONLY for callers that don't have a
    persisted snapshot to pass (e.g. ad hoc/manual use of this module)."""
    if ioc_correlation_result is not None:
        corr = ioc_correlation_result
    else:
        try:
            from ioc_correlation import correlate_iocs
        except Exception:
            return None
        try:
            corr = correlate_iocs(incident, triage_result)
        except Exception as exc:
            return {"name": "internal IOC correlation", "level": 0,
                    "label": f"unavailable ({exc})", "detail": "", "error": True}
    if not corr.get("available"):
        return {"name": "internal IOC correlation", "level": 0,
                "label": "unavailable", "detail": corr.get("reason", ""), "error": True}
    conf_level = {"high": 3, "medium": 2, "low": 1, "none": 0}
    best = 0
    best_label = "none"
    open_cases = 0
    for r in corr.get("results", []):
        lv = conf_level.get(r.get("confidence"), 0)
        if lv > best:
            best = lv
            best_label = r.get("confidence")
        open_cases += len(r.get("open_cases") or [])
    if not corr.get("results"):
        return {"name": "internal IOC correlation", "level": 0,
                "label": "no IOCs to correlate", "detail": ""}
    detail = (f"in {open_cases} active case(s)" if open_cases else
              f"{len(corr['results'])} IOC(s) correlated")
    return {"name": "internal IOC correlation", "level": best,
            "label": f"{best_label} internal confidence", "detail": detail}


def _investigation_signal(investigation_result: dict | None) -> dict | None:
    """[FYP-FUNCTION] Investigation Severity Signal.
    Investigation Agent's own structured severity — the ONLY structured
    field its persisted output carries (investigation_result_json.severity,
    a plain "Low"/"Medium"/"High"/"Critical" string). NEVER derived from
    narrative_report/summary prose. Callers must only pass a real,
    completed investigation_result (Awaiting Approval or Approved) —
    absent/None simply omits this signal, exactly like the external
    threat-intel signal when TI hasn't run."""
    if not investigation_result:
        return None
    sev = investigation_result.get("severity")
    if not sev:
        return None
    return {"name": "investigation severity", "level": _sev_to_level(sev),
            "label": str(sev).upper(), "detail": "investigation agent"}


def _ti_signal(ti_result: dict | None) -> dict | None:
    """[FYP-FUNCTION] External Threat Intel Signal.
    External threat-intel enrichment (VirusTotal/AbuseIPDB/AlienVault OTX
    via threat_intel.py) — only when a pre-computed result is passed in
    (network-gated, so never triggered from here). Threat Intelligence
    Enrichment is a mandatory stage in this workflow, so an absent result
    means "not completed yet," never "skipped by choice." The risk level is
    case-level (one enrichment run judged all the case's IOCs together),
    never a per-IOC verdict."""
    if not ti_result:
        return {"name": "external threat intel", "level": 0,
                "label": "not yet available (Threat Intelligence Enrichment "
                         "has not completed for this run)",
                "detail": "", "absent": True}
    level_map = {"High": 3, "Medium": 2, "Low": 0}
    lvl = ti_result.get("enrichment_risk_level")
    reasons = ti_result.get("enrichment_risk_reasons") or []
    return {"name": "external threat intel", "level": level_map.get(lvl, 0),
            "label": str(lvl or "unknown").lower(), "detail": "; ".join(reasons[:2])}


_ACTIONS = {
    "CRITICAL": "Escalate to Tier 2/3 now — declare incident",
    "HIGH": "Priority investigation (Tier 1)",
    "MEDIUM": "Standard investigation queue",
    "LOW": "Monitor / low-priority queue",
}


def aggregate_verdict(incident: dict, triage_result: dict | None = None,
                      ti_result: dict | None = None,
                      investigation_result: dict | None = None,
                      ioc_correlation_result: dict | None = None) -> dict:
    """[FYP-FUNCTION] [FYP-PROCESS] Unified Triage Verdict Aggregation /
    Severity Banding — THE headline entry point of this file.

    Roll the triage-side skill signals into one prioritized verdict.
    Deterministic, instant (no network of its own), never raises — every
    signal collector below is individually fault-tolerant, so a broken or
    absent skill only removes that one signal rather than failing the whole
    verdict.

    Processing (in order):
      1. [FYP-CALLS] _base_severity() — anchor signal (triage classification,
         else raw incident priority/severity).
      2. [FYP-CALLS] _asset_signal(), _ioc_signal(), _ti_signal(),
         _investigation_signal() — each optional; a None return is simply
         skipped (not appended to `signals`).
      3. [FYP-DECISION] Severity Banding ladder: `scored` = every signal that
         isn't flagged error/absent; `max_level` = highest scored level (0-3);
         `count3` = how many signals hit level 3; `count_ge2` = how many hit
         level >= 2. The band is picked by a corroboration rule, not by
         max_level alone — a lone strong signal is HIGH, not CRITICAL:
           * CRITICAL (priority 1): max_level>=3 AND (>=2 signals at level 3,
             OR the base/triage severity itself is already level 3).
           * HIGH (priority 2): max_level>=3 (uncorroborated), OR >=2 signals
             at level>=2.
           * MEDIUM (priority 3): max_level==2 and none of the above.
           * LOW (priority 4 or 5): max_level<=1.
      4. `rationale` = the scored signals with level>0, sorted strongest
         first (or a "no elevated signals" placeholder). `missing` = the
         names of signals that errored or were never supplied.

    Callers should pass triage_result/ti_result/investigation_result
    whenever those stages have actually persisted a result (case_view.py's
    Overview builder always does) — calling this bare (incident only) is
    what caused the Overview's old "Base Severity" finding to silently fall
    back to the raw incident's own priority/severity field instead of ever
    reading the real, persisted triage classification.

    Returns {"available": False, "reason": ...} instead of a verdict when
    NW_DISABLE_TRIAGE_VERDICT is set — see the file header kill switch.

    [FYP-USED-BY]: case_view.py, app.py, eval_harness.py, skills_sidecar.py,
    final_verdict.py._triage_base() (see file header for full detail)."""
    if os.environ.get("NW_DISABLE_TRIAGE_VERDICT"):
        return {"available": False, "reason": "disabled via NW_DISABLE_TRIAGE_VERDICT"}

    base_level, base_label, base_src = _base_severity(incident, triage_result)
    signals: list[dict] = [{"name": "base severity", "level": base_level,
                            "label": base_label, "detail": base_src}]

    for sig in (_asset_signal(incident, triage_result),
                _ioc_signal(incident, triage_result, ioc_correlation_result),
                _ti_signal(ti_result),
                _investigation_signal(investigation_result)):
        if sig is not None:
            signals.append(sig)

    # scored signals = those that actually carry a risk level (exclude errors/absent)
    scored = [s for s in signals if not s.get("error") and not s.get("absent")]
    levels = [s["level"] for s in scored]
    max_level = max(levels) if levels else 0
    count3 = sum(1 for lv in levels if lv >= 3)
    count_ge2 = sum(1 for lv in levels if lv >= 2)

    # [FYP-DECISION] [FYP-PROCESS] Severity Banding ladder (see aggregate_verdict's
    # docstring step 3 for the full rule table): deterministic banding — a
    # top-tier signal escalates; corroboration (≥2 strong signals, or the
    # incident itself critical) is required for CRITICAL.
    if max_level >= 3 and (count3 >= 2 or base_level >= 3):
        band, priority = "CRITICAL", 1
    elif max_level >= 3 or count_ge2 >= 2:
        band, priority = "HIGH", 2
    elif max_level == 2:
        band, priority = "MEDIUM", 3
    elif max_level == 1:
        band, priority = "LOW", 4
    else:
        band, priority = "LOW", 5

    rationale = sorted(
        [s for s in scored if s["level"] > 0],
        key=lambda s: -s["level"]) or [{"name": "no elevated signals",
                                        "level": 0, "label": "", "detail": ""}]

    missing = [s["name"] for s in signals if s.get("error") or s.get("absent")]

    return {
        "available": True,
        "level": band, "priority": priority,
        "action": _ACTIONS[band],
        "signals": signals,
        "rationale": rationale,
        "missing": missing,
        "stats": {"scored_signals": len(scored), "max_level": max_level,
                  "corroborating_strong": count_ge2},
    }


def format_verdict(v: dict) -> str:
    """[FYP-FUNCTION] Plain-text headline block for the Map panel — renders
    an aggregate_verdict() dict (level/priority/action/signals/rationale)
    into a human-readable summary with a per-signal bar chart glyph."""
    if not v.get("available"):
        return "UNIFIED TRIAGE VERDICT unavailable: " + v.get("reason", "unknown")
    lines = [
        f"UNIFIED TRIAGE VERDICT: {v['level']} — {v['action']} "
        f"(priority {v['priority']}/5)",
        "  aggregated from the platform's triage-side skills — decision support, "
        "does not overwrite the triage classification:",
    ]
    for s in v["signals"]:
        bar = "●" * (s["level"] + 1) + "○" * (3 - s["level"])
        detail = f" — {s['detail']}" if s.get("detail") else ""
        note = ""
        if s.get("error"):
            note = ""
        elif s.get("absent"):
            note = "  (not included)"
        lines.append(f"  [{bar}] {s['name']}: {s['label']}{detail}{note}")
    top = ", ".join(f"{s['name']} ({s['label']})" for s in v["rationale"]
                    if s["level"] > 0)
    if top:
        lines.append("  drivers: " + top)
    return "\n".join(lines)
