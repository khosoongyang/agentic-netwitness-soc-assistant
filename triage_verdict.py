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


def _sev_to_level(s: Any) -> int:
    return _SEV_LEVEL.get(str(s or "").strip().upper(), 0)


def _base_severity(incident: dict, triage_result: dict | None) -> tuple[int, str, str]:
    """(level, label, source) from triage classification, else incident field."""
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
    """asset_criticality.assess_incident → level 0-3 from the top asset rank."""
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


def _ioc_signal(incident: dict, triage_result: dict | None) -> dict | None:
    """ioc_correlation.correlate_iocs → level 0-3 from the best internal
    confidence across the incident's IOCs."""
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


def _ti_signal(ti_result: dict | None) -> dict | None:
    """External threat-intel enrichment — only when a pre-computed result is
    passed in (network-gated, so never triggered from here)."""
    if not ti_result:
        return {"name": "external threat intel", "level": 0,
                "label": "not run (opt-in — run 🌐 Enrich to include)",
                "detail": "", "absent": True}
    verdict_level = {"MALICIOUS": 3, "SUSPICIOUS": 2, "NO_FINDINGS": 0, "UNKNOWN": 0}
    best = 0
    best_label = "no external IOCs"
    for r in ti_result.get("results", []):
        base = str(r.get("verdict", "")).split(" ")[0].upper()
        lv = verdict_level.get(base, 0)
        if lv > best:
            best = lv
            best_label = base
    return {"name": "external threat intel", "level": best,
            "label": best_label.lower() if best else "no adverse findings",
            "detail": ""}


_ACTIONS = {
    "CRITICAL": "Escalate to Tier 2/3 now — declare incident",
    "HIGH": "Priority investigation (Tier 1)",
    "MEDIUM": "Standard investigation queue",
    "LOW": "Monitor / low-priority queue",
}


def aggregate_verdict(incident: dict, triage_result: dict | None = None,
                      ti_result: dict | None = None) -> dict:
    """Roll the triage-side skill signals into one prioritized verdict.
    Deterministic, instant (no network of its own), never raises."""
    if os.environ.get("NW_DISABLE_TRIAGE_VERDICT"):
        return {"available": False, "reason": "disabled via NW_DISABLE_TRIAGE_VERDICT"}

    base_level, base_label, base_src = _base_severity(incident, triage_result)
    signals: list[dict] = [{"name": "base severity", "level": base_level,
                            "label": base_label, "detail": base_src}]

    for sig in (_asset_signal(incident, triage_result),
                _ioc_signal(incident, triage_result),
                _ti_signal(ti_result)):
        if sig is not None:
            signals.append(sig)

    # scored signals = those that actually carry a risk level (exclude errors/absent)
    scored = [s for s in signals if not s.get("error") and not s.get("absent")]
    levels = [s["level"] for s in scored]
    max_level = max(levels) if levels else 0
    count3 = sum(1 for lv in levels if lv >= 3)
    count_ge2 = sum(1 for lv in levels if lv >= 2)

    # deterministic banding: a top-tier signal escalates; corroboration (≥2 strong
    # signals, or the incident itself critical) is required for CRITICAL.
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
    """Plain-text headline block for the Map panel."""
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
            note = "  ⚠"
        elif s.get("absent"):
            note = "  (not included)"
        lines.append(f"  [{bar}] {s['name']}: {s['label']}{detail}{note}")
    top = ", ".join(f"{s['name']} ({s['label']})" for s in v["rationale"]
                    if s["level"] > 0)
    if top:
        lines.append("  drivers: " + top)
    return "\n".join(lines)
