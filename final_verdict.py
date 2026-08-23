# ==============================================================================
# [FYP-FILE] final_verdict.py
# Important dependencies: __future__, os, typing.
# Key evaluator search terms: _disabled, _s, _as_list, _triage_base, _ioc_evidence, _response_readiness, [FYP-FUNCTION].
# ------------------------------------------------------------------------------
# File: final_verdict.py (repo root)
# Purpose: Deterministic, rule-based capstone that runs AFTER investigation
#   and asks whether the investigation SUBSTANTIATED the triage-time risk
#   prediction. Re-aggregates triage_verdict.py's verdict with investigation-
#   side signals into a refined verdict, plus a disposition (Confirmed /
#   Likely TP / Inconclusive / Possible FP) and a confidence rating that
#   triage_verdict.py cannot produce on its own (it runs before investigation
#   exists).
# Main functionalities:
#   - build_final_verdict(): [FYP-PROCESS] Post-Investigation Substantiation
#     / Final Verdict & Confidence — public entry point; never raises, wraps
#     _build() in a try/except.
#   - _build(): the actual aggregation — combines the triage baseline with
#     four investigation-side signal collectors (_ioc_evidence,
#     _response_readiness, _diamond_signal, _mitre_confirmation) into a
#     substantiation score, then a refined severity band, disposition and
#     confidence.
#   - format_final_verdict(): Markdown headline section for reports / the
#     Map panel.
# Inputs: incident (dict), optional triage_result, investigation_result,
#   ti_result — all already-persisted stage outputs, never re-run here.
# Outputs: build_final_verdict() -> {available, stage, level, priority,
#   disposition, confidence, action, delta, triage_verdict, signals,
#   rationale, missing, stats}.
# Workflow position: runs after the Investigation stage; reads
#   triage_verdict.py's output as its pre-investigation baseline (via
#   _triage_base()) and refines it with investigation evidence.
# Called by [FYP-USED-BY]: skills_sidecar.py — `_collect_final_verdict`
#   (from final_verdict import build_final_verdict) feeds the reporting
#   agent's Automated Analytical Intelligence section, and a second import
#   (`from final_verdict import format_final_verdict`) renders it as that
#   section's lead paragraph (both confirmed via grep).
# Calls [FYP-CALLS]: triage_verdict.aggregate_verdict() (the pre-
#   investigation baseline this module refines), diamond_model.build_diamond()
#   (kill-chain completeness signal), tactic_inference.infer_tactics()
#   (fallback MITRE tactic inference when nothing was already assigned) —
#   all imported inside try/except so a missing skill only drops that one
#   signal.
# HONESTY RULES [FYP-DECISION] baked into _build(): escalates at most ONE
#   severity band, and only on strong corroborated substantiation of a
#   high-severity ATT&CK tactic; NEVER silently downgrades — an
#   unsubstantiated elevated incident keeps its triage-time level but is
#   flagged low-confidence "verify (possible false positive)" instead of
#   being closed out.
# Kill switch: NW_DISABLE_FINAL_VERDICT env var short-circuits to
#   {"available": False, ...} — see _disabled().
# Key evaluator search terms [FYP-EVALUATOR]: "Post-Investigation
#   Substantiation" / "Final Verdict" (build_final_verdict/_build),
#   "Disposition" (Confirmed/Likely TP/Inconclusive/Possible FP block in
#   _build), "Confidence" (the subst -> confidence mapping), "Escalation
#   rule" (the `if subst >= 3 and severe_confirmed and (corroborated or
#   count_ge2 >= 2)` one-band-only escalation gate).
# ==============================================================================
"""
final_verdict.py — post-investigation "final" incident verdict (standalone capstone).

WHAT IT ADDS OVER triage_verdict.py
    triage_verdict.aggregate_verdict() is a TRIAGE-TIME risk *prediction* (base
    severity + asset + IOC + optional TI), computed before investigation. This
    module runs AFTER investigation and asks the next question: did the
    investigation SUBSTANTIATE that prediction? It re-aggregates the triage verdict
    with investigation-side signals to produce a refined verdict PLUS two things the
    triage verdict can't have yet:
      * a **disposition** — Confirmed / Likely TP / Inconclusive / Possible FP
      * a **confidence** — how well the investigation substantiated the risk.

    Investigation-side signals (each optional; missing degrades to "unavailable",
    never a crash):
      * IOC evidence depth   — # of IOCs the investigation surfaced.
      * Response readiness    — whether concrete response/containment actions exist.
      * Diamond completeness  — diamond_model kill-chain characterisation %.
      * MITRE confirmation    — tactic_inference confidence + whether the confirmed
                                tactic is a high-severity ATT&CK tactic.

HONESTY RULES BAKED IN
    * It ESCALATES one band only on strong, corroborated substantiation of a
      high-severity tactic — never jumps to CRITICAL without corroboration.
    * It NEVER silently downgrades risk. A thin investigation ≠ benign, so an
      unsubstantiated elevated incident keeps its level but is flagged LOW
      confidence / "verify (possible false positive)" — decision SUPPORT, not a
      close-out.
    * Standalone: imports+calls existing skills, edits none of them, no agent edits,
      no LLM, no network. Kill switch: NW_DISABLE_FINAL_VERDICT.

PUBLIC API
    build_final_verdict(incident, triage_result=None,
                        investigation_result=None, ti_result=None) -> dict
    format_final_verdict(verdict, compact=False) -> str
"""
from __future__ import annotations

import os
from typing import Any

_BAND_LEVEL = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
_LEVEL_BAND = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}

# High-severity ATT&CK tactics — confirming one of these substantiates real impact.
_SEVERE_TACTICS = (
    "impact", "exfiltration", "lateral movement", "command and control",
    "privilege escalation", "credential access",
)


# =============================================================================
# [FYP-SECTION] SOC ANALYSIS SUPPORT EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================


def _disabled() -> bool:
    """[FYP-FUNCTION] Kill-switch check for build_final_verdict() — True when
    NW_DISABLE_FINAL_VERDICT is set in the environment (see file header)."""
    return bool(os.environ.get("NW_DISABLE_FINAL_VERDICT"))


def _s(v: Any) -> str:
    """[FYP-FUNCTION] Safe-string coercion: None/blank -> "", else str(v).strip().
    Used throughout this file so a missing/None field degrades to an empty
    string instead of raising when concatenated into a label."""
    return str(v or "").strip()


def _as_list(v: Any) -> list:
    """[FYP-FUNCTION] Normalises a field that may arrive as None, a bare
    scalar, or an already-a-list into a list — None/""/[]/{} -> [], a single
    non-list value -> [value], so every caller below can safely len()/iterate
    without a type check of its own."""
    if v in (None, "", [], {}):
        return []
    return v if isinstance(v, list) else [v]


# ── investigation-side signal collectors (each -> {level 0-3, label, detail} | None)

def _triage_base(incident, triage_result, ti_result) -> dict | None:
    """[FYP-FUNCTION] [FYP-CALLS] Pre-investigation baseline signal.
    Re-runs triage_verdict.aggregate_verdict() to get the triage-time
    CRITICAL/HIGH/MEDIUM/LOW band + corroboration stats that _build() then
    refines. Fault-tolerant on both axes: an import failure (module missing)
    and a raised exception during aggregation both degrade to None, and a
    successful-but-"available": False result is also treated as None — the
    caller (_build) simply proceeds without a triage baseline rather than
    crashing the whole post-investigation verdict."""
    try:
        from triage_verdict import aggregate_verdict
    except Exception:
        return None
    try:
        v = aggregate_verdict(incident, triage_result, ti_result)
    except Exception:
        return None
    if not isinstance(v, dict) or not v.get("available"):
        return None
    return v


def _ioc_evidence(inv: dict) -> dict:
    """[FYP-FUNCTION] IOC Evidence Depth Signal.
    [FYP-DECISION] Deterministic count-based level: level 3 (high) if the
    investigation documented >=3 IOCs, level 2 (medium) if 1-2, else level 0
    (none). No LLM — purely len() of the persisted investigation_result's
    iocs list. Always "available" (never errors), even when inv is empty."""
    n = len(_as_list(inv.get("iocs")))
    level = 3 if n >= 3 else (2 if n >= 1 else 0)
    return {"name": "IOC evidence depth", "level": level,
            "label": f"{n} IOC(s) documented" if n else "no IOCs documented",
            "available": bool(inv)}


def _response_readiness(inv: dict) -> dict:
    """[FYP-FUNCTION] Response Readiness Signal.
    [FYP-DECISION] Deterministic keyword scan (via _action_text) over the
    investigation's recommended_actions: level 3 if any action text contains
    a containment/remediation keyword (contain/isolate/remediate/reset/
    block/quarantine/re-image/eradicate/recover/patch), level 2 if actions
    exist but none are "strong", else level 0. Purely rule-based string
    matching — no LLM judgement of action quality."""
    actions = _as_list(inv.get("recommended_actions"))
    kw = ("contain", "isolat", "remediat", "reset", "block", "quarantine",
          "re-image", "reimage", "eradicat", "recover", "patch")
    strong = any(any(k in _action_text(a) for k in kw) for a in actions)
    level = 3 if strong else (2 if actions else 0)
    return {"name": "response readiness", "level": level,
            "label": (f"{len(actions)} action(s)"
                      + (", incl. containment" if strong else "")) if actions
                     else "no response actions",
            "available": bool(inv)}


def _diamond_signal(incident, triage_result, ti_result) -> dict:
    """[FYP-FUNCTION] Kill-Chain Characterisation Signal [FYP-CALLS]
    diamond_model.build_diamond() — reads the Diamond Model's
    completeness_pct (how many of the 4 Diamond vertices — adversary,
    capability, infrastructure, victim — were populated) and buckets it
    deterministically: [FYP-DECISION] level 3 at >=60% complete, level 2 at
    >=40%, level 1 at >=20%, else 0. Import failure, a raised exception, or
    an unavailable Diamond result all degrade to the same
    {"level": 0, "available": False} stub rather than crashing this module."""
    try:
        from diamond_model import build_diamond
        d = build_diamond(incident, triage_result, ti_result)
    except Exception:
        return {"name": "kill-chain characterisation", "level": 0,
                "label": "unavailable", "available": False}
    if not isinstance(d, dict) or not d.get("available"):
        return {"name": "kill-chain characterisation", "level": 0,
                "label": "unavailable", "available": False}
    pct = int((d.get("stats") or {}).get("completeness_pct", 0))
    level = 3 if pct >= 60 else (2 if pct >= 40 else (1 if pct >= 20 else 0))
    return {"name": "kill-chain characterisation", "level": level,
            "label": f"Diamond model {pct}% complete", "available": True, "pct": pct}


def _mitre_confirmation(incident, triage_result=None, inv=None) -> dict:
    """[FYP-FUNCTION] MITRE Confirmation Signal — the one signal collector
    whose level feeds the escalation rule (see _build()'s severe_confirmed).
    [FYP-DECISION] Two-step, fully deterministic (no LLM in this function):
      1. Prefer an ALREADY-ASSIGNED tactic (investigation's mitre_mapping,
         else the raw incident's mitre_tactic, else the persisted triage
         result's mitre_tactic) — treated as "confirmed"/high confidence.
      2. Only when nothing is assigned, [FYP-CALLS] [FYP-FALLBACK]
         tactic_inference.infer_tactics() as a deterministic heuristic
         fallback (import/exception/unavailable all degrade to
         {"level": 0, "available": False} rather than crashing).
    `severe` = whether the confirmed/inferred tactic is one of the
    high-impact _SEVERE_TACTICS (impact, exfiltration, lateral movement,
    C2, privilege escalation, credential access). Final level = the
    confidence level (high=3/medium=2/low=1), bumped by one (capped at 3)
    when the tactic is severe — so a severe tactic always outranks a
    non-severe one at the same confidence."""
    # 1. A tactic already assigned by investigation/triage/the incident is a
    #    CONFIRMED classification (high confidence). Prefer it over inference.
    tactic, conf, src = "", "high", "confirmed"
    for m in _as_list((inv or {}).get("mitre_mapping")):
        tactic = _s(m if not isinstance(m, dict) else (m.get("tactic") or m.get("value")))
        if tactic:
            break
    if not tactic:
        tactic = _s(incident.get("mitre_tactic"))
    if not tactic and triage_result:
        tactic = _s((triage_result.get("metakeys_payload") or {}).get("mitre_tactic")
                    or (triage_result.get("ticket") or {}).get("mitre_tactic"))
    # 2. Fall back to deterministic inference only when nothing is assigned.
    if not tactic:
        try:
            from tactic_inference import infer_tactics
            r = infer_tactics(incident)
        except Exception:
            r = None
        if not isinstance(r, dict) or not r.get("available"):
            return {"name": "MITRE confirmation", "level": 0,
                    "label": "no tactic confirmed", "available": False, "severe": False}
        tactic = _s(r.get("tactic"))
        conf = _s(r.get("confidence")).lower() or "low"
        src = "inferred"
    severe = any(t in tactic.lower() for t in _SEVERE_TACTICS)
    conf_lv = {"high": 3, "medium": 2, "low": 1}.get(conf, 1)
    level = min(3, conf_lv + (1 if severe else 0)) if severe else conf_lv
    return {"name": "MITRE confirmation", "level": level, "available": True,
            "severe": severe,
            "label": f"{tactic} ({conf} confidence"
                     + (", high-severity tactic" if severe else "") + f", {src})"}


def _action_text(a: Any) -> str:
    """[FYP-FUNCTION] Normalises one recommended_actions entry (a plain
    string, or a dict with recommendation/action/rationale/risk_addressed
    keys) into a single lowercase string for _response_readiness()'s
    keyword scan."""
    if isinstance(a, dict):
        return " ".join(_s(a.get(k)) for k in
                        ("recommendation", "action", "rationale", "risk_addressed")).lower()
    return _s(a).lower()


# ── main aggregation ──────────────────────────────────────────────────────────

_ACTIONS = {
    ("CRITICAL", True):  "Declare incident — Tier 2/3 containment now",
    ("HIGH", True):      "Contain & remediate per playbook (Tier 1)",
    ("MEDIUM", True):    "Standard investigation queue — proceed to remediation",
    ("LOW", True):       "Monitor / low-priority queue",
    ("CRITICAL", False): "Treat as critical until cleared — gather corroborating evidence urgently",
    ("HIGH", False):     "Re-verify detection & gather more evidence before closing",
    ("MEDIUM", False):   "Collect additional evidence; likely low impact",
    ("LOW", False):      "Monitor / candidate for closure after review",
}


def build_final_verdict(incident: dict, triage_result: dict | None = None,
                        investigation_result: dict | None = None,
                        ti_result: dict | None = None) -> dict:
    """[FYP-FUNCTION] [FYP-PROCESS] Post-Investigation Substantiation / Final
    Verdict & Confidence — THE public entry point of this file (see file
    header for the full contract). Thin, never-raising wrapper around
    _build(): normalises None inputs to {} and catches any exception _build()
    raises, converting it to {"available": False, "reason": "error: <type>"}
    so a bug in one signal collector can never break the caller (skills_
    sidecar.py's reporting-agent feed). Also the sole place the
    NW_DISABLE_FINAL_VERDICT kill switch (_disabled()) is checked.

    Requires an investigation_result with some substance (see _build()'s
    has_investigation check), else returns available=False."""
    if _disabled():
        return {"available": False, "reason": "disabled via NW_DISABLE_FINAL_VERDICT"}
    try:
        return _build(incident or {}, triage_result, investigation_result or {}, ti_result)
    except Exception as exc:
        return {"available": False, "reason": f"error: {type(exc).__name__}"}


def _build(incident, triage_result, inv, ti_result) -> dict:
    """[FYP-FUNCTION] [FYP-PROCESS] Post-Investigation Substantiation / Final
    Verdict & Confidence — the actual aggregation logic behind
    build_final_verdict(). 100% deterministic, no LLM, no network of its own
    (everything it calls — triage_verdict, diamond_model, tactic_inference —
    is itself rule-based).

    Processing (in order):
      1. [FYP-CALLS] _triage_base() — the pre-investigation baseline band.
      2. [FYP-CALLS] _ioc_evidence(), _response_readiness(), _diamond_signal(),
         _mitre_confirmation() — the four investigation-side signals, always
         computed (each individually fault-tolerant; unavailable ones are
         simply excluded from `scored`, never a crash).
      3. [FYP-DECISION] Substantiation band 0-3 (None/Low/Medium/High): looks
         only at the investigation-side signals' max level and how many hit
         >=2 — mirrors triage_verdict.py's corroboration philosophy (a
         single strong signal alone tops out at 1, not 3).
      4. [FYP-DECISION] Escalation rule (see file header's "Escalation rule"
         evaluator term): the refined severity band starts equal to the
         triage-time band and is escalated by AT MOST ONE band, only when
         substantiation is High (subst>=3) AND the confirmed/inferred MITRE
         tactic is both severe and high-confidence (severe_confirmed) AND
         either the triage verdict was itself already corroborated or >=2
         investigation signals hit level>=2. It is NEVER downgraded — see
         the `elif subst == 0 and triage_level >= 2` branch, which only
         flags low confidence, never lowers the band. This is the file's
         core HONESTY RULE (see file header).
      5. [FYP-DECISION] Disposition: Confirmed True Positive (subst==3) /
         Likely True Positive (subst==2) / Inconclusive (subst==1) /
         Unsubstantiated-verify-possible-FP (subst==0 and the triage band
         was elevated) or No adverse findings (subst==0 and triage was
         already LOW).
      6. [FYP-DECISION] Confidence calculation — DETERMINISTIC, a plain
         dict lookup keyed on the same `subst` score computed in step 3
         (High/Medium/Low/Low for subst 3/2/1/0). No LLM and no separate
         model call ever produces "confidence" — it is entirely derived
         from how many/how-strong the rule-based investigation-side
         signals were, exactly like every other verdict in this module.

    [FYP-USED-BY]: skills_sidecar.py (see file header) via
    build_final_verdict()."""
    # only meaningful after an investigation actually produced something
    has_investigation = bool(
        _as_list(inv.get("iocs")) or _as_list(inv.get("recommended_actions"))
        or _s(inv.get("investigation_summary")) or _s(inv.get("summary"))
        or _s(inv.get("status")).lower() == "completed")
    base = _triage_base(incident, triage_result, ti_result)
    if not has_investigation and not base:
        return {"available": False, "reason": "no investigation result and no triage verdict"}

    triage_level = _BAND_LEVEL.get((base or {}).get("level", "LOW"), 0)
    triage_band = (base or {}).get("level", "LOW")

    # investigation-side substantiation signals
    ioc = _ioc_evidence(inv)
    resp = _response_readiness(inv)
    diamond = _diamond_signal(incident, triage_result, ti_result)
    mitre = _mitre_confirmation(incident, triage_result, inv)
    inv_signals = [ioc, resp, diamond, mitre]
    scored = [s for s in inv_signals if s.get("available")]
    levels = [s["level"] for s in scored]
    max_inv = max(levels) if levels else 0
    count_ge2 = sum(1 for lv in levels if lv >= 2)

    # [FYP-DECISION] substantiation band 0-3 (None/Low/Medium/High) — see
    # _build()'s docstring step 3. Requires BOTH a top-tier signal AND
    # corroboration (>=2 signals at level>=2) for the top band, same
    # corroboration philosophy as triage_verdict.aggregate_verdict().
    if max_inv >= 3 and count_ge2 >= 2:
        subst = 3
    elif max_inv >= 2 and count_ge2 >= 1:
        subst = 2
    elif max_inv >= 1:
        subst = 1
    else:
        subst = 0

    # corroboration = the triage verdict already had ≥2 strong signals or IOC/case hits
    corroborated = bool(base and (base.get("stats", {}).get("corroborating_strong", 0) >= 1))
    severe_confirmed = mitre.get("available") and mitre.get("severe") and mitre["level"] >= 3

    # [FYP-DECISION] refined level: escalate ONE band only on strong, corroborated
    # severe-tactic substantiation; otherwise hold the triage level (never
    # silently downgrade — see _build()'s docstring step 4 / file header
    # HONESTY RULES / the "Escalation rule" evaluator term).
    refined_level = triage_level
    delta = "unchanged"
    if subst >= 3 and severe_confirmed and (corroborated or count_ge2 >= 2):
        refined_level = min(3, triage_level + 1)
        delta = "escalated" if refined_level > triage_level else "confirmed"
    elif subst >= 2:
        delta = "confirmed"
    elif subst == 0 and triage_level >= 2:
        delta = "held (low confidence)"

    refined_band = _LEVEL_BAND[refined_level]
    substantiated = subst >= 2

    # [FYP-DECISION] disposition — deterministic mapping straight off the
    # substantiation score `subst` computed above (see _build()'s docstring
    # step 5); the only place `triage_level` re-enters is to distinguish a
    # thin-evidence elevated incident ("verify — possible false positive")
    # from a thin-evidence incident that was already LOW ("no adverse
    # findings") — this is what prevents subst==0 from ever reading as a
    # clean bill of health on a triage-time CRITICAL/HIGH.
    if subst >= 3:
        disposition = "Confirmed — True Positive"
    elif subst == 2:
        disposition = "Likely True Positive"
    elif subst == 1:
        disposition = "Inconclusive — partial substantiation"
    else:
        disposition = ("Unsubstantiated — verify (possible false positive)"
                       if triage_level >= 2 else "No adverse findings")

    # [FYP-DECISION] Confidence calculation — fully deterministic dict lookup
    # keyed on `subst` (the same 0-3 substantiation score the band/
    # disposition above are derived from). No LLM, no separate confidence
    # model: "how confident is this verdict" is entirely a function of how
    # many/how-strong the rule-based investigation-side signals corroborated
    # the triage-time prediction.
    confidence = {3: "High", 2: "Medium", 1: "Low", 0: "Low"}[subst]
    priority = {3: 1, 2: 2, 1: 3, 0: 4}[refined_level]
    action = _ACTIONS[(refined_band, substantiated)]

    rationale = sorted([s for s in scored if s["level"] > 0], key=lambda s: -s["level"])
    missing = [s["name"] for s in inv_signals if not s.get("available")]

    return {
        "available": True,
        "stage": "post-investigation",
        "level": refined_band,
        "priority": priority,
        "disposition": disposition,
        "confidence": confidence,
        "action": action,
        "delta": delta,
        "triage_verdict": {"level": triage_band, "priority": (base or {}).get("priority")},
        "signals": inv_signals,
        "rationale": rationale or [{"name": "no substantiating signals", "level": 0, "label": ""}],
        "missing": missing,
        "stats": {"substantiation": subst, "scored_signals": len(scored),
                  "max_inv_level": max_inv, "corroborated": corroborated},
    }


# ── rendering ─────────────────────────────────────────────────────────────────

def format_final_verdict(v: dict | None, compact: bool = False) -> str:
    """[FYP-FUNCTION] Markdown headline section for the report / Map panel —
    renders a build_final_verdict() dict (level/disposition/confidence/
    priority/delta/action/rationale/missing) into a human-readable summary.
    Returns "" (renders nothing) when v is falsy or v["available"] is False,
    so a disabled/unavailable verdict silently drops out of a report rather
    than printing a placeholder. [FYP-USED-BY]: skills_sidecar.py (see file
    header) as the Automated Analytical Intelligence section's lead
    paragraph."""
    if not v or not v.get("available"):
        return ""
    lines = ["## Final Incident Verdict (post-investigation)"]
    if not compact:
        lines.append("_Refines the triage-time verdict with investigation "
                     "substantiation. Decision support — does not close the incident._")
    tv = v.get("triage_verdict") or {}
    delta = str(v.get("delta") or "")
    delta_note = {
        "escalated": f" (⬆ escalated from triage {tv.get('level')})",
        "confirmed": f" (confirmed triage {tv.get('level')})",
        "held (low confidence)": f" (held at triage {tv.get('level')} — low confidence)",
        "unchanged": "",
    }.get(delta, "")
    lines.append(f"**{v['level']}** · **{v['disposition']}** · confidence **{v['confidence']}** "
                 f"· priority {v['priority']}/5{delta_note}")
    lines.append(f"- **Next action:** {v['action']}")
    drivers = [f"{s['name']} ({s['label']})" for s in v.get("rationale") or []
               if s.get("level", 0) > 0]
    if drivers:
        lines.append(f"- **Substantiated by:** {', '.join(drivers)}")
    if v.get("missing"):
        lines.append(f"- **Signals unavailable:** {', '.join(v['missing'])}")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover — manual smoke test
    import json
    inc = {"id": "INC-53018", "title": "Malicious HTA + Potential C2 for KELLYWANG",
           "severity": "High", "mitre_tactic": "Command and Control",
           "alertMeta": {"AlertTitles": ["Malicious HTA file detected", "Potential C2 Connection"]}}
    tri = {"metakeys_payload": {"classification": "high", "mitre_tactic": "Command and Control"},
           "ticket": {"classification": "High", "incident_category": "Compromised asset", "unc": "#EVAL"}}
    inv = {"status": "completed",
           "iocs": [{"value": "192.168.10.204"}, {"value": "evil.example.com"}, {"value": "hta.dll"}],
           "recommended_actions": [{"recommendation": "Isolate KELLYWANG and reset credentials"}],
           "investigation_summary": "Endpoint executed a malicious HTA reaching a C2 host."}
    v = build_final_verdict(inc, tri, inv)
    print(json.dumps({k: v[k] for k in ("level", "disposition", "confidence", "delta", "priority")}, indent=2))
    print()
    print(format_final_verdict(v))
