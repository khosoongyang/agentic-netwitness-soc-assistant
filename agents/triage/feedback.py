# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, collections, re, typing,
#   agents.triage.review.
# =============================================================================
# File: agents/triage/feedback.py
# Purpose: [FYP-TRIAGE-STEP3] X3 feedback routing -- false_positive reviews
#   become a RULE-TUNING BACKLOG (aggregated per detection source + raw-alert
#   signature + entity) and each backlog item can be exported as a Markdown
#   stub in Palantir's Alerting & Detection Strategy (ADS) format.
# Main functionality: aggregate_tuning_backlog(), render_ads_stub(),
#   ads_filename(), join_noisy_rules().
# Inputs: triage_reviews rows (plain dicts read by the workflow review store), and the
#   read-only noisy-pair counts from agents/triage/baseline.noisy_pairs().
# Outputs: plain dicts / Markdown strings.
# Workflow position: after the Triage gate (feedback page, export script).
# Called by: backend/services/triage_feedback_service.py,
#   scripts/export_tuning_backlog.py.
# Important side effects: none (pure).
# Error and fallback behaviour: unknown ADS sections are written as "TODO",
#   never invented.
# Key evaluator search terms: tuning backlog, ADS, Palantir, FP != Benign,
#   [FYP-TRIAGE-STEP3].
# =============================================================================
"""
Feedback routing  --  feedback.py
=================================
[FYP-TRIAGE-STEP3] SOC method Step 10: "If it's an FP from a broken rule,
flag it for tuning." FP != Benign-Expected: a false positive is a RULE
problem (fix the detection), Benign-Expected is a CONTEXT problem (record
who/when/why; see agents/triage/suppression.py). Only false_positive reviews
feed this backlog.

ADS format: https://github.com/palantir/alerting-detection-strategy-framework
(sections Goal, Categorization, Strategy Abstract, Technical Context, Blind
Spots & Assumptions, False Positives, Validation, Priority, Response).
Anything the reviews do not tell us is written as TODO -- never invented.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Iterable

MAX_NOTES_PER_ITEM = 5
MAX_EXAMPLES_PER_ITEM = 5
TODO = "TODO"


def _key(r: dict) -> tuple[str, str, str]:
    return (str(r.get("detection_source") or "unknown source"),
            str(r.get("alert_signature") or "unknown signature"),
            str(r.get("entity") or "unknown entity"))


def aggregate_tuning_backlog(reviews: Iterable[dict]) -> list[dict]:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Group false_positive reviews by
    (detection source, raw-alert signature, entity): FP count, the latest
    tuning notes, example incident ids, first/last seen. Sorted by FP count
    then recency."""
    groups: dict[tuple[str, str, str], dict] = {}
    for r in reviews or []:
        if not isinstance(r, dict) or r.get("analyst_disposition") != "false_positive":
            continue
        k = _key(r)
        g = groups.setdefault(k, {
            "detection_source": k[0], "alert_signature": k[1], "entity": k[2],
            "fp_count": 0, "tuning_notes": [], "example_incident_ids": [],
            "first_seen": None, "last_seen": None, "analysts": Counter(),
            "review_ids": [],
        })
        g["fp_count"] += 1
        g["review_ids"].append(r.get("id"))
        when = str(r.get("decided_at") or "")
        if when and (g["first_seen"] is None or when < g["first_seen"]):
            g["first_seen"] = when
        if when and (g["last_seen"] is None or when > g["last_seen"]):
            g["last_seen"] = when
        g["_notes"] = g.get("_notes", []) + [(when, str(r.get("rule_tuning_note") or "").strip())]
        inc = str(r.get("incident_id") or "")
        if inc and inc not in g["example_incident_ids"] \
                and len(g["example_incident_ids"]) < MAX_EXAMPLES_PER_ITEM:
            g["example_incident_ids"].append(inc)
        if r.get("analyst"):
            g["analysts"][str(r["analyst"])] += 1
    out = []
    for g in groups.values():
        notes = [n for _w, n in sorted(g.pop("_notes", []), key=lambda t: t[0], reverse=True) if n]
        seen: list[str] = []
        for n in notes:
            if n not in seen:
                seen.append(n)
        g["tuning_notes"] = seen[:MAX_NOTES_PER_ITEM]
        g["analysts"] = sorted(g["analysts"])
        out.append(g)
    out.sort(key=lambda g: str(g["last_seen"] or ""), reverse=True)
    out.sort(key=lambda g: g["fp_count"], reverse=True)   # stable: count, then recency
    return out


def ads_filename(item: dict) -> str:
    raw = f"{item.get('detection_source')}__{item.get('alert_signature')}__{item.get('entity')}"
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("_")[:120] or "rule"
    return f"ADS_{slug}.md"


def _md(text: Any) -> str:
    """Neutralise Markdown/HTML control characters in values copied from
    reviews (they may echo attacker-controlled alert text)."""
    s = str(text if text is not None else "")
    s = s.replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]()#+!|<>])", r"\\\1", s)


def render_ads_stub(item: dict, *, mitre: str | None = None, generated_at: str | None = None) -> str:
    """[FYP-FUNCTION] One Palantir-ADS Markdown stub for a backlog item.
    Only facts present in the reviews are filled in; every other section
    is TODO for the detection engineer."""
    notes = item.get("tuning_notes") or []
    fp_lines = "\n".join(f"- {_md(n)}" for n in notes) or f"- {TODO}"
    examples = ", ".join(_md(i) for i in item.get("example_incident_ids") or []) or TODO
    return "\n".join([
        f"# ADS: {_md(item.get('detection_source'))} / {_md(item.get('alert_signature'))}",
        "",
        f"> Rule-tuning backlog stub generated by Aegis Triage{(' at ' + _md(generated_at)) if generated_at else ''}.",
        "> Source: analyst false_positive reviews (FP = rule problem -> tuning).",
        "> Sections marked TODO were NOT known from the reviews and must not be guessed.",
        "",
        "## Goal",
        TODO,
        "",
        "## Categorization",
        f"MITRE ATT&CK: {_md(mitre) if mitre else TODO}",
        "",
        "## Strategy Abstract",
        f"Detection source: `{_md(item.get('detection_source'))}`; raw-alert signature: "
        f"`{_md(item.get('alert_signature'))}`. {TODO}: describe how the rule works.",
        "",
        "## Technical Context",
        f"Entity most affected: `{_md(item.get('entity'))}`. Example incidents: {examples}. {TODO}",
        "",
        "## Blind Spots and Assumptions",
        TODO,
        "",
        "## False Positives",
        f"{int(item.get('fp_count') or 0)} analyst-confirmed false positive(s) between "
        f"{_md(item.get('first_seen') or TODO)} and {_md(item.get('last_seen') or TODO)}. "
        "Analysts' tuning notes (latest first):",
        fp_lines,
        "",
        "## Validation",
        f"{TODO}: a true-positive test that must still fire after tuning.",
        "",
        "## Priority",
        f"{TODO}",
        "",
        "## Response",
        f"{TODO}",
        "",
    ])


def join_noisy_rules(pairs: Iterable[dict], reviews: Iterable[dict]) -> list[dict]:
    """[FYP-FUNCTION] Join read-only noisy (detection_source, entity) counts
    with FP / benign_expected review counts for the same pair."""
    fp: Counter = Counter()
    be: Counter = Counter()
    for r in reviews or []:
        k = (str(r.get("detection_source") or "").casefold(), str(r.get("entity") or "").casefold())
        if r.get("analyst_disposition") == "false_positive":
            fp[k] += 1
        elif r.get("analyst_disposition") == "benign_expected":
            be[k] += 1
    out = []
    for p in pairs or []:
        k = (str(p.get("detection_source") or "").casefold(), str(p.get("entity") or "").casefold())
        out.append({**p, "fp_reviews": fp.get(k, 0), "benign_expected_reviews": be.get(k, 0)})
    return out


__all__ = [
    "aggregate_tuning_backlog",
    "ads_filename",
    "render_ads_stub",
    "join_noisy_rules",
]
