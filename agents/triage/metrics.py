# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, collections, typing,
#   agents.triage.triage_result.
# =============================================================================
# File: agents/triage/metrics.py
# Purpose: [FYP-TRIAGE-STEP3] X6 agreement metrics over the labelled-verdict
#   store (triage_reviews + blind_reviews): Cohen's kappa, confusion matrix
#   and raw agreement for analyst vs mentor, AI-final vs mentor, AI-final vs
#   analyst and AI-proposed vs AI-final (how often the guards intervene);
#   override rate, needs_info rate, per-disposition counts and, in
#   blind_first mode, the revision-after-reveal rate.
# Main functionality: cohens_kappa(), confusion_matrix(), pair_agreement(),
#   compute_triage_metrics(), render_metrics_markdown().
# Inputs: review dicts (workflow/review_store.list_reviews) and blind-review
#   dicts (workflow/review_store.list_blind_reviews).
# Outputs: plain JSON-safe dicts / Markdown.
# Workflow position: offline evaluation (feedback page + scripts).
# Called by: backend/services/triage_feedback_service.py,
#   scripts/triage_metrics.py.
# Important side effects: none (pure Python; no sklearn, no numpy).
# Error and fallback behaviour: empty inputs -> n = 0 and kappa = None
#   (undefined), never a fabricated 0 or 1.
# Key evaluator search terms: cohens_kappa, feedback-loop circularity,
#   automation bias, small-sample caveat, [FYP-TRIAGE-STEP3].
# =============================================================================
"""
Agreement metrics  --  metrics.py
=================================
[FYP-TRIAGE-STEP3] Method principles:

* Feedback-loop circularity: human verdicts are not ground truth until a
  blind re-review agrees, so the headline numbers compare against the
  MENTOR's blind labels, and analyst-vs-AI agreement is reported as
  agreement, not accuracy.
* Automation bias: in blind_first mode the analyst commits before seeing
  the AI; revision_after_reveal_rate measures how often the AI then moved
  them.
* Small samples: kappa on n < 30 is unstable; every report carries the
  caveat.

Cohen's kappa:  kappa = (p_o - p_e) / (1 - p_e), where p_o is observed
agreement and p_e = sum_k p_A(k) * p_B(k) is chance agreement from the two
raters' marginals. When p_e == 1 (both raters used one identical label for
every item) kappa is undefined; we report kappa = 1.0 iff p_o == 1 in that
degenerate case, following the common convention, and flag it.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Sequence

from .triage_result import DISPOSITIONS

SMALL_SAMPLE_N = 30
SMALL_SAMPLE_CAVEAT = (f"Small sample (n < {SMALL_SAMPLE_N}): kappa and rates are unstable "
                       "and should not be used to claim reliability.")


def confusion_matrix(a: Sequence[str], b: Sequence[str],
                     labels: Sequence[str] = DISPOSITIONS) -> dict:
    """rows = rater A label, columns = rater B label."""
    labels = list(labels)
    for x in list(a) + list(b):
        if x not in labels:
            labels.append(x)
    m = {ra: {rb: 0 for rb in labels} for ra in labels}
    for x, y in zip(a, b):
        m[x][y] += 1
    return {"labels": labels, "matrix": [[m[ra][rb] for rb in labels] for ra in labels]}


def cohens_kappa(a: Sequence[str], b: Sequence[str]) -> dict:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Pure-Python Cohen's kappa.
    Returns {n, observed_agreement, expected_agreement, kappa, degenerate}."""
    if len(a) != len(b):
        raise ValueError("rater sequences must have the same length")
    n = len(a)
    if n == 0:
        return {"n": 0, "observed_agreement": None, "expected_agreement": None,
                "kappa": None, "degenerate": False}
    p_o = sum(1 for x, y in zip(a, b) if x == y) / n
    ca, cb = Counter(a), Counter(b)
    p_e = sum((ca[k] / n) * (cb[k] / n) for k in set(ca) | set(cb))
    if abs(1.0 - p_e) < 1e-12:
        return {"n": n, "observed_agreement": p_o, "expected_agreement": p_e,
                "kappa": 1.0 if p_o == 1.0 else None, "degenerate": True}
    return {"n": n, "observed_agreement": p_o, "expected_agreement": p_e,
            "kappa": (p_o - p_e) / (1.0 - p_e), "degenerate": False}


def pair_agreement(a: Sequence[str], b: Sequence[str], *, rater_a: str, rater_b: str) -> dict:
    out = cohens_kappa(a, b)
    out.update({"rater_a": rater_a, "rater_b": rater_b,
                "confusion": confusion_matrix(a, b)})
    out["small_sample"] = out["n"] < SMALL_SAMPLE_N
    return out


def _rate(num: int, den: int) -> float | None:
    return None if den == 0 else num / den


def compute_triage_metrics(reviews: Iterable[dict], blind: Iterable[dict] | None = None,
                           *, mentor: str | None = None) -> dict:
    """[FYP-FUNCTION] [FYP-EVALUATOR] All X6 metrics. `reviews` = one row
    per triage decision with a structured review; `blind` = mentor labels
    (review_id, reviewer, disposition). If several reviewers exist and
    `mentor` is None, the reviewer with the most labels is used."""
    rv = [r for r in (reviews or []) if isinstance(r, dict) and r.get("analyst_disposition")]
    bl = [b for b in (blind or []) if isinstance(b, dict) and b.get("disposition")]
    if mentor is None and bl:
        mentor = Counter(str(b.get("reviewer")) for b in bl).most_common(1)[0][0]
    mentor_by_review = {int(b["review_id"]): b["disposition"] for b in bl
                        if str(b.get("reviewer")) == str(mentor)}

    n = len(rv)
    analyst = [r["analyst_disposition"] for r in rv]
    with_ai = [r for r in rv if r.get("ai_final_disposition")]
    with_prop = [r for r in rv if r.get("ai_final_disposition") and r.get("ai_proposed_disposition")]
    with_mentor = [r for r in rv if r.get("id") is not None and int(r["id"]) in mentor_by_review]
    mentor_ai = [r for r in with_mentor if r.get("ai_final_disposition")]

    pairs = {
        "analyst_vs_mentor": pair_agreement(
            [r["analyst_disposition"] for r in with_mentor],
            [mentor_by_review[int(r["id"])] for r in with_mentor],
            rater_a="analyst", rater_b="mentor"),
        "ai_final_vs_mentor": pair_agreement(
            [r["ai_final_disposition"] for r in mentor_ai],
            [mentor_by_review[int(r["id"])] for r in mentor_ai],
            rater_a="ai_final", rater_b="mentor"),
        "ai_final_vs_analyst": pair_agreement(
            [r["ai_final_disposition"] for r in with_ai],
            [r["analyst_disposition"] for r in with_ai],
            rater_a="ai_final", rater_b="analyst"),
        "ai_proposed_vs_ai_final": pair_agreement(
            [r["ai_proposed_disposition"] for r in with_prop],
            [r["ai_final_disposition"] for r in with_prop],
            rater_a="ai_proposed", rater_b="ai_final"),
    }
    overrides = sum(1 for r in with_ai if r["analyst_disposition"] != r["ai_final_disposition"])
    guard_interventions = sum(1 for r in with_prop
                              if r["ai_proposed_disposition"] != r["ai_final_disposition"])
    blind_first = [r for r in rv if r.get("review_mode") == "blind_first"]
    revised = sum(1 for r in blind_first if r.get("revised_after_ai_reveal"))
    per_disp = {d: 0 for d in DISPOSITIONS}
    for d in analyst:
        per_disp[d] = per_disp.get(d, 0) + 1
    ai_per_disp = {d: 0 for d in DISPOSITIONS}
    for r in with_ai:
        ai_per_disp[r["ai_final_disposition"]] = ai_per_disp.get(r["ai_final_disposition"], 0) + 1
    provenance = Counter(str(r.get("label_provenance") or "analyst") for r in rv)

    caveats = []
    if n < SMALL_SAMPLE_N:
        caveats.append(SMALL_SAMPLE_CAVEAT)
    if not with_mentor:
        caveats.append("No blind re-review labels yet: analyst verdicts are NOT ground truth "
                       "(feedback-loop circularity); agreement with the AI is not accuracy.")
    return {
        "n_reviews": n,
        "n_with_ai_verdict": len(with_ai),
        "n_mentor_labelled": len(with_mentor),
        "mentor": mentor,
        "pairs": pairs,
        "override_rate": _rate(overrides, len(with_ai)),
        "guard_intervention_rate": _rate(guard_interventions, len(with_prop)),
        "needs_info_rate": _rate(per_disp.get("needs_info", 0), n),
        "per_disposition": per_disp,
        "ai_final_per_disposition": ai_per_disp,
        "blind_first": {
            "n": len(blind_first),
            "revised_after_reveal": revised,
            "revision_after_reveal_rate": _rate(revised, len(blind_first)),
        },
        "label_provenance": dict(provenance),
        "small_sample": n < SMALL_SAMPLE_N,
        "small_sample_threshold": SMALL_SAMPLE_N,
        "caveats": caveats,
    }


def _fmt(x: Any, pct: bool = False) -> str:
    if x is None:
        return "n/a"
    if pct:
        return f"{x * 100:.1f}%"
    return f"{x:.3f}" if isinstance(x, float) else str(x)


def render_metrics_markdown(m: dict, *, generated_at: str | None = None) -> str:
    """Markdown report (ASCII only, so it prints on a cp1252 console)."""
    lines = ["# Triage quality metrics", ""]
    if generated_at:
        lines += [f"Generated: {generated_at}", ""]
    for c in m.get("caveats") or []:
        lines.append(f"> CAVEAT: {c}")
    lines += ["", f"- Reviews: {m['n_reviews']} (with AI verdict: {m['n_with_ai_verdict']}, "
                  f"mentor-labelled: {m['n_mentor_labelled']}"
                  f"{', mentor: ' + str(m['mentor']) if m.get('mentor') else ''})",
              f"- Override rate (analyst != AI final): {_fmt(m['override_rate'], True)}",
              f"- Guard intervention rate (AI proposed != AI final): "
              f"{_fmt(m['guard_intervention_rate'], True)}",
              f"- Needs-info rate (analyst): {_fmt(m['needs_info_rate'], True)}",
              f"- Blind-first reviews: {m['blind_first']['n']}, revised after AI reveal: "
              f"{m['blind_first']['revised_after_reveal']} "
              f"({_fmt(m['blind_first']['revision_after_reveal_rate'], True)})",
              f"- Label provenance: {m.get('label_provenance') or {}}",
              "", "## Agreement", "",
              "| Pair | n | Raw agreement | Chance | Cohen's kappa |",
              "|---|---|---|---|---|"]
    for name, p in (m.get("pairs") or {}).items():
        k = _fmt(p.get("kappa"))
        if p.get("degenerate"):
            k += " (degenerate: one label only)"
        lines.append(f"| {name} | {p['n']} | {_fmt(p.get('observed_agreement'), True)} | "
                     f"{_fmt(p.get('expected_agreement'), True)} | {k} |")
    lines += ["", "## Per-disposition counts", "", "| Disposition | Analyst | AI final |", "|---|---|---|"]
    for d in DISPOSITIONS:
        lines.append(f"| {d} | {m['per_disposition'].get(d, 0)} | "
                     f"{m['ai_final_per_disposition'].get(d, 0)} |")
    for name, p in (m.get("pairs") or {}).items():
        if not p["n"]:
            continue
        labels = p["confusion"]["labels"]
        lines += ["", f"### Confusion matrix: {name} (rows = {p['rater_a']}, cols = {p['rater_b']})",
                  "", "| | " + " | ".join(labels) + " |", "|---" * (len(labels) + 1) + "|"]
        for lab, row in zip(labels, p["confusion"]["matrix"]):
            lines.append(f"| {lab} | " + " | ".join(str(v) for v in row) + " |")
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "SMALL_SAMPLE_N",
    "SMALL_SAMPLE_CAVEAT",
    "confusion_matrix",
    "cohens_kappa",
    "pair_agreement",
    "compute_triage_metrics",
    "render_metrics_markdown",
]
