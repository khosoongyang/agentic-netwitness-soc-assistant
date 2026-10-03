"""[FYP-TRIAGE-STEP3] Triage review + feedback-routing + quality-metrics service.

# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# File: backend/services/triage_feedback_service.py
# Purpose: All logic behind the Step-3 HTTP endpoints, so the routes in
#   backend/routes/triage_feedback.py stay thin:
#     X1  GET  /api/cases/<id>/triage/reviews
#     X3  GET  /api/triage/tuning-backlog
#         GET/POST /api/triage/suppressions (+ approve / reject / revoke)
#         GET  /api/triage/noisy-rules
#     X6  GET  /api/triage/metrics
# Inputs: workflow/review_store.py (workflow DB), agents/triage/{feedback,
#   metrics,baseline}.py (pure / read-only).
# Outputs: JSON-safe dicts; raises APIError with the canonical
#   {"error": {code, message}} shape.
# Important side effects: suppression lifecycle writes go to the workflow
#   DB only; the noisy-rules query opens the baseline DB READ-ONLY. Nothing
#   here closes or suppresses an incident (Tier 2: never auto-close).
# Key evaluator search terms: tuning backlog, suppression proposals,
#   noisy rules, Cohen's kappa, [FYP-TRIAGE-STEP3].
# =============================================================================
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agents.triage import feedback, metrics
from agents.triage.baseline import noisy_pairs
from workflow import review_store
from workflow import state_store as wss

from ..errors import APIError


def _wrap(call, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except review_store.ReviewStoreError as exc:
        raise APIError(exc.code, exc.message, exc.status_code) from exc


def _strip_packet(review: dict) -> dict:
    r = dict(review)
    r.pop("evidence_packet", None)
    return r


# ── X1 ───────────────────────────────────────────────────────────────────────

def case_reviews(case_id: str, *, include_packet: bool = False) -> dict[str, Any]:
    state = wss.get_state(str(case_id))
    reviews = review_store.list_reviews(str(case_id), include_packet=include_packet)
    return {"case_id": str(case_id),
            "run_id": (state or {}).get("run_id"),
            "reviews": reviews,
            "count": len(reviews)}


# ── X3 ───────────────────────────────────────────────────────────────────────

def tuning_backlog() -> dict[str, Any]:
    items = feedback.aggregate_tuning_backlog(
        review_store.list_reviews(dispositions=("false_positive",)))
    return {"items": items, "count": len(items),
            "note": "False positives = rule problems -> tuning. Benign-expected verdicts are "
                    "routed to scoped suppression proposals instead."}


def list_suppressions(status: str | None = None) -> dict[str, Any]:
    if status and status not in ("proposed", "approved", "rejected", "expired", "revoked"):
        raise APIError("INVALID_QUERY", "Unknown suppression status.", 400)
    items = review_store.list_suppressions(status or None)
    return {"items": items, "count": len(items)}


def propose_suppression(body: dict) -> dict[str, Any]:
    try:
        review_id = int(body.get("review_id"))
    except (TypeError, ValueError) as exc:
        raise APIError("INVALID_REQUEST", "review_id (integer) is required.", 400) from exc
    scope = body.get("scope") if isinstance(body.get("scope"), dict) else None
    return _wrap(review_store.propose_suppression_from_review, review_id,
                 proposed_by=str(body.get("analyst") or ""), scope=scope,
                 expiry_days=body.get("expiry_days"))


def decide_suppression(proposal_id: int, action: str, body: dict) -> dict[str, Any]:
    analyst = str(body.get("analyst") or "")
    if action == "approve":
        return _wrap(review_store.approve_suppression, proposal_id, analyst=analyst,
                     confirmation=str(body.get("confirmation") or ""))
    note = str(body.get("note") or "").strip() or None
    if action == "reject":
        return _wrap(review_store.reject_suppression, proposal_id, analyst=analyst, note=note)
    if action == "revoke":
        return _wrap(review_store.revoke_suppression, proposal_id, analyst=analyst, note=note)
    raise APIError("INVALID_REQUEST", "action must be approve, reject or revoke.", 400)


def noisy_rules(*, baseline_db: str | Path | None = None, limit: int = 20) -> dict[str, Any]:
    """Read-only baseline counts (soc_db; never written) joined with
    FP / benign_expected review counts."""
    limit = max(1, min(int(limit), 100))
    report = noisy_pairs(Path(baseline_db) if baseline_db else wss.DB_FILE, limit=limit)
    reviews = review_store.list_reviews(dispositions=("false_positive", "benign_expected"))
    report["pairs"] = feedback.join_noisy_rules(report.get("pairs") or [], reviews)
    return report


# ── X6 ───────────────────────────────────────────────────────────────────────

def triage_metrics() -> dict[str, Any]:
    return metrics.compute_triage_metrics(review_store.list_reviews(),
                                          review_store.list_blind_reviews())
