"""[FYP-TRIAGE-STEP3] Thin HTTP transport for the triage review, feedback
routing and quality-metrics endpoints. All logic lives in
backend/services/triage_feedback_service.py."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from ..errors import APIError
from ..services import triage_feedback_service as svc


triage_feedback_blueprint = Blueprint("triage_feedback", __name__, url_prefix="/api")


def _body() -> dict:
    body = request.get_json(silent=True)
    if body is None:
        return {}
    if not isinstance(body, dict):
        raise APIError("INVALID_REQUEST", "The request body must be a JSON object.", 400)
    return body


@triage_feedback_blueprint.get("/cases/<case_id>/triage/reviews")
def case_reviews(case_id: str):
    include = str(request.args.get("include_packet") or "").lower() in ("1", "true", "yes")
    return jsonify(svc.case_reviews(case_id, include_packet=include))


@triage_feedback_blueprint.get("/triage/tuning-backlog")
def tuning_backlog():
    return jsonify(svc.tuning_backlog())


@triage_feedback_blueprint.get("/triage/suppressions")
def list_suppressions():
    return jsonify(svc.list_suppressions(request.args.get("status") or None))


@triage_feedback_blueprint.post("/triage/suppressions")
def propose_suppression():
    return jsonify(svc.propose_suppression(_body())), 201


@triage_feedback_blueprint.post("/triage/suppressions/<int:proposal_id>/<action>")
def decide_suppression(proposal_id: int, action: str):
    return jsonify(svc.decide_suppression(proposal_id, action, _body()))


@triage_feedback_blueprint.get("/triage/noisy-rules")
def noisy_rules():
    try:
        limit = int(request.args.get("limit") or 20)
    except ValueError as exc:
        raise APIError("INVALID_QUERY", "limit must be an integer.", 400) from exc
    return jsonify(svc.noisy_rules(baseline_db=current_app.config.get("AEGIS_BASELINE_DB_PATH"),
                                   limit=limit))


@triage_feedback_blueprint.get("/triage/metrics")
def triage_metrics():
    return jsonify(svc.triage_metrics())
