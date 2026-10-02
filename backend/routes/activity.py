"""HTTP transport for Agent Activity (read-only).

GET /api/cases/<case_id>/activity          history (initial load / reload / fallback)
GET /api/cases/<case_id>/activity/stream   Server-Sent Events, resumable via Last-Event-ID
"""

from __future__ import annotations

from flask import Blueprint, Response, current_app, jsonify, request, stream_with_context

from ..errors import APIError
from ..services import activity_service

activity_blueprint = Blueprint("agent_activity", __name__, url_prefix="/api/cases")


def _int_arg(value, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _db_path():
    return current_app.config.get("AGENT_ACTIVITY_DB_PATH")


@activity_blueprint.get("/<case_id>/activity")
def case_activity(case_id: str):
    try:
        result = activity_service.list_events(
            case_id,
            run_id=request.args.get("run_id") or None,
            stage=request.args.get("stage") or None,
            after=_int_arg(request.args.get("after")),
            limit=_int_arg(request.args.get("limit"), 500) or 500,
            db_path=_db_path(),
        )
    except activity_service.CaseNotFound as exc:
        raise APIError("CASE_NOT_FOUND", "Case was not found.", 404) from exc
    return jsonify(result)


@activity_blueprint.get("/<case_id>/activity/stream")
def case_activity_stream(case_id: str):
    # EventSource sends Last-Event-ID on reconnect; honour whichever is newer.
    after = max(_int_arg(request.headers.get("Last-Event-ID")),
                _int_arg(request.args.get("after")))
    try:
        frames = activity_service.stream_events(
            case_id,
            run_id=request.args.get("run_id") or None,
            stage=request.args.get("stage") or None,
            after=after,
            db_path=_db_path(),
            max_seconds=float(current_app.config.get(
                "AGENT_ACTIVITY_STREAM_SECONDS", activity_service.STREAM_MAX_SECONDS)),
        )
        first = next(frames)  # resolves the case before the 200 is committed
    except activity_service.CaseNotFound as exc:
        raise APIError("CASE_NOT_FOUND", "Case was not found.", 404) from exc

    def generate():
        yield first
        yield from frames

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
