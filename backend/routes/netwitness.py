"""HTTP transport for the canonical NetWitness integration."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from integrations.netwitness import NetWitnessError

from ..errors import APIError
from ..services.netwitness_service import netwitness_service
from ..services.sync_service import SyncService


netwitness_blueprint = Blueprint("netwitness", __name__, url_prefix="/api/integrations/netwitness")


def _service():
    return current_app.config.get("AEGIS_NETWITNESS_SERVICE") or netwitness_service


def _body() -> dict:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise APIError("INVALID_REQUEST", "The request body must be a JSON object.", 400)
    return body


def _call(operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except NetWitnessError as exc:
        raise APIError(exc.code, exc.message, exc.status_code) from exc


def _int_arg(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError) as exc:
        raise APIError("INVALID_QUERY", f"{name} must be an integer.", 400) from exc
    if not minimum <= value <= maximum:
        raise APIError("INVALID_QUERY", f"{name} must be between {minimum} and {maximum}.", 400)
    return value


@netwitness_blueprint.get("/status")
def status():
    return jsonify(_service().status())


@netwitness_blueprint.post("/login")
def login():
    return jsonify(_call(_service().login, _body()))


@netwitness_blueprint.post("/token")
def token():
    return jsonify(_call(_service().set_token, _body()))


@netwitness_blueprint.post("/test")
def test_connection():
    return jsonify(_call(_service().test))


@netwitness_blueprint.get("/incidents")
def incidents():
    return jsonify(_call(
        _service().incidents,
        page=_int_arg("page", 0, 0, 100000),
        limit=_int_arg("limit", 100, 1, 100),
        since=request.args.get("since") or None,
    ))


@netwitness_blueprint.get("/incidents/<path:incident_id>")
def incident(incident_id: str):
    return jsonify(_call(_service().incident, incident_id))


@netwitness_blueprint.get("/incidents/<path:incident_id>/alerts")
def alerts(incident_id: str):
    return jsonify({"items": _call(_service().alerts, incident_id)})


@netwitness_blueprint.get("/alerts/<path:alert_id>")
def alert(alert_id: str):
    return jsonify(_call(_service().alert, alert_id))


@netwitness_blueprint.post("/sync")
def synchronize():
    body = _body()
    limit = body.get("limit")
    if limit is not None:
        try:
            limit = int(limit)
        except (TypeError, ValueError) as exc:
            raise APIError("INVALID_REQUEST", "limit must be an integer.", 400) from exc
        if not 1 <= limit <= 100000:
            raise APIError("INVALID_REQUEST", "limit must be between 1 and 100000.", 400)
    service = current_app.config.get("AEGIS_SYNC_SERVICE") or SyncService(_service())
    return jsonify(_call(service.synchronize, limit=limit, since=body.get("since") or None))
