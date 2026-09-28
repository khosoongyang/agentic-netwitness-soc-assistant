"""Secret-safe application settings routes."""

from flask import Blueprint, current_app, jsonify, request

from ..errors import APIError
from ..services.settings_service import SettingsError, settings_service


settings_blueprint = Blueprint("settings", __name__, url_prefix="/api/settings")


def _service():
    return current_app.config.get("AEGIS_SETTINGS_SERVICE") or settings_service


@settings_blueprint.get("")
def status():
    return jsonify(_service().status())


@settings_blueprint.put("")
def update():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise APIError("SETTINGS_INVALID", "The request body must be a JSON object.", 400)
    try:
        return jsonify(_service().update(body))
    except SettingsError as exc:
        raise APIError("SETTINGS_INVALID", str(exc), 400) from exc
