"""HTTP transport for validated incident imports."""

from __future__ import annotations

from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

from ..errors import APIError
from ..services.import_service import ImportService, ImportServiceError


imports_blueprint = Blueprint("imports", __name__, url_prefix="/api/imports")


def _service() -> ImportService:
    configured = current_app.config.get("AEGIS_IMPORT_SERVICE")
    if configured:
        return configured
    root = Path(current_app.root_path).parent
    return ImportService(root / "runtime" / "uploads", current_app.config.get("MAX_IMPORT_BYTES", 5 * 1024 * 1024))


@imports_blueprint.post("/incidents")
def import_incident():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        raise APIError("IMPORT_INVALID", "Choose an incident file to upload.", 400)
    maximum = current_app.config.get("MAX_IMPORT_BYTES", 5 * 1024 * 1024)
    raw = uploaded.stream.read(maximum + 1)
    try:
        result = _service().import_file(
            uploaded.filename,
            raw,
            expected_incident_id=request.form.get("incident_id") or None,
        )
    except ImportServiceError as exc:
        raise APIError(exc.code, exc.message, exc.status_code) from exc
    return jsonify(result), 201
