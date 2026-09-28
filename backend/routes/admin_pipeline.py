"""Read-only pipeline inspection and separated developer mutations."""

from __future__ import annotations

import io

from flask import Blueprint, current_app, jsonify, request, send_file

from ..errors import APIError
from ..services.dashboard_service import DEFAULT_PIPELINE_DB
from ..services.pipeline_service import PipelineService, PipelineServiceError
from ..services.settings_service import settings_service


pipeline_blueprint = Blueprint("pipeline", __name__, url_prefix="/api")


def _service():
    configured = current_app.config.get("AEGIS_PIPELINE_SERVICE")
    return configured or PipelineService(current_app.config.get("AEGIS_PIPELINE_DB_PATH") or DEFAULT_PIPELINE_DB)


def _settings():
    return current_app.config.get("AEGIS_SETTINGS_SERVICE") or settings_service


def _body():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise APIError("PIPELINE_OPERATION_FAILED", "The request body must be a JSON object.", 400)
    return body


def _call(operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except PipelineServiceError as exc:
        raise APIError(exc.code, exc.message, exc.status_code) from exc


@pipeline_blueprint.get("/pipeline")
def summary():
    return jsonify(_call(_service().summary))


@pipeline_blueprint.get("/pipeline/<stage>/records")
def records(stage: str):
    try:
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
    except ValueError as exc:
        raise APIError("PIPELINE_OPERATION_FAILED", "Pagination is invalid.", 400) from exc
    return jsonify(_call(_service().records, stage, limit=limit, offset=offset))


@pipeline_blueprint.get("/pipeline/<stage>/records/<path:record_id>/download")
def record_download(stage: str, record_id: str):
    if request.args.get("format", "csv") != "csv":
        raise APIError("PIPELINE_OPERATION_FAILED", "Only CSV pipeline export is supported.", 400)
    data, filename = _call(_service().export_csv, stage, record_id)
    return send_file(io.BytesIO(data), mimetype="text/csv", as_attachment=True, download_name=filename)


@pipeline_blueprint.delete("/admin/pipeline/<stage>/records/<path:record_id>")
def delete_record(stage: str, record_id: str):
    return jsonify(_call(
        _service().delete_record,
        stage,
        record_id,
        str(_body().get("confirmation") or ""),
        developer_mode=bool(_settings().status().get("developer_mode")),
    ))


@pipeline_blueprint.delete("/admin/pipeline/<stage>")
def clear_stage(stage: str):
    return jsonify(_call(
        _service().clear_stage,
        stage,
        str(_body().get("confirmation") or ""),
        developer_mode=bool(_settings().status().get("developer_mode")),
    ))
