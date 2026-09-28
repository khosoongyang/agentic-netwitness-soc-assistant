"""Semantic-search and explicitly confirmed vector administration routes."""

from flask import Blueprint, current_app, jsonify, request

from ..errors import APIError
from ..services.pipeline_service import PIPELINE_STAGES
from ..services.search_service import VectorStoreError, search_service
from ..services.settings_service import settings_service


search_blueprint = Blueprint("search", __name__, url_prefix="/api")


def _service():
    return current_app.config.get("AEGIS_SEARCH_SERVICE") or search_service


def _settings():
    return current_app.config.get("AEGIS_SETTINGS_SERVICE") or settings_service


def _body():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise APIError("VECTOR_STORE_UNAVAILABLE", "The request body must be a JSON object.", 400)
    return body


def _call(operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except VectorStoreError as exc:
        code = "FORBIDDEN_OPERATION" if exc.status_code == 403 else "VECTOR_STORE_UNAVAILABLE"
        raise APIError(code, exc.message, exc.status_code) from exc


@search_blueprint.get("/search/status")
def status():
    return jsonify(_service().status())


@search_blueprint.post("/search")
def search():
    body = _body()
    stage = str(body.get("stage") or "").strip()
    if stage and stage not in PIPELINE_STAGES:
        raise APIError("FORBIDDEN_OPERATION", "Pipeline stage is not allowed.", 403)
    try:
        limit = int(body.get("limit") or 5)
    except (TypeError, ValueError) as exc:
        raise APIError("VECTOR_STORE_UNAVAILABLE", "Search limit is invalid.", 400) from exc
    collection = f"pipeline_{stage}" if stage else "soc_incidents"
    return jsonify(_call(_service().search, body.get("query"), limit=limit, collection_name=collection))


@search_blueprint.get("/search/vectors")
def browse_vectors():
    stage = str(request.args.get("stage") or "").strip()
    if stage and stage not in PIPELINE_STAGES:
        raise APIError("FORBIDDEN_OPERATION", "Pipeline stage is not allowed.", 403)
    try:
        limit = int(request.args.get("limit", 100))
    except ValueError as exc:
        raise APIError("VECTOR_STORE_UNAVAILABLE", "Vector browse limit is invalid.", 400) from exc
    collection = f"pipeline_{stage}" if stage else "soc_incidents"
    return jsonify(_call(_service().browse, limit=limit, collection_name=collection))


@search_blueprint.post("/admin/vector/sync")
def sync_vectors():
    if not _settings().status().get("developer_mode"):
        raise APIError("FORBIDDEN_OPERATION", "Developer mode is required.", 403)
    return jsonify(_call(_service().sync_incidents, database_path=current_app.config.get("AEGIS_CASE_DB_PATH")))


@search_blueprint.delete("/admin/vector/collections/<collection_name>")
def wipe_collection(collection_name: str):
    if not _settings().status().get("developer_mode"):
        raise APIError("FORBIDDEN_OPERATION", "Developer mode is required.", 403)
    return jsonify(_call(_service().wipe, collection_name, str(_body().get("confirmation") or "")))
