"""Read-only case and workflow API routes."""

from flask import Blueprint, current_app, jsonify, request

from ..errors import InvalidQueryError
from ..services import case_service


cases_blueprint = Blueprint("cases", __name__, url_prefix="/api/cases")


def _integer_query(name: str, default: int) -> int:
    raw = request.args.get(name)
    if raw in (None, ""):
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise InvalidQueryError(f"{name} must be an integer.") from exc


@cases_blueprint.get("")
def cases():
    return jsonify(case_service.list_cases(
        search=request.args.get("search", ""),
        severity=request.args.get("severity", ""),
        status=request.args.get("status", ""),
        page=_integer_query("page", 1),
        limit=_integer_query("limit", 50),
        sort=request.args.get("sort", "updated"),
        direction=request.args.get("direction", "desc"),
        database_path=current_app.config.get("AEGIS_CASE_DB_PATH"),
    ))


@cases_blueprint.get("/<case_id>")
def case_detail(case_id: str):
    return jsonify(case_service.get_case_detail(
        case_id,
        database_path=current_app.config.get("AEGIS_CASE_DB_PATH"),
        case_view_builder=current_app.config.get("AEGIS_CASE_VIEW_BUILDER"),
    ))


@cases_blueprint.get("/<case_id>/workflow")
def case_workflow(case_id: str):
    return jsonify(case_service.get_case_workflow(
        case_id,
        database_path=current_app.config.get("AEGIS_CASE_DB_PATH"),
    ))
