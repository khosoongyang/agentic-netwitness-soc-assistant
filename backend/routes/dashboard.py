"""Read-only dashboard API routes."""

from flask import Blueprint, current_app, jsonify, request

from ..services import dashboard_service


dashboard_blueprint = Blueprint("dashboard", __name__, url_prefix="/api")


@dashboard_blueprint.get("/dashboard")
def dashboard():
    return jsonify(dashboard_service.get_dashboard(
        database_path=current_app.config.get("AEGIS_CASE_DB_PATH"),
        pipeline_database_path=current_app.config.get("AEGIS_PIPELINE_DB_PATH"),
    ))


@dashboard_blueprint.get("/dashboard/analytics")
def dashboard_analytics():
    return jsonify(dashboard_service.get_dashboard_analytics(
        range_key=request.args.get("range", "all"),
        database_path=current_app.config.get("AEGIS_CASE_DB_PATH"),
    ))
