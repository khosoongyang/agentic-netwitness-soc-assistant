"""Structured report review, editing, confirmation, and export routes."""

from __future__ import annotations

import io

from flask import Blueprint, current_app, jsonify, request, send_file

from ..errors import APIError
from ..services.report_service import ReportService, ReportServiceError


reports_blueprint = Blueprint("reports", __name__, url_prefix="/api/cases/<case_id>/reports")


def _service():
    return current_app.config.get("AEGIS_REPORT_SERVICE") or ReportService()


def _body():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise APIError("REPORT_INVALID", "The request body must be a JSON object.", 400)
    return body


def _call(operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except ReportServiceError as exc:
        raise APIError(exc.code, exc.message, exc.status_code) from exc


@reports_blueprint.get("")
def list_reports(case_id: str):
    return jsonify(_call(_service().list_reports, case_id))


@reports_blueprint.get("/<report_type>")
def read_report(case_id: str, report_type: str):
    return jsonify(_call(_service().get_report, case_id, report_type))


@reports_blueprint.put("/<report_type>")
def save_report(case_id: str, report_type: str):
    return jsonify(_call(_service().save_report, case_id, report_type, _body()))


@reports_blueprint.delete("/<report_type>/draft")
def discard_report(case_id: str, report_type: str):
    return jsonify(_call(
        _service().discard_report,
        case_id,
        report_type,
        str(_body().get("analyst") or "").strip(),
    ))


@reports_blueprint.post("/<report_type>/confirm")
def confirm_section(case_id: str, report_type: str):
    return jsonify(_call(_service().confirm_section, case_id, report_type, _body()))


@reports_blueprint.post("/final/confirm")
def confirm_final(case_id: str):
    return jsonify(_call(_service().confirm_final, case_id, _body()))


@reports_blueprint.get("/<report_type>/download")
def download_report(case_id: str, report_type: str):
    file_type = str(request.args.get("format") or "").lower()
    data, filename = _call(
        _service().export,
        case_id,
        report_type,
        file_type,
        str(request.args.get("analyst") or "SOC Analyst"),
        approved=request.args.get("approved") == "1",
    )
    mime = "application/pdf" if file_type == "pdf" else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    return send_file(io.BytesIO(data), mimetype=mime, as_attachment=True, download_name=filename)


@reports_blueprint.get("/export-all")
def export_all(case_id: str):
    data, filename = _call(_service().export_all, case_id)
    return send_file(io.BytesIO(data), mimetype="application/zip", as_attachment=True, download_name=filename)


@reports_blueprint.get("/data/download")
def reporting_data(case_id: str):
    data, filename = _call(_service().reporting_json, case_id)
    return send_file(io.BytesIO(data), mimetype="application/json", as_attachment=True, download_name=filename)
