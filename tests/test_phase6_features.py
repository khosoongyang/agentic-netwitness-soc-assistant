from __future__ import annotations

import importlib.util
import io
import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest

import backend.services.case_view_service as case_view
from workflow import state_store as wss


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "_aegis_phase6_backend"


def _backend():
    existing = sys.modules.get(PACKAGE)
    if existing:
        return existing
    package_dir = ROOT / "backend"
    spec = importlib.util.spec_from_file_location(
        PACKAGE, package_dir / "__init__.py", submodule_search_locations=[str(package_dir)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE] = module
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


backend = _backend()
chat_module = importlib.import_module(f"{PACKAGE}.services.chatbot_service")
report_module = importlib.import_module(f"{PACKAGE}.services.report_service")
settings_module = importlib.import_module(f"{PACKAGE}.services.settings_service")
search_module = importlib.import_module(f"{PACKAGE}.services.search_service")
pipeline_module = importlib.import_module(f"{PACKAGE}.services.pipeline_service")


@pytest.fixture
def case_db(tmp_path, monkeypatch):
    path = tmp_path / "cases.db"
    monkeypatch.setattr(wss, "DB_FILE", path)
    wss.db_init()
    with wss.db_connect() as connection:
        connection.execute(
            "INSERT INTO incidents (id,title,raw_json,run_id,workflow_status,parsing_status,"
            "triage_status,triage_result_json,reporting_status,reporting_attempt) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("CASE-1", "Case One", json.dumps({"id": "CASE-1", "title": "Case One"}),
             "RUN-1", "Awaiting Approval", "Complete", "Approved",
             json.dumps({"ticket": {"incident_id": "CASE-1", "unc": "UNC-1", "title": "Ticket", "summary": "Triage"}}),
             "Awaiting Approval", 2),
        )
        connection.commit()
    return path


def test_global_and_case_chat_use_trusted_server_context(case_db, monkeypatch):
    captured = {}

    def responder(message, incident, parsed, context):
        captured.update(message=message, incident=incident, context=context)
        return "grounded answer"

    monkeypatch.setattr(case_view, "build_aegis_context", lambda case_id, run_id: {
        "available": True, "incident_id": case_id, "run_id": run_id, "confirmed_facts": ["fact"]})
    service = chat_module.ChatbotService(responder)
    assert service.ask_global("hello")["message"] == "grounded answer"
    result = service.ask_case("CASE-1", "what happened?", database_path=case_db)
    assert result["case_id"] == "CASE-1"
    assert captured["incident"]["id"] == "CASE-1"
    assert captured["context"]["run_id"] == "RUN-1"


def test_chat_missing_case_unavailable_fallback_and_safe_error(case_db, monkeypatch):
    service = chat_module.ChatbotService(lambda *_: "ok")
    with pytest.raises(Exception) as missing:
        service.ask_case("MISSING", "hello", database_path=case_db)
    assert getattr(missing.value, "code", "CASE_NOT_FOUND") == "CASE_NOT_FOUND"
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert chat_module.ChatbotService().ask_global("hello")["available"] is False

    def failure(*_):
        raise RuntimeError("secret-key-value")

    with pytest.raises(chat_module.ChatServiceError) as caught:
        chat_module.ChatbotService(failure).ask_global("hello")
    assert "secret-key-value" not in caught.value.message


def report_preview(*_):
    return {
        "current_attempt": {
            "report_set_id": "SET-1",
            "reports": [{
                "report_type": "executive_summary",
                "structured_content": [{"type": "paragraph", "text": "Original"}],
                "generated_at": "2026-01-01T00:00:00Z",
            }],
        },
        "export_all_available": False,
        "warnings": [],
    }


def test_report_list_read_save_confirm_and_identity_guards(case_db, monkeypatch):
    monkeypatch.setattr(report_module.case_view, "build_reporting", report_preview)
    service = report_module.ReportService()
    listing = service.list_reports("CASE-1")
    assert len(listing["reports"]) == 4
    report = service.get_report("CASE-1", "executive_summary")
    assert report["blocks"][0]["text"] == "Original"
    saved = service.save_report("CASE-1", "executive_summary", {
        "analyst": "Alice", "run_id": "RUN-1", "report_set_id": "SET-1",
        "blocks": [{"type": "paragraph", "text": "Edited"}],
    })
    assert saved["blocks"][0]["text"] == "Edited"
    confirmed = service.confirm_section("CASE-1", "executive_summary", {
        "analyst": "Alice", "report_set_id": "SET-1"})
    assert confirmed["confirmed"] is True
    with pytest.raises(report_module.ReportServiceError) as stale:
        service.save_report("CASE-1", "executive_summary", {
            "analyst": "Alice", "run_id": "OTHER", "blocks": [{"type": "paragraph", "text": "x"}]})
    assert stale.value.status_code == 409


@pytest.mark.parametrize("file_type", ["docx", "pdf"])
def test_report_docx_pdf_and_integrity_failure(case_db, monkeypatch, file_type):
    monkeypatch.setattr(report_module.case_view, "build_reporting", report_preview)
    monkeypatch.setattr(report_module.report_editing, "export_report", lambda *args, **kwargs: (b"DOC", f"report.{file_type}"))
    service = report_module.ReportService()
    assert service.export("CASE-1", "executive_summary", file_type, "Alice") == (b"DOC", f"report.{file_type}")
    monkeypatch.setattr(report_module.reporting_approval, "approve_reporting_candidate", lambda *args, **kwargs: (_ for _ in ()).throw(report_module.reporting_approval.ReportValidationError("hash mismatch")))
    with pytest.raises(report_module.ReportServiceError) as failed:
        service.confirm_final("CASE-1", {"analyst": "Alice", "run_id": "RUN-1"})
    assert failed.value.code == "REPORT_CONFIRMATION_FAILED"
    assert "hash mismatch" in failed.value.message


def test_triage_ticket_review_edit_and_export(case_db, monkeypatch):
    monkeypatch.setattr(report_module.case_view, "build_reporting", report_preview)
    monkeypatch.setattr(report_module.triage_ticket_editing, "export_report", lambda *args, **kwargs: (b"TICKET", "ticket.pdf"))
    service = report_module.ReportService()
    ticket = service.get_report("CASE-1", "triage_ticket")
    assert ticket["exists"] is True
    saved = service.save_report("CASE-1", "triage_ticket", {
        "analyst": "Alice", "run_id": "RUN-1", "report_set_id": ticket["current_report_set_id"],
        "blocks": [{"type": "paragraph", "text": "Reviewed triage"}],
    })
    assert saved["blocks"][0]["text"] == "Reviewed triage"
    assert service.export("CASE-1", "triage_ticket", "pdf", "Alice") == (b"TICKET", "ticket.pdf")


def test_settings_never_return_secret_and_validate(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    service = settings_module.SettingsService()
    status = service.update({"analyst_name": "Alice", "openai_model": "gpt-4o-mini", "openai_api_key": "sk-test-secret"})
    assert status["openai_configured"] is True
    assert "api_key" not in status
    assert "sk-test-secret" not in json.dumps(status)
    with pytest.raises(settings_module.SettingsError):
        service.update({"openai_model": "bad model name!"})


class FakeCollection:
    def __init__(self):
        self.ids = ["CASE-1"]

    def count(self): return len(self.ids)
    def query(self, **_):
        return {"ids": [["CASE-1"]], "documents": [["malware finding"]], "distances": [[0.1]], "metadatas": [[{"severity": "HIGH"}]]}
    def get(self, **_): return {"ids": list(self.ids)}
    def delete(self, ids): self.ids = [value for value in self.ids if value not in ids]
    def upsert(self, documents, ids, metadatas): self.ids = list(ids)


def test_semantic_search_unavailable_search_and_confirmed_wipe():
    unavailable = search_module.SearchService(collection_factory=lambda _: (_ for _ in ()).throw(RuntimeError()))
    assert unavailable.status()["available"] is False
    collection = FakeCollection()
    service = search_module.SearchService(collection_factory=lambda _: collection)
    assert service.search("malware")["items"][0]["id"] == "CASE-1"
    with pytest.raises(search_module.VectorStoreError):
        service.wipe("soc_incidents", "wrong")
    assert service.wipe("soc_incidents", "WIPE soc_incidents")["vectors"] == 0


@pytest.fixture
def pipeline_db(tmp_path):
    path = tmp_path / "pipeline.db"
    with sqlite3.connect(path) as connection:
        for stage in pipeline_module.PIPELINE_STAGES:
            connection.execute(f"CREATE TABLE {stage} (id TEXT PRIMARY KEY, incident_id TEXT, title TEXT, severity TEXT, stage TEXT, created_at TEXT, summary TEXT, raw_json TEXT)")
        connection.execute("INSERT INTO alerts_to_triage VALUES (?,?,?,?,?,?,?,?)", ("REC-1", "CASE-1", "Alert", "HIGH", "alerts_to_triage", "2026-01-01", "Summary", '{"source":"NW"}'))
        connection.commit()
    return path


def test_pipeline_inspection_export_and_admin_safety(pipeline_db):
    service = pipeline_module.PipelineService(pipeline_db)
    assert service.summary()["stages"][0]["count"] == 1
    assert service.records("alerts_to_triage")["items"][0]["raw"]["source"] == "NW"
    data, filename = service.export_csv("alerts_to_triage", "REC-1")
    assert b"REC-1" in data and filename.endswith(".csv")
    with pytest.raises(pipeline_module.PipelineServiceError):
        service.records("../../secrets")
    with pytest.raises(pipeline_module.PipelineServiceError):
        service.delete_record("alerts_to_triage", "REC-1", "wrong", developer_mode=True)
    result = service.delete_record("alerts_to_triage", "REC-1", "DELETE alerts_to_triage/REC-1", developer_mode=True)
    assert result["deleted"] is True


def test_phase6_routes_and_frontend_are_registered(tmp_path):
    class Chat:
        def ask_global(self, message): return {"message": "ok", "available": True, "case_id": None}

    app = backend.create_app({"TESTING": True, "AEGIS_CHATBOT_SERVICE": Chat()})
    client = app.test_client()
    assert client.post("/api/chat", json={"message": "hello"}).json["message"] == "ok"
    settings = client.get("/api/settings")
    assert settings.status_code == 200 and "openai_api_key" not in settings.json
    for path in ("/frontend/js/pages/chatbot.js", "/frontend/js/pages/reports.js", "/frontend/js/pages/search.js", "/frontend/js/pages/pipeline.js", "/frontend/js/pages/settings.js"):
        assert client.get(path).status_code == 200


def test_case_csv_and_exact_raw_incident_routes(case_db):
    client = backend.create_app({"TESTING": True, "AEGIS_CASE_DB_PATH": case_db}).test_client()
    exported = client.get("/api/cases/export")
    assert exported.status_code == 200 and b"CASE-1" in exported.data
    raw = client.get("/api/cases/CASE-1/raw")
    assert raw.status_code == 200 and raw.json["incident"]["id"] == "CASE-1"


def test_report_routes_final_confirmation_and_download_contracts():
    class Reports:
        def list_reports(self, case_id): return {"case_id": case_id, "reports": []}
        def get_report(self, case_id, report_type): return {"case_id": case_id, "report_type": report_type}
        def save_report(self, case_id, report_type, body): return {"saved": report_type}
        def confirm_section(self, case_id, report_type, body): return {"confirmed": report_type}
        def confirm_final(self, case_id, body): return {"finalized": case_id}
        def export(self, case_id, report_type, file_type, analyst, approved=False): return (b"FILE", f"report.{file_type}")
        def reporting_json(self, case_id): return (b"{}", "data.json")

    client = backend.create_app({"TESTING": True, "AEGIS_REPORT_SERVICE": Reports()}).test_client()
    base = "/api/cases/CASE-1/reports"
    assert client.get(base).status_code == 200
    assert client.get(f"{base}/executive_summary").status_code == 200
    assert client.put(f"{base}/executive_summary", json={}).json["saved"] == "executive_summary"
    assert client.post(f"{base}/executive_summary/confirm", json={}).json["confirmed"] == "executive_summary"
    assert client.post(f"{base}/final/confirm", json={}).json["finalized"] == "CASE-1"
    assert client.get(f"{base}/executive_summary/download?format=docx").data == b"FILE"
    assert client.get(f"{base}/executive_summary/download?format=pdf").data == b"FILE"
    assert client.get(f"{base}/data/download").data == b"{}"
