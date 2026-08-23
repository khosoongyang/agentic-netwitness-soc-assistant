from __future__ import annotations

import json
import importlib.util
import sys
from pathlib import Path

import pytest

import workflow_state_store as state_store


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "_aegis_phase5_backend"


def _load_canonical_backend():
    existing = sys.modules.get(PACKAGE_NAME)
    if existing is not None:
        return existing
    package_dir = PROJECT_ROOT / "backend"
    spec = importlib.util.spec_from_file_location(
        PACKAGE_NAME,
        package_dir / "__init__.py",
        submodule_search_locations=[str(package_dir)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load the canonical Aegis backend")
    module = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE_NAME] = module
    spec.loader.exec_module(module)
    return module


_load_canonical_backend()
import_module = __import__
import_service_module = import_module(
    f"{PACKAGE_NAME}.services.import_service", fromlist=["ImportService", "ImportServiceError"]
)
sync_service_module = import_module(
    f"{PACKAGE_NAME}.services.sync_service", fromlist=["SyncService", "upsert_incidents"]
)
ImportService = import_service_module.ImportService
ImportServiceError = import_service_module.ImportServiceError
SyncService = sync_service_module.SyncService
upsert_incidents = sync_service_module.upsert_incidents


@pytest.fixture
def isolated_case_db(tmp_path, monkeypatch):
    monkeypatch.setattr(state_store, "DB_FILE", tmp_path / "cases.db")
    return tmp_path / "cases.db"


def test_incident_sync_and_duplicate_merge_preserve_workflow_state(isolated_case_db):
    first = upsert_incidents([{"id": "INC-1", "title": "First", "riskScore": 80, "status": "OPEN"}])
    with state_store.db_connect() as connection:
        connection.execute("UPDATE incidents SET workflow_status='Awaiting Approval', run_id='RUN-1' WHERE id='INC-1'")
        connection.commit()
    second = upsert_incidents([{"id": "INC-1", "title": "Updated", "riskScore": 95, "status": "CLOSED"}])
    with state_store.db_connect() as connection:
        row = connection.execute("SELECT * FROM incidents WHERE id='INC-1'").fetchone()
    assert first == {"fetched": 1, "added": 1, "updated": 0, "skipped": 0}
    assert second == {"fetched": 1, "added": 0, "updated": 1, "skipped": 0}
    assert row["title"] == "Updated"
    assert row["severity"] == "CRITICAL"
    assert row["workflow_status"] == "Awaiting Approval"
    assert row["run_id"] == "RUN-1"


def test_sync_service_retrieves_then_merges(isolated_case_db):
    class Integration:
        def enriched_incidents(self, **kwargs):
            return [{"incidentId": "INC-2", "title": "Remote"}]

    result = SyncService(Integration()).synchronize(limit=10)
    assert result["added"] == 1
    assert result["warnings"] == []


@pytest.mark.parametrize("filename,content", [
    ("incident.json", b'{"id":"JSON-1","title":"JSON incident"}'),
    ("incident.csv", b'id,title\nCSV-1,CSV incident\n'),
    ("incident.txt", b'2026-01-01 suspicious connection from 192.0.2.10'),
    ("incident.log", b'2026-01-01 malware detected on endpoint'),
])
def test_supported_uploads_are_normalized_and_stored(tmp_path, isolated_case_db, filename, content):
    service = ImportService(tmp_path / "uploads")
    result = service.import_file(filename, content)
    assert result["incident_id"]
    assert result["summary"]["added"] == 1
    stored = list((tmp_path / "uploads").iterdir())
    assert len(stored) == 1
    assert stored[0].name != filename


def test_unsupported_and_malformed_uploads(tmp_path, isolated_case_db):
    service = ImportService(tmp_path / "uploads")
    with pytest.raises(ImportServiceError) as unsupported:
        service.import_file("incident.exe", b"data")
    assert unsupported.value.code == "IMPORT_UNSUPPORTED_TYPE"
    with pytest.raises(ImportServiceError) as malformed:
        service.import_file("incident.json", b"{not-json")
    assert malformed.value.code == "IMPORT_INVALID"
    assert not (tmp_path / "uploads").exists()


def test_import_identity_mismatch_is_rejected_before_storage(tmp_path, isolated_case_db):
    service = ImportService(tmp_path / "uploads")
    with pytest.raises(ImportServiceError) as caught:
        service.import_file(
            "incident.json",
            json.dumps({"id": "INC-A", "title": "A"}).encode(),
            expected_incident_id="INC-B",
        )
    assert caught.value.status_code == 409
    assert not (tmp_path / "uploads").exists()
