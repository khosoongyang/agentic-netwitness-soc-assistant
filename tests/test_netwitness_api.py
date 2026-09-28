from __future__ import annotations

import io
import importlib.util
import sys
from pathlib import Path

from integrations.netwitness import NetWitnessError


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


canonical_backend = _load_canonical_backend()
create_app = canonical_backend.create_app
ImportService = __import__(
    f"{PACKAGE_NAME}.services.import_service", fromlist=["ImportService"]
).ImportService


class FakeNetWitnessService:
    def __init__(self):
        self.login_body = None

    def status(self):
        return {
            "configured": True,
            "authenticated": True,
            "verified": True,
            "base_url": "https://nw.example",
            "username_configured": True,
            "auth_style": "Bearer",
            "verify_tls": True,
            "ca_certificate_configured": False,
        }

    def login(self, body):
        self.login_body = body
        return self.status()

    def set_token(self, body):
        return self.status()

    def test(self):
        return {"connected": True, **self.status()}

    def incidents(self, **kwargs):
        return {"items": [{"id": "INC-1"}], "page": kwargs["page"], "limit": kwargs["limit"]}

    def incident(self, incident_id):
        return {"id": incident_id}

    def alerts(self, incident_id):
        return [{"id": "A-1", "incident_id": incident_id}]

    def alert(self, alert_id):
        return {"id": alert_id}


class FakeSyncService:
    def synchronize(self, **kwargs):
        return {"fetched": 1, "added": 1, "updated": 0, "skipped": 0, "warnings": []}


class FailingService(FakeNetWitnessService):
    def test(self):
        raise NetWitnessError("NETWITNESS_UNREACHABLE", "NetWitness could not be reached.", 503)


def client(service=None, **config):
    settings = {"TESTING": True, "AEGIS_NETWITNESS_SERVICE": service or FakeNetWitnessService()}
    settings.update(config)
    return create_app(settings).test_client()


def test_netwitness_routes_and_secret_redaction():
    service = FakeNetWitnessService()
    http = client(service, AEGIS_SYNC_SERVICE=FakeSyncService())
    response = http.post("/api/integrations/netwitness/login", json={
        "base_url": "https://nw.example", "username": "analyst", "password": "never-return-this",
    })
    assert response.status_code == 200
    assert b"never-return-this" not in response.data
    assert b"token" not in response.data.lower()
    assert http.post("/api/integrations/netwitness/token", json={"token": "hidden"}).status_code == 200
    assert http.post("/api/integrations/netwitness/test", json={}).status_code == 200
    assert http.get("/api/integrations/netwitness/incidents?limit=10").json["items"][0]["id"] == "INC-1"
    assert http.get("/api/integrations/netwitness/incidents/INC-1").status_code == 200
    assert http.get("/api/integrations/netwitness/incidents/INC-1/alerts").status_code == 200
    assert http.get("/api/integrations/netwitness/alerts/A-1").status_code == 200
    assert http.post("/api/integrations/netwitness/sync", json={}).json["added"] == 1


def test_netwitness_error_contract():
    response = client(FailingService()).post("/api/integrations/netwitness/test", json={})
    assert response.status_code == 503
    assert response.json == {"error": {"code": "NETWITNESS_UNREACHABLE", "message": "NetWitness could not be reached."}}


def test_integration_frontend_is_served_without_browser_secret_storage():
    http = client()
    index = http.get("/")
    script = http.get("/frontend/js/pages/integrations.js")
    assert index.status_code == 200
    assert b'data-nav="integrations"' in index.data
    assert script.status_code == 200
    assert b'type="password"' in script.data
    assert b"localStorage" not in script.data
    assert b"sessionStorage" not in script.data


def test_import_route_uses_structured_errors(tmp_path):
    http = client(AEGIS_IMPORT_SERVICE=ImportService(tmp_path))
    response = http.post("/api/imports/incidents", data={
        "file": (io.BytesIO(b"payload"), "incident.exe"),
    })
    assert response.status_code == 400
    assert response.json["error"]["code"] == "IMPORT_UNSUPPORTED_TYPE"
