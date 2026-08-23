"""Smoke tests for the canonical Aegis Flask application shell."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_canonical_app_factory():
    """Load root backend despite the legacy reporting package's same name."""
    package_name = "_aegis_canonical_backend"
    package_dir = PROJECT_ROOT / "backend"
    spec = importlib.util.spec_from_file_location(
        package_name,
        package_dir / "__init__.py",
        submodule_search_locations=[str(package_dir)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load the canonical Aegis backend")
    module = importlib.util.module_from_spec(spec)
    sys.modules[package_name] = module
    spec.loader.exec_module(module)
    return module.create_app


create_app = _load_canonical_app_factory()


@pytest.fixture
def app() -> Flask:
    flask_app = create_app()
    flask_app.config.update(TESTING=True)
    return flask_app


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


def test_health_endpoint(client: FlaskClient) -> None:
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "application": "Aegis"}


def test_frontend_index_loads(client: FlaskClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert b"Aegis" in response.data
    assert b"Canonical Aegis application" in response.data
    assert b"Overview" in response.data
    assert b"Cases" in response.data
    assert b'type="module"' in response.data


def test_frontend_css_loads(client: FlaskClient) -> None:
    response = client.get("/frontend/css/app.css")

    assert response.status_code == 200
    assert response.mimetype == "text/css"
    assert b"--surface" in response.data


def test_frontend_javascript_loads(client: FlaskClient) -> None:
    response = client.get("/frontend/js/app.js")

    assert response.status_code == 200
    assert b"aegisShell" in response.data


def test_workspace_uses_backend_actions_and_bounded_polling(client: FlaskClient) -> None:
    response = client.get("/frontend/js/pages/workspace.js")

    assert response.status_code == 200
    assert b'data-workflow-action' in response.data
    assert b'method: "POST"' in response.data
    assert b"MAX_POLL_ATTEMPTS" in response.data
    assert b"window.confirm" in response.data


@pytest.mark.parametrize(
    ("path", "marker"),
    [
        ("/frontend/css/layout.css", b".app-shell"),
        ("/frontend/css/components.css", b".stage-card"),
        ("/frontend/js/api.js", b"fetchJSON"),
        ("/frontend/js/router.js", b"pushState"),
        ("/frontend/js/pages/overview.js", b"/api/dashboard"),
        ("/frontend/js/pages/cases.js", b"/api/cases"),
        ("/frontend/js/pages/workspace.js", b"/workflow"),
    ],
)
def test_modular_frontend_assets_load(
    client: FlaskClient, path: str, marker: bytes
) -> None:
    response = client.get(path)

    assert response.status_code == 200
    assert marker in response.data
