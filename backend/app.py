"""Minimal Flask application factory for Aegis."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, send_from_directory

from .errors import install_error_handlers
from .routes import api_blueprint
from .routes.cases import cases_blueprint
from .routes.dashboard import dashboard_blueprint
from .routes.imports import imports_blueprint
from .routes.netwitness import netwitness_blueprint
from .routes.workflow import workflow_blueprint


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = PROJECT_ROOT / "frontend"


def create_app(test_config: dict | None = None) -> Flask:
    """Create the canonical Aegis Flask application shell."""
    app = Flask(
        "aegis",
        static_folder=str(FRONTEND_DIR),
        static_url_path="/frontend",
    )
    if test_config:
        app.config.update(test_config)
    app.register_blueprint(api_blueprint)
    app.register_blueprint(dashboard_blueprint)
    app.register_blueprint(cases_blueprint)
    app.register_blueprint(workflow_blueprint)
    app.register_blueprint(netwitness_blueprint)
    app.register_blueprint(imports_blueprint)
    install_error_handlers(app)

    @app.get("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    return app
