"""Minimal Flask application factory for Aegis."""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, send_from_directory

from .errors import install_error_handlers
from .routes import api_blueprint
from .routes.activity import activity_blueprint
from .routes.cases import cases_blueprint
from .routes.chatbot import chatbot_blueprint
from .routes.dashboard import dashboard_blueprint
from .routes.admin_pipeline import pipeline_blueprint
from .routes.imports import imports_blueprint
from .routes.netwitness import netwitness_blueprint
from .routes.reports import reports_blueprint
from .routes.search import search_blueprint
from .routes.settings import settings_blueprint
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
    # Global request-body cap (Phase 10 hardening): most routes already
    # enforce their own tighter limit (uploads: 5MB, chat: 8000 chars,
    # report blocks: 500 x 200KB each) before touching the body, but a few
    # simple JSON routes (e.g. settings) have none - this bounds worst-case
    # memory use for any route without one, well above normal request
    # sizes so it never rejects legitimate use.
    app.config.setdefault("MAX_CONTENT_LENGTH", 20 * 1024 * 1024)
    if test_config:
        app.config.update(test_config)
    app.register_blueprint(api_blueprint)
    app.register_blueprint(dashboard_blueprint)
    app.register_blueprint(cases_blueprint)
    app.register_blueprint(workflow_blueprint)
    app.register_blueprint(netwitness_blueprint)
    app.register_blueprint(imports_blueprint)
    app.register_blueprint(chatbot_blueprint)
    app.register_blueprint(reports_blueprint)
    app.register_blueprint(settings_blueprint)
    app.register_blueprint(search_blueprint)
    app.register_blueprint(pipeline_blueprint)
    app.register_blueprint(activity_blueprint)
    install_error_handlers(app)
    _install_agent_activity(app)

    @app.get("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    return app


def _install_agent_activity(app: Flask) -> None:
    """Install Agent Activity instrumentation (runtime pass-through wrappers;
    see observability/__init__.py). Skipped for test apps and pytest runs
    unless AGENT_ACTIVITY_INSTRUMENTATION is set explicitly, so the shared
    test process never writes to the real soc_db/agent_activity.db. Any
    failure leaves the workflow un-instrumented and the app fully working."""
    enabled = app.config.get("AGENT_ACTIVITY_INSTRUMENTATION")
    if enabled is None:
        enabled = not app.config.get("TESTING") and "PYTEST_CURRENT_TEST" not in os.environ
    if not enabled:
        return
    try:
        import observability

        state = observability.install(app.config.get("AGENT_ACTIVITY_DB_PATH"))
        if not state.get("enabled"):
            app.logger.warning("Agent Activity not enabled: %s", state.get("error"))
    except Exception as exc:  # pragma: no cover - defensive
        app.logger.warning("Agent Activity not enabled: %s", exc)
