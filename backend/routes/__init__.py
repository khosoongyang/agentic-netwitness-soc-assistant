"""HTTP routes for the canonical Aegis backend."""

from flask import Blueprint, jsonify


api_blueprint = Blueprint("api", __name__, url_prefix="/api")


@api_blueprint.get("/health")
def health():
    """Return a minimal, non-sensitive application health response."""
    return jsonify({"status": "ok", "application": "Aegis"})
