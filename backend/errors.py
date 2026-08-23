"""Shared JSON API error types and handlers."""

from __future__ import annotations

from dataclasses import dataclass

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException


@dataclass
class APIError(Exception):
    code: str
    message: str
    status_code: int = 400


class CaseNotFoundError(APIError):
    def __init__(self) -> None:
        super().__init__("CASE_NOT_FOUND", "Case was not found.", 404)


class InvalidQueryError(APIError):
    def __init__(self, message: str) -> None:
        super().__init__("INVALID_QUERY", message, 400)


class DataStoreUnavailableError(APIError):
    def __init__(self) -> None:
        super().__init__(
            "DATA_STORE_UNAVAILABLE",
            "The Aegis case data store is unavailable.",
            503,
        )


def install_error_handlers(app: Flask) -> None:
    """Install the consistent API error contract without exposing traces."""

    @app.errorhandler(APIError)
    def handle_api_error(error: APIError):
        return jsonify({"error": {"code": error.code, "message": error.message}}), error.status_code

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        if not request.path.startswith("/api/"):
            if isinstance(error, HTTPException):
                return error
            raise error

        if isinstance(error, HTTPException):
            code = error.code or 500
            return jsonify({
                "error": {
                    "code": "NOT_FOUND" if code == 404 else "HTTP_ERROR",
                    "message": error.description,
                }
            }), code

        app.logger.exception("Unhandled Aegis API error", exc_info=error)
        return jsonify({
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "The request could not be completed.",
            }
        }), 500
