# ==============================================================================
# [FYP-FILE] File: soc_reporting_agent/backend/error_handling.py
# Important dependencies: __future__, backend, flask, functools, json, pathlib, psycopg2, typing.
#
# Purpose:
#   Shared error-handling utilities for the SOC Reporting subsystem's Flask
#   API layer (backend/app.py). Provides a single, analyst-friendly JSON
#   error contract so that every "/api/..." endpoint returns a consistent
#   shape (success flag, error_code, severity, title, message, analyst_action,
#   details, recoverable) regardless of what internal exception caused the
#   failure, instead of leaking raw Python tracebacks to the dashboard.
#
# Main functionalities:
#   - ApiError: [FYP-ERROR] typed exception analysts/handlers can raise to
#     produce a specific, well-formed error response (code/status/severity/
#     analyst_action/details/recoverable) instead of a generic 500.
#   - error_payload / api_error: build the JSON error body (and Flask
#     response tuple) that every failure path converges on.
#   - safe_load_json_file / safe_write_json_file: [FYP-ERROR] [FYP-FALLBACK]
#     tolerant JSON file I/O helpers used across backend/app.py for reading
#     agent input/output files, raising ApiError with actionable messages
#     for missing/empty/malformed files instead of a bare exception.
#   - api_guard: [FYP-ERROR] [FYP-FALLBACK] [FYP-EVALUATOR] decorator that
#     wraps a Flask view function, catching ApiError/KeyError/ValueError/
#     PostgresUnavailableError/psycopg2.Error/Exception (in that priority
#     order) and converting each into the standard error JSON contract with
#     an appropriate HTTP status code, error_code, and analyst_action.
#   - install_api_guards: applies api_guard to every already-registered
#     Flask view function whose route starts with "/api/", once, at app
#     start-up -- this is what actually turns the error contract on for the
#     whole API surface without hand-decorating every route.
#
# Inputs:
#   - Exceptions raised anywhere inside a guarded view function (ApiError,
#     KeyError, ValueError, PostgresUnavailableError, psycopg2.Error, or any
#     other Exception).
#   - Path | str for the JSON file helpers.
#   - app: Flask -- the application instance, for install_api_guards.
#
# Outputs:
#   - error_payload()/api_error(): dict / (Flask Response, status_code)
#     tuple with the standard error contract described above.
#   - safe_load_json_file(): parsed JSON (Any) or `default` if optional and
#     missing/empty.
#   - install_api_guards(): no return value; mutates app.view_functions in
#     place, wrapping each "/api/*" view with api_guard exactly once
#     (tracked via a `_api_guarded` attribute to avoid double-wrapping).
#
# Workflow position:
#   Cross-cutting infrastructure, not a pipeline stage. install_api_guards()
#   runs once during Flask app construction in backend/app.py; ApiError /
#   safe_load_json_file / safe_write_json_file are used throughout request
#   handling in every route.
#
# Called by:
#   - soc_reporting_agent/backend/app.py
#     (`from backend.error_handling import api_error, install_api_guards,
#     safe_load_json_file, safe_write_json_file`) -- install_api_guards(app)
#     is invoked once at module load time to wrap all "/api/*" routes;
#     safe_load_json_file/safe_write_json_file and api_error are used
#     directly throughout route handlers.
#
# Calls:
#   - soc_reporting_agent/backend/postgres_casework_store.py
#     (`PostgresUnavailableError`) -- imported so api_guard can recognise and
#     specially handle a Postgres-outage condition.
#   - psycopg2 (third-party) -- for psycopg2.Error handling.
#   - flask (third-party) -- jsonify/request.
#
# Key evaluator search terms:
#   ApiError, api_guard, error-handling wrapper, install_api_guards,
#   POSTGRES_UNAVAILABLE, UNHANDLED_BACKEND_ERROR, analyst_action.
# ==============================================================================

from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Any, Callable

import psycopg2
from flask import jsonify, request

from backend.postgres_casework_store import PostgresUnavailableError


# =============================================================================
# [FYP-SECTION] REPORTING BACKEND AND API EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================


class ApiError(Exception):
    """[FYP-CLASS] [FYP-ERROR] Typed, structured API error.

    Raise this anywhere inside a guarded view function (or a helper it
    calls, e.g. safe_load_json_file) to produce a specific, analyst-friendly
    JSON error response instead of a bare 500.
    Fields:
      message -- the underlying error text (also becomes the exception str).
      code -- machine-readable error_code (default "API_ERROR").
      status_code -- HTTP status to return (default 400).
      title -- display title; defaults to a title-cased version of `code`.
      severity -- "warning" | "critical" | ... (UI styling hint).
      analyst_action -- what the analyst should do next (default: generic
        "review and retry" guidance).
      details -- extra structured context (e.g. file path, JSON line/col).
      recoverable -- whether retrying is expected to help.
    Called by: any backend/app.py route or helper that wants a specific
    error response; caught by api_guard() below, which converts it to the
    standard JSON error contract via api_error().
    """
    # [FYP-FUNCTION] `__init__` — implements the init operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `message`, `code`, `status_code`, `title`, `severity`, `analyst_action`, `details`, `recoverable`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/error_handling.py:__init__, workflow_state_store.py:__init__; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `__init__`, `replace`, `super`, `title`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def __init__(
        self,
        message: str,
        *,
        code: str = "API_ERROR",
        status_code: int = 400,
        title: str | None = None,
        severity: str = "warning",
        analyst_action: str = "Review the request and try again.",
        details: dict[str, Any] | None = None,
        recoverable: bool = True,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.title = title or code.replace("_", " ").title()
        self.severity = severity
        self.analyst_action = analyst_action
        self.details = details or {}
        self.recoverable = recoverable


def error_payload(
    message: str,
    *,
    code: str = "API_ERROR",
    title: str | None = None,
    severity: str = "warning",
    analyst_action: str = "Review the request and try again.",
    details: dict[str, Any] | None = None,
    recoverable: bool = True,
) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-ERROR] Build the standard JSON error-response body dict (the shape every "/api/*" failure returns).

    Params: same fields as ApiError (see class docstring). Returns: dict
    with success=False plus error_code/severity/title/message/status/
    analyst_action/details/recoverable. `status` duplicates `message` for
    older frontend code that reads a plain `status` string.
    Called by: api_error() below.
    """
    return {
        "success": False,
        "error_code": code,
        "severity": severity,
        "title": title or code.replace("_", " ").title(),
        "message": message,
        "status": message,
        "analyst_action": analyst_action,
        "details": details or {},
        "recoverable": recoverable,
    }


def api_error(
    message: str,
    status_code: int = 400,
    *,
    code: str = "API_ERROR",
    title: str | None = None,
    severity: str = "warning",
    analyst_action: str = "Review the request and try again.",
    details: dict[str, Any] | None = None,
    recoverable: bool = True,
):
    """[FYP-FUNCTION] [FYP-ERROR] Build the Flask (jsonify(error_payload), status_code) response tuple that a route can `return` directly.

    Params: same as error_payload(), plus status_code (HTTP status).
    Returns: tuple[Response, int] suitable for a Flask view to return.
    Called by: backend/app.py routes directly (for explicit error returns),
    and by api_guard() below (to convert caught exceptions).
    Calls: error_payload, flask.jsonify.
    """
    return jsonify(error_payload(
        message,
        code=code,
        title=title,
        severity=severity,
        analyst_action=analyst_action,
        details=details,
        recoverable=recoverable,
    )), status_code


def safe_load_json_file(path: Path | str, *, default: Any = None, required: bool = False, label: str = "JSON file") -> Any:
    """[FYP-FUNCTION] [FYP-ERROR] [FYP-FALLBACK] Read and parse a JSON file, converting common failure modes into ApiError with actionable analyst guidance.

    Params: path -- file to read; default -- value to return when the file
    is missing/empty and NOT required; required -- if True, missing/empty
    raises ApiError instead of returning default; label -- human label used
    in error messages (e.g. "Investigation result").
    Returns: parsed JSON value, or `default` for an optional missing/empty
    file.
    [FYP-FALLBACK] behaviour:
      - missing file, not required -> return default (no error).
      - missing file, required -> ApiError MISSING_INPUT_FILE, telling the
        analyst to run the previous workflow step first.
      - empty file, not required -> return default.
      - empty file, required -> ApiError EMPTY_INPUT_FILE, telling the
        analyst to re-run the previous agent.
      - malformed JSON -> ApiError MALFORMED_JSON with the exact line/column
        from the JSONDecodeError, telling the analyst to fix or regenerate
        the file.
    Called by: backend/app.py, wherever an agent's JSON output file needs to
    be read as part of building a response or preparing the next stage's
    input.
    """
    path = Path(path)
    if not path.exists():
        if required:
            raise ApiError(
                f"{label} was not found: {path.name}",
                code="MISSING_INPUT_FILE",
                title="Missing input file",
                analyst_action="Run the previous workflow step first, then retry this action.",
                details={"path": str(path)},
            )
        return default
    try:
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            if required:
                raise ApiError(
                    f"{label} is empty: {path.name}",
                    code="EMPTY_INPUT_FILE",
                    title="Empty input file",
                    analyst_action="Re-run the previous agent so it writes a complete output file.",
                    details={"path": str(path)},
                )
            return default
        return json.loads(text)
    except ApiError:
        raise
    except json.JSONDecodeError as exc:
        raise ApiError(
            f"{label} contains malformed JSON: {exc}",
            code="MALFORMED_JSON",
            title="Malformed JSON",
            analyst_action="Open the agent output, fix or regenerate the malformed JSON, then retry.",
            details={"path": str(path), "line": exc.lineno, "column": exc.colno},
        )


def safe_write_json_file(path: Path | str, payload: Any) -> None:
    """[FYP-FUNCTION] [FYP-OUTPUT] Write `payload` as pretty-printed JSON to path, creating parent directories as needed. No error translation -- I/O errors propagate to api_guard()."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def api_guard(fn: Callable[..., Any]) -> Callable[..., Any]:
    """[FYP-FUNCTION] [FYP-ERROR] [FYP-FALLBACK] [FYP-EVALUATOR] Decorator: wrap a Flask view function with the standard analyst-facing error contract.

    Params: fn -- the Flask view function to wrap.
    Returns: a wrapper function (same call signature) that runs fn and, on
    exception, returns api_error(...) instead of letting Flask's default
    error handling surface a raw traceback/500.
    [FYP-FALLBACK] exception-to-response mapping, checked in this priority
    order:
      1. ApiError -> use its own code/status_code/title/severity/
         analyst_action/details/recoverable verbatim (the "explicit,
         intentional error" path).
      2. KeyError -> 404 NOT_FOUND ("Record not found"); tells the analyst
         to refresh the ticket list.
      3. ValueError -> 400 INVALID_REQUEST ("Invalid request"); tells the
         analyst to check form values.
      4. PostgresUnavailableError -> 503 POSTGRES_UNAVAILABLE, severity
         "critical" (SQLite fallback is explicitly disabled for this
         subsystem -- see message); tells the analyst to start Postgres or
         fix POSTGRES_DSN.
      5. psycopg2.Error -> 500 DATABASE_WRITE_FAILED, severity "critical";
         warns the analyst NOT to blindly repeat risky actions and to check
         the activity log first (a failed DB write may have partially
         applied).
      6. Any other Exception -> 500 UNHANDLED_BACKEND_ERROR, severity
         "critical"; generic "capture this message, check backend logs"
         guidance -- the last-resort catch-all so no route can ever return a
         raw Python traceback to the dashboard.
    Called by: api_guard() itself is applied automatically to every "/api/*"
    view by install_api_guards() (below) at app start-up; it is the central
    error-handling wrapper for this subsystem's entire API surface.
    Calls: api_error.
    """
    # [FYP-FUNCTION] `wrapper` — implements the wrapper operation used by the surrounding reporting backend and API workflow.
    # [FYP-INPUT] Parameters: `*args`, `**kwargs`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `api_error`, `fn`, `str`, `strip`.
    # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        try:
            return fn(*args, **kwargs)
        except ApiError as exc:
            return api_error(
                exc.message,
                exc.status_code,
                code=exc.code,
                title=exc.title,
                severity=exc.severity,
                analyst_action=exc.analyst_action,
                details=exc.details,
                recoverable=exc.recoverable,
            )
        except KeyError as exc:
            return api_error(
                str(exc).strip("'"),
                404,
                code="NOT_FOUND",
                title="Record not found",
                analyst_action="Refresh the ticket list and confirm the ticket, alert, or recommendation still exists.",
            )
        except ValueError as exc:
            return api_error(
                str(exc),
                400,
                code="INVALID_REQUEST",
                title="Invalid request",
                analyst_action="Check the form values and try again.",
            )
        except PostgresUnavailableError as exc:
            return api_error(
                "PostgreSQL is required. SQLite fallback is disabled.",
                503,
                code="POSTGRES_UNAVAILABLE",
                title="PostgreSQL unavailable",
                severity="critical",
                analyst_action="Start PostgreSQL or fix POSTGRES_DSN, then retry.",
                details={"error": str(exc)},
                recoverable=True,
            )
        except psycopg2.Error as exc:
            return api_error(
                str(exc),
                500,
                code="DATABASE_WRITE_FAILED",
                title="Database operation failed",
                severity="critical",
                analyst_action="Do not repeat risky analyst actions. Refresh the dashboard and check the activity log before retrying.",
                recoverable=True,
            )
        except Exception as exc:
            return api_error(
                str(exc),
                500,
                code="UNHANDLED_BACKEND_ERROR",
                title="Backend error",
                severity="critical",
                analyst_action="Capture this message, check backend logs, then retry after the issue is fixed.",
                recoverable=True,
            )
    return wrapper


def install_api_guards(app) -> None:
    """[FYP-FUNCTION] [FYP-ERROR] [FYP-API] Wrap JSON API endpoints with a consistent analyst-friendly error contract.

    Params: app -- the Flask application instance.
    Returns: None. Side effect: mutates app.view_functions in place.
    Behaviour: iterates every currently-registered view function; for each
    whose URL rule(s) start with "/api/", wraps it with api_guard() UNLESS
    it has already been guarded (tracked via a `_api_guarded` attribute set
    on the wrapper, so calling this twice is safe/idempotent). Views not
    under "/api/" (e.g. the dashboard's HTML/static routes) are left
    untouched.
    Called by: soc_reporting_agent/backend/app.py, once at module load time
    (`install_api_guards(app)`), immediately after all routes are defined.
    Calls: api_guard.
    """
    for endpoint, view in list(app.view_functions.items()):
        rule_paths = [rule.rule for rule in app.url_map.iter_rules(endpoint)]
        if not any(path.startswith("/api/") for path in rule_paths):
            continue
        if getattr(view, "_api_guarded", False):
            continue
        guarded = api_guard(view)
        setattr(guarded, "_api_guarded", True)
        app.view_functions[endpoint] = guarded
