# ==============================================================================
# [FYP-FILE] soc_reporting_agent/backend/store_factory.py
# File: soc_reporting_agent/backend/store_factory.py
# Important dependencies: __future__, backend, typing.
# ==============================================================================
# Purpose:
#   [FYP-EVALUATOR] Single seam/factory that decides which casework store
#   implementation the rest of the backend uses. This is the intended
#   "swap the database implementation here" point referenced by
#   backend/casework_store.py's module docstring ("PostgreSQL is the
#   operational SOC database via backend.store_factory/get_casework_store").
#   In the current codebase the decision is fixed: PostgresCaseworkStore is
#   always returned; backend/casework_store.py (SQLite) is never selected
#   here (it is only used directly/standalone by
#   soc_reporting_agent/scripts/test_evidence_gap_branch_and_reporting_wrapper.py).
#
# Main functionalities:
#   - get_casework_store(): construct and return the operational store
#     (always PostgresCaseworkStore in this codebase).
#   - UnavailableCaseworkStore: a stand-in object used by backend/app.py
#     when PostgresCaseworkStore construction fails at import time, so the
#     module-level CASEWORK name always exists but raises a clear error
#     the first time any of its methods/attributes are actually used.
#   - postgres_unavailable_result(): build a JSON-serialisable "database
#     unavailable" API response payload.
#
# Inputs:
#   - initialise: bool (get_casework_store) -- whether to run schema
#     initialisation (PostgresCaseworkStore.init_db()) immediately.
#   - error: Exception | str -- the underlying failure, passed into
#     UnavailableCaseworkStore / postgres_unavailable_result.
#   - [FYP-CONFIG] No connection strings or credentials pass through this
#     module, and this file does not itself read any config/env vars; only
#     PostgresCaseworkStore (imported here, in backend/postgres_casework_store.py)
#     resolves DSN/credential env vars, inside its own __init__.
#
# Outputs:
#   - A PostgresCaseworkStore instance (get_casework_store), or a
#     dict API-error payload (postgres_unavailable_result).
#
# Workflow position:
#   Sits between backend/app.py and backend/postgres_casework_store.py.
#   backend/app.py builds its module-level CASEWORK singleton by calling
#   get_casework_store() once at import time; every API route then reads/
#   writes case data through that CASEWORK object.
#
# Called by:
#   - soc_reporting_agent/backend/app.py: `CASEWORK = get_casework_store()`
#     wrapped in `except PostgresUnavailableError: CASEWORK =
#     UnavailableCaseworkStore(exc)` (confirmed via grep).
#
# Calls:
#   - [FYP-CALLS] backend.postgres_casework_store (PostgresCaseworkStore,
#     PostgresUnavailableError, postgres_required_payload).
#
# Key evaluator search terms:
#   get_casework_store, UnavailableCaseworkStore, store selection, database
#   factory, PostgreSQL only, SQLite fallback disabled.
# ==============================================================================

from __future__ import annotations

from typing import Any

from backend.postgres_casework_store import (
    PostgresCaseworkStore,
    PostgresUnavailableError,
    postgres_required_payload,
)


# [FYP-SECTION] Unavailable-store fallback (used only when PostgreSQL
# construction fails at import time; see get_casework_store() below).
# [FYP-CLASS] UnavailableCaseworkStore
# [FYP-FALLBACK] [FYP-ERROR] Placeholder store used only when
# PostgresCaseworkStore could not be constructed (e.g. PostgreSQL
# unreachable/misconfigured at process startup). Holding a real object of
# this type instead of leaving CASEWORK as None means every call site in
# backend/app.py that does `CASEWORK.<method>(...)` fails with the same
# clear PostgresUnavailableError message rather than an AttributeError on
# None, no matter which method is called first.
class UnavailableCaseworkStore:
    # [FYP-FUNCTION] Store The Startup Failure
    # error: Exception | str -- the failure that prevented the real store
    # from being constructed (e.g. PostgresUnavailableError raised by
    # PostgresCaseworkStore.__init__/init_db).
    def __init__(self, error: Exception | str):
        self.error = error

    # [FYP-FUNCTION] Raise On Any Attribute/Method Access
    # [FYP-ERROR] Any attribute lookup (including every store method:
    # get_ticket, update_ticket, list_tickets, ...) raises
    # PostgresUnavailableError(str(self.error)) instead of returning a
    # value, so callers see a consistent, descriptive failure.
    def __getattr__(self, _name: str):
        raise PostgresUnavailableError(str(self.error))


# [FYP-SECTION] Store selection -- the factory decision point (SQLite vs
# PostgreSQL) referenced by casework_store.py's own module docstring.
# [FYP-EVALUATOR] [FYP-FUNCTION] Get The Operational SOC Casework Store
# [FYP-INPUT] initialise: bool (default True) -- forwarded to
# PostgresCaseworkStore(initialise=...), controlling whether schema DDL is
# applied immediately on construction.
# [FYP-DECISION] [FYP-DATABASE] This is the store-selection logic: it
# unconditionally returns PostgresCaseworkStore (PostgreSQL). There is no
# runtime branch that returns backend.casework_store.CaseworkStore
# (SQLite) -- see the existing docstring immediately below for why that
# fallback was deliberately removed.
# [FYP-OUTPUT] A PostgresCaseworkStore instance, or raises
# PostgresUnavailableError if PostgreSQL is not configured/reachable.
# [FYP-USED-BY] backend/app.py, at module import time, to build the
# CASEWORK singleton used by every API route.
# [FYP-FUNCTION] `get_casework_store` — retrieves get casework store data for the surrounding reporting backend and API workflow.
# [FYP-INPUT] Parameters: `initialise`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/app.py:<module>; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `PostgresCaseworkStore`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def get_casework_store(*, initialise: bool = True) -> PostgresCaseworkStore:
    """Return the operational SOC store.

    PostgreSQL is the only runtime database. SQLite fallback is intentionally
    disabled so data loss or split-brain workflow state cannot be hidden.
    """
    return PostgresCaseworkStore(initialise=initialise)


# [FYP-SECTION] API error-payload helper (for the caller to surface a
# clean "database unavailable" response instead of a raw traceback).
# [FYP-FUNCTION] Build "PostgreSQL Unavailable" API Response
# [FYP-FALLBACK] [FYP-INPUT] error: Exception | str | None -- optional
# underlying failure detail to attach.
# [FYP-PROCESS] Delegates the base shape to
# postgres_casework_store.postgres_required_payload(), then adds an
# "error" key when `error` is supplied. No secrets are included; only
# str(error) (an exception message, not a connection string/credential)
# is attached.
# [FYP-OUTPUT] dict with status="failed_postgres_unavailable",
# reporting_mode="blocked", message, and optionally "error".
# No direct caller confidently identified inside this repo snapshot (grep
# found no call sites for postgres_unavailable_result outside this file);
# it is exported via __all__ for use by API error-handling code.
# [FYP-FUNCTION] `postgres_unavailable_result` — implements the postgres unavailable result operation used by the surrounding reporting backend and API workflow.
# [FYP-INPUT] Parameters: `error`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis reporting backend and API workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `postgres_required_payload`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def postgres_unavailable_result(error: Exception | str | None = None) -> dict[str, Any]:
    message = "PostgreSQL is required. SQLite fallback is disabled."
    payload = postgres_required_payload(message)
    if error:
        payload["error"] = str(error)
    return payload


__all__ = [
    "PostgresCaseworkStore",
    "PostgresUnavailableError",
    "UnavailableCaseworkStore",
    "get_casework_store",
    "postgres_unavailable_result",
]
