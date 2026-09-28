"""Safe NetWitness errors shared by the integration and HTTP service layers."""

from __future__ import annotations


class NetWitnessError(RuntimeError):
    """An integration failure whose public message never contains secrets."""

    def __init__(self, code: str, message: str, status_code: int = 502) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


NOT_CONFIGURED = ("NETWITNESS_NOT_CONFIGURED", "NetWitness is not configured.", 400)
AUTH_FAILED = ("NETWITNESS_AUTH_FAILED", "Unable to authenticate with NetWitness.", 401)
TOKEN_INVALID = ("NETWITNESS_TOKEN_INVALID", "The NetWitness token is invalid or expired.", 401)
UNREACHABLE = ("NETWITNESS_UNREACHABLE", "NetWitness could not be reached.", 503)
TLS_ERROR = ("NETWITNESS_TLS_ERROR", "NetWitness TLS verification failed.", 502)
REQUEST_FAILED = ("NETWITNESS_REQUEST_FAILED", "The NetWitness request failed.", 502)
RESPONSE_INVALID = ("NETWITNESS_RESPONSE_INVALID", "NetWitness returned an invalid response.", 502)


def error(details: tuple[str, str, int]) -> NetWitnessError:
    return NetWitnessError(*details)
