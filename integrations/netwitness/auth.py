"""NetWitness configuration and authentication header helpers."""

from __future__ import annotations

from dataclasses import dataclass
import base64
from pathlib import Path
from urllib.parse import urlparse

from .diagnostics import NOT_CONFIGURED, NetWitnessError, error


AUTH_STYLES = {"NetWitness-Token", "Bearer", "Cookie", "Both"}


def decode_legacy_password(value: str) -> str:
    """Read the base64 format used by the legacy settings file, or plain text."""
    if not value:
        return ""
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
        return decoded if decoded.isprintable() else value
    except Exception:
        return value


@dataclass
class NetWitnessConfig:
    base_url: str
    username: str = ""
    password: str = ""
    token: str = ""
    auth_style: str = "NetWitness-Token"
    verify_tls: bool = True
    ca_certificate: str = ""
    timeout: int = 30

    def validate(self) -> None:
        self.base_url = self.base_url.strip().strip("'\"").rstrip("/")
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise NetWitnessError("NETWITNESS_NOT_CONFIGURED", "Enter a valid NetWitness HTTP(S) URL.", 400)
        if self.auth_style not in AUTH_STYLES:
            raise NetWitnessError("NETWITNESS_NOT_CONFIGURED", "Select a supported NetWitness authentication style.", 400)
        if self.ca_certificate and not Path(self.ca_certificate).is_file():
            raise NetWitnessError("NETWITNESS_TLS_ERROR", "The configured CA certificate was not found.", 400)

    @property
    def requests_verify(self) -> bool | str:
        if self.ca_certificate:
            return self.ca_certificate
        return self.verify_tls

    def require_host(self) -> None:
        if not self.base_url:
            raise error(NOT_CONFIGURED)


def authentication_headers(token: str, style: str) -> dict[str, str]:
    headers = {"Accept": "application/json;charset=UTF-8"}
    if style == "Bearer":
        headers["Authorization"] = f"Bearer {token}"
    elif style == "Cookie":
        headers["Cookie"] = f"access_token={token}"
    elif style == "Both":
        headers["Authorization"] = f"Bearer {token}"
        headers["Cookie"] = f"access_token={token}"
    else:
        headers["NetWitness-Token"] = token
    return headers
