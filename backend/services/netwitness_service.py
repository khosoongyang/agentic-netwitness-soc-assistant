"""Server-side ownership of NetWitness configuration and credentials."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from integrations.netwitness import NetWitnessClient, NetWitnessConfig
from integrations.netwitness.auth import decode_legacy_password
from integrations.netwitness.diagnostics import NOT_CONFIGURED, NetWitnessError, error


load_dotenv(Path(__file__).resolve().parents[2] / ".env")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


class NetWitnessService:
    """Keeps sensitive connection state in server memory, never in responses."""

    def __init__(self, client_factory=NetWitnessClient) -> None:
        self._client_factory = client_factory
        self._lock = threading.RLock()
        self._config: NetWitnessConfig | None = None
        self._verified = False
        host = (
            os.environ.get("NW_HOST")
            or os.environ.get("NETWITNESS_HOST")
            or os.environ.get("NETWITNESS_BASE_URL")
            or ""
        )
        if host:
            try:
                self._config = NetWitnessConfig(
                    base_url=host,
                    username=os.environ.get("NW_USERNAME") or os.environ.get("NETWITNESS_USERNAME", ""),
                    password=decode_legacy_password(
                        os.environ.get("NW_PASSWORD") or os.environ.get("NETWITNESS_PASSWORD", "")
                    ),
                    token=os.environ.get("NW_TOKEN") or os.environ.get("NETWITNESS_TOKEN", ""),
                    auth_style=os.environ.get("NW_AUTH_STYLE", "NetWitness-Token"),
                    verify_tls=_env_bool("NETWITNESS_VERIFY_SSL", True),
                    ca_certificate=os.environ.get("NW_CERT_PATH", ""),
                )
                self._config.validate()
            except NetWitnessError:
                self._config = None

    def _new_config(self, values: dict[str, Any], *, token: str = "") -> NetWitnessConfig:
        config = NetWitnessConfig(
            base_url=str(values.get("base_url") or values.get("host") or ""),
            username=str(values.get("username") or ""),
            password=str(values.get("password") or ""),
            token=token,
            auth_style=str(values.get("auth_style") or "NetWitness-Token"),
            verify_tls=bool(values.get("verify_tls", True)),
            ca_certificate=str(values.get("ca_certificate") or ""),
        )
        config.validate()
        return config

    def _client(self) -> NetWitnessClient:
        with self._lock:
            if self._config is None:
                raise error(NOT_CONFIGURED)
            return self._client_factory(self._config)

    def status(self) -> dict[str, Any]:
        with self._lock:
            config = self._config
            return {
                "configured": config is not None,
                "authenticated": bool(config and config.token),
                "verified": self._verified,
                "base_url": config.base_url if config else "",
                "username_configured": bool(config and config.username),
                "auth_style": config.auth_style if config else "NetWitness-Token",
                "verify_tls": bool(config and config.verify_tls),
                "ca_certificate_configured": bool(config and config.ca_certificate),
            }

    def login(self, values: dict[str, Any]) -> dict[str, Any]:
        config = self._new_config(values)
        client = self._client_factory(config)
        client.login()
        client.verify_token()
        with self._lock:
            self._config = config
            self._verified = True
        return self.status()

    def set_token(self, values: dict[str, Any]) -> dict[str, Any]:
        token = str(values.get("token") or "").strip()
        if not token:
            raise NetWitnessError("NETWITNESS_TOKEN_INVALID", "Enter a NetWitness token.", 400)
        config = self._new_config(values, token=token)
        client = self._client_factory(config)
        client.verify_token()
        with self._lock:
            self._config = config
            self._verified = True
        return self.status()

    def test(self) -> dict[str, Any]:
        client = self._client()
        client.verify_token()
        with self._lock:
            self._verified = True
        return {"connected": True, **self.status()}

    def incidents(self, *, page: int, limit: int, since: str | None = None) -> dict:
        return self._client().get_incidents(page=page, limit=limit, since=since)

    def incident(self, incident_id: str) -> dict:
        return self._client().get_incident(incident_id)

    def alerts(self, incident_id: str) -> list[dict]:
        return self._client().get_alerts(incident_id)

    def alert(self, alert_id: str) -> dict:
        return self._client().get_alert_details(alert_id)

    def enriched_incidents(self, *, limit: int | None = None, since: str | None = None) -> list[dict]:
        return self._client().get_incidents_with_alerts(limit=limit, since=since)


netwitness_service = NetWitnessService()
