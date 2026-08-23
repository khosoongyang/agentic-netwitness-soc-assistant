"""Framework-independent NetWitness Respond REST client for the dashboard API."""

from __future__ import annotations

import base64
import os
from typing import Any
from urllib.parse import quote

import requests
import urllib3

from backend.postgres_casework_store import normalise_alert


def _env(*names: str) -> str:
    for name in names:
        value = os.getenv(name, "").strip().strip("'\"")
        if value:
            return value
    return ""


def _password(value: str) -> str:
    """Decode the legacy base64 password format while preserving plain text."""
    if not value:
        return ""
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
        return decoded if decoded.isprintable() else value
    except Exception:
        return value


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("items", "results", "alerts", "incidents", "data", "content"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _items(value)
            if nested:
                return nested
    return []


class NetWitnessClient:
    """Small, defensive client used by the Flask dashboard routes."""

    def __init__(self) -> None:
        self.base_url = _env("NETWITNESS_BASE_URL", "NW_HOST").rstrip("/")
        self.token = _env("NETWITNESS_TOKEN", "NW_TOKEN")
        self.username = _env("NETWITNESS_USERNAME", "NW_USERNAME")
        self.password = _password(_env("NETWITNESS_PASSWORD", "NW_PASSWORD"))
        self.verify = _bool_env("NETWITNESS_VERIFY_SSL", False)
        self.timeout = float(_env("NETWITNESS_TIMEOUT") or "20")
        if not self.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @property
    def configured(self) -> bool:
        return bool(self.base_url and (self.token or (self.username and self.password)))

    def headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["NetWitness-Token"] = self.token
        return headers

    def get_token(self) -> str:
        if self.token:
            return self.token
        if not self.base_url or not self.username or not self.password:
            return ""
        response = requests.post(
            f"{self.base_url}/rest/api/auth/userpass",
            data={"username": self.username, "password": self.password},
            headers={
                "Accept": "application/json;charset=UTF-8",
                "Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-1",
            },
            verify=self.verify,
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        token = str(payload.get("accessToken") or payload.get("access_token") or "")
        if not token:
            raise RuntimeError("NetWitness authentication succeeded without returning a token")
        self.token = token
        os.environ["NW_TOKEN"] = token
        os.environ["NETWITNESS_TOKEN"] = token
        return token

    def status(self) -> dict[str, Any]:
        return {
            "configured": self.configured,
            "base_url": self.base_url,
            "authenticated": bool(self.token),
            "verify_ssl": self.verify,
        }

    def query(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.configured:
            return {"success": False, "configured": False, "status": "NetWitness is not configured", "items": []}
        try:
            self.get_token()
            response = requests.get(
                f"{self.base_url}/{path.lstrip('/')}",
                params=params or {},
                headers=self.headers(),
                verify=self.verify,
                timeout=self.timeout,
            )
            if response.status_code in {401, 403} and self.username and self.password:
                self.token = ""
                self.get_token()
                response = requests.get(
                    f"{self.base_url}/{path.lstrip('/')}",
                    params=params or {},
                    headers=self.headers(),
                    verify=self.verify,
                    timeout=self.timeout,
                )
            try:
                payload: Any = response.json()
            except ValueError:
                payload = None
            if not response.ok:
                return {
                    "success": False,
                    "configured": True,
                    "status": f"NetWitness returned HTTP {response.status_code}",
                    "status_code": response.status_code,
                    "response_preview": response.text[:500],
                    "items": [],
                }
            return {
                "success": True,
                "configured": True,
                "status": "connected",
                "status_code": response.status_code,
                "items": _items(payload),
                "raw": payload,
            }
        except (requests.RequestException, RuntimeError, ValueError) as exc:
            return {"success": False, "configured": True, "status": str(exc), "error": str(exc), "items": []}

    def fetch_alerts(self, filters: dict[str, Any] | None = None) -> dict[str, Any]:
        path = _env("NETWITNESS_ALERTS_PATH") or "/rest/api/alerts"
        result = self.query(path, filters)
        result["items"] = [normalise_alert(item) for item in result.get("items") or []]
        return result

    def fetch_alert(self, alert_id: str) -> dict[str, Any]:
        path = (_env("NETWITNESS_ALERTS_PATH") or "/rest/api/alerts").rstrip("/")
        result = self.query(f"{path}/{quote(str(alert_id), safe='')}")
        raw = result.get("raw")
        item = raw if isinstance(raw, dict) and not _items(raw) else next(iter(result.get("items") or []), None)
        return {**result, "alert": normalise_alert(item) if isinstance(item, dict) else None}

    def search_history(self, filters: dict[str, Any] | None = None) -> dict[str, Any]:
        path = _env("NETWITNESS_HISTORY_PATH") or "/rest/api/incidents"
        result = self.query(path, filters)
        result["items"] = [normalise_alert(item) for item in result.get("items") or []]
        return result
