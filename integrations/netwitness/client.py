"""Framework-independent NetWitness Respond API client."""

from __future__ import annotations

from urllib.parse import quote

import requests

from .alerts import alert_items, enrich_incident, has_more_alerts
from .auth import NetWitnessConfig, authentication_headers
from .diagnostics import (
    AUTH_FAILED,
    REQUEST_FAILED,
    RESPONSE_INVALID,
    TLS_ERROR,
    TOKEN_INVALID,
    UNREACHABLE,
    NetWitnessError,
    error,
)
from .incidents import incident_identity, incident_items


class NetWitnessClient:
    """Small, injectable client with centralized TLS and authentication."""

    def __init__(self, config: NetWitnessConfig, session=None) -> None:
        config.validate()
        self.config = config
        self.session = session or requests.Session()

    def _url(self, path: str) -> str:
        return f"{self.config.base_url}{path}"

    @staticmethod
    def _token_expired(response) -> bool:
        if response.status_code not in {400, 401, 403, 500}:
            return False
        text = str(getattr(response, "text", "") or "").lower()
        if any(marker in text for marker in ("expired token", "token expired", "expired_token")):
            return True
        try:
            body = response.json()
        except Exception:
            return False
        errors = body.get("errors", []) if isinstance(body, dict) else []
        return any(
            "expired" in str(item.get("message", "")).lower()
            or "token" in str(item.get("message", "")).lower()
            for item in errors if isinstance(item, dict)
        )

    def _send(self, method: str, path: str, *, authenticated: bool = True, retry_auth: bool = True, **kwargs):
        headers = dict(kwargs.pop("headers", {}))
        if authenticated:
            if not self.config.token:
                raise error(TOKEN_INVALID)
            headers.update(authentication_headers(self.config.token, self.config.auth_style))
        try:
            response = self.session.request(
                method,
                self._url(path),
                headers=headers,
                timeout=self.config.timeout,
                verify=self.config.requests_verify,
                **kwargs,
            )
        except requests.exceptions.SSLError as exc:
            raise error(TLS_ERROR) from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            raise error(UNREACHABLE) from exc
        except requests.exceptions.RequestException as exc:
            raise error(REQUEST_FAILED) from exc

        auth_failure = response.status_code in {401, 403} or self._token_expired(response)
        if auth_failure:
            if authenticated and retry_auth and self.config.username and self.config.password:
                self.login()
                return self._send(method, path, authenticated=authenticated, retry_auth=False, **kwargs)
            raise error(TOKEN_INVALID if authenticated else AUTH_FAILED)
        if not 200 <= response.status_code < 300:
            raise error(REQUEST_FAILED)
        return response

    @staticmethod
    def _json(response):
        try:
            return response.json()
        except (TypeError, ValueError) as exc:
            raise error(RESPONSE_INVALID) from exc

    def login(self) -> None:
        if not self.config.username or not self.config.password:
            raise error(AUTH_FAILED)
        try:
            response = self._send(
                "POST",
                "/rest/api/auth/userpass",
                authenticated=False,
                data={"username": self.config.username, "password": self.config.password},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-1",
                    "Accept": "application/json;charset=UTF-8",
                },
            )
        except NetWitnessError as exc:
            if exc.code == "NETWITNESS_REQUEST_FAILED":
                raise error(AUTH_FAILED) from exc
            raise
        payload = self._json(response)
        token = payload.get("accessToken") or payload.get("access_token") if isinstance(payload, dict) else ""
        if not token:
            raise error(AUTH_FAILED)
        self.config.token = str(token)

    def verify_token(self) -> bool:
        response = self._send("GET", "/rest/api/incidents", params={"pageSize": 1, "pageNumber": 0})
        try:
            incident_items(self._json(response))
        except ValueError as exc:
            raise error(RESPONSE_INVALID) from exc
        return True

    def get_incidents(self, *, page: int = 0, limit: int = 100, since: str | None = None) -> dict:
        params = {"pageSize": limit, "pageNumber": page}
        if since:
            params["since"] = since
        payload = self._json(self._send("GET", "/rest/api/incidents", params=params))
        try:
            items = incident_items(payload)
        except ValueError as exc:
            raise error(RESPONSE_INVALID) from exc
        return {
            "items": items,
            "page": page,
            "limit": limit,
            "has_next": bool(payload.get("hasNext", False)),
            "total": payload.get("totalItems"),
        }

    def get_incident(self, incident_id: str) -> dict:
        safe_id = quote(str(incident_id), safe="")
        payload = self._json(self._send("GET", f"/rest/api/incidents/{safe_id}"))
        if isinstance(payload, dict) and isinstance(payload.get("item"), dict):
            payload = payload["item"]
        if not isinstance(payload, dict):
            raise error(RESPONSE_INVALID)
        returned_id = incident_identity(payload)
        if returned_id and returned_id != str(incident_id):
            raise NetWitnessError("NETWITNESS_RESPONSE_INVALID", "NetWitness returned a different incident identity.", 502)
        return payload

    def get_alerts(self, incident_id: str, *, page_size: int = 100) -> list[dict]:
        safe_id = quote(str(incident_id), safe="")
        collected: list[dict] = []
        for page in range(1000):
            payload = self._json(self._send(
                "GET",
                f"/rest/api/incidents/{safe_id}/alerts",
                params={"pageSize": page_size, "pageNumber": page},
            ))
            items = alert_items(payload)
            for item in items:
                item["incident_id"] = str(incident_id)
            collected.extend(items)
            if not has_more_alerts(payload, page):
                break
        return collected

    def get_alert_details(self, alert_id: str) -> dict:
        safe_id = quote(str(alert_id), safe="")
        payload = self._json(self._send("GET", f"/rest/api/alerts/{safe_id}"))
        if isinstance(payload, dict) and isinstance(payload.get("item"), dict):
            payload = payload["item"]
        if not isinstance(payload, dict):
            raise error(RESPONSE_INVALID)
        returned_id = str(payload.get("id") or payload.get("alertId") or "").strip()
        if returned_id and returned_id != str(alert_id):
            raise NetWitnessError("NETWITNESS_RESPONSE_INVALID", "NetWitness returned a different alert identity.", 502)
        return payload

    def get_incidents_with_alerts(self, *, limit: int | None = None, since: str | None = None) -> list[dict]:
        all_items: list[dict] = []
        for page in range(1000):
            remaining = 100 if limit is None else min(100, max(limit - len(all_items), 1))
            result = self.get_incidents(page=page, limit=remaining, since=since)
            all_items.extend(result["items"])
            if not result["has_next"] or (limit is not None and len(all_items) >= limit):
                break
        if limit is not None:
            all_items = all_items[:limit]
        for incident in all_items:
            incident_id = incident_identity(incident)
            if not incident_id:
                incident.setdefault("alerts", [])
                continue
            incident["alerts"] = self.get_alerts(incident_id)
            enrich_incident(incident)
        return all_items
