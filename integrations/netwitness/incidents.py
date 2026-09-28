"""Pure NetWitness incident helpers."""

from __future__ import annotations

from typing import Any


def incident_items(payload: Any) -> list[dict]:
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ValueError("incident response does not contain an items list")
    if not all(isinstance(item, dict) for item in payload["items"]):
        raise ValueError("incident items must be objects")
    return payload["items"]


def incident_identity(incident: dict) -> str:
    return str(incident.get("id") or incident.get("incidentId") or "").strip()


def normalise_severity(incident: dict) -> str:
    raw = str(incident.get("riskScore") or incident.get("severity") or "").upper()
    try:
        score = int(raw)
        return "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
    except ValueError:
        return raw if raw in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "LOW"
