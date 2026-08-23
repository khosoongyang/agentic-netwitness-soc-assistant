"""Alert response handling for NetWitness Respond API variants."""

from __future__ import annotations

from typing import Any

from nw_alerts import _alerts_has_more, _extract_alert_items, _merge_alert_digest


def alert_items(payload: Any) -> list[dict]:
    """Reuse the legacy-tolerant response extraction in one canonical place."""
    return _extract_alert_items(payload)


def has_more_alerts(payload: Any, page_number: int) -> bool:
    return _alerts_has_more(payload, page_number)


def enrich_incident(incident: dict) -> dict:
    _merge_alert_digest(incident)
    return incident
