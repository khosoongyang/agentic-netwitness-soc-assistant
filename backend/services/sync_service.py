"""Synchronize remote or imported incidents into canonical case storage."""

from __future__ import annotations

import json
from datetime import datetime

from workflow import state_store
from integrations.netwitness.incidents import incident_identity, normalise_severity


def upsert_incidents(incidents: list[dict]) -> dict[str, int]:
    """Preserve the legacy merge contract without touching workflow columns."""
    state_store.db_init()
    valid = [(incident_identity(item), item) for item in incidents]
    valid = [(identity, item) for identity, item in valid if identity]
    existing: set[str] = set()
    if valid:
        with state_store.db_connect() as connection:
            for offset in range(0, len(valid), 900):
                ids = [identity for identity, _ in valid[offset:offset + 900]]
                marks = ",".join("?" for _ in ids)
                existing.update(row["id"] for row in connection.execute(
                    f"SELECT id FROM incidents WHERE id IN ({marks})", ids
                ).fetchall())

    now = datetime.now().isoformat(timespec="seconds")
    rows = []
    for identity, incident in valid:
        slim = {key: value for key, value in incident.items() if key not in {"alerts", "journalEntries"}}
        if incident.get("alerts"):
            slim["_alerts_stripped"] = len(incident["alerts"])
        rows.append((
            identity,
            incident.get("title") or incident.get("name") or "",
            normalise_severity(incident),
            str(incident.get("status") or ""),
            str(incident.get("assignee") or ""),
            int(incident.get("alertCount") or incident.get("numAlerts") or 0),
            str(incident.get("created") or incident.get("createdDate") or "")[:19],
            str(incident.get("updated") or incident.get("lastUpdated") or "")[:19],
            json.dumps(slim),
            now,
            now,
        ))

    if rows:
        with state_store.db_connect() as connection:
            for offset in range(0, len(rows), 2000):
                connection.executemany("""
                    INSERT INTO incidents
                        (id, title, severity, status, assignee, alert_count,
                         created, updated, raw_json, first_seen, last_seen)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        title=excluded.title, severity=excluded.severity,
                        status=excluded.status, assignee=excluded.assignee,
                        alert_count=excluded.alert_count, updated=excluded.updated,
                        raw_json=excluded.raw_json, last_seen=excluded.last_seen
                """, rows[offset:offset + 2000])
                connection.commit()
            connection.execute("INSERT INTO fetch_log (fetched_at, count) VALUES (?,?)", (now, len(rows)))
            connection.commit()
    identities = {identity for identity, _ in valid}
    return {
        "fetched": len(incidents),
        "added": len(identities - existing),
        "updated": len(identities & existing),
        "skipped": len(incidents) - len(valid),
    }


class SyncService:
    def __init__(self, integration_service) -> None:
        self.integration_service = integration_service

    def synchronize(self, *, limit: int | None = None, since: str | None = None) -> dict:
        incidents = self.integration_service.enriched_incidents(limit=limit, since=since)
        summary = upsert_incidents(incidents)
        summary["warnings"] = []
        return summary
