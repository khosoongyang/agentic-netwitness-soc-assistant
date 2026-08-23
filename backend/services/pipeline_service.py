"""Bounded inspection and explicitly confirmed administration of the pipeline database."""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from pathlib import Path
from typing import Any


PIPELINE_STAGES = {
    "alerts_to_triage": "Alerts to Triage",
    "post_triage_investigate": "Post-Triage · Needs Investigation",
    "post_triage_no_investigate": "Post-Triage · No Investigation Needed",
    "post_investigation": "Post-Investigation · Findings",
    "initial_ticket": "Initial Ticket Generation",
    "pending_ticket_report": "Pending Ticket / Report Generation",
    "finalized_report": "Finalized Report",
    "workflow_runs": "Workflow Runs (Audit)",
}


class PipelineServiceError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        self.code, self.message, self.status_code = code, message, status_code
        super().__init__(message)


class PipelineService:
    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path)

    @staticmethod
    def _stage(stage: str) -> str:
        if stage not in PIPELINE_STAGES:
            raise PipelineServiceError("FORBIDDEN_OPERATION", "Pipeline stage is not allowed.", 403)
        return stage

    def _connect(self, *, readonly=True):
        if not self.database_path.is_file():
            raise PipelineServiceError("PIPELINE_OPERATION_FAILED", "The pipeline database is unavailable.", 503)
        if readonly:
            connection = sqlite3.connect(f"{self.database_path.resolve().as_uri()}?mode=ro", uri=True, timeout=15)
            connection.execute("PRAGMA query_only=ON")
        else:
            connection = sqlite3.connect(str(self.database_path), timeout=15)
        connection.row_factory = sqlite3.Row
        return connection

    def summary(self) -> dict[str, Any]:
        output = []
        with self._connect() as connection:
            for stage, label in PIPELINE_STAGES.items():
                try:
                    count, last = connection.execute(
                        f"SELECT COUNT(*), MAX(created_at) FROM {stage}"
                    ).fetchone()
                except sqlite3.DatabaseError:
                    count, last = 0, None
                output.append({"key": stage, "label": label, "count": int(count), "last_write": last})
        return {"stages": output}

    def records(self, stage: str, *, limit: int = 100, offset: int = 0) -> dict:
        stage = self._stage(stage)
        if not 1 <= limit <= 300 or offset < 0:
            raise PipelineServiceError("PIPELINE_OPERATION_FAILED", "Pagination is invalid.")
        with self._connect() as connection:
            total = int(connection.execute(f"SELECT COUNT(*) FROM {stage}").fetchone()[0])
            rows = connection.execute(
                f"SELECT id,incident_id,title,severity,stage,created_at,summary,raw_json FROM {stage} "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            try:
                item["raw"] = json.loads(item.pop("raw_json") or "{}")
            except (TypeError, ValueError):
                item["raw"] = {}
                item.pop("raw_json", None)
            items.append(item)
        return {"stage": stage, "label": PIPELINE_STAGES[stage], "items": items, "total": total}

    def export_csv(self, stage: str, record_id: str) -> tuple[bytes, str]:
        stage = self._stage(stage)
        with self._connect() as connection:
            row = connection.execute(f"SELECT * FROM {stage} WHERE id=?", (record_id,)).fetchone()
        if not row:
            raise PipelineServiceError("PIPELINE_OPERATION_FAILED", "Pipeline record was not found.", 404)
        payload = {key: value for key, value in dict(row).items() if key != "raw_json"}
        try:
            extra = json.loads(row["raw_json"] or "{}")
            payload.update({key: value for key, value in extra.items() if key not in payload and not isinstance(value, (dict, list))})
        except (TypeError, ValueError):
            pass
        stream = io.StringIO()
        writer = csv.DictWriter(stream, fieldnames=list(payload))
        writer.writeheader()
        writer.writerow(payload)
        safe_id = "".join(char if char.isalnum() or char in "-_" else "_" for char in record_id)[:64]
        return stream.getvalue().encode(), f"{stage}_{safe_id}.csv"

    def delete_record(self, stage: str, record_id: str, confirmation: str, *, developer_mode: bool) -> dict:
        stage = self._stage(stage)
        if not developer_mode:
            raise PipelineServiceError("FORBIDDEN_OPERATION", "Developer mode is required.", 403)
        if not record_id or len(record_id) > 256 or confirmation != f"DELETE {stage}/{record_id}":
            raise PipelineServiceError("FORBIDDEN_OPERATION", "Exact record confirmation is required.", 403)
        with self._connect(readonly=False) as connection:
            cursor = connection.execute(f"DELETE FROM {stage} WHERE id=?", (record_id,))
            connection.commit()
        return {"stage": stage, "record_id": record_id, "deleted": cursor.rowcount == 1}

    def clear_stage(self, stage: str, confirmation: str, *, developer_mode: bool) -> dict:
        stage = self._stage(stage)
        if not developer_mode or confirmation != f"CLEAR {stage}":
            raise PipelineServiceError("FORBIDDEN_OPERATION", "Exact developer confirmation is required.", 403)
        with self._connect(readonly=False) as connection:
            count = int(connection.execute(f"SELECT COUNT(*) FROM {stage}").fetchone()[0])
            connection.execute(f"DELETE FROM {stage}")
            connection.commit()
        return {"stage": stage, "deleted": count}
