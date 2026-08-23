"""Validated incident file ingestion using legacy-compatible parsing rules."""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime
from pathlib import Path

from alert_triage import normalize_to_incident, validate_alert
from integrations.netwitness.incidents import incident_identity

from .sync_service import upsert_incidents


class ImportServiceError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class ImportService:
    SUPPORTED = {".json", ".csv", ".txt", ".log"}

    def __init__(self, upload_dir: Path, max_bytes: int = 5 * 1024 * 1024) -> None:
        self.upload_dir = Path(upload_dir)
        self.max_bytes = max_bytes

    def _parse(self, filename: str, raw: bytes) -> dict:
        suffix = Path(filename).suffix.lower()
        if suffix not in self.SUPPORTED:
            raise ImportServiceError("IMPORT_UNSUPPORTED_TYPE", "Upload a JSON, CSV, TXT, or LOG file.")
        if not raw:
            raise ImportServiceError("IMPORT_INVALID", "The uploaded file is empty.")
        if len(raw) > self.max_bytes:
            raise ImportServiceError("IMPORT_INVALID", "The uploaded file exceeds the size limit.", 413)
        try:
            if suffix == ".json":
                data = json.loads(raw.decode("utf-8", errors="replace"))
                if isinstance(data, list):
                    if not data:
                        raise ImportServiceError("IMPORT_INVALID", "The JSON array is empty.")
                    incident = data[0] if isinstance(data[0], dict) else {"raw": data[0]}
                elif isinstance(data, dict):
                    if "items" in data:
                        if not isinstance(data["items"], list) or not data["items"] or not isinstance(data["items"][0], dict):
                            raise ImportServiceError("IMPORT_INVALID", "The JSON items envelope is empty or malformed.")
                        incident = data["items"][0]
                    else:
                        incident = data
                else:
                    raise ImportServiceError("IMPORT_INVALID", "The JSON root must be an object or array.")
            elif suffix == ".csv":
                rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8", errors="replace"))))
                if not rows:
                    raise ImportServiceError("IMPORT_INVALID", "The CSV has no data rows.")
                incident = dict(rows[0])
                incident["_csv_alerts"] = rows
            else:
                text = raw.decode("utf-8", errors="replace")
                if not text.strip():
                    raise ImportServiceError("IMPORT_INVALID", "The uploaded log is empty.")
                incident = {
                    "id": filename,
                    "title": f"Uploaded log — {filename}",
                    "description": text[:4000],
                    "raw_log": text,
                    "message": text[:8000],
                    "timestamp": datetime.now().isoformat(),
                    "source": "file_upload",
                }
        except ImportServiceError:
            raise
        except (UnicodeError, json.JSONDecodeError, csv.Error) as exc:
            raise ImportServiceError("IMPORT_INVALID", "The uploaded file could not be parsed.") from exc
        if not isinstance(incident, dict) or not incident:
            raise ImportServiceError("IMPORT_INVALID", "The upload does not contain an incident object.")
        if not isinstance(incident.get("alertMeta"), dict) or not incident.get("alertMeta"):
            try:
                if validate_alert(incident)["ok"]:
                    incident = normalize_to_incident(incident, "edr" if suffix in {".txt", ".log"} else "siem")
            except Exception:
                pass
        incident.setdefault("id", filename)
        incident.setdefault("title", filename)
        return incident

    def import_file(self, filename: str, raw: bytes, *, expected_incident_id: str | None = None) -> dict:
        safe_name = Path(filename or "").name
        if not safe_name:
            raise ImportServiceError("IMPORT_INVALID", "A filename is required.")
        incident = self._parse(safe_name, raw)
        identity = incident_identity(incident)
        if not identity:
            raise ImportServiceError("IMPORT_INVALID", "The imported incident has no identity.")
        if expected_incident_id and identity != str(expected_incident_id):
            raise ImportServiceError("IMPORT_INVALID", "The imported incident identity does not match the requested case.", 409)

        self.upload_dir.mkdir(parents=True, exist_ok=True)
        stored_name = f"{uuid.uuid4().hex}{Path(safe_name).suffix.lower()}"
        (self.upload_dir / stored_name).write_bytes(raw)
        summary = upsert_incidents([incident])
        return {"incident_id": identity, "filename": safe_name, "summary": summary}
