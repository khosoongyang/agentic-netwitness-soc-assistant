"""Secret-safe, process-local application settings used by the Flask UI."""

from __future__ import annotations

import os
import re
import threading
from typing import Any


class SettingsError(ValueError):
    pass


class SettingsService:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._analyst = ""
        self._developer_mode = False

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "analyst_name": self._analyst,
                "developer_mode": self._developer_mode,
                "openai_configured": bool(os.environ.get("OPENAI_API_KEY", "").strip()),
                "openai_model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini",
                "storage": {
                    "workflow_database_configured": True,
                    "runtime_directory": "runtime/",
                },
            }

    def update(self, values: dict[str, Any]) -> dict[str, Any]:
        analyst = str(values.get("analyst_name", self._analyst)).strip()
        model = str(values.get("openai_model", os.environ.get("OPENAI_MODEL", "gpt-4o-mini"))).strip()
        if len(analyst) > 120 or any(ord(char) < 32 for char in analyst):
            raise SettingsError("Analyst name is invalid.")
        if not model or len(model) > 120 or not re.fullmatch(r"[A-Za-z0-9._:-]+", model):
            raise SettingsError("OpenAI model name is invalid.")
        api_key = values.get("openai_api_key")
        if api_key is not None:
            api_key = str(api_key).strip()
            if api_key and (len(api_key) < 8 or len(api_key) > 512):
                raise SettingsError("OpenAI API key is invalid.")
            if api_key:
                os.environ["OPENAI_API_KEY"] = api_key
        if values.get("clear_openai_api_key") is True:
            os.environ.pop("OPENAI_API_KEY", None)
        with self._lock:
            self._analyst = analyst
            self._developer_mode = bool(values.get("developer_mode", self._developer_mode))
            os.environ["OPENAI_MODEL"] = model
        return self.status()


settings_service = SettingsService()
