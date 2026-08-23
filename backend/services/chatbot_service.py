"""Trusted-context adapter for the existing Ask Aegis implementation."""

from __future__ import annotations

import json
import os
from typing import Any, Callable

from workflow import state_store as wss

from ..errors import CaseNotFoundError
from .case_service import _get_case_row


class ChatServiceError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 503) -> None:
        self.code, self.message, self.status_code = code, message, status_code
        super().__init__(message)


def _default_responder(message: str, incident: dict | None, parsed: dict | None, context: dict | None) -> str:
    from agents.triage import OpenAILLMConfig, soc_triage_chat_respond

    config = OpenAILLMConfig(
        base_url="https://api.openai.com/v1",
        api_key=os.environ.get("OPENAI_API_KEY", ""),
        model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        temperature=0.0,
        max_tokens=3072,
        timeout=300,
    )
    return soc_triage_chat_respond(
        message,
        incident,
        llm_config=config,
        parsed_context=parsed,
        case_context=context,
    )


class ChatbotService:
    def __init__(self, responder: Callable = _default_responder) -> None:
        self.responder = responder

    @staticmethod
    def _message(value: Any) -> str:
        message = str(value or "").strip()
        if not message or len(message) > 8000:
            raise ChatServiceError("CHAT_CONTEXT_FAILED", "Enter a message between 1 and 8000 characters.", 400)
        return message

    def ask_global(self, message: Any) -> dict[str, Any]:
        prompt = self._message(message)
        return self._respond(prompt, None, None, None, None)

    def ask_case(self, case_id: str, message: Any, *, database_path=None) -> dict[str, Any]:
        prompt = self._message(message)
        row = _get_case_row(case_id, database_path)
        state = wss.get_state(case_id)
        if state is None:
            raise CaseNotFoundError()
        try:
            incident = json.loads(row.get("raw_json") or "{}")
        except (TypeError, ValueError):
            incident = {}
        incident.setdefault("id", case_id)
        try:
            parsed = json.loads(state.get("parsing_result_json") or "{}")
        except (TypeError, ValueError):
            parsed = {}
        from .case_view_service import build_aegis_context
        context = build_aegis_context(case_id, state.get("run_id"))
        if not context.get("available"):
            raise ChatServiceError("CHAT_CONTEXT_FAILED", "Trusted case context is unavailable.", 409)
        return self._respond(prompt, incident, parsed, context, case_id)

    def _respond(self, prompt, incident, parsed, context, case_id):
        if not os.environ.get("OPENAI_API_KEY", "").strip() and self.responder is _default_responder:
            return {
                "message": "Ask Aegis is unavailable because OpenAI is not configured.",
                "available": False,
                "case_id": case_id,
            }
        try:
            answer = self.responder(prompt, incident, parsed, context)
        except Exception as exc:
            raise ChatServiceError("CHAT_UNAVAILABLE", "Ask Aegis could not complete the request.") from exc
        answer = str(answer or "").strip()
        if not answer:
            raise ChatServiceError("CHAT_UNAVAILABLE", "Ask Aegis returned an empty response.")
        return {"message": answer, "available": True, "case_id": case_id}
