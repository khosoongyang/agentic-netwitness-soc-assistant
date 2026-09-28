"""Ask Aegis HTTP routes."""

from flask import Blueprint, current_app, jsonify, request

from ..errors import APIError
from ..services.chatbot_service import ChatServiceError, ChatbotService


chatbot_blueprint = Blueprint("chatbot", __name__, url_prefix="/api")


def _service():
    return current_app.config.get("AEGIS_CHATBOT_SERVICE") or ChatbotService()


def _body():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise APIError("CHAT_CONTEXT_FAILED", "The request body must be a JSON object.", 400)
    return body


def _call(operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except ChatServiceError as exc:
        raise APIError(exc.code, exc.message, exc.status_code) from exc


@chatbot_blueprint.post("/chat")
def global_chat():
    return jsonify(_call(_service().ask_global, _body().get("message")))


@chatbot_blueprint.post("/cases/<case_id>/chat")
def case_chat(case_id: str):
    return jsonify(_call(
        _service().ask_case,
        case_id,
        _body().get("message"),
        database_path=current_app.config.get("AEGIS_CASE_DB_PATH"),
    ))
