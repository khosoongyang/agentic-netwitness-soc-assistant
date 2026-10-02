"""Redaction applied to every event before it is stored or streamed.

Agent Activity is analyst-facing, so it must never carry credentials,
authentication material, URL query strings (provider URLs can embed keys),
local filesystem paths or stack traces. Prompts/messages are never passed to
emit() in the first place (adapters record only counts), but free text that
does pass through - model explanation fields, provider error strings,
exception messages - is scrubbed here as defence in depth.
"""

from __future__ import annotations

import re
from typing import Any

MAX_TEXT = 4000
MAX_LIST = 50
MAX_DEPTH = 6
REDACTED = "«redacted»"

_TEXT_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    # OpenAI-style secret keys.
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"), REDACTED),
    # Authorization: Bearer <token>
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-~+/=]{8,}"), f"Bearer {REDACTED}"),
    # key=value / key: value for credential-looking names.
    (re.compile(
        r"(?i)\b(api[_-]?key|apikey|x-apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|"
        r"client[_-]?secret|secret|password|passwd|authorization)\b(\s*[:=]\s*)(['\"]?)[^\s'\",;&}]+"),
     rf"\1\2\3{REDACTED}"),
    # URL query strings (may carry keys/tokens).
    (re.compile(r"(https?://[^\s?#\"'<>]+)\?[^\s\"'<>]*"), r"\1?«query redacted»"),
    # Absolute local paths (Windows drive paths, common Unix roots).
    (re.compile(r"[A-Za-z]:\\[^\s\"'<>|]+"), "«local path»"),
    (re.compile(r"(?<![\w:/])/(?:home|Users|tmp|var|opt|etc|usr|mnt|srv|root)/[^\s\"'<>]+"), "«local path»"),
)

_TRACEBACK_RE = re.compile(r"Traceback \(most recent call last\):.*", re.DOTALL)

_SECRET_KEY_RE = re.compile(
    r"(?i)^(api[_-]?key|apikey|x-apikey|key|token|access[_-]?token|refresh[_-]?token|auth|"
    r"authorization|password|passwd|secret|client[_-]?secret|credentials?|cookie|headers?)$")


def sanitize_text(value: Any, max_len: int = MAX_TEXT) -> str:
    text = "" if value is None else str(value)
    text = _TRACEBACK_RE.sub("«stack trace removed»", text)
    for pattern, replacement in _TEXT_RULES:
        text = pattern.sub(replacement, text)
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def is_secret_key(name: Any) -> bool:
    return bool(_SECRET_KEY_RE.match(str(name or "").strip()))


def sanitize_value(value: Any, depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        return "…"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in list(value.items())[:200]:
            key_s = str(key)
            out[key_s] = REDACTED if is_secret_key(key_s) else sanitize_value(item, depth + 1)
        return out
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        cleaned = [sanitize_value(item, depth + 1) for item in items[:MAX_LIST]]
        if len(items) > MAX_LIST:
            cleaned.append(f"… {len(items) - MAX_LIST} more")
        return cleaned
    return sanitize_text(value)


def describe_exception(exc: BaseException) -> str:
    """Analyst-safe one-liner: exception type plus a scrubbed, truncated
    message. Never includes a traceback."""
    message = sanitize_text(str(exc), max_len=300)
    name = type(exc).__name__
    return f"{name}: {message}" if message else name
