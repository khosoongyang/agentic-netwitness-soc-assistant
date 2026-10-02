"""Readable detail blocks carried in ``metadata.details``.

Adapters turn genuine runtime values into these small blocks so the
frontend can render expandable detail sections generically, without
knowing anything about a particular stage. Empty values are dropped - a
block only lists what actually exists.
"""

from __future__ import annotations

from typing import Any, Iterable

_EMPTY = (None, "", [], {}, ())


def _present(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    return value not in _EMPTY


def fields(pairs: Iterable[tuple[str, Any]], label: str | None = None) -> dict | None:
    rows = [{"label": str(name), "value": str(value)} for name, value in pairs if _present(value)]
    if not rows:
        return None
    block: dict[str, Any] = {"type": "fields", "fields": rows}
    if label:
        block["label"] = label
    return block


def text(label: str, value: Any) -> dict | None:
    if not _present(value):
        return None
    return {"type": "text", "label": label, "text": str(value)}


def items(label: str, values: Any) -> dict | None:
    if isinstance(values, str):
        values = [values]
    cleaned = [str(v) for v in (values or []) if _present(v)]
    if not cleaned:
        return None
    return {"type": "list", "label": label, "items": cleaned}


def note(value: str) -> dict:
    return {"type": "note", "text": value}


def blocks(*candidates: dict | None) -> list[dict]:
    return [block for block in candidates if block]


def format_count(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def format_duration_ms(ms: Any) -> str:
    try:
        ms = float(ms)
    except (TypeError, ValueError):
        return ""
    return f"{ms / 1000:.1f} s" if ms >= 1000 else f"{int(ms)} ms"
