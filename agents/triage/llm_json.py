"""agents/triage/llm_json.py -- Lenient JSON extraction from model output, the focused repair call, and
severity-level normalisation.

[AUDIT T-22] Moved verbatim out of soc_triage_agent.py (2,500+ lines) to
split it by responsibility. soc_triage_agent re-exports every name
defined here, so existing imports and behaviour are unchanged.
"""
from __future__ import annotations

import json
import re
from typing import Any

from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI


# ══════════════════════════════════════════════════════════════════════════════
# 5.  JSON EXTRACTION & REPAIR
# ══════════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `_coerce_dict` — transforms coerce dict input into the stable representation required by downstream triage processing.
# [FYP-INPUT] Parameters: `parsed`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include agents/triage/soc_triage_agent.py:_extract_json; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `isinstance`, `update`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _coerce_dict(parsed: Any) -> dict:
    """
    The model doesn't always emit a JSON object — sometimes it's an array
    (e.g. [{...}]) or a bare scalar. Every caller of _extract_json does
    data.get(...), so anything non-dict must be coerced here or it crashes
    with "'list' object has no attribute 'get'".
    """
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        merged: dict = {}
        for item in parsed:
            if isinstance(item, dict):
                merged.update(item)
        return merged
    return {}


# [FYP-FUNCTION] `_extract_json` — transforms extract json input into the stable representation required by downstream triage processing.
# [FYP-INPUT] Parameters: `text`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include agents/triage/soc_triage_agent.py:_repair_json, agents/triage/soc_triage_agent.py:_run_cls, agents/triage/soc_triage_agent.py:_run_ioc; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_coerce_dict`, `finditer`, `group`, `list`, `loads`, `range`, `replace`, `reversed`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _extract_json(text: str) -> dict:
    """Extract a JSON object from raw model output (handles reasoning prose)."""
    if not text:
        return {}
    cleaned = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()
    try:
        data = _coerce_dict(json.loads(cleaned))
        if data:
            return data
    except json.JSONDecodeError:
        pass
    last_close = cleaned.rfind("}")
    if last_close == -1:
        return {}
    depth = 0
    for i in range(last_close, -1, -1):
        if cleaned[i] == "}":
            depth += 1
        elif cleaned[i] == "{":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(cleaned[i: last_close + 1])
                except json.JSONDecodeError:
                    break
    for m in reversed(list(re.finditer(r"\{[^{}]+\}", cleaned, re.DOTALL))):
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            continue
    return {}


_VALID_LEVELS = ("critical", "high", "medium", "low")
_SEV_ORDER    = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# [FYP-FUNCTION] `_normalize_level` — transforms normalize level input into the stable representation required by downstream triage processing.
# [FYP-INPUT] Parameters: `value`, `default`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include agents/triage/soc_triage_agent.py:triage; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `lower`, `startswith`, `strip`, `sub`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _normalize_level(value: str | None, default: str) -> str:
    """
    Map the model's free-text level to one of the canonical SOC levels.
    Without this, phrasing drift (case, whitespace, "informational", a
    trailing period) silently falls through to the "medium" dict-lookup
    default in SOC_CLASSIFICATION_TABLE, which looks like inconsistent
    output but is really just an un-normalized string miss.
    """
    if not value:
        return default
    v = re.sub(r"[^a-z]", "", value.strip().lower())
    if v in _VALID_LEVELS:
        return v
    if v.startswith("info"):
        return "low"
    for level in _VALID_LEVELS:
        if level in v:
            return level
    return default


# [FYP-FUNCTION] `_repair_json` — implements the repair json operation used by the surrounding triage workflow.
# [FYP-INPUT] Parameters: `raw_text`, `required_keys`, `llm`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include agents/triage/soc_triage_agent.py:_run_cls, agents/triage/soc_triage_agent.py:_run_ioc, agents/triage/soc_triage_agent.py:_run_risk; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `HumanMessage`, `StrOutputParser`, `SystemMessage`, `_extract_json`, `from_messages`, `invoke`, `join`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _repair_json(raw_text: str, required_keys: list[str], llm: ChatOpenAI) -> dict:
    """Focused repair call when _extract_json misses required keys."""
    keys_str = ", ".join(f'"{k}"' for k in required_keys)
    prompt = ChatPromptTemplate.from_messages([
        SystemMessage(content=(
            "You are a JSON formatter. Extract or reconstruct a JSON object from "
            "the text. Return ONLY valid JSON — no prose, no markdown, no fences. "
            f"Required keys: {keys_str}"
        )),
        HumanMessage(content=f"TEXT:\n{raw_text[-2000:]}\n\nReturn ONLY JSON:"),
    ])
    try:
        chain = prompt | llm | StrOutputParser()
        raw   = chain.invoke({})
        data  = _extract_json(raw)
        if data:
            return data
    except Exception:
        pass
    return {}


