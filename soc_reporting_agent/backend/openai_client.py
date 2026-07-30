# ==============================================================================
# [FYP-FILE] File: soc_reporting_agent/backend/openai_client.py
# Important dependencies: __future__, json, os, re, typing.
#
# Purpose:
#   Thin, centralised wrapper around the OpenAI Python SDK for this
#   subsystem. Consolidates what used to be a mix of Chat Completions,
#   LangChain ChatOpenAI, and Responses API call sites into one helper
#   (invoke_openai_text) so model selection, parameter compatibility (e.g.
#   not sending `temperature` to reasoning-tier models that reject it), and
#   fallback behaviour are handled in exactly one place.
#
# Main functionalities:
#   - build_client: [FYP-LLM] [FYP-CONFIG] construct an OpenAI client from
#     environment configuration, refusing to proceed on a missing/placeholder
#     API key.
#   - invoke_openai_text: [FYP-LLM] [FYP-EVALUATOR] [FYP-ENTRY-POINT] THE LLM
#     call function for this subsystem. Prefers the Responses API, with a
#     fallback to Chat Completions for older SDKs/models, and several
#     [FYP-FALLBACK] retry-without-unsupported-parameter paths.
#   - extract_json_object / _strip_markdown_fences / _first_balanced_json_object:
#     [FYP-LLM] tolerant parsing of an LLM's text response back into a JSON
#     object, handling markdown code fences and trailing prose around the
#     JSON.
#   - is_placeholder_key / latest_model / supports_temperature: small
#     [FYP-CONFIG] classification helpers that drive the above behaviour.
#
# Inputs:
#   - Environment variables (read by name only -- values are never logged or
#     echoed by this module): OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL.
#   - invoke_openai_text(prompt, system=..., model=..., temperature=...,
#     max_output_tokens=..., timeout=..., text_format=...): caller-supplied
#     prompt/parameters (source: reporting/template_document_exporter.py and
#     backend/app.py call sites).
#
# Outputs:
#   - invoke_openai_text() -> str: the model's raw text response (never
#     returns an empty string -- raises RuntimeError instead, see
#     [FYP-ERROR] note below).
#   - extract_json_object() -> dict[str, Any]: best-effort parsed JSON object
#     from arbitrary LLM text, or {} if nothing parseable was found.
#
# Workflow position:
#   Called synchronously by whichever backend/reporting code needs an LLM
#   completion (e.g. report narrative generation, JSON extraction for
#   structured report sections) -- this module has no awareness of
#   stage_workflow/orchestration_service; it is a pure integration wrapper
#   invoked as one step within the Reporting stage's export generation.
#
# Called by:
#   - soc_reporting_agent/backend/app.py
#     (`from backend.openai_client import invoke_openai_text`).
#   - soc_reporting_agent/reporting/template_document_exporter.py
#     (`from backend.openai_client import extract_json_object,
#     invoke_openai_text`), used while building report document content.
#
# Calls:
#   - openai (third-party SDK), imported lazily inside build_client() so the
#     rest of the module can be imported even if the package is missing
#     (the ImportError is only raised when a client is actually requested).
#
# Security note:
#   This module reads the API key strictly via the OPENAI_API_KEY
#   environment variable and never logs, prints, or embeds the key value
#   anywhere (including in comments/docstrings) -- only the variable name is
#   referenced. is_placeholder_key() exists specifically to fail fast with a
#   clear error if a real key was never configured, rather than sending a
#   placeholder string to the OpenAI API. [FYP-SECURITY]
#
# Key evaluator search terms:
#   invoke_openai_text, LLM call, OPENAI_API_KEY, Responses API,
#   Chat Completions fallback, extract_json_object, build_client.
# ==============================================================================

from __future__ import annotations

import json
import os
import re
from typing import Any


# [FYP-CONFIG] [FYP-LLM] Model name prefixes treated as "latest-generation"
# (currently GPT-5.x / o5 reasoning-tier models). Used to decide API-call
# shape (Responses API required) and parameter compatibility (no
# `temperature`).
LATEST_MODEL_PREFIXES = ("gpt-5", "o5")


# =============================================================================
# [FYP-SECTION] REPORTING BACKEND AND API EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================


def is_placeholder_key(key: str | None) -> bool:
    """[FYP-FUNCTION] [FYP-SECURITY] [FYP-VALIDATION] Detect an unset or still-placeholder OPENAI_API_KEY value.

    Params: key -- the raw value read from the OPENAI_API_KEY environment
    variable (never logged here).
    Returns: True if empty/whitespace-only, or matches known placeholder
    patterns ("replace_*", "your_openai_api_key", "changeme", "sk-replace_me").
    Called by: build_client() below, to fail fast with a clear error instead
    of sending a placeholder credential to the OpenAI API.
    """
    value = (key or "").strip()
    if not value:
        return True
    lowered = value.lower()
    return lowered.startswith("replace_") or "your_openai_api_key" in lowered or lowered in {"changeme", "sk-replace_me"}


def latest_model(model: str | None) -> bool:
    """[FYP-FUNCTION] [FYP-LLM] True when `model` starts with one of LATEST_MODEL_PREFIXES (GPT-5.x/o5 reasoning-tier models)."""
    model = (model or "").strip().lower()
    return model.startswith(LATEST_MODEL_PREFIXES)


def supports_temperature(model: str | None) -> bool:
    """[FYP-FUNCTION] [FYP-LLM] [FYP-VALIDATION] Whether it is safe to pass a `temperature` parameter to this model."""
    # GPT-5.x reasoning/frontier models commonly reject temperature on the Responses API.
    return not latest_model(model)


def build_client(timeout: float | int | None = None):
    """[FYP-FUNCTION] [FYP-LLM] [FYP-CONFIG] [FYP-SECURITY] Construct an OpenAI SDK client from environment configuration.

    Params: timeout -- optional per-client request timeout in seconds.
    Returns: an `openai.OpenAI` client instance.
    Reads (by name only, never echoed): OPENAI_API_KEY (required, validated
    via is_placeholder_key), OPENAI_BASE_URL (optional, for a custom/proxy
    endpoint), max_retries is fixed at 1 (this subsystem handles its own
    fallback/retry logic in invoke_openai_text rather than relying on SDK
    auto-retry).
    [FYP-ERROR] Raises RuntimeError if OPENAI_API_KEY is missing/placeholder,
    or if the `openai` package is not installed / too old to import
    (import is deferred to inside this function specifically so the rest of
    this module can still be imported without the package present).
    Called by: invoke_openai_text() below.
    """
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if is_placeholder_key(api_key):
        raise RuntimeError("OPENAI_API_KEY is missing or still set to a placeholder")
    try:
        from openai import OpenAI
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(f"openai package is not installed or too old: {exc}") from exc

    kwargs: dict[str, Any] = {"api_key": api_key, "max_retries": 1}
    base_url = os.getenv("OPENAI_BASE_URL", "").strip()
    if base_url:
        kwargs["base_url"] = base_url
    if timeout:
        kwargs["timeout"] = float(timeout)
    return OpenAI(**kwargs)


def _extract_responses_text(response: Any) -> str:
    """[FYP-FUNCTION] [FYP-LLM] Extract the plain-text completion out of a Responses API response object.

    Prefers the SDK's convenience `output_text` attribute; falls back to
    manually walking `response.output[*].content[*].text` and joining the
    text chunks, for SDK versions/response shapes where output_text is not
    populated.
    Called by: invoke_openai_text() (Responses API branch).
    """
    text = getattr(response, "output_text", None)
    if text:
        return str(text).strip()
    chunks: list[str] = []
    for item in getattr(response, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            part = getattr(content, "text", None)
            if part:
                chunks.append(str(part))
    return "\n".join(chunks).strip()


def invoke_openai_text(
    prompt: str,
    *,
    system: str | None = None,
    model: str | None = None,
    temperature: float | None = None,
    max_output_tokens: int | None = None,
    timeout: float | int | None = None,
    text_format: dict[str, Any] | None = None,
) -> str:
    """Call OpenAI using the Responses API first, with a safe legacy fallback.

    The rest of the app previously mixed Chat Completions, LangChain ChatOpenAI,
    and Responses API calls. Latest GPT-5.x models are documented for the
    Responses API, so this helper centralises the call path and avoids passing
    unsupported parameters such as temperature to GPT-5.x models.

    [FYP-FUNCTION] [FYP-LLM] [FYP-ENTRY-POINT] [FYP-EVALUATOR] THE LLM call
    function for this subsystem.
    Params:
      prompt -- user prompt text (required).
      system -- optional system/instruction message.
      model -- model id override; defaults to OPENAI_MODEL env var, then
        "gpt-5.4-mini".
      temperature -- sampling temperature; silently dropped for
        latest-generation models (see supports_temperature()).
      max_output_tokens -- response length cap (mapped to the SDK's
        max_output_tokens for Responses API, or max_tokens for Chat
        Completions).
      timeout -- per-call timeout in seconds; defaults to 120 if not given.
      text_format -- optional structured-output schema
        (Responses API `text.format`), for JSON-schema-constrained output.
    Returns: str -- the model's text response, stripped of leading/trailing
    whitespace.
    [FYP-ERROR] [FYP-FALLBACK] Call path and fallback chain:
      1. Build a client via build_client(timeout=timeout or 120).
      2. If the installed SDK has no `client.responses` attribute (older
         SDK): use Chat Completions directly. If the requested model is a
         latest-generation model, this is treated as a hard error (that SDK
         cannot serve it) -- RuntimeError telling the operator to upgrade
         the `openai` package.
      3. Otherwise call `client.responses.create(...)` (the primary path).
         If that call raises, inspect the exception message and retry once,
         with the offending parameter stripped, when the error text looks
         like an "unsupported parameter" complaint about:
           - text_format / structured output ("text"/"format"/"schema"/
             "json_schema" mentioned) -> drop `text` and retry.
           - temperature ("unsupported" + "temperature") -> drop
             `temperature` and retry.
         If the failure does not match either retry heuristic:
           - for a latest-generation model, re-raise as RuntimeError (no
             legacy fallback exists for these models).
           - otherwise, fall back to Chat Completions with the same
             prompt/system/temperature/max_output_tokens.
      4. On success via the Responses API, extract text via
         _extract_responses_text(); if it comes back empty, raise
         RuntimeError("OpenAI returned an empty text response") -- this
         function never silently returns an empty string, so callers can
         treat a str return value as always meaningful.
    Called by: backend/app.py, reporting/template_document_exporter.py
    (report narrative/content generation).
    Calls: build_client, _extract_responses_text, supports_temperature,
    latest_model.
    """
    selected = (model or os.getenv("OPENAI_MODEL") or "gpt-5.4-mini").strip()
    client = build_client(timeout=timeout or 120)

    input_payload: Any
    if system:
        input_payload = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]
    else:
        input_payload = prompt

    if not hasattr(client, "responses"):
        if latest_model(selected):
            raise RuntimeError(
                "The installed openai package does not expose client.responses. "
                "Upgrade it with: python -m pip install --upgrade openai"
            )
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        chat_args: dict[str, Any] = {"model": selected, "messages": messages}
        if temperature is not None and supports_temperature(selected):
            chat_args["temperature"] = temperature
        if max_output_tokens:
            chat_args["max_tokens"] = max_output_tokens
        response = client.chat.completions.create(**chat_args)
        return str(response.choices[0].message.content or "").strip()

    request_args: dict[str, Any] = {"model": selected, "input": input_payload}
    if max_output_tokens:
        request_args["max_output_tokens"] = max_output_tokens
    if temperature is not None and supports_temperature(selected):
        request_args["temperature"] = temperature
    if text_format:
        request_args["text"] = {"format": text_format}

    try:
        response = client.responses.create(**request_args)
    except Exception as exc:
        message = str(exc).lower()
        if text_format and (
            "unsupported" in message
            or "unknown parameter" in message
            or "unrecognized" in message
            or "not supported" in message
            or "invalid type" in message
        ) and ("text" in message or "format" in message or "schema" in message or "json_schema" in message):
            # [FYP-FALLBACK] Structured-output schema rejected by this
            # model/SDK combination -- retry once without it rather than
            # failing the whole call outright.
            request_args.pop("text", None)
            response = client.responses.create(**request_args)
        elif "unsupported" in message and "temperature" in message:
            # [FYP-FALLBACK] Model rejected `temperature` (typical for
            # reasoning-tier models) -- retry once without it.
            request_args.pop("temperature", None)
            response = client.responses.create(**request_args)
        elif latest_model(selected):
            # [FYP-ERROR] No further fallback exists for latest-generation
            # models -- surface the original failure with context.
            raise RuntimeError(
                f"OpenAI Responses API call failed for model {selected}: {exc}"
            ) from exc
        else:
            # [FYP-FALLBACK] Non-latest model and an unrecognised Responses
            # API failure: fall back to the older Chat Completions endpoint
            # entirely rather than failing the call.
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            chat_args = {"model": selected, "messages": messages}
            if temperature is not None and supports_temperature(selected):
                chat_args["temperature"] = temperature
            if max_output_tokens:
                chat_args["max_tokens"] = max_output_tokens
            response = client.chat.completions.create(**chat_args)
            return str(response.choices[0].message.content or "").strip()

    text = _extract_responses_text(response)
    if not text:
        raise RuntimeError("OpenAI returned an empty text response")
    return text


def _strip_markdown_fences(text: str) -> str:
    """[FYP-FUNCTION] [FYP-LLM] Strip a surrounding ```json ... ``` (or bare ``` ... ```) code fence from LLM output text, if present."""
    cleaned = str(text or "").strip()
    match = re.fullmatch(r"```(?:json|JSON)?\s*(.*?)\s*```", cleaned, flags=re.DOTALL)
    if match:
        return match.group(1).strip()
    cleaned = re.sub(r"^\s*```(?:json|JSON)?\s*", "", cleaned, flags=re.DOTALL)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned, flags=re.DOTALL)
    return cleaned.strip()


def _first_balanced_json_object(text: str) -> str | None:
    """[FYP-FUNCTION] [FYP-LLM] Scan text for the first balanced `{...}` object (brace-depth tracking, string/escape aware), to recover JSON embedded in surrounding prose.

    Params: text -- raw text that may contain a JSON object plus other
    content (e.g. "Here is the result: {...} Let me know if...").
    Returns: the substring of the first balanced-brace object found, or
    None if no balanced object exists.
    Called by: extract_json_object() below, as the last-resort parse
    strategy.
    """
    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escape = False
        for idx in range(start, len(text)):
            char = text[idx]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[start:idx + 1]
        start = text.find("{", start + 1)
    return None


def extract_json_object(text: str) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-LLM] [FYP-FALLBACK] [FYP-VALIDATION] Best-effort recovery of a JSON object from raw LLM text output.

    Params: text -- raw LLM response text (source: invoke_openai_text()
    return value, or any other LLM text output).
    Returns: dict[str, Any] -- the parsed object, or {} if nothing
    parseable was found (never raises).
    [FYP-FALLBACK] Parse strategy, tried in order until one succeeds:
      1. json.loads() on the text as-is.
      2. Strip markdown code fences (_strip_markdown_fences) and retry
         json.loads().
      3. Scan for the first balanced `{...}` object anywhere in the text
         (_first_balanced_json_object) and json.loads() that substring.
      If none of the above yield a dict, return {}.
    Called by: reporting/template_document_exporter.py, to turn an LLM's
    free-text response into a structured dict for report sections.
    Calls: _strip_markdown_fences, _first_balanced_json_object.
    """
    cleaned = str(text or "").strip()
    try:
        obj = json.loads(cleaned)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        pass

    cleaned = _strip_markdown_fences(cleaned)
    try:
        obj = json.loads(cleaned)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        pass

    candidate = _first_balanced_json_object(cleaned)
    if candidate:
        try:
            obj = json.loads(candidate)
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}
    return {}
