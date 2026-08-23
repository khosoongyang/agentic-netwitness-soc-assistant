"""
[FYP-FILE]
# Inputs: Receives function arguments, configured state, and persisted artifacts described below.
# Outputs: Produces return values and documented state, file, database, export, or UI effects.
# Workflow position: Aegis test and validation.
# Important dependencies: __future__, backend, json.
# Key evaluator search terms: test_extract_json_object_plain_object, test_extract_json_object_strips_markdown_fence, test_extract_json_object_with_surrounding_text, test_extract_json_object_balanced_nested_object_with_braces_in_string, test_extract_json_object_invalid_or_non_object_returns_empty_dict, [FYP-FUNCTION].
File: soc_reporting_agent/tests/test_openai_client_json_extraction.py
Purpose: Unit tests for backend/openai_client.py's extract_json_object() --
    the tolerant parser that turns an LLM's raw text response back into a
    Python dict, even when the model wraps the JSON in a markdown code
    fence, surrounds it with prose, or emits malformed/non-object trailing
    text alongside it.
Main functionalities: Feeds a handful of representative raw LLM response
    strings (plain JSON, fenced JSON, JSON with surrounding text, JSON with
    braces inside a string value, and invalid/non-object input) into
    extract_json_object() and asserts the returned dict matches exactly, or
    is an empty dict on unparsable input.
Called by: Executed by pytest, or by running
    `python -m pytest soc_reporting_agent/tests/test_openai_client_json_extraction.py`.
[FYP-CALLS] backend.openai_client -- extract_json_object().
[/FYP-FILE]
"""
from __future__ import annotations

import json

from backend.openai_client import extract_json_object


# =============================================================================
# [FYP-SECTION] TEST SETUP, FIXTURES, AND ASSERTIONS
# =============================================================================


def test_extract_json_object_plain_object():
    """[FYP-FUNCTION] Validates backend.openai_client.extract_json_object(): a bare, well-formed JSON object string parses to the equivalent dict."""
    assert extract_json_object('{"status": "ok", "items": []}') == {"status": "ok", "items": []}


def test_extract_json_object_strips_markdown_fence():
    """[FYP-FUNCTION] Validates backend.openai_client.extract_json_object(): a JSON object wrapped in a ```json ... ``` markdown code fence (common LLM output style) is stripped and parsed correctly."""
    raw = """```json
{"status": "ok", "items": ["a"]}
```"""
    assert extract_json_object(raw) == {"status": "ok", "items": ["a"]}


def test_extract_json_object_with_surrounding_text():
    """[FYP-FUNCTION] Validates backend.openai_client.extract_json_object(): a JSON object preceded and followed by free-form prose ("Here is the result: ... Done.") is located and parsed, ignoring the surrounding text."""
    raw = 'Here is the result:\n{"status": "ok", "value": 3}\nDone.'
    assert extract_json_object(raw) == {"status": "ok", "value": 3}


def test_extract_json_object_balanced_nested_object_with_braces_in_string():
    """[FYP-FUNCTION] Validates backend.openai_client.extract_json_object(): the balanced-brace scan correctly finds the true end of a nested JSON object even when a string value inside it contains literal "{"/"}" characters (e.g. PowerShell command text), and ignores trailing unbalanced junk after it."""
    payload = {
        "status": "ok",
        "nested": {"message": "PowerShell used {not json} inside command text"},
        "items": [{"id": 1}],
    }
    raw = f"prefix {json.dumps(payload)} suffix {{this is not valid"
    assert extract_json_object(raw) == payload


def test_extract_json_object_invalid_or_non_object_returns_empty_dict():
    """[FYP-FUNCTION] Validates backend.openai_client.extract_json_object(): non-JSON text and a top-level JSON array (not an object) both fail closed to an empty dict rather than raising."""
    assert extract_json_object("not json") == {}
    assert extract_json_object('["not", "an", "object"]') == {}
