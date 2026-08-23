"""
[FYP-FILE]
# Important dependencies: __future__, json, pathlib, pytest, re, soc_workflow, sys, types.
File: tests/test_ai_stage_summaries.py
Purpose: Verifies the short "AI summary" orientation layer shown on each
    stage card in app.py's My Workspace — soc_workflow.py's
    limit_ai_summary_sentences() hard cap, generate_stage_ai_summary()
    (Threat Intelligence/Investigation/Reporting) and
    generate_parsing_ai_summary() (Parsing), plus
    workflow_state_store.save_stage_ai_summary()'s merge-not-overwrite
    persistence of the generated summary alongside the stage's full native
    result.
Main functionalities: Injects a fake backend.openai_client module so no
    real OpenAI call is made, calls the summary-generation functions with
    representative stage result dicts, and asserts the returned/persisted
    ai_summary text, the prompt/system text sent to the (fake) model, and
    that app.py/soc_workflow.py's source wires this AI summary layer in
    ahead of/alongside the native per-stage summary rather than replacing
    it.
Inputs: A monkeypatched sys.modules["backend.openai_client"] whose
    invoke_openai_text() returns a scripted string and records every call;
    representative stage_result dicts for Parsing/Triage/Threat
    Intelligence/Investigation/Reporting; an isolated tmp_path SQLite DB
    (wss.DB_FILE) for the persistence test. Two tests instead read the raw
    source text of app.py and soc_workflow.py from ROOT.
Outputs: Assertions on the ai_summary/ai_thinking strings returned by the
    generate_* functions, on the recorded fake-OpenAI call kwargs (prompt
    content, system instructions, max_output_tokens), on the merged JSON
    persisted via save_stage_ai_summary(), and on literal substrings
    present in app.py/soc_workflow.py source.
Workflow position: Presentation/orientation layer over the real per-stage
    results produced by soc_workflow.py's run_* stage functions (see
    tests/test_threat_intel_workflow.py, tests/test_investigation_stage.py,
    tests/test_reporting_stage.py for those stages themselves).
Called by: Executed by pytest, or by running
    `python -m pytest tests/test_ai_stage_summaries.py`.
Calls: soc_workflow (sw) — limit_ai_summary_sentences(),
    generate_stage_ai_summary(), generate_parsing_ai_summary();
    workflow_state_store (wss) — db_init(), start_run(), _guarded_update(),
    save_stage_ai_summary(), get_state().
Key evaluator search terms: ai_summary, limit_ai_summary_sentences,
    generate_stage_ai_summary, generate_parsing_ai_summary,
    save_stage_ai_summary, ai_thinking, sentence guard, backend.openai_client.
[/FYP-FILE]
"""
from __future__ import annotations

import json
import re
import sys
import types
from pathlib import Path

import pytest

import soc_workflow as sw
import workflow_state_store as wss


ROOT = Path(__file__).resolve().parent.parent


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] Fixtures and stubs
# ══════════════════════════════════════════════════════════════════════════

def _install_fake_openai(monkeypatch, response: str, calls: list[dict]) -> None:
    """[FYP-FUNCTION] Test helper (not itself a test). Injects a fake
    backend/backend.openai_client module pair into sys.modules whose
    invoke_openai_text() always returns the given `response` string and
    appends its call kwargs (prompt, system, model, max_output_tokens, ...)
    to `calls`, so generate_stage_ai_summary()/generate_parsing_ai_summary()
    can be exercised without a real OpenAI API key or network call."""
    backend = types.ModuleType("backend")
    openai_client = types.ModuleType("backend.openai_client")

    # [FYP-FUNCTION] `_invoke` — implements the invoke operation used by the surrounding test and validation workflow.
    # [FYP-INPUT] Parameters: `prompt`, `**kwargs`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `append`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _invoke(prompt: str, **kwargs) -> str:
        calls.append({"prompt": prompt, **kwargs})
        return response

    openai_client.invoke_openai_text = _invoke
    backend.openai_client = openai_client
    monkeypatch.setitem(sys.modules, "backend", backend)
    monkeypatch.setitem(sys.modules, "backend.openai_client", openai_client)


def _sentence_count(text: str) -> int:
    """[FYP-FUNCTION] Test helper (not itself a test). Counts sentence-ending
    punctuation (optionally followed by a closing quote/bracket) in `text`,
    used to confirm limit_ai_summary_sentences() output never exceeds its cap."""
    return len(re.findall(r"[.!?](?:[\"')\]]+)?(?:\s|$)", text))


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] limit_ai_summary_sentences() — hard cap on model output
# ══════════════════════════════════════════════════════════════════════════

def test_sentence_guard_keeps_only_two_sentences_without_splitting_ips():
    """[FYP-FUNCTION] Validates soc_workflow.limit_ai_summary_sentences()
    truncates to the first two sentences of a longer passage, while its
    sentence-boundary detection does not mistake the dots inside IP
    addresses (10.0.0.5, 8.8.8.8) for sentence terminators.
    """
    text = (
        "Host 10.0.0.5 contacted 8.8.8.8. "
        "The connection was blocked. Review the endpoint. Close the case."
    )
    limited = sw.limit_ai_summary_sentences(text)
    assert limited == (
        "Host 10.0.0.5 contacted 8.8.8.8. The connection was blocked."
    )
    assert _sentence_count(limited) == 2


def test_sentence_guard_caps_a_single_run_on_at_eighty_words():
    """[FYP-FUNCTION] Validates soc_workflow.limit_ai_summary_sentences()'s
    word-count fallback: a single 120-word run-on sentence (no punctuation
    to split on until the end) is truncated to 80 words and terminated with
    a period, still counting as exactly one sentence.
    """
    limited = sw.limit_ai_summary_sentences(" ".join(["signal"] * 120))
    assert len(limited.split()) == 80
    assert limited.endswith(".")
    assert _sentence_count(limited) == 1


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] generate_stage_ai_summary() / generate_parsing_ai_summary()
# — prompting and output enforcement per stage
# ══════════════════════════════════════════════════════════════════════════

# [FYP-EVALUATOR]
@pytest.mark.parametrize(
    ("stage", "result", "expected_fact"),
    [
        (
            "Parsing",
            {"status": "completed", "processed_alert": {"host": "WKSTN-7"}},
            "WKSTN-7",
        ),
        (
            "Triage",
            {"ticket": {"classification": "HIGH", "matched_ioc_count": 3}},
            "HIGH",
        ),
        (
            "Threat Intelligence Enrichment",
            {"status": "completed", "enrichment_risk_score": 82},
            "82",
        ),
        (
            "Investigation",
            {"status": "completed", "severity": "High", "summary": "Lateral movement."},
            "Lateral movement",
        ),
        (
            "Reporting",
            {"status": "completed", "report_quality_score": 94},
            "94",
        ),
    ],
)
def test_every_stage_uses_ai_context_and_hard_caps_model_output(
    monkeypatch,
    stage,
    result,
    expected_fact,
):
    """[FYP-FUNCTION] Validates soc_workflow.generate_stage_ai_summary()
    across all five stages (Parsing, Triage, Threat Intelligence
    Enrichment, Investigation, Reporting). For each stage, a
    representative `result` dict is passed in and asserts: the prompt sent
    to the (fake) model contains a real fact pulled from that stage's
    result (host, classification, risk score, summary text, quality
    score), the system instructions request "one or two" sentences,
    max_output_tokens is capped at 180, and the returned ai_summary has
    already been passed through limit_ai_summary_sentences() — the fake
    model's 3-sentence reply is truncated to 2.
    """
    calls: list[dict] = []
    _install_fake_openai(
        monkeypatch,
        "The stage completed. The evidence affects the next decision. "
        "This third sentence must not survive.",
        calls,
    )

    generated = sw.generate_stage_ai_summary(stage, result, model="test-model")

    assert expected_fact in calls[0]["prompt"]
    assert "one or two" in calls[0]["system"]
    assert calls[0]["max_output_tokens"] == 180
    assert generated["ai_summary"] == (
        "The stage completed. The evidence affects the next decision."
    )
    assert _sentence_count(generated["ai_summary"]) == 2


def test_parsing_summary_is_capped_without_truncating_thinking(monkeypatch):
    """[FYP-FUNCTION] Validates soc_workflow.generate_parsing_ai_summary(),
    the Parsing-stage-specific variant that also returns an ai_thinking
    field. Asserts the SUMMARY: portion of the fake model's reply is capped
    to 2 sentences by limit_ai_summary_sentences(), the THINKING: bullet
    list is preserved in ai_thinking untruncated, and the system prompt
    requests "exactly 1-2" sentences.
    """
    calls: list[dict] = []
    _install_fake_openai(
        monkeypatch,
        "SUMMARY: First finding. Second finding. Third finding.\n"
        "THINKING: - Checked host\n- Checked IP",
        calls,
    )

    generated = sw.generate_parsing_ai_summary(
        {"processed_alert": {"host": "WKSTN-7"}}, model="test-model"
    )

    assert generated["ai_summary"] == "First finding. Second finding."
    assert "Checked host" in generated["ai_thinking"]
    assert "exactly 1-2" in calls[0]["system"]


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] save_stage_ai_summary() persistence, and source-level wiring
# checks against app.py / soc_workflow.py
# ══════════════════════════════════════════════════════════════════════════

def test_summary_backfill_merges_without_overwriting_native_stage_output(
    tmp_path,
    monkeypatch,
):
    """[FYP-FUNCTION] Validates workflow_state_store.save_stage_ai_summary()
    against an isolated tmp_path SQLite DB: seeds a stage's
    investigation_result_json with a full native result (summary,
    severity), then saves an AI summary for that same stage. Asserts the
    generated ai_summary/ai_summary_model fields are merged into the
    existing JSON blob without clobbering the native "summary"/"severity"
    fields already there — the AI summary is additive, not a replacement.
    """
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "summary-backfill.db")
    wss.db_init()
    run_id = wss.start_run("INC-1")
    native = {
        "status": "completed",
        "summary": "Full native investigation output remains intact.",
        "severity": "High",
    }
    wss._guarded_update(
        "INC-1",
        run_id,
        {"investigation_result_json": json.dumps(native)},
    )

    assert wss.save_stage_ai_summary(
        "INC-1",
        run_id,
        "Investigation",
        {
            "ai_summary": "Short first sentence. Short second sentence.",
            "ai_summary_model": "test-model",
        },
    )
    saved = json.loads(wss.get_state("INC-1")["investigation_result_json"])
    assert saved["summary"] == native["summary"]
    assert saved["severity"] == "High"
    assert saved["ai_summary"] == (
        "Short first sentence. Short second sentence."
    )


# [FYP-USED-BY]
def test_workspace_summary_card_never_falls_back_to_native_stage_summary():
    """[FYP-FUNCTION] Source-level guard on the preserved Streamlit app's My
    Workspace stage card rendering (not a runtime/behavioral test): reads the
    legacy app's raw source and asserts it still contains the literal
    statements that wire up the AI-summary-first display contract — assigning
    `_stage_summary = _stage_ai_summary`, re-applying
    `wf_limit_ai_summary_sentences()` to any previously saved AI summary,
    and calling `wss.save_stage_ai_summary(`. Catches an accidental
    regression to showing the native stage summary instead of the AI one.
    """
    source = (ROOT / "scripts" / "legacy_streamlit_app.py").read_text(encoding="utf-8")
    assert "_stage_summary = _stage_ai_summary" in source
    assert "wf_limit_ai_summary_sentences(_saved_ai_summary)" in source
    assert "wss.save_stage_ai_summary(" in source


def test_successful_downstream_stages_generate_ai_summary_before_persisting():
    """[FYP-FUNCTION] Source-level guard on soc_workflow.py's stage-runner
    functions: reads soc_workflow.py's raw source and asserts each
    downstream stage (Threat Intelligence Enrichment, Investigation,
    Reporting) still calls generate_stage_ai_summary() with its own result
    dict as soon as that stage completes successfully, so an AI summary is
    always generated and available before the result is persisted/shown.
    """
    source = (ROOT / "soc_workflow.py").read_text(encoding="utf-8")
    assert (
        'generate_stage_ai_summary(\n'
        '                    "Threat Intelligence Enrichment", ti_result'
    ) in source
    assert 'generate_stage_ai_summary("Investigation", inv_result)' in source
    assert 'generate_stage_ai_summary("Reporting", reporting_result)' in source
