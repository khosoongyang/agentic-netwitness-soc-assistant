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


def _install_fake_openai(monkeypatch, response: str, calls: list[dict]) -> None:
    backend = types.ModuleType("backend")
    openai_client = types.ModuleType("backend.openai_client")

    def _invoke(prompt: str, **kwargs) -> str:
        calls.append({"prompt": prompt, **kwargs})
        return response

    openai_client.invoke_openai_text = _invoke
    backend.openai_client = openai_client
    monkeypatch.setitem(sys.modules, "backend", backend)
    monkeypatch.setitem(sys.modules, "backend.openai_client", openai_client)


def _sentence_count(text: str) -> int:
    return len(re.findall(r"[.!?](?:[\"')\]]+)?(?:\s|$)", text))


def test_sentence_guard_keeps_only_two_sentences_without_splitting_ips():
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
    limited = sw.limit_ai_summary_sentences(" ".join(["signal"] * 120))
    assert len(limited.split()) == 80
    assert limited.endswith(".")
    assert _sentence_count(limited) == 1


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


def test_summary_backfill_merges_without_overwriting_native_stage_output(
    tmp_path,
    monkeypatch,
):
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


def test_workspace_summary_card_never_falls_back_to_native_stage_summary():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "_stage_summary = _stage_ai_summary" in source
    assert "wf_limit_ai_summary_sentences(_saved_ai_summary)" in source
    assert "wss.save_stage_ai_summary(" in source


def test_successful_downstream_stages_generate_ai_summary_before_persisting():
    source = (ROOT / "soc_workflow.py").read_text(encoding="utf-8")
    assert (
        'generate_stage_ai_summary(\n'
        '                    "Threat Intelligence Enrichment", ti_result'
    ) in source
    assert 'generate_stage_ai_summary("Investigation", inv_result)' in source
    assert 'generate_stage_ai_summary("Reporting", reporting_result)' in source
