from __future__ import annotations

import pytest

import soc_workflow as sw
import workflow_state_store as wss


@pytest.fixture(autouse=True)
def _isolated_workflow(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    monkeypatch.setattr(sw, "PIPELINE_DB_FILE", tmp_path / "pipeline.db")
    monkeypatch.setattr(sw, "_TRUSTED_OUTPUT_ROOT", tmp_path / "artifacts")
    wss.db_init()


def test_parsing_only_does_not_invoke_or_start_triage(monkeypatch):
    def _triage_must_not_run(*args, **kwargs):
        raise AssertionError("Parsing action must not run Triage")

    monkeypatch.setattr(sw, "mock_triage_result", _triage_must_not_run)

    result = sw.run_until_triage_approval(
        {"id": "INC-PARSE-ONLY", "title": "Parsing boundary test"},
        use_mock_triage=True,
        parsing_only=True,
    )

    state = wss.get_state("INC-PARSE-ONLY")
    assert result["stages"]["parsing"] == "completed"
    assert result["stages"]["triage"] == "pending"
    assert "triage" not in result
    assert state["parsing_status"] == "Complete"
    assert state["triage_status"] == "Pending"
    assert state["triage_result_json"] is None
    assert state["workflow_status"] == "Awaiting Action"
