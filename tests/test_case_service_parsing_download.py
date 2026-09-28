"""Regression coverage for backend/services/case_service.py's Parsing
download endpoint: the downloaded JSON must be exactly the persisted
canonical parser result's normalised_alert -- not a frontend
reconstruction, not the whole compact summary wrapper."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.services import case_service
from backend.errors import StageResultNotAvailableError
from workflow import state_store as wss


@pytest.fixture()
def db_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "workflow.db"
    monkeypatch.setattr(wss, "DB_FILE", path)
    wss.db_init()
    return path


def _seed_case(case_id: str, *, parsing_result: dict | None) -> str:
    run_id = wss.start_run(case_id)
    if parsing_result is not None:
        wss.save_parsing_result(case_id, run_id, parsing_result)
        wss.set_parsing_status(case_id, run_id, "Complete")
    return run_id


def test_download_returns_the_persisted_normalised_alert(db_path):
    normalised_alert = {
        "alert_summary": {"alert_id": "INC-DL-1"},
        "network_indicators": {"source_ips": ["10.0.0.5"]},
    }
    _seed_case("INC-DL-1", parsing_result={
        "run_id": "irrelevant-for-this-test",
        "status": "completed",
        "normalised_alert": normalised_alert,
        "processed_alert": {"incident_id": "INC-DL-1"},
    })

    data, filename = case_service.get_parsing_result_download("INC-DL-1", database_path=db_path)

    assert filename == "INC-DL-1_normalised_alert.json"
    payload = json.loads(data)
    assert payload == normalised_alert


def test_download_is_not_passed_through_the_display_sanitiser(db_path):
    # The display sanitiser redacts any key tokenising to "key" and
    # truncates strings over 4,000 chars -- both of which would corrupt the
    # parser's real schema (extraction_summary.key_fields_found,
    # raw_meta_key_count) and long command lines in the downloaded file.
    long_command = "powershell.exe -NoProfile " + "A" * 5000
    normalised_alert = {
        "alert_summary": {"alert_id": "INC-DL-4"},
        "process_indicators": {"command_lines": [long_command]},
        "parser_metadata": {
            "raw_meta_key_count": 20,
            "extraction_summary": {"key_fields_found": ["alert_id"], "key_fields_missing": ["protocol"]},
        },
        "data_quality": {"raw_meta_key_count": 20},
    }
    _seed_case("INC-DL-4", parsing_result={"status": "completed", "normalised_alert": normalised_alert})

    data, _ = case_service.get_parsing_result_download("INC-DL-4", database_path=db_path)

    assert json.loads(data) == normalised_alert


def test_download_falls_back_to_whole_result_when_normalised_alert_absent(db_path):
    # Defensive path: if a persisted result somehow has no normalised_alert
    # (e.g. an older/partial record), the download must not come back empty.
    result_without_normalised_alert = {"status": "completed", "summary": "x"}
    _seed_case("INC-DL-2", parsing_result=result_without_normalised_alert)

    data, filename = case_service.get_parsing_result_download("INC-DL-2", database_path=db_path)
    payload = json.loads(data)
    assert payload["status"] == "completed"
    assert payload["summary"] == "x"


def test_download_raises_when_parsing_has_not_run(db_path):
    _seed_case("INC-DL-3", parsing_result=None)

    with pytest.raises(StageResultNotAvailableError):
        case_service.get_parsing_result_download("INC-DL-3", database_path=db_path)
