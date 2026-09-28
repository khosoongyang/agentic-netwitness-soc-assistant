"""
[FYP-FILE]
# Important dependencies: __future__, pytest, soc_workflow, workflow_state_store.
File: tests/test_parsing_only.py
Purpose: Verifies the "Parsing only" workflow boundary in soc_workflow.py —
    that running the Parsing stage in isolation (parsing_only=True) never
    triggers Triage, even when a mock Triage implementation is available.
Main functionalities: Runs sw.run_until_triage_approval() with
    parsing_only=True and asserts that Triage is left untouched (status
    "Pending", no result JSON) while Parsing reports "Complete".
Inputs: A minimal in-memory incident dict ({"id": "INC-PARSE-ONLY", ...});
    an isolated tmp_path SQLite DB (workflow_state_store.DB_FILE),
    tmp_path pipeline DB (soc_workflow.PIPELINE_DB_FILE), and tmp_path
    artifact root (soc_workflow._TRUSTED_OUTPUT_ROOT) via monkeypatch — no
    real soc_db/ or outputs/ directories are touched. mock_triage_result is
    monkeypatched to raise if invoked, acting as a tripwire.
Outputs: Assertions on the dict returned by run_until_triage_approval()
    (result["stages"]) and on workflow_state_store's persisted incident
    state (state["parsing_status"], state["triage_status"], etc.).
Workflow position: Validates the Parsing stage boundary at the very start
    of the pipeline (Parsing -> Triage handoff in soc_workflow.py) —
    ensures "Parsing only" mode never silently cascades into Triage.
Called by: Executed by pytest, or by running
    `python -m pytest tests/test_parsing_only.py`.
Calls: soc_workflow (sw) — run_until_triage_approval(), mock_triage_result;
    workflow_state_store (wss) — DB_FILE, db_init(), get_state().
Key evaluator search terms: parsing only, parsing boundary, triage not
    started, run_until_triage_approval, stage isolation.
[/FYP-FILE]
"""
from __future__ import annotations

import pytest

from workflow import engine as sw
from workflow import state_store as wss


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] Fixtures — isolated DB/artifact root for every test
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _isolated_workflow(tmp_path, monkeypatch):
    """[FYP-FUNCTION] Isolate workflow state per test.

    Redirects workflow_state_store.DB_FILE, soc_workflow.PIPELINE_DB_FILE,
    and soc_workflow._TRUSTED_OUTPUT_ROOT to a pytest tmp_path, then
    initializes a fresh schema via wss.db_init(). Runs automatically for
    every test in this file so no test can read/write the real soc_db/ or
    outputs/ directories.
    """
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "workflow.db")
    monkeypatch.setattr(sw, "PIPELINE_DB_FILE", tmp_path / "pipeline.db")
    monkeypatch.setattr(sw, "_TRUSTED_OUTPUT_ROOT", tmp_path / "artifacts")
    wss.db_init()


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] Test — Parsing-only boundary
# ══════════════════════════════════════════════════════════════════════════

# [FYP-VALIDATION] [FYP-STAGE-LOCK] [FYP-EVALUATOR]
def test_parsing_only_does_not_invoke_or_start_triage(monkeypatch):
    """[FYP-FUNCTION] Parsing-only mode must not start Triage.

    Sets up: monkeypatches sw.mock_triage_result to an assertion-raising
    tripwire so any call into Triage fails the test immediately.
    Exercises: sw.run_until_triage_approval(..., use_mock_triage=True,
    parsing_only=True) on a bare incident dict.
    Asserts: the returned stages dict shows parsing "completed" and triage
    "pending" (with no "triage" key at all), and the persisted
    workflow_state_store record shows triage_status="Pending",
    triage_result_json=None, parsing_status="Complete", and
    workflow_status="Awaiting Action".
    Validates: the parsing_only flag in soc_workflow.run_until_triage_approval()
    — the single most illustrative test in this file, since it is the only
    test and it directly demonstrates the Parsing/Triage stage boundary.
    """
    # [FYP-FUNCTION] `_triage_must_not_run` — implements the triage must not run operation used by the surrounding test and validation workflow.
    # [FYP-INPUT] Parameters: `*args`, `**kwargs`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis test and validation workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `AssertionError`.
    # [FYP-ERROR] Raises explicit validation/processing errors to the caller; no silent fallback is applied here.

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
