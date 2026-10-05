"""tests/test_stage_output_paths.py -- long-standing failure root cause.

Parsing / Threat-Intel output dirs were REP_DIR/outputs/<incident>/<run_id>/<stage>
where run_id = "<incident>@<timestamp>-<hex>", i.e. the incident id twice.
With a 150-char checkout path and Windows MAX_PATH (260, LongPathsEnabled=0
on this machine) any incident id longer than ~15 chars made
open(.../parsing/processed_alert.json) fail with [Errno 2] -- the 3
test_parsing_integration failures, and the same crash for real long ids.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from workflow import engine as sw


@pytest.mark.parametrize("inc", ["INC-1", "INC-INTEGRATION-1", "X" * 120])
def test_stage_dir_paths_fit_windows_max_path(inc):
    run_id = f"{inc}@20261005-095824-8101b3"
    for stage in ("parsing", "threat_intel"):
        p = sw._stage_output_dir(inc, run_id, stage) / "processed_alert.json"
        assert len(str(p)) < 260, (len(str(p)), stage)


def test_stage_dir_is_deterministic_and_distinct():
    a = sw._stage_output_dir("INC-1", "INC-1@x-1", "parsing")
    assert a == sw._stage_output_dir("INC-1", "INC-1@x-1", "parsing")
    assert a != sw._stage_output_dir("INC-1", "INC-1@x-2", "parsing")
    assert a != sw._stage_output_dir("INC-2", "INC-2@x-1", "parsing")
    assert a.parent != sw._stage_output_dir("INC-1", "INC-1@x-1", "threat_intel").parent or a.name != "threat_intel"
    assert a.name == "parsing"
    assert Path(sw.REP_DIR / "outputs") in a.parents


def test_short_ids_keep_the_readable_layout():
    """Existing on-disk layout (and tests that build it by hand) for ordinary
    ids is unchanged: outputs/<incident>/<run_id>/<stage>."""
    d = sw._stage_output_dir("INC-HANDOFF-1", "run-handoff-1", "parsing")
    assert d == sw.REP_DIR / "outputs" / "INC-HANDOFF-1" / "run-handoff-1" / "parsing"


def test_all_stage_dir_builders_use_the_helper():
    src = Path(sw.__file__).read_text(encoding="utf-8")
    code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
    assert '/ _safe(run_id) / "parsing"' not in code
    assert '/ _safe(run_id) / "threat_intel"' not in code
