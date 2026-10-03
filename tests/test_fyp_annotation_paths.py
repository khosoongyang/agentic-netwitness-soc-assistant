"""tests/test_fyp_annotation_paths.py -- audit T-22.

Evaluator-facing annotations pointed at modules that no longer exist
(soc_workflow.py, case_view.py, workflow_state_store.py,
soc_triage_agent/soc_triage_agent.py). They now name the current files.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STALE = re.compile(r"soc_workflow\.py|(?<![\w/])case_view\.py|workflow_state_store\.py|"
                   r"soc_triage_agent/soc_triage_agent\.py")


def _py_files():
    for base in ("agents", "workflow", "backend"):
        for p in (ROOT / base).rglob("*.py"):
            if "__pycache__" not in p.parts:
                yield p


def test_no_stale_module_paths_in_fyp_annotations():
    offenders = []
    for p in _py_files():
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if "[FYP-" in line and STALE.search(line):
                offenders.append(f"{p.relative_to(ROOT)}:{n}")
    assert offenders == [], offenders[:10]


def test_engine_usage_points_at_the_runnable_module_form():
    src = (ROOT / "workflow" / "engine.py").read_text(encoding="utf-8")
    assert "python -m workflow.engine --incident-file" in src
    assert "python soc_workflow.py" not in src
