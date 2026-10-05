"""tests/test_no_tracked_file_mutation.py -- regression for the test leak that
wrote a garbage payload into the TRACKED fixture
agents/reporting/inputs/threat_intel_result.json.

handoff_to_reporting()'s flat (non run-scoped) path now honours
REPORTING_INPUT_DIR / REPORTING_OUTPUT_DIR -- the same variables the
reporting adapter reads -- and conftest.py points them at a temp tree.
conftest.py also fails the whole session if any tracked file changes
(pytest_sessionfinish guard).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from workflow import engine as sw

ROOT = Path(__file__).resolve().parents[1]
TRACKED_INPUTS = ROOT / "agents" / "reporting" / "inputs"


def _digests() -> dict[str, str]:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(TRACKED_INPUTS.glob("*.json"))}


def test_flat_reporting_handoff_writes_to_isolated_dirs_not_tracked_fixtures():
    before = _digests()
    ticket_id = sw.handoff_to_reporting(
        {"ticket": {"incident_id": "INC-LEAK", "unc": "#LEAK", "classification": "HIGH"},
         "metakeys_payload": {"incident_id": "INC-LEAK"}},
        {"id": "INC-LEAK", "title": "leak check"},
        {"status": "completed", "severity": "High"},
        threat_intel_result={"enrichment_risk_level": 12345, "garbage": object()})
    assert ticket_id
    assert _digests() == before, "handoff_to_reporting() mutated tracked reporting fixtures"
    out = Path(os.environ["REPORTING_OUTPUT_DIR"])
    written = json.loads((out / "threat_intel_result.json").read_text(encoding="utf-8"))
    assert written["enrichment_risk_level"] == 12345
    assert ROOT not in Path(os.environ["REPORTING_INPUT_DIR"]).resolve().parents or \
        ".pt-" in os.environ["REPORTING_INPUT_DIR"]


def test_conftest_has_tracked_file_guard():
    import conftest
    assert hasattr(conftest, "pytest_sessionfinish")
    assert conftest._tracked_changes() is not None or conftest.shutil.which("git") is None
