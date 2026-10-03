"""tests/test_triage_time_handling.py -- audit T-13 / T-14.

T-13: _extract_incident_time sliced the first 19 chars and stamped "UTC" on
any offset, so "2026-07-20T10:00:00+08:00" became "10:00:00 UTC" (8 h off);
epoch milliseconds were returned raw.
T-14: naive datetime.utcnow() timestamps (deprecated in 3.12, and compared
against tz-aware timestamps elsewhere).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from agents.triage import soc_triage_agent as sta


@pytest.mark.parametrize("raw,expected", [
    ("2026-07-20T10:00:00+08:00", "2026-07-20 02:00:00 UTC"),
    ("2026-07-20T10:00:00-05:30", "2026-07-20 15:30:00 UTC"),
    ("2026-07-20T10:00:00Z", "2026-07-20 10:00:00 UTC"),
    ("2026-07-20T10:00:00.123Z", "2026-07-20 10:00:00 UTC"),
    ("2026-07-20T10:00:00.123456", "2026-07-20 10:00:00 UTC"),   # naive => assumed UTC (unchanged)
    ("2026-07-20 10:00:00", "2026-07-20 10:00:00 UTC"),
    (1784541600000, "2026-07-20 10:00:00 UTC"),                   # epoch ms
    (1784541600, "2026-07-20 10:00:00 UTC"),                      # epoch s
    ("1784541600000", "2026-07-20 10:00:00 UTC"),
])
def test_incident_time_is_converted_to_utc(raw, expected):
    assert sta._extract_incident_time({"created": raw}) == expected


def test_unparseable_time_is_returned_verbatim_never_mislabelled():
    assert sta._extract_incident_time({"created": "last Tuesday night"}) == "last Tuesday night"
    assert sta._extract_incident_time({}) == "—"


def test_no_naive_utcnow_left_in_triage_agent():
    src = Path(sta.__file__).read_text(encoding="utf-8")
    code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
    assert not re.search(r"\butcnow\(\)", code)


def test_ticket_created_at_is_timezone_aware(tmp_path, monkeypatch):
    from test_triage_step1_agent_integration import FakeLLM, _history_db, _incident
    monkeypatch.setattr(sta, "_TICKET_DB", tmp_path / "t.db")
    sta._ticket_db_init()
    a = sta.TriageAgent(baseline_db_path=_history_db(tmp_path / "h.db"))
    monkeypatch.setattr(a, "_call", FakeLLM())
    res = a.triage(_incident(), force=True)
    assert res["ticket"]["created_at"].endswith("+00:00")
