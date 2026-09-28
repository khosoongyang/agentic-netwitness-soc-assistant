"""tests/test_triage_step1_baseline.py -- Triage Step 1: historical baseline
(agents/triage/baseline.py) and entity parsing/classification.

Fully offline: every test builds its own temporary SQLite `incidents` table
(the same columns the real soc_db/soc_incidents.db uses for this purpose:
id, title, created, raw_json). The real soc_db/ is never opened.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from agents.triage.baseline import (
    KNOWN_NOISY_THRESHOLD_30D,
    classify_entity,
    compute_baseline,
    detection_source,
    extract_entity,
    incident_created_time,
)

ESA = ("High Risk Alerts: ESA", "6618e5a2dddef60d6853bec1")
ENDPOINT = ("High Risk Alerts: NetWitness Endpoint", "6618e5a2dddef60d6853bebf")
# An unrelated later row so the DB's coverage extends past the incident
# under test (otherwise the baseline is -- correctly -- "unknown").
COVERAGE_TAIL = ("INC-TAIL", "High Risk Alerts: ESA for 203.0.113.1", "2026-06-01T00:00:00", ESA)


def _make_db(path: Path, rows: list[tuple[str, str, str, tuple[str, str] | None]]) -> Path:
    """rows: (id, title, created 'YYYY-MM-DDTHH:MM:SS', (createdBy, ruleId) or None)."""
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE incidents (id TEXT PRIMARY KEY, title TEXT, severity TEXT, "
                "created TEXT, raw_json TEXT, triage_result_json TEXT)")
    for rid, title, created, src in rows:
        raw = {"id": rid, "title": title, "created": created + ".000Z"}
        if src:
            raw["createdBy"], raw["ruleId"] = src
        con.execute("INSERT INTO incidents (id, title, created, raw_json, triage_result_json) "
                    "VALUES (?,?,?,?,?)",
                    (rid, title, created, json.dumps(raw),
                     # A past LLM verdict that must NEVER influence the baseline.
                     json.dumps({"assessment": {"disposition": "false_positive"}})))
    con.commit()
    con.close()
    return path


def _incident(inc_id="INC-100", entity="192.168.10.14", created="2026-03-01T12:00:00.000Z",
              src=ESA, **extra) -> dict:
    inc = {"id": inc_id, "title": f"{src[0] if src else 'Alert'} for {entity}", "created": created}
    if src:
        inc["createdBy"], inc["ruleId"] = src
    inc.update(extra)
    return inc


@pytest.fixture()
def history_db(tmp_path):
    """Coverage 2025-01-01 .. 2026-06-01. Incident under test: 2026-03-01T12:00:00."""
    rows = [
        ("INC-1", "High Risk Alerts: ESA for 192.168.10.14", "2025-01-01T00:00:00", ESA),   # all-time only
        ("INC-2", "High Risk Alerts: ESA for 192.168.10.14", "2026-01-15T00:00:00", ESA),   # 90d
        ("INC-3", "High Risk Alerts: ESA for 192.168.10.14", "2026-02-10T00:00:00", ESA),   # 30d
        ("INC-4", "High Risk Alerts: ESA for 192.168.10.14", "2026-02-27T00:00:00", ESA),   # 7d
        ("INC-5", "High Risk Alerts: NetWitness Endpoint for 192.168.10.14",
         "2026-02-28T00:00:00", ENDPOINT),                                                  # other source, 7d
        ("INC-6", "High Risk Alerts: ESA for 192.168.10.140", "2026-02-28T00:00:00", ESA),  # different entity
        ("INC-7", "High Risk Alerts: ESA for 10.0.0.1", "2026-02-28T00:00:00", ESA),        # different entity
        ("INC-100", "High Risk Alerts: ESA for 192.168.10.14", "2026-03-01T12:00:00", ESA), # self
        ("INC-8", "High Risk Alerts: ESA for 192.168.10.14", "2026-03-01T12:00:01", ESA),   # 1s in the future
        ("INC-9", "High Risk Alerts: ESA for 192.168.10.14", "2026-06-01T00:00:00", ESA),   # future
    ]
    return _make_db(tmp_path / "hist.db", rows)


# =============================================================================
# Windows relative to the incident's own created time
# =============================================================================

def test_windows_are_relative_to_incident_time(history_db):
    b = compute_baseline(_incident(), history_db)
    assert b["status"] == "measured"
    assert b["as_of"] == "2026-03-01T12:00:00"
    assert b["same_source_entity"] == {"7d": 1, "30d": 2, "90d": 3, "all_time": 4}
    assert b["same_entity_any_source"] == {"7d": 2, "30d": 3, "90d": 4, "all_time": 5}
    assert b["first_seen"] == "2025-01-01T00:00:00"
    assert b["last_seen"] == "2026-02-27T00:00:00"
    assert b["is_first_occurrence"] is False


def test_same_incident_later_in_history_sees_more(history_db):
    """Same entity, a later anchor time: counts move with the anchor, not 'now'."""
    b = compute_baseline(_incident(inc_id="INC-X", created="2026-02-11T00:00:00Z"), history_db)
    assert b["same_source_entity"]["all_time"] == 3   # INC-1, INC-2, INC-3
    assert b["same_source_entity"]["7d"] == 1         # INC-3


def test_self_is_excluded(history_db):
    b = compute_baseline(_incident(), history_db)
    # INC-100 has the same entity/source and created == as_of; it must not count.
    assert b["same_source_entity"]["all_time"] == 4


def test_self_excluded_by_id_even_if_timestamp_is_earlier(tmp_path):
    db = _make_db(tmp_path / "self.db", [
        ("INC-0", "High Risk Alerts: ESA for 192.168.10.14", "2025-01-01T00:00:00", ESA),
        # the stored copy of this very incident, with an earlier stored time
        ("INC-100", "High Risk Alerts: ESA for 192.168.10.14", "2026-02-01T00:00:00", ESA),
        ("INC-Z", "High Risk Alerts: ESA for 192.168.10.14", "2026-06-01T00:00:00", ESA),
    ])
    b = compute_baseline(_incident(), db)
    assert b["same_source_entity"]["all_time"] == 1


def test_no_future_leakage(history_db):
    b = compute_baseline(_incident(), history_db)
    # INC-8 (+1 s) and INC-9 (June) are after the incident: never counted.
    assert b["same_entity_any_source"]["all_time"] == 5
    assert b["last_seen"] < b["as_of"]


def test_detection_source_uses_created_by_and_rule_id(history_db):
    """ESA vs NetWitness Endpoint on the same entity are different sources."""
    b = compute_baseline(_incident(src=ENDPOINT), history_db)
    assert b["same_source_entity"]["all_time"] == 1          # only INC-5
    assert b["same_entity_any_source"]["all_time"] == 5


def test_entity_match_is_exact_not_prefix(history_db):
    b = compute_baseline(_incident(entity="192.168.10.140"), history_db)
    assert b["same_entity_any_source"]["all_time"] == 1      # INC-6 only, not .14


def test_first_occurrence(history_db):
    b = compute_baseline(_incident(entity="172.16.5.5"), history_db)
    assert b["status"] == "measured"
    assert b["is_first_occurrence"] is True
    assert b["same_source_entity"]["all_time"] == 0
    assert b["first_seen"] is None


def test_known_noisy_threshold(tmp_path):
    rows = [(f"INC-{i}", "High Risk Alerts: ESA for 10.9.9.9",
             f"2026-02-{(i % 28) + 1:02d}T01:00:00", ESA)
            for i in range(KNOWN_NOISY_THRESHOLD_30D)]
    rows.append(("INC-OLD", "High Risk Alerts: ESA for 10.9.9.9", "2025-01-01T00:00:00", ESA))
    db = _make_db(tmp_path / "noisy.db", rows)
    b = compute_baseline(_incident(entity="10.9.9.9", created="2026-03-01T00:00:00Z"), db)
    assert b["same_source_entity"]["30d"] == KNOWN_NOISY_THRESHOLD_30D
    assert b["is_known_noisy"] is True
    b2 = compute_baseline(_incident(entity="192.168.10.14"), _make_db(tmp_path / "q.db", [
        ("A", "High Risk Alerts: ESA for 192.168.10.14", "2025-01-01T00:00:00", ESA),
        COVERAGE_TAIL]))
    assert b2["is_known_noisy"] is False


def test_coverage_window_and_partial_windows(history_db, tmp_path):
    b = compute_baseline(_incident(), history_db)
    assert b["coverage_start"] == "2025-01-01T00:00:00"
    assert b["coverage_end"] == "2026-06-01T00:00:00"
    assert b["window_complete"] == {"7d": True, "30d": True, "90d": True}
    # Incident 10 days after coverage starts: 30d/90d windows are incomplete.
    db = _make_db(tmp_path / "young.db", [
        ("A", "High Risk Alerts: ESA for 192.168.10.14", "2026-02-20T00:00:00", ESA),
        ("B", "High Risk Alerts: ESA for 192.168.10.14", "2026-02-25T00:00:00", ESA),
        COVERAGE_TAIL])
    b2 = compute_baseline(_incident(), db)
    assert b2["status"] == "measured"
    assert b2["window_complete"] == {"7d": True, "30d": False, "90d": False}


def test_past_verdicts_are_never_read(history_db):
    """The fixture DB stores a 'false_positive' verdict on every row; the
    baseline output carries only counts and never a disposition."""
    b = compute_baseline(_incident(), history_db)
    assert "false_positive" not in json.dumps(b)
    assert "disposition" not in json.dumps(b)


# =============================================================================
# Unknown / missing = unknown, not safe
# =============================================================================

def test_unresolved_entity_is_unknown(history_db):
    inc = {"id": "INC-U", "title": "Something odd happened", "created": "2026-03-01T00:00:00Z",
           "createdBy": ESA[0], "ruleId": ESA[1]}
    b = compute_baseline(inc, history_db)
    assert b["status"] == "unknown"
    assert "entity unresolved" in b["reason"]
    assert b["same_source_entity"]["30d"] is None
    assert b["is_first_occurrence"] is None


def test_missing_db_is_unknown(tmp_path):
    b = compute_baseline(_incident(), tmp_path / "does_not_exist.db")
    assert b["status"] == "unknown"
    assert "not found" in b["reason"]
    assert not (tmp_path / "does_not_exist.db").exists()   # never created


def test_db_without_incidents_table_is_unknown(tmp_path):
    db = tmp_path / "empty.db"
    sqlite3.connect(str(db)).close()
    b = compute_baseline(_incident(), db)
    assert b["status"] == "unknown"


def test_missing_created_time_is_unknown(history_db):
    inc = _incident()
    del inc["created"]
    assert compute_baseline(inc, history_db)["status"] == "unknown"


def test_incident_after_coverage_is_unknown(history_db):
    """A zero count for a period the DB does not cover must not read as 'first occurrence'."""
    b = compute_baseline(_incident(created="2026-09-01T00:00:00Z"), history_db)
    assert b["status"] == "unknown"
    assert "after baseline coverage" in b["reason"]


def test_incident_before_coverage_is_unknown(history_db):
    assert compute_baseline(_incident(created="2024-01-01T00:00:00Z"), history_db)["status"] == "unknown"


def test_missing_created_by_measures_entity_only(history_db):
    b = compute_baseline(_incident(src=None, title="Alert for 192.168.10.14"), history_db)
    assert b["status"] == "measured"
    assert b["same_source_entity"]["30d"] is None
    assert b["same_entity_any_source"]["all_time"] == 5


# =============================================================================
# Read-only access
# =============================================================================

def test_database_is_opened_read_only(history_db):
    before = history_db.read_bytes()
    compute_baseline(_incident(), history_db)
    assert history_db.read_bytes() == before
    assert not Path(str(history_db) + "-wal").exists() or Path(str(history_db) + "-wal").stat().st_size == 0


def test_path_with_spaces_and_ampersand(tmp_path):
    """The real project path contains spaces and '&'; the URI must be encoded."""
    d = tmp_path / "RP Internship @ Evvo & EIP"
    d.mkdir()
    db = _make_db(d / "x.db", [("A", "High Risk Alerts: ESA for 192.168.10.14",
                                "2026-02-01T00:00:00", ESA), COVERAGE_TAIL])
    assert compute_baseline(_incident(), db)["status"] == "measured"


# =============================================================================
# Entity parsing and classification
# =============================================================================

@pytest.mark.parametrize("value,kind", [
    ("192.168.10.14", "ip_internal"),
    ("10.1.2.3", "ip_internal"),
    ("172.16.0.1", "ip_internal"),
    ("172.32.0.1", "ip_external"),
    ("127.0.0.1", "ip_internal"),
    ("149.50.96.45", "ip_external"),
    ("8.8.8.8", "ip_external"),
    ("fe80:0:0:0:f7c4:bff3:4c73:f8d1", "ip_internal"),
    ("KELLYWANG", "hostname"),
    ("DESKTOP-HU4A549", "hostname"),
    ("CORP\\jdoe", "user"),
    ("jdoe@corp.example", "user"),
    ("", "unresolved"),
    (None, "unresolved"),
    ("!!! ???", "unresolved"),
])
def test_classify_entity(value, kind):
    assert classify_entity(value) == kind


@pytest.mark.parametrize("title,value,kind", [
    ("High Risk Alerts: ESA for 192.168.10.14", "192.168.10.14", "ip_internal"),
    ("High Risk Alerts: NetWitness Endpoint for KELLYWANG", "KELLYWANG", "hostname"),
    ("High Risk Alerts: NetWitness Endpoint for HOST KELLYWANG", "KELLYWANG", "hostname"),
    ("High Risk Alerts: NetWitness Endpoint for FILE powershell.exe", "powershell.exe", "file"),
    ("Rule for finance for 149.50.96.45", "149.50.96.45", "ip_external"),
])
def test_extract_entity_from_title(title, value, kind):
    ent = extract_entity({"title": title})
    assert (ent["value"], ent["kind"], ent["source"]) == (value, kind, "incident.title")


def test_extract_entity_uses_name_for_respond_api_exports():
    ent = extract_entity({"name": "High Risk Alerts: NetWitness Endpoint for KELLYWANG"})
    assert ent["value"] == "KELLYWANG"


def test_extract_entity_falls_back_to_alert_meta():
    ent = extract_entity({"title": "Lateral Movement via SSH",
                          "alertMeta": {"SourceIp": ["10.0.0.9"], "DestinationIp": ["8.8.8.8"]}})
    assert ent == {"value": "10.0.0.9", "kind": "ip_internal",
                   "source": "incident.alertMeta.SourceIp[0]", "raw": "10.0.0.9"}
    ent2 = extract_entity({"title": "x", "alertMeta": {"DestinationIp": ["8.8.8.8"]}})
    assert ent2["value"] == "8.8.8.8" and ent2["kind"] == "ip_external"


def test_extract_entity_unresolved():
    assert extract_entity({"title": "Repeated failed logons"})["kind"] == "unresolved"


def test_detection_source_and_created_time_parsing():
    assert detection_source({"createdBy": ESA[0], "ruleId": ESA[1]})["key"] == f"{ESA[0]}|{ESA[1]}"
    assert detection_source({})["key"] is None
    assert incident_created_time({"created": "2025-12-01T07:33:39.338+00:00"})[0] == "2025-12-01T07:33:39"
    assert incident_created_time({"created": "2025-12-01T09:33:39+02:00"})[0] == "2025-12-01T07:33:39"
    assert incident_created_time({"created": 1764574415204})[0] == "2025-12-01T07:33:35"
    assert incident_created_time({}) == (None, None)
