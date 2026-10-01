"""tests/test_triage_step2_labelling.py -- Triage Step 2 / X7: the mentor
labelling kit (scripts/export_labelling_sheet.py) export/import round-trip.

Label provenance: imported cases carry label.source = mentor_reviewed plus
reviewer, date and one-line evidence, and validate as eval cases. The DB is
opened read-only and never modified.
"""
from __future__ import annotations

import csv
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _db(path: Path) -> Path:
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE incidents (id TEXT PRIMARY KEY, title TEXT, created TEXT, raw_json TEXT)")
    rows = []
    for i in range(40):   # noisy ESA entity
        rows.append((f"INC-N{i}", "High Risk Alerts: ESA for 10.0.0.9", f"2026-01-{i % 28 + 1:02d}T00:00:00",
                     {"createdBy": "High Risk Alerts: ESA", "priority": "HIGH", "riskScore": 70,
                      "alertCount": 1, "alertMeta": {"SourceIp": ["10.0.0.9"], "AlertTitles": ["C2 beacon"]}}))
    for i in range(5):    # rare ESA entities
        rows.append((f"INC-R{i}", f"High Risk Alerts: ESA for 172.16.0.{i}", "2026-02-01T00:00:00",
                     {"createdBy": "High Risk Alerts: ESA", "alertMeta": {}}))
    for i in range(5):    # rare Endpoint entities
        rows.append((f"INC-E{i}", f"High Risk Alerts: NetWitness Endpoint for HOST{i}", "2026-02-02T00:00:00",
                     {"createdBy": "High Risk Alerts: NetWitness Endpoint",
                      "alertMeta": {"Hostname": [f"HOST{i}"], "User": ["bob"]}}))
    for rid, title, created, raw in rows:
        con.execute("INSERT INTO incidents VALUES (?,?,?,?)", (rid, title, created, json.dumps(raw)))
    con.commit()
    con.close()
    return path


def test_export_is_stratified_and_label_free(tmp_path):
    kit = _load("export_labelling_sheet")
    db = _db(tmp_path / "inc.db")
    before = db.stat().st_mtime_ns
    out = tmp_path / "sheet.csv"
    rows = kit.export_sheet(db, 9, out, seed=1)
    assert db.stat().st_mtime_ns == before
    strata = {r["stratum"] for r in rows}
    assert {"esa/noisy", "esa/rare", "netwitness_endpoint/rare"} <= strata
    with out.open(encoding="utf-8-sig") as f:
        read = list(csv.DictReader(f))
    assert len(read) == 9 and list(read[0].keys()) == kit.CSV_FIELDS
    # no Aegis verdict on the sheet -> the mentor labels independently
    assert not any(k for k in read[0] if "aegis" in k.lower() or "triage" in k.lower())
    assert all(r["label_disposition"] == "" for r in read)
    noisy = next(r for r in read if r["stratum"] == "esa/noisy")
    assert int(noisy["entity_occurrences"]) == 40 and noisy["source_ips"] == "10.0.0.9"


def test_import_round_trip_creates_valid_mentor_cases(tmp_path):
    kit = _load("export_labelling_sheet")
    ev = _load("eval_triage")
    db = _db(tmp_path / "inc.db")
    sheet = tmp_path / "sheet.csv"
    kit.export_sheet(db, 6, sheet, seed=3)
    with sheet.open(encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    rows[0].update(label_disposition="true_positive", label_evidence="beacon to known C2 IP",
                   reviewer="Mentor A", review_date="2026-10-02")
    rows[1].update(label_disposition="False_Positive", label_evidence="rule matched backup job",
                   reviewer="Mentor A", review_date="2026-10-02")
    rows[2].update(label_disposition="maybe", reviewer="Mentor A", label_evidence="x")
    rows[3].update(label_disposition="benign_expected")            # no reviewer -> rejected
    with sheet.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=kit.CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    out_dir = tmp_path / "cases"
    written, problems = kit.import_sheet(sheet, out_dir, db)
    assert len(written) == 2 and len(problems) == 2
    assert any("invalid label_disposition" in p for p in problems)
    assert any("reviewer and label_evidence are required" in p for p in problems)
    cases = ev.load_cases([str(out_dir / "*.json")])
    by_label = {c["label"]["value"]: c for c in cases}
    tp = by_label["true_positive"]
    assert tp["label"] == {"value": "true_positive", "source": "mentor_reviewed", "labeller": "Mentor A",
                           "date": "2026-10-02", "rationale": "beacon to known C2 IP"}
    assert tp["expected"]["must_not"] == ["false_positive", "benign_expected"]
    assert tp["incident"]["id"] == rows[0]["incident_id"]
    assert tp["data_availability"]["incident_source"] == "sqlite_slim"
    assert by_label["false_positive"]["expected"]["disposition_acceptable"] == ["false_positive", "needs_info"]


def test_cli_import_exit_code_reports_problems(tmp_path):
    kit = _load("export_labelling_sheet")
    db = _db(tmp_path / "inc.db")
    sheet = tmp_path / "s.csv"
    assert kit.main(["export", "--n", "3", "--out", str(sheet), "--db", str(db)]) == 0
    assert kit.main(["import", str(sheet), "--out-dir", str(tmp_path / "c"), "--db", str(db)]) == 0
