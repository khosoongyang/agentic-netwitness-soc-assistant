"""tests/test_triage_step3_scripts.py -- [FYP-TRIAGE-STEP3] X6 scripts.

  * scripts/blind_review.py export: HTML + CSV contain NO dispositions
    (neither AI nor analyst), every value is escaped, cases are shuffled;
    import: labels land in blind_reviews.
  * scripts/export_labelling_sheet.py import-reviews: only mentor-AGREED
    reviews become eval cases (label.source = mentor_reviewed).
  * scripts/triage_metrics.py writes .json + .md with the caveat.
All offline, temp DBs only.
"""
from __future__ import annotations

import csv
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest

from workflow import commands, review_store
from workflow import state_store as wss

from test_triage_step3_review import _review, _triage_result

ROOT = Path(__file__).resolve().parents[1]
XSS = "<img src=x onerror=alert(1)>"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"_s3_{name}", ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"_s3_{name}"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    """Three decided cases with structured reviews (TP / FP / needs_info)."""
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "wf.db")
    wss.db_init()
    specs = [("INC-A", "true_positive", {}),
             ("INC-B", "false_positive", {"lookalike_considered": "x", "rule_tuning_note": "tune",
                                          "disagreement_reason": "rule broken"}),
             ("INC-C", "needs_info", {"lookalike_considered": "x",
                                      "disagreement_reason": "more data"})]
    ids = {}
    for inc, disp, extra in specs:
        with wss.db_connect() as con:
            con.execute("INSERT INTO incidents (id, title, severity, status, raw_json) VALUES (?,?,?,?,?)",
                        (inc, f"ESA for 10.0.0.5", "HIGH", "New",
                         json.dumps({"id": inc, "title": "ESA for 10.0.0.5"})))
            con.commit()
        run_id = wss.start_run(inc)
        tri = _triage_result("true_positive")
        # attacker-controlled text inside the snapshot -> must render inert
        tri["evidence_packet"]["detection"]["createdBy"]["value"] = XSS
        wss._guarded_update(inc, run_id, {
            "parsing_status": "Complete", "triage_status": "Awaiting Approval",
            "workflow_status": "Awaiting Approval", "approval_stage": "triage",
            "triage_result_json": json.dumps(tri)})
        ids[inc] = commands.approve_stage(
            inc, "triage", analyst="Alice",
            review=_review(analyst_disposition=disp, **extra))["review_id"]
    return ids


def test_blind_export_contains_no_dispositions_and_escapes(seeded, tmp_path):
    br = _load("blind_review")
    res = br.export(tmp_path / "out", n=10, seed=3, stratify="disposition")
    assert res["cases"] == 3
    html_text = Path(res["html"]).read_text(encoding="utf-8")
    csv_text = Path(res["csv"]).read_text(encoding="utf-8")
    for leak in ("true_positive", "false_positive", "needs_info", "benign_expected",
                 "Repeated ESA hits", "tune"):
        # the mentor instructions list the label NAMES once; no case may carry one
        body = html_text.split("</p>", 1)[1]
        assert leak not in body, leak
    assert "disposition" not in body and "hypotheses" not in body
    assert XSS not in html_text and "&lt;img src=x onerror=alert(1)&gt;" in html_text
    assert "<script" not in html_text.lower()
    rows = list(csv.DictReader(csv_text.splitlines()))
    assert len(rows) == 3 and all(r["disposition"] == "" for r in rows)
    assert sorted(int(r["review_id"]) for r in rows) == sorted(seeded.values())
    for disp in ("true_positive", "false_positive", "needs_info"):
        assert disp not in csv_text.split("\n", 1)[1]


def test_blind_export_is_shuffled_and_seeded(seeded, tmp_path):
    br = _load("blind_review")
    reviews = review_store.list_reviews(include_packet=True)
    a = [r["id"] for r in br.sample_reviews(reviews, 3, 1, None)]
    b = [r["id"] for r in br.sample_reviews(reviews, 3, 1, None)]
    assert a == b and sorted(a) == sorted(seeded.values())


def test_blind_import_then_labelling_import_reviews(seeded, tmp_path):
    br = _load("blind_review")
    res = br.export(tmp_path / "out", n=10, seed=3, stratify=None)
    labelled = tmp_path / "labelled.csv"
    rows = list(csv.DictReader(Path(res["csv"]).read_text(encoding="utf-8").splitlines()))
    truth = {seeded["INC-A"]: "true_positive", seeded["INC-B"]: "needs_info",
             seeded["INC-C"]: "needs_info"}
    with labelled.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            r["disposition"] = truth[int(r["review_id"])]
            r["evidence_note"] = "decided by the raw alert"
            w.writerow(r)
    out = br.import_csv(labelled, reviewer="Mentor")
    assert out == {"imported": 3, "skipped": []}
    prov = {r["id"]: r["label_provenance"] for r in review_store.list_reviews()}
    assert prov[seeded["INC-A"]] == "mentor_agreed"
    assert prov[seeded["INC-B"]] == "mentor_disputed"
    assert prov[seeded["INC-C"]] == "mentor_agreed"

    # the baseline incidents DB for the case builder (temp copy of 2 incidents)
    base = tmp_path / "base.db"
    con = sqlite3.connect(str(base))
    con.execute("CREATE TABLE incidents (id TEXT PRIMARY KEY, title TEXT, created TEXT, raw_json TEXT)")
    for iid in ("INC-A", "INC-C"):
        con.execute("INSERT INTO incidents VALUES (?,?,?,?)",
                    (iid, "ESA for 10.0.0.5", "2026-07-20T00:00:00", json.dumps({"id": iid})))
    con.commit()
    con.close()
    els = _load("export_labelling_sheet")
    written, problems = els.import_reviews(wss.DB_FILE, tmp_path / "cases", base)
    assert problems == [] and len(written) == 2           # INC-B (disputed) is NOT exported
    case = json.loads(written[0].read_text(encoding="utf-8"))
    assert case["label"]["source"] == "mentor_reviewed"
    assert case["triage_review"]["label_provenance"] == "mentor_agreed"
    assert case["expected"] == els.EXPECTED_BY_LABEL[case["label"]["value"]]


def test_triage_metrics_script_writes_json_and_md(seeded, tmp_path):
    tm = _load("triage_metrics")
    res = tm.write_report(tmp_path / "rep")
    m = json.loads(Path(res["json"]).read_text(encoding="utf-8"))
    assert m["n_reviews"] == 3 and m["small_sample"] is True
    assert m["override_rate"] == pytest.approx(2 / 3)
    md = Path(res["markdown"]).read_text(encoding="utf-8")
    assert "Cohen's kappa" in md and "CAVEAT" in md and md.isascii()


def test_metrics_and_backlog_scripts_on_empty_db(tmp_path, monkeypatch):
    monkeypatch.setattr(wss, "DB_FILE", tmp_path / "empty.db")
    tm = _load("triage_metrics")
    m = json.loads(Path(tm.write_report(tmp_path / "rep")["json"]).read_text(encoding="utf-8"))
    assert m["n_reviews"] == 0 and m["pairs"]["analyst_vs_mentor"]["kappa"] is None
    etb = _load("export_tuning_backlog")
    out = etb.export(tmp_path / "bl")
    assert out["items"] == 0 and (tmp_path / "bl" / "index.md").is_file()
