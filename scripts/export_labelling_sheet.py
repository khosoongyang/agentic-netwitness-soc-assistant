# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: argparse, csv, json, random, re, sqlite3, pathlib.
# =============================================================================
# File: scripts/export_labelling_sheet.py
# Purpose: Triage Step 2 (X7) -- the mentor LABELLING KIT.
#   export: sample N incidents from soc_db/soc_incidents.db (READ-ONLY),
#     stratified by detection source (ESA vs NetWitness Endpoint) x entity
#     noise (noisy repeat entities vs rare ones), into a CSV a mentor can
#     label (disposition + one-line evidence + reviewer).
#   import: turn the labelled CSV into eval case files
#     (tests/triage_eval/cases/mentor_<id>.json) with
#     label.source = "mentor_reviewed", ready for scripts/eval_triage.py.
# Principle: "measure before you claim" -- labels need provenance; the
#   mentor labels independently of the triage output (the sheet carries no
#   Aegis verdict, to avoid circular labels).
# Inputs: soc_db/soc_incidents.db (opened mode=ro).
# Outputs: a CSV (export) / case JSON files (import). Never writes soc_db/.
# Key evaluator search terms: export_labelling_sheet, mentor_reviewed,
#   [FYP-TRIAGE-STEP2].
# =============================================================================
"""Usage:
  python scripts/export_labelling_sheet.py export --n 40 --out labelling_sheet.csv [--seed 7]
  python scripts/export_labelling_sheet.py import labelling_sheet.csv [--out-dir tests/triage_eval/cases]
  python scripts/export_labelling_sheet.py import-reviews [--workflow-db PATH] [--out-dir ...]

[FYP-TRIAGE-STEP3] import-reviews closes the loop with Step 3 (X6): triage
reviews whose ANALYST label was confirmed by the mentor's BLIND re-review
(triage_reviews.label_provenance = 'mentor_agreed', see scripts/
blind_review.py) become eval cases through the SAME case builder as the
CSV import (label.source = "mentor_reviewed"). Unconfirmed analyst labels
are never exported: a human verdict is not ground truth until an
independent re-review agrees (feedback-loop circularity).

Mentor instructions (also in the CSV header row names):
  label_disposition : true_positive | false_positive | benign_expected | needs_info
  label_evidence    : ONE line -- the observable fact that decided it
  reviewer          : your name/initials
  review_date       : YYYY-MM-DD
Leave label_disposition empty to skip a row.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "soc_db" / "soc_incidents.db"
DEFAULT_CASE_DIR = ROOT / "tests" / "triage_eval" / "cases"

DISPOSITIONS = ("true_positive", "false_positive", "benign_expected", "needs_info")
NOISY_MIN = 30            # same detection + entity seen >= 30 times overall
RARE_MAX = 3              # ... or <= 3 times
CSV_FIELDS = [
    "incident_id", "stratum", "detection_source", "entity", "entity_occurrences",
    "title", "created", "priority", "risk_score", "alert_count", "alert_titles",
    "hosts", "users", "source_ips", "destination_ips",
    "label_disposition", "label_evidence", "reviewer", "review_date",
]
_TITLE_ENTITY = re.compile(r"\sfor\s+(.+?)\s*$")

# Expected acceptable sets per mentor label. A confirmed-malicious incident
# must never be closed benign; a benign label still accepts needs_info (the
# guards require business context for benign_expected).
EXPECTED_BY_LABEL = {
    "true_positive": {"disposition_acceptable": ["true_positive", "needs_info"],
                      "must_not": ["false_positive", "benign_expected"]},
    "false_positive": {"disposition_acceptable": ["false_positive", "needs_info"],
                       "must_not": []},
    "benign_expected": {"disposition_acceptable": ["benign_expected", "needs_info"],
                        "must_not": []},
    "needs_info": {"disposition_acceptable": ["needs_info"], "must_not": []},
}


def _connect_ro(db: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro", uri=True, timeout=15)


def _source_class(created_by: str | None) -> str:
    cb = (created_by or "").lower()
    if "endpoint" in cb:
        return "netwitness_endpoint"
    if "esa" in cb:
        return "esa"
    return "other"


def _entity(title: str | None) -> str | None:
    m = _TITLE_ENTITY.search(title or "")
    return m.group(1).strip() if m else None


def _meta_list(meta: dict, key: str, cap: int = 5) -> str:
    vals = meta.get(key) if isinstance(meta, dict) else None
    if isinstance(vals, list):
        return "; ".join(str(v) for v in vals[:cap])
    return str(vals) if vals else ""


def sample_incidents(db: Path, n: int, seed: int = 7) -> list[dict]:
    """[FYP-FUNCTION] Stratified sample: (ESA | Endpoint | other) x
    (noisy | mid | rare entity), round-robin across strata so every stratum
    that exists is represented."""
    con = _connect_ro(db)
    try:
        rows = con.execute("SELECT id, title, created, raw_json FROM incidents").fetchall()
    finally:
        con.close()
    occ: Counter = Counter()
    parsed = []
    for rid, title, created, raw in rows:
        try:
            rj = json.loads(raw or "{}")
        except Exception:
            rj = {}
        src = _source_class(rj.get("createdBy"))
        ent = _entity(title)
        occ[(src, ent)] += 1
        parsed.append((rid, title, created, rj, src, ent))
    strata: dict[str, list] = defaultdict(list)
    for rid, title, created, rj, src, ent in parsed:
        k = occ[(src, ent)]
        noise = "noisy" if k >= NOISY_MIN else "rare" if k <= RARE_MAX else "mid"
        strata[f"{src}/{noise}"].append((rid, title, created, rj, src, ent, k))
    rng = random.Random(seed)
    for v in strata.values():
        v.sort(key=lambda r: r[0])
        rng.shuffle(v)
    picked, keys = [], sorted(strata)
    while len(picked) < n and any(strata[k] for k in keys):
        for k in keys:
            if strata[k] and len(picked) < n:
                picked.append((k,) + strata[k].pop())
    out = []
    for stratum, rid, title, created, rj, src, ent, k in picked:
        meta = rj.get("alertMeta") or {}
        out.append({
            "incident_id": rid, "stratum": stratum, "detection_source": rj.get("createdBy") or "",
            "entity": ent or "", "entity_occurrences": k, "title": title or "",
            "created": created or "", "priority": rj.get("priority") or "",
            "risk_score": rj.get("riskScore") if rj.get("riskScore") is not None else "",
            "alert_count": rj.get("alertCount") if rj.get("alertCount") is not None else "",
            "alert_titles": _meta_list(meta, "AlertTitles"), "hosts": _meta_list(meta, "Hostname"),
            "users": _meta_list(meta, "User"), "source_ips": _meta_list(meta, "SourceIp"),
            "destination_ips": _meta_list(meta, "DestinationIp"),
            "label_disposition": "", "label_evidence": "", "reviewer": "", "review_date": "",
        })
    return out


def export_sheet(db: Path, n: int, out: Path, seed: int = 7) -> list[dict]:
    rows = sample_incidents(db, n, seed)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    return rows


def _incident_from_db(db: Path, incident_id: str) -> dict | None:
    con = _connect_ro(db)
    try:
        row = con.execute("SELECT raw_json, title, created FROM incidents WHERE id=?",
                          (incident_id,)).fetchone()
    finally:
        con.close()
    if not row:
        return None
    try:
        inc = json.loads(row[0] or "{}")
    except Exception:
        inc = {}
    inc.setdefault("id", incident_id)
    inc.setdefault("title", row[1])
    inc.setdefault("created", row[2])
    return inc


def _write_case(out_dir: Path, iid: str, inc: dict, disp: str, *, labeller: str, date: str,
                rationale: str, description: str, provenance: dict,
                data_availability: dict | None = None) -> Path:
    """Shared case builder for both import paths (CSV sheet and
    mentor-agreed triage reviews) -- one place defines the case shape."""
    case = {
        "name": f"mentor_{iid}",
        "description": description,
        "incident": inc,
        "data_availability": data_availability or {
            "incident_source": "sqlite_slim", "alerts_fetch_attempted": False,
            "alerts_fetch_succeeded": False, "alerts_complete": False,
            "alerts_count": 0, "journal_fetch_succeeded": None,
            "warnings": ["slim SQLite copy: raw alerts not stored"]},
        "expected": EXPECTED_BY_LABEL[disp],
        "label": {"value": disp, "source": "mentor_reviewed", "labeller": labeller,
                  "date": date or "unknown", "rationale": rationale},
        **provenance,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"mentor_{re.sub(r'[^A-Za-z0-9_.-]', '_', iid)}.json"
    path.write_text(json.dumps(case, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def import_sheet(csv_path: Path, out_dir: Path, db: Path = DEFAULT_DB) -> tuple[list[Path], list[str]]:
    """[FYP-FUNCTION] Labelled CSV -> case files (label.source=mentor_reviewed).
    The incident is the SLIM SQLite copy (no raw alerts), so data_availability
    records incident_source=sqlite_slim; to evaluate with raw alerts, replace
    `incident` with an `incident_file` pointing at a Respond-API export."""
    written, problems = [], []
    out_dir.mkdir(parents=True, exist_ok=True)
    with csv_path.open(encoding="utf-8-sig", newline="") as f:
        for i, row in enumerate(csv.DictReader(f), start=2):
            disp = (row.get("label_disposition") or "").strip().lower()
            if not disp:
                continue
            iid = (row.get("incident_id") or "").strip()
            if disp not in DISPOSITIONS:
                problems.append(f"row {i} ({iid}): invalid label_disposition {disp!r}")
                continue
            if not (row.get("reviewer") or "").strip() or not (row.get("label_evidence") or "").strip():
                problems.append(f"row {i} ({iid}): reviewer and label_evidence are required")
                continue
            inc = _incident_from_db(db, iid)
            if inc is None:
                problems.append(f"row {i}: incident {iid!r} not found in {db.name}")
                continue
            written.append(_write_case(
                out_dir, iid, inc, disp, labeller=row["reviewer"].strip(),
                date=(row.get("review_date") or "").strip(),
                rationale=row["label_evidence"].strip(),
                description=(f"Mentor-labelled incident from the labelling sheet "
                             f"(stratum {row.get('stratum')})."),
                provenance={"labelling_sheet": {"file": csv_path.name, "row": i,
                                                "stratum": row.get("stratum")}}))
    return written, problems


def import_reviews(workflow_db: Path, out_dir: Path, db: Path = DEFAULT_DB) -> tuple[list[Path], list[str]]:
    """[FYP-FUNCTION] [FYP-TRIAGE-STEP3] Mentor-AGREED triage reviews -> eval
    cases. Reads the workflow DB's triage_reviews + blind_reviews (opened
    read-only); only rows with label_provenance = 'mentor_agreed' qualify
    (the analyst's and the mentor's blind label match)."""
    written, problems = [], []
    if not workflow_db.is_file():
        return written, [f"workflow DB not found: {workflow_db}"]
    con = _connect_ro(workflow_db)
    try:
        rows = con.execute(
            "SELECT r.id, r.incident_id, r.analyst_disposition, r.justification, r.analyst, "
            "b.reviewer, b.evidence_note, b.reviewed_at FROM triage_reviews r "
            "JOIN blind_reviews b ON b.review_id = r.id AND b.disposition = r.analyst_disposition "
            "WHERE r.label_provenance = 'mentor_agreed' ORDER BY r.id").fetchall()
    except sqlite3.Error as exc:
        return written, [f"review tables unreadable: {exc}"]
    finally:
        con.close()
    for rid, iid, disp, justification, analyst, reviewer, note, reviewed_at in rows:
        if disp not in DISPOSITIONS:
            problems.append(f"review {rid}: invalid disposition {disp!r}")
            continue
        inc = _incident_from_db(db, iid) if db.is_file() else None
        if inc is None:
            problems.append(f"review {rid}: incident {iid!r} not found in {db.name}")
            continue
        written.append(_write_case(
            out_dir, str(iid), inc, disp, labeller=f"{reviewer} (blind) + {analyst} (analyst)",
            date=str(reviewed_at or "")[:10],
            rationale=(note or justification or "").strip() or "agreed in blind re-review",
            description=f"Triage review #{rid}: analyst label confirmed by blind re-review.",
            provenance={"triage_review": {"review_id": rid, "label_provenance": "mentor_agreed"}}))
    return written, problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("--n", type=int, default=40)
    e.add_argument("--out", type=Path, default=ROOT / "runtime" / "eval_reports" / "labelling_sheet.csv")
    e.add_argument("--seed", type=int, default=7)
    e.add_argument("--db", type=Path, default=DEFAULT_DB)
    i = sub.add_parser("import")
    i.add_argument("csv", type=Path)
    i.add_argument("--out-dir", type=Path, default=DEFAULT_CASE_DIR)
    i.add_argument("--db", type=Path, default=DEFAULT_DB)
    r = sub.add_parser("import-reviews")
    r.add_argument("--workflow-db", type=Path, default=DEFAULT_DB)
    r.add_argument("--out-dir", type=Path, default=DEFAULT_CASE_DIR)
    r.add_argument("--db", type=Path, default=DEFAULT_DB)
    args = ap.parse_args(argv)
    if args.cmd == "export":
        rows = export_sheet(args.db, args.n, args.out, args.seed)
        print(f"[labelling] wrote {len(rows)} rows to {args.out}")
        print("[labelling] strata: " + ", ".join(f"{k}={v}" for k, v in
                                                 sorted(Counter(r['stratum'] for r in rows).items())))
        return 0
    if args.cmd == "import-reviews":
        written, problems = import_reviews(args.workflow_db, args.out_dir, args.db)
    else:
        written, problems = import_sheet(args.csv, args.out_dir, args.db)
    for p in problems:
        print(f"[labelling] SKIPPED {p}", file=sys.stderr)
    print(f"[labelling] wrote {len(written)} case file(s) to {args.out_dir}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
