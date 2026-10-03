# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: argparse, csv, html, json, random, pathlib,
#   workflow.review_store.
# =============================================================================
# File: scripts/blind_review.py
# Purpose: [FYP-TRIAGE-STEP3] X6 blind re-review for the mentor.
#   export: sample N triage reviews (optionally stratified by the analyst
#     disposition), shuffle them, and write a self-contained HTML (every
#     value escaped, no scripts, no external assets) plus a CSV. Each case
#     shows the evidence-packet snapshot taken AT DECISION TIME and the
#     raw-alert signatures -- but NO AI disposition, NO analyst disposition,
#     no hypotheses and no justification, so the mentor labels blind.
#   import: load the mentor's labelled CSV into the blind_reviews table;
#     matching labels mark the review label_provenance='mentor_agreed'.
# Principle: feedback-loop circularity -- a human verdict is not ground
#   truth until an independent (blind) re-review agrees. Automation bias --
#   the mentor never sees what the AI said.
# Outputs: runtime/eval_reports/blind_review_<ts>.{html,csv} (git-ignored).
# Key evaluator search terms: blind_review, blind_reviews, [FYP-TRIAGE-STEP3].
# =============================================================================
"""Usage:
  python scripts/blind_review.py export --sample 30 --seed 7 [--stratify disposition] [--out-dir DIR]
  python scripts/blind_review.py import labelled.csv [--reviewer NAME]

CSV columns the mentor fills in:
  disposition   : true_positive | false_positive | benign_expected | needs_info
  evidence_note : ONE line -- the observable fact that decided it
  reviewer      : your name/initials (or pass --reviewer on import)
  reviewed_at   : YYYY-MM-DD (optional)
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import random
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_OUT = ROOT / "runtime" / "eval_reports"
CSV_FIELDS = ["case_no", "review_id", "incident_id", "disposition", "evidence_note",
              "reviewer", "reviewed_at"]
# Keys that would leak a verdict and are therefore NEVER exported.
_FORBIDDEN_KEYS = {"disposition", "proposed_disposition", "analyst_disposition",
                   "ai_final_disposition", "ai_proposed_disposition", "hypotheses",
                   "justification", "agrees_with_ai", "uncertainty", "guard_actions",
                   "analyst_initial_disposition", "lookalike_ruled_out", "suppression_match",
                   "analyst_note"}


def _scrub(node):
    """Drop every verdict-bearing key at any depth (defence in depth: the
    evidence packet itself holds no disposition, but context.analyst_note /
    suppression_match are human verdict hints and are removed too)."""
    if isinstance(node, dict):
        return {k: _scrub(v) for k, v in node.items() if k not in _FORBIDDEN_KEYS}
    if isinstance(node, list):
        return [_scrub(v) for v in node]
    return node


def sample_reviews(reviews: list[dict], n: int, seed: int, stratify: str | None) -> list[dict]:
    rng = random.Random(seed)
    pool = [r for r in reviews if r.get("evidence_packet")]
    if stratify == "disposition":
        groups: dict[str, list[dict]] = defaultdict(list)
        for r in pool:
            groups[str(r.get("analyst_disposition"))].append(r)
        for g in groups.values():
            rng.shuffle(g)
        picked: list[dict] = []
        keys = sorted(groups)
        while len(picked) < n and any(groups[k] for k in keys):
            for k in keys:
                if groups[k] and len(picked) < n:
                    picked.append(groups[k].pop())
    else:
        picked = rng.sample(pool, min(n, len(pool)))
    rng.shuffle(picked)
    return picked


def _signatures(packet: dict) -> list[dict]:
    sig = ((packet.get("raw_alerts") or {}).get("signatures") or {})
    value = sig.get("value") if isinstance(sig, dict) else None
    items = (value or {}).get("items") if isinstance(value, dict) else None
    out = []
    for s in items or []:
        out.append({k: s.get(k) for k in ("alert_name", "process", "command_line", "count",
                                           "threat_desc", "max_risk_score")})
    return out


def _leaf_rows(packet: dict, prefix: str = ""):
    for key, node in (packet or {}).items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(node, dict) and set(node) == {"value", "status", "source"}:
            yield path, node
        elif isinstance(node, dict):
            yield from _leaf_rows(node, path)


def _esc(value) -> str:
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, default=str)
    if len(value) > 600:
        value = value[:600] + " [truncated]"
    return html.escape(value, quote=True)


def render_html(cases: list[dict], *, generated_at: str) -> str:
    """Self-contained HTML; EVERY dynamic value goes through html.escape."""
    parts = ["<!DOCTYPE html><html><head><meta charset='utf-8'>",
             "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">",
             "<title>Aegis blind triage re-review</title><style>",
             "body{font-family:system-ui,sans-serif;margin:24px;color:#111}"
             "table{border-collapse:collapse;width:100%;margin:8px 0}"
             "td,th{border:1px solid #ccc;padding:4px 6px;font-size:12px;vertical-align:top;text-align:left}"
             ".missing{color:#999}.case{border-top:3px solid #333;margin-top:28px;padding-top:8px}"
             "code{white-space:pre-wrap;word-break:break-all}",
             "</style></head><body>",
             "<h1>Blind triage re-review</h1>",
             f"<p>Generated {_esc(generated_at)}. {len(cases)} case(s), shuffled. The AI verdict and "
             "the analyst's verdict are deliberately hidden. For each case record a disposition "
             "(true_positive / false_positive / benign_expected / needs_info) and one line of "
             "evidence in the CSV. Missing evidence is unknown, not safe.</p>"]
    for c in cases:
        p = c["packet"]
        parts.append(f"<div class='case'><h2>Case {c['case_no']}</h2>"
                     f"<p>Incident <code>{_esc(c['incident_id'])}</code></p>")
        sigs = _signatures(p)
        if sigs:
            parts.append("<h3>Raw-alert signatures</h3><table><tr><th>Alert</th><th>Process</th>"
                         "<th>Command line</th><th>Count</th><th>threat_desc</th><th>Max risk</th></tr>")
            for s in sigs:
                parts.append("<tr>" + "".join(f"<td><code>{_esc(s.get(k))}</code></td>" for k in
                                              ("alert_name", "process", "command_line", "count",
                                               "threat_desc", "max_risk_score")) + "</tr>")
            parts.append("</table>")
        parts.append("<h3>Evidence packet (snapshot at decision time)</h3><table>"
                     "<tr><th>Path</th><th>Status</th><th>Value</th><th>Source</th></tr>")
        for path, leaf in _leaf_rows(p):
            if path == "raw_alerts.signatures":
                continue
            cls = " class='missing'" if leaf["status"] == "missing" else ""
            val = "-" if leaf["status"] == "missing" else _esc(leaf["value"])
            parts.append(f"<tr{cls}><td><code>{_esc(path)}</code></td><td>{_esc(leaf['status'])}</td>"
                         f"<td><code>{val}</code></td><td>{_esc(leaf['source'])}</td></tr>")
        parts.append("</table></div>")
    parts.append("</body></html>")
    return "\n".join(parts)


def export(out_dir: Path, n: int, seed: int, stratify: str | None) -> dict:
    """[FYP-FUNCTION] Write the blind HTML + CSV. Returns paths + count."""
    from workflow import review_store
    reviews = review_store.list_reviews(include_packet=True)
    picked = sample_reviews(reviews, n, seed, stratify)
    cases = []
    for i, r in enumerate(picked, start=1):
        cases.append({"case_no": i, "review_id": r["id"], "incident_id": r["incident_id"],
                      "packet": _scrub(r["evidence_packet"])})
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    hpath = out_dir / f"blind_review_{ts}.html"
    cpath = out_dir / f"blind_review_{ts}.csv"
    hpath.write_text(render_html(cases, generated_at=now.isoformat()), encoding="utf-8")
    with cpath.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for c in cases:
            w.writerow({"case_no": c["case_no"], "review_id": c["review_id"],
                        "incident_id": c["incident_id"], "disposition": "", "evidence_note": "",
                        "reviewer": "", "reviewed_at": ""})
    return {"cases": len(cases), "html": str(hpath), "csv": str(cpath)}


def import_csv(path: Path, reviewer: str | None = None) -> dict:
    """[FYP-FUNCTION] Load the mentor's labels into blind_reviews."""
    from workflow import review_store
    rows = []
    with path.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if not str(row.get("disposition") or "").strip():
                continue
            if reviewer and not str(row.get("reviewer") or "").strip():
                row["reviewer"] = reviewer
            rows.append(row)
    return review_store.import_blind_reviews(rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workflow-db", type=Path, default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("--sample", type=int, default=30)
    e.add_argument("--seed", type=int, default=7)
    e.add_argument("--stratify", choices=["disposition"], default=None)
    e.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    i = sub.add_parser("import")
    i.add_argument("csv", type=Path)
    i.add_argument("--reviewer", default=None)
    args = ap.parse_args(argv)
    if args.workflow_db is not None:
        from workflow import state_store as wss
        wss.DB_FILE = args.workflow_db
    if args.cmd == "export":
        res = export(args.out_dir, args.sample, args.seed, args.stratify)
        print(f"[blind-review] {res['cases']} case(s) -> {res['html']} + {res['csv']}")
        return 0
    res = import_csv(args.csv, args.reviewer)
    for s in res["skipped"]:
        print(f"[blind-review] SKIPPED row {s['row']}: {s['reason']}", file=sys.stderr)
    print(f"[blind-review] imported {res['imported']} label(s)")
    return 1 if res["skipped"] else 0


if __name__ == "__main__":
    sys.exit(main())
