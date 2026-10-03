# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: argparse, datetime, pathlib, agents.triage.feedback,
#   workflow.review_store.
# =============================================================================
# File: scripts/export_tuning_backlog.py
# Purpose: [FYP-TRIAGE-STEP3] X3 -- write the rule-tuning backlog (false
#   positive analyst reviews, aggregated per detection source + raw-alert
#   signature + entity) as one Markdown stub per rule in Palantir's
#   Alerting & Detection Strategy (ADS) format. Unknown sections are TODO,
#   never invented. Output: runtime/tuning_backlog/ (git-ignored).
# Principle: SOC method Step 10 "If it's an FP from a broken rule, flag it
#   for tuning"; FP != Benign-Expected (benign-expected verdicts go to
#   scoped suppression proposals instead, never here).
# Inputs: the workflow DB (workflow.state_store.DB_FILE or --workflow-db).
# Outputs: ADS_<source>__<signature>__<entity>.md + index.md.
# Key evaluator search terms: export_tuning_backlog, ADS, [FYP-TRIAGE-STEP3].
# =============================================================================
"""Usage:
  python scripts/export_tuning_backlog.py [--out runtime/tuning_backlog] [--workflow-db PATH]
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_OUT = ROOT / "runtime" / "tuning_backlog"


def export(out_dir: Path = DEFAULT_OUT) -> dict:
    """[FYP-FUNCTION] Write one ADS stub per backlog item + an index."""
    from agents.triage import feedback
    from workflow import review_store
    items = feedback.aggregate_tuning_backlog(review_store.list_reviews(dispositions=("false_positive",)))
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    files = []
    for item in items:
        path = out_dir / feedback.ads_filename(item)
        path.write_text(feedback.render_ads_stub(item, generated_at=stamp), encoding="utf-8")
        files.append(str(path))
    index = ["# Rule-tuning backlog", "", f"Generated {stamp}. {len(items)} rule(s).", "",
             "| FP count | Detection source | Signature | Entity | Stub |", "|---|---|---|---|---|"]
    for item, f in zip(items, files):
        index.append(f"| {item['fp_count']} | {feedback._md(item['detection_source'])} | "
                     f"{feedback._md(item['alert_signature'])} | {feedback._md(item['entity'])} | "
                     f"{Path(f).name} |")
    (out_dir / "index.md").write_text("\n".join(index) + "\n", encoding="utf-8")
    return {"items": len(items), "files": files, "out_dir": str(out_dir)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--workflow-db", type=Path, default=None,
                    help="workflow SQLite DB (default: workflow.state_store.DB_FILE)")
    args = ap.parse_args(argv)
    if args.workflow_db is not None:
        from workflow import state_store as wss
        wss.DB_FILE = args.workflow_db
    res = export(args.out)
    print(f"[tuning-backlog] wrote {res['items']} ADS stub(s) to {res['out_dir']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
