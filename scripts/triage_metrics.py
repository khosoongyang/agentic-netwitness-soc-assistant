# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: argparse, datetime, json, pathlib,
#   agents.triage.metrics, workflow.review_store.
# =============================================================================
# File: scripts/triage_metrics.py
# Purpose: [FYP-TRIAGE-STEP3] X6 -- agreement metrics over the labelled
#   verdict store (Cohen's kappa + confusion matrix + raw agreement for
#   analyst vs mentor, AI-final vs mentor, AI-final vs analyst, AI-proposed
#   vs AI-final; override / needs_info / revision-after-reveal rates).
#   Writes runtime/eval_reports/triage_metrics_<ts>.json and .md
#   (git-ignored). Pure Python; no sklearn.
# Principle: feedback-loop circularity (human verdicts are not ground truth
#   until a blind re-review agrees) and automation bias (blind_first
#   revision rate). n < 30 always carries the small-sample caveat.
# Key evaluator search terms: triage_metrics, Cohen's kappa,
#   [FYP-TRIAGE-STEP3].
# =============================================================================
"""Usage:
  python scripts/triage_metrics.py [--out-dir runtime/eval_reports] [--workflow-db PATH] [--mentor NAME]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_OUT = ROOT / "runtime" / "eval_reports"


def write_report(out_dir: Path = DEFAULT_OUT, mentor: str | None = None) -> dict:
    from agents.triage import metrics
    from workflow import review_store
    m = metrics.compute_triage_metrics(review_store.list_reviews(), review_store.list_blind_reviews(),
                                       mentor=mentor)
    now = datetime.now(timezone.utc)
    m["generated_at"] = now.isoformat()
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = now.strftime("%Y%m%d-%H%M%S")
    jpath = out_dir / f"triage_metrics_{ts}.json"
    mpath = out_dir / f"triage_metrics_{ts}.md"
    jpath.write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")
    mpath.write_text(metrics.render_metrics_markdown(m, generated_at=m["generated_at"]), encoding="utf-8")
    return {"metrics": m, "json": str(jpath), "markdown": str(mpath)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--workflow-db", type=Path, default=None)
    ap.add_argument("--mentor", default=None)
    args = ap.parse_args(argv)
    if args.workflow_db is not None:
        from workflow import state_store as wss
        wss.DB_FILE = args.workflow_db
    res = write_report(args.out_dir, args.mentor)
    m = res["metrics"]
    print(f"[triage-metrics] n={m['n_reviews']} mentor-labelled={m['n_mentor_labelled']} "
          f"-> {res['json']}")
    for c in m["caveats"]:
        print(f"[triage-metrics] CAVEAT: {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
