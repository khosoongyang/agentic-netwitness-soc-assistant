# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: argparse, datetime, hashlib, json, pathlib, requests.
# =============================================================================
# File: scripts/update_lolbas.py
# Purpose: Triage Step 2 (P12) -- download the LOLBAS project's JSON API
#   (catalogue of abusable built-in Windows binaries) into a git-ignored
#   runtime cache used by agents/triage/lolbas.py, and record provenance
#   (source URL, retrieval time, sha256, entry count) in a sidecar
#   .meta.json.
# Inputs: https://lolbas-project.github.io/api/lolbas.json (or --url).
# Outputs: runtime/threat_data/lolbas.json + runtime/threat_data/lolbas.meta.json
#   (both git-ignored -- the LOLBAS dataset is GPL-3.0 and is NOT committed).
# Key evaluator search terms: update_lolbas, [FYP-TRIAGE-STEP2].
# =============================================================================
"""Usage:  python scripts/update_lolbas.py [--out runtime/threat_data/lolbas.json] [--url URL]

Run it once after cloning and then (e.g.) weekly. Triage keeps working
without it: rule_signals.lolbas is then status "missing" with a reason.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_URL = "https://lolbas-project.github.io/api/lolbas.json"
DEFAULT_OUT = ROOT / "runtime" / "threat_data" / "lolbas.json"
REQUIRED_KEYS = ("Name", "Commands", "Full_Path")


def validate(entries: object) -> list[dict]:
    if not isinstance(entries, list) or not entries:
        raise ValueError("expected a non-empty JSON list of LOLBAS entries")
    good = [e for e in entries if isinstance(e, dict) and all(k in e for k in REQUIRED_KEYS)]
    if len(good) < len(entries) * 0.9:
        raise ValueError(f"only {len(good)}/{len(entries)} entries have {REQUIRED_KEYS}")
    return good


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args(argv)

    import requests  # existing runtime dependency

    print(f"[update_lolbas] downloading {args.url}")
    resp = requests.get(args.url, timeout=args.timeout)
    resp.raise_for_status()
    raw = resp.content
    entries = validate(json.loads(raw.decode("utf-8")))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.out.with_suffix(".json.tmp")
    tmp.write_bytes(raw)
    tmp.replace(args.out)
    meta = {
        "source_url": args.url,
        "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "entries": len(entries),
        "license": "GPL-3.0 (LOLBAS project) -- runtime cache only, not committed",
    }
    args.out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    # ASCII-only console output: a cp1252 Windows console cannot encode "…".
    print(f"[update_lolbas] wrote {args.out} ({meta['entries']} entries, sha256 {meta['sha256'][:16]}...)")
    print(f"[update_lolbas] wrote {args.out.with_suffix('.meta.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
