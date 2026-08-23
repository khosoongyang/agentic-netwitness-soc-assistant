# =============================================================================
# [FYP-FILE] soc_reporting_agent/adapters/common.py
# Important dependencies: __future__, datetime, dotenv, json, os, pathlib, shutil, subprocess.
#
# File: Shared helper library for the Reporting-side adapter scripts.
#
# Purpose: Centralise the small pieces of plumbing (paths, JSON I/O, a
#   generic subprocess runner, OpenAI env config, and a legacy incident
#   normaliser) that every adapters/run_*.py entry point in this folder
#   would otherwise duplicate. This module is imported, never executed
#   directly, and defines no CLI of its own.
#
# Main functionalities:
#   - Resolve run-scoped vs. flat INPUTS_DIR/OUTPUTS_DIR (see [FYP-CONFIG]
#     below) and ensure the standard adapter directories exist.
#   - read_json/write_json: tolerant JSON load/save with automatic
#     mirroring of written outputs into a per-run folder when requested.
#   - run_script/openai_env_config: spawn a child Python script with an
#     augmented environment and capture its result / build OpenAI-style
#     env vars for it.
#   - normalise_incident: legacy best-effort mapper from a raw/enriched
#     alert dict onto a simplified incident summary shape.
#
# Inputs: Environment variables (REPORTING_INPUT_DIR, REPORTING_OUTPUT_DIR,
#   SOC_RUN_OUTPUT_DIR/SOC_OUTPUT_DIR), a .env file at PROJECT_ROOT/.env,
#   and whatever JSON files individual callers pass to read_json/write_json.
#
# Outputs: No direct outputs of its own beyond what callers ask it to
#   write; write_json() may additionally mirror a copy under a run-scoped
#   directory.
#
# Workflow position: Support/glue layer under soc_reporting_agent/adapters/,
#   sitting beneath the adapter entry points (run_parser_normalisation.py,
#   run_reporting.py) that soc_workflow.py subprocess-invokes for the
#   Parsing & Normalisation and Reporting pipeline stages.
#
# [FYP-USED-BY] Imported by:
#   - soc_reporting_agent/adapters/run_parser_normalisation.py
#   - soc_reporting_agent/adapters/run_reporting.py
#   - soc_reporting_agent/scripts/test_evidence_gap_branch_and_reporting_wrapper.py
#   (export_documents.py does NOT import this module; it imports
#   config.settings instead.)
#
# [FYP-CALLS] Standard library only (json, os, shutil, subprocess, sys,
#   datetime, pathlib) plus python-dotenv's load_dotenv(). No other
#   soc_reporting_agent modules are imported here.
#
# Key evaluator search terms: INPUTS_DIR, OUTPUTS_DIR, write_json,
#   read_json, run_script, normalise_incident, openai_env_config,
#   SOC_RUN_OUTPUT_DIR mirroring.
# =============================================================================
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

# [FYP-CONFIG] Adapter directory layout. PROJECT_ROOT is the
# soc_reporting_agent/ package root (two levels above this file).
PROJECT_ROOT = Path(__file__).resolve().parents[1]
# Run-scoped Reporting workspace: when the durable dashboard workflow
# invokes this subprocess it sets REPORTING_INPUT_DIR/REPORTING_OUTPUT_DIR
# to a per-incident/run/attempt directory (see soc_workflow.run_reporting_stage())
# so drafts/confirmed/exports/manifests are naturally isolated — every
# function below that references INPUTS_DIR/OUTPUTS_DIR becomes run-scoped
# automatically since these are resolved once, at import time, from those
# env vars. Falling back to the flat PROJECT_ROOT/inputs|outputs dirs keeps
# standalone/manual CLI invocation (no env vars set) working exactly as
# before.
INPUTS_DIR = Path(os.getenv("REPORTING_INPUT_DIR") or (PROJECT_ROOT / "inputs"))
OUTPUTS_DIR = Path(os.getenv("REPORTING_OUTPUT_DIR") or (PROJECT_ROOT / "outputs"))
LOGS_DIR = PROJECT_ROOT / "logs"
RUNTIME_DIR = PROJECT_ROOT / "runtime"

# Directories are created eagerly at import time so any adapter importing
# this module can immediately read/write without its own mkdir boilerplate.
for d in (INPUTS_DIR, OUTPUTS_DIR, LOGS_DIR, RUNTIME_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Load soc_reporting_agent/.env (API keys, LLM/DB settings) without
# overriding any values the process environment already sets — lets
# soc_workflow.py's explicit extra_env take precedence over the file.
load_dotenv(PROJECT_ROOT / ".env", override=False)


# [FYP-SECTION] Small generic helpers (time, JSON I/O, file discovery)
def now_iso() -> str:
    """[FYP-FUNCTION] Current UTC time as an ISO-8601 string, used for started_at/finished_at stamps."""
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path, default: Any = None) -> Any:
    """[FYP-FUNCTION] Load JSON from path; return default on any missing/empty/invalid file
    instead of raising, since adapter inputs are frequently absent mid-pipeline."""
    try:
        if not path.exists() or path.stat().st_size == 0:
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        # [FYP-ERROR] Malformed/partially-written JSON (e.g. a concurrent
        # writer) is treated the same as "missing" rather than raising.
        return default


def write_json(path: Path, data: Any) -> None:
    """[FYP-FUNCTION] Write data as pretty-printed JSON to path, creating parent dirs as needed.

    [FYP-PROCESS] If SOC_RUN_OUTPUT_DIR/SOC_OUTPUT_DIR is set and path lives
    under OUTPUTS_DIR, also mirror the same content into that run-scoped
    directory (see comment below) so a later/concurrent run cannot clobber
    an earlier run's durable copy."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    # Run-specific mirroring for concurrent/re-run support. Legacy adapters still
    # write to the normal outputs/ paths so existing downstream code works. When
    # SOC_RUN_OUTPUT_DIR is provided by the dashboard backend, every output file
    # written under outputs/ is also mirrored under that run folder using the same
    # relative path. This preserves an immutable per-run copy even when the
    # compatibility output is overwritten by a later run.
    run_output_dir = os.getenv("SOC_RUN_OUTPUT_DIR") or os.getenv("SOC_OUTPUT_DIR")
    if run_output_dir:
        try:
            resolved = path.resolve()
            outputs_root = OUTPUTS_DIR.resolve()
            if resolved == outputs_root or outputs_root in resolved.parents:
                relative = resolved.relative_to(outputs_root)
                mirror_path = Path(run_output_dir) / relative
                mirror_path.parent.mkdir(parents=True, exist_ok=True)
                mirror_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            # [FYP-ERROR] Mirroring is a best-effort convenience copy; a
            # failure here (bad path, permissions, disk full) must never
            # break the primary write above, so it is swallowed silently.
            pass


def latest_file(pattern: str, base: Path = OUTPUTS_DIR) -> Path | None:
    """[FYP-FUNCTION] Return the most recently modified file under base matching a glob
    pattern (e.g. "*/reports/report_manifest.json"), or None if none exist."""
    files = [p for p in base.glob(pattern) if p.is_file()]
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def copy_if_exists(src: Path, dst: Path) -> bool:
    """[FYP-FUNCTION] Copy src to dst (creating dst's parent dirs) only if src exists; no-op otherwise."""
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


# [FYP-SECTION] Legacy incident normalisation helpers
def severity_from_score(score: Any) -> str:
    """[FYP-FUNCTION] Map a 0-100 risk score onto a Critical/High/Medium/Low severity label."""
    try:
        s = float(score)
    except Exception:
        return str(score or "Unknown")
    if s >= 90:
        return "Critical"
    if s >= 70:
        return "High"
    if s >= 40:
        return "Medium"
    return "Low"


def _first_non_empty(*values: Any, default: Any = "") -> Any:
    """[FYP-FUNCTION] Return the first value that is not None/""/[]/{}—a tolerant coalesce
    used throughout normalise_incident() to pick between differently-named
    alert fields across NetWitness/enriched/sample JSON shapes."""
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return default


def _ioc_risk_score(enriched: dict) -> int:
    """[FYP-FUNCTION] Heuristic 0-95 risk score derived from keyword matches inside any
    iocs/indicators entries on the enriched alert (used as a risk_score
    fallback when no explicit score field is present)."""
    score = 0
    raw_iocs = enriched.get("iocs") or enriched.get("indicators") or []
    if isinstance(raw_iocs, dict):
        raw_iocs = [raw_iocs]
    if not isinstance(raw_iocs, list):
        raw_iocs = []
    for ioc in raw_iocs:
        text = json.dumps(ioc, default=str).lower()
        if any(word in text for word in ["malicious", "critical", "high", "malware", "c2", "command and control"]):
            score += 50
        elif any(word in text for word in ["suspicious", "medium", "unknown"]):
            score += 25
        elif text.strip():
            score += 8
    return min(score, 95) if score else 0


def normalise_incident(enriched: dict | None = None) -> dict:
    """[FYP-FUNCTION] Legacy best-effort mapper from a raw/enriched alert dict
    onto a simplified incident summary shape (id/title/summary/risk_score/
    severity/host/ip/username/file_name/raw).

    If enriched is omitted, falls back to reading enriched_alert.json from
    INPUTS_DIR then OUTPUTS_DIR. Every field is resolved via
    _first_non_empty() across several historical alert schemas so this keeps
    working regardless of which upstream stage produced the JSON.
    """
    enriched = enriched or read_json(INPUTS_DIR / "enriched_alert.json", {}) or read_json(OUTPUTS_DIR / "enriched_alert.json", {}) or {}
    # Support NetWitness style, processed-alert style, enriched-alert style, and simple sample JSON.
    ioc_score = _ioc_risk_score(enriched)
    risk_score = _first_non_empty(
        enriched.get("risk_score"),
        enriched.get("incident_risk_score"),
        enriched.get("enrichment_risk_score"),
        enriched.get("riskScore"),
        ioc_score if ioc_score else None,
        default=75,
    )
    title = _first_non_empty(
        enriched.get("incident_title"),
        enriched.get("alert_name"),
        enriched.get("alert_title"),
        enriched.get("title"),
        enriched.get("name"),
        default="High Risk Endpoint Malware Activity",
    )
    summary = _first_non_empty(
        enriched.get("incident_summary"),
        enriched.get("summary"),
        enriched.get("description"),
        enriched.get("alert_detail"),
        default=f"SOC alert requires triage: {title}",
    )
    return {
        "id": _first_non_empty(enriched.get("incident_id"), enriched.get("incidentId"), enriched.get("id"), enriched.get("case_id"), default="INC-0001"),
        "title": title,
        "summary": summary,
        "risk_score": risk_score,
        "severity": _first_non_empty(enriched.get("severity"), enriched.get("priority"), default=severity_from_score(risk_score)),
        "host": _first_non_empty(enriched.get("host"), enriched.get("event_domain"), enriched.get("destination_hostname"), enriched.get("hostname"), enriched.get("event_source"), default="unknown-host"),
        "ip": _first_non_empty(enriched.get("source_ip"), enriched.get("destination_ip"), enriched.get("ip"), default=""),
        "username": _first_non_empty(enriched.get("username"), enriched.get("user"), enriched.get("assignee"), default=""),
        "file_name": _first_non_empty(enriched.get("possible_file_name"), enriched.get("file_name"), enriched.get("filename"), default=""),
        "raw": enriched,
    }


# [FYP-SECTION] Child-process execution and OpenAI env helpers
def run_script(script: Path, timeout: int = 300, extra_env: dict[str, str] | None = None) -> dict:
    """[FYP-FUNCTION] Run `script` as a child Python process (same interpreter,
    cwd=PROJECT_ROOT) and capture a normalised result dict.

    [FYP-CALLS] Used by run_reporting.py's main() to invoke
    agents/reporting_agent.py out-of-process (see [FYP-USED-BY] note at top
    of file). extra_env is merged on top of a full copy of the current
    process environment (os.environ), so callers only need to pass the keys
    they want to add/override — not the whole environment.

    [FYP-EVALUATOR] Every branch (success, timeout, unexpected exception)
    returns the same dict shape (started_at/finished_at/returncode/success/
    stdout/stderr/script) so callers can treat all three outcomes uniformly
    without special-casing exceptions. stdout/stderr are truncated to the
    last 20000 characters to avoid ballooning downstream JSON artefacts.
    """
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    started = now_iso()
    try:
        result = subprocess.run(
            [sys.executable, str(script)],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=env,
        )
        return {
            "started_at": started,
            "finished_at": now_iso(),
            "returncode": result.returncode,
            "success": result.returncode == 0,
            "stdout": result.stdout[-20000:],
            "stderr": result.stderr[-20000:],
            "script": str(script.relative_to(PROJECT_ROOT)),
        }
    except subprocess.TimeoutExpired as exc:
        # [FYP-ERROR] Child process exceeded `timeout` seconds. Reported as a
        # distinct status="timeout" (returncode=-1) rather than raising, so
        # the adapter's main() can still write a well-formed failure result.
        return {
            "started_at": started,
            "finished_at": now_iso(),
            "returncode": -1,
            "success": False,
            "status": "timeout",
            "stdout": (exc.stdout or "")[-20000:] if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "")[-20000:] if isinstance(exc.stderr, str) else "",
            "script": str(script.relative_to(PROJECT_ROOT)),
        }
    except Exception as exc:
        # [FYP-ERROR] Anything else (e.g. script path missing, OS-level spawn
        # failure) is caught here so run_script() never raises into callers;
        # status="execution_error" distinguishes this from a normal non-zero
        # exit or a timeout.
        return {
            "started_at": started,
            "finished_at": now_iso(),
            "returncode": -1,
            "success": False,
            "status": "execution_error",
            "stdout": "",
            "stderr": str(exc),
            "script": str(script.relative_to(PROJECT_ROOT)),
        }


def openai_env_config(prefix: str = "") -> dict[str, str]:
    """[FYP-FUNCTION] Build the OPENAI_MODEL/OPENAI_API_KEY
    env vars to hand to a child process via run_script()'s extra_env.

    [FYP-CONFIG] Model resolution order: f"{prefix}OPENAI_MODEL" env var (lets
    a caller namespace its own override), then the plain OPENAI_MODEL env
    var, then REPORTING_LLM_MODEL, finally the "gpt-4o-mini" default.
    prefix is "" for every current caller, so in practice this is just
    OPENAI_MODEL -> REPORTING_LLM_MODEL -> default.
    """
    model = os.getenv(f"{prefix}OPENAI_MODEL") or os.getenv("OPENAI_MODEL") or os.getenv("REPORTING_LLM_MODEL") or "gpt-4o-mini"
    return {
        "OPENAI_MODEL": model,
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", ""),
    }
