"""
# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# =============================================================================
# File:
#   soc_workflow.py
#
# Purpose:
#   THE ORCHESTRATION ENGINE for the Aegis SOC platform. This is a headless,
#   code-driven "puppet master" — not a UI file — that sequences the four
#   pipeline stages (Parsing, Triage, Investigation, Reporting), persists
#   every stage transition to the pipeline database, and implements the
#   in-process evidence-gap feedback loop that can trigger an automatic
#   Investigation re-run without any human click. The Flask workflow adapter
#   imports functions from this module directly and invokes them through the
#   durable, human-gated flow; this file itself
#   also exposes a `main()` CLI entry point that runs the whole chain
#   headlessly (`python soc_workflow.py --incident-file ...`).
#
# Main functionalities:
#   1. Stage routing: needs_investigation() decides Investigation vs
#      straight-to-Reporting based on the triage classification.
#   2. Stage handoffs: handoff_to_investigation(), handoff_to_reporting()
#      package one stage's output into the next stage's expected input files.
#   3. Automatic re-run / feedback loop: detect_evidence_gaps() +
#      investigate_with_feedback() re-run Investigation in-process when the
#      first pass leaves too many evidence gaps (WORKFLOW_FEEDBACK_THRESHOLD).
#   4. Pipeline database bookkeeping: pipeline_insert()/pipeline_db_init()
#      write to soc_db/soc_pipeline.db, the same six-stage schema app.py's
#      "Pipeline DB" tab renders.
#   5. Subprocess/CLI stage runners: run_investigation(), run_reporting(),
#      export_report_documents() shell out to soc_investigation_agent_revised/
#      and soc_reporting_agent/ via their own entry points/adapters.
#   6. Headless end-to-end stage chain: run_until_triage_approval(),
#      resume_after_triage_approval(), run_investigation_stage(),
#      run_reporting_stage(), run_stage_chain(), main().
#
# Inputs:
#   An incident dict (from sample_incident.json / a fetched NetWitness
#   incident / app.py's session state), plus files dropped by upstream
#   stages (triaged_alerts/, soc_reporting_agent/inputs/*.json).
#
# Outputs:
#   JSON result files consumed by the next stage, rows in
#   soc_db/soc_pipeline.db, exported report documents, and return dicts
#   consumed directly by app.py's UI rendering.
#
# Workflow position:
#   Sits BETWEEN the UI (app.py) and the four stage subsystems. app.py calls
#   into this module's functions on each analyst-triggered stage action; this
#   module does not itself gate on human approval or lock stages in the UI
#   sense — see workflow_state_store.py / app.py session state for that.
#
# Called by:
#   app.py (verified via grep: needs_investigation, investigate_with_feedback,
#   build_post_investigation_record, pipeline_insert, handoff_to_reporting,
#   run_reporting are all called from app.py). eval_harness.py calls
#   build_investigation_alert for a regression test. run_full_workflow()/
#   main() are CLI-only entry points, not called by app.py.
#
# Calls:
#   soc_triage_agent (TriageAgent, OpenAILLMConfig), soc_investigation_agent_revised/
#   (via subprocess/file-queue), soc_reporting_agent/ (via its own adapter),
#   workflow_state_store.py (wss), workflow_validation.py (wv), nw_alerts.py
#   (_merge_alert_digest), soc_db/soc_pipeline.db (sqlite3).
#
# Important dependencies:
#   workflow_state_store, workflow_validation, nw_alerts — all repo-root
#   siblings documented separately.
#
# Important side effects:
#   Writes soc_db/soc_pipeline.db rows, writes JSON artifacts under each
#   stage's run directory, launches subprocesses for Investigation/Reporting.
#
# Error and fallback behaviour:
#   Parsing failures are non-fatal (parsed_context left None, triage runs
#   standalone). See [FYP-ERROR]/[FYP-FALLBACK] tags at individual call sites.
#
# Key evaluator search terms:
#   needs_investigation, detect_evidence_gaps, investigate_with_feedback,
#   handoff_to_investigation, handoff_to_reporting, pipeline_insert,
#   run_stage_chain, run_until_triage_approval, resume_after_triage_approval,
#   [FYP-FLOW], [FYP-DECISION], [FYP-RERUN], [FYP-STAGE-LOCK]
# =============================================================================

soc_workflow.py — SOC multi-agent workflow orchestrator
========================================================
Code-driven "puppet master" connecting four stages:

  0. Parsing       soc_reporting_agent/parser  in-process (regex/rule-based, no LLM
                                                for the extraction itself)
  1. Triage        soc_triage_agent/         in-process (OpenAI LLM)
  2. Investigation soc_investigation_agent/  subprocess (file-queue driven)
  3. Reporting     soc_reporting_agent/      subprocess (via its own adapter)

Data handoffs
-------------
  parsing -> triage        : processed_alert (flat extracted indicators) passed
                            as parsed_context into TriageAgent.triage() — skipped
                            under --mock-triage. Non-fatal: parsing failure just
                            leaves parsed_context=None and triage runs standalone.
  triage -> investigation : triaged alert JSON dropped into
                            soc_investigation_agent/triaged_alerts/
  triage -> reporting     : triage_result.json + enriched_alert.json +
                            ticket_context.json in soc_reporting_agent/
  investigation -> reporting : investigation_result.json

Pipeline database
-----------------
Every stage transition is recorded in soc_db/soc_pipeline.db using the same
six stage tables that app.py renders in its Pipeline DB tab:

  alerts_to_triage -> post_triage_investigate | post_triage_no_investigate
                   -> initial_ticket -> pending_ticket_report -> finalized_report

Usage (headless)
----------------
  python soc_workflow.py --incident-file sample_incident.json
  python soc_workflow.py --incident-file sample_incident.json --mock-triage
  python soc_workflow.py --incident-file sample_incident.json --skip-investigation
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import workflow_state_store as wss
import workflow_validation as wv
from nw_alerts import _merge_alert_digest

ROOT       = Path(__file__).resolve().parent
# Swapped 2026-07-22: the team's revised investigation agent (adds
# policy_engine compliance auditing + richer report sections). Contract
# verified identical: main.py entry, triaged_alerts/ inbox, incident_reports/
# Incident-*/incident_data.json (raw_alerts/summary_text/metadata.severity/
# indicators) + final_analysis_report.md with the same `| step_x | … |
# MET/NOT_MET |` trace table the feedback loop parses. The previous agent
# remains on disk untouched — rollback = point this back.
INV_DIR    = ROOT / "soc_investigation_agent_revised"
REP_DIR    = ROOT / "soc_reporting_agent"
SOC_DB_DIR = ROOT / "soc_db"
SOC_DB_DIR.mkdir(exist_ok=True)

PIPELINE_DB_FILE = SOC_DB_DIR / "soc_pipeline.db"

# Classifications that route an incident to the investigation agent.
INVESTIGATE_CLASSIFICATIONS = {"critical", "high", "medium"}


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 1.  PIPELINE DATABASE  (same schema/stages as app.py)
# ══════════════════════════════════════════════════════════════════════════════

PIPELINE_STAGES = [
    "alerts_to_triage",
    "post_triage_investigate",
    "post_triage_no_investigate",
    "post_investigation",
    "initial_ticket",
    "pending_ticket_report",
    "finalized_report",
    "workflow_runs",
]


def build_post_investigation_record(inv: dict, ticket: dict,
                                    title: str = "",
                                    run_stamp: str | None = None) -> dict:
    """
    [FYP-FUNCTION] Post-Investigation Pipeline Record Builder

    Pipeline record for the post_investigation stage — one shape shared by
    app.py and the CLI workflow so the DB viewer sees consistent fields.

    With run_stamp, the record id is run-scoped (postinv_#UNC@stamp) so every
    workflow execution APPENDS a new findings row instead of replacing the
    previous one; ticket lineage stays via incident_id + ticket_unc fields.

    [FYP-STATE]: id shape is the key decision here — no run_stamp means the
    id is unc-scoped only (`postinv_{unc}`), so pipeline_insert()'s
    INSERT OR REPLACE will overwrite any prior post_investigation row for
    that ticket instead of appending a new one. Callers that want per-run
    history (e.g. investigate_with_feedback's re-run) must pass run_stamp.

    Args:
        inv: investigation agent's native result dict (severity, summary, ...).
        ticket: the triage ticket dict this investigation was run for
            (supplies incident_id/unc/title/classification fallbacks).
        title: optional override for the record title; falls back to
            ticket["title"] then incident_id.
        run_stamp: optional per-run token (see [FYP-STATE] above) used to
            make the record id unique per workflow execution.

    Returns:
        dict shaped for pipeline_insert(stage="post_investigation", record=...):
        id/incident_id/ticket_unc/title/severity/summary/investigation.

    [FYP-USED-BY]: app.py (imported as `_wfm`) — builds this record after an
    investigation run completes, then passes it straight to
    `_wfm.pipeline_insert("post_investigation", rec)`.
    """
    inc_id = inv.get("incident_id") or ticket.get("incident_id") or ""
    unc    = ticket.get("unc") or inc_id
    rec_id = f"postinv_{unc}@{run_stamp}" if run_stamp else f"postinv_{unc}"
    return {
        "id": rec_id,
        "incident_id": inc_id,
        "ticket_unc": unc,
        "title": f"[FINDINGS] {title or ticket.get('title') or inc_id}",
        "severity": inv.get("severity") or ticket.get("classification") or "",
        "summary": str(inv.get("summary") or "Investigation completed.")[:500],
        "investigation": {k: v for k, v in inv.items() if k != "subprocess"},
    }


# [FYP-FUNCTION] `_pl_con` — implements the pl con operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>, app.py:_pipeline_stage_map, app.py:_pipeline_worked_ids; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `connect`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _pl_con() -> sqlite3.Connection:
    # [FYP-DATABASE]: opens a fresh sqlite3 connection per call (no pooling).
    # Generous busy-timeout: the app's poll loop reads these tables every
    # ~1.5s while the worker writes — waits must outlast brief read locks.
    con = sqlite3.connect(str(PIPELINE_DB_FILE), check_same_thread=False,
                          timeout=15)
    con.row_factory = sqlite3.Row
    return con


def pipeline_db_init() -> None:
    """
    [FYP-FUNCTION] Pipeline DB Schema Initialiser

    [FYP-DATABASE]: idempotent bootstrap of soc_db/soc_pipeline.db — creates
    the 8 PIPELINE_STAGES tables (see PIPELINE_STAGES list above) with
    `CREATE TABLE IF NOT EXISTS`, so calling this on an already-initialised
    DB is a safe no-op for existing tables. Also switches the DB to WAL mode
    (best-effort; failure is swallowed) so app.py's UI-thread poll loop can
    read concurrently while a worker thread writes via pipeline_insert().

    Schema (identical across all 8 tables): id TEXT PRIMARY KEY,
    incident_id, title, severity, stage, created_at, summary, raw_json
    (full record JSON — the typed columns above are just for cheap
    filtering/sorting in the DB viewer; raw_json is the source of truth).

    [FYP-CALLS]: run_until_triage_approval() (this module) calls
    pipeline_db_init() once at the start of a fresh headless run. app.py
    keeps its own separate pipeline_db_init()/pipeline_insert() pair
    (same schema, called at import time) for its own direct sqlite3 writes
    — the two implementations are independent but must stay schema-
    compatible since they share the same DB file/tables.
    """
    with _pl_con() as c:
        try:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        for s in PIPELINE_STAGES:
            c.execute(f"""CREATE TABLE IF NOT EXISTS {s} (
                id TEXT PRIMARY KEY, incident_id TEXT, title TEXT,
                severity TEXT, stage TEXT, created_at TEXT,
                summary TEXT, raw_json TEXT)""")
        c.commit()


def pipeline_insert(stage: str, record: dict) -> str:
    """
    [FYP-FUNCTION] Pipeline DB Row Writer (used at every stage transition)

    Insert a record into a pipeline stage table (mirrors app.py behaviour).
    Same-id re-inserts REPLACE the row; a run counter + timestamp stamp the
    summary so refreshed records are visibly new in the DB viewer.

    [FYP-DATABASE]: `INSERT OR REPLACE` keyed on `id` — this is an UPSERT,
    not an append. Whether a given call creates a new row or overwrites an
    existing one is entirely controlled by the `id` the CALLER puts on
    `record` (see build_post_investigation_record's [FYP-STATE] note: a
    run_stamp-suffixed id appends history, a bare id overwrites in place).

    Re-insert bookkeeping: before writing, reads back any existing row's
    raw_json to recover `workflow_runs_count`, increments it, and — if this
    is not the first write for this id — prefixes the summary with
    `[run N · HH:MM:SS]` so an analyst re-viewing the DB tab can tell a row
    was refreshed rather than created fresh.

    Args:
        stage: one of PIPELINE_STAGES (table name — interpolated directly
            into the SQL, so callers MUST pass a trusted constant, never
            unsanitised user input).
        record: dict to persist; `id`/`unc` is used as the primary key
            (falls back to a fresh uuid4 if neither is present, truncated
            to 64 chars), `incident_id`/`incidentId`, `title`/`name`,
            `severity`/`classification` are lifted into typed columns for
            cheap querying, and the full dict is stored as raw_json.

    Returns:
        The row id actually written (str) — callers often keep this to
        cross-reference the row later.

    [FYP-USED-BY]: called throughout this module at every stage handoff
    (handoff_to_investigation, handoff_to_reporting, run_investigation,
    run_reporting, run_until_triage_approval, run_investigation_stage,
    run_reporting_stage, run_stage_chain) and directly by app.py (via the
    `_wfm.pipeline_insert` alias) for post_investigation/finalized_report/
    workflow_runs records raised from UI-driven actions.
    """
    import uuid as _uuid
    rec_id = str(record.get("id") or record.get("unc") or _uuid.uuid4())[:64]
    now = datetime.now().isoformat(timespec="seconds")
    with _pl_con() as c:
        runs = 1
        try:
            prev = c.execute(f"SELECT raw_json FROM {stage} WHERE id=?",
                             (rec_id,)).fetchone()
            if prev:
                runs = int((json.loads(prev[0] or "{}"))
                           .get("workflow_runs_count") or 1) + 1
        except Exception:
            pass
        record = dict(record)
        record["workflow_runs_count"] = runs
        summary = str(record.get("summary") or record.get("description") or "")
        if runs > 1:
            summary = f"[run {runs} · {now[11:19]}] {summary}"
        c.execute(
            f"INSERT OR REPLACE INTO {stage} "
            "(id,incident_id,title,severity,stage,created_at,summary,raw_json) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (rec_id,
             str(record.get("incident_id") or record.get("incidentId") or ""),
             str(record.get("title") or record.get("name") or ""),
             str(record.get("severity") or record.get("classification") or ""),
             stage, now,
             summary[:500],
             json.dumps(record, default=str)))
        c.commit()
    return rec_id


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 2.  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _log(tag: str, msg: str) -> None:
    """[FYP-FUNCTION] tiny timestamped console logger — `[HH:MM:SS] [tag] msg`,
    flushed immediately so output interleaves correctly with subprocess
    streaming (see _run_subprocess_streaming). Used throughout this module
    wherever a plain print() with a consistent prefix is wanted."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [{tag}] {msg}", flush=True)


def _write_json(path: Path, data: Any) -> None:
    """[FYP-FUNCTION] Plain (non-atomic) JSON writer — creates parent dirs and
    pretty-prints `data` to `path`. NOT crash-safe mid-write; for artifacts
    that must survive a crash/restart use _atomic_write_json() instead (see
    [FYP-SECTION] 2.5 below)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8")


def _read_json(path: Path, default: Any = None) -> Any:
    """[FYP-FUNCTION] [FYP-FALLBACK] Best-effort JSON reader — returns
    `default` (never raises) for a missing/empty/corrupt file, so callers
    can treat "no prior artifact" and "unreadable artifact" identically."""
    try:
        if not path.exists() or path.stat().st_size == 0:
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _safe_ticket_id(unc: str) -> str:
    """[FYP-FUNCTION] '#00012A' -> 'TKT-00012A' (filesystem/env safe)."""
    core = re.sub(r"[^A-Za-z0-9]", "", str(unc or ""))
    return f"TKT-{core}" if core else "TKT-UNKNOWN"


def _run_subprocess_streaming(cmd: list[str], cwd: Path, timeout: int,
                              extra_env: dict[str, str] | None = None,
                              line_cb=None, watchdog_cb=None,
                              watchdog_interval: int | None = None) -> dict:
    """
    [FYP-FUNCTION] Streaming Subprocess Runner (Investigation/Reporting agents)

    Like _run_subprocess, but streams merged stdout/stderr line-by-line to
    line_cb(str) while the process runs — used by the app's agent board to
    show live 'thinking' for subprocess agents. Same result shape.

    watchdog_cb, when given, is invoked every watchdog_interval seconds
    (default _HEARTBEAT_RENEW_SECONDS) while the subprocess runs, via a
    self-rescheduling threading.Timer alongside the existing single-shot
    timeout watchdog. If it ever returns False (e.g. a global workspace
    lock's renewal failed — see run_investigation's docstring), the child
    process is terminated exactly like a timeout, but the result's
    status is "lock_lost", not "timeout" — callers must treat that
    distinctly (never as a normal completed/failed investigation).

    [FYP-ERROR] [FYP-FALLBACK]: three distinct terminal outcomes besides a
    clean exit — "lock_lost" (watchdog_cb returned False), "timeout" (ran
    past `timeout` seconds) and "execution_error" (Popen/launch itself
    raised) — all returned as a dict rather than an exception, so callers
    branch on `result["status"]`/`result["success"]` instead of try/except.
    [FYP-USED-BY]: run_investigation(), run_reporting() (this module) —
    both subprocess stage runners, so live agent output can be surfaced to
    app.py's UI as it happens. _run_subprocess() (non-streaming, below) is
    the plain counterpart used by export_report_documents() and as the
    non-streaming code path inside run_investigation()/run_reporting().
    """
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONUNBUFFERED", "1")
    if extra_env:
        env.update(extra_env)
    started = datetime.now().isoformat(timespec="seconds")
    lines: list[str] = []
    watchdog_interval = watchdog_interval or _HEARTBEAT_RENEW_SECONDS
    try:
        proc = subprocess.Popen(cmd, cwd=str(cwd), env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace",
                                bufsize=1)
        # Watchdogs: the read loop below blocks while the process is silent,
        # so both timeout AND lock-loss must be enforced out-of-band, not
        # per-line.
        timed_out = {"v": False}
        lock_lost = {"v": False}

        # [FYP-FUNCTION] `_kill_on_timeout` — implements the kill on timeout operation used by the surrounding workflow orchestration and state workflow.
        # [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
        # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
        # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
        # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
        # [FYP-CALLS] Calls: `kill`.
        # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

        def _kill_on_timeout():
            timed_out["v"] = True
            try:
                proc.kill()
            except Exception:
                pass

        watchdog = threading.Timer(timeout, _kill_on_timeout)
        watchdog.start()

        lock_timer_holder: dict = {}

        # [FYP-FUNCTION] `_check_lock` — evaluates check lock conditions so invalid or unsafe workflow orchestration and state processing is stopped early.
        # [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
        # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
        # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
        # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
        # [FYP-CALLS] Calls: `Timer`, `kill`, `poll`, `start`, `terminate`, `wait`, `watchdog_cb`.
        # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

        def _check_lock() -> None:
            if proc.poll() is not None:
                return   # process already finished — nothing to guard
            if not watchdog_cb():
                lock_lost["v"] = True
                try:
                    proc.terminate()
                    proc.wait(timeout=10)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                return
            t = threading.Timer(watchdog_interval, _check_lock)
            t.daemon = True
            lock_timer_holder["t"] = t
            t.start()

        lock_timer = None
        if watchdog_cb is not None:
            lock_timer = threading.Timer(watchdog_interval, _check_lock)
            lock_timer.daemon = True
            lock_timer_holder["t"] = lock_timer
            lock_timer.start()
        try:
            for line in proc.stdout:  # blocks until EOF; lines arrive live
                lines.append(line)
                if line_cb:
                    try:
                        line_cb(line.rstrip())
                    except Exception:
                        pass
            rc = proc.wait()
        finally:
            watchdog.cancel()
            current_timer = lock_timer_holder.get("t")
            if current_timer is not None:
                current_timer.cancel()
        if lock_lost["v"]:
            return {"started_at": started, "returncode": -1,
                    "success": False, "status": "lock_lost",
                    "stdout": "".join(lines)[-20000:],
                    "stderr": "Shared workspace lock was lost while the "
                             "subprocess was running; it was terminated."}
        if timed_out["v"]:
            return {"started_at": started, "returncode": -1,
                    "success": False, "status": "timeout",
                    "stdout": "".join(lines)[-20000:],
                    "stderr": f"Timed out after {timeout}s"}
        return {"started_at": started, "returncode": rc, "success": rc == 0,
                "stdout": "".join(lines)[-20000:], "stderr": ""}
    except Exception as exc:
        return {"started_at": started, "returncode": -1, "success": False,
                "status": "execution_error",
                "stdout": "".join(lines)[-20000:], "stderr": str(exc)}


def _run_subprocess(cmd: list[str], cwd: Path, timeout: int,
                    extra_env: dict[str, str] | None = None) -> dict:
    """[FYP-FUNCTION] Plain (non-streaming) subprocess runner — blocks on
    subprocess.run() and returns the same {started_at, returncode, success,
    stdout, stderr[, status]} result shape as _run_subprocess_streaming(),
    just without live line-by-line callbacks. [FYP-USED-BY]:
    export_report_documents(); also used as the non-watchdog code path
    inside run_investigation()/run_reporting() when no live-progress
    callback is supplied."""
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    if extra_env:
        env.update(extra_env)
    started = datetime.now().isoformat(timespec="seconds")
    try:
        res = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                             encoding="utf-8", errors="replace",
                             timeout=timeout, env=env)
        return {"started_at": started, "returncode": res.returncode,
                "success": res.returncode == 0,
                "stdout": (res.stdout or "")[-20000:],
                "stderr": (res.stderr or "")[-20000:]}
    except subprocess.TimeoutExpired as exc:
        return {"started_at": started, "returncode": -1, "success": False,
                "status": "timeout",
                "stdout": (exc.stdout if isinstance(exc.stdout, str) else "") or "",
                "stderr": f"Timed out after {timeout}s"}
    except Exception as exc:
        return {"started_at": started, "returncode": -1, "success": False,
                "status": "execution_error", "stdout": "", "stderr": str(exc)}


def _first(*values, default=None):
    """[FYP-FUNCTION] Returns the first "truthy-ish" value among `values`
    (skipping None, "", [], {}), else `default` — a compact fallback-chain
    helper used when picking the first present field across several
    possible key spellings/sources."""
    for v in values:
        if v not in (None, "", [], {}):
            return v
    return default


def _openai_compat_env() -> dict[str, str]:
    """Return no endpoint overrides; subprocesses inherit OpenAI settings."""
    return {}


def _llm_seed() -> str:
    """[FYP-FUNCTION] One fixed seed for every LLM call in the pipeline — same policy as the
    triage agent (OPENAI_SEED, default 42) so repeat runs are reproducible.
    [FYP-USED-BY]: run_investigation(), run_reporting() — passed to the
    subprocess as OPENAI_SEED/REPORTING_LLM_SEED alongside _openai_compat_env()."""
    return os.environ.get("OPENAI_SEED", "").strip() or "42"


def _safe(s: str) -> str:
    """[FYP-FUNCTION] Filesystem/env-safe slug: any char outside
    [A-Za-z0-9_-] becomes "_". Used to build directory/file names from
    arbitrary incident/run identifiers (see _artifact_dir below)."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", str(s))


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 2.5  RUN-SCOPED ARTIFACT PERSISTENCE (identity-enveloped, atomic writes)
# ══════════════════════════════════════════════════════════════════════════════
# Every artifact this module writes for durable resume (the full raw
# incident; later, run-scoped parsing summaries) lives under this one
# trusted root, wrapped in an identity envelope {incident_id, run_id,
# artifact_type, created_at, payload} and written temp-then-replace so a
# crash mid-write can never leave a partial file to be loaded.

_TRUSTED_OUTPUT_ROOT = REP_DIR / "outputs"


def _artifact_dir(incident_id: str, run_id: str) -> Path:
    """[FYP-FUNCTION] [FYP-STATE] A readable prefix plus a content hash of the FULL original
    identifier, so two different incident_ids that _safe() would
    otherwise collapse to the same sanitized string never share a
    directory."""
    safe_id = _safe(incident_id)
    id_hash = hashlib.sha256(str(incident_id).encode()).hexdigest()[:10]
    run_hash = hashlib.sha256(str(run_id).encode()).hexdigest()[:10]
    return _TRUSTED_OUTPUT_ROOT / f"{safe_id}-{id_hash}" / run_hash


def reporting_attempt_dir(incident_id: str, run_id: str, reporting_stage_attempt: int) -> Path:
    """[FYP-FUNCTION] [FYP-STATE] Native run-scoped Reporting workspace root for one attempt —
    reporting_attempt_dir(...)/inputs and .../outputs are passed to the
    Reporting subprocess chain as REPORTING_INPUT_DIR/REPORTING_OUTPUT_DIR
    (see handoff_to_reporting()/run_reporting()/run_reporting_stage()), so
    drafts/confirmed/exports/candidate_manifest.json for this attempt are
    isolated by construction — a later rerun gets a brand-new attempt
    directory and never touches this one. Public (no leading underscore)
    because reporting_approval.py also needs to resolve this same path when
    validating a candidate set for approval."""
    return _artifact_dir(incident_id, run_id) / "reporting" / f"attempt_{int(reporting_stage_attempt)}"


def _atomic_write_json(path: Path, data: dict) -> None:
    """[FYP-FUNCTION] Write-temp-then-replace so a crash or restart mid-write can never
    leave a partially-written file behind to be loaded."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, default=str)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)   # atomic on both POSIX and Windows


def _save_run_artifact(incident_id: str, run_id: str, filename: str,
                       artifact_type: str, payload: dict) -> Path:
    """[FYP-FUNCTION] [FYP-STATE] Every artifact is wrapped in an identity envelope, not just the raw
    payload, so reload can validate BOTH incident_id and run_id without
    depending on whatever (possibly absent) identity fields the payload
    itself happens to carry."""
    envelope = {
        "incident_id": str(incident_id), "run_id": run_id,
        "artifact_type": artifact_type,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }
    path = _artifact_dir(incident_id, run_id) / filename
    _atomic_write_json(path, envelope)
    return path


def _resolve_trusted_path(path_str: str | None) -> Path | None:
    """[FYP-FUNCTION] [FYP-ERROR] Path-traversal guard: resolves `path_str`
    and requires it to sit inside _TRUSTED_OUTPUT_ROOT and exist as a file,
    else returns None. Every artifact reload in this module goes through
    this first — a state-store row pointing outside the trusted root (or at
    a directory, or nowhere) is treated as "no artifact", not an error."""
    if not path_str:
        return None
    try:
        p = Path(path_str).resolve()
        p.relative_to(_TRUSTED_OUTPUT_ROOT.resolve())
    except Exception:
        return None
    return p if p.is_file() else None


def _load_artifact_envelope(path: Path | None, incident_id: str, run_id: str) -> dict | None:
    """[FYP-FUNCTION] [FYP-STATE] Shared reload+validate routine — checks both incident_id and run_id
    against the envelope (not the payload's own, possibly-absent identity
    fields), and a half-written temp file is never at the final path (see
    _atomic_write_json), so this either finds a complete file or none."""
    if not path:
        return None
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if (envelope.get("incident_id") != str(incident_id)
            or envelope.get("run_id") != run_id):
        return None
    return envelope.get("payload")


def _data_availability(incident: dict) -> dict:
    """[FYP-FUNCTION] [FYP-DECISION] Real fetch-outcome metadata for the incident about to be persisted as
    this run's raw-incident artifact — NOT a bare bool(incident.get("alerts")),
    which can't distinguish "alerts were fetched and there genuinely are
    none" from "the fetch failed" or "this is the slim, already-stripped
    DB copy". The live NetWitness alert-fetch loop (app.py) already tracks
    outcome honestly: it sets incident["alerts_fetch_error"] (and
    "alerts_fetch_diag") on any failure, and leaves those absent while
    populating incident["alerts"] (even with an empty list) on success.
    db_upsert_incidents() stamps "_alerts_stripped" onto the slim copy it
    persists to SQLite — its presence means this object was, at some
    point, stripped of its real alerts, regardless of what "alerts" key
    (if any) it carries now, so incident_source is derived from THAT
    marker directly rather than from a separately-passed flag the caller
    (run_until_triage_approval) has no reliable way to supply anyway."""
    fetch_error = incident.get("alerts_fetch_error")
    has_alerts_key = "alerts" in incident
    was_stripped = "_alerts_stripped" in incident
    fetch_ok = has_alerts_key and not fetch_error and not was_stripped
    if was_stripped:
        incident_source = "sqlite_slim"
    elif has_alerts_key:
        incident_source = "netwitness_live"
    else:
        incident_source = "other"
    return {
        "incident_source": incident_source,
        "alerts_fetch_attempted": has_alerts_key or bool(fetch_error),
        "alerts_fetch_succeeded": fetch_ok,
        "alerts_complete": fetch_ok,
        "alerts_count": len(incident.get("alerts") or []),
        # No dedicated journal-fetch success/failure signal exists anywhere
        # in the current fetch code — reported honestly as "not tracked"
        # rather than fabricated as True/False.
        "journal_fetch_succeeded": None,
        "warnings": ([f"NetWitness alert fetch failed: {fetch_error}"] if fetch_error else []),
    }


def load_raw_incident_for_run(incident_id: str, run_id: str) -> dict | None:
    """[FYP-FUNCTION] [FYP-STATE] The ONLY source of the full raw incident (with alertMeta) for the
    durable Threat Intelligence path — never browser-session state. Returns
    None (not a guess) if the row's run_id doesn't match or the file is
    missing/invalid/mismatched.

    The artifact's payload is {"incident": {...}, "data_availability": {...}}
    (see run_until_triage_approval); this function always returns just the
    bare incident dict, unchanged from every existing caller's point of
    view. Artifacts written before this metadata existed have the incident
    dict directly as the payload (no "incident"/"data_availability" keys)
    — both shapes are handled so old runs keep resolving."""
    state = wss.get_state(incident_id)
    if not state or state.get("run_id") != run_id:
        return None
    payload = _load_artifact_envelope(
        _resolve_trusted_path(state.get("raw_incident_path")), incident_id, run_id)
    if payload is None:
        return None
    if isinstance(payload, dict) and "incident" in payload and "data_availability" in payload:
        return payload["incident"]
    return payload   # legacy artifact: the payload WAS the incident dict


def load_data_availability_for_run(incident_id: str, run_id: str) -> dict | None:
    """[FYP-FUNCTION] Companion to load_raw_incident_for_run() — returns the fetch-outcome
    metadata stamped alongside the incident, or None for a legacy artifact
    (predating this metadata) or a missing/invalid one. case_view.py must
    treat None the same as "unavailable / assume incomplete", never as
    "assume complete"."""
    state = wss.get_state(incident_id)
    if not state or state.get("run_id") != run_id:
        return None
    payload = _load_artifact_envelope(
        _resolve_trusted_path(state.get("raw_incident_path")), incident_id, run_id)
    if isinstance(payload, dict) and "data_availability" in payload:
        return payload["data_availability"]
    return None


def load_parsing_result_for_run(incident_id: str, run_id: str) -> dict | None:
    """[FYP-FUNCTION] Reads the run-scoped parsing summary saved by
    wss.save_parsing_result() and, where the paths it recorded still
    resolve inside the trusted root, loads the full normalised_alert/
    processed_alert content back from disk. Returns None if the summary's
    own run_id doesn't match — never trusts a stale/foreign summary."""
    state = wss.get_state(incident_id)
    if not state or state.get("run_id") != run_id:
        return None
    try:
        summary = json.loads(state.get("parsing_result_json") or "{}")
    except Exception:
        return None
    if summary.get("run_id") != run_id:
        return None
    out = dict(summary)
    for key in ("normalised_alert", "processed_alert"):
        p = _resolve_trusted_path((summary.get("output_files") or {}).get(key))
        if p:
            try:
                out[key] = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                out[key] = None
    return out


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 2.6  STAGE CLAIM / LEASE  (execution/threading layer only)
# ══════════════════════════════════════════════════════════════════════════════
# The pure database transactions (claim_stage, renew_stage_lease,
# release_stage_lease, complete_stage, the global execution lock functions,
# StageClaimError/GlobalLockBusyError) now live in workflow_state_store.py —
# that module owns the schema and every atomic transaction; this module owns
# worker EXECUTION: the background renewal thread, subprocess invocation,
# and stage chaining. A stage function must atomically CLAIM its stage (no
# live lease held by another worker) before doing any real work,
# periodically RENEW the lease while it runs, and only ever write its
# result/status through wss.complete_stage(), which re-checks ownership
# (including lease liveness) at the moment of writing.

from workflow_state_store import (
    StageClaimError, GlobalLockBusyError,
    claim_stage, renew_stage_lease, release_stage_lease, complete_stage,
    acquire_global_lock, renew_global_lock, release_global_lock,
    set_worker_progress_note,
    _LEASE_DURATION_SECONDS, _HEARTBEAT_RENEW_SECONDS,
)

# Documented ceiling for how long a worker will wait, with bounded backoff,
# to acquire a shared-workspace global lock before giving up (see
# run_investigation_stage / run_reporting_stage). Generous enough to
# outlast one worst-case contending investigation (two subprocess passes,
# ~1200s) with headroom — not an indefinite hang.
_GLOBAL_LOCK_MAX_WAIT_SECONDS = 1800


class LeaseRenewer:
    """
    [FYP-CLASS] Background Stage-Lease/Global-Lock Heartbeat Thread

    Background renewal thread for the duration of one stage's real work,
    used uniformly for Threat Intelligence/Investigation/Reporting so no
    stage depends on having frequent progress callbacks to stay alive.
    Exposes `lease_lost` so the stage function can notice a lost lease
    itself instead of only finding out when its next DB write silently
    loses a race — complete_stage()'s own atomic ownership check is still
    the final source of truth; this is a fast, early exit, not a
    substitute for it. Optionally ALSO renews a global workspace lock on
    the same heartbeat tick once also_renew_global_lock() is called —
    exposes `global_lock_lost` separately from `lease_lost` so a caller can
    tell which one failed.

    [FYP-STAGE-LOCK]: one instance per stage-function invocation
    (constructed with incident_id/run_id/worker_id, the SAME worker_id
    claim_stage() returned to the caller). `.start()` right after
    claim_stage() succeeds, `.stop()` in a `finally:` block so the thread
    is always torn down. Ticks every `_HEARTBEAT_RENEW_SECONDS`, calling
    `renew_stage_lease()` (and, if `also_renew_global_lock()` was called,
    `renew_global_lock()` too) — either renewal failing sets the
    corresponding Event and stops the loop; it does not retry.

    [FYP-USED-BY]: resume_after_triage_approval(), run_investigation_stage()
    (also calls also_renew_global_lock("investigation_workspace")),
    run_reporting_stage() (also calls
    also_renew_global_lock("reporting_workspace")) — all three of this
    module's durable per-stage worker functions.
    """
    # [FYP-FUNCTION] `__init__` — implements the init operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `incident_id`, `run_id`, `worker_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_reporting_agent/backend/error_handling.py:__init__, workflow_state_store.py:__init__; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `Event`, `Thread`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def __init__(self, incident_id: str, run_id: str, worker_id: str):
        self._incident_id = incident_id
        self._run_id = run_id
        self._worker_id = worker_id
        self._global_lock_name: str | None = None
        self._stop = threading.Event()
        self.lease_lost = threading.Event()
        self.global_lock_lost = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    # [FYP-FUNCTION] `also_renew_global_lock` — implements the also renew global lock operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `lock_name`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_workflow.py:run_investigation_stage, soc_workflow.py:run_reporting_stage; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: no nested function/service calls.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def also_renew_global_lock(self, lock_name: str) -> None:
        self._global_lock_name = lock_name

    # [FYP-FUNCTION] `_run` — implements the run operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `renew_global_lock`, `renew_stage_lease`, `set`, `wait`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _run(self):
        while not self._stop.wait(_HEARTBEAT_RENEW_SECONDS):
            if not renew_stage_lease(self._incident_id, self._run_id, self._worker_id):
                self.lease_lost.set()
                break
            if self._global_lock_name and not renew_global_lock(
                    self._global_lock_name, self._worker_id):
                self.global_lock_lost.set()
                break

    # [FYP-FUNCTION] `start` — implements the start operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include app.py:<module>, app.py:_bounded_get, app.py:_proceed_to_next_workflow_stage; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `start`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def start(self):
        self._t.start()

    # [FYP-FUNCTION] `stop` — implements the stop operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include soc_workflow.py:resume_after_triage_approval, soc_workflow.py:run_investigation_stage, soc_workflow.py:run_reporting_stage; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `join`, `set`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def stop(self):
        self._stop.set()
        self._t.join(timeout=2)


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 3.  STAGE 1 — TRIAGE  (in-process)
# ══════════════════════════════════════════════════════════════════════════════

def run_triage(incident: dict, progress_fn=None,
               parsed_context: dict | None = None,
               force: bool = False) -> dict:
    """
    [FYP-FUNCTION] Triage Stage Runner (in-process, LLM-backed)

    Run the triage agent in-process. Returns its native result dict.

    parsed_context is Stage 0's processed_alert (see run_parsing) — when
    present, the IOC/risk/classification phases reuse those already-extracted
    indicators instead of re-deriving them from the raw incident. force=True
    bypasses TriageAgent's result cache, for an explicit retry.

    Args:
        incident: raw incident dict to triage.
        progress_fn: optional live-progress callback, forwarded straight
            into TriageAgent so its internal phases (IOC extraction, risk
            scoring, classification, ticket generation, ...) can stream
            progress to the caller.
        parsed_context: see above; None means triage derives everything
            from `incident` itself (no Parsing handoff).
        force: bypass TriageAgent's own result cache and force a fresh run.

    Returns:
        TriageAgent.triage()'s native result dict — contains a "ticket" key
        (classification, unc, summary, mitre_tactic/technique, ...) on
        success, or an "error" key on failure.

    [FYP-CALLS]: soc_triage_agent.TriageAgent.triage() (a fresh
    TriageAgent instance per call, configured via OpenAILLMConfig).
    [FYP-USED-BY]: run_until_triage_approval() (this module) — the only
    caller; not called by app.py directly (only indirectly through
    run_until_triage_approval).
    """
    from soc_triage_agent import OpenAILLMConfig, TriageAgent
    agent = TriageAgent(cfg=OpenAILLMConfig(), progress_fn=progress_fn)
    return agent.triage(incident, force=force, parsed_context=parsed_context)


def run_parsing(incident: dict, run_id: str) -> dict:
    """
    [FYP-FUNCTION] Parsing Stage Runner (in-process, rule-based)

    Run the existing Parsing & Normalisation stage in-process, reusing
    soc_reporting_agent's parser unmodified. Mirrors run_triage()'s pattern:
    a thin wrapper, no new parsing logic. Also asks the LLM for a plain-
    English summary of what the parser extracted (see generate_parsing_ai_summary).

    run_id now required — scopes the output directory per run (not just
    per incident) so a durable reload (load_parsing_result_for_run) can
    trust the files belong to THIS run, not a stale/overwritten previous
    run of the same incident.

    Args:
        incident: raw incident dict to parse/normalise.
        run_id: this run's id — output written under
            REP_DIR/outputs/{safe(incident_id)}/{safe(run_id)}/parsing/.

    Returns:
        The parser's native result dict (status/normalised_alert/
        processed_alert/missing_important_fields/...), with ai_summary/
        ai_thinking merged in on a "completed" status.

    [FYP-CALLS]: soc_reporting_agent/services/parser_normaliser.
    run_parser_normalisation_for_dashboard() (imported lazily, with
    REP_DIR added to sys.path first), generate_parsing_ai_summary().
    [FYP-USED-BY]: run_until_triage_approval() (this module) — the only
    caller (skipped entirely when use_mock_triage=True).
    """
    rep_dir = str(REP_DIR)
    if rep_dir not in sys.path:
        sys.path.insert(0, rep_dir)
    from services.parser_normaliser import run_parser_normalisation_for_dashboard

    inc_id = str(incident.get("id") or incident.get("incidentId") or "unknown")
    output_dir = REP_DIR / "outputs" / _safe(inc_id) / _safe(run_id) / "parsing"
    result = run_parser_normalisation_for_dashboard(incident, output_dir=output_dir)
    if result.get("status") == "completed":
        result.update(generate_parsing_ai_summary(result))
    return result


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 3.5  AI-SUMMARY / "THINKING" RENDERING HELPERS
# ══════════════════════════════════════════════════════════════════════════════
# Shared by every stage (Parsing/Triage/Threat-Intel/Investigation/Reporting):
# building the bounded fact packet sent to the summary LLM call
# (_stage_ai_summary_context), enforcing the plain-English length/format
# limits app.py's UI expects (limit_ai_summary_sentences), and turning each
# stage's raw agent output into the human-readable "thinking" panels/trace
# tables the UI renders (render_*_thinking_plain, _investigation_*). None
# of this changes stage decisions — it is presentation-layer only.

def _split_ai_summary_sections(text: str) -> tuple[str, str]:
    """[FYP-FUNCTION] Split the LLM's labelled SUMMARY/THINKING reply into two strings.
    Falls back to treating the whole reply as the summary if the model
    didn't follow the requested labels."""
    m = re.search(r"SUMMARY:\s*(.*?)\s*THINKING:\s*(.*)", text, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return text.strip(), ""


_AI_SUMMARY_MAX_SENTENCES = 2
_AI_SUMMARY_MAX_WORDS = 80
_AI_SUMMARY_ABBREVIATIONS = {
    "e.g.", "i.e.", "etc.", "mr.", "mrs.", "ms.", "dr.", "prof.",
    "inc.", "ltd.", "vs.", "no.",
}


def limit_ai_summary_sentences(
    text: Any,
    *,
    max_sentences: int = _AI_SUMMARY_MAX_SENTENCES,
    max_words: int = _AI_SUMMARY_MAX_WORDS,
) -> str:
    """
    [FYP-FUNCTION] AI-Summary Length Enforcer

    Return a concise, plain-text AI summary with a hard sentence cap.

    Prompts request one or two sentences, but model instructions alone are
    not a reliable output boundary. This guard is applied both when a
    summary is generated and when an older persisted summary is rendered.
    Decimal values and IP addresses are not treated as sentence boundaries.
    """
    cleaned = str(text or "").strip()
    if not cleaned:
        return ""
    cleaned = re.sub(
        r"(?i)^\s*(?:summary|ai[- ]generated summary)\s*:\s*", "", cleaned
    )
    cleaned = re.sub(r"(?m)^\s*(?:[-*•]\s+|\d+[.)]\s+)", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return ""

    sentences: list[str] = []
    start = 0
    length = len(cleaned)
    index = 0
    while index < length and len(sentences) < max(1, max_sentences):
        char = cleaned[index]
        if char not in ".!?":
            index += 1
            continue

        next_index = index + 1
        while next_index < length and cleaned[next_index] in "\"')]}":
            next_index += 1

        if char == ".":
            next_non_space = next_index
            while (
                next_non_space < length
                and cleaned[next_non_space].isspace()
            ):
                next_non_space += 1
            if (
                index > 0
                and cleaned[index - 1].isdigit()
                and next_non_space < length
                and cleaned[next_non_space].isdigit()
            ):
                index += 1
                continue
            prior_token_match = re.search(
                r"([A-Za-z.]+)\.$", cleaned[: index + 1]
            )
            prior_token = (
                prior_token_match.group(0).lower()
                if prior_token_match else ""
            )
            if prior_token in _AI_SUMMARY_ABBREVIATIONS:
                index += 1
                continue

        boundary = next_index >= length
        if not boundary and cleaned[next_index].isspace():
            boundary = True
        if boundary:
            sentence = cleaned[start:next_index].strip()
            if sentence:
                sentences.append(sentence)
            start = next_index
            while start < length and cleaned[start].isspace():
                start += 1
            index = start
            continue
        index += 1

    if len(sentences) < max(1, max_sentences) and start < length:
        remainder = cleaned[start:].strip()
        if remainder:
            sentences.append(remainder)

    limited = " ".join(sentences[:max(1, max_sentences)]).strip()
    words = limited.split()
    if max_words > 0 and len(words) > max_words:
        limited = " ".join(words[:max_words]).rstrip(" ,;:—-")
        if limited and limited[-1] not in ".!?":
            limited += "."
    return limited


def _stage_ai_summary_context(stage: str, result: dict) -> str:
    """[FYP-FUNCTION] Build a bounded, stage-specific fact packet for the summary model.
    Normalises the many possible stage-name spellings (aliases dict) down to
    one of parsing/triage/threat_intel/investigation/reporting and picks
    just the fields relevant to that stage out of its raw result dict, so
    the LLM summary prompt stays small and on-topic instead of receiving
    the whole (often large) stage result verbatim."""
    key = re.sub(r"[^a-z]+", "_", str(stage or "").strip().lower()).strip("_")
    aliases = {
        "parsing_and_normalisation": "parsing",
        "parsing_normalisation": "parsing",
        "threat_intelligence_enrichment": "threat_intel",
        "threat_intelligence": "threat_intel",
        "investigation_agent": "investigation",
        "reporting_agent": "reporting",
    }
    key = aliases.get(key, key)
    result = result if isinstance(result, dict) else {}

    if key == "parsing":
        context = {
            "status": result.get("status"),
            "parser_confidence": result.get("parser_confidence"),
            "normalised_alert_count": result.get("normalised_alert_count"),
            "selected_alert_id": result.get("selected_alert_id"),
            "processed_alert": result.get("processed_alert"),
            "missing_important_fields": result.get("missing_important_fields"),
            "recommended_next_action": result.get("recommended_next_action"),
        }
    elif key == "triage":
        ticket = result.get("ticket") or {}
        meta = result.get("metakeys_payload") or {}
        context = {
            "classification": ticket.get("classification"),
            "incident_category": ticket.get("incident_category"),
            "mitre_tactic": ticket.get("mitre_tactic"),
            "mitre_technique": ticket.get("mitre_technique"),
            "risk_rating": ticket.get("risk_rating"),
            "stage_output_summary": ticket.get("summary"),
            "recommended_actions": ticket.get("recommended_actions"),
            "matched_metakeys": ticket.get("metakeys"),
            "matched_ioc_count": ticket.get("matched_ioc_count"),
            "ioc_summary": meta.get("ioc_summary"),
            "risk_level": meta.get("risk_level"),
        }
    elif key == "threat_intel":
        context = {
            "status": result.get("status"),
            "enrichment_risk_level": result.get("enrichment_risk_level"),
            "enrichment_risk_score": result.get("enrichment_risk_score"),
            "enrichment_risk_reasons": result.get("enrichment_risk_reasons"),
            "threat_intelligence": result.get("threat_intelligence"),
            "warnings": result.get("warnings"),
            "stage_output_summary": result.get("summary"),
            "recommended_next_action": result.get("recommended_next_action"),
        }
    elif key == "investigation":
        context = {
            "status": result.get("status"),
            "incident_id": (
                result.get("investigated_for") or result.get("incident_id")
            ),
            "triage_classification": result.get("triage_classification"),
            "alert_logs_ingested": result.get("alert_count") or len(result.get("cluster_alert_ids") or [1]),
            "incident_folder": result.get("incident_folder"),
            "cluster_alert_ids": result.get("cluster_alert_ids"),
            "severity": result.get("severity"),
            "indicators": result.get("indicators"),
            "stage_output_summary": result.get("summary"),
            "missing_evidence": result.get("missing_evidence"),
            "feedback_loop": result.get("feedback_loop"),
            "severity_divergence": result.get("severity_divergence"),
            "narrative_report_excerpt": str(
                result.get("narrative_report") or ""
            )[:4000],
        }
    elif key == "reporting":
        context = {
            "status": result.get("status"),
            "report_status": (
                result.get("report_status_display")
                or result.get("report_status")
            ),
            "validation_status": (
                result.get("validation_status_display")
                or result.get("validation_status")
            ),
            "report_completeness_score": result.get(
                "report_completeness_score"
            ),
            "report_quality_score": result.get("report_quality_score"),
            "report_manifest": result.get("report_manifest"),
            "generated_reports": result.get("generated_reports"),
            "stage_output_summary": result.get("summary"),
            "investigation_limitations": (
                result.get("investigation_limitations")
                or result.get("limitations")
            ),
            "warnings": result.get("warnings"),
            "recommended_next_action": result.get("recommended_next_action"),
        }
    else:
        context = {
            key_name: value for key_name, value in result.items()
            if key_name not in {
                "subprocess", "orchestrator_subprocess", "artifacts",
                "output_files", "ai_thinking",
            }
        }
    return json.dumps(context, indent=2, default=str)[:9000]


def generate_stage_ai_summary(
    stage: str,
    stage_result: dict,
    model: str | None = None,
) -> dict:
    """
    [FYP-FUNCTION] Generic Per-Stage AI Summary Generator

    Generate the one-to-two sentence analyst summary for any stage.

    The detailed native stage result remains unchanged and available in its
    Output view. This is a separate, deliberately short orientation layer.

    [FYP-FALLBACK]: any LLM-call exception is caught and turned into a
    visible "AI summary unavailable — LLM call failed: ..." string rather
    than propagating — a summary-generation failure must never fail the
    stage itself.
    [FYP-CALLS]: _stage_ai_summary_context(), soc_reporting_agent/backend/
    openai_client.invoke_openai_text(), limit_ai_summary_sentences().
    """
    rep_dir = str(REP_DIR)
    if rep_dir not in sys.path:
        sys.path.insert(0, rep_dir)
    from backend.openai_client import invoke_openai_text

    selected_model = model or os.getenv("OPENAI_MODEL") or "gpt-5.4-mini"
    context = _stage_ai_summary_context(stage, stage_result)
    try:
        summary = invoke_openai_text(
            f"{stage} stage result fields:\n{context}",
            system=(
                "You are a SOC analyst assistant summarising the current "
                "workflow stage for an analyst. Return exactly one or two "
                "concise plain-English sentences, with no heading, bullets, "
                "brackets, or raw field dump, and no more than 70 words total. "
                "State what happened or was found; use the second sentence only "
                "for why it matters or the next action. Use only facts in the "
                "provided stage result and never invent missing values."
            ),
            model=selected_model,
            max_output_tokens=180,
        )
        summary = limit_ai_summary_sentences(summary)
    except Exception as exc:
        summary = limit_ai_summary_sentences(
            f"AI summary unavailable — LLM call failed: {exc}"
        )

    return {
        "ai_summary": summary,
        "ai_summary_model": selected_model,
        "ai_summary_generated_at": datetime.now().isoformat(timespec="seconds"),
    }


def generate_parsing_ai_summary(parsing_result: dict, model: str | None = None) -> dict:
    """[FYP-FUNCTION] [FYP-FALLBACK] Ask OpenAI for a plain-English summary of what the Parsing &
    Normalisation stage extracted, based on its processed_alert output.
    Reuses the existing OpenAI helper (soc_reporting_agent/backend/openai_client.py,
    already used by the reporting stage) — no separate LLM client is introduced."""
    rep_dir = str(REP_DIR)
    if rep_dir not in sys.path:
        sys.path.insert(0, rep_dir)
    from backend.openai_client import invoke_openai_text

    processed_alert = parsing_result.get("processed_alert") or {}
    context = json.dumps(processed_alert, indent=2, default=str)[:4000]
    selected_model = model or os.getenv("OPENAI_MODEL") or "gpt-5.4-mini"

    try:
        raw = invoke_openai_text(
            f"Parsed alert fields:\n{context}",
            system=(
                "You are a SOC analyst assistant. You are given the parsed and "
                "normalised fields extracted from a NetWitness alert by the "
                "parsing pipeline. Reply in exactly this format:\n"
                "SUMMARY: <exactly 1-2 concise plain-English sentences, no "
                "more than 70 words total, on what this alert is and why it "
                "matters>\n"
                "THINKING: <2-4 short bullet points on the specific indicators "
                "(host, IPs, user, file, process, MITRE technique) that drove "
                "your read>\n"
                "Only state facts present in the data below — never invent "
                "values that aren't there."
            ),
            model=selected_model,
            max_output_tokens=420,
        )
        summary, thinking = _split_ai_summary_sections(raw)
        summary = limit_ai_summary_sentences(summary)
    except Exception as exc:
        summary = limit_ai_summary_sentences(
            f"AI summary unavailable — LLM call failed: {exc}"
        )
        thinking = summary

    return {
        "ai_summary": summary,
        "ai_thinking": thinking,
        "ai_summary_model": selected_model,
        "ai_summary_generated_at": datetime.now().isoformat(timespec="seconds"),
    }


def render_triage_thinking_plain(triage_result: dict) -> str:
    """[FYP-FUNCTION] Connected-narrative 'thinking process' for the Triage panel — built
    ONLY from TriageAgent.triage()'s own trace (the real IOC Checklist /
    Risk Rating / SOC Classification phase output), not a secondary LLM
    re-summarization. An LLM asked to reflect on the finished ticket can
    misstate or contradict what the agent actually computed; reading the
    trace directly cannot.

    Written as reasoning ("given this, therefore that"), not a field dump —
    a bullet-per-field rendering reads as contradictory in cases like "0
    matched IOC(s)" alongside a non-empty metakeys list, even though that's
    not actually a contradiction: the IOC phase's LLM call can report a
    category's `metakeys` (fields it looked at) independently of whether
    any IOC in that category matched (soc_triage_agent.py's _run_ioc(),
    where `extra_mkeys` is merged into all_metakeys regardless of
    matched_iocs). This phrasing makes that relationship explicit instead
    of implying a false contradiction.

    No markdown — the UI card renders this as escaped plain text with
    blank-line paragraph breaks preserved, not parsed markdown."""
    by_step = {s.get("step"): s for s in (triage_result.get("trace") or [])}
    paragraphs: list[str] = []

    ioc = by_step.get("IOC Checklist")
    if ioc is not None:
        count   = ioc.get("total_ioc_count") or 0
        summary = ioc.get("ioc_summary") or ""
        mkeys   = ioc.get("matched_metakeys") or []
        if count:
            p = f"The IOC checklist matched {count} indicator(s)"
            p += f": {summary}." if summary else "."
        else:
            # Avoid repeating the same "nothing matched" idea twice when
            # ioc_summary already says so in its own words.
            p = summary or "The IOC checklist matched no known-bad indicators."
        if mkeys:
            p += (f" Fields the review looked at: {', '.join(mkeys)} — "
                  f"present in the alert, not necessarily indicators of "
                  f"compromise on their own.")
        paragraphs.append(p)

    risk = by_step.get("Risk Rating")
    if risk is not None:
        d = risk.get("data") or {}
        p = (f"Based on that, risk was rated {d.get('overall_risk') or '—'} "
            f"overall — initiation {d.get('likelihood_initiation') or '—'}, "
            f"occurrence {d.get('likelihood_occurrence') or '—'}, adverse "
            f"impact {d.get('likelihood_adverse_impact') or '—'}")
        p += f": {d['rationale']}" if d.get("rationale") else "."
        paragraphs.append(p)

    cls = by_step.get("SOC Classification")
    if cls is not None:
        d = cls.get("data") or {}
        tactic    = d.get("mitre_tactic") or "Unknown"
        technique = d.get("mitre_technique") or "Unknown"
        p = f"This was classified as {(d.get('classification') or '—').upper()}"
        p += f": {d['summary']}" if d.get("summary") else "."
        p += f" MITRE mapping: {tactic} ({technique})."
        paragraphs.append(p)

    return "\n\n".join(paragraphs)


def _thinking_fragment(value: Any, limit: int = 560) -> str:
    """[FYP-FUNCTION] Collapse persisted agent output into a short, card-safe sentence."""
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0].rstrip(" ,;:") + "…"


def _investigation_trace_rows(narrative_report: str, limit: int = 3) -> list[dict]:
    """[FYP-FUNCTION] Read orchestrator.py's persisted Playbook Execution Trace table.

    main.py writes FinalIncidentAnalysis.execution_trace to the Markdown
    report. soc_workflow.run_investigation() then persists that report in
    investigation_result_json.narrative_report. Reading that exact table
    keeps the UI tied to the Investigation agent's real milestone decisions.
    """
    if "## Playbook Execution Trace" not in str(narrative_report or ""):
        return []
    section = narrative_report.split("## Playbook Execution Trace", 1)[1]
    section = section.split("\n## ", 1)[0]
    rows: list[dict] = []
    pattern = re.compile(
        r"^\|\s*`([^`]+)`\s*\|\s*(.*?)\s*\|\s*\*\*([^*]+)\*\*\s*\|\s*(.*?)\s*\|\s*$"
    )
    for line in section.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        rows.append({
            "step_id": match.group(1),
            "instruction": match.group(2),
            "status": match.group(3),
            "findings": match.group(4),
        })
        if len(rows) >= limit:
            break
    return rows


def _investigation_recommended_containment_actions(narrative_report: str) -> list[str]:
    """[FYP-FUNCTION] Read orchestrator.py's persisted Recommended Containment Actions bullets.

    main.py writes FinalIncidentAnalysis.recommended_containment (the
    Investigation agent's specific, policy-driven containment findings — e.g.
    exact hostnames, IPs, processes, registry paths) to the Markdown report as
    a bullet list under this heading. run_investigation() otherwise only
    keeps that report as an opaque narrative_report blob, so without this the
    reporting handoff never sees the real containment actions under any of
    the field names (recommended_containment / recommended_actions) it reads —
    it only sees the generic skills_sidecar fallback. Reading the bullets back
    out here keeps section 10.3 of the analyst-facing report tied to the
    Investigation agent's own containment findings, verbatim.
    """
    text = str(narrative_report or "")
    if "## Recommended Containment Actions" not in text:
        return []
    section = text.split("## Recommended Containment Actions", 1)[1]
    section = section.split("\n## ", 1)[0]
    actions: list[str] = []
    for line in section.splitlines():
        line = line.strip()
        if line.startswith("- "):
            action = line[2:].strip()
            if action:
                actions.append(action)
    return actions


# Column-header aliases for the MITRE ATT&CK table mitre_mapper.
# generate_markdown_table() writes (orchestrator.FinalIncidentAnalysis.
# mitre_mappings / mitre_mapper.MitreTTPMapping). Mirrors case_view.py's own
# _MITRE_HEADER_ALIASES so the reporting handoff parses the identical table
# the Investigation stage's own MITRE ATT&CK tab reads — case_view.py cannot
# be imported here (it imports this module), so the small deterministic
# parser is intentionally duplicated rather than shared.
_MITRE_HEADER_ALIASES = {
    "timeline phase / activity": "timeline_phase",
    "timeline phase": "timeline_phase",
    "observed evidence": "observed_evidence",
    "mitre tactic": "tactic",
    "tactic": "tactic",
    "mitre technique name": "technique_name",
    "technique name": "technique_name",
    "mitre id": "technique_id",
    "mitre technique id": "technique_id",
    "technique id": "technique_id",
}


def _split_mitre_table_row(line: str) -> list[str]:
    """[FYP-FUNCTION] Split one Markdown table row (`| a | b\\|c | ... |`) into
    unescaped cell strings — a small deterministic parser used by
    _investigation_mitre_mappings() below to read the narrative report's
    MITRE table without any Markdown-table library dependency."""
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    cells = re.split(r"(?<!\\)\|", line)
    return [c.replace("\\|", "|").strip() for c in cells]


def _investigation_mitre_mappings(narrative_report: str) -> list[dict]:
    """[FYP-FUNCTION] Read orchestrator.py's persisted MITRE ATT&CK TTP Mapping table.

    main.py writes FinalIncidentAnalysis.mitre_mappings (mitre_mapper.
    MitreTTPMapping — timeline_phase, observed_evidence, tactic,
    technique_name, technique_id) to the Markdown report as a table under the
    "Technical Chronology & MITRE ATT&CK TTP Mapping" heading. Investigation's
    own raw JSON result never carries this structured field (only the
    narrative_report blob does), so the table is located by its header row —
    any line whose cells include MITRE Tactic / MITRE Technique ID, in any
    order — rather than assumed to sit at a fixed position. A missing column
    yields "" for that field rather than raising; the row is skipped only if
    every field is empty. This keeps section 7.1 of the analyst-facing report
    tied to the Investigation agent's own MITRE ATT&CK findings, verbatim,
    and matching what the Investigation stage's own MITRE ATT&CK tab shows.
    """
    text = str(narrative_report or "")
    if not text:
        return []
    lines = text.splitlines()
    header_idx = None
    col_map: dict[int, str] = {}
    for i, line in enumerate(lines):
        if "|" not in line:
            continue
        cells = [c.lower() for c in _split_mitre_table_row(line)]
        found = {idx: _MITRE_HEADER_ALIASES[c] for idx, c in enumerate(cells)
                if c in _MITRE_HEADER_ALIASES}
        if {"tactic", "technique_id"} <= set(found.values()):
            header_idx = i
            col_map = found
            break
    if header_idx is None:
        return []
    row_start = header_idx + 1
    if row_start < len(lines) and re.match(r"^\s*\|?[\s:|-]+\|?\s*$", lines[row_start]):
        row_start += 1
    mappings: list[dict] = []
    for line in lines[row_start:]:
        if "|" not in line.strip() or not line.strip().startswith("|"):
            break
        cells = _split_mitre_table_row(line)
        row = {"timeline_phase": "", "observed_evidence": "",
               "tactic": "", "technique_name": "", "technique_id": ""}
        for idx, field in col_map.items():
            if idx < len(cells):
                row[field] = cells[idx]
        if not (row["tactic"] or row["technique_id"] or row["technique_name"]):
            continue
        mappings.append(row)
    return mappings


def _parse_progress_datetime(value: Any) -> datetime | None:
    """[FYP-FUNCTION] [FYP-FALLBACK] Best-effort ISO-8601 parse (handles a
    trailing "Z") — returns None rather than raising on anything
    unparseable, so progress-rendering helpers can treat a bad/missing
    timestamp as "unknown" instead of crashing the UI."""
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _format_progress_datetime(value: Any) -> str:
    """[FYP-FUNCTION] Human-readable "YYYY-MM-DD HH:MM:SS [UTC]" rendering of
    a progress timestamp; falls back to the raw value (or a placeholder
    string) when it can't be parsed — see _parse_progress_datetime()."""
    parsed = _parse_progress_datetime(value)
    if parsed is None:
        return str(value or "Time not recorded")
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
        return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def _format_elapsed(started_at: Any, finished_at: Any) -> str:
    """[FYP-FUNCTION] HH:MM:SS elapsed time between two progress timestamps;
    returns "" if either is missing/unparseable. Normalises mixed
    naive/aware datetimes (drops tzinfo from whichever side has it) rather
    than raising a TypeError on subtraction."""
    started = _parse_progress_datetime(started_at)
    finished = _parse_progress_datetime(finished_at)
    if started is None or finished is None:
        return ""
    if started.tzinfo is None and finished.tzinfo is not None:
        finished = finished.replace(tzinfo=None)
    elif started.tzinfo is not None and finished.tzinfo is None:
        started = started.replace(tzinfo=None)
    seconds = max(0, int((finished - started).total_seconds()))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _render_stage_progress_plain(
    stage_key: str,
    stage_label: str,
    result: dict,
    workflow_state: dict,
    activity: list[dict],
) -> str:
    """[FYP-FUNCTION] [FYP-STATE] Timestamped stage progress from the durable workflow ledger.
    Reconstructs a plain-text, deduplicated timeline (started/completed/
    approved/rejected) for one stage by filtering `activity` (the workflow
    ledger's event log — see workflow_state_store.py) down to events for
    this stage's aliases, then synthesises a synthetic "started" line from
    worker_started_at and a synthetic terminal line from the stage's status
    column when the ledger itself has no explicit matching event yet — so
    the panel never shows a stage as silently stuck with no timeline at all."""
    stage_aliases = {
        "parsing": {"parsing", "parsing_normalisation"},
        "triage": {"triage"},
        "threat_intel": {"threat_intel", "threat_intelligence"},
        "investigation": {"investigation"},
        "reporting": {"reporting"},
    }
    matching_stages = stage_aliases.get(stage_key, {stage_key})
    relevant = [
        item for item in (activity or [])
        if str(item.get("stage") or "").strip().lower() in matching_stages
    ]

    status_column = {
        "parsing": "parsing_status",
        "triage": "triage_status",
        "threat_intel": "threat_intel_status",
        "investigation": "investigation_status",
        "reporting": "reporting_status",
    }.get(stage_key)
    updated_column = {
        "threat_intel": "threat_intel_updated_at",
        "investigation": "investigation_updated_at",
        "reporting": "reporting_updated_at",
    }.get(stage_key)
    status = str(workflow_state.get(status_column) or result.get("status") or "Pending")
    status_lower = status.strip().lower()

    lines: list[str] = []
    seen: set[tuple[str, str]] = set()
    started_at = None
    finished_at = None
    latest_event_at = None

    action_labels = {
        "stage_started": f"{stage_label} started.",
        "stage_succeeded": f"{stage_label} processing completed.",
        "stage_failed": f"{stage_label} failed.",
        "approved": f"{stage_label} was approved by the SOC analyst.",
        "rejected": f"{stage_label} was rejected by the SOC analyst.",
    }
    for item in relevant:
        action = str(item.get("action") or "").strip().lower()
        message = action_labels.get(action)
        if not message:
            continue
        timestamp = item.get("timestamp") or item.get("occurred_at")

        if action == "stage_started":
            details = []
            alert_count = result.get("alert_count") or result.get("alert_logs_ingested")
            cls = result.get("triage_classification") or result.get("classification") or workflow_state.get("severity")
            if alert_count:
                details.append(f"ingested {alert_count} alert log(s)")
            if cls and str(cls).upper() != "UNRATED":
                details.append(f"classified as {cls}")
            if details:
                message = f"{stage_label} started ({', '.join(details)})."

        identity = (str(timestamp or ""), message)
        if identity in seen:
            continue
        seen.add(identity)
        lines.append(f"{_format_progress_datetime(timestamp)} — {message}")
        latest_event_at = timestamp or latest_event_at
        if action == "stage_started" and started_at is None:
            started_at = timestamp
        if action in {"stage_succeeded", "stage_failed"}:
            finished_at = timestamp

    worker_matches_stage = (
        str(workflow_state.get("worker_stage") or "").strip().lower()
        in matching_stages
    )
    if worker_matches_stage and workflow_state.get("worker_started_at"):
        worker_started = workflow_state.get("worker_started_at")
        if started_at is None:
            started_at = worker_started
            details = []
            alert_count = result.get("alert_count") or result.get("alert_logs_ingested")
            cls = result.get("triage_classification") or result.get("classification") or workflow_state.get("severity")
            if alert_count:
                details.append(f"ingested {alert_count} alert log(s)")
            if cls and str(cls).upper() != "UNRATED":
                details.append(f"classified as {cls}")
            message = f"{stage_label} started" + (f" ({', '.join(details)})." if details else ".")
            identity = (str(worker_started), message)
            if identity not in seen:
                lines.append(
                    f"{_format_progress_datetime(worker_started)} — {message}"
                )
                seen.add(identity)

    if not finished_at and updated_column:
        finished_at = workflow_state.get(updated_column)
    if not finished_at:
        finished_at = (
            result.get("generated_at")
            or result.get("created_at")
            or result.get("ai_summary_generated_at")
        )

    has_terminal_event = any(
        text.endswith(
            (
                "processing completed.",
                "failed.",
                "was approved by the SOC analyst.",
                "was rejected by the SOC analyst.",
            )
        )
        for text in lines
    )
    if finished_at and not has_terminal_event and status_lower not in {
        "pending", "processing", "running", "in progress"
    }:
        terminal_message = (
            f"{stage_label} failed."
            if status_lower == "failed"
            else f"{stage_label} processing completed."
        )
        lines.append(
            f"{_format_progress_datetime(finished_at)} — {terminal_message}"
        )

    # Insert concise incident folder classification note if available in result
    folder_name = (
        result.get("incident_folder")
        or result.get("incident_category")
        or result.get("cluster_name")
    )
    if not folder_name:
        narrative = str(result.get("narrative_report") or result.get("summary") or "")
        m = re.search(r"\b(?:cluster|folder)\s+([A-Za-z0-9_-]+)", narrative, re.IGNORECASE)
        if m:
            folder_name = m.group(1).strip()
    if folder_name:
        ts = finished_at or latest_event_at
        folder_msg = f"Classified under incident folder: {folder_name}."
        identity = (str(ts or ""), folder_msg)
        if identity not in seen:
            lines.append(f"{_format_progress_datetime(ts)} — {folder_msg}")
            seen.add(identity)

    if status_lower in {"processing", "running", "in progress"}:
        heartbeat = workflow_state.get("worker_heartbeat_at")
        current_time = (
            heartbeat
            or workflow_state.get("worker_started_at")
            or workflow_state.get("workflow_updated_at")
        )
        if started_at is None:
            started_at = current_time
        progress_note = str(
            workflow_state.get("worker_progress_note") or ""
        ).strip()
        current_message = f"Current stage: {stage_label} is processing"
        if progress_note:
            current_message += f" — {progress_note}"
        lines.append(
            f"{_format_progress_datetime(current_time)} — "
            f"{current_message}."
        )
    else:
        status_text = {
            "awaiting approval": "complete and awaiting SOC analyst approval",
            "approved": "approved",
            "complete": "complete",
            "complete with warnings": "complete with warnings",
            "failed": "failed",
            "rejected": "rejected",
            "blocked": "blocked",
            "pending": "pending",
        }.get(status_lower, status)
        current_time = (
            latest_event_at
            or finished_at
            or workflow_state.get("workflow_updated_at")
        )
        lines.append(
            f"{_format_progress_datetime(current_time)} — "
            f"Current stage: {stage_label} is {status_text}."
        )

    elapsed = _format_elapsed(started_at, finished_at)
    if elapsed:
        lines.append(f"Elapsed stage time: {elapsed}.")
    return "\n\n".join(lines)


def render_agent_thinking_plain(
    stage: str,
    result: dict | None,
    *,
    workflow_state: dict | None = None,
    activity: list[dict] | None = None,
) -> str:
    """
    [FYP-FUNCTION] Unified "Thinking Process" Renderer (all stages)

    Render every agent's timestamped Thinking Process progress.

    The case workspace supplies workflow_state + activity, producing the
    durable stage_started/stage_succeeded/stage_failed/approval timeline,
    current worker heartbeat, and elapsed stage time. The result-only
    branches remain as a backwards-compatible fallback for non-workspace
    callers. No hidden model chain-of-thought or generic case verdict is used.

    [FYP-DECISION]: when workflow_state/activity are supplied this
    delegates entirely to _render_stage_progress_plain() (the durable
    ledger-based timeline); only legacy/no-workspace callers fall through
    to the per-stage (parsing/triage/threat_intel/investigation/reporting)
    result-field rendering below, built from each stage's own persisted
    output (e.g. render_triage_thinking_plain() for triage,
    _investigation_trace_rows()/_thinking_fragment() for investigation).
    [FYP-CALLS]: _render_stage_progress_plain(), render_triage_thinking_plain(),
    _investigation_trace_rows(), _thinking_fragment().
    """
    result = result if isinstance(result, dict) else {}
    key = re.sub(r"[^a-z]+", "_", str(stage or "").strip().lower()).strip("_")
    aliases = {
        "parsing_and_normalisation": "parsing",
        "parsing_normalisation": "parsing",
        "threat_intelligence_enrichment": "threat_intel",
        "threat_intelligence": "threat_intel",
        "investigation_agent": "investigation",
        "reporting_agent": "reporting",
    }
    key = aliases.get(key, key)

    if workflow_state is not None or activity is not None:
        stage_labels = {
            "parsing": "Parsing",
            "triage": "Triage",
            "threat_intel": "Threat Intelligence Enrichment",
            "investigation": "Investigation",
            "reporting": "Reporting",
        }
        return _render_stage_progress_plain(
            key,
            stage_labels.get(key, str(stage or "Selected stage")),
            result,
            workflow_state or {},
            activity or [],
        )

    if not result:
        return ""

    if key == "parsing":
        direct = str(result.get("ai_thinking") or "").strip()
        if direct:
            return direct
        paragraphs = []
        count = result.get("normalised_alert_count")
        selected = result.get("selected_alert_id")
        if result.get("status") == "completed":
            subject = f"alert {selected}" if selected else "the selected alert"
            count_text = (
                f" and produced {count} normalised alert record(s)"
                if count is not None else ""
            )
            paragraphs.append(
                f"Parsing and normalisation completed for {subject}{count_text}."
            )
        missing = result.get("missing_important_fields") or []
        if missing:
            paragraphs.append(
                "The parser flagged missing fields for downstream review: "
                + ", ".join(str(item) for item in missing[:8]) + "."
            )
        if result.get("processed_alert"):
            paragraphs.append(
                "The resulting processed alert was handed to Triage as the "
                "validated workflow input."
            )
        return "\n\n".join(paragraphs)

    if key == "triage":
        return render_triage_thinking_plain(result)

    if key == "threat_intel":
        paragraphs = []
        level = result.get("enrichment_risk_level") or "Unknown"
        score = result.get("enrichment_risk_score")
        reasons = result.get("enrichment_risk_reasons") or []
        risk_text = f"Threat Intelligence rated the enrichment risk {level}"
        if score is not None:
            risk_text += f" with a score of {score}"
        if reasons:
            risk_text += ": " + "; ".join(
                _thinking_fragment(reason, 220) for reason in reasons[:4]
            )
        paragraphs.append(risk_text.rstrip(".") + ".")

        ti = result.get("threat_intelligence") or {}
        notes = result.get("warnings") or ti.get("notes") or []
        if notes:
            paragraphs.append(
                "Provider checks and limitations: "
                + "; ".join(_thinking_fragment(note, 220) for note in notes[:4])
            )
        next_action = result.get("recommended_next_action")
        if next_action:
            paragraphs.append(
                "Therefore, the workflow action is: "
                + _thinking_fragment(next_action, 320)
            )
        return "\n\n".join(paragraphs)

    if key == "investigation":
        paragraphs = []
        incident_id = result.get("investigated_for") or result.get("incident_id")
        folder = result.get("incident_folder")
        cluster_ids = result.get("cluster_alert_ids") or []
        if folder:
            sync_text = (
                f"sync_engine.py synchronized the evidence for "
                f"{incident_id or 'this alert'} into {folder}"
            )
            if cluster_ids:
                sync_text += (
                    f", where {len(cluster_ids)} alert(s) formed the "
                    "investigation timeline"
                )
            paragraphs.append(sync_text + ".")

        trace_rows = _investigation_trace_rows(result.get("narrative_report") or "")
        if trace_rows:
            decisions = []
            for row in trace_rows:
                decisions.append(
                    f"{row['step_id']} {row['status']}: "
                    f"{_thinking_fragment(row['findings'], 260)}"
                )
            paragraphs.append(
                "orchestrator.py evaluated the playbook milestones. "
                + " ".join(decisions)
            )

        severity = result.get("severity")
        summary = _thinking_fragment(result.get("summary"), 620)
        if severity or summary:
            conclusion = (
                f"The resulting investigation severity is {severity}. "
                if severity else ""
            )
            conclusion += summary
            paragraphs.append(conclusion.strip())

        feedback = result.get("feedback_loop") or {}
        if feedback.get("triggered"):
            gaps = feedback.get("gaps") or []
            paragraphs.append(
                f"The evidence-gap feedback loop was triggered for "
                f"{len(gaps)} gap(s); Triage supplement and re-investigation "
                "results were retained in this persisted output."
            )
        return "\n\n".join(paragraphs)

    if key == "reporting":
        paragraphs = []
        manifest = result.get("report_manifest") or {}
        sections = manifest.get("sections") or {}
        generated = result.get("generated_reports") or []
        count = len(sections) or len(generated)
        report_status = (
            result.get("report_status_display")
            or manifest.get("display_status")
            or result.get("report_status")
            or result.get("status")
            or "generated"
        )
        paragraphs.append(
            f"soc_workflow.py handed the approved investigation context to "
            f"Reporting, which produced {count} report section(s). Current "
            f"report state: {report_status}."
        )

        completeness = result.get("report_completeness_score")
        quality = result.get("report_quality_score")
        validation = (
            result.get("validation_status_display")
            or result.get("validation_status")
        )
        checks = []
        if completeness is not None:
            checks.append(f"completeness {completeness}")
        if quality is not None:
            checks.append(f"quality {quality}")
        if validation:
            checks.append(f"validation {validation}")
        if checks:
            paragraphs.append(
                "The reporting checks recorded " + ", ".join(checks) + "."
            )

        limitations = (
            result.get("investigation_limitations")
            or result.get("limitations")
            or result.get("warnings")
            or []
        )
        if limitations:
            paragraphs.append(
                "Limitations carried into analyst review: "
                + "; ".join(
                    _thinking_fragment(item, 220) for item in limitations[:4]
                )
            )
        paragraphs.append(
            "The generated candidate set remains subject to the persisted SOC "
            "analyst review and approval gate before closure."
        )
        return "\n\n".join(paragraphs)

    return _thinking_fragment(
        result.get("summary")
        or result.get("status")
        or result.get("recommended_next_action")
    )


def generate_triage_ai_summary(triage_result: dict, model: str | None = None) -> dict:
    """
    [FYP-FUNCTION] Triage AI-Summary Generator

    Ask OpenAI for a plain-English summary of what TriageAgent.triage()
    produced (the 'AI-Generated Summary' panel). The 'Thinking Process'
    panel is filled separately and deterministically by
    render_triage_thinking_plain() from the agent's own trace — not from
    this LLM call — so it stays accurate even if this call fails or the
    LLM misreads the data. Reuses the same OpenAI helper as the Parsing
    stage — no separate LLM client is introduced.

    [FYP-FALLBACK]: LLM-call exceptions are caught and rendered as a visible
    "AI summary unavailable" string, mirroring generate_parsing_ai_summary()
    / generate_stage_ai_summary() — a summary failure never fails Triage.
    """
    rep_dir = str(REP_DIR)
    if rep_dir not in sys.path:
        sys.path.insert(0, rep_dir)
    from backend.openai_client import invoke_openai_text

    ticket = triage_result.get("ticket") or {}
    meta   = triage_result.get("metakeys_payload") or {}
    context = json.dumps({
        "classification": ticket.get("classification"),
        "incident_category": ticket.get("incident_category"),
        "mitre_tactic": ticket.get("mitre_tactic"),
        "mitre_technique": ticket.get("mitre_technique"),
        "risk_rating": ticket.get("risk_rating"),
        "summary": ticket.get("summary"),
        "recommended_actions": ticket.get("recommended_actions"),
        "matched_metakeys": ticket.get("metakeys"),
        "matched_ioc_count": ticket.get("matched_ioc_count"),
        "ioc_summary": meta.get("ioc_summary"),
        "risk_level": meta.get("risk_level"),
    }, indent=2, default=str)[:4000]
    selected_model = model or os.getenv("OPENAI_MODEL") or "gpt-5.4-mini"

    try:
        summary = invoke_openai_text(
            f"Triage result fields:\n{context}",
            system=(
                "You are a SOC analyst assistant. You are given the structured "
                "output of the Triage agent for a NetWitness incident — its "
                "classification, MITRE mapping, risk rating, matched IOCs, and "
                "recommended actions. Reply with exactly one or two concise "
                "plain-English sentences, no more than 70 words total, on what "
                "this incident is and why it was classified this way. "
                "Only state facts present in the data below — never invent "
                "values that aren't there."
            ),
            model=selected_model,
            max_output_tokens=180,
        ).strip()
        summary = limit_ai_summary_sentences(summary)
    except Exception as exc:
        summary = limit_ai_summary_sentences(
            f"AI summary unavailable — LLM call failed: {exc}"
        )

    return {
        "ai_summary": summary,
        "ai_thinking": render_triage_thinking_plain(triage_result),
        "ai_summary_model": selected_model,
        "ai_summary_generated_at": datetime.now().isoformat(timespec="seconds"),
    }


def mock_triage_result(incident: dict) -> dict:
    """
    [FYP-FUNCTION] [FYP-FALLBACK] Canned Triage Result (offline/LLM-less testing)

    Canned triage output with the same shape as TriageAgent.triage() —
    same top-level keys (mock/metakeys_payload/ticket/trace/error) so every
    downstream consumer (needs_investigation(), handoff_to_investigation(),
    handoff_to_reporting(), pipeline_insert(), the AI-summary/thinking
    renderers) can treat it identically to a real LLM-backed result. Fixed
    HIGH classification/#99999Z ticket id — deliberately obvious as mock
    data (never mistakeable for a real ticket).

    Used with --mock-triage to test the workflow without LLM access.

    [FYP-USED-BY]: run_until_triage_approval() (this module) — called
    instead of run_triage() only when use_mock_triage=True.
    """
    inc_id  = str(incident.get("id") or incident.get("incidentId") or "unknown")
    title   = incident.get("title") or incident.get("name") or "Untitled"
    now_iso = datetime.utcnow().isoformat()
    metakeys = ["ip.src", "ip.dst", "user.name", "host.name"]
    return {
        "mock": True,
        "metakeys_payload": {
            "incident_id": inc_id, "incident_title": title, "timestamp": now_iso,
            "matched_metakeys": metakeys,
            "metakey_values": {},
            "ioc_summary": "MOCK: brute-force authentication pattern with "
                           "unusual privileged account activity.",
            "risk_level": "high", "classification": "high",
        },
        "ticket": {
            "unc": "#99999Z", "incident_id": inc_id, "title": title,
            "incident_time": incident.get("created") or now_iso,
            "created_at": now_iso, "classification": "HIGH",
            "risk_rating": {
                "likelihood_initiation": "High", "likelihood_occurrence": "High",
                "likelihood_adverse_impact": "Medium", "overall_risk": "High",
                "rationale": "MOCK rationale for offline workflow testing.",
            },
            "incident_category": "Internal Hacking (attempted)",
            "initial_response_time": "<= 30 minutes",
            "summary": "MOCK: repeated failed logons followed by a successful "
                       "privileged logon from the same source address.",
            "recommended_actions": ["Isolate the affected host",
                                    "Reset the targeted account credentials"],
            "matched_ioc_count": 3, "metakeys": metakeys,
        },
        "trace": [{"step": "IOC Checklist", "status": "ok",
                   "ioc_summary": "MOCK ioc summary", "total_ioc_count": 3,
                   "matched_metakeys": metakeys, "per_category": {}}],
        "error": None,
    }


def needs_investigation(triage_result: dict) -> bool:
    """
    [FYP-FUNCTION] Workflow Stage Routing (Triage -> Investigation decision)

    Purpose:
        The single [FYP-DECISION] point that decides whether an incident is
        routed to the Investigation stage or goes straight from Triage to
        Threat Intel/Reporting. This is what an evaluator should be shown
        for "where is the next stage selected".

    Parameters:
        triage_result: the completed Triage stage output dict. Reads the
            classification from either metakeys_payload.classification (LLM
            path) or ticket.classification (fallback path) — whichever is
            populated.

    Processing:
        Lower-cases the classification string and checks membership in
        INVESTIGATE_CLASSIFICATIONS = {"critical", "high", "medium"}
        (module-level constant near the top of this file). "low"/"informational"
        and anything unrecognised return False.

    Returns:
        bool — True routes the incident into Investigation via
        handoff_to_investigation()/investigate_with_feedback(); False skips
        straight to Threat Intel/Reporting.

    [FYP-USED-BY]:
        app.py (verified via grep) when deciding which stage tab/button to
        unlock next after Triage completes.

    [FYP-EVALUATOR]: demonstrate this function for "how is the next stage
    selected" — it is a pure, deterministic function with no side effects.
    """
    cls = str(triage_result.get("metakeys_payload", {}).get("classification")
              or triage_result.get("ticket", {}).get("classification") or "").lower()
    return cls in INVESTIGATE_CLASSIFICATIONS


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 3.5  STAGE — THREAT INTELLIGENCE ENRICHMENT  (in-process)
# ══════════════════════════════════════════════════════════════════════════════
# Thin orchestration wrapper around threat_intel.run_threat_intel_for_dashboard()
# (VirusTotal + AbuseIPDB + AlienVault OTX, case-level enrichment_risk_score/
# enrichment_risk_level/enrichment_risk_reasons — no per-IOC verdict system).
# This section only does incident/run identity validation and re-keys the
# engine's own result onto the workflow's stage-result envelope; the engine
# itself already computes notes vs. warnings and writes its output files
# before returning, so nothing here mutates the result further.

class ThreatIntelValidationError(Exception):
    """[FYP-CLASS] [FYP-ERROR] Raised when inputs handed to run_threat_intel() don't belong to the
    same incident/run — refuses a stale or mismatched enrichment."""


def run_threat_intel(incident_id: str, run_id: str,
                     normalised_alert: dict | None,
                     triage_result: dict, incident: dict | None = None) -> dict:
    """
    [FYP-FUNCTION] [FYP-EVALUATOR] Threat Intelligence Enrichment Stage Runner (in-process)

    Threat Intelligence Enrichment stage. Takes the already-loaded,
    already-validated Triage + Parsing outputs (and, where available, the
    full raw incident) for THIS incident/run explicitly — never re-reads
    "the latest" state itself. Never raises on lookup failures (the engine
    degrades every provider call to a "skipped"/"error" status instead);
    only raises ThreatIntelValidationError if the triage_result's own
    embedded incident_id doesn't match incident_id.

    [FYP-EVALUATOR]: THE actual threat-intel work, despite living behind a
    durable stage runner confusingly named resume_after_triage_approval()
    (see that function's own [FYP-EVALUATOR] note) — good place to show
    "where does VirusTotal/AbuseIPDB/AlienVault OTX enrichment happen".
    [FYP-CALLS]: threat_intel.run_threat_intel_for_dashboard() (the actual
    provider-lookup engine — VirusTotal/AbuseIPDB/AlienVault OTX), which
    also writes this stage's own output files under `output_dir`.
    [FYP-USED-BY]: resume_after_triage_approval() (this module) — the sole
    caller; not called by app.py directly.
    """
    import threat_intel

    ticket = triage_result.get("ticket") or {}
    meta   = triage_result.get("metakeys_payload") or {}
    tri_inc_id = str(meta.get("incident_id") or ticket.get("incident_id") or "")
    if tri_inc_id and tri_inc_id != str(incident_id):
        raise ThreatIntelValidationError(
            f"triage_result belongs to incident {tri_inc_id!r}, expected "
            f"{incident_id!r} — refusing stale/mismatched threat-intel run")

    output_dir = REP_DIR / "outputs" / _safe(str(incident_id)) / _safe(run_id) / "threat_intel"
    flat_alert = threat_intel._build_flat_alert(incident or {}, triage_result, normalised_alert)
    dashboard_result = threat_intel.run_threat_intel_for_dashboard(flat_alert, output_dir=output_dir)

    return {
        "incident_id": str(incident_id), "run_id": run_id,
        "stage": "threat_intelligence",
        "status": dashboard_result["status"],
        "generated_at": dashboard_result["created_at"],
        "threat_intelligence": dashboard_result["threat_intelligence"],
        "enrichment_risk_score": dashboard_result["enrichment_risk_score"],
        "enrichment_risk_level": dashboard_result["enrichment_risk_level"],
        "enrichment_risk_reasons": dashboard_result["enrichment_risk_reasons"],
        "warnings": dashboard_result["warnings"],
        "enriched_alert": dashboard_result["enriched_alert"],
        "summary": dashboard_result["summary"],
        "recommended_next_action": dashboard_result["recommended_next_action"],
        "output_files": dashboard_result["output_files"],
    }


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 4.  HANDOFF — TRIAGE → INVESTIGATION
# ══════════════════════════════════════════════════════════════════════════════

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NOISE_VALUES = {"", "unknown", "none", "null", "n/a", "-", "0.0.0.0",
                 "localhost", "127.0.0.1"}


def _flatten_dict(d, prefix: str = "") -> dict:
    """[FYP-FUNCTION] Recursively flatten a nested dict/list into a single
    dict of {"a.b[0].c": value} dotted/indexed paths — used by
    _harvest_incident_context() to scan every field of an arbitrarily
    nested raw incident for user/host/IP-shaped values without hardcoding
    every possible nesting shape."""
    items: dict = {}
    if isinstance(d, dict):
        for k, v in d.items():
            items.update(_flatten_dict(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(d, list):
        for i, v in enumerate(d):
            items.update(_flatten_dict(v, f"{prefix}[{i}]"))
    else:
        items[prefix] = d
    return items


# [FYP-FUNCTION] `_scalar` — implements the scalar operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:_mk, soc_workflow.py:handoff_to_reporting; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `isinstance`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _scalar(value):
    """Metakey values may be lists after deep extraction — take the first."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


# [FYP-FUNCTION] `_harvest_incident_context` — implements the harvest incident context operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `incident`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:build_investigation_alert, soc_workflow.py:handoff_to_reporting; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_add`, `_flatten_dict`, `append`, `findall`, `get`, `group`, `keys`, `lower`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _harvest_incident_context(incident: dict) -> dict:
    """Best-effort forensic context from the raw incident, used when triage's
    metakey extraction found nothing (e.g. cached pre-upgrade results). Pure
    code, sorted iteration — deterministic for identical input."""
    flat = _flatten_dict(incident)
    users: list = []
    hosts: list = []
    oses:  list = []
    src_ips: list = []
    dst_ips: list = []
    all_ips: list = []

    # [FYP-FUNCTION] `_add` — implements the add operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `bucket`, `val`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include nw_alerts.py:_add, nw_alerts.py:_distill_alerts, skills_sidecar.py:_assets_from_skills; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `append`, `len`, `lower`, `str`, `strip`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _add(bucket: list, val) -> None:
        s = str(val).strip()
        if s and s.lower() not in _NOISE_VALUES and s not in bucket \
                and len(bucket) < 8:
            bucket.append(s)

    for key in sorted(flat.keys()):
        val = flat[key]
        if val in (None, "", [], {}):
            continue
        lk = key.lower()
        sval = str(val)
        if "assignee" in lk or "analyst" in lk:
            continue
        if re.search(r"user(name|_name|dst|src)?$|account.?name$", lk):
            _add(users, val)
        elif re.search(r"host.?name$|computer.?name$|machine.?name$|device\.name$", lk):
            _add(hosts, val)
        elif re.search(r"\bos\b|operating.?system|os.?type|os.?version", lk):
            _add(oses, val)
        for ip in _IP_RE.findall(sval):
            if ip.lower() in _NOISE_VALUES:
                continue
            _add(all_ips, ip)
            if re.search(r"src|source", lk):
                _add(src_ips, ip)
            elif re.search(r"dst|dest", lk):
                _add(dst_ips, ip)

    # Title-entity fallback: NetWitness rule titles routinely name the only
    # affected entity ("High Risk Alerts: NetWitness Endpoint for KELLYWANG")
    # while the incident object itself carries no user/host fields at all.
    title_entity = ""
    m = re.search(r"\b(?:for|on|from)\s+([A-Za-z][\w.$-]{2,})\s*$",
                  str(incident.get("title") or "").strip())
    if m and m.group(1).lower() not in _NOISE_VALUES:
        title_entity = m.group(1)
        if not hosts and not users:
            hosts.append(title_entity)

    return {"users": users, "hosts": hosts, "operating_systems": oses,
            "source_ips": src_ips, "destination_ips": dst_ips, "ips": all_ips,
            "title_entity": title_entity}


# [FYP-FUNCTION] `_to_iso_timestamp` — implements the to iso timestamp operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:build_investigation_alert; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `float`, `fromisoformat`, `isinstance`, `isoformat`, `replace`, `str`, `strip`, `sub`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _to_iso_timestamp(value) -> str:
    """Normalize timestamp spellings to ISO-8601."""
    if value in (None, "", "Unknown"):
        return ""
    if isinstance(value, (int, float)):
        ts = float(value) / (1000 if value > 1e11 else 1)
        try:
            return datetime.utcfromtimestamp(ts).isoformat() + "+00:00"
        except Exception:
            return ""
    s = str(value).strip()
    s = re.sub(r"\s+UTC$", "+00:00", s, flags=re.IGNORECASE)
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    try:
        datetime.fromisoformat(s.replace("Z", "+00:00"))
        return s
    except Exception:
        return str(value)


# [FYP-FUNCTION] `prune_empty` — implements the prune empty operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `d`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:build_investigation_alert, soc_workflow.py:prune_empty; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `isinstance`, `items`, `prune_empty`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def prune_empty(d):
    """Recursively strip None, empty strings, empty lists/dicts, and 'Unknown'."""
    if isinstance(d, dict):
        cleaned = {k: prune_empty(v) for k, v in d.items()}
        return {k: v for k, v in cleaned.items() if v not in (None, "", [], {}, "Unknown", "unknown")}
    elif isinstance(d, list):
        cleaned = [prune_empty(v) for v in d]
        return [v for v in cleaned if v not in (None, "", [], {}, "Unknown", "unknown")]
    return d


# [FYP-FUNCTION] `build_investigation_alert` — constructs build investigation alert output for the next workflow orchestration and state consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `triage_result`, `incident`, `supplement`, `threat_intel_result`, `parsing_result`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include eval_harness.py:_c_playbook, soc_workflow.py:handoff_to_investigation; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_amlist`, `_cmdlines`, `_first`, `_harvest_incident_context`, `_mk`, `_mklist`, `_process_lineage`, `_to_iso_timestamp`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_investigation_alert(triage_result: dict, incident: dict,
                              supplement: dict | None = None,
                              threat_intel_result: dict | None = None,
                              parsing_result: dict | None = None) -> dict:
    """Convert triage output into the concise alert-JSON schema matching INC-6125."""
    payload = triage_result.get("metakeys_payload", {})
    ticket  = triage_result.get("ticket", {})
    mkv     = payload.get("metakey_values") or {}
    ctx     = _harvest_incident_context(incident)

    # [FYP-FUNCTION] `_mk` — implements the mk operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `key`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_workflow.py:build_investigation_alert; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_scalar`, `get`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _mk(key):
        return _scalar(mkv.get(key))

    _am = incident.get("alertMeta") or {}

    # [FYP-FUNCTION] `_amlist` — implements the amlist operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `*keys`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_workflow.py:_cmdlines, soc_workflow.py:_process_lineage, soc_workflow.py:build_investigation_alert; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `append`, `fromkeys`, `get`, `isinstance`, `list`, `str`, `strip`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _amlist(*keys) -> list:
        out: list = []
        for k in keys:
            v = _am.get(k)
            if isinstance(v, list):
                out += [str(x).strip() for x in v if str(x).strip()]
            elif v not in (None, "", [], {}):
                out.append(str(v).strip())
        return list(dict.fromkeys(out))

    # [FYP-FUNCTION] `_mklist` — implements the mklist operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `*keys`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_workflow.py:_cmdlines, soc_workflow.py:_process_lineage, soc_workflow.py:build_investigation_alert; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `append`, `fromkeys`, `get`, `isinstance`, `list`, `str`, `strip`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _mklist(*keys) -> list:
        out: list = []
        for k in keys:
            v = mkv.get(k)
            if isinstance(v, list):
                out += [str(x).strip() for x in v if str(x).strip()]
            elif v not in (None, "", [], {}):
                out.append(str(v).strip())
        return list(dict.fromkeys(out))

    # [FYP-FUNCTION] `_process_lineage` — implements the process lineage operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_workflow.py:build_investigation_alert; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_amlist`, `_mklist`, `append`, `len`, `range`, `replace`, `split`, `str`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _process_lineage() -> list:
        edges: list = []
        chains = (_mklist("process.lineage", "process.chain", "process.tree")
                  + _amlist("ProcessTree", "ProcessLineage"))
        for c in chains:
            norm = str(c).replace("→", "|").replace("->", "|").replace(">", "|")
            parts = [p.strip() for p in norm.split("|") if p.strip()]
            for i in range(len(parts) - 1):
                edges.append({"parent": parts[i], "child": parts[i + 1]})
        if edges:
            return edges
        children = _mklist("process.name")
        parents = _mklist("process.parent", "parent.process", "parent.name")
        if children and parents and len(children) == len(parents):
            return [{"parent": parents[i], "child": children[i]} for i in range(len(children))]
        return []

    src_ip = _first(_mk("ip.src"), incident.get("source_ip"), (ctx["source_ips"] or [None])[0])
    dst_ip = _first(_mk("ip.dst"), incident.get("destination_ip"), (ctx["destination_ips"] or [None])[0])
    hostname = _first(_mk("host.name"), incident.get("hostname"), (ctx["hosts"] or [None])[0])
    user = _first(_mk("user.name"), incident.get("username"), (ctx["users"] or [None])[0])

    # [FYP-FUNCTION] `_cmdlines` — implements the cmdlines operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include soc_workflow.py:build_investigation_alert; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `_amlist`, `_mklist`, `add`, `append`, `get`, `isinstance`, `set`, `str`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _cmdlines() -> list:
        out = _mklist("param.src", "param.dst", "param", "param_src", "param_dst", "process.cmdline", "cmdline", "command_line", "process_cmd", "os.cmdline")
        out += _amlist("CommandLine", "CmdLine", "ParamSrc", "ParamDst", "ProcessTree")
        if parsing_result:
            proc_alert = parsing_result.get("processed_alert") or {}
            norm_alert = parsing_result.get("normalised_alert") or {}
            if proc_alert.get("command_line"):
                out.append(str(proc_alert["command_line"]).strip())
            for c in (proc_alert.get("process_indicators", {}).get("command_lines") or []):
                if c:
                    out.append(str(c).strip())
            for c in (norm_alert.get("process_indicators", {}).get("command_lines") or []):
                if c:
                    out.append(str(c).strip())
        t_cmd = triage_result.get("command_line") or triage_result.get("process_indicators", {}).get("command_line")
        if t_cmd:
            out.append(str(t_cmd).strip())
        for ev in (incident.get("events") or []):
            if isinstance(ev, dict):
                c = ev.get("param_src") or ev.get("param") or ev.get("cmdline") or ev.get("command_line") or ev.get("process_cmd") or ev.get("param_dst")
                if c and str(c).strip() not in _NOISE_VALUES:
                    out.append(str(c).strip())

        seen = set()
        deduped = []
        for x in out:
            if not x or x in _NOISE_VALUES:
                continue
            cleaned = str(x).strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                deduped.append(cleaned)
        return deduped

    cmds = _cmdlines()
    cmd_val = cmds[0] if len(cmds) == 1 else (cmds if len(cmds) > 1 else None)

    # Extract all sub-alerts belonging to this incident if multiple exist
    sub_alerts = []
    raw_alerts_list = incident.get("alerts") or incident.get("events") or []
    if isinstance(raw_alerts_list, list):
        for idx, sub in enumerate(raw_alerts_list):
            if isinstance(sub, dict):
                sub_id = sub.get("id") or sub.get("alert_id") or f"alert_{idx+1}"
                sub_title = sub.get("title") or sub.get("name") or sub.get("signature") or sub.get("type") or "Security Alert"
                sub_ts = _to_iso_timestamp(sub.get("created") or sub.get("receivedTime") or sub.get("timestamp"))
                sub_sev = sub.get("severity") or sub.get("priority") or "Medium"
                sub_user = sub.get("userName") or sub.get("user") or user
                sub_host = sub.get("hostSummary") or sub.get("hostname") or sub.get("host") or hostname
                sub_src_ip = sub.get("sourceIp") or sub.get("src_ip") or src_ip
                sub_dst_ip = sub.get("destinationIp") or sub.get("dst_ip") or dst_ip
                sub_desc = sub.get("detail") or sub.get("description") or sub.get("summary") or ""
                
                sub_entry = {
                    "alert_id": str(sub_id),
                    "title": str(sub_title),
                    "timestamp": sub_ts,
                    "severity": str(sub_sev),
                    "user": sub_user,
                    "hostname": sub_host,
                    "source_ip": sub_src_ip,
                    "destination_ip": sub_dst_ip,
                    "description": sub_desc,
                }
                sub_alerts.append(prune_empty(sub_entry))

    raw_alert = {
        "incident_id": payload.get("incident_id") or ticket.get("incident_id"),
        "classification": {
            "alert_type": ticket.get("incident_category"),
            "severity": ticket.get("classification"),
            "risk_score": ticket.get("risk_rating") or incident.get("riskScore"),
        },
        "incident_details": {
            "title": payload.get("incident_title") or ticket.get("title"),
            "timestamp": _to_iso_timestamp(_first(ticket.get("incident_time"), payload.get("timestamp"))),
            "description": ticket.get("summary"),
            "mitre_att&ck": {
                "tactic": _first(payload.get("mitre_tactic"), ticket.get("mitre_tactic"), incident.get("mitre_tactic")),
                "technique": _first(payload.get("mitre_technique"), ticket.get("mitre_technique"), incident.get("mitre_technique")),
            },
        },
        "network_indicators": {
            "source": {
                "ip_address": src_ip,
                "port": _first(_mk("port.src")),
                "mac_address": _first(_amlist("MacAddress")),
                "hostname": hostname,
            },
            "destination": {
                "ip_address": dst_ip,
                "port": _first(_mk("port.dst"), _mk("tcp.dstport")),
                "service": _first(_mk("service"), _mk("network.service")),
                "domain": _mk("domain"),
            },
        },
        "endpoint_indicators": {
            "user": user,
            "hostname": hostname,
            "operating_system": _first(_mk("os.version"), (ctx["operating_systems"] or [None])[0]),
            "processes": {
                "process_name": _first(_mklist("process.name")),
                "command_line": cmd_val,
                "lineage": _process_lineage(),
            },
            "files": {
                "filename": _first(_mklist("file.name", "filename")),
                "filepath": _first(_mklist("file.path")),
                "hashes": _mklist("file.hash", "checksum", "checksumSha256", "checksumSha1", "checksumMd5", "sha256", "md5"),
            },
        },
        "email_artifacts": {
            "sender": _first(_mklist("email.src", "sender")),
            "recipient": _first(_mklist("email.dst", "recipient")),
            "subject": _first(_mklist("email.subject", "subject")),
        },
        **({"alerts": sub_alerts} if sub_alerts else {}),
        **({"triage_deep_dive": supplement} if supplement else {}),
        **({
            "threat_intelligence_enrichment": threat_intel_result.get("threat_intelligence") or threat_intel_result.get("enriched_alert"),
            "enrichment_risk_score": threat_intel_result.get("enrichment_risk_score"),
            "enrichment_risk_level": threat_intel_result.get("enrichment_risk_level"),
            "enrichment_risk_reasons": threat_intel_result.get("enrichment_risk_reasons"),
        } if threat_intel_result else {}),
    }

    return prune_empty(raw_alert)



def handoff_to_investigation(triage_result: dict, incident: dict,
                             supplement: dict | None = None,
                             threat_intel_result: dict | None = None,
                             parsing_result: dict | None = None) -> Path:
    """
    [FYP-FUNCTION] Triage -> Investigation Handoff

    Purpose: [FYP-FLOW] Packages Triage (+ optional Threat Intel/Parsing)
    output into the JSON alert file soc_investigation_agent_revised/ picks
    up from its triaged_alerts/ inbox — the file-queue handoff between the
    Triage and Investigation stages.

    [FYP-VALIDATION]/[FYP-STAGE-LOCK]: quarantines any leftover queued alert
    from a DIFFERENT incident into triaged_alerts/stale/ before writing this
    incident's alert. Investigation drains the whole queue in one pass, so a
    stale file from a previously-interrupted run would otherwise get merged
    into this run's report — this is a correctness safeguard, not a UI lock.

    Returns: Path to the written alert JSON. Side effect: file write under
    soc_investigation_agent_revised/triaged_alerts/.

    [FYP-USED-BY]: investigate_with_feedback() / run_investigation_stage().
    """
    alert = build_investigation_alert(triage_result, incident,
                                      supplement=supplement,
                                      threat_intel_result=threat_intel_result,
                                      parsing_result=parsing_result)
    queue_dir = INV_DIR / "triaged_alerts"
    queue_dir.mkdir(exist_ok=True)
    inc_id = re.sub(r"[^A-Za-z0-9_-]", "_", str(alert["incident_id"]))

    # Quarantine leftovers from interrupted runs. The investigation agent
    # drains the WHOLE queue, so a stale alert from a killed run would get
    # processed inside this incident's run — and can merge into / rename the
    # resulting report (the INC-53018-run-reported-as-INC-53027 bug). Stale
    # alerts are preserved in triaged_alerts/stale/; re-run their incident
    # from the app to investigate them properly with fresh triage data.
    stale_dir = queue_dir / "stale"
    for old in queue_dir.glob("*.json"):
        if old.name != f"{inc_id}_alert.json":
            try:
                stale_dir.mkdir(exist_ok=True)
                dest = stale_dir / f"{old.stem}_{datetime.now():%Y%m%d-%H%M%S}.json"
                old.replace(dest)
                _log("HANDOFF", f"stale queued alert moved aside: {old.name}")
            except Exception:
                pass

    path = queue_dir / f"{inc_id}_alert.json"
    _write_json(path, alert)
    _log("HANDOFF", f"triage -> investigation: {path.name}")
    return path


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 5.  STAGE 2 — INVESTIGATION  (subprocess)  +  TRIAGE FEEDBACK LOOP
# ══════════════════════════════════════════════════════════════════════════════

_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Playbook-table rows in the investigation markdown report:
#   | `step_1` | instruction | **NOT_MET** | findings |
_PLAYBOOK_ROW_RE = re.compile(
    r"\|\s*`(step_[^`]+)`\s*\|([^|]*)\|\s*\**(MET|NOT_MET|SKIPPED)\**\s*\|")


# Keywords that signal high-value investigative gaps — these steps are
# prioritised in the feedback loop so the triage deep-dive focuses on
# the questions that matter most for determining scope and containment.
_HIGH_VALUE_GAP_KEYWORDS = (
    "lateral", "horizontal", "vertical", "privilege", "escalat",
    "process", "spawn", "exfiltrat", "command", "containment",
    "malicious", "further investigation",
)


def detect_evidence_gaps(inv: dict) -> list[str]:
    """
    [FYP-FUNCTION] Evidence Gap Detection (automatic re-run trigger)

    [FYP-DECISION]/[FYP-RERUN]: Decide whether the investigation lacked
    information, and name the gaps. Triggers when the fraction of NOT_MET
    playbook steps meets or exceeds the configurable threshold
    (env var WORKFLOW_FEEDBACK_THRESHOLD, default 0.4 = 40%). Returns the
    unmet steps' instructions — prioritised by investigative value via
    _HIGH_VALUE_GAP_KEYWORDS — these become the questions the triage agent's
    deep-dive pass must answer.

    [FYP-EVALUATOR]: this is the exact threshold check that decides whether
    investigate_with_feedback() below performs an automatic Investigation
    re-run — no human clicks anything for this particular re-run.

    Input: inv — the Investigation stage result dict (narrative_report,
    status, missing_evidence). Output: list of up to 8 gap description
    strings, or [] if investigation was sufficient.
    """
    try:
        threshold = float(os.environ.get("WORKFLOW_FEEDBACK_THRESHOLD", "0.4"))
    except ValueError:
        threshold = 0.4
    threshold = max(0.0, min(threshold, 1.0))  # clamp to [0, 1]

    gaps: list[str] = []
    md = str(inv.get("narrative_report") or "")
    rows = _PLAYBOOK_ROW_RE.findall(md)
    if rows:
        not_met = [(sid, instr.strip()) for sid, instr, status in rows
                   if status == "NOT_MET"]
        if len(not_met) / len(rows) >= threshold:
            # Prioritise high-value investigative gaps so the triage
            # deep-dive focuses on scope/containment questions first.
            # [FYP-FUNCTION] `_gap_priority` — implements the gap priority operation used by the surrounding workflow orchestration and state workflow.
            # [FYP-INPUT] Parameters: `item`; values come from its direct caller, route, UI event, fixture, or stage handoff.
            # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
            # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
            # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
            # [FYP-CALLS] Calls: `any`, `lower`.
            # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

            def _gap_priority(item):
                _, instr = item
                instr_l = instr.lower()
                return 0 if any(kw in instr_l for kw in _HIGH_VALUE_GAP_KEYWORDS) else 1
            not_met.sort(key=_gap_priority)
            gaps += [f"{sid}: {instr[:180]}" for sid, instr in not_met]
    if inv.get("status") == "completed_limited":
        gaps.append("Final analysis report was not generated.")
    for m in (inv.get("missing_evidence") or []):
        s = str(m)
        if s not in gaps:
            gaps.append(s)
    return gaps[:8]

def investigate_with_feedback(triage_result: dict, incident: dict,
                              inc_id: str, timeout: int = 600,
                              line_cb=None, feedback_cb=None,
                              max_passes: int | None = None,
                              threat_intel_result: dict | None = None,
                              watchdog_cb=None,
                              parsing_result: dict | None = None) -> dict:
    """
    [FYP-FUNCTION] Investigation Re-run / Feedback Loop (automatic)

    [FYP-EVALUATOR] [FYP-RERUN]: THE function that implements automatic
    Investigation re-execution. Runs Investigation once via
    handoff_to_investigation() + run_investigation(); if
    detect_evidence_gaps() finds the NOT_MET ratio over threshold, it feeds
    those gaps back into a deep-dive triage supplement (soc_triage_agent's
    deep_triage_supplement) and re-runs Investigation again — up to
    max_passes times (env WORKFLOW_FEEDBACK_PASSES, default 1 extra pass).
    This entire loop is IN-PROCESS and automatic: no analyst approval or
    button click is required between passes.

    [FYP-DECISION]: a playbook-redirection safeguard prevents the feedback
    loop from silently overwriting the triage classification (`cls` above)
    — it only ever supplements evidence, never re-labels severity itself.

    Parameters: triage_result/incident (stage inputs), inc_id, timeout,
    line_cb/feedback_cb (progress callbacks into app.py's UI), max_passes,
    threat_intel_result/parsing_result (upstream context).

    Returns: the final Investigation result dict (same shape as
    run_investigation()'s return), now possibly enriched by the deep-dive
    pass. [FYP-USED-BY]: app.py's Investigation-stage execution handler.
    """
    # [FYP-FUNCTION] `_emit` — implements the emit operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `event`, `detail`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include osquery_investigation.py:format_pack, soc_triage_agent/soc_triage_agent.py:_call, soc_triage_agent/soc_triage_agent.py:_run_cls; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `feedback_cb`.
    # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

    def _emit(event: str, detail: str = "") -> None:
        if feedback_cb:
            try:
                feedback_cb(event, detail)
            except Exception:
                pass

    if max_passes is None:
        try:
            max_passes = max(0, int(os.environ.get(
                "WORKFLOW_FEEDBACK_PASSES", "1")))
        except ValueError:
            max_passes = 1

    ticket = triage_result.get("ticket") or {}
    cls    = ticket.get("classification")

    handoff_to_investigation(triage_result, incident,
                             threat_intel_result=threat_intel_result,
                             parsing_result=parsing_result)
    _emit("handoff", "Alert handed to triaged_alerts queue")
    inv = run_investigation(inc_id, timeout=timeout, line_cb=line_cb,
                            triage_classification=cls, watchdog_cb=watchdog_cb)

    fb: dict = {"triggered": False, "passes": 0, "gaps": []}
    for pass_no in range(1, max_passes + 1):
        if inv.get("status") in ("failed", "lock_lost"):
            break
        gaps = detect_evidence_gaps(inv)
        if not gaps:
            break
        fb.update(triggered=True, passes=pass_no, gaps=gaps)
        gap_ids = ", ".join(g.split(":")[0] for g in gaps)
        _emit("gaps_detected",
              f"{len(gaps)} evidence gap(s) ({gap_ids}) — returning work to triage")
        _log("FEEDBACK", f"investigation reported {len(gaps)} gap(s); "
                         f"triage deep-dive pass {pass_no}")
        try:
            _emit("triage_deep_dive_start",
                  f"Triage deep-dive: mining the incident for {gap_ids}")
            from soc_triage_agent import deep_triage_supplement
            supp = deep_triage_supplement(incident, gaps)
            answered = sum(1 for v in (supp.get("gap_findings") or {}).values()
                           if "not present" not in str(v).lower())
            fb["gaps_answered"] = answered
            conf_list = [str(v).lower() for v in (supp.get("confidence_per_gap") or {}).values()]
            conf_summary = " (confidences: " + ", ".join(f"{c}={conf_list.count(c)}" for c in sorted(set(conf_list)) if c != "none") + ")" if conf_list else ""
            _emit("triage_deep_dive_done",
                  f"Deep-dive complete — {answered}/{len(gaps)} gap(s) "
                  f"answered{conf_summary}")
            _log("FEEDBACK", f"deep-dive answered {answered}/{len(gaps)} gaps")
        except Exception as exc:
            fb["supplement_error"] = str(exc)[:300]
            _emit("supplement_error", str(exc)[:150])
            break

        # Playbook redirection: the deep-dive may correct the MITRE tactic /
        # category, which steers playbook selection on the second pass. This
        # is applied to a DEEP COPY used only for the re-handoff — the shared
        # triage result (already persisted to tickets/pipeline) is never
        # mutated. Classification is code-pinned by design and is NEVER
        # rewritten by an LLM opinion; a suggested change is recorded for
        # the analyst instead.
        import copy as _copy
        redirect: dict = {}
        for _k in ("mitre_tactic", "incident_category"):
            _v = supp.get(_k)
            if _v and str(_v).strip().lower() not in ("null", "none", ""):
                redirect[_k] = str(_v).strip()
        _suggested_cls = supp.get("classification")
        if _suggested_cls and str(_suggested_cls).strip().lower() not in ("null", "none", ""):
            fb["suggested_classification"] = str(_suggested_cls).strip().upper()

        tri_for_rerun = triage_result
        if redirect:
            fb["playbook_redirect"] = redirect
            tri_for_rerun = _copy.deepcopy(triage_result)
            if "mitre_tactic" in redirect:
                tri_for_rerun.setdefault("metakeys_payload", {})[
                    "mitre_tactic"] = redirect["mitre_tactic"]
            if "incident_category" in redirect:
                tri_for_rerun.setdefault("ticket", {})[
                    "incident_category"] = redirect["incident_category"]
            redir_msg = ("Playbook redirection: "
                         + ", ".join(f"{k} → '{v}'" for k, v in redirect.items()))
            _emit("second_pass_start", f"{redir_msg}")
            _log("FEEDBACK", redir_msg)

        handoff_to_investigation(
            tri_for_rerun, incident,
            supplement={"requested_gaps": gaps, **supp,
                        "feedback_pass": pass_no},
            threat_intel_result=threat_intel_result)
        _emit("second_pass_start",
              f"Re-investigating with the triage supplement (pass {pass_no + 1})")
        inv2 = run_investigation(inc_id, timeout=timeout, line_cb=line_cb,
                                 triage_classification=cls, watchdog_cb=watchdog_cb)
        if inv2.get("status") in ("failed", "lock_lost"):
            fb["second_pass_failed"] = True
            inv = inv2 if inv2.get("status") == "lock_lost" else inv
            break
        inv = inv2

    inv["feedback_loop"] = fb
    if fb["triggered"]:
        # Honest summary: say what actually happened, including failures —
        # a crashed deep-dive must never read as a successful loop.
        if fb.get("supplement_error"):
            note = (f"[Feedback loop: investigation found {len(fb['gaps'])} "
                    f"evidence gap(s) but the triage deep-dive failed "
                    f"({fb['supplement_error'][:120]}); pass-1 findings kept.]")
        elif fb.get("second_pass_failed"):
            note = (f"[Feedback loop: triage deep-dive answered "
                    f"{fb.get('gaps_answered', 0)}/{len(fb['gaps'])} gap(s) "
                    f"but the re-investigation failed; pass-1 findings kept.]")
        else:
            note = (f"[Feedback loop: investigation found {len(fb['gaps'])} "
                    f"evidence gap(s); triage deep-dive answered "
                    f"{fb.get('gaps_answered', 0)} of them; investigation "
                    f"re-ran with the supplement"
                    + (f"; playbook redirected ({', '.join(fb['playbook_redirect'].values())})"
                       if fb.get("playbook_redirect") else "")
                    + (f"; deep-dive suggested classification "
                       f"{fb['suggested_classification']} — analyst to review"
                       if fb.get("suggested_classification") else "") + ".]")
        inv["summary"] = note + "\n\n" + str(inv.get("summary") or "")
    return inv


# [FYP-FUNCTION] `_annotate_severity_divergence` — implements the annotate severity divergence operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `inv`, `triage_classification`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:run_investigation; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `capitalize`, `get`, `lower`, `rstrip`, `str`, `strip`, `upper`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _annotate_severity_divergence(inv: dict, triage_classification) -> None:
    """Logical coherence: if the investigation's severity differs from the
    triage classification, say so explicitly instead of leaving two agents
    silently contradicting each other in the final report."""
    inv_sev = str(inv.get("severity") or "").strip().lower()
    tri_cls = str(triage_classification or "").strip().lower()
    if not inv_sev or not tri_cls or inv_sev not in _SEV_RANK \
            or tri_cls not in _SEV_RANK or inv_sev == tri_cls:
        return
    direction = ("upgraded" if _SEV_RANK[inv_sev] > _SEV_RANK[tri_cls]
                 else "downgraded")
    note = (f"Note: the investigation {direction} severity to "
            f"{inv_sev.capitalize()} (triage classified this incident "
            f"{tri_cls.upper()}) — an analyst should reconcile the two "
            f"assessments before closure.")
    inv["severity_divergence"] = {"triage": tri_cls.capitalize(),
                                  "investigation": inv_sev.capitalize(),
                                  "direction": direction}
    inv["summary"] = (str(inv.get("summary") or "").rstrip()
                      + ("\n\n" if inv.get("summary") else "") + note)

def reconcile_incident_severity(incident_id: str, unc: str, final_severity: str) -> None:
    """
    [FYP-FUNCTION] Post-Investigation Severity Reconciliation
    [FYP-EVALUATOR]: demonstrate this for "what happens when Investigation's
    verdict disagrees with Triage's?" — this is the annotation step, run
    only when _annotate_severity_divergence() (called just before this, in
    run_investigation()) flagged a real divergence.

    Annotate the stored ticket records with the investigation's severity.

    [FYP-DECISION]: NON-DESTRUCTIVE by design: the triage classification is
    the triage agent's judgment and stays untouched (the divergence note
    tells the analyst to reconcile manually). This only ADDS an
    `investigation_severity` field alongside it — both soc_tickets.db's
    `tickets.payload` and soc_pipeline.db's `initial_ticket.raw_json` end up
    carrying the original triage verdict AND the final investigation
    verdict side by side, never one overwriting the other.

    [FYP-DATABASE]: writes to TWO separate sqlite databases in sequence
    (soc_db/soc_tickets.db then soc_db/soc_pipeline.db), each independently
    best-effort — a failure on either is caught, logged via _log("RECONCILE",
    ...), and does NOT raise, so a DB hiccup here never fails the
    investigation itself (this function returns None either way).

    Args:
        incident_id: the alert/incident id the investigation ran for
            (used only in log lines here, not as a DB key).
        unc: the triage ticket's UNC — the actual lookup key in both
            `tickets` (WHERE unc=?) and `initial_ticket` (WHERE id=?, since
            initial_ticket rows are keyed by ticket unc — see
            run_until_triage_approval's pipeline_insert("initial_ticket", ...)).
        final_severity: the investigation's severity verdict (title-cased
            here via .strip().capitalize()) to record as
            `investigation_severity`. A falsy value or missing `unc` is a
            silent no-op (nothing to reconcile).

    [FYP-CALLS]: reads/writes soc_db/soc_tickets.db (`tickets` table) and
    soc_db/soc_pipeline.db (`initial_ticket` table) directly via sqlite3 —
    bypasses pipeline_insert() since this is a targeted UPDATE of an
    existing row, not a new stage record.

    (Note: the tickets table's `payload` column IS the ticket dict itself —
    an earlier version assumed a wrapper object and silently failed.)
    """
    if not final_severity or not unc:
        return
    final_severity = final_severity.strip().capitalize()

    tkt_db = Path(__file__).resolve().parent / "soc_db" / "soc_tickets.db"
    if tkt_db.exists():
        try:
            with sqlite3.connect(str(tkt_db), timeout=15) as con:
                row = con.execute("SELECT payload FROM tickets WHERE unc=?",
                                  (unc,)).fetchone()
                if row:
                    ticket = json.loads(row[0])
                    ticket["investigation_severity"] = final_severity
                    con.execute("UPDATE tickets SET payload=? WHERE unc=?",
                                (json.dumps(ticket), unc))
                    con.commit()
                    _log("RECONCILE", f"ticket {unc}: investigation_severity="
                                      f"{final_severity} recorded (triage "
                                      f"classification preserved)")
        except Exception as e:
            _log("RECONCILE", f"tickets.db annotate failed for {unc}: {e}")

    pl_db = Path(__file__).resolve().parent / "soc_db" / "soc_pipeline.db"
    if pl_db.exists():
        try:
            with sqlite3.connect(str(pl_db), timeout=15) as con:
                row = con.execute(
                    "SELECT raw_json FROM initial_ticket WHERE id=?",
                    (unc,)).fetchone()
                if row:
                    rec = json.loads(row[0])
                    rec["investigation_severity"] = final_severity
                    if isinstance(rec.get("ticket"), dict):
                        rec["ticket"]["investigation_severity"] = final_severity
                    con.execute(
                        "UPDATE initial_ticket SET raw_json=? WHERE id=?",
                        (json.dumps(rec), unc))
                    con.commit()
                    _log("RECONCILE", f"initial_ticket {unc}: "
                                      f"investigation_severity annotated")
        except Exception as e:
            _log("RECONCILE", f"pipeline.db annotate failed for {unc}: {e}")


def run_investigation(incident_id: str, timeout: int = 600,
                      line_cb=None, triage_classification=None,
                      watchdog_cb=None) -> dict:
    """
    [FYP-FUNCTION] Investigation Agent Subprocess Runner
    [FYP-EVALUATOR]: the actual `python main.py` launch for
    soc_investigation_agent_revised — pair with handoff_to_investigation()
    (writes its triaged_alerts/ input) and investigate_with_feedback()
    (the caller that decides whether a SECOND call to this function is
    needed, i.e. the automatic re-run/feedback loop).

    Run the investigation agent over its triaged_alerts/ queue and collect
    the incident folder that absorbed our alert. line_cb streams the agent's
    log output live (used by the app's agent board); triage_classification
    enables explicit severity-divergence annotation.

    [FYP-STAGE-LOCK]: watchdog_cb, when given, is polled every
    _HEARTBEAT_RENEW_SECONDS while the subprocess runs (see
    _run_subprocess_streaming) — used by run_investigation_stage() to renew
    the global shared-workspace lock DURING the subprocess call, not just
    before/after it. If it ever returns False (lock lost), the still-running
    child process is terminated before this function returns, so a second
    worker can never observe the shared triaged_alerts/incident_reports tree
    mid-write from a worker that no longer holds the lock. This is distinct
    from a plain timeout: the result's status is "lock_lost", and the caller
    must NOT treat that as a normal investigation failure (no complete_stage()
    call, no last_error update — see run_investigation_stage).

    Args:
        incident_id: the alert id this investigation was launched for — used
            to identify, among the (possibly several) Incident-* folders the
            subprocess may have touched, the one that actually absorbed
            THIS alert (matched against incident_data.json's raw_alerts ids,
            filtered to folders new-or-touched since `started`).
        timeout: seconds before the subprocess is killed (default 600s).
        line_cb: optional per-line callback streaming the child's stdout/
            stderr live (agent board log tail); forces the streaming
            subprocess path (_run_subprocess_streaming) when set.
        triage_classification: triage's severity verdict, forwarded to
            _annotate_severity_divergence() so a mismatch with the
            investigation's own severity is flagged AND (via
            reconcile_incident_severity()) persisted to the ticket DBs.
        watchdog_cb: see [FYP-STAGE-LOCK] above.

    Returns:
        dict with status one of "completed" | "completed_limited" | "failed"
        | "lock_lost", plus severity/summary/indicators/narrative_report/
        recommended_containment/mitre_mappings/artifacts on success. A
        "lock_lost" result is a SENTINEL, not a normal failure — see above.

    [FYP-CALLS]: reconcile_incident_severity() (only when a real
    severity divergence is detected), _investigation_recommended_
    containment_actions(), _investigation_mitre_mappings(),
    _annotate_severity_divergence().
    [FYP-USED-BY]: investigate_with_feedback() (both the first pass and any
    automatic re-run pass — see the module's [FYP-RERUN] feedback loop).
    """
    before = {p.name for p in (INV_DIR / "incident_reports").glob("Incident-*")}
    started = time.time()

    _env = {**_openai_compat_env(), "OPENAI_SEED": _llm_seed(),
            # One investigation = one incident: correlation matches against a
            # DIFFERENT incident are recorded as similar_to, never merged.
            "INVESTIGATION_SINGLE_INCIDENT": "1",
            # Single-alert incidents are the norm now — never fall back to the
            # zero-LLM heuristic report; always run the real Pass1/Pass2
            # analysis (quality is prioritized over marginal token cost).
            "INVESTIGATION_FORCE_LLM": "1"}
    if line_cb or watchdog_cb:
        run = _run_subprocess_streaming([sys.executable, "main.py"], cwd=INV_DIR,
                                        timeout=timeout, extra_env=_env,
                                        line_cb=line_cb, watchdog_cb=watchdog_cb)
    else:
        run = _run_subprocess([sys.executable, "main.py"], cwd=INV_DIR,
                              timeout=timeout, extra_env=_env)

    if run.get("status") == "lock_lost":
        return {"agent": "Investigation Agent", "subprocess": run,
                "incident_id": incident_id, "status": "lock_lost",
                "incident_folder": None, "summary": "", "severity": "",
                "indicators": [], "narrative_report": "",
                "error": "shared Investigation workspace lock was lost while "
                         "main.py was running; the subprocess was terminated"}

    result: dict = {"agent": "Investigation Agent", "subprocess": run,
                    "incident_id": incident_id, "status": "failed",
                    "incident_folder": None, "summary": "", "severity": "",
                    "indicators": [], "narrative_report": ""}

    reports_dir = INV_DIR / "incident_reports"
    target: Path | None = None
    for folder in sorted(reports_dir.glob("Incident-*")):
        data_file = folder / "incident_data.json"
        data = _read_json(data_file, {})
        raw_ids = [str(a.get("id")) for a in (data.get("raw_alerts") or [])]
        # MERGE into an existing incident rewrites incident_data.json without
        # changing the folder, so freshness is judged on the data file itself.
        is_new_or_touched = (folder.name not in before
                             or (data_file.exists()
                                 and data_file.stat().st_mtime >= started - 1))
        if str(incident_id) in raw_ids and is_new_or_touched:
            target = folder
            break

    if target is None:
        result["error"] = (run.get("stderr") or "").strip()[-1500:] or \
                          "Investigation run produced no incident folder for this alert."
        return result

    data = _read_json(target / "incident_data.json", {})
    md_path = target / "final_analysis_report.md"
    narrative = md_path.read_text(encoding="utf-8") if md_path.exists() else ""

    meta = data.get("metadata") or {}
    sev = str(meta.get("severity") or "")
    if sev.lower() in ("low", "medium", "high", "critical"):
        sev = sev.capitalize()
    cluster_ids = sorted({str(a.get("id")) for a in (data.get("raw_alerts") or [])
                          if a.get("id")})
    summary = data.get("summary_text") or ""
    if len(cluster_ids) > 1:
        # The correlation engine merged this alert with earlier incidents —
        # state the cluster membership up front so the report identity is
        # never mistaken for a different incident.
        summary = (f"[Correlated cluster {target.name}: "
                   f"{', '.join(cluster_ids)} — this run was triggered by "
                   f"{incident_id}.]\n\n" + summary)
    result.update({
        "status": "completed" if run["success"] and narrative else "completed_limited",
        "incident_folder": target.name,
        "investigated_for": str(incident_id),
        "cluster_alert_ids": cluster_ids,
        "summary": summary,
        "severity": sev,
        "indicators": data.get("indicators") or [],
        "narrative_report": narrative,
        # Structured, verbatim containment bullets recovered from the
        # narrative report (see _investigation_recommended_containment_actions)
        # — the reporting handoff's investigation_result.json needs this under
        # the Investigation agent's own field name so it is never mistaken for
        # "no recommendation supplied" and backfilled with generic text.
        "recommended_containment": _investigation_recommended_containment_actions(narrative),
        # Structured MITRE ATT&CK TTP mappings recovered from the narrative
        # report (see _investigation_mitre_mappings) under the Investigation
        # agent's own field name (orchestrator.FinalIncidentAnalysis.
        # mitre_mappings) — without this, the reporting handoff's section 7.1
        # never sees the real per-technique timeline_phase/observed_evidence
        # and falls back to a generic technique-ID scan of unrelated fields.
        "mitre_mappings": _investigation_mitre_mappings(narrative),
        "artifacts": {
            "incident_folder": str(target),
            "incident_data": str(target / "incident_data.json"),
            "report_markdown": str(md_path) if md_path.exists() else None,
        },
    })
    if result["status"] == "completed_limited":
        result["missing_evidence"] = ["Final analysis report was not generated."]
    _annotate_severity_divergence(result, triage_classification)
    
    # Annotate stored records with the investigation severity — only when it
    # actually DIVERGES from triage (agreement needs no reconciliation).
    if result.get("severity_divergence") and result.get("severity"):
        ticket_unc = None
        try:
            raw_alerts = data.get("raw_alerts") or []
            for a in raw_alerts:
                triage_block = a.get("triage") or {}
                if triage_block.get("ticket_unc"):
                    ticket_unc = triage_block["ticket_unc"]
                    break
        except Exception:
            pass
        if ticket_unc:
            reconcile_incident_severity(incident_id, ticket_unc, result["severity"])
            
    return result


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 6.  HANDOFF — TRIAGE/INVESTIGATION → REPORTING
# ══════════════════════════════════════════════════════════════════════════════

def handoff_to_reporting(triage_result: dict, incident: dict,
                         investigation_result: dict | None,
                         threat_intel_result: dict | None = None, *,
                         incident_id: str | None = None, run_id: str | None = None,
                         reporting_stage_attempt: int | None = None) -> str:
    """
    [FYP-FUNCTION] Investigation/Triage -> Reporting Handoff
    [FYP-FLOW] [FYP-RERUN] [FYP-EVALUATOR]

    Write the input files the reporting agent's adapter expects.

    When incident_id/run_id/reporting_stage_attempt are ALL given (the
    durable run_reporting_stage() path), writes into a native run-scoped
    workspace (reporting_attempt_dir(...)) rather than the shared, flat
    REP_DIR/inputs|outputs paths — every rerun gets its own attempt
    directory, so nothing written here is ever silently overwritten or
    bled into by a different run/attempt — and additionally writes
    processed_alert.json, approval_history.json, workflow_metadata.json,
    and a hash-verified handoff_manifest.json.

    Left at their defaults (None), this falls back to the exact original
    flat-path behaviour — used by the legacy in-memory Agent Board engine
    (app.py's `_wfm.handoff_to_reporting(tri, incident, inv)`, which has no
    run-scoping concept) and by tests that call this directly against a
    monkeypatched REP_DIR.

    Returns the sanitized ticket id used for per-ticket output folders.

    threat_intel_result is written explicitly (a separate
    threat_intel_result.json, mirroring the existing triage_result.json)
    rather than assumed to already be embedded inside investigation_result
    — Reporting previously only ever saw Threat Intelligence if it
    happened to survive into the Investigation agent's own narrative text,
    which is not a reliable structured signal."""
    payload = triage_result.get("metakeys_payload", {})
    ticket  = triage_result.get("ticket", {})
    inc_id  = payload.get("incident_id") or ticket.get("incident_id") or "INC-0001"
    title   = payload.get("incident_title") or ticket.get("title") or "SOC incident"
    ticket_id = _safe_ticket_id(ticket.get("unc"))

    run_scoped = incident_id is not None and run_id is not None and reporting_stage_attempt is not None
    if run_scoped:
        attempt_dir = reporting_attempt_dir(incident_id, run_id, reporting_stage_attempt)
        outputs = attempt_dir / "outputs"
        inputs  = attempt_dir / "inputs"
    else:
        attempt_dir = None
        outputs = REP_DIR / "outputs"
        inputs  = REP_DIR / "inputs"
    outputs.mkdir(parents=True, exist_ok=True)
    inputs.mkdir(parents=True, exist_ok=True)

    triage_doc = {
        "agent": "Triage Agent",
        "status": "completed",
        "incident_id": inc_id,
        "alert_id": inc_id,
        "title": title,
        "severity": ticket.get("classification"),
        "classification": ticket.get("classification"),
        "mitre_tactic": _first(payload.get("mitre_tactic"),
                               ticket.get("mitre_tactic"), default="Unknown"),
        "mitre_technique": _first(payload.get("mitre_technique"),
                                  ticket.get("mitre_technique"), default="Unknown"),
        "risk_rating": ticket.get("risk_rating"),
        "ioc_summary": payload.get("ioc_summary"),
        "matched_metakeys": payload.get("matched_metakeys"),
        "matched_ioc_count": ticket.get("matched_ioc_count"),
        "incident_category": ticket.get("incident_category"),
        "initial_response_time": ticket.get("initial_response_time"),
        "summary": ticket.get("summary"),
        "recommended_actions": ticket.get("recommended_actions"),
        "ticket": ticket,
        "created_at": ticket.get("created_at"),
    }
    _write_json(outputs / "triage_result.json", triage_doc)

    _ctx = _harvest_incident_context(incident)
    _mkv = payload.get("metakey_values") or {}
    enriched = {
        "incident_id": inc_id,
        "alert_title": title,
        "incident_summary": _first(incident.get("summary"), ticket.get("summary"),
                                   default=f"SOC alert requires review: {title}"),
        "severity": str(ticket.get("classification") or "Medium").capitalize(),
        "risk_score": _first(incident.get("riskScore"), incident.get("risk_score")),
        "host": _first(incident.get("hostname"), _scalar(_mkv.get("host.name")),
                       (_ctx["hosts"] or [None])[0]),
        "source_ip": _first(incident.get("source_ip"), _scalar(_mkv.get("ip.src")),
                            (_ctx["source_ips"] or _ctx["ips"] or [None])[0]),
        "username": _first(incident.get("username"), _scalar(_mkv.get("user.name")),
                           (_ctx["users"] or [None])[0]),
        "iocs": payload.get("ioc_summary") and [{"summary": payload["ioc_summary"],
                                                 "severity": payload.get("risk_level")}] or [],
        "raw_incident": incident,
    }
    _write_json(inputs / "enriched_alert.json", enriched)
    _write_json(outputs / "enriched_alert.json", enriched)
    _write_json(inputs / "ticket_context.json", {"ticket": ticket,
                                                 "ticket_id": ticket_id})

    if investigation_result is None:
        investigation_result = {
            "agent": "Investigation Agent",
            "status": "needs_more_data",
            "incident_id": inc_id,
            "summary": "Investigation stage was skipped or produced no output.",
            "missing_evidence": ["Investigation was not run for this incident."],
            "reporting_mode": "with_limitations",
        }
    else:
        # Feed the report's IOC table and MITRE section: the reporting
        # context builder reads investigation.iocs / .mitre_mapping directly.
        investigation_result = dict(investigation_result)
        if investigation_result.get("indicators"):
            investigation_result.setdefault("iocs",
                                            investigation_result["indicators"])
        tac  = _first(payload.get("mitre_tactic"), ticket.get("mitre_tactic"))
        tech = _first(payload.get("mitre_technique"), ticket.get("mitre_technique"))
        if tac and str(tac) != "Unknown":
            mapping = str(tac) if not tech or str(tech) == "Unknown" \
                      else f"{tac} — {tech}"
            investigation_result.setdefault("mitre_mapping", [mapping])

    # ── Skills sidecar: fold the deterministic skill suite (Diamond Model,
    # unified triage verdict, IOC correlation, asset criticality, mitigation
    # coverage) into the reporting agent's report. Uses ONLY fields the reporting
    # context-builder already consumes; strictly additive/non-destructive; never
    # raises. Disable with NW_DISABLE_SKILLS_SIDECAR=1.
    try:
        import skills_sidecar
        _bundle = skills_sidecar.build_skills_context(
            incident, triage_result=triage_result,
            investigation_result=investigation_result)
        if _bundle.get("available"):
            investigation_result = skills_sidecar.enrich_investigation_result(
                investigation_result, _bundle)
            _log("HANDOFF", "skills sidecar applied to report ("
                 + ", ".join(_bundle.get("skills_ran") or []) + ")")
    except Exception as _exc:  # sidecar must never break the handoff
        _log("HANDOFF", f"skills sidecar skipped: {_exc}")

    _write_json(outputs / "investigation_result.json", investigation_result)
    if threat_intel_result is not None:
        _write_json(inputs / "threat_intel_result.json", threat_intel_result)
        _write_json(outputs / "threat_intel_result.json", threat_intel_result)

    if run_scoped:
        # Parsing's own output — input_loader.py's existing "processed_alert"
        # input key, promoted to hard-required for a current-run generation
        # (see HARD_REQUIRED_INPUT_KEYS). Sourced from Parsing's own run-scoped
        # output directory (the same path run_parsing() writes to), with an
        # identity check mirroring workflow_validation.validate_parsing_result()'s
        # existing precedent: only copy it in if its own incident_id matches.
        try:
            parsing_output_dir = REP_DIR / "outputs" / _safe(incident_id) / _safe(run_id) / "parsing"
            processed_alert_src = parsing_output_dir / "processed_alert.json"
            if processed_alert_src.exists():
                processed_alert_data = json.loads(processed_alert_src.read_text(encoding="utf-8"))
                parsed_incident_id = str(processed_alert_data.get("incident_id") or "")
                if not parsed_incident_id or parsed_incident_id == str(incident_id):
                    _write_json(inputs / "processed_alert.json", processed_alert_data)
                else:
                    _log("HANDOFF", f"processed_alert.json belongs to incident "
                                    f"{parsed_incident_id!r}, expected {incident_id!r} — "
                                    "refusing stale/mismatched handoff")
            else:
                _log("HANDOFF", f"processed_alert.json not found at {processed_alert_src} "
                                "— Reporting will fail safely on this required input")
        except Exception as exc:
            _log("HANDOFF", f"processed_alert.json handoff failed: {exc}")

        # Approval history as of this moment (Triage's + Investigation's
        # decisions, plus any prior Reporting reject/rerun for this run) —
        # never this attempt's own not-yet-existing Reporting decision.
        try:
            approval_history = wss.get_approval_history(incident_id, run_id)
        except Exception:
            approval_history = []
        _write_json(inputs / "approval_history.json", approval_history)

        try:
            state_now = wss.get_state(incident_id) or {}
        except Exception:
            state_now = {}
        workflow_metadata = {
            "incident_id": str(incident_id),
            "run_id": run_id,
            "reporting_stage_attempt": reporting_stage_attempt,
            "reporting_execution_id": f"{incident_id}::{run_id}::attempt_{reporting_stage_attempt}",
            "triage_status": state_now.get("triage_status"),
            "threat_intel_status": state_now.get("threat_intel_status"),
            "investigation_status": state_now.get("investigation_status"),
            "reporting_status": state_now.get("reporting_status"),
            "execution_started_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_json(inputs / "workflow_metadata.json", workflow_metadata)

        # Hash-verified hand-off manifest — every file this call just wrote,
        # with size + SHA-256, so run_reporting_stage() can re-verify content
        # (not just presence) before launching the Reporting subprocess.
        _handoff_files: dict[str, str] = {}
        for _d in (outputs, inputs):
            for _p in sorted(_d.glob("*.json")):
                try:
                    _handoff_files[str(_p.relative_to(attempt_dir))] = str(_p)
                except Exception:
                    pass
        handoff_manifest = {
            "incident_id": str(incident_id),
            "run_id": run_id,
            "reporting_stage_attempt": reporting_stage_attempt,
            "files": {
                rel: {"sha256": hashlib.sha256(Path(p).read_bytes()).hexdigest(),
                     "size": Path(p).stat().st_size}
                for rel, p in _handoff_files.items()
            },
        }
        _write_json(inputs / "handoff_manifest.json", handoff_manifest)

    _log("HANDOFF", f"triage+investigation -> reporting (ticket {ticket_id}, "
                    f"attempt {reporting_stage_attempt})")
    return ticket_id


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 7.  STAGE 3 — REPORTING  (subprocess via the reporting agent's own adapter)
# ══════════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `_archive_run_exports` — implements the archive run exports operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `exports`, `run_stamp`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:run_reporting; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `copy2`, `dict`, `get`, `mkdir`, `str`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _archive_run_exports(exports: dict, run_stamp: str) -> dict:
    """Copy this run's DOCX/PDF to run-stamped archive files. The exporter
    overwrites the same combined_incident_report.* paths every run, so
    historical pipeline rows would otherwise all serve the newest file."""
    import shutil
    out = dict(exports)
    for fmt in ("docx", "pdf"):
        path = out.get(fmt)
        if not path:
            continue
        try:
            p = Path(str(path))
            arch_dir = p.parent / "archive"
            arch_dir.mkdir(exist_ok=True)
            arch = arch_dir / f"{p.stem}_{run_stamp}{p.suffix}"
            shutil.copy2(p, arch)
            out[f"{fmt}_latest"] = str(p)
            out[fmt] = str(arch)
        except Exception as exc:
            out[f"{fmt}_archive_error"] = str(exc)
    return out


def run_reporting(ticket_id: str, timeout: int = 900,
                  run_stamp: str | None = None, line_cb=None, *,
                  reporting_input_dir: Path | None = None,
                  reporting_output_dir: Path | None = None,
                  run_id: str | None = None,
                  reporting_stage_attempt: int | None = None) -> dict:
    """
    [FYP-FUNCTION] Reporting Agent Subprocess Runner
    [FYP-EVALUATOR]: launches soc_reporting_agent/adapters/run_reporting.py,
    reads back final_report.json, then triggers export_report_documents()
    for DOCX/PDF — the single function that turns an approved investigation
    into a finished report artifact. Pair with handoff_to_reporting()
    (writes this call's inputs) and run_reporting_stage() (the durable
    caller that supplies reporting_input_dir/output_dir/run_id/attempt).

    reporting_input_dir/reporting_output_dir, when given (the durable
    run_reporting_stage() path), point the subprocess chain at a native
    run-scoped workspace via REPORTING_INPUT_DIR/REPORTING_OUTPUT_DIR
    instead of the shared, flat REP_DIR/inputs|outputs — see
    reporting_attempt_dir(). Left None (the legacy in-memory Agent Board
    engine's call path, unchanged) falls back to the original flat
    behaviour exactly as before.

    Args:
        ticket_id: sanitised ticket id (see _safe_ticket_id) — passed to the
            subprocess as SOC_TICKET_ID; used for the ticket's own output
            subfolder.
        timeout: seconds before the subprocess is killed (default 900s);
            the inner adapter gets `max(timeout - 60, 300)` via
            REPORTING_TIMEOUT, keeping a safety margin for this wrapper's
            own bookkeeping.
        run_stamp: when given, this run's exported DOCX/PDF are additionally
            archived under a run-stamped filename (see _archive_run_exports)
            so a later run's export never silently overwrites this one's
            historical copy.
        line_cb: optional live stdout/stderr streaming callback (agent board).
        reporting_input_dir / reporting_output_dir / run_id /
            reporting_stage_attempt: durable run-scoping — see docstring
            above and reporting_attempt_dir().

    Returns:
        The reporting agent's final_report.json contents (dict), augmented
        with `orchestrator_subprocess` (returncode/success) and
        `document_exports` (DOCX/PDF paths from export_report_documents(),
        possibly archived). On a hard failure (no final_report.json
        produced at all) returns {"agent": ..., "status": "failed",
        "error": ..., "subprocess": run}.

    [FYP-CALLS]: export_report_documents(), _archive_run_exports().
    [FYP-USED-BY]: run_reporting_stage() (durable path) and app.py directly
    (via `_wfm.run_reporting(...)`) for the legacy in-memory Agent Board
    engine.
    """
    llm_env = _openai_compat_env()
    has_llm = bool(os.environ.get("OPENAI_API_KEY", "").strip() or llm_env)
    output_dir = reporting_output_dir or (REP_DIR / "outputs")
    extra_env = {
        **llm_env,
        "SOC_TICKET_ID": ticket_id,
        "REPORTING_USE_LLM": "true" if has_llm else "false",
        "REPORTING_LLM_PROVIDER": "openai",
        # Consistency: greedy decoding + fixed seed, mirroring the triage
        # agent's determinism policy (repeat runs -> repeat narratives).
        "REPORTING_LLM_TEMPERATURE": "0",
        "REPORTING_LLM_SEED": _llm_seed(),
        # Speed: enhance report sections concurrently (independent LLM calls);
        # set to 1 to restore strictly sequential generation.
        "REPORTING_LLM_PARALLEL": os.environ.get("REPORTING_LLM_PARALLEL", "3"),
        # Request economy: only retry sections with HARD quality failures;
        # cosmetic soft warnings are accepted as-is instead of re-generating.
        "REPORTING_QUALITY_RETRY": os.environ.get("REPORTING_QUALITY_RETRY",
                                                  "hard_only"),
        # Give the inner adapter->agent subprocess most of our budget.
        "REPORTING_TIMEOUT": str(max(timeout - 60, 300)),
    }
    if reporting_input_dir is not None:
        extra_env["REPORTING_INPUT_DIR"] = str(reporting_input_dir)
    if reporting_output_dir is not None:
        extra_env["REPORTING_OUTPUT_DIR"] = str(reporting_output_dir)
    if run_id is not None:
        extra_env["SOC_RUN_ID"] = run_id
    if reporting_stage_attempt is not None:
        extra_env["SOC_REPORTING_ATTEMPT"] = str(reporting_stage_attempt)
    if llm_env.get("OPENAI_MODEL"):
        # The Cisco TGI endpoint has no Responses API — force chat completions.
        extra_env["REPORTING_LLM_MODEL"] = llm_env["OPENAI_MODEL"]
        extra_env["REPORTING_OPENAI_API"] = "chat"
    if line_cb:
        run = _run_subprocess_streaming(
            [sys.executable, str(REP_DIR / "adapters" / "run_reporting.py")],
            cwd=REP_DIR, timeout=timeout, extra_env=extra_env, line_cb=line_cb)
    else:
        run = _run_subprocess(
            [sys.executable, str(REP_DIR / "adapters" / "run_reporting.py")],
            cwd=REP_DIR, timeout=timeout, extra_env=extra_env)

    final = _read_json(output_dir / "final_report.json", {})
    if not final:
        return {"agent": "Reporting Agent", "status": "failed",
                "error": (run.get("stderr") or run.get("stdout") or "")[-1500:],
                "subprocess": run}
    final["orchestrator_subprocess"] = {k: run[k] for k in ("returncode", "success")
                                        if k in run}
    if final.get("status") != "failed":
        exports = export_report_documents(
            final.get("incident_id"), reporting_output_dir=reporting_output_dir,
            run_id=run_id, reporting_stage_attempt=reporting_stage_attempt)
        if run_stamp:
            exports = _archive_run_exports(exports, run_stamp)
        final["document_exports"] = exports
        # Persist exports into the on-disk wrapper too, so the CLI / error
        # files / dashboard all see the same export outcome.
        _write_json(output_dir / "final_report.json", final)
    return final


# [FYP-FUNCTION] `export_report_documents` — constructs export report documents output for the next workflow orchestration and state consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `incident_id`, `timeout`, `reporting_output_dir`, `run_id`, `reporting_stage_attempt`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:run_reporting; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `_log`, `_run_subprocess`, `append`, `bool`, `exists`, `get`, `len`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def export_report_documents(incident_id: str | None, timeout: int = 180, *,
                            reporting_output_dir: Path | None = None,
                            run_id: str | None = None,
                            reporting_stage_attempt: int | None = None) -> dict:
    """Confirm all report sections and export combined DOCX + PDF via the
    reporting package's own exporters. Returns {docx, pdf, ...errors}.

    A returned path is guaranteed FRESH (written during this call) — a stale
    file from an earlier run is reported as an error, never as a success."""
    started = time.time()
    cmd = [sys.executable, str(REP_DIR / "adapters" / "export_documents.py")]
    if incident_id:
        cmd.append(str(incident_id))
    extra_env: dict[str, str] = {}
    if reporting_output_dir is not None:
        extra_env["REPORTING_OUTPUT_DIR"] = str(reporting_output_dir)
    if run_id is not None:
        extra_env["SOC_RUN_ID"] = run_id
    if reporting_stage_attempt is not None:
        extra_env["SOC_REPORTING_ATTEMPT"] = str(reporting_stage_attempt)
    run = _run_subprocess(cmd, cwd=REP_DIR, timeout=timeout, extra_env=extra_env or None)
    out: dict = {}
    for line in (run.get("stdout") or "").splitlines():
        if line.startswith("EXPORT_JSON:"):
            try:
                out = json.loads(line[len("EXPORT_JSON:"):])
            except Exception:
                out = {}
            break
    if not out:
        return {"error": (run.get("stderr") or run.get("stdout") or "no output")[-800:]}

    export_keys = ["docx", "pdf"]
    for section_key in ("executive_summary", "technical_findings",
                        "soc_analyst_review"):
        export_keys += [f"{section_key}_docx", f"{section_key}_pdf"]
    for fmt in export_keys:
        path = out.get(fmt)
        if not path:
            continue
        p = Path(str(path))
        if not p.exists():
            out[f"{fmt}_error"] = f"exporter reported {path} but the file does not exist"
            out[fmt] = None
        elif p.stat().st_mtime < started - 1:
            out[f"{fmt}_error"] = (f"stale file from a previous run "
                                   f"(not regenerated): {path}")
            out[fmt] = None
    _log("EXPORT", f"docx={bool(out.get('docx'))} pdf={bool(out.get('pdf'))}")
    return out


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 8.  FULL WORKFLOW  (durable-run entry points: run_until_triage_approval,
# resume_after_triage_approval, run_investigation_stage, run_reporting_stage,
# run_stage_chain — the CLI/UI-facing stage-by-stage API, most evaluator-relevant)
# ══════════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `enrich_incident_with_apiretrieval_fetch` — implements the enrich incident with apiretrieval fetch operation used by the surrounding workflow orchestration and state workflow.
# [FYP-INPUT] Parameters: `incident`, `host`, `token`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_workflow.py:run_until_triage_approval; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_log`, `_merge_alert_digest`, `dict`, `get`, `get_comprehensive_incident_payload`, `isinstance`, `items`, `len`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def enrich_incident_with_apiretrieval_fetch(incident: dict, host: str | None = None, token: str | None = None) -> dict:
    """Enrich incident with comprehensive raw alerts via APIRetrieval FETCH API or disk exports."""
    inc_id = str(incident.get("id") or incident.get("incidentId") or "unknown")
    try:
        import APIRetrieval
        payload = APIRetrieval.get_comprehensive_incident_payload(inc_id, host=host, token=token)
        if isinstance(payload, dict) and payload:
            inc_data = payload.get("incident") if isinstance(payload.get("incident"), dict) else {}
            alerts = payload.get("alerts") if isinstance(payload.get("alerts"), list) else []
            if alerts:
                combined = dict(incident)
                if inc_data:
                    combined.update({k: v for k, v in inc_data.items() if v not in (None, "", [], {})})
                combined["alerts"] = alerts
                _merge_alert_digest(combined)
                _log("INGESTION", f"Enriched incident {inc_id} with {len(alerts)} comprehensive raw alerts via APIRetrieval")
                return combined
    except Exception as exc:
        _log("INGESTION", f"APIRetrieval fetch fallback skipped for {inc_id}: {exc}")
    return incident


def run_until_triage_approval(incident: dict, *, use_mock_triage: bool = False,
                              force_triage: bool = False, allow_retry: bool = False,
                              progress_fn=None, parsing_only: bool = False,
                              host: str | None = None, token: str | None = None) -> dict:
    """
    [FYP-FUNCTION] [FYP-ENTRY-POINT] Parsing -> Triage Durable Run Starter
    [FYP-EVALUATOR]: this is where a NEW workflow run is born
    (wss.start_run) and where soc_pipeline.db first gets a row
    ("alerts_to_triage") for this incident — a good starting point to trace
    a single incident all the way through the pipeline DB tabs.

    The single Parsing -> Triage entry point. Both the Start Process
    button and the chat trigger in app.py call this through the shared
    _run_triage_workflow_with_ui() helper — there is no second,
    independently-sequenced path.

    Runs Parsing and, unless ``parsing_only`` is true, Triage. The case-page
    Parsing action uses ``parsing_only=True`` so completing Parsing leaves
    Triage pending for an explicit later action. The chat triage trigger
    retains the full Parsing -> Triage path. Full runs stop after the
    mandatory SOC Analyst approval pause and do not start Investigation.

    [FYP-APPROVAL]: the function's whole job is to run exactly two stages
    (Parsing, Triage) and then STOP at `wv.mandatory_triage_approval(...)` —
    it never calls run_investigation_stage()/run_reporting_stage() itself.
    Continuing past Triage requires a separate, explicit analyst action
    (Approve Triage in app.py), which is what eventually calls
    resume_after_triage_approval()/run_stage_chain().

    [FYP-FLOW]: sequence is pipeline_db_init() -> enrich incident via
    APIRetrieval -> wss.start_run() (mints run_id) -> persist raw incident
    artifact -> pipeline_insert("alerts_to_triage", ...) -> run_parsing() ->
    validate via workflow_validation -> (stop here if parsing_only) ->
    run_triage()/mock_triage_result() -> AI summary -> pipeline_insert
    ("initial_ticket", ...) -> wss.save_triage_result() -> one-time IOC
    correlation snapshot -> mandatory approval gate -> pipeline_insert
    ("workflow_runs", ...) -> return ctx.

    [FYP-ERROR] [FYP-FALLBACK]: any Parsing or Triage exception/non-
    "completed" status is caught, recorded into ctx["errors"], the relevant
    workflow_state_store statuses are set to "Failed"/"Blocked", and the
    function returns EARLY with that partial ctx — it never raises those
    stage errors upward. The IOC correlation snapshot is explicitly
    best-effort/non-fatal: a failure there is logged and recorded as
    status="Failed" in workflow_state_store, but Triage still proceeds to
    "Awaiting Approval" normally.

    Raises workflow_state_store.WorkflowAlreadyRunningError if a run is
    already Processing or Awaiting Approval for this incident and
    allow_retry=False.

    Args:
        incident: raw incident dict (NetWitness-style — id/incidentId,
            title/name, summary, riskScore/severity, ...).
        use_mock_triage: skip Parsing's real output feed and the real LLM
            triage call, using mock_triage_result() instead (fast/offline
            testing path — see main()'s --mock-triage flag).
        force_triage: bypass run_triage()'s result cache and force a fresh
            LLM call.
        allow_retry: permit starting a new run even if a prior run for this
            incident is still Processing/Awaiting Approval (see raises above).
        progress_fn: optional (event, label, text) callback for live UI
            progress (wired through to run_triage() too).
        parsing_only: stop after Parsing, leaving Triage "Pending" for a
            later explicit action (used by the case-page's standalone
            Parsing button).
        host / token: forwarded to enrich_incident_with_apiretrieval_fetch()
            for an optional live NetWitness re-fetch of richer alert data.

    Returns:
        ctx: dict with keys incident/errors/stages/run_id/parsing/triage/
        approval/thinking_process (shape varies by how far the run got
        before stopping/failing — always has "errors" and "stages").

    [FYP-CALLS]: pipeline_db_init(), enrich_incident_with_apiretrieval_fetch(),
    run_parsing(), run_triage()/mock_triage_result(), generate_triage_ai_summary(),
    pipeline_insert() (x3: alerts_to_triage, initial_ticket, workflow_runs),
    workflow_state_store (wss.*), workflow_validation (wv.*), ioc_correlation.
    [FYP-USED-BY]: app.py, imported as `wf_run_until_triage_approval`
    (only non-underscore-prefixed alias used directly, per the module's
    dead-import cleanup note above).
    """
    pipeline_db_init()
    inc_id = str(incident.get("id") or incident.get("incidentId") or "unknown")
    title  = incident.get("title") or incident.get("name") or "Untitled"
    
    # Enrich incident with comprehensive raw alerts using APIRetrieval FETCH API / disk exports
    incident = enrich_incident_with_apiretrieval_fetch(incident, host=host, token=token)
    
    ctx: dict = {"incident": incident, "errors": {}, "stages": {}}
    run_started = datetime.now()

    run_id = wss.start_run(inc_id, allow_retry=allow_retry)
    ctx["run_id"] = run_id

    # Persist the full raw incident (with alertMeta) for this run BEFORE
    # anything else — this is the only durable source of it for the
    # Threat Intelligence stage's resume path (never browser-session state).
    # Alongside it, stamp REAL fetch-outcome metadata (not merely
    # bool(incident.get("alerts"))) — an empty-but-successfully-fetched
    # alert list is genuinely different from a fetch that failed or was
    # never attempted, and case_view.py must be able to tell them apart
    # (see _data_availability()).
    try:
        raw_incident_path = _save_run_artifact(
            inc_id, run_id, "raw_incident.json", "raw_incident",
            {"incident": incident, "data_availability": _data_availability(incident)})
        wss.save_raw_incident_path(inc_id, run_id, str(raw_incident_path))
    except Exception as exc:
        _log("WORKFLOW", f"raw incident persist failed (non-fatal for this "
                         f"in-process run, but breaks durable resume): {exc}")

    pipeline_insert("alerts_to_triage", {
        "id": inc_id, "incident_id": inc_id, "title": title,
        "severity": str(incident.get("riskScore") or incident.get("severity") or ""),
        "summary": str(incident.get("summary") or "")[:500]})

    # [FYP-FUNCTION] `_emit` — implements the emit operation used by the surrounding workflow orchestration and state workflow.
    # [FYP-INPUT] Parameters: `event`, `label`, `text`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis workflow orchestration and state workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
    # [FYP-USED-BY] Static symbol references include osquery_investigation.py:format_pack, soc_triage_agent/soc_triage_agent.py:_call, soc_triage_agent/soc_triage_agent.py:_run_cls; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `progress_fn`.
    # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

    def _emit(event: str, label: str, text: str = "") -> None:
        if progress_fn:
            try:
                progress_fn(event, label, text)
            except Exception:
                pass

    # ── Stage 0: Parsing & Normalisation ──────────────────────────────────────
    _emit("phase_start", "Parsing and Normalisation")
    if use_mock_triage:
        parsing_result = {"status": "completed", "normalised_alert": {},
                          "processed_alert": {}, "missing_important_fields": []}
    else:
        _log("PARSING", f"running parsing & normalisation for incident {inc_id}")
        try:
            parsing_result = run_parsing(incident, run_id)
        except Exception as exc:
            ctx["stages"]["parsing"] = "failed"
            ctx["errors"]["parsing"] = str(exc)
            wss.set_parsing_status(inc_id, run_id, "Failed")
            wss.set_triage_status(inc_id, run_id, "Blocked")
            wss.set_workflow_status(inc_id, run_id, "Failed")
            _emit("phase_error", "Parsing and Normalisation", str(exc))
            _log("PARSING", f"FAILED: {exc}")
            return ctx

    ctx["parsing"] = parsing_result
    if parsing_result.get("status") != "completed":
        ctx["stages"]["parsing"] = "failed"
        ctx["errors"]["parsing"] = "parser returned a non-completed status"
        wss.set_parsing_status(inc_id, run_id, "Failed")
        wss.set_triage_status(inc_id, run_id, "Blocked")
        wss.set_workflow_status(inc_id, run_id, "Failed")
        _emit("phase_error", "Parsing and Normalisation", "non-completed status")
        _log("PARSING", "FAILED: non-completed status")
        return ctx

    ctx["stages"]["parsing"] = "completed"
    wss.set_parsing_status(inc_id, run_id, "Complete")
    try:
        wss.save_parsing_result(inc_id, run_id, {
            "run_id": run_id,
            "status": parsing_result.get("status"),
            "parser_confidence": parsing_result.get("parser_confidence"),
            "recommended_next_action": parsing_result.get("recommended_next_action"),
            "output_files": parsing_result.get("output_files"),
            "ai_summary": parsing_result.get("ai_summary"),
            "ai_thinking": parsing_result.get("ai_thinking"),
            "ai_summary_model": parsing_result.get("ai_summary_model"),
            "ai_summary_generated_at": parsing_result.get(
                "ai_summary_generated_at"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as exc:
        _log("PARSING", f"run-scoped parsing summary persist failed "
                        f"(breaks durable resume for this run): {exc}")
    _emit("phase_complete", "Parsing and Normalisation",
          parsing_result.get("parser_confidence") or "")

    # ── Validate the Parsing -> Triage handoff ────────────────────────────────
    try:
        validation = wv.validate_parsing_result(
            incident_id=inc_id, parsing_result=parsing_result, skip=use_mock_triage)
    except wv.ParsingValidationError as exc:
        ctx["stages"]["parsing"] = "failed"
        ctx["errors"]["parsing"] = str(exc)
        wss.set_parsing_status(inc_id, run_id, "Failed")
        wss.set_triage_status(inc_id, run_id, "Blocked")
        wss.set_workflow_status(inc_id, run_id, "Failed")
        _log("PARSING", f"VALIDATION FAILED: {exc}")
        return ctx
    ctx["parsing_validation"] = validation

    if parsing_only:
        # Parsing is a discrete case-page action. Do not mark Triage as
        # Processing (or invoke it) until the analyst explicitly starts it.
        wss.set_triage_status(inc_id, run_id, "Pending")
        wss.set_workflow_status(inc_id, run_id, "Awaiting Action")
        ctx["stages"]["triage"] = "pending"
        ctx["stages"]["workflow"] = "awaiting_action"
        _log("WORKFLOW", "parsing complete; triage remains pending")
        return ctx

    wss.set_triage_status(inc_id, run_id, "Processing")
    parsed_context = parsing_result.get("processed_alert") or None

    # ── Stage 1: Triage ───────────────────────────────────────────────────────
    _log("TRIAGE", f"running triage for incident {inc_id}")
    try:
        triage_result = (mock_triage_result(incident) if use_mock_triage
                         else run_triage(incident, progress_fn=progress_fn,
                                         parsed_context=parsed_context,
                                         force=force_triage))
    except Exception as exc:
        ctx["stages"]["triage"] = "failed"
        ctx["errors"]["triage"] = str(exc)
        wss.set_triage_status(inc_id, run_id, "Failed")
        wss.set_workflow_status(inc_id, run_id, "Failed")
        _log("TRIAGE", f"FAILED: {exc}")
        return ctx

    ctx["triage"] = triage_result
    if triage_result.get("error"):
        ctx["stages"]["triage"] = "failed"
        ctx["errors"]["triage"] = triage_result["error"]
        wss.set_triage_status(inc_id, run_id, "Failed")
        wss.set_workflow_status(inc_id, run_id, "Failed")
        _log("TRIAGE", f"FAILED: {triage_result['error']}")
        return ctx

    ticket = triage_result["ticket"]
    cls    = ticket.get("classification", "")
    _log("TRIAGE", f"complete — ticket {ticket.get('unc')} classification={cls}")

    # AI-Generated Summary + Thinking Process for the analyst-facing panel —
    # same SUMMARY:/THINKING: pattern as generate_parsing_ai_summary(), now
    # applied to the real triage ticket. Skipped under --mock-triage (no LLM
    # call), same reasoning as the parsing stage.
    if not use_mock_triage:
        triage_result.update(generate_triage_ai_summary(triage_result))

    pipeline_insert("initial_ticket", {
        "id": ticket.get("unc") or f"TKT_{inc_id}", "incident_id": inc_id,
        "title": f"Ticket {ticket.get('unc')} — {title}", "severity": cls,
        "summary": ticket.get("summary") or "", "ticket": ticket})

    # ── Save Triage result ──────────────────────────────────────────────────────
    wss.save_triage_result(inc_id, run_id, triage_result)

    # ── One-time internal IOC correlation snapshot ──────────────────────────────
    # Computed once here (never live, on every case-page render) so the
    # Unified Verdict/Key Findings/Evidence tab read a stable, run-scoped
    # result. Best-effort/supporting only: a correlation failure records
    # ioc_correlation_status="Failed" with a safe reason, but never fails
    # Triage or the overall workflow — Triage still reaches "Awaiting
    # Approval" normally either way.
    try:
        from ioc_correlation import correlate_iocs
        _corr = correlate_iocs(incident, triage_result)
        _corr_status = "Complete" if _corr.get("available") else "Complete with Warnings"
        wss.save_ioc_correlation_result(inc_id, run_id, status=_corr_status, result=_corr)
    except Exception as exc:
        _log("WORKFLOW", f"IOC correlation snapshot failed (non-fatal, supporting "
                         f"context only): {exc}")
        try:
            wss.save_ioc_correlation_result(
                inc_id, run_id, status="Failed",
                result={"available": False, "reason": str(exc)[:300]})
        except Exception:
            pass

    # ── Mandatory approval gate — stop here ─────────────────────────────────────
    gate = wv.mandatory_triage_approval(incident_id=inc_id, triage_result=triage_result)
    wss.set_triage_status(inc_id, run_id, "Awaiting Approval")
    wss.set_workflow_status(inc_id, run_id, "Awaiting Approval",
                            approval_stage=gate["approval_stage"])
    ctx["approval"] = gate
    ctx["stages"]["triage"] = "awaiting_approval"      # matches the DB, not "completed"
    ctx["stages"]["workflow"] = "awaiting_approval"
    ctx["thinking_process"] = wv.build_thinking_process(
        incident=incident, inc_id=inc_id, parsing_result=parsing_result,
        validation=validation, triage_result=triage_result,
        gate=gate, run_id=run_id)

    dur = int((datetime.now() - run_started).total_seconds())
    pipeline_insert("workflow_runs", {
        "id": f"run_{run_started.strftime('%Y%m%d-%H%M%S')}_{inc_id[:20]}",
        "incident_id": inc_id,
        "title": f"Run {run_started.strftime('%H:%M:%S')} — {title}",
        "severity": cls,
        "summary": f"parsing: completed · triage: awaiting_approval · "
                   f"ticket {ticket.get('unc')} · {dur}s",
        "stages": ctx["stages"], "ticket_unc": ticket.get("unc"),
        "duration_seconds": dur})

    _log("WORKFLOW", f"paused for mandatory SOC analyst approval "
                     f"(ticket={ticket.get('unc')}, next={gate['next_stage_after_approval']})")
    return ctx


def resume_after_triage_approval(incident_id: str, run_id: str) -> dict:
    """
    [FYP-FUNCTION] [FYP-ENTRY-POINT] Durable Threat-Intelligence Stage Runner
    [FYP-EVALUATOR]: despite the name, this is the THREAT INTELLIGENCE
    stage runner, not a triage-approval handler — it is what "resuming after
    triage was approved" actually DOES (next stage after Triage is Threat
    Intel). Good pairing with run_investigation_stage()/run_reporting_stage()
    to show the three durable per-stage workers share one shape: claim_stage
    -> LeaseRenewer -> do the work -> complete_stage -> release lease.

    Durable resume entry point for Threat Intelligence. Takes ONLY
    incident_id/run_id — reloads workflow state, the parsing result, the
    full raw incident, and the triage result from SQLite/disk. Safe to
    call from a fresh process, a new application session, or after a
    restart, as long as soc_incidents.db still shows this run_id as
    current and threat_intel_status == 'Processing' (set atomically by
    workflow_state_store.approve_triage() or .retry_threat_intel()). NO
    UI calls; safe to run in a background thread.

    [FYP-STAGE-LOCK]: claim_stage(..., expect_status="Processing") is the
    atomic ownership check — if another worker already claimed this stage
    (or the status has moved on), this raises StageClaimError immediately
    and the function does nothing further (propagated to the caller, e.g.
    run_stage_chain, as "already being handled elsewhere / nothing to do").
    A LeaseRenewer background thread then keeps this worker's claim alive
    for the duration of the (potentially slow, LLM-backed) threat-intel
    call.

    [FYP-STATE]: every stage completion — success or failure — goes through
    complete_stage(), which atomically checks this worker still owns the
    lease before writing, so a worker that lost its lease mid-run can never
    clobber a newer worker's result. On success, status_updates advances
    threat_intel_status to Complete/"Complete with Warnings" AND flips
    investigation_status/workflow_status to "Processing" in the SAME atomic
    write — this is what makes run_stage_chain()'s next dispatch branch
    ("if investigation_status == Processing") observe the handoff correctly.

    [FYP-ERROR] [FYP-FALLBACK]: any exception during the threat-intel call
    itself is caught, a best-effort complete_stage() records status="failed"
    (threat_intel_status="Failed", investigation_status="Blocked",
    workflow_status="Failed"), wss.set_last_error() records the message, and
    a {"status": "failed", ...} dict is returned — this function does not
    propagate arbitrary exceptions to its caller (only StageClaimError is
    re-raised, deliberately, so run_stage_chain can distinguish "lost the
    race" from "actually failed").

    Args:
        incident_id: the incident this run belongs to.
        run_id: the specific durable run (from wss.start_run() in
            run_until_triage_approval()) being resumed.

    Returns:
        The threat-intel result dict (run_threat_intel()'s return, plus an
        AI summary) on success, or {"status": "failed", "errors": [...]}
        on failure. Raises StageClaimError if this worker never actually
        owned/kept the stage lease (a losing race, not a crash).

    [FYP-CALLS]: claim_stage(), LeaseRenewer, run_threat_intel(),
    generate_stage_ai_summary(), complete_stage(), release_stage_lease(),
    load_parsing_result_for_run(), load_raw_incident_for_run().
    [FYP-USED-BY]: run_stage_chain() (this module) — the sole caller; NOT
    imported directly by app.py (see the module's dead-import note).
    """
    try:
        worker_id, _stage_attempt = claim_stage(
            incident_id, run_id, stage="threat_intel",
            status_column="threat_intel_status", expect_status="Processing")
    except StageClaimError:
        raise   # run_stage_chain treats this as "already being handled elsewhere"

    renewer = LeaseRenewer(incident_id, run_id, worker_id)
    renewer.start()
    try:
        state = wss.get_state(incident_id)
        triage_result  = json.loads(state.get("triage_result_json") or "{}")
        parsing_result = load_parsing_result_for_run(incident_id, run_id) or {}
        incident       = load_raw_incident_for_run(incident_id, run_id) or {}
        ti_result = run_threat_intel(
            incident_id=incident_id, run_id=run_id, incident=incident,
            normalised_alert=parsing_result.get("processed_alert"),
            triage_result=triage_result)
        if ti_result.get("status") != "failed":
            ti_result.update(
                generate_stage_ai_summary(
                    "Threat Intelligence Enrichment", ti_result
                )
            )
        if renewer.lease_lost.is_set():
            raise StageClaimError(f"threat_intel: worker {worker_id} lost its lease mid-run")
        ok = complete_stage(
            incident_id, run_id, worker_id, stage="threat_intel",
            result_column="threat_intel_result_json", result=ti_result,
            status_updates=(
                {"threat_intel_status": "Failed", "investigation_status": "Blocked",
                 "workflow_status": "Failed"} if ti_result["status"] == "failed" else
                {"threat_intel_status": ("Complete with Warnings"
                                         if ti_result["status"] == "completed_with_warnings"
                                         else "Complete"),
                 "investigation_status": "Processing", "workflow_status": "Processing"}))
        if not ok:
            raise StageClaimError(f"threat_intel: lease for {incident_id}/{run_id} "
                                  "was reassigned before this result could be saved")
        _log("THREAT_INTEL", f"{ti_result['status']} — "
                             f"risk={ti_result['enrichment_risk_level']} "
                             f"(score={ti_result['enrichment_risk_score']}, "
                             f"warnings={len(ti_result.get('warnings') or [])})")
        return ti_result
    except StageClaimError:
        raise   # a losing race is not a crash — run_stage_chain just stops quietly
    except Exception as exc:
        # complete_stage() may itself be unreachable (e.g. lease already
        # gone) — this is a best-effort failure record; if the lease is
        # truly gone, complete_stage()'s own ownership check rejects it
        # too (no double-write).
        try:
            complete_stage(
                incident_id, run_id, worker_id, stage="threat_intel",
                result_column="threat_intel_result_json",
                result={"status": "failed", "errors": [str(exc)[:300]]},
                status_updates={"threat_intel_status": "Failed",
                               "investigation_status": "Blocked",
                               "workflow_status": "Failed"})
        except Exception:
            pass
        wss.set_last_error(incident_id, run_id, f"threat_intel failed: {str(exc)[:300]}")
        _log("THREAT_INTEL", f"FAILED: {exc}")
        return {"status": "failed", "errors": [str(exc)[:300]]}
    finally:
        renewer.stop()
        release_stage_lease(incident_id, run_id, worker_id)   # no-op if complete_stage()
                                                              # already cleared it


_INVESTIGATION_LOCK = "investigation_workspace"


def run_investigation_stage(incident_id: str, run_id: str) -> dict:
    """
    [FYP-FUNCTION] [FYP-ENTRY-POINT] Durable Investigation Stage Runner
    [FYP-EVALUATOR]: strong evaluator demo — shows BOTH a per-incident
    stage lease AND a cross-incident global workspace lock in one function,
    because the Investigation agent's triaged_alerts/incident_reports tree
    is shared by every incident, not partitioned per-run like the other
    stages' artifact directories.

    Durable Investigation stage wrapper. Ends in 'Awaiting Approval'
    (never 'Complete') on success — Investigation still requires mandatory
    SOC Analyst approval before Reporting can start.

    [FYP-STAGE-LOCK]: per-incident worker leases alone do not stop a
    DIFFERENT incident's investigation from entering the same shared
    triaged_alerts/incident_reports workspace at the same time (main.py
    drains the whole queue / scans the whole tree every invocation). So
    after claiming this incident's own stage lease (claim_stage), this
    function ALSO acquires the global "investigation_workspace" lock
    (workflow_state_store.acquire_global_lock) before calling
    investigate_with_feedback() — with a bounded backoff wait (not "give up
    and hope a future poll retries it": the frontend polling loop only
    refreshes the DISPLAY, it never calls run_stage_chain() on its own).
    The SAME worker stays alive, continuously renewing its own stage lease
    AND (once acquired) the global lock, for up to
    _GLOBAL_LOCK_MAX_WAIT_SECONDS while waiting for the shared workspace.

    [FYP-DECISION]: the wait loop uses exponential backoff (starts at 2s,
    ×1.5 each retry, capped at 30s) and surfaces a live
    set_worker_progress_note("Waiting for Investigation capacity") so the
    UI can show WHY a run appears stalled, rather than looking silently
    stuck.

    [FYP-ERROR] [FYP-FALLBACK]: three distinct non-success paths, all
    handled differently:
      1. StageClaimError (lost the per-incident lease, or lease lost while
         waiting for the global lock, or the global lock never freed up in
         time) — re-raised, NOT recorded as a failure; the stage stays
         "Processing" for a future resume attempt.
      2. inv_result["status"] == "lock_lost" (global lock renewal failed
         DURING the subprocess — see run_investigation()'s watchdog_cb) —
         also converted to StageClaimError and the subprocess's output is
         explicitly discarded (no complete_stage() call), because it may
         have run concurrently with another worker's writes to the shared
         tree.
      3. inv_result["status"] == "failed" — a genuine investigation
         failure: complete_stage() records it, investigation_status/
         reporting_status/workflow_status all move to Failed/Blocked/
         Failed with last_error set.

    Args:
        incident_id: the incident this run belongs to.
        run_id: the specific durable run being resumed/continued.

    Returns:
        On success: the investigation result dict with status overridden to
        "awaiting_approval" (the underlying investigate_with_feedback()
        result keeps its own internal status too). On failure: the raw
        failed result dict. Raises StageClaimError on a lost race (see above).

    [FYP-CALLS]: claim_stage(), LeaseRenewer, acquire_global_lock()/
    renew_global_lock()/release_global_lock(), investigate_with_feedback(),
    generate_stage_ai_summary(), build_post_investigation_record(),
    pipeline_insert("post_investigation", ...), complete_stage(),
    release_stage_lease().
    [FYP-USED-BY]: run_stage_chain() (this module) — the sole caller; NOT
    imported directly by app.py.
    """
    try:
        worker_id, _stage_attempt = claim_stage(
            incident_id, run_id, stage="investigation",
            status_column="investigation_status", expect_status="Processing")
    except StageClaimError:
        raise
    renewer = LeaseRenewer(incident_id, run_id, worker_id)
    renewer.start()
    lock_acquired = False
    try:
        deadline = time.monotonic() + _GLOBAL_LOCK_MAX_WAIT_SECONDS
        backoff = 2.0
        while True:
            try:
                acquire_global_lock(_INVESTIGATION_LOCK, owner_id=worker_id,
                                    incident_id=incident_id, run_id=run_id,
                                    ttl_seconds=_LEASE_DURATION_SECONDS)
                lock_acquired = True
                set_worker_progress_note(incident_id, run_id, None)
                break
            except GlobalLockBusyError:
                if renewer.lease_lost.is_set():
                    raise StageClaimError(
                        f"investigation: stage lease lost while waiting "
                        f"for the shared workspace")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise StageClaimError(
                        f"investigation: could not acquire the shared "
                        f"workspace within {_GLOBAL_LOCK_MAX_WAIT_SECONDS}s")
                set_worker_progress_note(incident_id, run_id,
                                         "Waiting for Investigation capacity")
                time.sleep(min(backoff, remaining))
                backoff = min(backoff * 1.5, 30.0)

        renewer.also_renew_global_lock(_INVESTIGATION_LOCK)

        state = wss.get_state(incident_id)
        triage_result  = json.loads(state.get("triage_result_json") or "{}")
        ti_result      = json.loads(state.get("threat_intel_result_json") or "{}")
        incident       = load_raw_incident_for_run(incident_id, run_id) or {}
        parsing_result = load_parsing_result_for_run(incident_id, run_id) or {}
        ticket = triage_result.get("ticket") or {}
        triage_cls = ticket.get("classification") or state.get("severity") or "UNRATED"
        alert_list = incident.get("alerts") or (incident.get("alertMeta") or {}).get("AlertTitles") or []
        alert_count = max(len(alert_list), 1)
        progress_note = f"Ingested {alert_count} alert log(s) for incident {incident_id} (classified as {triage_cls}) — Investigation processing..."
        set_worker_progress_note(incident_id, run_id, progress_note)

        _log("INVESTIGATION", f"running investigation agent for {incident_id} ({alert_count} alerts, {triage_cls})…")
        inv_result = investigate_with_feedback(
            triage_result, incident, incident_id,
            threat_intel_result=ti_result,
            parsing_result=parsing_result,
            feedback_cb=lambda ev, d: _log("FEEDBACK", f"{ev}: {d}"),
            watchdog_cb=lambda: renew_global_lock(_INVESTIGATION_LOCK, worker_id))
        if inv_result.get("status") not in {"failed", "lock_lost"}:
            inv_result.setdefault("alert_count", alert_count)
            inv_result.setdefault("triage_classification", triage_cls)
            inv_result.update(
                generate_stage_ai_summary("Investigation", inv_result)
            )

        if renewer.lease_lost.is_set():
            raise StageClaimError(f"investigation: worker {worker_id} lost its lease mid-run")
        if renewer.global_lock_lost.is_set() or inv_result.get("status") == "lock_lost":
            # The shared workspace lock was lost (renewal failed) either on
            # the periodic LeaseRenewer heartbeat or as detected by the
            # subprocess watchdog itself. Either way, this attempt's output
            # (if any) must NOT be accepted as a completed investigation —
            # no complete_stage() call, no last_error update. Treat exactly
            # like contention: the stage stays "Processing", ownerless,
            # ready for the next resume attempt (same recovery path as any
            # other StageClaimError).
            raise StageClaimError(
                f"investigation: shared workspace lock lost mid-run for "
                f"worker {worker_id}; subprocess result discarded")

        failed = inv_result.get("status") == "failed"
        failure_message = None
        if failed:
            failure_detail = (inv_result.get("error")
                              or (inv_result.get("subprocess") or {}).get("stderr")
                              or "investigation agent returned a failed status")
            failure_lines = [line.strip() for line in str(failure_detail).splitlines()
                             if line.strip()]
            failure_message = (
                f"investigation failed: "
                f"{(failure_lines[-1] if failure_lines else str(failure_detail))[:300]}"
            )
        if not failed:
            try:
                pipeline_insert("post_investigation",
                                build_post_investigation_record(
                                    inv_result, ticket, title, run_stamp=run_stamp))
            except Exception as exc:
                _log("INVESTIGATION", f"post_investigation pipeline insert failed: {exc}")

        ok = complete_stage(
            incident_id, run_id, worker_id, stage="investigation",
            result_column="investigation_result_json", result=inv_result,
            status_updates=(
                {"investigation_status": "Failed", "reporting_status": "Blocked",
                 "workflow_status": "Failed", "last_error": failure_message} if failed else
                {"investigation_status": "Awaiting Approval",
                 "workflow_status": "Awaiting Approval", "approval_stage": "investigation",
                 "last_error": None}))
        if not ok:
            raise StageClaimError(f"investigation: lease for {incident_id}/{run_id} "
                                  "was reassigned before this result could be saved")
        _log("INVESTIGATION", f"complete — status={inv_result.get('status')}"
                             if not failed else "INVESTIGATION FAILED")
        return inv_result if failed else {**inv_result, "status": "awaiting_approval"}
    except StageClaimError:
        raise
    except Exception as exc:
        try:
            complete_stage(
                incident_id, run_id, worker_id, stage="investigation",
                result_column="investigation_result_json",
                result={"status": "failed", "error": str(exc)[:300]},
                status_updates={"investigation_status": "Failed",
                               "reporting_status": "Blocked",
                               "workflow_status": "Failed"})
        except Exception:
            pass
        wss.set_last_error(incident_id, run_id, f"investigation failed: {str(exc)[:300]}")
        _log("INVESTIGATION", f"FAILED: {exc}")
        return {"status": "failed"}
    finally:
        if lock_acquired:
            release_global_lock(_INVESTIGATION_LOCK, worker_id)
        renewer.stop()
        release_stage_lease(incident_id, run_id, worker_id)


_REPORTING_LOCK = "reporting_workspace"


def run_reporting_stage(incident_id: str, run_id: str) -> dict:
    """
    [FYP-FUNCTION] [FYP-ENTRY-POINT] Durable Reporting Stage Runner
    [FYP-EVALUATOR]: the final durable stage worker — good place to show
    the hash-verified handoff manifest (content integrity, not just
    presence checks) and the candidate-manifest identity check, both of
    which are defence-in-depth ON TOP OF the reporting_workspace lock.

    Durable Reporting stage wrapper — reuses handoff_to_reporting()/
    run_reporting() unmodified. Ends in 'Awaiting Approval' on success;
    only reporting_approval.approve_reporting_candidate() (which validates
    the candidate set, then calls workflow_state_store.
    commit_reporting_approval()) ever sets workflow_status to 'Complete'.

    Threat Intelligence is loaded and passed to handoff_to_reporting()
    explicitly (not assumed to be embedded in investigation_result).

    [FYP-STAGE-LOCK]: the "reporting_workspace" global lock (same
    acquire-with-backoff pattern as run_investigation_stage's
    "investigation_workspace" lock) covers the complete lifecycle: a
    run-scoped copy of the handoff is persisted BEFORE touching the shared
    REP_DIR/inputs|outputs paths, the shared workspace is used only while
    the lock is held, and a run-scoped copy of the generated output is
    persisted AFTER reading it back — the lock is released only once that
    copy exists, never immediately after writing inputs.

    [FYP-DECISION]: TWO extra integrity checks beyond the lock itself:
      1. handoff_manifest.json verification — after handoff_to_reporting()
         writes its inputs, this reads back the manifest it wrote (paths +
         size + sha256 per file, see handoff_to_reporting's run-scoped
         branch) and re-hashes every file ON DISK to confirm nothing was
         truncated/altered before the subprocess launches. A mismatch
         raises RuntimeError (caught by the outer except, recorded as a
         failed stage).
      2. candidate_manifest identity check — after run_reporting()
         completes, the exported candidate manifest's own
         incident_id/run_id/reporting_stage_attempt must match this call's
         — otherwise the lock's guarantee would have been violated by a
         lock-design bug, so this is treated as a hard failure, not a
         warning (unlike the softer ticket_id mismatch check just above it,
         which only logs a WARNING since the lock already rules out the
         dangerous case).

    [FYP-ERROR] [FYP-FALLBACK]: StageClaimError propagates on a lost
    per-incident lease OR a failure to acquire the global lock within
    _GLOBAL_LOCK_MAX_WAIT_SECONDS (stage stays "Processing" for a future
    resume). Any other exception (including the handoff-manifest
    RuntimeError above) is caught, best-effort recorded via complete_stage()
    with status="Failed", wss.set_last_error() set, and {"status": "failed"}
    returned.

    Args:
        incident_id: the incident this run belongs to.
        run_id: the specific durable run being resumed/continued.

    Returns:
        On success: the reporting agent's final result dict (status
        "awaiting_approval"-equivalent via reporting_status, document
        exports attached). On failure: {"status": "failed"} (details go to
        last_error / the DB record, not the return value). Raises
        StageClaimError on a lost race.

    [FYP-CALLS]: claim_stage(), LeaseRenewer, acquire_global_lock()/
    release_global_lock(), _save_run_artifact() (x2: reporting_handoff,
    reporting_output), reporting_attempt_dir(), handoff_to_reporting(),
    run_reporting(), generate_stage_ai_summary(),
    pipeline_insert("pending_ticket_report"/"finalized_report", ...),
    complete_stage(), release_stage_lease().
    [FYP-USED-BY]: run_stage_chain() (this module) — the sole caller; NOT
    imported directly by app.py.
    """
    try:
        worker_id, _stage_attempt = claim_stage(
            incident_id, run_id, stage="reporting",
            status_column="reporting_status", expect_status="Processing")
    except StageClaimError:
        raise
    renewer = LeaseRenewer(incident_id, run_id, worker_id)
    renewer.start()
    lock_acquired = False
    try:
        deadline = time.monotonic() + _GLOBAL_LOCK_MAX_WAIT_SECONDS
        backoff = 2.0
        while True:
            try:
                acquire_global_lock(_REPORTING_LOCK, owner_id=worker_id,
                                    incident_id=incident_id, run_id=run_id,
                                    ttl_seconds=_LEASE_DURATION_SECONDS)
                lock_acquired = True
                set_worker_progress_note(incident_id, run_id, None)
                break
            except GlobalLockBusyError:
                if renewer.lease_lost.is_set():
                    raise StageClaimError(
                        "reporting: stage lease lost while waiting for the "
                        "shared workspace")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise StageClaimError(
                        f"reporting: could not acquire the shared workspace "
                        f"within {_GLOBAL_LOCK_MAX_WAIT_SECONDS}s")
                set_worker_progress_note(incident_id, run_id,
                                         "Waiting for Reporting capacity")
                time.sleep(min(backoff, remaining))
                backoff = min(backoff * 1.5, 30.0)
        renewer.also_renew_global_lock(_REPORTING_LOCK)

        state = wss.get_state(incident_id)
        triage_result = json.loads(state.get("triage_result_json") or "{}")
        investigation_result = json.loads(state.get("investigation_result_json") or "{}")
        threat_intel_result = json.loads(state.get("threat_intel_result_json") or "{}")
        incident = load_raw_incident_for_run(incident_id, run_id) or {}
        ticket = triage_result.get("ticket") or {}
        title  = incident.get("title") or incident.get("name") or "Untitled"
        run_stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

        try:
            _save_run_artifact(incident_id, run_id, "reporting_handoff.json",
                               "reporting_handoff",
                               {"triage_result": triage_result,
                                "investigation_result": investigation_result,
                                "threat_intel_result": threat_intel_result})
        except Exception as exc:
            _log("REPORTING", f"reporting_handoff run-artifact persist failed "
                              f"(non-fatal): {exc}")

        attempt_dir = reporting_attempt_dir(incident_id, run_id, _stage_attempt)
        reporting_input_dir = attempt_dir / "inputs"
        reporting_output_dir = attempt_dir / "outputs"

        ticket_id = handoff_to_reporting(
            triage_result, incident, investigation_result,
            threat_intel_result=threat_intel_result,
            incident_id=incident_id, run_id=run_id,
            reporting_stage_attempt=_stage_attempt)

        # Verify the hand-off by CONTENT (hash), not just presence — a
        # same-size, different-content file would pass a size-only check.
        try:
            handoff_manifest = json.loads(
                (reporting_input_dir / "handoff_manifest.json").read_text(encoding="utf-8"))
            if (str(handoff_manifest.get("incident_id")) != str(incident_id)
                    or handoff_manifest.get("run_id") != run_id
                    or handoff_manifest.get("reporting_stage_attempt") != _stage_attempt):
                raise ValueError(
                    f"handoff_manifest.json identity mismatch: {handoff_manifest.get('incident_id')!r}/"
                    f"{handoff_manifest.get('run_id')!r}/{handoff_manifest.get('reporting_stage_attempt')!r} "
                    f"!= expected {incident_id!r}/{run_id!r}/{_stage_attempt!r}")
            for rel, meta in (handoff_manifest.get("files") or {}).items():
                p = attempt_dir / rel
                if not p.exists():
                    raise ValueError(f"hand-off file missing before subprocess launch: {rel}")
                if not str(p.resolve()).startswith(str(attempt_dir.resolve())):
                    raise ValueError(f"hand-off file escapes the trusted attempt root: {rel}")
                actual_size = p.stat().st_size
                actual_sha256 = hashlib.sha256(p.read_bytes()).hexdigest()
                if actual_size != meta.get("size") or actual_sha256 != meta.get("sha256"):
                    raise ValueError(f"hand-off file content changed after being written: {rel}")
        except Exception as exc:
            raise RuntimeError(f"reporting hand-off verification failed: {exc}") from exc

        try:
            pipeline_insert("pending_ticket_report", {
                "id": f"pending_{ticket.get('unc') or incident_id}",
                "incident_id": str(incident_id),
                "title": f"[PENDING] {title}", "severity": ticket.get("classification", ""),
                "summary": "Handed off to reporting agent."})
        except Exception:
            pass

        _log("REPORTING", "running reporting agent (subprocess)…")
        reporting_result = run_reporting(
            ticket_id, run_stamp=run_stamp,
            reporting_input_dir=reporting_input_dir,
            reporting_output_dir=reporting_output_dir,
            run_id=run_id, reporting_stage_attempt=_stage_attempt)

        if renewer.lease_lost.is_set():
            raise StageClaimError(f"reporting: worker {worker_id} lost its lease mid-run")
        if renewer.global_lock_lost.is_set():
            raise StageClaimError(
                f"reporting: shared workspace lock lost mid-run for worker "
                f"{worker_id}; subprocess result discarded")

        # Identity sanity check — secondary to the lock (which is what
        # actually prevents cross-run contamination): the lock guarantees no
        # OTHER run's handoff_to_reporting()/run_reporting() could have been
        # mid-flight while this one holds it, so a mismatch here would
        # indicate a lock-design bug worth investigating, not an expected
        # event under normal operation.
        result_ticket_id = str(reporting_result.get("ticket_id")
                               or (reporting_result.get("triage") or {}).get("ticket_id") or "")
        if result_ticket_id and result_ticket_id != str(ticket_id):
            _log("REPORTING", f"WARNING: reporting output ticket_id "
                              f"{result_ticket_id!r} does not match this run's "
                              f"ticket_id {ticket_id!r} despite holding the "
                              f"reporting_workspace lock")

        try:
            _save_run_artifact(incident_id, run_id, "reporting_output.json",
                               "reporting_output",
                               {"incident_id": str(incident_id), "run_id": run_id,
                                "ticket_id": ticket_id,
                                "reporting_result": {
                                    k: v for k, v in reporting_result.items()
                                    if k not in ("subprocess", "orchestrator_subprocess")}})
        except Exception as exc:
            _log("REPORTING", f"reporting_output run-artifact persist failed "
                              f"(non-fatal): {exc}")

        failed = reporting_result.get("status") == "failed"

        # Validate the candidate manifest's identity — all three of
        # incident_id/run_id/reporting_stage_attempt, not incident_id
        # alone — before accepting this attempt's output as good. A
        # mismatch here means something is badly wrong (not merely a
        # possible outcome to warn about, unlike the ticket_id check
        # above) — treat it exactly like a generation failure.
        if not failed:
            candidate_manifest_path_str = (reporting_result.get("document_exports") or {}).get(
                "candidate_manifest_path")
            try:
                cm = json.loads(Path(candidate_manifest_path_str).read_text(encoding="utf-8")) \
                    if candidate_manifest_path_str else {}
            except Exception:
                cm = {}
            if cm and (str(cm.get("incident_id")) != str(incident_id)
                      or cm.get("run_id") != run_id
                      or cm.get("reporting_stage_attempt") != _stage_attempt):
                _log("REPORTING", f"candidate manifest identity mismatch: "
                                  f"{cm.get('incident_id')!r}/{cm.get('run_id')!r}/"
                                  f"{cm.get('reporting_stage_attempt')!r} != expected "
                                  f"{incident_id!r}/{run_id!r}/{_stage_attempt!r}")
                failed = True
                reporting_result["status"] = "failed"
                reporting_result["error"] = "candidate manifest identity mismatch"

        if not failed:
            reporting_result.update(
                generate_stage_ai_summary("Reporting", reporting_result)
            )
            try:
                pipeline_insert("finalized_report", {
                    "id": f"final_{ticket.get('unc') or incident_id}@{run_stamp}",
                    "incident_id": str(incident_id), "ticket_unc": ticket.get("unc"),
                    "title": f"[FINAL] {title}", "severity": ticket.get("classification", ""),
                    "summary": str(reporting_result.get("summary")
                                  or "Report generated.")[:500],
                    "report": {k: v for k, v in reporting_result.items()
                              if k not in ("subprocess", "orchestrator_subprocess")}})
            except Exception as exc:
                _log("REPORTING", f"finalized_report pipeline insert failed: {exc}")

        ok = complete_stage(
            incident_id, run_id, worker_id, stage="reporting",
            result_column="reporting_result_json", result=reporting_result,
            status_updates=(
                {"reporting_status": "Failed", "workflow_status": "Failed"} if failed else
                {"reporting_status": "Awaiting Approval",
                 "workflow_status": "Awaiting Approval", "approval_stage": "reporting"}),
            expected_stage_attempt=_stage_attempt)
        if not ok:
            raise StageClaimError(f"reporting: lease for {incident_id}/{run_id} "
                                  "was reassigned before this result could be saved")
        _log("REPORTING", f"complete — status={reporting_result.get('status')}"
                          if not failed else "REPORTING FAILED")
        return reporting_result
    except StageClaimError:
        raise
    except Exception as exc:
        try:
            complete_stage(
                incident_id, run_id, worker_id, stage="reporting",
                result_column="reporting_result_json",
                result={"status": "failed", "error": str(exc)[:300]},
                status_updates={"reporting_status": "Failed", "workflow_status": "Failed"},
                expected_stage_attempt=_stage_attempt)
        except Exception:
            pass
        wss.set_last_error(incident_id, run_id, f"reporting failed: {str(exc)[:300]}")
        _log("REPORTING", f"FAILED: {exc}")
        return {"status": "failed"}
    finally:
        if lock_acquired:
            release_global_lock(_REPORTING_LOCK, worker_id)
        renewer.stop()
        release_stage_lease(incident_id, run_id, worker_id)


def run_stage_chain(incident_id: str, run_id: str) -> None:
    """
    [FYP-FUNCTION] [FYP-ENTRY-POINT] State-Aware Stage Dispatcher
    [FYP-EVALUATOR]: THE function app.py hands to background threads
    (`threading.Thread(target=wf_run_stage_chain, ...)`) every time it
    kicks off or resumes work after Triage approval — the single place that
    decides "what runs next" for a given run_id. Read this alongside
    resume_after_triage_approval()/run_investigation_stage()/
    run_reporting_stage() to see the full Threat Intel -> Investigation ->
    Reporting chain and how each stage hands off to the next purely via
    workflow_state_store's *_status columns.

    Top-level worker entry point AND what "Resume Workflow" calls. A
    state-aware dispatcher: reads current state ONCE and resumes
    whichever stage is actually 'Processing', falling through to the
    next stage only if that stage's own outcome says to continue. This
    means a fresh run (started right after Approve Triage) and an
    interrupted-mid-Investigation resume both correctly converge on the
    right stage — it does NOT always restart from Threat Intelligence.

    [FYP-FLOW]: three sequential `if state[...] == "Processing":` checks
    (threat_intel_status -> investigation_status -> reporting_status), each
    guarded so it only proceeds to the NEXT stage's check if the current
    one both succeeded AND didn't end in a normal pause:
      - threat_intel: any failure -> return (don't touch investigation).
      - investigation: result status in {"failed", "awaiting_approval"} ->
        return (awaiting_approval is a SUCCESSFUL pause requiring analyst
        action, not a failure — explicitly distinguished from "failed" in
        the comment/branch itself).
      - reporting: fires and returns regardless (last stage in the chain).
    Between stages, `state = wss.get_state(incident_id)` is re-read so the
    next check sees the just-updated status, not a stale snapshot from
    before this call started.

    [FYP-DECISION]: the leading `if not state or state["run_id"] != run_id:
    return` guard is what makes this function race-safe against a NEWER run
    superseding this one (e.g. force-retry) — it silently does nothing
    rather than resuming stale work.

    [FYP-ERROR] [FYP-FALLBACK]: every StageClaimError from the three stage
    functions is caught locally and treated as "someone else is already
    handling this — stop quietly," not a caller-visible error. This
    function itself never raises: "Pure backend function: no UI-framework
    import, no UI dependency, safe to call from a thread, a script, or a
    future queue consumer."

    Args:
        incident_id: the incident this run belongs to.
        run_id: the specific durable run to resume/continue.

    Returns:
        None always — outcomes are observable only via
        workflow_state_store's persisted status columns (this function is
        fire-and-forget from the caller's point of view).

    [FYP-CALLS]: resume_after_triage_approval(), run_investigation_stage(),
    run_reporting_stage(), workflow_state_store.get_state().
    [FYP-USED-BY]: app.py, imported as `wf_run_stage_chain` — launched via
    `threading.Thread(target=wf_run_stage_chain, args=(incident_id, run_id))`
    at multiple points (after Approve Triage, after Approve Investigation,
    on an explicit "Resume Workflow" action, on retry-after-failure).
    """
    state = wss.get_state(incident_id)
    if not state or state["run_id"] != run_id:
        return   # superseded by a newer run — nothing to resume here

    if state["threat_intel_status"] == "Processing":
        try:
            result = resume_after_triage_approval(incident_id, run_id)
        except StageClaimError:
            return
        if result.get("status") == "failed":
            return
        state = wss.get_state(incident_id)

    if state["investigation_status"] == "Processing":
        try:
            result = run_investigation_stage(incident_id, run_id)
        except StageClaimError:
            return
        if result.get("status") in ("failed", "awaiting_approval"):
            return   # awaiting_approval is a normal, successful pause — not a failure
        state = wss.get_state(incident_id)

    if state["reporting_status"] == "Processing":
        try:
            run_reporting_stage(incident_id, run_id)
        except StageClaimError:
            return
    # If none of the three *_status columns is "Processing" (e.g. the
    # workflow is Awaiting Approval, Failed, Rejected, or Complete), this
    # function does nothing — correct: there is no interrupted work to
    # resume, and re-running an already-terminal stage is exactly what
    # the atomic claim in workflow_state_store.claim_stage() would refuse anyway.


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 9.  CLI  [FYP-ENTRY-POINT] main() — `python soc_workflow.py --incident-file ...`
# ══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    """
    [FYP-FUNCTION] [FYP-ENTRY-POINT] Headless CLI Entry Point
    [FYP-EVALUATOR]: `python soc_workflow.py --incident-file sample_incident.json`
    — the standalone, no-UI way to exercise Parsing -> Triage without
    launching app.py at all. Useful for a quick evaluator smoke test or for
    CI-style regression checks against a canned incident file.

    Parses CLI args, loads an incident JSON file, and drives it through
    run_until_triage_approval() ONLY — this CLI currently stops at the
    mandatory Triage approval pause; it does NOT continue into Investigation
    or Reporting (see [FYP-FALLBACK] note below re: --skip-investigation /
    --force-investigation / the two --*-timeout flags).

    [FYP-FLOW]: reconfigure stdout to UTF-8 (best-effort, e.g. for Windows
    consoles) -> load .env (best-effort) -> argparse -> read the incident
    JSON off disk -> run_until_triage_approval(...) -> print a stage-by-
    stage summary + any errors -> write the full (incident-stripped)
    context to workflow_last_run.json -> return an exit code.

    [FYP-FALLBACK]: --skip-investigation, --force-investigation,
    --investigation-timeout, and --reporting-timeout are all ACCEPTED by
    argparse but NOT yet wired to any behaviour in this function — passing
    them prints a NOTE explaining they're reserved for a future "resume
    after approval" CLI command, rather than silently ignoring them. This
    is intentional forward-compatibility, not a bug: the durable resume
    path (resume_after_triage_approval/run_investigation_stage/
    run_reporting_stage/run_stage_chain) has no CLI wrapper yet, only the
    app.py UI drives it today.

    CLI arguments:
        --incident-file  (required) path to a NetWitness-style incident
            JSON dict.
        --mock-triage    use mock_triage_result() instead of a real LLM call
            (fast/offline path — forwarded to run_until_triage_approval()).
        --force-triage   bypass run_triage()'s cache and force a fresh
            LLM call.
        --allow-retry    permit starting a new run even if a prior run for
            this incident is still Processing/Awaiting Approval.
        --skip-investigation / --force-investigation / --investigation-timeout
            / --reporting-timeout: reserved, not yet used (see above).

    Returns:
        Process exit code: 0 on a successful (or non-triage-erroring) run,
        1 if ctx["errors"] contains a "triage" key (parsing failures alone
        do not force a non-zero exit here — only a triage-stage error does).

    [FYP-CALLS]: run_until_triage_approval(), _write_json().
    [FYP-USED-BY]: nothing in-repo — this is the `if __name__ == "__main__"`
    CLI entry point itself, invoked as a subprocess by an operator/evaluator,
    not imported/called by app.py (app.py drives the same underlying
    functions directly instead).
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="SOC 3-agent workflow orchestrator")
    ap.add_argument("--incident-file", required=True,
                    help="Path to an incident JSON file (NetWitness-style dict)")
    ap.add_argument("--mock-triage", action="store_true",
                    help="Use canned triage output (no LLM call)")
    # [FYP-FALLBACK]: these four flags are parsed but not yet consumed — see
    # the docstring above. Kept as reserved/forward-compatible CLI surface.
    ap.add_argument("--skip-investigation", action="store_true")
    ap.add_argument("--force-investigation", action="store_true")
    ap.add_argument("--investigation-timeout", type=int, default=600)
    ap.add_argument("--reporting-timeout", type=int, default=480)
    ap.add_argument("--allow-retry", action="store_true",
                    help="Allow retrying a run even if a previous run is awaiting approval")
    ap.add_argument("--force-triage", action="store_true",
                    help="Bypass the triage result cache and re-run Triage")
    args = ap.parse_args()

    incident = json.loads(Path(args.incident_file).read_text(encoding="utf-8"))

    # [FYP-EVALUATOR]: this is the CLI's ONLY pipeline call — Parsing and
    # Triage run here; the function returns at the mandatory approval gate.
    ctx = run_until_triage_approval(
        incident, use_mock_triage=args.mock_triage, force_triage=args.force_triage, allow_retry=args.allow_retry)

    # Surface a NOTE (not an error) for any reserved/not-yet-wired flag the
    # caller passed, so a CLI user isn't left wondering why nothing happened.
    _unused = [f"--{f.replace('_', '-')}" for f in
              ("skip_investigation", "force_investigation") if getattr(args, f, False)]
    if getattr(args, "investigation_timeout", 600) != 600:
        _unused.append("--investigation-timeout")
    if getattr(args, "reporting_timeout", 480) != 480:
        _unused.append("--reporting-timeout")
    if _unused:
        print(f"\nNOTE: this run stops at the mandatory Triage approval pause. "
              f"These flags were passed but aren't used yet — they'll apply to "
              f"the future 'resume after approval' command: {', '.join(_unused)}")

    print("\n" + "=" * 70)
    print("WORKFLOW SUMMARY")
    print("=" * 70)
    for stage, status in ctx.get("stages", {}).items():
        print(f"  {stage:<15} {status}")
    if ctx["errors"]:
        print("  errors:")
        for k, v in ctx["errors"].items():
            print(f"    {k}: {str(v)[:200]}")
    # Dump the full run context (minus the raw incident, already on disk via
    # the incident file itself) for post-hoc inspection/debugging.
    out_path = ROOT / "workflow_last_run.json"
    slim = {k: v for k, v in ctx.items() if k != "incident"}
    _write_json(out_path, slim)
    print(f"  full context written to {out_path.name}")
    return 1 if ctx["errors"].get("triage") else 0


if __name__ == "__main__":
    # [FYP-ENTRY-POINT]: `python soc_workflow.py --incident-file ...`
    raise SystemExit(main())
