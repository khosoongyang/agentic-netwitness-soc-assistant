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
#   1. Stage routing: run_stage_chain() executes whichever stage the
#      analyst explicitly started (status "Processing"), in the fixed order
#      Triage -> Threat Intel -> Investigation -> Reporting; there is no
#      classification-based skip. Each stage's completion only unlocks the
#      next one ("Pending"); it never starts it.
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
#   An incident dict (from demo/sample_incident.json / a fetched NetWitness
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
#   workflow/commands.py, via the durable stage-chain entry points
#   (run_until_triage_approval, resume_after_triage_approval,
#   run_investigation_stage, run_reporting_stage, run_stage_chain).
#   eval_harness.py calls build_investigation_alert for a regression test.
#   main() is a CLI-only entry point, not called by the Flask app.
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
#   detect_evidence_gaps, investigate_with_feedback,
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
  python soc_workflow.py --incident-file demo/sample_incident.json
  python soc_workflow.py --incident-file demo/sample_incident.json --mock-triage
  python soc_workflow.py --incident-file demo/sample_incident.json --skip-investigation
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

from workflow import state_store as wss
from workflow import validation as wv
from integrations.netwitness.alerts import _merge_alert_digest
# Phase 3 (canonical Investigation Result contract migration): the
# dependency-light Phase 1 contract module -- pydantic/typing only, does NOT
# import orchestrator.py or its heavy ChromaDB/LLM machinery -- used by
# run_investigation() to validate investigation_analysis.json (see Phase 2)
# before trusting it over the legacy Markdown-reconstruction path.
from agents.investigation.investigation_result import InvestigationAgentOutput
# Canonical audit Phase 5: the one Parsing case-identity resolver (stdlib-only
# module), shared by the producer, validate_parsing_result() and -- via
# workflow.parsing_canonical -- load_parsing_result_for_run().
from agents.parsing.parser_context_guard import CASE_IDENTITY_MATCH
from workflow.parsing_canonical import (
    PARSING_IDENTITY_MISMATCH, PARSING_IDENTITY_UNVERIFIED, evaluate_parsing_envelope,
)
# Canonical audit Phase 6: stage readiness (prerequisite evaluation only).
from workflow.readiness import StageNotReadyError, evaluate_stage_readiness, public_view

ROOT       = Path(__file__).resolve().parent.parent
# Swapped 2026-07-22: the team's revised investigation agent (adds
# policy_engine compliance auditing + richer report sections). Contract
# verified identical: main.py entry, triaged_alerts/ inbox, incident_reports/
# Incident-*/incident_data.json (raw_alerts/summary_text/metadata.severity/
# indicators) + final_analysis_report.md with the same `| step_x | … |
# MET/NOT_MET |` trace table the feedback loop parses. The previous agent
# remains on disk untouched — rollback = point this back.
INV_DIR    = ROOT / "agents" / "investigation"
REP_DIR    = ROOT / "agents" / "reporting"
SOC_DB_DIR = ROOT / "soc_db"
SOC_DB_DIR.mkdir(exist_ok=True)

PIPELINE_DB_FILE = SOC_DB_DIR / "soc_pipeline.db"


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


RAW_INCIDENT_MISSING = "missing_raw_incident"
RAW_INCIDENT_IDENTITY_MISMATCH = "raw_incident_identity_mismatch"
RAW_INCIDENT_RUN_MISMATCH = "raw_incident_run_mismatch"


def inspect_raw_incident_for_run(incident_id: str, run_id: str,
                                 state: dict | None = None) -> tuple[dict | None, str | None, str | None]:
    """[FYP-FUNCTION] [FYP-STATE] Read-only inspection of this run's persisted
    raw-incident artifact: (incident, None, None) when it is usable, else
    (None, reason_code, detail). Canonical audit Phase 6: a raw incident that
    belongs to another case or run is unusable evidence and is never handed
    to a stage. `state` may be passed by a caller that already holds the
    incidents row (workflow.readiness); otherwise it is read here."""
    if state is None:
        state = wss.get_state(incident_id)
    if not state or state.get("run_id") != run_id:
        return None, RAW_INCIDENT_RUN_MISMATCH, (
            f"run {run_id!r} is not the current workflow run for case {incident_id!r}")
    path = _resolve_trusted_path(state.get("raw_incident_path"))
    if not path:
        return None, RAW_INCIDENT_MISSING, f"no raw incident artifact is persisted for run {run_id!r}"
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None, RAW_INCIDENT_MISSING, "the persisted raw incident artifact is unreadable"
    if not isinstance(envelope, dict):
        return None, RAW_INCIDENT_MISSING, "the persisted raw incident artifact is malformed"
    if envelope.get("incident_id") != str(incident_id):
        return None, RAW_INCIDENT_IDENTITY_MISMATCH, (
            f"the raw incident artifact belongs to case {envelope.get('incident_id')!r}, "
            f"not {incident_id!r}")
    if envelope.get("run_id") != run_id:
        return None, RAW_INCIDENT_RUN_MISMATCH, (
            f"the raw incident artifact belongs to run {envelope.get('run_id')!r}, "
            f"not the current run {run_id!r}")
    payload = envelope.get("payload")
    if payload is None:
        return None, RAW_INCIDENT_MISSING, "the raw incident artifact has no payload"
    if isinstance(payload, dict) and "incident" in payload and "data_availability" in payload:
        incident = payload["incident"]
    else:
        incident = payload   # legacy artifact: the payload WAS the incident dict
    if isinstance(incident, dict):
        own_id = incident.get("id") or incident.get("incidentId")
        if own_id not in (None, "") and str(own_id) != str(incident_id):
            return None, RAW_INCIDENT_IDENTITY_MISMATCH, (
                f"the raw incident record is {str(own_id)!r}, not {incident_id!r}")
    return incident, None, None


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
    — both shapes are handled so old runs keep resolving. Canonical audit
    Phase 6: a record whose own id is another case is also refused (see
    inspect_raw_incident_for_run())."""
    incident, _code, _detail = inspect_raw_incident_for_run(incident_id, run_id)
    return incident


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
    """[FYP-FUNCTION] The canonical Parsing result for this case/run: the
    run-scoped parsing_result_json envelope saved by wss.save_parsing_result(),
    with its INLINE structured normalised_alert and flat processed_alert.

    Canonical audit Phase 5: disk files under output_files are derived
    exports and are never read back over the inline content (previously the
    structured normalised_alert was replaced here by parsed_incident.json,
    which held the flat processed_alert). Returns None — never a guess — when
    the summary's run_id doesn't match, or when its case identity, re-resolved
    from the inline content (resolve_case_identity()), is anything but a
    match for `incident_id` (mismatch or not_available).

    Canonical audit Phase 6: the rules live in workflow.parsing_canonical
    (evaluate_parsing_envelope), shared verbatim with workflow.readiness."""
    state = wss.get_state(incident_id)
    result, reason_code, detail = evaluate_parsing_envelope(state, incident_id, run_id)
    if reason_code in (PARSING_IDENTITY_MISMATCH, PARSING_IDENTITY_UNVERIFIED):
        _log("PARSING", f"parsing result for {incident_id!r} run {run_id!r} rejected: "
                        f"{reason_code} — {detail}")
    return result


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

from workflow.state_store import (
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
    from agents.triage import OpenAILLMConfig, TriageAgent
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

    [FYP-CALLS]: agents.parsing.parser_normaliser.
    run_parser_normalisation_for_dashboard(), generate_parsing_ai_summary().
    [FYP-USED-BY]: run_until_triage_approval() (this module) — the only
    caller (skipped entirely when use_mock_triage=True).
    """
    from agents.parsing import run_parser_normalisation_for_dashboard

    inc_id = str(incident.get("id") or incident.get("incidentId") or "unknown")
    output_dir = REP_DIR / "outputs" / _safe(inc_id) / _safe(run_id) / "parsing"
    # Canonical audit Phase 5: the workflow case is the expected identity —
    # the parser fails (not_available counts as a failure) unless its output
    # resolves to exactly this case.
    result = run_parser_normalisation_for_dashboard(
        incident, output_dir=output_dir, expected_case_id=inc_id)
    if result.get("status") == "completed":
        result.update(generate_parsing_ai_summary(result))
    return result


# ══════════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] 3.5  AI-SUMMARY / "THINKING" RENDERING HELPERS
# ══════════════════════════════════════════════════════════════════════════════
# Moved to workflow/stage_summaries.py (Phase 4 of the orchestration
# cleanup): _split_ai_summary_sections, limit_ai_summary_sentences,
# _stage_ai_summary_context, generate_stage_ai_summary,
# generate_parsing_ai_summary, render_triage_thinking_plain,
# _thinking_fragment,
# _investigation_recommended_containment_actions, _split_mitre_table_row,
# _investigation_mitre_mappings, _parse_progress_datetime,
# _format_progress_datetime, _format_elapsed, _render_stage_progress_plain,
# render_agent_thinking_plain, generate_triage_ai_summary. Imported below so
# every existing call site in this file -- and workflow.engine.<name> in
# tests -- keeps working unchanged.
from workflow.stage_summaries import (
    _split_ai_summary_sections,
    limit_ai_summary_sentences,
    _stage_ai_summary_context,
    generate_stage_ai_summary,
    generate_parsing_ai_summary,
    render_triage_thinking_plain,
    _thinking_fragment,
    _investigation_recommended_containment_actions,
    _split_mitre_table_row,
    _investigation_mitre_mappings,
    _parse_progress_datetime,
    _format_progress_datetime,
    _format_elapsed,
    _render_stage_progress_plain,
    render_agent_thinking_plain,
    generate_triage_ai_summary,
)




def mock_triage_result(incident: dict) -> dict:
    """
    [FYP-FUNCTION] [FYP-FALLBACK] Canned Triage Result (offline/LLM-less testing)

    Canned triage output with the same shape as TriageAgent.triage() —
    same top-level keys (mock/metakeys_payload/ticket/trace/error) so every
    downstream consumer (handoff_to_investigation(), handoff_to_reporting(),
    pipeline_insert(), the AI-summary/thinking renderers) can treat it
    identically to a real LLM-backed result. Fixed
    HIGH classification/#99999Z ticket id — deliberately obvious as mock
    data (never mistakeable for a real ticket).

    Used with --mock-triage to test the workflow without LLM access.

    [FYP-USED-BY]: run_until_triage_approval() (this module) — called
    instead of run_triage() only when use_mock_triage=True.

    Phase 1 (Canonical Triage Result contract migration) correction: this
    function's own docstring has always promised the exact shape of
    TriageAgent.triage()'s real success output, but it was missing
    metakeys_payload/ticket's mitre_tactic/mitre_technique (both always set
    on a real run, see soc_triage_agent.py:1421-1422,1442-1443) and the
    top-level used_parsed_context (always a bool on a real run,
    soc_triage_agent.py:1460). Added below so this mock validates against
    the same agents.triage.triage_result.TriageAgentSuccessOutput contract
    a real run does. No previously-relied-upon key was removed or renamed.
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
            "mitre_tactic": "Credential Access", "mitre_technique": "Brute Force",
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
            "mitre_tactic": "Credential Access", "mitre_technique": "Brute Force",
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
        "used_parsed_context": False,
        "error": None,
    }


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
    from agents.threat_intelligence import threat_intel

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


# [FYP-SECTION] Threat Intelligence Phase 5B — compact Investigation-facing
# TI projection.
# -----------------------------------------------------------------------------
# build_investigation_threat_intel_context() derives a small, bounded,
# deterministic narrative block from the canonical ThreatIntelResult, for
# embedding ahead of the generic (truncatable) Investigation narrative. This
# is NOT a second canonical TI contract -- ThreatIntelResult (agents/
# threat_intelligence/threat_intel_result.py) remains the sole Threat-
# Intelligence-owned canonical result; this is a derived, workflow/
# Investigation-facing projection of it, owned here because
# build_investigation_alert() (below) is already the workflow-side function
# that decides what of Threat Intelligence's output reaches Investigation.
#
# Only enrichment_risk_level/enrichment_risk_score/enrichment_risk_reasons
# are used. enrichment_risk_reasons is already Threat Intelligence's own
# deterministic, curated summary of provider evidence
# (threat_intel.py::calculate_enrichment_risk()) -- e.g. "VirusTotal
# reported 5 malicious detection(s) for IP 203.0.113.9.", "AbuseIPDB abuse
# confidence score is high for 203.0.113.9: 92." -- so no separate
# provider-findings list is layered on top of it; that would only repeat
# the same machine-curated facts in a second shape.
#
# Deliberately excluded (per the Threat Intelligence Phase 4 audit's trust-
# boundary and signal-value findings): AlienVault OTX related_pulses/pulse
# names, VirusTotal meaningful_name, ISP/registrar/WHOIS-style fields,
# harmless/undetected counts, submission/creation dates, sections_available,
# and any other raw provider metadata. None of these are read by
# calculate_enrichment_risk() or by any Investigation-adjacent consumer
# (diamond_model.py/triage_verdict.py/mitigation_mapping.py), some are
# externally-authored free text, and all of them belong to the full
# ThreatIntelResult (still embedded unchanged under
# threat_intelligence_enrichment on the queued alert, and still fully
# available to the deterministic Reporting-side skills sidecar) -- this
# projection is for LLM-facing prioritization only, not a replacement for
# the canonical result.
_MAX_TI_SUMMARY_REASONS = 10


def build_investigation_threat_intel_context(threat_intel_result: dict | None) -> str | None:
    """Derive a compact, bounded Threat Intelligence narrative block for
    Investigation's LLM-facing document.

    Returns None when threat_intel_result is falsy (mirrors
    build_investigation_alert()'s existing threat_intel_result-is-falsy
    handling for the other TI-owned queued-alert keys), so callers can
    skip embedding the field entirely rather than embedding an empty
    section. Bounded to at most _MAX_TI_SUMMARY_REASONS reasons so the
    block's size — and therefore its survival ahead of the generic
    narrative's 12,000-character truncation — is deterministic regardless
    of how many IOCs a given case produced reasons for."""
    if not threat_intel_result:
        return None

    level = threat_intel_result.get("enrichment_risk_level")
    score = threat_intel_result.get("enrichment_risk_score")
    reasons = threat_intel_result.get("enrichment_risk_reasons") or []

    lines = [
        "=== THREAT INTELLIGENCE SUMMARY ===",
        f"Risk Level: {level if level is not None else 'Unknown'}",
        f"Risk Score: {score if score is not None else 'Unknown'}",
    ]
    if reasons:
        lines.append("Risk Reasons:")
        lines.extend(f"- {reason}" for reason in reasons[:_MAX_TI_SUMMARY_REASONS])
        remaining = len(reasons) - _MAX_TI_SUMMARY_REASONS
        if remaining > 0:
            lines.append(f"- (+{remaining} more reason(s) recorded)")
    else:
        lines.append("Risk Reasons: None recorded.")
    return "\n".join(lines)


# [FYP-SECTION] Investigation handoff entity semantics (canonical audit Phase 2A)
# -----------------------------------------------------------------------------
# Every entity value carries the ordered list of upstream sources ("origins")
# it was observed in, so the handoff keeps genuinely multi-valued evidence
# (several source/destination IPs, users, hosts...) instead of the first
# value only, and the Context Brief can state provenance. Field meaning is
# preserved: a DNS name is a domain, never an endpoint hostname (NetWitness
# alias.host / triage "host.name" frequently carries the CONTACTED domain);
# an endpoint hostname is not a network source hostname; per-alert values
# are never inherited from case-level values; absent stays absent.

ENTITY_ORIGIN_TRIAGE = "Triage metakeys"
ENTITY_ORIGIN_INCIDENT = "Incident record"
ENTITY_ORIGIN_PARSING = "Parsing"
ENTITY_ORIGIN_ALERT_META = "NetWitness alert metadata"
ENTITY_ORIGIN_SCAN = "Raw incident scan (heuristic)"
ENTITY_ORIGIN_TITLE = "Incident title (heuristic)"
_ENTITY_ROLES = ("source_ips", "destination_ips", "users", "hosts", "domains",
                 "hashes", "files", "processes")

_DOMAIN_SHAPED_RE = re.compile(
    r"^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$")


def _is_domain_shaped(value) -> bool:
    """A DNS name such as "ctldl.windowsupdate.com" (dotted labels ending in an
    alphabetic TLD). Such values are routed to domains, never treated as an
    endpoint hostname."""
    text = str(value or "").strip().rstrip(".")
    return bool(text) and not _IP_RE.fullmatch(text) and bool(_DOMAIN_SHAPED_RE.match(text))


def _add_entity(bucket: dict, value, origin: str) -> None:
    """Add value(s) to an ordered {value: [origins]} bucket. Skips empty /
    placeholder values and stringified containers; never reorders."""
    values = value if isinstance(value, (list, tuple)) else [value]
    for item in values:
        if item is None or isinstance(item, (dict, list, tuple, set)):
            continue
        text = str(item).strip()
        if (not text or text.lower() in _NOISE_VALUES
                or (text[0] in "[{" and text[-1] in "]}")):
            continue
        origins = bucket.setdefault(text, [])
        if origin not in origins:
            origins.append(origin)


def _route_host_semantics(hosts: dict, domains: dict) -> None:
    """Endpoint hostnames only: DNS-name-shaped values move to domains (keeping
    their origins); IP-shaped values are dropped from hosts (IPs are captured
    under their own roles)."""
    for value in list(hosts):
        origins = hosts[value]
        if _IP_RE.fullmatch(value):
            del hosts[value]
        elif _is_domain_shaped(value):
            del hosts[value]
            for origin in origins:
                _add_entity(domains, value, origin)


def _collect_case_entities(payload: dict, incident: dict,
                           parsing_result: dict | None, ctx: dict) -> dict:
    """Case-level entities with provenance, in a fixed source precedence:
    Triage metakeys -> incident record -> Parsing (canonical normalised
    telemetry) -> NetWitness alertMeta digest -> raw-incident heuristics.
    Returns {role: {value: [origins]}}; insertion order is deterministic."""
    roles: dict = {role: {} for role in _ENTITY_ROLES}
    mkv = payload.get("metakey_values") or {}
    am = incident.get("alertMeta") if isinstance(incident.get("alertMeta"), dict) else {}
    parsed = (parsing_result or {}).get("processed_alert") or {}
    if not isinstance(parsed, dict):
        parsed = {}
    net = parsed.get("network_indicators") or {}
    uh = parsed.get("user_and_host_indicators") or {}
    files = parsed.get("file_indicators") or {}
    procs = parsed.get("process_indicators") or {}
    web = parsed.get("web_indicators") or {}

    def add(role: str, value, origin: str) -> None:
        _add_entity(roles[role], value, origin)

    add("source_ips", mkv.get("ip.src"), ENTITY_ORIGIN_TRIAGE)
    add("destination_ips", mkv.get("ip.dst"), ENTITY_ORIGIN_TRIAGE)
    add("users", mkv.get("user.name"), ENTITY_ORIGIN_TRIAGE)
    add("hosts", mkv.get("host.name"), ENTITY_ORIGIN_TRIAGE)
    for key in ("domain", "domain.dst", "alias.host"):
        add("domains", mkv.get(key), ENTITY_ORIGIN_TRIAGE)
    for key in ("file.hash", "checksum", "checksumSha256", "checksumSha1",
                "checksumMd5", "sha256", "md5"):
        add("hashes", mkv.get(key), ENTITY_ORIGIN_TRIAGE)
    for key in ("file.name", "filename"):
        add("files", mkv.get(key), ENTITY_ORIGIN_TRIAGE)
    add("processes", mkv.get("process.name"), ENTITY_ORIGIN_TRIAGE)

    add("source_ips", incident.get("source_ip"), ENTITY_ORIGIN_INCIDENT)
    add("destination_ips", incident.get("destination_ip"), ENTITY_ORIGIN_INCIDENT)
    add("users", incident.get("username"), ENTITY_ORIGIN_INCIDENT)
    add("hosts", incident.get("hostname"), ENTITY_ORIGIN_INCIDENT)

    add("source_ips", net.get("source_ips"), ENTITY_ORIGIN_PARSING)
    add("destination_ips", net.get("destination_ips"), ENTITY_ORIGIN_PARSING)
    add("users", uh.get("all_usernames"), ENTITY_ORIGIN_PARSING)
    add("hosts", uh.get("hostnames"), ENTITY_ORIGIN_PARSING)
    add("domains", uh.get("domains"), ENTITY_ORIGIN_PARSING)
    add("domains", web.get("domains"), ENTITY_ORIGIN_PARSING)
    add("hashes", files.get("file_hashes"), ENTITY_ORIGIN_PARSING)
    add("files", files.get("file_names"), ENTITY_ORIGIN_PARSING)
    add("processes", procs.get("process_names"), ENTITY_ORIGIN_PARSING)

    add("source_ips", am.get("SourceIp"), ENTITY_ORIGIN_ALERT_META)
    add("destination_ips", am.get("DestinationIp"), ENTITY_ORIGIN_ALERT_META)
    add("users", am.get("User"), ENTITY_ORIGIN_ALERT_META)
    add("users", am.get("AdUser"), ENTITY_ORIGIN_ALERT_META)
    add("hosts", am.get("Hostname"), ENTITY_ORIGIN_ALERT_META)
    add("domains", am.get("DnsDomain"), ENTITY_ORIGIN_ALERT_META)
    add("hashes", am.get("FileHash"), ENTITY_ORIGIN_ALERT_META)
    add("files", am.get("FileName"), ENTITY_ORIGIN_ALERT_META)

    add("source_ips", ctx.get("source_ips"), ENTITY_ORIGIN_SCAN)
    add("destination_ips", ctx.get("destination_ips"), ENTITY_ORIGIN_SCAN)
    add("users", ctx.get("users"), ENTITY_ORIGIN_SCAN)
    title_entity = ctx.get("title_entity")
    title_fallback = bool(title_entity) and list(ctx.get("hosts") or []) == [title_entity]
    add("hosts", ctx.get("hosts"),
        ENTITY_ORIGIN_TITLE if title_fallback else ENTITY_ORIGIN_SCAN)

    _route_host_semantics(roles["hosts"], roles["domains"])
    return roles


def _nw_value(*values):
    """First value that is present (not None / blank string / empty container)."""
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, (list, dict)) and not value:
            continue
        return value
    return None


def _sub_alert_entry(sub: dict) -> dict:
    """One NetWitness alert's OWN fields (flat or nested Respond structure:
    alert{name,type,host_summary,events}, originalHeaders, originalAlert).
    Nothing is inherited from the case and nothing is fabricated: a field the
    alert does not carry stays absent."""
    def _dict(value) -> dict:
        return value if isinstance(value, dict) else {}

    alert_obj = _dict(sub.get("alert"))
    headers = _dict(sub.get("originalHeaders"))
    original = _dict(sub.get("originalAlert"))
    origin = "alert"
    bucket: dict = {role: {} for role in ("source_ips", "destination_ips", "users",
                                          "hostnames", "domains")}
    _add_entity(bucket["source_ips"], [sub.get("sourceIp"), sub.get("src_ip"),
                                       sub.get("source_ip")], origin)
    _add_entity(bucket["destination_ips"], [sub.get("destinationIp"), sub.get("dst_ip"),
                                            sub.get("destination_ip")], origin)
    _add_entity(bucket["users"], [sub.get("userName"), sub.get("user")], origin)
    _add_entity(bucket["hostnames"], [sub.get("hostname"), sub.get("host")], origin)

    events = alert_obj.get("events") or original.get("events") or sub.get("events") or []
    for ev in (events if isinstance(events, list) else [])[:50]:
        if not isinstance(ev, dict):
            continue
        for side, role in (("source", "source_ips"), ("destination", "destination_ips")):
            node = _dict(ev.get(side))
            device = _dict(node.get("device"))
            user = _dict(node.get("user"))
            _add_entity(bucket[role], [device.get("ip_address"), device.get("ipAddress")], origin)
            _add_entity(bucket["hostnames"], [device.get("dns_hostname"), device.get("dnsHostname"),
                                              device.get("netbios_name")], origin)
            _add_entity(bucket["domains"], [device.get("dns_domain"), device.get("dnsDomain")], origin)
            _add_entity(bucket["users"], [user.get("username"), user.get("ad_username"),
                                          user.get("adUsername")], origin)
        _add_entity(bucket["source_ips"], ev.get("ip_src"), origin)
        _add_entity(bucket["destination_ips"], ev.get("ip_dst"), origin)
        _add_entity(bucket["users"], [ev.get("user_src"), ev.get("user_dst"), ev.get("username"),
                                      ev.get("user_account"), ev.get("user")], origin)
        # ECAT puts the endpoint machine name in events[].domain; a real DNS
        # name there is routed to domains by _route_host_semantics().
        _add_entity(bucket["hostnames"], [ev.get("hostname"), ev.get("host_src"),
                                          ev.get("host_dst"), ev.get("domain")], origin)
        _add_entity(bucket["domains"], [ev.get("domain_dst"), ev.get("alias_host")], origin)
    _route_host_semantics(bucket["hostnames"], bucket["domains"])

    alert_types = _nw_value(alert_obj.get("type"), sub.get("type"))
    if isinstance(alert_types, str):
        alert_types = [alert_types]
    entry = {
        "alert_id": _nw_value(sub.get("id"), sub.get("alert_id"), sub.get("_id"), original.get("id")),
        "title": _nw_value(sub.get("title"), sub.get("name"), alert_obj.get("name"),
                           headers.get("name"), original.get("moduleName"), sub.get("signature")),
        "timestamp": _to_iso_timestamp(_nw_value(sub.get("created"), sub.get("receivedTime"),
                                                 sub.get("timestamp"), headers.get("timestamp"))),
        # The alert's own NetWitness severity (raw value) -- never a default,
        # never the Triage classification.
        "severity": _nw_value(sub.get("severity"), sub.get("priority"),
                              headers.get("severity"), original.get("severity")),
        "alert_types": alert_types if isinstance(alert_types, list) else None,
        "detection_source": _nw_value(alert_obj.get("source"), headers.get("deviceProduct")),
        # e.g. "192.168.10.200:53539 to 8.8.8.8:53" -- a connection summary,
        # not a hostname.
        "connection_summary": _nw_value(alert_obj.get("host_summary"), sub.get("hostSummary")),
        "source_ips": list(bucket["source_ips"]),
        "destination_ips": list(bucket["destination_ips"]),
        "users": list(bucket["users"]),
        "hostnames": list(bucket["hostnames"]),
        "domains": list(bucket["domains"]),
        "description": _nw_value(sub.get("detail"), sub.get("description"),
                                 alert_obj.get("description"), headers.get("description")),
    }
    return prune_empty(entry)


# [FYP-SECTION] Investigation Context Brief (canonical audit Phase 2B)
# -----------------------------------------------------------------------------
# A deterministic, bounded, sectioned text block built ONLY from canonical
# structured stage results (Triage result, Parsing result, Threat
# Intelligence result, the run's raw-incident record) -- never from post-stage
# AI summaries or display objects. ingest_pipeline.serialize_json_to_narrative()
# renders it FIRST, so verbose content (alert lists, raw provider data) can
# never displace it under the 12,000-character document cap, and Pass 1 and
# Pass 2 receive the same foundation (both consume the same documents).
#
# Budgets (characters) were chosen from the canonical-audit measurements:
# CASE ~0.3k, TRIAGE 0.6-1.2k, TI summary block 0.15-0.6k (+coverage, gaps,
# top-8 indicator lines of ~160 chars), entity lists bounded per role.
# Worst case = 7,000 (+2,500 reserved for deep-dive answers on a feedback
# pass) + ~120 framing = < 9,700, leaving the 12,000-char document cap intact.
# A section over budget is cut with an explicit "[... section truncated ...]"
# marker; lists show a deterministic top-N plus "(+N more)".
INVESTIGATION_BRIEF_HEADER = "=== INVESTIGATION CONTEXT BRIEF (canonical stage results; bounded) ==="
INVESTIGATION_BRIEF_FOOTER = "=== END INVESTIGATION CONTEXT BRIEF ==="
BRIEF_SECTION_BUDGETS = {
    "CASE": 500,
    "TRIAGE": 1500,
    "ENTITIES & TELEMETRY": 1800,
    "THREAT INTELLIGENCE": 2400,
    "DATA QUALITY / LIMITATIONS": 800,
    "DEEP-DIVE ANSWERS (feedback pass)": 2500,   # reserved; rendered only when present
}
BRIEF_LIST_LIMITS = {"ips": 8, "users": 6, "hosts": 6, "domains": 8, "hashes": 5,
                     "files": 6, "processes": 6, "command_lines": 3, "indicators": 8,
                     "not_enriched_examples": 6, "gaps": 4, "warnings": 4,
                     "parsing_warnings": 4, "missing_fields": 8, "deep_dive_gaps": 8}
_BRIEF_LINE_MAX = 400


def _brief_clip(text, limit: int = _BRIEF_LINE_MAX) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def _brief_section(title: str, lines: list[str]) -> str:
    budget = BRIEF_SECTION_BUDGETS[title]
    body = [f"[{title}]"] + [_brief_clip(line) for line in lines if line]
    text = "\n".join(body)
    if len(text) > budget:
        marker = f"\n[... {title} section truncated at {budget} chars ...]"
        text = text[:budget - len(marker)].rstrip() + marker
    return text


_BRIEF_ORIGIN_CODES = {
    ENTITY_ORIGIN_PARSING: "P", ENTITY_ORIGIN_TRIAGE: "T", ENTITY_ORIGIN_ALERT_META: "NW",
    ENTITY_ORIGIN_INCIDENT: "INC", ENTITY_ORIGIN_SCAN: "H", ENTITY_ORIGIN_TITLE: "H-title",
}
BRIEF_ORIGIN_LEGEND = ("Origins: P=Parsing, T=Triage metakeys, NW=NetWitness alert metadata, "
                       "INC=incident record, H=raw-incident heuristic, H-title=incident title heuristic")


def _brief_entity_line(label: str, entries: dict, limit: int, *, max_len: int = _BRIEF_LINE_MAX) -> str | None:
    """`label (total): v1 [P,T]; v2 [NW]; (+N more)` -- packed to max_len so the
    (+N more) marker always survives; items in deterministic source order."""
    if not entries:
        return None
    items = list(entries.items())
    head = f"{label} ({len(items)}): "
    shown: list[str] = []
    for value, srcs in items[:limit]:
        codes = ",".join(_BRIEF_ORIGIN_CODES.get(s, s) for s in srcs)
        piece = f"{value} [{codes}]" if codes else str(value)
        remaining = len(items) - len(shown) - 1
        tail = f"; (+{remaining} more)" if remaining else ""
        if shown and len(head) + len("; ".join(shown + [piece])) + len(tail) > max_len:
            break
        shown.append(piece)
    more = len(items) - len(shown)
    return head + "; ".join(shown) + (f"; (+{more} more)" if more else "")


def _pack_lines(lines: list[str], budget: int, more_label: str) -> list[str]:
    """Keep whole lines while they fit `budget` chars, then a deterministic
    "(+N more <label>)" line."""
    kept, used = [], 0
    for i, line in enumerate(lines):
        reserve = len(f"(+{len(lines) - i} more {more_label})") + 1
        if used + len(line) + 1 + (reserve if i < len(lines) - 1 else 0) > budget:
            kept.append(f"(+{len(lines) - i} more {more_label})")
            return kept
        kept.append(line)
        used += len(line) + 1
    return kept


def _brief_list(values, limit: int) -> tuple[list, int]:
    values = [v for v in (values or []) if v not in (None, "", [], {})]
    return values[:limit], max(0, len(values) - limit)


def _ti_provider_verdict(provider: str, data) -> str:
    """Compact per-provider verdict -- counts/scores only; never provider
    free text (pulse names, ISP, meaningful names)."""
    if not isinstance(data, dict) or not data:
        return "not queried"
    status = str(data.get("status") or "unknown")
    if status != "completed":
        return status
    if provider == "virustotal":
        mal, susp = data.get("malicious", 0) or 0, data.get("suspicious", 0) or 0
        total = data.get("analysed_vendors")
        return f"{mal} malicious, {susp} suspicious" + (f" of {total}" if total else "")
    if provider == "abuseipdb":
        score = data.get("abuse_confidence_score")
        reports = data.get("total_reports")
        return f"confidence {score}" + (f", {reports} reports" if reports is not None else "")
    if provider in ("otx", "alienvault_otx"):
        return f"{data.get('pulse_count', 0) or 0} pulses"
    return status


def _ti_indicator_rank(ind: dict) -> tuple:
    prov = ind.get("providers") or {}
    vt = prov.get("virustotal") or {}
    ab = prov.get("abuseipdb") or {}
    otx = prov.get("otx") or {}
    return (-((vt.get("malicious") or 0) * 10 + (vt.get("suspicious") or 0)),
            -(ab.get("abuse_confidence_score") or 0),
            -(otx.get("pulse_count") or 0),
            str(ind.get("value")))


def _ti_indicator_line(ind: dict) -> str:
    prov = ind.get("providers") or {}
    roles = ", ".join(ind.get("roles") or []) or "not recorded"
    origins = ind.get("origins") or []
    origin_text = ", ".join(origins[:2]) + (f" (+{len(origins) - 2})" if len(origins) > 2 else "") \
        if origins else "not recorded"
    parts = [str(ind.get("value")), str(ind.get("type") or "?"), f"role: {roles}",
             f"origin: {origin_text}", f"VT: {_ti_provider_verdict('virustotal', prov.get('virustotal'))}"]
    if ind.get("type") == "ip":
        parts.append(f"AbuseIPDB: {_ti_provider_verdict('abuseipdb', prov.get('abuseipdb'))}")
    parts.append(f"OTX: {_ti_provider_verdict('otx', prov.get('otx'))}")
    return "- " + " | ".join(parts)


def _legacy_ti_indicator_lines(bundle: dict) -> list[str]:
    """Legacy contract: per-IOC lines joined from the provider result lists.
    Roles/origins were never recorded by that contract and are stated as such."""
    iocs = bundle.get("iocs") or {}
    vt = bundle.get("virustotal") or {}
    by_value: dict = {}

    def add(value, typ):
        if value and str(value) not in by_value:
            by_value[str(value)] = {"type": typ, "providers": {}}

    for v in iocs.get("ip_indicators") or []:
        add(v, "ip")
    for v in iocs.get("domain_indicators") or []:
        add(v, "domain")
    for v in (iocs.get("file_hashes") or [iocs.get("file_hash")]):
        add(v, "hash")
    for provider, results in (("virustotal", (vt.get("ip_results") or []) + (vt.get("domain_results") or [])
                               + (vt.get("file_hash_results") or ([vt["file_hash"]] if isinstance(vt.get("file_hash"), dict) else []))),
                              ("abuseipdb", (bundle.get("abuseipdb") or {}).get("ip_results") or []),
                              ("otx", (bundle.get("alienvault_otx") or {}).get("otx_results") or [])):
        for r in results:
            if isinstance(r, dict) and str(r.get("indicator")) in by_value:
                by_value[str(r.get("indicator"))]["providers"].setdefault(provider, r)
    lines = []
    for value, info in by_value.items():
        ind = {"value": value, "type": info["type"], "providers": info["providers"],
               "roles": [], "origins": []}
        line = _ti_indicator_line(ind).replace("role: not recorded", "role: not recorded (legacy TI)")
        lines.append(line)
    return lines


def _brief_ti_section(ti: dict | None) -> tuple[list[str], list[str]]:
    """(TI section lines, data-quality lines). Precedence: the canonical
    multi-IOC fields (indicators/coverage/provider_coverage/intelligence_gaps)
    when indicators[] is present; legacy provider lists only when it is absent
    -- never both, so the two contracts are never silently merged. Line order
    is priority order: risk summary, coverage, provider coverage, gaps,
    warnings and not-enriched counts always precede the per-indicator lines,
    which are packed last into whatever budget remains."""
    if not ti:
        return (["No Threat Intelligence result is available for this case."],
                ["Threat Intelligence: no result -- external reputation evidence was NOT obtained."])
    fixed, dq = [], []
    summary = build_investigation_threat_intel_context(ti)
    if summary:
        fixed.extend(summary.splitlines())
    fixed.append(f"TI stage status: {ti.get('status') or 'not recorded'}")
    bundle = ti.get("threat_intelligence") if isinstance(ti.get("threat_intelligence"), dict) else {}
    indicators = bundle.get("indicators")
    indicator_lines: list[str] = []
    more_label = "enriched indicators"
    if isinstance(indicators, list):
        fixed.append("TI contract: multi-indicator (per-IOC roles, origins and provider verdicts)")
        cov = bundle.get("coverage") if isinstance(bundle.get("coverage"), dict) else None
        if cov:
            fixed.append(f"Coverage: extracted {cov.get('extracted')}, eligible {cov.get('eligible')}, "
                         f"enriched {cov.get('enriched')}, excluded {cov.get('excluded')}, "
                         f"skipped {cov.get('skipped')} (by limit {cov.get('skipped_by_limit')}; "
                         f"limit {cov.get('limit_per_type')} per type)")
        else:
            fixed.append("Coverage: not recorded in this TI result")
        pcov = bundle.get("provider_coverage") if isinstance(bundle.get("provider_coverage"), dict) else {}
        if pcov:
            fixed.append("Provider coverage: " + "; ".join(
                f"{(pcov[k] or {}).get('label') or k} {(pcov[k] or {}).get('state')} "
                f"(queried {(pcov[k] or {}).get('queried')}/{(pcov[k] or {}).get('applicable')}, "
                f"failed {(pcov[k] or {}).get('failed')})" for k in sorted(pcov)))
            for k in sorted(pcov):
                p = pcov[k] or {}
                if p.get("state") in ("failed", "partial", "not_configured") or (p.get("failed") or 0) > 0:
                    dq.append(f"TI provider {p.get('label') or k}: {p.get('state')} "
                              f"({p.get('failed') or 0} failed, {p.get('not_configured') or 0} not configured)")
        else:
            fixed.append("Provider coverage: not recorded in this TI result")
        gaps, more_gaps = _brief_list(bundle.get("intelligence_gaps"), BRIEF_LIST_LIMITS["gaps"])
        fixed.append("Intelligence gaps: " + ("; ".join(map(str, gaps)) + (f" (+{more_gaps} more)" if more_gaps else "")
                                             if gaps else "none recorded"))
        not_enriched = [i for i in indicators if isinstance(i, dict) and i.get("status") != "enriched"]
        if not_enriched:
            counts: dict = {}
            for i in not_enriched:
                key = f"{i.get('status')}/{i.get('status_category') or 'unspecified'}"
                counts[key] = counts.get(key, 0) + 1
            examples = [str(i.get("value")) for i in not_enriched[:BRIEF_LIST_LIMITS["not_enriched_examples"]]]
            more = len(not_enriched) - len(examples)
            fixed.append("NOT enriched: " + ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
                         + f" -- e.g. {', '.join(examples)}" + (f" (+{more} more)" if more else ""))
            skipped = sum(1 for i in not_enriched if i.get("status") == "skipped")
            if skipped:
                dq.append(f"TI: {skipped} eligible indicator(s) were NOT looked up -- absence of TI "
                          "findings for them is not evidence they are benign")
        enriched = sorted((i for i in indicators if isinstance(i, dict) and i.get("status") == "enriched"),
                          key=_ti_indicator_rank)
        indicator_lines = [_ti_indicator_line(i) for i in enriched[:BRIEF_LIST_LIMITS["indicators"]]]
        extra = len(enriched) - len(indicator_lines)
        header = (f"Enriched indicators ({len(enriched)}, highest provider evidence first):"
                  if enriched else "Enriched indicators: none")
    else:
        fixed.append("TI contract: legacy (indicator roles/origins and coverage were not recorded)")
        indicator_lines = _legacy_ti_indicator_lines(bundle)
        extra = max(0, len(indicator_lines) - BRIEF_LIST_LIMITS["indicators"])
        indicator_lines = indicator_lines[:BRIEF_LIST_LIMITS["indicators"]]
        header = f"Legacy TI indicators ({len(indicator_lines) + extra}):" if indicator_lines else \
            "Legacy TI indicators: none recorded"
        more_label = "legacy TI indicators"
        dq.append("TI: legacy result -- looked-up vs not-looked-up indicators cannot be "
                  "distinguished; absence of findings is not evidence of benign")
    warnings, more_w = _brief_list(ti.get("warnings"), BRIEF_LIST_LIMITS["warnings"])
    fixed.append("TI warnings: " + ("; ".join(map(str, warnings)) + (f" (+{more_w} more)" if more_w else "")
                                    if warnings else "none recorded"))
    if warnings:
        dq.append(f"TI reported {len(ti.get('warnings') or [])} warning(s) (see THREAT INTELLIGENCE)")
    if ti.get("recommended_next_action"):
        fixed.append(f"TI recommended next action: {ti['recommended_next_action']}")
    fixed.append(header)

    # Pack the per-indicator lines into the remaining TI budget.
    used = len("[THREAT INTELLIGENCE]") + sum(len(_brief_clip(l)) + 1 for l in fixed)
    remaining = BRIEF_SECTION_BUDGETS["THREAT INTELLIGENCE"] - used - 8
    packed = _pack_lines([_brief_clip(l) for l in indicator_lines], max(0, remaining), more_label)
    if extra:
        if packed and packed[-1].startswith("(+"):
            n = int(packed[-1][2:].split(" ", 1)[0]) + extra
            packed[-1] = f"(+{n} more {more_label})"
        else:
            packed.append(f"(+{extra} more {more_label})")
    return fixed + packed, dq


def build_investigation_context_brief(triage_result: dict, incident: dict, alert: dict, entities: dict,
                                      *, threat_intel_result: dict | None = None,
                                      parsing_result: dict | None = None,
                                      supplement: dict | None = None) -> str:
    """Deterministic, bounded Investigation Context Brief (see section
    comment above). Pure: same inputs -> same text."""
    payload = triage_result.get("metakeys_payload") or {}
    ticket = triage_result.get("ticket") or {}
    details = alert.get("incident_details") or {}
    classification = alert.get("classification") or {}
    endpoint = alert.get("endpoint_indicators") or {}
    email = alert.get("email_artifacts") or {}
    raw_alerts = incident.get("alerts") if isinstance(incident.get("alerts"), list) else None
    sections = []

    # 1. CASE
    case_lines = [f"Case ID (Investigation subject): {alert.get('incident_id')}",
                  f"Title: {details.get('title') or 'not provided'}",
                  f"Incident time: {details.get('timestamp') or 'not provided'}"]
    nw = []
    for label, key in (("risk score", "riskScore"), ("priority", "priority"),
                       ("created", "created"), ("sources", "sources")):
        value = incident.get(key)
        if value not in (None, "", [], {}):
            nw.append(f"{label} {', '.join(map(str, value)) if isinstance(value, list) else value}")
    alert_count = incident.get("alertCount") if incident.get("alertCount") is not None else \
        (len(raw_alerts) if raw_alerts is not None else None)
    if alert_count is not None:
        nw.append(f"alerts {alert_count}")
    case_lines.append("NetWitness: " + ("; ".join(nw) if nw else "no incident metadata available"))
    sections.append(_brief_section("CASE", case_lines))

    # 2. TRIAGE
    rr = ticket.get("risk_rating") if isinstance(ticket.get("risk_rating"), dict) else {}
    triage_lines = [
        f"Triage level: {ticket.get('classification') or 'not provided'} "
        "(Triage classification -- not the NetWitness severity)",
        f"Category: {ticket.get('incident_category') or 'not provided'}",
    ]
    if rr:
        triage_lines.append(
            f"Risk dimensions: initiation {rr.get('likelihood_initiation')}, occurrence "
            f"{rr.get('likelihood_occurrence')}, adverse impact {rr.get('likelihood_adverse_impact')}, "
            f"overall {rr.get('overall_risk')}")
        if rr.get("rationale"):
            triage_lines.append(f"Risk rationale: {rr['rationale']}")
    mitre = details.get("mitre_att&ck") or {}
    triage_lines.append(f"MITRE (Triage): tactic {mitre.get('tactic') or 'not provided'}; "
                        f"technique {mitre.get('technique') or 'not provided'}")
    if ticket.get("summary"):
        triage_lines.append(f"Triage interpretation (Triage agent's assessment, not a factual "
                            f"incident description): {ticket['summary']}")
    if payload.get("ioc_summary"):
        triage_lines.append(f"Triage IOC checklist findings: {payload['ioc_summary']}")
    if classification.get("source_risk_score") is not None:
        triage_lines.append(f"NetWitness source risk score: {classification['source_risk_score']}")
    sections.append(_brief_section("TRIAGE", triage_lines))

    # 3. ENTITIES & TELEMETRY
    L = BRIEF_LIST_LIMITS
    ent_lines = [
        _brief_entity_line("Source IPs", entities.get("source_ips") or {}, L["ips"]),
        _brief_entity_line("Destination IPs", entities.get("destination_ips") or {}, L["ips"]),
        _brief_entity_line("Users", entities.get("users") or {}, L["users"]),
        _brief_entity_line("Endpoint hosts", entities.get("hosts") or {}, L["hosts"]),
        _brief_entity_line("Domains (role not asserted)", entities.get("domains") or {}, L["domains"]),
        _brief_entity_line("File hashes", entities.get("hashes") or {}, L["hashes"]),
        _brief_entity_line("Files", entities.get("files") or {}, L["files"]),
        _brief_entity_line("Processes", entities.get("processes") or {}, L["processes"]),
    ]
    procs = endpoint.get("processes") or {}
    cmds = procs.get("command_line")
    cmds = cmds if isinstance(cmds, list) else ([cmds] if cmds else [])
    shown_cmds, more_cmds = _brief_list(cmds, L["command_lines"])
    for c in shown_cmds:
        ent_lines.append(f"Command line: {_brief_clip(c, 240)}")
    if more_cmds:
        ent_lines.append(f"(+{more_cmds} more command lines)")
    lineage = procs.get("lineage") or []
    if lineage:
        ent_lines.append("Process lineage: " + "; ".join(
            f"{e.get('parent')} -> {e.get('child')}" for e in lineage[:4] if isinstance(e, dict))
            + (f" (+{len(lineage) - 4} more)" if len(lineage) > 4 else ""))
    parsed = (parsing_result or {}).get("processed_alert") or {}
    ps = parsed.get("powershell_analysis") if isinstance(parsed, dict) else None
    if isinstance(ps, dict) and ps.get("decode_status") not in (None, "", "not_found", "not_detected"):
        ps_iocs = ps.get("extracted_iocs") if isinstance(ps.get("extracted_iocs"), dict) else {}
        ioc_text = "; ".join(f"{k}: {', '.join(map(str, v[:5]))}" + (f" (+{len(v) - 5})" if len(v) > 5 else "")
                             for k, v in sorted(ps_iocs.items()) if isinstance(v, list) and v)
        ent_lines.append(f"Decoded PowerShell [Parsing]: status {ps.get('decode_status')}; "
                         f"{ps.get('decoded_command_summary') or ''}"
                         + (f"; extracted IOCs -- {ioc_text}" if ioc_text else ""))
    net = alert.get("network_indicators") or {}
    src, dst = net.get("source") or {}, net.get("destination") or {}
    net_parts = [f"{label} {value}" for label, value in (
        ("source port", src.get("port")), ("source MAC", src.get("mac_address")),
        ("destination port", dst.get("port")), ("service", dst.get("service")),
        ("destination domain", dst.get("domain"))) if value not in (None, "")]
    if net_parts:
        ent_lines.append("Network detail [Triage metakeys / NetWitness alert metadata]: " + "; ".join(net_parts))
    if endpoint.get("operating_system"):
        ent_lines.append(f"Operating system: {endpoint['operating_system']}")
    files_detail = endpoint.get("files") or {}
    if files_detail.get("filepath"):
        ent_lines.append(f"File path: {files_detail['filepath']}")
    for label, key in (("Email sender", "sender"), ("Email recipient", "recipient"), ("Email subject", "subject")):
        if email.get(key):
            ent_lines.append(f"{label}: {email[key]}")
    ent_lines = [line for line in ent_lines if line]
    if not ent_lines:
        ent_lines = ["No entities were recorded by Parsing, Triage or the NetWitness alert metadata."]
    else:
        ent_lines.insert(0, BRIEF_ORIGIN_LEGEND)
    ent_lines.append(f"NetWitness alerts listed after this brief: {len(alert.get('alerts') or [])}")
    sections.append(_brief_section("ENTITIES & TELEMETRY", ent_lines))

    # 4. THREAT INTELLIGENCE
    ti_lines, ti_dq = _brief_ti_section(threat_intel_result)
    sections.append(_brief_section("THREAT INTELLIGENCE", ti_lines))

    # 5. DATA QUALITY / LIMITATIONS
    dq_lines = []
    if not incident or not (incident.get("id") or incident.get("incidentId")):
        dq_lines.append("Raw incident record UNAVAILABLE for this run -- context is built from "
                        "stage results only; NetWitness alert details could not be obtained.")
    else:
        avail = _data_availability(incident)
        if avail.get("warnings"):
            dq_lines.extend(avail["warnings"])
        elif avail.get("incident_source") == "sqlite_slim":
            dq_lines.append("NetWitness alerts: stored slim copy only (alert details stripped).")
        elif raw_alerts is None:
            dq_lines.append("NetWitness alerts: not attached to the incident record (fetch status not recorded).")
    if not parsing_result:
        dq_lines.append("Parsing result UNAVAILABLE -- normalised telemetry could not be obtained.")
    else:
        pw, more_pw = _brief_list(parsing_result.get("warnings"), L["parsing_warnings"])
        if pw:
            dq_lines.append("Parsing warnings: " + "; ".join(map(str, pw)) + (f" (+{more_pw} more)" if more_pw else ""))
        mf, more_mf = _brief_list(parsing_result.get("missing_important_fields"), L["missing_fields"])
        if mf:
            dq_lines.append("Parsing missing fields (not present in telemetry): " + ", ".join(map(str, mf))
                            + (f" (+{more_mf} more)" if more_mf else ""))
    dq_lines.extend(ti_dq)
    if not dq_lines:
        dq_lines.append("No data-quality limitations were recorded by the upstream stages.")
    sections.append(_brief_section("DATA QUALITY / LIMITATIONS", dq_lines))

    # 6. DEEP-DIVE ANSWERS (feedback pass only; reserved budget)
    if supplement:
        findings = supplement.get("gap_findings") if isinstance(supplement.get("gap_findings"), dict) else {}
        conf = supplement.get("confidence_per_gap") if isinstance(supplement.get("confidence_per_gap"), dict) else {}
        queries = supplement.get("actionable_queries") if isinstance(supplement.get("actionable_queries"), dict) else {}
        gaps = [str(g) for g in (supplement.get("requested_gaps") or [])]
        gaps += [g for g in findings if g not in gaps]
        dd_lines = [f"Feedback pass {supplement.get('feedback_pass') or '?'}: {len(gaps)} evidence gap(s) "
                    "re-examined against the raw incident by the Triage deep-dive"]
        for gap in gaps[:L["deep_dive_gaps"]]:
            line = f"- Gap: {_brief_clip(gap, 120)} -> ({conf.get(gap) or 'n/a'}) {_brief_clip(findings.get(gap) or 'no finding returned', 200)}"
            if queries.get(gap):
                line += f" | collect via: {_brief_clip(queries[gap], 120)}"
            dd_lines.append(line)
        if len(gaps) > L["deep_dive_gaps"]:
            dd_lines.append(f"(+{len(gaps) - L['deep_dive_gaps']} more gaps)")
        extracted = supplement.get("extracted_values") if isinstance(supplement.get("extracted_values"), dict) else {}
        if extracted:
            dd_lines.append("Deep-dive extracted values: " + "; ".join(
                f"{k}={extracted[k]}" for k in sorted(extracted)[:8]))
        if supplement.get("deep_dive_summary"):
            dd_lines.append(f"Deep-dive summary: {supplement['deep_dive_summary']}")
        suggested = [f"{k} {supplement[k]}" for k in ("classification", "mitre_tactic", "incident_category")
                     if supplement.get(k) and str(supplement[k]).strip().lower() not in ("null", "none")]
        if suggested:
            dd_lines.append("Deep-dive suggestions (NOT applied; analyst to review): " + "; ".join(suggested))
        sections.append(_brief_section("DEEP-DIVE ANSWERS (feedback pass)", dd_lines))

    return "\n".join([INVESTIGATION_BRIEF_HEADER, *sections, INVESTIGATION_BRIEF_FOOTER])


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
    alert, _entities = _assemble_investigation_alert(
        triage_result, incident, supplement=supplement,
        threat_intel_result=threat_intel_result, parsing_result=parsing_result)
    return alert


def _assemble_investigation_alert(triage_result: dict, incident: dict,
                                  supplement: dict | None = None,
                                  threat_intel_result: dict | None = None,
                                  parsing_result: dict | None = None) -> tuple[dict, dict]:
    """Body of build_investigation_alert(): returns (alert JSON incl. the
    Investigation Context Brief, case entities with provenance). Shared by
    the Investigation handoff and the Phase 2C deep-dive context, so both
    see the SAME canonical brief from one builder. Kept separate from the
    public function so building the deep-dive context does not register as
    an Investigation handoff in Agent Activity."""
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

    # Case-level entities with provenance (Phase 2A): genuine multi-valued
    # evidence is kept; the scalar fields below are the first value of each
    # list in the documented source precedence (backward compatible).
    entities = _collect_case_entities(payload, incident, parsing_result, ctx)
    src_ip = next(iter(entities["source_ips"]), None)
    dst_ip = next(iter(entities["destination_ips"]), None)
    hostname = next(iter(entities["hosts"]), None)        # never a DNS name
    user = next(iter(entities["users"]), None)

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

    # Every NetWitness alert of this incident, each with ONLY its own fields
    # (Phase 2A: no fabricated id/title/"Medium" severity, no case-level
    # user/host/IP inheritance -- see _sub_alert_entry()).
    sub_alerts = []
    raw_alerts_list = incident.get("alerts") or incident.get("events") or []
    if isinstance(raw_alerts_list, list):
        for sub in raw_alerts_list:
            if isinstance(sub, dict):
                sub_entry = _sub_alert_entry(sub)
                if sub_entry:
                    sub_alerts.append(sub_entry)

    raw_alert = {
        "incident_id": payload.get("incident_id") or ticket.get("incident_id"),
        "classification": {
            "alert_type": ticket.get("incident_category"),
            "severity": ticket.get("classification"),
            # Two distinct concepts previously conflated under one ambiguous
            # "risk_score" key (`ticket.get("risk_rating") or
            # incident.get("riskScore")`), which made the field's type
            # alternate between a dict (Triage's structured risk_rating) and
            # a scalar (the source-system's numeric riskScore) depending on
            # which happened to be truthy. No consumer in agents/investigation/
            # reads "risk_score" off this handoff JSON (verified by repo-wide
            # grep before this change) -- incident_map.py's own "risk_score"
            # reads the raw NetWitness `incident` dict directly, not this
            # file -- so no compatibility alias is needed; both new keys are
            # additive-only relative to what anything actually consumes.
            "triage_risk_rating": ticket.get("risk_rating"),
            "source_risk_score": incident.get("riskScore"),
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
            # Phase 2A: no "hostname" here -- the affected endpoint's hostname
            # is not evidence that it was the connection's SOURCE host.
            "source": {
                "ip_address": src_ip,
                "ip_addresses": list(entities["source_ips"]),
                "port": _first(_mk("port.src")),
                "mac_address": _first(_amlist("MacAddress")),
            },
            "destination": {
                "ip_address": dst_ip,
                "ip_addresses": list(entities["destination_ips"]),
                "port": _first(_mk("port.dst"), _mk("tcp.dstport")),
                "service": _first(_mk("service"), _mk("network.service")),
                "domain": _mk("domain"),
            },
            # DNS names observed for the case, role not asserted (a contacted
            # domain is not necessarily the destination of every connection).
            "observed_domains": list(entities["domains"]),
        },
        "endpoint_indicators": {
            "user": user,
            "users": list(entities["users"]),
            "hostname": hostname,
            "hostnames": list(entities["hosts"]),
            "operating_system": _first(_mk("os.version"), (ctx["operating_systems"] or [None])[0]),
            "processes": {
                "process_name": next(iter(entities["processes"]), None),
                "process_names": list(entities["processes"]),
                "command_line": cmd_val,
                "lineage": _process_lineage(),
            },
            "files": {
                "filename": next(iter(entities["files"]), None),
                "filenames": list(entities["files"]),
                "filepath": _first(_mklist("file.path")),
                "hashes": list(entities["hashes"]),
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
            # Phase 5B: additive compact projection, rendered ahead of the
            # generic narrative by ingest_pipeline.serialize_json_to_narrative()
            # (see that function and build_investigation_threat_intel_context()
            # above) — the four existing TI-owned keys below are unchanged.
            "threat_intelligence_summary": build_investigation_threat_intel_context(threat_intel_result),
            "threat_intelligence_enrichment": threat_intel_result.get("threat_intelligence") or threat_intel_result.get("enriched_alert"),
            "enrichment_risk_score": threat_intel_result.get("enrichment_risk_score"),
            "enrichment_risk_level": threat_intel_result.get("enrichment_risk_level"),
            "enrichment_risk_reasons": threat_intel_result.get("enrichment_risk_reasons"),
        } if threat_intel_result else {}),
    }

    # Phase 2B: the bounded Investigation Context Brief, rendered first by
    # ingest_pipeline. The structured keys above stay in the queued JSON
    # (metadata, correlation, sidecar) unchanged.
    raw_alert["investigation_context_brief"] = build_investigation_context_brief(
        triage_result, incident, prune_empty(raw_alert), entities,
        threat_intel_result=threat_intel_result, parsing_result=parsing_result,
        supplement=supplement)

    return prune_empty(raw_alert), entities



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


# [FYP-SECTION] Deep-dive context (canonical audit Phase 2C)
# -----------------------------------------------------------------------------
# What the Triage deep-dive (deep_triage_supplement) reads when Investigation
# reports evidence gaps. It previously read json.dumps(raw_incident,
# indent=2)[:12000] -- a prefix of pretty-printed JSON (3.5% of INC-52970)
# with no Parsing, Triage or Threat Intelligence context. It now reads, in
# priority order:
#   1. the evidence gaps (rendered first by deep_triage_supplement itself);
#   2. the SAME Investigation Context Brief Investigation received, from the
#      same builder (_assemble_investigation_alert ->
#      build_investigation_context_brief), without a deep-dive answers
#      section -- one canonical-context implementation, nothing to drift;
#   3. a deterministic digest of the raw NetWitness evidence the brief does
#      not carry: raw-evidence availability, gap focus, TI coverage of the
#      case entities, incident-level NetWitness metadata, and the alerts --
#      identical alerts collapsed, gap-relevant alerts first, packed whole
#      into the remaining budget with explicit omission counts.
# Budget: DEEP_DIVE_CONTEXT_BUDGET characters for 2 + 3 together -- the size
# of the previous raw cut, deliberately not raised. The brief is bounded by
# its own section budgets (< ~7.1k); the digest receives the remainder.
# Omitted material is always counted and labelled; nothing is cut silently.
DEEP_DIVE_CONTEXT_BUDGET = 12000
DEEP_DIVE_HEADER = "=== DEEP-DIVE EVIDENCE DIGEST (raw NetWitness fields; deterministic; bounded) ==="
DEEP_DIVE_FOOTER = "=== END DEEP-DIVE EVIDENCE DIGEST ==="
DEEP_DIVE_TRUNCATION_MARKER = "[raw evidence section truncated at configured budget]"
DEEP_DIVE_EVENT_SCAN = 50          # events read per alert (same cap as _sub_alert_entry)
DEEP_DIVE_VALUES_PER_FIELD = 4
DEEP_DIVE_LINE_MAX = 360
DEEP_DIVE_GROUP_MAX = 1100         # one verbose alert group can never crowd out the rest
DEEP_DIVE_BLOCK_BUDGETS = {"RAW EVIDENCE AVAILABILITY": 900, "GAP FOCUS": 500,
                           "TI COVERAGE OF CASE ENTITIES": 700,
                           "INCIDENT METADATA (NetWitness)": 700}
DEEP_DIVE_NOT_CHECKED_EXAMPLES = 6

# Deterministic gap-topic -> evidence-category mapping (word-prefix keyword
# match; no model call, no semantic search).
_DEEP_DIVE_GAP_CATEGORIES = (
    ("process", ("process", "spawn", "command line", "command-line", "commandline", "cmd",
                 "powershell", "script", "execut", "parent", "child", "lineage", "binary",
                 "launch")),
    ("network", ("lateral", "horizontal", "vertical", "network", "connect", "traffic", "ip",
                 "port", "dns", "domain", "beacon", "c2", "command and control", "exfiltrat",
                 "communicat", "destination", "contacted", "remote")),
    ("file", ("file", "hash", "malware", "payload", "download", "attachment", "sha", "md5",
              "dropped")),
    ("user", ("user", "account", "privilege", "escalat", "credential", "logon", "login",
              "authenticat", "admin")),
    ("host", ("host", "endpoint", "device", "machine", "workstation", "operating system",
              "os", "asset")),
)
_DEEP_DIVE_GAP_RX = tuple(
    (cat, re.compile(r"\b(?:" + "|".join(re.escape(k) for k in kws) + ")", re.I))
    for cat, kws in _DEEP_DIVE_GAP_CATEGORIES)
_DEEP_DIVE_CATEGORY_ORDER = ("network", "process", "file", "user", "host", "event")

# Raw NetWitness event fields per category, labelled by their real field
# path. IPs, users, hostnames and domains come from _sub_alert_entry() (the
# Phase 2A semantics Investigation uses) and are not re-selected here.
_DEEP_DIVE_EVENT_FIELDS = {
    "network": ("from", "to", "service_name", "analysis_service", "analysis_session",
                "destination.device.geolocation.country",
                "destination.device.geolocation.organization",
                "destination.device.geolocation.domain", "source.device.geolocation.country",
                "port_src", "port_dst", "source.device.port", "destination.device.port"),
    "process": ("source.launch_argument", "destination.launch_argument", "param", "param_src",
                "param_dst", "cmdline", "command_line", "process", "process_name", "process_vid"),
    "file": ("source.filename", "source.path", "destination.filename", "destination.path",
             "directory", "source.file_SHA256", "source.hash", "destination.file_SHA256",
             "destination.hash", "data.filename", "data.hash", "analysis_file", "registry_key"),
    "user": ("source.user.email_address", "destination.user.email_address"),
    "host": ("operating_system", "device_type", "detector.product_name", "detector.ip_address",
             "alias_ip"),
    "event": ("type", "action", "category", "description", "attack_tactic", "attack_technique",
              "context"),
}
_DEEP_DIVE_PORT_FIELDS = {"port_src", "port_dst", "source.device.port", "destination.device.port"}
_DEEP_DIVE_LONG_FIELDS = {"source.launch_argument", "destination.launch_argument", "param",
                          "param_src", "param_dst", "cmdline", "command_line", "description"}
_DEEP_DIVE_EMPTY = {"", "unknown", "none", "null", "n/a", "-"}
# Shorter labels for the longest NetWitness paths (budget); all others are
# shown under their real field path.
_DEEP_DIVE_FIELD_LABELS = {
    "destination.device.geolocation.country": "destination geo country",
    "destination.device.geolocation.organization": "destination geo org",
    "destination.device.geolocation.domain": "destination geo domain",
    "source.device.geolocation.country": "source geo country",
}
# alertMeta keys already rendered as case entities by the brief.
_DEEP_DIVE_ALERT_META_IN_BRIEF = {"SourceIp", "DestinationIp", "User", "AdUser", "Hostname",
                                  "DnsDomain", "FileHash", "FileName"}
_DEEP_DIVE_INCIDENT_FIELDS = ("categories", "tactics", "techniques", "summary", "firstAlertTime",
                              "lastUpdated", "averageAlertRiskScore", "groupBySourceIp",
                              "groupByDestinationIp")
_DEEP_DIVE_SEVERITY_WORDS = {"low": 25.0, "medium": 50.0, "high": 75.0, "critical": 100.0}


def _dd_block(title: str, lines: list[str], budget: int) -> str:
    body = [f"[{title}]"] + [_brief_clip(line, DEEP_DIVE_LINE_MAX) for line in lines if line]
    text = "\n".join(body)
    if len(text) > budget:
        marker = f"\n[... {title} truncated at {budget} chars ...]"
        text = text[:budget - len(marker)].rstrip() + marker
    return text


def _dd_values(node, path: str) -> list[str]:
    """Scalar values at a dotted NetWitness field path (lists traversed),
    first-seen order; blanks/placeholders dropped, nothing invented."""
    current = [node]
    for part in path.split("."):
        nxt = []
        for item in current:
            if isinstance(item, dict):
                value = item.get(part)
                if isinstance(value, list):
                    nxt.extend(value)
                elif value is not None:
                    nxt.append(value)
        current = nxt
    out = []
    for value in current:
        if isinstance(value, (dict, list)):
            continue
        text = str(value).strip()
        if text and text.lower() not in _DEEP_DIVE_EMPTY:
            out.append(text)
    return out


def _dd_field(label: str, values, limit: int = DEEP_DIVE_VALUES_PER_FIELD,
              value_max: int = 120) -> str | None:
    values = list(dict.fromkeys(str(v) for v in (values or []) if v not in (None, "")))
    if not values:
        return None
    shown = [_brief_clip(v, value_max) for v in values[:limit]]
    more = len(values) - len(shown)
    return f"{label}: {', '.join(shown)}" + (f" (+{more})" if more else "")


def _dd_scalar_text(value) -> str:
    if isinstance(value, dict):
        named = [str(value[k]) for k in ("parent", "name") if value.get(k) not in (None, "")]
        if named:
            return "/".join(named)
        return ", ".join(f"{k}={v}" for k, v in sorted(value.items())
                         if not isinstance(v, (dict, list)) and v not in (None, ""))
    return str(value)


def _deep_dive_gap_categories(gaps) -> dict:
    """{category: [gap ids]} in fixed category order."""
    found: dict = {}
    for gap in gaps or []:
        text = str(gap)
        gap_id = text.split(":", 1)[0].strip()[:40] if ":" in text else _brief_clip(text, 40)
        for cat, rx in _DEEP_DIVE_GAP_RX:
            if rx.search(text):
                found.setdefault(cat, []).append(gap_id)
    return {cat: found[cat] for cat, _ in _DEEP_DIVE_GAP_CATEGORIES if cat in found}


def _deep_dive_alert_digest(sub: dict) -> dict:
    """One NetWitness alert reduced to its identity plus per-category
    'field: values' parts (no case-level inheritance, nothing fabricated)."""
    entry = _sub_alert_entry(sub)
    alert_obj = sub.get("alert") if isinstance(sub.get("alert"), dict) else {}
    original = sub.get("originalAlert") if isinstance(sub.get("originalAlert"), dict) else {}
    events = alert_obj.get("events") or original.get("events") or sub.get("events") or []
    events = [ev for ev in events if isinstance(ev, dict)] if isinstance(events, list) else []
    scanned = events[:DEEP_DIVE_EVENT_SCAN]
    cats: dict = {cat: [] for cat in _DEEP_DIVE_CATEGORY_ORDER}
    for label, key in (("source IPs", "source_ips"), ("destination IPs", "destination_ips"),
                       ("domains", "domains")):
        cats["network"].append(_dd_field(label, entry.get(key)))
    cats["user"].append(_dd_field("users", entry.get("users")))
    cats["host"].append(_dd_field("hostnames", entry.get("hostnames")))
    # "from"/"to" already carry address:port, so the separate port fields and
    # the alert's host_summary are only shown when they are absent.
    has_endpoints = any(_dd_values(ev, "from") or _dd_values(ev, "to") for ev in scanned)
    for cat, paths in _DEEP_DIVE_EVENT_FIELDS.items():
        for path in paths:
            if has_endpoints and path in _DEEP_DIVE_PORT_FIELDS:
                continue
            values: list = []
            for ev in scanned:
                values.extend(_dd_values(ev, path))
            cats[cat].append(_dd_field(_DEEP_DIVE_FIELD_LABELS.get(path, path), values,
                                       value_max=240 if path in _DEEP_DIVE_LONG_FIELDS else 120))
    if not has_endpoints:
        cats["network"].append(_dd_field("alert.host_summary", [entry.get("connection_summary")]))
    cats = {cat: [p for p in parts if p] for cat, parts in cats.items()}
    return {
        "entry": entry,
        "categories": {cat: parts for cat, parts in cats.items() if parts},
        "events_total": len(events),
        "events_scanned": len(scanned),
    }


def _deep_dive_severity_value(severity) -> float:
    try:
        return float(severity)
    except (TypeError, ValueError):
        return _DEEP_DIVE_SEVERITY_WORDS.get(str(severity or "").strip().lower(), -1.0)


def _deep_dive_alert_groups(raw_alerts: list, gap_cats: dict) -> list[dict]:
    """Identical alerts (same title/severity/source/types/fields, differing
    only in id and time) collapse into one group; groups are ranked by gap
    relevance, then NetWitness severity, then earliest time, then position."""
    groups: dict = {}
    for index, sub in enumerate(raw_alerts):
        if not isinstance(sub, dict):
            continue
        digest = _deep_dive_alert_digest(sub)
        entry = digest["entry"]
        key = json.dumps([entry.get("title"), entry.get("severity"), entry.get("detection_source"),
                          entry.get("alert_types"), digest["categories"]], sort_keys=True, default=str)
        group = groups.get(key)
        if group is None:
            group = groups[key] = {"index": index, "digest": digest, "ids": [], "times": [],
                                   "count": 0, "events_truncated": False}
        group["count"] += 1
        if entry.get("alert_id"):
            group["ids"].append(str(entry["alert_id"]))
        if entry.get("timestamp"):
            group["times"].append(str(entry["timestamp"]))
        if digest["events_total"] > digest["events_scanned"]:
            group["events_truncated"] = True
    ordered = list(groups.values())
    for group in ordered:
        present = group["digest"]["categories"]
        group["relevance"] = sum(len(ids) for cat, ids in gap_cats.items() if cat in present)

    def rank(group):
        times = sorted(group["times"])
        return (-group["relevance"],
                -_deep_dive_severity_value(group["digest"]["entry"].get("severity")),
                times[0] if times else "~", group["index"])
    return sorted(ordered, key=rank)


def _deep_dive_render_group(number: int, group: dict, gap_cats: dict) -> str:
    entry = group["digest"]["entry"]
    times = sorted(group["times"])
    when = (times[0] if len(set(times)) <= 1 else f"{times[0]} .. {times[-1]}") if times else "time not provided"
    label = f"[A{number}]" + (f" ×{group['count']} identical alerts" if group["count"] > 1 else "")
    head = [f"\"{entry.get('title') or 'title not provided'}\"",
            f"NetWitness severity {entry.get('severity') if entry.get('severity') is not None else 'not provided'}",
            when]
    if entry.get("detection_source"):
        head.append(f"source {entry['detection_source']}")
    if entry.get("alert_types"):
        head.append("types " + ", ".join(map(str, entry["alert_types"])))
    if group["ids"]:
        head.append(f"id {group['ids'][0]}" + (f" (+{len(group['ids']) - 1} more ids)"
                                               if len(group["ids"]) > 1 else ""))
    lines = [_brief_clip(f"{label} " + " | ".join(head), DEEP_DIVE_LINE_MAX)]
    present = group["digest"]["categories"]
    order = sorted(present, key=lambda cat: (-len(gap_cats.get(cat, [])),
                                             _DEEP_DIVE_CATEGORY_ORDER.index(cat)))
    body = ["  " + _brief_clip(f"{cat}: " + "; ".join(present[cat]), DEEP_DIVE_LINE_MAX) for cat in order]
    if not body:
        body = ["  (no event-level fields recorded for this alert)"]
    if group["events_truncated"]:
        body.append(f"  (fields read from the first {DEEP_DIVE_EVENT_SCAN} events of "
                    f"{group['digest']['events_total']})")
    used = len(lines[0])
    for i, line in enumerate(body):
        remaining = len(body) - i
        marker = f"  (+{remaining} more field lines for this alert group omitted at the per-alert budget)"
        if used + 1 + len(line) + (1 + len(marker) if remaining > 1 else 0) > DEEP_DIVE_GROUP_MAX:
            lines.append(marker)
            break
        lines.append(line)
        used += 1 + len(line)
    return "\n".join(lines)


def _deep_dive_raw_state(incident: dict, case_id) -> tuple[str, list[str]]:
    """Explicit raw-evidence state + availability lines. States:
    raw_incident_unavailable / provider_failed / unverified (slim marker but
    alerts attached) / unavailable (slim copy) / not_fetched /
    no_alerts_observed / fetched."""
    if not incident or not (incident.get("id") or incident.get("incidentId")):
        return "raw_incident_unavailable", [
            f"RAW INCIDENT UNAVAILABLE: the raw NetWitness incident record for {case_id} could not "
            "be loaded for this run. No alert-level fields can be shown; missing fields below are "
            "NOT evidence of absence. Answer from the canonical stage results above."]
    avail = _data_availability(incident)
    alerts = incident.get("alerts")
    count = len(alerts) if isinstance(alerts, list) else 0
    if incident.get("alerts_fetch_error"):
        lines = [f"PROVIDER FAILED: the NetWitness alert fetch failed ({_brief_clip(incident['alerts_fetch_error'], 160)}). "
                 "Alert-level evidence was NOT obtained; its absence is NOT evidence of absence."]
        if count:
            lines.append(f"{count} alert(s) were nonetheless attached and are shown below (may be incomplete).")
        return "provider_failed", lines
    if avail.get("incident_source") == "sqlite_slim" and count:
        # Slim marker present (alerts were stripped from a stored copy at some
        # point) yet alerts are attached again: shown, completeness unknown.
        return "unverified", [
            f"NetWitness alerts: {count} alert(s) attached and shown below, but this incident copy "
            f"carries the stored-slim marker (_alerts_stripped={incident.get('_alerts_stripped')}) -- "
            "completeness is NOT verified; missing fields are not evidence of absence."]
    if avail.get("incident_source") == "sqlite_slim":
        return "unavailable", [
            "EVIDENCE UNAVAILABLE: only the stored slim incident copy exists (NetWitness alert "
            "details were stripped). Alert-level fields cannot be shown; their absence is NOT "
            "evidence of absence."]
    if not isinstance(alerts, list):
        events = incident.get("events")
        if isinstance(events, list) and events:
            return "fetched", [f"NetWitness alerts: not attached; {len(events)} incident event(s) are shown below."]
        return "not_fetched", [
            "NOT FETCHED: no NetWitness alert fetch was recorded for this incident; only "
            "incident-level metadata is available. Absence of alert fields is NOT evidence of absence."]
    if not alerts:
        return "no_alerts_observed", [
            "NO EVIDENCE OBSERVED at alert level: the NetWitness alert fetch succeeded and the "
            "incident has 0 alerts."]
    return "fetched", [f"NetWitness alerts fetched: {count} alert(s)."]


def _deep_dive_ti_coverage(entities: dict, ti: dict | None) -> list[str]:
    """Cross-check of the case's IP/domain/hash entities (from the shared
    brief builder) against the TI result: enriched / excluded / skipped /
    NOT CHECKED (no TI record at all)."""
    candidates: dict = {}
    for role, label in (("source_ips", "source IP"), ("destination_ips", "destination IP"),
                        ("domains", "domain"), ("hashes", "hash")):
        for value in (entities.get(role) or {}):
            candidates.setdefault(str(value), [])
            if label not in candidates[str(value)]:
                candidates[str(value)].append(label)
    if not candidates:
        return ["No IP, domain or hash entities were recorded for this case."]
    if not ti:
        return [f"No TI result: all {len(candidates)} case IP/domain/hash indicators are NOT CHECKED "
                "(not looked up -- NOT evidence of benign)."]
    bundle = ti.get("threat_intelligence") if isinstance(ti.get("threat_intelligence"), dict) else {}
    indicators = bundle.get("indicators")
    status_by_value: dict = {}
    if isinstance(indicators, list):
        for ind in indicators:
            if isinstance(ind, dict) and ind.get("value") not in (None, ""):
                status_by_value.setdefault(str(ind["value"]).lower(), str(ind.get("status") or "status not recorded"))
    else:
        iocs = bundle.get("iocs") if isinstance(bundle.get("iocs"), dict) else {}
        for key in ("ip_indicators", "domain_indicators", "file_hashes"):
            for value in iocs.get(key) or []:
                status_by_value.setdefault(str(value).lower(), "in legacy TI result")
        if iocs.get("file_hash"):
            status_by_value.setdefault(str(iocs["file_hash"]).lower(), "in legacy TI result")
    counts: dict = {}
    not_checked = []
    for value, labels in candidates.items():
        status = status_by_value.get(value.lower())
        if status is None:
            not_checked.append(f"{value} ({'/'.join(labels)})")
            status = "NOT CHECKED"
        counts[status] = counts.get(status, 0) + 1
    lines = [f"Case IP/domain/hash indicators vs TI result ({len(candidates)}): "
             + ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))]
    if not_checked:
        shown = not_checked[:DEEP_DIVE_NOT_CHECKED_EXAMPLES]
        more = len(not_checked) - len(shown)
        lines.append("NOT CHECKED by TI (no TI record -- NOT evidence of benign): " + "; ".join(shown)
                     + (f" (+{more} more)" if more else ""))
    return lines


def _deep_dive_incident_metadata(incident: dict) -> list[str]:
    lines = []
    for key in _DEEP_DIVE_INCIDENT_FIELDS:
        value = incident.get(key)
        if value in (None, "", [], {}):
            continue
        values = value if isinstance(value, list) else [value]
        line = _dd_field(key, [_dd_scalar_text(v) for v in values], limit=5,
                         value_max=240 if key == "summary" else 120)
        if line:
            lines.append(line)
    meta = incident.get("alertMeta") if isinstance(incident.get("alertMeta"), dict) else {}
    for key in sorted(meta):
        if key in _DEEP_DIVE_ALERT_META_IN_BRIEF:
            continue
        value = meta[key]
        values = value if isinstance(value, list) else [value]
        line = _dd_field(f"alertMeta.{key}", [_dd_scalar_text(v) for v in values if v not in (None, "")], limit=5)
        if line:
            lines.append(line)
    return lines


def build_deep_dive_context(triage_result: dict, incident: dict, gaps: list, *,
                            case_id: str | None = None,
                            threat_intel_result: dict | None = None,
                            parsing_result: dict | None = None) -> tuple[str, dict]:
    """Deterministic, bounded deep-dive input: the shared Investigation
    Context Brief + the raw-evidence digest (see section comment above).
    Returns (context text, measurement metadata). Pure: same inputs -> same
    text. Raises ValueError if the canonical results do not belong to
    `case_id` (C1: the deep-dive must examine the Investigation subject)."""
    incident = incident if isinstance(incident, dict) else {}
    alert, entities = _assemble_investigation_alert(
        triage_result, incident, threat_intel_result=threat_intel_result,
        parsing_result=parsing_result)
    subject = str(case_id or alert.get("incident_id") or "")
    if case_id is not None:
        for label, value in (("Triage result", alert.get("incident_id")),
                             ("raw incident", incident.get("id") or incident.get("incidentId"))):
            if value not in (None, "") and str(value) != str(case_id):
                raise ValueError(f"deep-dive context identity mismatch: {label} is for {value}, "
                                 f"Investigation subject is {case_id}")
    brief = alert.get("investigation_context_brief") or ""
    gap_cats = _deep_dive_gap_categories(gaps)
    raw_state, avail_lines = _deep_dive_raw_state(incident, subject or "this case")
    raw_alerts = incident.get("alerts") if isinstance(incident.get("alerts"), list) else None
    if raw_alerts is None and isinstance(incident.get("events"), list):
        raw_alerts = incident["events"]
    raw_alerts = raw_alerts or []
    groups = _deep_dive_alert_groups(raw_alerts, gap_cats) if raw_state != "raw_incident_unavailable" else []
    alerts_total = sum(g["count"] for g in groups)
    skipped_entries = len(raw_alerts) - alerts_total

    if groups and gap_cats:
        for cat in gap_cats:
            if not any(cat in g["digest"]["categories"] for g in groups):
                avail_lines.append(
                    f"NO EVIDENCE OBSERVED for {cat} fields in any of the {alerts_total} alert(s) "
                    + ("(fields absent from the fetched telemetry, not omitted)." if raw_state == "fetched"
                       else "(alert set completeness not verified -- not proof of absence)."))
    if any(g["events_truncated"] for g in groups):
        avail_lines.append(f"Event fields are read from the first {DEEP_DIVE_EVENT_SCAN} events of each alert.")
    if skipped_entries:
        avail_lines.append(f"{skipped_entries} non-structured alert entr(y/ies) could not be read.")

    if gap_cats:
        focus = ["Evidence categories requested by the gaps (alerts carrying them are listed first): "
                 + "; ".join(f"{cat} ({', '.join(ids)})" for cat, ids in gap_cats.items())]
    else:
        focus = ["No gap matched a field category; alerts are ordered by NetWitness severity, then time."]
    blocks = [DEEP_DIVE_HEADER,
              _dd_block("RAW EVIDENCE AVAILABILITY", avail_lines, DEEP_DIVE_BLOCK_BUDGETS["RAW EVIDENCE AVAILABILITY"]),
              _dd_block("GAP FOCUS", focus, DEEP_DIVE_BLOCK_BUDGETS["GAP FOCUS"]),
              _dd_block("TI COVERAGE OF CASE ENTITIES", _deep_dive_ti_coverage(entities, threat_intel_result),
                        DEEP_DIVE_BLOCK_BUDGETS["TI COVERAGE OF CASE ENTITIES"])]
    meta_lines = _deep_dive_incident_metadata(incident)
    if meta_lines:
        blocks.append(_dd_block("INCIDENT METADATA (NetWitness)", meta_lines,
                                DEEP_DIVE_BLOCK_BUDGETS["INCIDENT METADATA (NetWitness)"]))

    # Pack whole alert groups, in rank order, into what the budget leaves.
    rendered = [_deep_dive_render_group(i + 1, g, gap_cats) for i, g in enumerate(groups)]
    fixed_len = len(brief) + 1 + sum(len(b) + 1 for b in blocks) + len(DEEP_DIVE_FOOTER)
    omitted_reserve = 2 * DEEP_DIVE_LINE_MAX + 120    # summary + omitted-titles lines
    alert_budget = DEEP_DIVE_CONTEXT_BUDGET - fixed_len - omitted_reserve - len("[NETWITNESS ALERTS]") - 2
    kept, used = [], 0
    for block in rendered:
        if used + len(block) + 1 > alert_budget:
            break
        kept.append(block)
        used += len(block) + 1
    shown_alerts = sum(g["count"] for g in groups[:len(kept)])
    omitted_groups = groups[len(kept):]
    omitted_alerts = alerts_total - shown_alerts
    if groups:
        summary = (f"Showing {shown_alerts} of {alerts_total} alerts as {len(kept)} of {len(groups)} "
                   "distinct alert groups (identical alerts collapsed)")
        if omitted_alerts:
            summary += (f" (+{omitted_alerts} more alerts in {len(omitted_groups)} groups OMITTED at the "
                        "context budget -- not shown, NOT absent)")
        alert_lines = [summary, *kept]
        if omitted_groups:
            titles = [f"{g['digest']['entry'].get('title') or 'title not provided'}"
                      + (f" ×{g['count']}" if g["count"] > 1 else "") for g in omitted_groups]
            alert_lines.append(_brief_clip(f"(+{omitted_alerts} more alerts OMITTED at the context budget; "
                                           f"titles: {'; '.join(titles)})", DEEP_DIVE_LINE_MAX))
        blocks.append("[NETWITNESS ALERTS]\n" + "\n".join(alert_lines))
    blocks.append(DEEP_DIVE_FOOTER)
    digest = "\n".join(blocks)

    budget_exceeded = len(brief) + 1 + len(digest) > DEEP_DIVE_CONTEXT_BUDGET
    if budget_exceeded:   # safety net only -- the packing above keeps within budget
        room = max(0, DEEP_DIVE_CONTEXT_BUDGET - len(brief) - 2 - len(DEEP_DIVE_TRUNCATION_MARKER)
                   - len(DEEP_DIVE_FOOTER) - 1)
        digest = (digest[:room].rstrip() + "\n" + DEEP_DIVE_TRUNCATION_MARKER + "\n" + DEEP_DIVE_FOOTER)
    text = brief + "\n" + digest
    meta = {
        "budget": DEEP_DIVE_CONTEXT_BUDGET,
        "context_chars": len(text),
        "brief_chars": len(brief),
        "digest_chars": len(digest),
        "raw_state": raw_state,
        "alerts_total": alerts_total,
        "alerts_shown": shown_alerts,
        "alerts_omitted": omitted_alerts,
        "alert_groups_total": len(groups),
        "alert_groups_shown": len(kept),
        "gap_categories": {cat: list(ids) for cat, ids in gap_cats.items()},
        "budget_exceeded": budget_exceeded,
    }
    return text, meta


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
    status, missing_evidence, and — since Phase 3 — the structured
    execution_trace flat-alias set by run_investigation() whenever
    investigation_analysis.json validated). Output: list of up to 8 gap
    description strings, or [] if investigation was sufficient.

    [FYP-EVALUATOR] Phase 3 (canonical Investigation Result contract
    migration): the (step_id, instruction, status) rows this function
    reasons over now come from the structured execution_trace when
    run_investigation() populated it (investigation_source ==
    "structured_json"), instead of regex-parsing the Markdown playbook
    table. The threshold comparison, NOT_MET interpretation, high-value gap
    prioritisation, completed_limited/missing_evidence handling, and the
    8-gap cap are byte-for-byte unchanged — only where the rows come from
    has changed. When execution_trace is absent (Markdown-fallback path),
    the original _PLAYBOOK_ROW_RE regex path runs exactly as before.
    """
    try:
        threshold = float(os.environ.get("WORKFLOW_FEEDBACK_THRESHOLD", "0.4"))
    except ValueError:
        threshold = 0.4
    threshold = max(0.0, min(threshold, 1.0))  # clamp to [0, 1]

    gaps: list[str] = []
    structured_trace = inv.get("execution_trace")
    if structured_trace:
        rows = [
            (str(step.get("step_id") or ""), str(step.get("instruction") or ""),
             str(step.get("status") or ""))
            for step in structured_trace
        ]
    else:
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
            from agents.triage import deep_triage_supplement
            # Phase 2C: the deep-dive reads the same canonical brief as
            # Investigation plus a bounded raw-evidence digest -- not a
            # prefix of the pretty-printed raw incident.
            dd_context, dd_meta = build_deep_dive_context(
                triage_result, incident, gaps, case_id=inc_id,
                threat_intel_result=threat_intel_result,
                parsing_result=parsing_result)
            _log("FEEDBACK", f"deep-dive context {dd_meta['context_chars']}/{dd_meta['budget']} chars; "
                             f"raw evidence {dd_meta['raw_state']}; alerts shown "
                             f"{dd_meta['alerts_shown']}/{dd_meta['alerts_total']}")
            supp = deep_triage_supplement(incident, gaps, investigation_context=dd_context)
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
            threat_intel_result=threat_intel_result,
            # Phase 2A: the feedback pass keeps the same canonical Parsing
            # evidence as pass 1 (it was previously dropped here).
            parsing_result=parsing_result)
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

    tkt_db = ROOT / "soc_db" / "soc_tickets.db"
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

    pl_db = ROOT / "soc_db" / "soc_pipeline.db"
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


# Filesystem mtime tolerance when judging whether an Investigation artefact was
# written by THIS run -- the same 1s slack run_investigation() has always
# applied to incident_data.json.
_INVESTIGATION_FRESHNESS_SLACK_SECONDS = 1.0
# Written by agents/investigation/main.py::write_investigation_run_manifest()
# whenever the workflow supplies INVESTIGATION_RUN_NONCE.
INVESTIGATION_RUN_MANIFEST = "investigation_run_manifest.json"


def _written_this_run(path: Path, started: float) -> bool:
    """True when `path` exists and was (re)written at or after this run's
    subprocess start (minus mtime-granularity slack)."""
    try:
        return path.stat().st_mtime >= started - _INVESTIGATION_FRESHNESS_SLACK_SECONDS
    except OSError:
        return False


def _load_structured_investigation_analysis(
    target: Path, case_id: str, started: float
) -> tuple[InvestigationAgentOutput | None, str, str]:
    """[FYP-FUNCTION] Structured-JSON read path, with canonical case identity (C1).

    Loads `target/investigation_analysis.json` (written by
    agents/investigation/main.py's write_investigation_analysis_json()) and
    validates it against the canonical InvestigationAgentOutput contract.

    Returns (validated_output, status, detail) where status is:
      - "ok": written by this run, contract-valid, and its incident_id is
        EXACTLY the workflow case `case_id`;
      - "unavailable": missing, not written by this run (stale), malformed,
        or contract-invalid -- a format/availability problem, for which the
        caller may still use a fresh, identity-verified Markdown report;
      - "mismatch": a valid analysis whose canonical incident_id is another
        case. A data-integrity failure: the caller must NOT fall back to
        Markdown from the same folder.

    Membership of `case_id` in the folder's alert cluster is evidence, not
    identity, and is deliberately not sufficient here. Never raises.
    """
    json_path = target / "investigation_analysis.json"
    if not json_path.exists():
        _log("INVESTIGATION", f"{target.name}: investigation_analysis.json "
                              f"does not exist, falling back to Markdown "
                              f"reconstruction")
        return None, "unavailable", "investigation_analysis.json does not exist"
    if not _written_this_run(json_path, started):
        _log("INVESTIGATION", f"{target.name}: investigation_analysis.json "
                              f"was not written by this run (stale), falling "
                              f"back to Markdown reconstruction")
        return None, "unavailable", "investigation_analysis.json is stale"
    try:
        raw_text = json_path.read_text(encoding="utf-8")
        raw = json.loads(raw_text) if raw_text.strip() else None
    except Exception as exc:
        _log("INVESTIGATION", f"{target.name}: investigation_analysis.json "
                              f"is malformed or unreadable JSON, falling "
                              f"back to Markdown reconstruction: {exc}")
        return None, "unavailable", "investigation_analysis.json is malformed"
    if not isinstance(raw, dict):
        _log("INVESTIGATION", f"{target.name}: investigation_analysis.json "
                              f"is malformed or unreadable JSON (did not "
                              f"contain a JSON object), falling back to "
                              f"Markdown reconstruction")
        return None, "unavailable", "investigation_analysis.json is not a JSON object"
    try:
        agent_output = InvestigationAgentOutput.model_validate(raw)
    except Exception as exc:
        _log("INVESTIGATION", f"{target.name}: investigation_analysis.json "
                              f"failed contract validation, falling back to "
                              f"Markdown reconstruction: {exc}")
        return None, "unavailable", "investigation_analysis.json failed contract validation"
    if str(agent_output.incident_id) != str(case_id):
        detail = (f"investigation_analysis.incident_id is {agent_output.incident_id!r} "
                  f"but the workflow case is {str(case_id)!r}")
        _log("INVESTIGATION", f"{target.name}: REJECTED -- {detail}")
        return None, "mismatch", detail
    _log("INVESTIGATION", f"{target.name}: using validated structured "
                          f"investigation_analysis.json (investigation_source="
                          f"structured_json)")
    return agent_output, "ok", ""


def _check_investigation_run_manifest(target: Path, case_id: str,
                                      run_nonce: str) -> tuple[str, str, str]:
    """Strongest freshness/identity proof the agent provides: a manifest
    binding this subprocess invocation's nonce, its subject and the SHA-256
    of every report it wrote. Returns (status, kind, detail) with status
    "absent" (older agent / fake -- mtime freshness still applies), "ok", or
    "rejected" (kind: "stale" | "mismatch" | "tampered")."""
    path = target / INVESTIGATION_RUN_MANIFEST
    if not path.exists():
        return "absent", "", ""
    manifest = _read_json(path, None)
    if not isinstance(manifest, dict):
        return "rejected", "tampered", f"{INVESTIGATION_RUN_MANIFEST} is unreadable"
    if manifest.get("run_nonce") != run_nonce:
        return "rejected", "stale", (f"{INVESTIGATION_RUN_MANIFEST} belongs to a "
                                     "different Investigation run")
    if str(manifest.get("subject_id") or "") != str(case_id):
        return "rejected", "mismatch", (f"run manifest subject is "
                                        f"{manifest.get('subject_id')!r} but the "
                                        f"workflow case is {str(case_id)!r}")
    for name, digest in (manifest.get("files") or {}).items():
        try:
            actual = hashlib.sha256((target / str(name)).read_bytes()).hexdigest()
        except OSError:
            actual = None
        if actual != digest:
            return "rejected", "tampered", f"{name} does not match the run manifest"
    return "ok", "", ""


def _evaluate_investigation_candidate(target: Path, case_id: str, started: float,
                                      run_nonce: str) -> dict:
    """Decide whether one Incident-* folder written by this run carries an
    Investigation output whose canonical identity is the workflow case.
    Returns {"valid", "kind" ("ok"|"mismatch"|"stale"|"tampered"|
    "unverifiable"), "detail", "agent_output", "source", "narrative"}."""
    def _invalid(kind: str, detail: str) -> dict:
        return {"valid": False, "kind": kind, "detail": detail,
                "agent_output": None, "source": None, "narrative": ""}

    manifest_status, manifest_kind, manifest_detail = _check_investigation_run_manifest(
        target, case_id, run_nonce)
    if manifest_status == "rejected":
        return _invalid(manifest_kind, manifest_detail)

    md_path = target / "final_analysis_report.md"
    md_fresh = _written_this_run(md_path, started)
    narrative = md_path.read_text(encoding="utf-8") if md_path.exists() else ""
    header_id = wss.investigation_report_subject(narrative) if md_fresh else None

    agent_output, status, detail = _load_structured_investigation_analysis(
        target, case_id, started)
    if status == "mismatch":
        return _invalid("mismatch", detail)
    if header_id is not None and header_id != str(case_id):
        return _invalid("mismatch", f"Investigation report header id is {header_id!r} "
                                    f"but the workflow case is {str(case_id)!r}")
    if status == "ok":
        # A stale report from an earlier run is never presented as this run's.
        return {"valid": True, "kind": "ok", "detail": "", "agent_output": agent_output,
                "source": "structured_json", "narrative": narrative if md_fresh else ""}

    # Structured output genuinely unavailable -> Markdown fallback, only for a
    # report written by THIS run whose canonical header is exactly the case.
    if not narrative:
        return _invalid("unverifiable", f"{detail}; no Investigation report was written")
    if not md_fresh:
        return _invalid("stale", f"{detail}; final_analysis_report.md was not written by this run")
    if header_id is None:
        return _invalid("unverifiable", f"{detail}; final_analysis_report.md has no canonical "
                                        "'INVESTIGATION SUMMARY: <case>' header")
    return {"valid": True, "kind": "ok", "detail": "", "agent_output": None,
            "source": "markdown_fallback", "narrative": narrative}


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
        incident_id: the workflow case this investigation was launched for —
            its canonical identity. Sent to the agent as
            INVESTIGATION_SUBJECT_ID; the accepted output's canonical id
            (structured incident_id, else this run's report header) must
            equal it exactly. Cluster membership (incident_data.json
            raw_alerts) only selects candidate folders written by this run;
            exactly one candidate with a matching identity is accepted.
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
    started = time.time()
    # Binds every artefact this subprocess writes to THIS invocation (see
    # _check_investigation_run_manifest()).
    run_nonce = uuid.uuid4().hex

    _env = {**_openai_compat_env(), "OPENAI_SEED": _llm_seed(),
            # Canonical case identity (C1): the agent may correlate/merge this
            # case with historical incidents for evidence, but the analysis
            # it writes must identify THIS workflow case as its subject.
            "INVESTIGATION_SUBJECT_ID": str(incident_id),
            "INVESTIGATION_RUN_NONCE": run_nonce,
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

    # Result selection (C1). A candidate is an Incident-* correlation folder
    # whose incident_data.json was written by THIS run and lists this case
    # among its clustered alerts (evidence membership). It is VALID only if
    # its Investigation output's canonical identity is exactly this case.
    # Exactly one valid candidate is accepted; zero or several fail -- the old
    # "first sorted folder containing the case" rule is gone.
    case_id = str(incident_id)
    reports_dir = INV_DIR / "incident_reports"
    candidates: list[tuple[Path, dict]] = []
    for folder in sorted(reports_dir.glob("Incident-*")):
        data_file = folder / "incident_data.json"
        # MERGE into an existing incident rewrites incident_data.json without
        # changing the folder, so freshness is judged on the data file itself.
        if not _written_this_run(data_file, started):
            continue
        data = _read_json(data_file, {})
        raw_ids = {str(a.get("id")) for a in (data.get("raw_alerts") or [])
                   if isinstance(a, dict)}
        if case_id in raw_ids:
            candidates.append((folder, data))

    if not candidates:
        result["error"] = (run.get("stderr") or "").strip()[-1500:] or \
                          "Investigation run produced no incident folder for this alert."
        return result

    evaluations = [(folder, data, _evaluate_investigation_candidate(
        folder, case_id, started, run_nonce)) for folder, data in candidates]
    valid = [item for item in evaluations if item[2]["valid"]]
    if len(valid) != 1:
        if valid:
            error = (f"investigation_output_ambiguous: {len(valid)} correlation folders "
                     f"({', '.join(f.name for f, _, _ in valid)}) each hold a valid "
                     f"Investigation output for {case_id}; refusing to choose one")
        else:
            mismatches = [(f, e) for f, _, e in evaluations if e["kind"] == "mismatch"]
            reasons = "; ".join(f"{f.name}: {e['detail']}" for f, e in (
                mismatches or [(f, e) for f, _, e in evaluations]))
            error = (f"investigation_identity_mismatch: {reasons}" if mismatches
                     else f"investigation_output_unverifiable: {reasons}")
        _log("INVESTIGATION", f"REJECTED output for {case_id} -- {error}")
        result["error"] = error
        return result

    target, data, chosen = valid[0]
    narrative = chosen["narrative"]
    md_path = target / "final_analysis_report.md"

    meta = data.get("metadata") or {}
    sev = str(meta.get("severity") or "")
    if sev.lower() in ("low", "medium", "high", "critical"):
        sev = sev.capitalize()
    # Correlated evidence membership (never identity).
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

    # Prefer the structured, identity-verified investigation_analysis.json;
    # Markdown reconstruction is used only when structured output was
    # genuinely unavailable AND this run's report header names this case.
    agent_output = chosen["agent_output"]
    investigation_source = chosen["source"]

    if agent_output is not None:
        recommended_containment = list(agent_output.recommended_containment)
        mitre_mappings = [m.model_dump() for m in agent_output.mitre_mappings]
    else:
        # Structured, verbatim containment bullets recovered from the
        # narrative report (see _investigation_recommended_containment_actions)
        # — the reporting handoff's investigation_result.json needs this under
        # the Investigation agent's own field name so it is never mistaken for
        # "no recommendation supplied" and backfilled with generic text.
        recommended_containment = _investigation_recommended_containment_actions(narrative)
        # Structured MITRE ATT&CK TTP mappings recovered from the narrative
        # report (see _investigation_mitre_mappings) under the Investigation
        # agent's own field name (orchestrator.FinalIncidentAnalysis.
        # mitre_mappings) — without this, the reporting handoff's section 7.1
        # never sees the real per-technique timeline_phase/observed_evidence
        # and falls back to a generic technique-ID scan of unrelated fields.
        mitre_mappings = _investigation_mitre_mappings(narrative)

    result.update({
        "status": "completed" if run["success"] and narrative else "completed_limited",
        "incident_folder": target.name,
        "investigated_for": str(incident_id),
        "cluster_alert_ids": cluster_ids,
        "summary": summary,
        "severity": sev,
        "indicators": data.get("indicators") or [],
        "narrative_report": narrative,
        "recommended_containment": recommended_containment,
        "mitre_mappings": mitre_mappings,
        "artifacts": {
            "incident_folder": str(target),
            "incident_data": str(target / "incident_data.json"),
            # Never point at a report left over from an earlier run.
            "report_markdown": str(md_path) if _written_this_run(md_path, started) else None,
        },
        # Canonical envelope marker (Phase 3) -- NOT the orchestration/
        # approval "workflow stage status" tracked by state_store (that
        # remains entirely separate, see run_investigation_stage() /
        # complete_stage()). This only records which source populated this
        # result's Investigation-agent-owned fields.
        "workflow": {"investigation_source": investigation_source},
    })
    if agent_output is not None:
        # Full canonical Phase 1 contract payload, nested so it can be
        # consumed directly without reshaping existing flat consumers (see
        # Phase 3 migration plan, "Compatibility with existing flat
        # consumers"). Temporary flat-key aliases below duplicate the fields
        # existing/tested consumers need at the top level; this nested copy
        # is the single canonical source of the complete agent output.
        result["investigation_analysis"] = agent_output.model_dump(mode="json")
        # Temporary flat compatibility aliases (migration compatibility only,
        # not a second source of truth -- always derived from
        # result["investigation_analysis"] above). confidence/
        # severity_justification/confidence_justification/execution_trace had
        # no flat top-level key before Phase 3 (confidence was previously
        # dropped before the JSON handoff entirely); they are added here,
        # additively, only when the structured contract validated, so no
        # existing consumer reading their absence can regress.
        result["confidence"] = agent_output.confidence
        result["severity_justification"] = agent_output.severity_justification
        result["confidence_justification"] = agent_output.confidence_justification
        result["execution_trace"] = [step.model_dump() for step in agent_output.execution_trace]
        result["suggested_pivots"] = getattr(agent_output, "suggested_pivots", []) or []
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
    run_scoped = incident_id is not None and run_id is not None and reporting_stage_attempt is not None
    # Canonical audit Phase 6: never a fabricated case id or ticket. The
    # run-scoped workflow path hands off THIS case (incident_id) and refuses
    # a Triage result without a real ticket before anything is written; the
    # legacy standalone path uses the real identity it was given or fails.
    if run_scoped:
        inc_id = str(incident_id)
        if not str(ticket.get("unc") or "").strip():
            raise ValueError(f"missing_triage_ticket: the Triage result for case {inc_id!r} "
                             "carries no real ticket -- refusing the Reporting handoff")
    else:
        inc_id = (payload.get("incident_id") or ticket.get("incident_id")
                  or (incident or {}).get("id") or (incident or {}).get("incidentId"))
        if not inc_id:
            raise ValueError("missing_case_identity: neither the Triage result nor the incident "
                             "carries a case id -- refusing the Reporting handoff")
    title   = payload.get("incident_title") or ticket.get("title") or "SOC incident"
    # TKT-UNKNOWN can only arise on the legacy standalone path (see above).
    ticket_id = _safe_ticket_id(ticket.get("unc"))

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

    # Canonical audit Phase 3: Triage-owned fields only, named as Triage
    # names them. The Triage result carries no status field, so the status
    # is derived from what it actually contains (never a hard-coded
    # "completed"), and Triage's classification is its triage LEVEL -- it
    # is exposed as triage_level, never as a "severity" that Reporting could
    # mistake for the incident severity Investigation owns.
    if triage_result.get("error"):
        triage_status = "failed"
    elif ticket:
        triage_status = "completed"
    else:
        triage_status = "not_recorded"
    triage_doc = {
        "agent": "Triage Agent",
        "status": triage_status,
        "incident_id": inc_id,
        "alert_id": inc_id,
        "title": title,
        "triage_level": ticket.get("classification"),
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

    # Phase 3: Reporting's enriched_alert.json is Threat Intelligence's own
    # canonical enriched alert (Parsing's processed alert + TI enrichment),
    # identity-checked against this case. Only when TI produced none is the
    # legacy Triage/raw-incident reconstruction written -- explicitly marked
    # non-canonical, and without a Triage-derived "severity".
    case_for_identity = str(incident_id if incident_id is not None else inc_id)
    ti_enriched = (threat_intel_result or {}).get("enriched_alert") \
        if isinstance((threat_intel_result or {}).get("enriched_alert"), dict) else None
    ti_enriched_case = str((ti_enriched or {}).get("incident_id") or (ti_enriched or {}).get("alert_id") or "")
    if ti_enriched and (not ti_enriched_case or ti_enriched_case == case_for_identity):
        enriched = {**ti_enriched, "incident_id": ti_enriched.get("incident_id") or case_for_identity,
                    "enriched_alert_source": "threat_intelligence", "canonical": True}
    else:
        if ti_enriched:
            _log("HANDOFF", f"TI enriched_alert belongs to {ti_enriched_case!r}, expected "
                            f"{case_for_identity!r} -- not used; legacy reconstruction written")
        _ctx = _harvest_incident_context(incident)
        _mkv = payload.get("metakey_values") or {}
        enriched = {
            "incident_id": inc_id,
            "alert_title": title,
            "incident_summary": _first(incident.get("summary"), ticket.get("summary"),
                                       default=f"SOC alert requires review: {title}"),
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
            "enriched_alert_source": "reconstructed_triage_raw",
            "canonical": False,
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
            "investigation_result_source": "missing",
        }
    elif investigation_result:
        # Phase 3: the Reporting copy carries Investigation-owned fields
        # only. Previously the Triage MITRE tactic/technique was injected
        # here as Investigation's "mitre_mapping", and the correlation
        # cluster's indicator set (every case in the cluster) was aliased to
        # "iocs" -- Reporting presented both as this case's Investigation
        # findings. Triage MITRE stays in triage_result.json; the cluster
        # set stays available, labelled as correlated-cluster evidence.
        investigation_result = dict(investigation_result)
        if "indicators" in investigation_result:
            investigation_result["correlation_cluster_indicators"] = \
                investigation_result.pop("indicators") or []
        workflow_meta = investigation_result.get("workflow") \
            if isinstance(investigation_result.get("workflow"), dict) else {}
        investigation_result["investigation_result_source"] = \
            workflow_meta.get("investigation_source") or "not_recorded"
    # An empty ({}) Investigation result is passed through unchanged (no
    # sidecar enrichment, no injected fields), so Reporting's input loader
    # rejects it as a missing hard-required input instead of reporting on it.

    # ── Skills sidecar: fold the deterministic skill suite (Diamond Model,
    # unified triage verdict, IOC correlation, asset criticality, mitigation
    # coverage) into the reporting agent's report. Uses ONLY fields the reporting
    # context-builder already consumes; strictly additive/non-destructive; never
    # raises. Disable with NW_DISABLE_SKILLS_SIDECAR=1.
    #
    # Phase 4 (canonical Investigation Result contract migration -- TI wiring
    # fix): threat_intel_result is already available in this function's local
    # scope (persisted a few lines below) and every TI-aware collector
    # (_collect_diamond/_collect_verdict/_collect_mitigation/_collect_sop/
    # _collect_compliance/_collect_final_verdict, see skills_sidecar.py)
    # already accepts a ti_result argument -- it was simply never forwarded,
    # so those collectors always ran as if Threat Intelligence had never
    # completed. Every consumer of ti_result uses a None-safe `.get(...)`
    # or `x and x.get(...)` pattern (verified against diamond_model.py,
    # triage_verdict.py, mitigation_mapping.py, compliance_evidence.py [does
    # not read ti_result at all], final_verdict.py), and build_skills_context
    # itself is called inside this try/except -- so forwarding the real,
    # persisted result here is a pure data-availability fix with no control
    # flow change when threat_intel_result is None, same as before.
    try:
        if not investigation_result:
            raise ValueError("no Investigation result to enrich")
        import agents.investigation.skills_sidecar as skills_sidecar
        _bundle = skills_sidecar.build_skills_context(
            incident, triage_result=triage_result,
            investigation_result=investigation_result,
            ti_result=threat_intel_result)
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
        # (see HARD_REQUIRED_INPUT_KEYS). Canonical audit Phase 5: taken from
        # the canonical Parsing result for THIS case/run
        # (load_parsing_result_for_run(), which only returns a result whose
        # case identity resolves to a match for incident_id) — never from
        # whatever processed_alert.json happens to sit in a parsing
        # directory. The flat processed_alert content itself is unchanged.
        try:
            parsing_now = load_parsing_result_for_run(incident_id, run_id)
            processed_alert_data = (parsing_now or {}).get("processed_alert")
            if isinstance(processed_alert_data, dict) and processed_alert_data:
                _write_json(inputs / "processed_alert.json", processed_alert_data)
            else:
                _log("HANDOFF", f"no identity-verified Parsing result for {incident_id!r} "
                                f"run {run_id!r} — processed_alert.json not written; "
                                "Reporting will fail safely on this required input")
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
            # Phase 4: the CURRENT execution attempt of each gated stage, so
            # Reporting can bind workflow_approvals rows (approval_history
            # .json) to the attempt they decided -- an older attempt's
            # decision must never read as the current one.
            "triage_attempt": state_now.get("triage_attempt"),
            "investigation_attempt": state_now.get("investigation_attempt"),
            "reporting_attempt": state_now.get("reporting_attempt"),
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


REPORTING_WORKSPACE_RUN_SCOPED = "run_scoped"
REPORTING_WORKSPACE_LEGACY = "legacy"


def _reporting_workspace_mode(**parts) -> str:
    """[FYP-FUNCTION] [FYP-VALIDATION] Canonical audit Phase 7: decide the
    Reporting workspace mode from the EXPLICIT run-scoping arguments only.
    All given -> run_scoped; none given -> legacy; anything in between is a
    partial run-scoped configuration and is refused (ValueError) before a
    subprocess starts -- never a silent fall-back to the shared folders."""
    missing = [name for name, value in parts.items() if value is None]
    if not missing:
        return REPORTING_WORKSPACE_RUN_SCOPED
    if len(missing) == len(parts):
        return REPORTING_WORKSPACE_LEGACY
    raise ValueError("reporting_workspace_incomplete: run-scoped Reporting is missing "
                     + ", ".join(missing) + " -- refusing to fall back to the shared legacy workspace")


def run_reporting(ticket_id: str, timeout: int = 900,
                  run_stamp: str | None = None, line_cb=None, *,
                  reporting_input_dir: Path | None = None,
                  reporting_output_dir: Path | None = None,
                  run_id: str | None = None,
                  reporting_stage_attempt: int | None = None,
                  incident_id: str | None = None) -> dict:
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
            reporting_stage_attempt / incident_id: durable run-scoping — see
            docstring above and reporting_attempt_dir(). Canonical audit
            Phase 7: all five or none (see _reporting_workspace_mode()); the
            subprocesses are told the mode explicitly
            (REPORTING_WORKSPACE_MODE) together with the canonical case
            (SOC_CASE_ID), and a run-scoped run keeps its LLM narrative
            cache inside the attempt (REPORTING_LLM_CACHE_DIR).

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
    mode = _reporting_workspace_mode(
        reporting_input_dir=reporting_input_dir, reporting_output_dir=reporting_output_dir,
        run_id=run_id, reporting_stage_attempt=reporting_stage_attempt, incident_id=incident_id)
    llm_env = _openai_compat_env()
    has_llm = bool(os.environ.get("OPENAI_API_KEY", "").strip() or llm_env)
    output_dir = reporting_output_dir or (REP_DIR / "outputs")
    extra_env = {
        "REPORTING_WORKSPACE_MODE": mode,
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
    if mode == REPORTING_WORKSPACE_RUN_SCOPED:
        extra_env["SOC_CASE_ID"] = str(incident_id)
        # Attempt-local narrative cache: another attempt's cached narrative
        # is never read, even for identical inputs (location only -- the
        # narrative logic itself is unchanged).
        extra_env["REPORTING_LLM_CACHE_DIR"] = str(Path(reporting_output_dir) / "report_cache")
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
    if (mode == REPORTING_WORKSPACE_RUN_SCOPED and final.get("status") != "failed"
            and str(final.get("incident_id") or "") != str(incident_id)):
        # Defence in depth: the adapter already stamps the canonical case.
        final["status"] = "failed"
        final["error"] = (f"reporting_result_identity_mismatch: final_report.json names "
                          f"{final.get('incident_id')!r}, not {incident_id!r}")
    if final.get("status") != "failed":
        # Phase 7: a run-scoped export is told the canonical workflow case,
        # never whatever the result wrapper happened to resolve.
        exports = export_report_documents(
            incident_id if mode == REPORTING_WORKSPACE_RUN_SCOPED else final.get("incident_id"),
            reporting_output_dir=reporting_output_dir,
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
    mode = _reporting_workspace_mode(
        reporting_output_dir=reporting_output_dir, run_id=run_id,
        reporting_stage_attempt=reporting_stage_attempt,
        incident_id=incident_id if reporting_output_dir is not None else None)
    cmd = [sys.executable, str(REP_DIR / "adapters" / "export_documents.py")]
    if incident_id:
        cmd.append(str(incident_id))
    extra_env: dict[str, str] = {"REPORTING_WORKSPACE_MODE": mode}
    if mode == REPORTING_WORKSPACE_RUN_SCOPED:
        extra_env["SOC_CASE_ID"] = str(incident_id)
    if reporting_output_dir is not None:
        extra_env["REPORTING_OUTPUT_DIR"] = str(reporting_output_dir)
    if run_id is not None:
        extra_env["SOC_RUN_ID"] = run_id
    if reporting_stage_attempt is not None:
        extra_env["SOC_REPORTING_ATTEMPT"] = str(reporting_stage_attempt)
    run = _run_subprocess(cmd, cwd=REP_DIR, timeout=timeout, extra_env=extra_env)
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
        import integrations.netwitness.fetch_api as APIRetrieval
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

    # Mint/persist the run identity FIRST. wss.start_run() is a fast, local
    # DB write with no network I/O; enrich_incident_with_apiretrieval_fetch()
    # below can make live NetWitness HTTP calls (each with a 15-30s timeout)
    # when no matching disk export exists. Callers that observe the
    # incidents table for a freshly-published run_id (workflow/commands.py
    # ::_launch_fresh, which starts this function on a background thread and
    # polls for run_id to appear so it can return it to the HTTP caller)
    # would otherwise race against that enrichment latency and time out
    # before a run_id ever gets published.
    run_id = wss.start_run(inc_id, allow_retry=allow_retry)
    run_started = datetime.now()

    # Enrich incident with comprehensive raw alerts using APIRetrieval FETCH API / disk exports
    incident = enrich_incident_with_apiretrieval_fetch(incident, host=host, token=token)

    ctx: dict = {"incident": incident, "errors": {}, "stages": {}, "run_id": run_id}

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
            wss.set_last_error(inc_id, run_id, f"parsing failed: {str(exc)[:300]}")
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
        # run_parser_normalisation_for_dashboard() sets status to "failed"
        # both for genuine parser errors and when its own
        # parser_context_guard identity check refuses stale/mismatched
        # output (see agents/parsing/parser_normaliser.py) — in that case
        # `summary` already carries the real, specific reason, which is
        # far more useful to an analyst than the generic message below.
        failure_reason = (
            parsing_result.get("summary")
            if parsing_result.get("identity_validation", {}).get("passed") is False
            else None
        ) or (
            f"parser returned status "
            f"{parsing_result.get('status')!r} instead of 'completed'"
        )
        wss.set_last_error(inc_id, run_id, f"parsing failed: {failure_reason}"[:500])
        _emit("phase_error", "Parsing and Normalisation", "non-completed status")
        _log("PARSING", "FAILED: non-completed status")
        return ctx

    # ── Validate the Parsing -> Triage handoff ────────────────────────────────
    # Canonical audit Phase 5: validated BEFORE anything is persisted or the
    # stage is marked Complete, so a result whose case identity is a
    # mismatch or not_available is never recorded as a successful Parsing
    # result (this run's parsing_result_json is simply never written).
    try:
        validation = wv.validate_parsing_result(
            incident_id=inc_id, parsing_result=parsing_result, skip=use_mock_triage)
    except wv.ParsingValidationError as exc:
        ctx["stages"]["parsing"] = "failed"
        ctx["errors"]["parsing"] = str(exc)
        wss.set_parsing_status(inc_id, run_id, "Failed")
        wss.set_triage_status(inc_id, run_id, "Blocked")
        wss.set_workflow_status(inc_id, run_id, "Failed")
        wss.set_last_error(inc_id, run_id, f"parsing failed: {str(exc)[:300]}")
        _emit("phase_error", "Parsing and Normalisation", str(exc))
        _log("PARSING", f"VALIDATION FAILED: {exc}")
        return ctx
    ctx["parsing_validation"] = validation

    # Persist BEFORE marking the stage Complete: the case page's Parsing
    # tab (and any later resume) reads only parsing_result_json, not this
    # in-process ctx, so a persist failure here must not be allowed to
    # leave the stage looking "Complete" with nothing durable behind it —
    # that would let Continue to Triage / a rerun proceed on missing data.
    try:
        wss.save_parsing_result(inc_id, run_id, {
            # Canonical Parsing result envelope (canonical audit Phase 5):
            # run + case identity live HERE, not inside the alert objects.
            # incident_id is only present once case_identity resolved to a
            # match; load_parsing_result_for_run() re-resolves it from the
            # inline content below rather than trusting this claim.
            "run_id": run_id,
            "incident_id": (str(inc_id) if (validation.get("case_identity") or {}).get("status")
                            == CASE_IDENTITY_MATCH else None),
            "case_identity": validation.get("case_identity"),
            "input_shape": parsing_result.get("input_shape"),
            "raw_record_id": parsing_result.get("raw_record_id"),
            "normalised_alert_count": parsing_result.get("normalised_alert_count"),
            "event_count": parsing_result.get("event_count"),
            "selected_alert_id": parsing_result.get("selected_alert_id"),
            "status": parsing_result.get("status"),
            "summary": parsing_result.get("summary"),
            "recommended_next_action": parsing_result.get("recommended_next_action"),
            "important_extracted_fields": parsing_result.get("important_extracted_fields"),
            "missing_important_fields": parsing_result.get("missing_important_fields"),
            "warnings": parsing_result.get("warnings"),
            "parser_summary_card": parsing_result.get("parser_summary_card"),
            # parser_context_guard's input/output identity fingerprint and
            # verdict (see agents/parsing/parser_normaliser.py's own
            # identity_validation wiring) — kept for the same reason the
            # CLI adapter persists it: it is the audit trail proving this
            # parser output was actually checked against the raw alert it
            # was given, not just trusted blindly.
            "input_identity": parsing_result.get("input_identity"),
            "identity_validation": parsing_result.get("identity_validation"),
            # The actual structured parser output the case page's Normalised
            # Alert panel and its Download JSON button render — see
            # run_parser_normalisation_for_dashboard() in
            # agents/parsing/parser_normaliser.py for their shape.
            "normalised_alert": parsing_result.get("normalised_alert"),
            "processed_alert": parsing_result.get("processed_alert"),
            "output_files": parsing_result.get("output_files"),
            "ai_summary": parsing_result.get("ai_summary"),
            "ai_thinking": parsing_result.get("ai_thinking"),
            "ai_summary_model": parsing_result.get("ai_summary_model"),
            "ai_summary_generated_at": parsing_result.get(
                "ai_summary_generated_at"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as exc:
        ctx["stages"]["parsing"] = "failed"
        ctx["errors"]["parsing"] = f"result persist failed: {exc}"
        wss.set_parsing_status(inc_id, run_id, "Failed")
        wss.set_triage_status(inc_id, run_id, "Blocked")
        wss.set_workflow_status(inc_id, run_id, "Failed")
        wss.set_last_error(inc_id, run_id, f"parsing failed: result persist failed: {str(exc)[:250]}")
        _log("PARSING", f"result persist FAILED (breaks durable resume for this run): {exc}")
        return ctx

    ctx["stages"]["parsing"] = "completed"
    wss.set_parsing_status(inc_id, run_id, "Complete")
    _emit("phase_complete", "Parsing and Normalisation", "")

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
    # Phase 6: run binding for the persisted Triage result.
    triage_result["run_id"] = run_id
    wss.save_triage_result(inc_id, run_id, triage_result)

    # ── One-time internal IOC correlation snapshot ──────────────────────────────
    # Computed once here (never live, on every case-page render) so the
    # Unified Verdict/Key Findings/Evidence tab read a stable, run-scoped
    # result. Best-effort/supporting only: a correlation failure records
    # ioc_correlation_status="Failed" with a safe reason, but never fails
    # Triage or the overall workflow — Triage still reaches "Awaiting
    # Approval" normally either way.
    try:
        from agents.investigation.tools.ioc_correlation import correlate_iocs
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


def _require_stage_ready(incident_id: str, stage: str, run_id: str) -> dict:
    """Canonical audit Phase 6 worker re-check: evaluate the PREREQUISITES of
    `stage` for this claimed run (never the stage's own, now-Processing,
    status) and raise StageNotReadyError if they are not satisfied."""
    readiness = evaluate_stage_readiness(incident_id, stage, run_id=run_id)
    if not readiness["ready"]:
        raise StageNotReadyError(readiness)
    if readiness["degraded"]:
        _log(stage.upper(), f"running with degraded evidence: {readiness['degraded_details']}")
    return readiness


def _record_stage_not_ready(incident_id: str, run_id: str, worker_id: str, stage: str,
                            exc: StageNotReadyError, status_updates: dict, *,
                            expected_stage_attempt: int | None = None) -> dict:
    """Record a readiness refusal through the stage's normal failure path
    (complete_stage + last_error), keeping the stable reason code."""
    failure = {"status": "failed", "errors": [str(exc)[:500]],
               "readiness": public_view(exc.readiness)}
    try:
        complete_stage(incident_id, run_id, worker_id, stage=stage,
                       result_column=f"{stage}_result_json", result=failure,
                       status_updates=status_updates,
                       expected_stage_attempt=expected_stage_attempt)
    except Exception:
        pass
    try:
        wss.set_last_error(incident_id, run_id, str(exc)[:500])
    except Exception:
        pass
    _log(stage.upper(), f"NOT READY: {exc}")
    return failure


def run_triage_stage(incident_id: str, run_id: str) -> dict:
    """
    [FYP-FUNCTION] [FYP-ENTRY-POINT] Durable Triage Stage Runner

    Durable, per-stage Triage worker — the counterpart to
    resume_after_triage_approval()/run_investigation_stage()/
    run_reporting_stage() below for the one stage that, before this
    function existed, only ever ran bundled together with Parsing inside
    run_until_triage_approval(). That coupling was fine for the original
    single "Start Process" button, but it meant the per-stage workspace
    UI's "Run Triage"/"Re-run Triage" buttons (workflow/commands.py::
    start_stage()/rerun_stage()) had no way to execute Triage alone —
    every click re-ran Parsing too, even when Parsing had already
    completed. This function is the fix: it takes ONLY incident_id/run_id,
    reloads the persisted Parsing result and raw incident for THIS run
    from SQLite/disk (load_parsing_result_for_run()/
    load_raw_incident_for_run()) rather than re-executing Parsing, and
    follows the exact same claim_stage -> LeaseRenewer -> do the work ->
    complete_stage -> release_stage_lease shape as the other three durable
    stage runners in this module.

    Safe to call from a fresh process or a background thread, as long as
    triage_status == "Processing" (set atomically by
    workflow_state_store.begin_stage()/.rerun_stage(), exactly like the
    other three stages). Ends in "Awaiting Approval" on success (the
    mandatory SOC Analyst approval gate, same as the combined path) or
    "Failed" on any exception/error result. Bypasses TriageAgent's own
    result cache (force=True) — an explicit analyst Run/Re-run click must
    always actually execute, never silently reuse a stale cached ticket
    from an earlier run of the same incident.

    run_until_triage_approval() (above) remains the entry point for a
    genuinely fresh case (no run_id yet) and for the standalone Parsing
    action (parsing_only=True) — this function is Triage's OWN entry point
    once Parsing has already produced a persisted result for the current
    run.

    Args:
        incident_id: the incident this run belongs to.
        run_id: the specific durable run being resumed.

    Returns:
        The triage result dict (TriageAgent.triage()'s native shape) on
        success, or {"status": "failed", "errors": [...]} on failure.
        Raises StageClaimError if this worker never actually owned/kept
        the stage lease (a losing race, not a crash).

    [FYP-CALLS]: claim_stage(), LeaseRenewer, load_parsing_result_for_run(),
    load_raw_incident_for_run(), run_triage(), generate_triage_ai_summary(),
    ioc_correlation.correlate_iocs(), wv.mandatory_triage_approval(),
    complete_stage(), release_stage_lease().
    [FYP-USED-BY]: run_stage_chain() (this module), via
    workflow/commands.py::start_stage()/rerun_stage() for the "triage"
    stage.
    """
    try:
        worker_id, _stage_attempt = claim_stage(
            incident_id, run_id, stage="triage",
            status_column="triage_status", expect_status="Processing")
    except StageClaimError:
        raise   # run_stage_chain treats this as "already being handled elsewhere"

    renewer = LeaseRenewer(incident_id, run_id, worker_id)
    renewer.start()
    try:
        # Phase 6: canonical Parsing and this run's own raw incident are
        # REQUIRED -- production Triage never runs on parsed_context=None or
        # an empty incident because an input is missing.
        _require_stage_ready(incident_id, "triage", run_id)
        parsing_result = load_parsing_result_for_run(incident_id, run_id)
        incident = load_raw_incident_for_run(incident_id, run_id)
        if parsing_result is None or not incident:
            raise RuntimeError("canonical Triage inputs changed after the readiness check")
        inc_id = str(incident.get("id") or incident.get("incidentId") or incident_id)
        title = incident.get("title") or incident.get("name") or "Untitled"
        parsed_context = parsing_result.get("processed_alert") or None

        _log("TRIAGE", f"running triage for incident {inc_id}")
        try:
            triage_result = run_triage(incident, parsed_context=parsed_context, force=True)
        except Exception as exc:
            triage_result = {"error": str(exc)[:500]}

        if triage_result.get("error"):
            _log("TRIAGE", f"FAILED: {triage_result['error']}")
            if renewer.lease_lost.is_set():
                raise StageClaimError(f"triage: worker {worker_id} lost its lease mid-run")
            complete_stage(
                incident_id, run_id, worker_id, stage="triage",
                result_column="triage_result_json", result=triage_result,
                status_updates={"triage_status": "Failed", "workflow_status": "Failed"})
            wss.set_last_error(incident_id, run_id, f"triage failed: {triage_result['error']}"[:500])
            return {"status": "failed", "errors": [triage_result["error"]]}

        ticket = triage_result["ticket"]
        cls = ticket.get("classification", "")
        _log("TRIAGE", f"complete — ticket {ticket.get('unc')} classification={cls}")

        triage_result.update(generate_triage_ai_summary(triage_result))

        pipeline_insert("initial_ticket", {
            "id": ticket.get("unc") or f"TKT_{inc_id}", "incident_id": inc_id,
            "title": f"Ticket {ticket.get('unc')} — {title}", "severity": cls,
            "summary": ticket.get("summary") or "", "ticket": ticket})

        # One-time internal IOC correlation snapshot — best-effort/non-fatal,
        # same as run_until_triage_approval()'s combined path.
        try:
            from agents.investigation.tools.ioc_correlation import correlate_iocs
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

        gate = wv.mandatory_triage_approval(incident_id=inc_id, triage_result=triage_result)
        # Phase 6: run binding for the persisted Triage result.
        triage_result["run_id"] = run_id

        if renewer.lease_lost.is_set():
            raise StageClaimError(f"triage: worker {worker_id} lost its lease mid-run")
        ok = complete_stage(
            incident_id, run_id, worker_id, stage="triage",
            result_column="triage_result_json", result=triage_result,
            status_updates={
                "triage_status": "Awaiting Approval",
                "workflow_status": "Awaiting Approval",
                "approval_stage": gate["approval_stage"],
            })
        if not ok:
            raise StageClaimError(f"triage: lease for {incident_id}/{run_id} "
                                  "was reassigned before this result could be saved")
        _log("WORKFLOW", f"paused for mandatory SOC analyst approval "
                         f"(ticket={ticket.get('unc')}, next={gate['next_stage_after_approval']})")
        return triage_result
    except StageClaimError:
        raise   # a losing race is not a crash — run_stage_chain just stops quietly
    except StageNotReadyError as exc:
        return _record_stage_not_ready(
            incident_id, run_id, worker_id, "triage", exc,
            {"triage_status": "Failed", "workflow_status": "Failed"})
    except Exception as exc:
        try:
            complete_stage(
                incident_id, run_id, worker_id, stage="triage",
                result_column="triage_result_json",
                result={"status": "failed", "errors": [str(exc)[:300]]},
                status_updates={"triage_status": "Failed", "workflow_status": "Failed"})
        except Exception:
            pass
        wss.set_last_error(incident_id, run_id, f"triage failed: {str(exc)[:300]}")
        _log("TRIAGE", f"FAILED: {exc}")
        return {"status": "failed", "errors": [str(exc)[:300]]}
    finally:
        renewer.stop()
        release_stage_lease(incident_id, run_id, worker_id)   # no-op if complete_stage()
                                                              # already cleared it


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
    workflow_state_store.begin_stage(), .rerun_stage() or
    .retry_threat_intel() — approve_triage() only leaves it "Pending"). NO
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
    threat_intel_status to Complete/"Complete with Warnings" and leaves
    investigation_status "Pending" with workflow_status "Awaiting Action" in
    the SAME atomic write — the same unlock-but-don't-start idiom
    approve_triage()/approve_investigation() use. "Pending" means
    Investigation is available and waiting for the analyst; "Processing"
    means it is executing. Threat Intelligence completion must never write
    "Processing" for Investigation, because run_stage_chain()'s next
    dispatch branch ("if investigation_status == Processing") would then
    execute it without an explicit analyst action. Investigation starts only
    via its own start action (commands.start_stage -> wss.begin_stage).

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
        # Phase 6: canonical Triage (case + run + real ticket), its current
        # approval and canonical Parsing are REQUIRED; the raw incident is
        # optional (degraded when unavailable or foreign -- never consumed).
        readiness = _require_stage_ready(incident_id, "threat_intel", run_id)
        triage_result  = readiness["inputs"]["triage"]
        parsing_result = load_parsing_result_for_run(incident_id, run_id)
        if parsing_result is None:
            raise RuntimeError("canonical Parsing changed after the readiness check")
        incident       = load_raw_incident_for_run(incident_id, run_id) or {}   # optional; never a foreign record
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
                 # Unlock, never start: Investigation only begins when the
                 # analyst explicitly starts it (begin_stage()).
                 "investigation_status": "Pending", "workflow_status": "Awaiting Action"}))
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
    except StageNotReadyError as exc:
        return _record_stage_not_ready(
            incident_id, run_id, worker_id, "threat_intel", exc,
            {"threat_intel_status": "Failed", "investigation_status": "Blocked",
             "workflow_status": "Failed"})
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
        # Phase 6: prerequisites (Parsing, Triage + approval, TI result for
        # this case/run) are checked BEFORE waiting for the shared workspace.
        readiness = _require_stage_ready(incident_id, "investigation", run_id)
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
        triage_result  = readiness["inputs"]["triage"]
        ti_result      = readiness["inputs"]["threat_intel"]
        incident       = load_raw_incident_for_run(incident_id, run_id) or {}   # optional; never a foreign record
        parsing_result = load_parsing_result_for_run(incident_id, run_id)
        if parsing_result is None:
            raise RuntimeError("canonical Parsing changed after the readiness check")
        ticket = triage_result.get("ticket") or {}
        triage_cls = ticket.get("classification") or state.get("severity") or "UNRATED"
        alert_list = incident.get("alerts") or (incident.get("alertMeta") or {}).get("AlertTitles") or []
        alert_count = max(len(alert_list), 1)

        _log("INVESTIGATION", f"running investigation agent for {incident_id} ({alert_count} alerts, {triage_cls})…")
        inv_result = investigate_with_feedback(
            triage_result, incident, incident_id,
            threat_intel_result=ti_result,
            parsing_result=parsing_result,
            feedback_cb=lambda ev, d: _log("FEEDBACK", f"{ev}: {d}"),
            watchdog_cb=lambda: renew_global_lock(_INVESTIGATION_LOCK, worker_id))
        # C1 persisted-result boundary: never save (or offer for approval) an
        # Investigation result that asserts another case's identity. The
        # foreign analysis itself is not persisted; only the failure is.
        if inv_result.get("status") not in {"failed", "lock_lost"}:
            identity_problem = wss.investigation_identity_problem(incident_id, inv_result)
            if identity_problem:
                _log("INVESTIGATION", f"REJECTED result for {incident_id} -- {identity_problem}")
                inv_result = {"agent": "Investigation Agent", "incident_id": str(incident_id),
                              "status": "failed",
                              "error": f"investigation_identity_mismatch: {identity_problem}",
                              "incident_folder": inv_result.get("incident_folder"),
                              "cluster_alert_ids": inv_result.get("cluster_alert_ids") or []}
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
                post_inv_run_stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                pipeline_insert("post_investigation",
                                build_post_investigation_record(
                                    inv_result, ticket, run_stamp=post_inv_run_stamp))
            except Exception as exc:
                _log("INVESTIGATION", f"post_investigation pipeline insert failed: {exc}")

        # Phase 6: run binding for the persisted Investigation result.
        inv_result["run_id"] = run_id
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
    except StageNotReadyError as exc:
        return _record_stage_not_ready(
            incident_id, run_id, worker_id, "investigation", exc,
            {"investigation_status": "Failed", "reporting_status": "Blocked",
             "workflow_status": "Failed"})
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


def _reporting_attempt_artifact(reporting_stage_attempt: int, filename: str) -> str:
    """Run-artifact name (relative to _artifact_dir) for one Reporting
    attempt: reporting/attempt_N/<filename>, alongside that attempt's
    inputs/ and outputs/ -- attempt N+1 never overwrites attempt N's copy."""
    return f"reporting/attempt_{int(reporting_stage_attempt)}/{filename}"


def _verify_reporting_candidate(incident_id: str, run_id: str, reporting_stage_attempt: int,
                                exports: dict) -> dict:
    """[FYP-FUNCTION] [FYP-VALIDATION] Canonical audit Phase 7: verify the
    candidate set this attempt exported with the SAME integrity check
    approval uses (agents/reporting/reporting_approval.verify_candidate_set),
    against this module's trusted root. Returns {"ok": True, ...} or
    {"ok": False, "reason_code", "detail"}; never raises."""
    from agents.reporting.reporting_approval import (CANDIDATE_MANIFEST_MISSING, CandidateSetError,
                                                     verify_candidate_set)
    path = exports.get("candidate_manifest_path")
    if not path:
        why = (exports.get("candidate_manifest_error") or exports.get("error")
               or "the exporter published no candidate manifest")
        return {"ok": False, "reason_code": CANDIDATE_MANIFEST_MISSING,
                "detail": "no candidate manifest was published for this attempt: " + str(why)[:300]}
    try:
        manifest = verify_candidate_set(path, incident_id=incident_id, run_id=run_id,
                                        reporting_stage_attempt=reporting_stage_attempt,
                                        trusted_root=_TRUSTED_OUTPUT_ROOT)
    except CandidateSetError as exc:
        return {"ok": False, "reason_code": exc.reason_code, "detail": exc.detail[:300]}
    except Exception as exc:   # never let verification itself crash the stage
        return {"ok": False, "reason_code": "candidate_manifest_unreadable",
                "detail": f"candidate set could not be verified: {exc}"[:300]}
    return {"ok": True, "report_set_id": manifest.get("report_set_id"),
            "candidate_manifest_sha256": manifest.get("candidate_manifest_sha256"),
            "reports": len(manifest.get("reports") or [])}


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
    "investigation_workspace" lock) covers the complete lifecycle. Canonical
    audit Phase 7: workflow FILE isolation no longer depends on it — every
    run-scoped attempt reads and writes only its own reporting_attempt_dir()
    (inputs, outputs, exports, manifests, LLM narrative cache), never the
    shared REP_DIR/inputs|outputs. The lock is kept unchanged because it
    still serialises the heavy shared resources a Reporting run drives (the
    Reporting model load, DOCX->PDF conversion and other external
    processes); any redesign of it belongs to a later phase.

    [FYP-DECISION]: TWO extra integrity checks beyond the lock itself:
      1. handoff_manifest.json verification — after handoff_to_reporting()
         writes its inputs, this reads back the manifest it wrote (paths +
         size + sha256 per file, see handoff_to_reporting's run-scoped
         branch) and re-hashes every file ON DISK to confirm nothing was
         truncated/altered before the subprocess launches. A mismatch
         raises RuntimeError (caught by the outer except, recorded as a
         failed stage).
      2. candidate-set verification (canonical audit Phase 7) — after
         run_reporting() completes, the exported candidate set is verified
         with reporting_approval.verify_candidate_set(), the same integrity
         check approval runs: the manifest must exist, be readable and live
         inside THIS attempt; its incident_id/run_id/reporting_stage_attempt
         must match; and every listed file plus the manifest's own hash
         must match. Any failure (including a missing manifest) fails the
         attempt with a stable candidate_* reason code — Reporting never
         reaches Awaiting Approval without a verified candidate set.

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
        # Phase 6: every canonical current-run input Reporting depends on is
        # checked up front -- before the shared workspace lock, the attempt
        # directory, the handoff or the subprocess.
        readiness = _require_stage_ready(incident_id, "reporting", run_id)
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

        triage_result = readiness["inputs"]["triage"]
        investigation_result = readiness["inputs"]["investigation"]
        # C1 defence in depth: Reporting never starts from (or hands off)
        # another case's Investigation result -- fails the attempt instead.
        identity_problem = wss.investigation_identity_problem(incident_id, investigation_result)
        if identity_problem:
            raise RuntimeError(f"investigation identity check failed: {identity_problem}")
        threat_intel_result = readiness["inputs"]["threat_intel"]
        incident = load_raw_incident_for_run(incident_id, run_id) or {}   # optional; never a foreign record
        ticket = triage_result.get("ticket") or {}
        title  = incident.get("title") or incident.get("name") or "Untitled"
        run_stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

        try:
            # Phase 7: per attempt -- a rerun never overwrites an earlier
            # attempt's copy (nothing reads these back; audit copies only).
            _save_run_artifact(incident_id, run_id,
                               _reporting_attempt_artifact(_stage_attempt, "reporting_handoff.json"),
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
            run_id=run_id, reporting_stage_attempt=_stage_attempt,
            incident_id=incident_id)

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
            _save_run_artifact(incident_id, run_id,
                               _reporting_attempt_artifact(_stage_attempt, "reporting_output.json"),
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

        # Canonical audit Phase 7: generation -> export -> candidate manifest
        # -> VERIFIED candidate set -> only then Awaiting Approval. A
        # missing, unreadable, foreign, out-of-attempt or altered candidate
        # set fails the attempt with a stable reason code.
        candidate_failure = None
        if not failed:
            check = _verify_reporting_candidate(
                incident_id, run_id, _stage_attempt, reporting_result.get("document_exports") or {})
            reporting_result["candidate_manifest_check"] = check
            if not check["ok"]:
                candidate_failure = f"{check['reason_code']}: {check['detail']}"
                _log("REPORTING", f"candidate set verification failed — {candidate_failure}")
                failed = True
                reporting_result["status"] = "failed"
                reporting_result["error"] = candidate_failure

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
        if candidate_failure:
            wss.set_last_error(incident_id, run_id, f"reporting failed: {candidate_failure[:300]}")
        _log("REPORTING", f"complete — status={reporting_result.get('status')}"
                          if not failed else "REPORTING FAILED")
        return reporting_result
    except StageClaimError:
        raise
    except StageNotReadyError as exc:
        return _record_stage_not_ready(
            incident_id, run_id, worker_id, "reporting", exc,
            {"reporting_status": "Failed", "workflow_status": "Failed"},
            expected_stage_attempt=_stage_attempt)
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
    (`threading.Thread(target=wf_run_stage_chain, ...)`) every time a
    per-stage "Run"/"Re-run" action or Approve puts a stage into
    "Processing" — the single place that decides "what runs next" for a
    given run_id. Read this alongside run_triage_stage()/
    resume_after_triage_approval()/run_investigation_stage()/
    run_reporting_stage() to see the full Triage -> Threat Intel ->
    Investigation -> Reporting chain. Each stage's completion only unlocks
    the next ("Pending" = available, waiting for the analyst); only an
    explicit start/rerun/resume action sets a stage to "Processing"
    (= execute now), which is the one status this dispatcher acts on.

    Top-level worker entry point AND what "Resume Workflow" calls. A
    state-aware dispatcher: reads current state ONCE and resumes
    whichever stage is actually 'Processing', falling through to the
    next stage only if that stage's own outcome says to continue. This
    means a fresh run (started right after an approval unlocks the next
    stage) and an interrupted-mid-Investigation resume both correctly
    converge on the right stage — it does NOT always restart from Triage
    or Threat Intelligence.

    [FYP-FLOW]: four sequential `if state[...] == "Processing":` checks
    (triage_status -> threat_intel_status -> investigation_status ->
    reporting_status), each guarded so it only proceeds to the NEXT
    stage's check if the current one both succeeded AND didn't end in a
    normal pause:
      - triage: any failure -> return (don't touch threat_intel). Success
        always ends at "Awaiting Approval", which leaves threat_intel_status
        at "Pending" (not "Processing") — so the next check below simply
        finds nothing to do, with no explicit early-return needed for the
        pause case (unlike investigation's, below).
      - threat_intel: any failure -> return (don't touch investigation).
        Success ends at investigation_status "Pending" / workflow_status
        "Awaiting Action" (same as triage's pause) — so the investigation
        check below finds nothing to do. Investigation only runs through
        this dispatcher after the analyst's explicit start action
        (begin_stage) has set it to "Processing".
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

    [FYP-ERROR] [FYP-FALLBACK]: every StageClaimError from the four stage
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

    [FYP-CALLS]: run_triage_stage(), resume_after_triage_approval(), run_investigation_stage(),
    run_reporting_stage(), workflow_state_store.get_state().
    [FYP-USED-BY]: app.py, imported as `wf_run_stage_chain` — launched via
    `threading.Thread(target=wf_run_stage_chain, args=(incident_id, run_id))`
    at multiple points (after Approve Triage, after Approve Investigation,
    on an explicit "Resume Workflow" action, on retry-after-failure).
    """
    state = wss.get_state(incident_id)
    if not state or state["run_id"] != run_id:
        return   # superseded by a newer run — nothing to resume here

    if state["triage_status"] == "Processing":
        try:
            result = run_triage_stage(incident_id, run_id)
        except StageClaimError:
            return
        if result.get("status") == "failed":
            return   # Triage always pauses at "Awaiting Approval" on success —
                     # threat_intel_status stays "Pending" until the analyst
                     # explicitly approves Triage and starts it, so simply
                     # falling through here (rather than returning) is safe:
                     # the next check below will correctly see "Pending", not
                     # "Processing", and do nothing further.
        state = wss.get_state(incident_id)

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
    [FYP-EVALUATOR]: `python soc_workflow.py --incident-file demo/sample_incident.json`
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
    # the incident file itself) for post-hoc inspection/debugging. Lives
    # under runtime/ (gitignored, regenerated each CLI run) rather than the
    # repo root - it's a debug artifact, not source.
    out_path = ROOT / "runtime" / "workflow_last_run.json"
    slim = {k: v for k, v in ctx.items() if k != "incident"}
    _write_json(out_path, slim)
    print(f"  full context written to {out_path.relative_to(ROOT)}")
    return 1 if ctx["errors"].get("triage") else 0


if __name__ == "__main__":
    # [FYP-ENTRY-POINT]: `python soc_workflow.py --incident-file ...`
    raise SystemExit(main())
