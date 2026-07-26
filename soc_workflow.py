"""
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
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime
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
# 1.  PIPELINE DATABASE  (same schema/stages as app.py)
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
    """Pipeline record for the post_investigation stage — one shape shared by
    app.py and the CLI workflow so the DB viewer sees consistent fields.

    With run_stamp, the record id is run-scoped (postinv_#UNC@stamp) so every
    workflow execution APPENDS a new findings row instead of replacing the
    previous one; ticket lineage stays via incident_id + ticket_unc fields."""
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


def _pl_con() -> sqlite3.Connection:
    # Generous busy-timeout: the app's poll loop reads these tables every
    # ~1.5s while the worker writes — waits must outlast brief read locks.
    con = sqlite3.connect(str(PIPELINE_DB_FILE), check_same_thread=False,
                          timeout=15)
    con.row_factory = sqlite3.Row
    return con


def pipeline_db_init() -> None:
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
    """Insert a record into a pipeline stage table (mirrors app.py behaviour).
    Same-id re-inserts REPLACE the row; a run counter + timestamp stamp the
    summary so refreshed records are visibly new in the DB viewer."""
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
# 2.  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _log(tag: str, msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [{tag}] {msg}", flush=True)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8")


def _read_json(path: Path, default: Any = None) -> Any:
    try:
        if not path.exists() or path.stat().st_size == 0:
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _safe_ticket_id(unc: str) -> str:
    """'#00012A' -> 'TKT-00012A' (filesystem/env safe)."""
    core = re.sub(r"[^A-Za-z0-9]", "", str(unc or ""))
    return f"TKT-{core}" if core else "TKT-UNKNOWN"


def _run_subprocess_streaming(cmd: list[str], cwd: Path, timeout: int,
                              extra_env: dict[str, str] | None = None,
                              line_cb=None) -> dict:
    """Like _run_subprocess, but streams merged stdout/stderr line-by-line to
    line_cb(str) while the process runs — used by the app's agent board to
    show live 'thinking' for subprocess agents. Same result shape."""
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONUNBUFFERED", "1")
    if extra_env:
        env.update(extra_env)
    started = datetime.now().isoformat(timespec="seconds")
    lines: list[str] = []
    try:
        import threading
        proc = subprocess.Popen(cmd, cwd=str(cwd), env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace",
                                bufsize=1)
        # Watchdog: the read loop below blocks while the process is silent,
        # so timeout must be enforced out-of-band, not per-line.
        timed_out = {"v": False}

        def _kill_on_timeout():
            timed_out["v"] = True
            try:
                proc.kill()
            except Exception:
                pass

        watchdog = threading.Timer(timeout, _kill_on_timeout)
        watchdog.start()
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
    for v in values:
        if v not in (None, "", [], {}):
            return v
    return default


def _normalise_llm_url(url: str) -> str:
    """Ensure the base URL ends with /v1 (same rule as app.py's get_cisco_cfg).
    Some OpenAI-compatible gateways answer 401 — not 404 — for unknown
    routes, so a missing /v1 looks exactly like a bad token. This bit the
    first live run."""
    url = (url or "").strip().rstrip("/")
    if url and not url.endswith("/v1"):
        url += "/v1"
    return url


def _maybe_b64_decode(value: str) -> str:
    """app.py's sidebar save writes CISCO_LLM_KEY to .env base64-encoded
    ("to avoid special char issues"). Decode when the value is valid base64;
    hand-edited raw tokens (e.g. "sk-...") fail validation and pass through."""
    import base64
    try:
        decoded = base64.b64decode(value.encode(), validate=True).decode("utf-8")
        return decoded if decoded.isprintable() else value
    except Exception:
        return value


def _openai_compat_env() -> dict[str, str]:
    """LLM env for the investigation/reporting subprocesses.

    Preference order:
      1. A real OPENAI_API_KEY in the environment — use OpenAI as-is.
      2. Fall back to a custom OpenAI-compatible endpoint configured via
         CISCO_LLM_URL/KEY/MODEL, reusing the triage agent's credentials.
      3. Neither present — return {} and the agents use their non-LLM paths.
    """
    if os.environ.get("OPENAI_API_KEY", "").strip():
        return {}
    cisco_url   = _normalise_llm_url(os.environ.get("CISCO_LLM_URL", ""))
    cisco_key   = _maybe_b64_decode(os.environ.get("CISCO_LLM_KEY", "").strip())
    cisco_model = os.environ.get("CISCO_LLM_MODEL", "").strip()
    if not (cisco_url and cisco_key):
        return {}
    return {
        "OPENAI_API_KEY":  cisco_key,
        "OPENAI_BASE_URL": cisco_url,   # read by the openai SDK
        "OPENAI_API_BASE": cisco_url,   # read by langchain-openai
        "OPENAI_MODEL":    cisco_model or "tgi",
    }


def _llm_seed() -> str:
    """One fixed seed for every LLM call in the pipeline — same policy as the
    triage agent (CISCO_LLM_SEED, default 42) so repeat runs are reproducible."""
    return os.environ.get("CISCO_LLM_SEED", "").strip() or "42"


# ══════════════════════════════════════════════════════════════════════════════
# 3.  STAGE 1 — TRIAGE  (in-process)
# ══════════════════════════════════════════════════════════════════════════════

def run_triage(incident: dict, progress_fn=None,
               parsed_context: dict | None = None,
               force: bool = False) -> dict:
    """Run the triage agent in-process. Returns its native result dict.

    parsed_context is Stage 0's processed_alert (see run_parsing) — when
    present, the IOC/risk/classification phases reuse those already-extracted
    indicators instead of re-deriving them from the raw incident. force=True
    bypasses TriageAgent's result cache, for an explicit retry."""
    from soc_triage_agent import CiscoLLMConfig, TriageAgent
    agent = TriageAgent(cfg=CiscoLLMConfig(), progress_fn=progress_fn)
    return agent.triage(incident, force=force, parsed_context=parsed_context)


def run_parsing(incident: dict) -> dict:
    """Run the existing Parsing & Normalisation stage in-process, reusing
    soc_reporting_agent's parser unmodified. Mirrors run_triage()'s pattern:
    a thin wrapper, no new parsing logic. Also asks the LLM for a plain-
    English summary of what the parser extracted (see generate_parsing_ai_summary)."""
    rep_dir = str(REP_DIR)
    if rep_dir not in sys.path:
        sys.path.insert(0, rep_dir)
    from services.parser_normaliser import run_parser_normalisation_for_dashboard

    inc_id = str(incident.get("id") or incident.get("incidentId") or "unknown")
    output_dir = REP_DIR / "outputs" / inc_id / "parsing"
    result = run_parser_normalisation_for_dashboard(incident, output_dir=output_dir)
    if result.get("status") == "completed":
        result.update(generate_parsing_ai_summary(result))
    return result


def _split_ai_summary_sections(text: str) -> tuple[str, str]:
    """Split the LLM's labelled SUMMARY/THINKING reply into two strings.
    Falls back to treating the whole reply as the summary if the model
    didn't follow the requested labels."""
    m = re.search(r"SUMMARY:\s*(.*?)\s*THINKING:\s*(.*)", text, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return text.strip(), ""


def generate_parsing_ai_summary(parsing_result: dict, model: str | None = None) -> dict:
    """Ask OpenAI for a plain-English summary of what the Parsing &
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
                "SUMMARY: <2-3 plain-English sentences on what this alert is "
                "and why it matters>\n"
                "THINKING: <2-4 short bullet points on the specific indicators "
                "(host, IPs, user, file, process, MITRE technique) that drove "
                "your read>\n"
                "Only state facts present in the data below — never invent "
                "values that aren't there."
            ),
            model=selected_model,
            max_output_tokens=600,
        )
        summary, thinking = _split_ai_summary_sections(raw)
    except Exception as exc:
        summary = thinking = f"AI summary unavailable — LLM call failed: {exc}"

    return {
        "ai_summary": summary,
        "ai_thinking": thinking,
        "ai_summary_model": selected_model,
        "ai_summary_generated_at": datetime.now().isoformat(timespec="seconds"),
    }


def render_triage_thinking_plain(triage_result: dict) -> str:
    """Connected-narrative 'thinking process' for the Triage panel — built
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


def generate_triage_ai_summary(triage_result: dict, model: str | None = None) -> dict:
    """Ask OpenAI for a plain-English summary of what TriageAgent.triage()
    produced (the 'AI-Generated Summary' panel). The 'Thinking Process'
    panel is filled separately and deterministically by
    render_triage_thinking_plain() from the agent's own trace — not from
    this LLM call — so it stays accurate even if this call fails or the
    LLM misreads the data. Reuses the same OpenAI helper as the Parsing
    stage — no separate LLM client is introduced."""
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
                "recommended actions. Reply with 2-3 plain-English sentences on "
                "what this incident is and why it was classified this way. "
                "Only state facts present in the data below — never invent "
                "values that aren't there."
            ),
            model=selected_model,
            max_output_tokens=300,
        ).strip()
    except Exception as exc:
        summary = f"AI summary unavailable — LLM call failed: {exc}"

    return {
        "ai_summary": summary,
        "ai_thinking": render_triage_thinking_plain(triage_result),
        "ai_summary_model": selected_model,
        "ai_summary_generated_at": datetime.now().isoformat(timespec="seconds"),
    }


def mock_triage_result(incident: dict) -> dict:
    """Canned triage output with the same shape as TriageAgent.triage().
    Used with --mock-triage to test the workflow without LLM access."""
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
    cls = str(triage_result.get("metakeys_payload", {}).get("classification")
              or triage_result.get("ticket", {}).get("classification") or "").lower()
    return cls in INVESTIGATE_CLASSIFICATIONS


# ══════════════════════════════════════════════════════════════════════════════
# 4.  HANDOFF — TRIAGE → INVESTIGATION
# ══════════════════════════════════════════════════════════════════════════════

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NOISE_VALUES = {"", "unknown", "none", "null", "n/a", "-", "0.0.0.0",
                 "localhost", "127.0.0.1"}


def _flatten_dict(d, prefix: str = "") -> dict:
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


def _scalar(value):
    """Metakey values may be lists after deep extraction — take the first."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


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


def _to_iso_timestamp(value) -> str:
    """Normalize assorted timestamp spellings ('2025-11-18 03:18:37 UTC',
    epoch millis, ISO) to ISO-8601 so the investigation agent's
    parse_timestamp_to_epoch() succeeds and temporal correlation works."""
    if value in (None, "", "Unknown"):
        return ""
    if isinstance(value, (int, float)):          # epoch (NetWitness uses ms)
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


# NOTE: entity-map, threat-intel, asset-criticality, detection-rules and
# mitigation-coverage are STANDALONE skills (incident_map.py / threat_intel.py /
# asset_criticality.py / detection_rules.py / mitigation_mapping.py), surfaced
# via the app UI (Map panel) — they are deliberately NOT embedded into the
# investigation alert, to keep soc_investigation_agent/ free of our upgrades.


def build_investigation_alert(triage_result: dict, incident: dict,
                              supplement: dict | None = None) -> dict:
    """Convert triage output into the alert-JSON schema the investigation
    agent's ingest pipeline expects (see soc_investigation_agent/log_config.yaml).
    supplement: optional deep-dive findings from the feedback loop — embedded
    so the analysis LLM sees the answers (or confirmed absences) per gap."""
    payload = triage_result.get("metakeys_payload", {})
    ticket  = triage_result.get("ticket", {})
    mkv     = payload.get("metakey_values") or {}
    ctx     = _harvest_incident_context(incident)

    def _mk(key):
        return _scalar(mkv.get(key))

    # ── enrichment helpers: surface the incident's OWN richer evidence that
    # triage saw but the thin handoff dropped (behavioural alert titles, file/
    # process IOCs, endpoint identity, alert volume). Forwarded agent-to-agent so
    # the investigation LLM has real context; skill computations are still NOT
    # embedded (see the note above) and the UI triage report/ticket are untouched.
    _am = incident.get("alertMeta") or {}

    def _amlist(*keys) -> list:
        out: list = []
        for k in keys:
            v = _am.get(k)
            if isinstance(v, list):
                out += [str(x).strip() for x in v if str(x).strip()]
            elif v not in (None, "", [], {}):
                out.append(str(v).strip())
        return list(dict.fromkeys(out))

    def _mklist(*keys) -> list:
        out: list = []
        for k in keys:
            v = mkv.get(k)
            if isinstance(v, list):
                out += [str(x).strip() for x in v if str(x).strip()]
            elif v not in (None, "", [], {}):
                out.append(str(v).strip())
        return list(dict.fromkeys(out))

    def _process_lineage() -> list:
        """Parent→child process edges. Prefer an explicit lineage/chain field
        ("a > b > c"); else pair same-length process/parent lists (flagged
        inferred); else []. Deterministic, evidence-based — never fabricates an
        edge it can't source."""
        edges: list = []
        chains = (_mklist("process.lineage", "process.chain", "process.tree")
                  + _amlist("ProcessTree", "ProcessLineage"))
        for c in chains:
            norm = str(c).replace("→", "|").replace("->", "|").replace(">", "|")
            parts = [p.strip() for p in norm.split("|") if p.strip()]
            for i in range(len(parts) - 1):
                edges.append({"parent": parts[i], "child": parts[i + 1],
                              "source": "explicit chain"})
        if edges:
            return edges
        children = _mklist("process.name")
        parents = _mklist("process.parent", "parent.process", "parent.name")
        if children and parents and len(children) == len(parents):
            return [{"parent": parents[i], "child": children[i],
                     "source": "paired (inferred)"} for i in range(len(children))]
        return []

    return {
        "incident_id": payload.get("incident_id") or ticket.get("incident_id"),
        "incident_details": {
            "timestamp": _to_iso_timestamp(
                _first(ticket.get("incident_time"), payload.get("timestamp"))),
            "description": ticket.get("summary") or "",
            "mitre_att&ck": {
                # Triage now maps every incident onto a canonical tactic; the
                # investigation agent uses it for playbook auto-selection.
                "tactic":    _first(payload.get("mitre_tactic"),
                                    ticket.get("mitre_tactic"),
                                    incident.get("mitre_tactic"), default="Unknown"),
                "technique": _first(payload.get("mitre_technique"),
                                    ticket.get("mitre_technique"),
                                    incident.get("mitre_technique"), default="Unknown"),
            },
        },
        "classification": {
            "alert_type":         ticket.get("incident_category") or "Unknown",
            "soc_classification": ticket.get("classification") or "Unknown",
        },
        # Metakey values from triage first; harvested from the raw incident as
        # fallback. "Unknown" here previously left every playbook step NOT_MET.
        "log_indicators": {
            "target_user":   _first(_mk("user.name"), incident.get("username"),
                                    (ctx["users"] or [None])[0],
                                    default="Unknown"),
            "computer_name": _first(_mk("host.name"), incident.get("hostname"),
                                    (ctx["hosts"] or [None])[0],
                                    default="Unknown"),
            "operating_system": _first(_mk("os.version"),
                                       (ctx["operating_systems"] or [None])[0],
                                       default="Unknown"),
        },
        "network_indicators": {
            "source_ip":      _first(_mk("ip.src"), incident.get("source_ip"),
                                     (ctx["source_ips"] or [None])[0]),
            "destination_ip": _first(_mk("ip.dst"), incident.get("destination_ip"),
                                     (ctx["destination_ips"] or [None])[0]),
            "domain":         _mk("domain"),
        },
        # Full harvested lists — the ingest pipeline's regex scanner picks the
        # IPs out of this block for correlation, and the analysis LLM sees the
        # complete set (playbook step 1 asks for exactly these fields).
        "observed_indicators": {
            "usernames":      ctx["users"],
            "hostnames":      ctx["hosts"],
            "ip_addresses":   ctx["ips"],
            "source_ips":     ctx["source_ips"],
            "destination_ips": ctx["destination_ips"],
            "entity_from_alert_title": ctx.get("title_entity") or None,
        },
        "triage": {
            "ticket_unc":        ticket.get("unc"),
            "risk_rating":       ticket.get("risk_rating"),
            "ioc_summary":       payload.get("ioc_summary"),
            "matched_metakeys":  payload.get("matched_metakeys"),
            "metakey_values":    mkv,
            "matched_ioc_count": ticket.get("matched_ioc_count"),
        },
        "source_incident": {
            "title":   payload.get("incident_title") or ticket.get("title"),
            "summary": str(incident.get("summary") or "")[:1000],
        },
        # ── ENRICHMENT: the incident's own richer evidence, forwarded so the
        # investigation agent's ingest (flat-string IOC scanner + analysis LLM)
        # has real context to answer playbook step_1-5. The triage report and
        # ticket rendered in the UI are intentionally left simple/unchanged.
        "enrichment": {
            "endpoint_identity": {
                "hostnames":       _amlist("Hostname") or ctx["hosts"],
                "users":           _amlist("User", "AdUser") or ctx["users"],
                "mac_addresses":   _amlist("MacAddress"),
                "dns_domains":     _amlist("DnsDomain"),
                "source_ips":      _amlist("SourceIp") or ctx["source_ips"],
                "destination_ips": _amlist("DestinationIp") or ctx["destination_ips"],
            },
            "behavioural_alerts": {
                "alert_titles":     _amlist("AlertTitles"),
                "alert_types":      _amlist("AlertTypes"),
                "mitre_tactics":    _amlist("AlertTactics"),
                "mitre_techniques": _amlist("AlertTechniques"),
            },
            "file_indicators": {
                "hashes": _mklist("file.hash", "checksum", "checksumSha256",
                                  "checksumSha1", "checksumMd5", "sha256", "md5"),
                "names":  _mklist("file.name", "filename"),
                "paths":  _mklist("file.path"),
            },
            "process_indicators": {
                "names": _mklist("process.name"),
                "paths": _mklist("process.path"),
                "pids":  _mklist("process.pid"),
            },
            # ── Handoff round 3: parent→child process lineage + command lines.
            # The highest-signal endpoint context for the investigation LLM (an HTA
            # spawning cmd→powershell reaching a C2 host IS the attack chain).
            # Populated from live ECAT endpoint data; when explicit lineage isn't
            # present the flat process/parent/command-line lists still forward the
            # evidence without inventing edges.
            "process_tree": {
                "processes":        _mklist("process.name"),
                "process_paths":    _mklist("process.path", "directory", "filename.path"),
                "pids":             _mklist("process.pid"),
                "parent_processes": _mklist("process.parent", "parent.process",
                                            "parent.name", "parent.path", "parent.pid"),
                "command_lines":    _mklist("process.cmdline", "cmdline", "os.cmdline",
                                            "param.dst", "param.src"),
                "lineage":          _process_lineage(),
            },
            "network_activity": {
                "source_ips":      _amlist("SourceIp") or ctx["source_ips"],
                "destination_ips": _amlist("DestinationIp") or ctx["destination_ips"],
                "ports":           _mklist("port.dst", "port.src", "tcp.dstport"),
                "protocols":       _mklist("protocol", "ip.proto", "service"),
                "network_services": _mklist("network.service"),
                "bytes":           _mklist("bytes.out", "bytes.transferred", "bytes.src"),
                "geo":             _mklist("geo.country", "geo.city", "org.dst"),
                "domains":         _mklist("domain", "fqdn", "alias.host"),
            },
            "host_behaviour": {
                "config_changes":  _mklist("config.change", "change.type"),
                "cpu_usage":       _mklist("cpu.usage"),
                "device_types":    _mklist("device.type"),
                "user_roles":      _mklist("user.role"),
                "operating_systems": _mklist("os.version", "os.type") or ctx["operating_systems"],
            },
            "event_context": {
                "event_types":  _mklist("event.type", "alert.type", "ec.activity"),
                "event_times":  _mklist("event.time"),
            },
            # Full metakey map so nothing triage extracted is dropped in transit —
            # the analysis LLM sees every populated field. UI is unaffected.
            "all_metakey_values": {k: v for k, v in mkv.items()
                                   if v not in (None, "", [], {})},
            "alert_statistics": {
                "alert_count":              incident.get("alertCount"),
                "event_count":              incident.get("eventCount"),
                "risk_score":               incident.get("riskScore"),
                "average_alert_risk_score": incident.get("averageAlertRiskScore"),
                "matched_ioc_count":        ticket.get("matched_ioc_count"),
            },
            "matched_metakey_catalog": payload.get("matched_metakeys") or [],
            "ioc_summary":    payload.get("ioc_summary"),
            "triage_summary": ticket.get("summary"),
            "_note": "Agent-to-agent enrichment: the incident's own evidence "
                     "forwarded from triage. The triage report and ticket shown "
                     "in the UI are intentionally unchanged/simple.",
        },
        **({"triage_deep_dive": supplement} if supplement else {}),
    }


def handoff_to_investigation(triage_result: dict, incident: dict,
                             supplement: dict | None = None) -> Path:
    alert = build_investigation_alert(triage_result, incident,
                                      supplement=supplement)
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
# 5.  STAGE 2 — INVESTIGATION  (subprocess)  +  TRIAGE FEEDBACK LOOP
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
    """Decide whether the investigation lacked information, and name the gaps.

    Triggers when the fraction of NOT_MET playbook steps meets or exceeds
    the configurable threshold (WORKFLOW_FEEDBACK_THRESHOLD, default 0.4 = 40%).
    Returns the unmet steps' instructions — prioritised by investigative
    value — these become the questions the triage agent's deep-dive pass
    must answer."""
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
                              max_passes: int | None = None) -> dict:
    """Investigation with a triage feedback loop.

    Pass 1 runs normally. If the result shows the investigation lacked
    information (detect_evidence_gaps), the work goes BACK to the triage
    agent for a focused deep-dive on exactly those gaps, then investigation
    re-runs with the supplement embedded in the alert. Gaps the incident
    data cannot answer come back marked 'not present in incident data', so
    the second pass converges instead of looping.

    feedback_cb(event, detail) events: handoff, gaps_detected,
    triage_deep_dive_start, triage_deep_dive_done, second_pass_start,
    supplement_error. WORKFLOW_FEEDBACK_PASSES=0 disables the loop.
    """
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

    handoff_to_investigation(triage_result, incident)
    _emit("handoff", "Alert handed to triaged_alerts queue")
    inv = run_investigation(inc_id, timeout=timeout, line_cb=line_cb,
                            triage_classification=cls)

    fb: dict = {"triggered": False, "passes": 0, "gaps": []}
    for pass_no in range(1, max_passes + 1):
        if inv.get("status") == "failed":
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
                        "feedback_pass": pass_no})
        _emit("second_pass_start",
              f"Re-investigating with the triage supplement (pass {pass_no + 1})")
        inv2 = run_investigation(inc_id, timeout=timeout, line_cb=line_cb,
                                 triage_classification=cls)
        if inv2.get("status") == "failed":
            fb["second_pass_failed"] = True
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
    """Annotate the stored ticket records with the investigation's severity.

    NON-DESTRUCTIVE by design: the triage classification is the triage
    agent's judgment and stays untouched (the divergence note tells the
    analyst to reconcile). This adds an `investigation_severity` field to
    the tickets payload and the pipeline initial_ticket record so both DBs
    carry the final assessment alongside the original one.

    (Note: the tickets table's `payload` column IS the ticket dict itself —
    an earlier version assumed a wrapper object and silently failed.)"""
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
                      line_cb=None, triage_classification=None) -> dict:
    """Run the investigation agent over its triaged_alerts/ queue and collect
    the incident folder that absorbed our alert. line_cb streams the agent's
    log output live (used by the app's agent board); triage_classification
    enables explicit severity-divergence annotation."""
    before = {p.name for p in (INV_DIR / "incident_reports").glob("Incident-*")}
    started = time.time()

    _env = {**_openai_compat_env(), "OPENAI_SEED": _llm_seed(),
            # One investigation = one incident: correlation matches against a
            # DIFFERENT incident are recorded as similar_to, never merged.
            "INVESTIGATION_SINGLE_INCIDENT": "1",
            # Single-alert incidents are the norm now — never fall back to the
            # zero-LLM heuristic report; always run the real Pass1/Pass2
            # analysis (costs ~a cent on DeepSeek, quality is the point).
            "INVESTIGATION_FORCE_LLM": "1"}
    if line_cb:
        run = _run_subprocess_streaming([sys.executable, "main.py"], cwd=INV_DIR,
                                        timeout=timeout, extra_env=_env,
                                        line_cb=line_cb)
    else:
        run = _run_subprocess([sys.executable, "main.py"], cwd=INV_DIR,
                              timeout=timeout, extra_env=_env)

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
# 6.  HANDOFF — TRIAGE/INVESTIGATION → REPORTING
# ══════════════════════════════════════════════════════════════════════════════

def handoff_to_reporting(triage_result: dict, incident: dict,
                         investigation_result: dict | None) -> str:
    """Write the input files the reporting agent's adapter expects.
    Returns the sanitized ticket id used for per-ticket output folders."""
    payload = triage_result.get("metakeys_payload", {})
    ticket  = triage_result.get("ticket", {})
    inc_id  = payload.get("incident_id") or ticket.get("incident_id") or "INC-0001"
    title   = payload.get("incident_title") or ticket.get("title") or "SOC incident"
    ticket_id = _safe_ticket_id(ticket.get("unc"))

    outputs = REP_DIR / "outputs"
    inputs  = REP_DIR / "inputs"

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

    _log("HANDOFF", f"triage+investigation -> reporting (ticket {ticket_id})")
    return ticket_id


# ══════════════════════════════════════════════════════════════════════════════
# 7.  STAGE 3 — REPORTING  (subprocess via the reporting agent's own adapter)
# ══════════════════════════════════════════════════════════════════════════════

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
                  run_stamp: str | None = None, line_cb=None) -> dict:
    llm_env = _openai_compat_env()
    has_llm = bool(os.environ.get("OPENAI_API_KEY", "").strip() or llm_env)
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

    final = _read_json(REP_DIR / "outputs" / "final_report.json", {})
    if not final:
        return {"agent": "Reporting Agent", "status": "failed",
                "error": (run.get("stderr") or run.get("stdout") or "")[-1500:],
                "subprocess": run}
    final["orchestrator_subprocess"] = {k: run[k] for k in ("returncode", "success")
                                        if k in run}
    if final.get("status") != "failed":
        exports = export_report_documents(final.get("incident_id"))
        if run_stamp:
            exports = _archive_run_exports(exports, run_stamp)
        final["document_exports"] = exports
        # Persist exports into the on-disk wrapper too, so the CLI / error
        # files / dashboard all see the same export outcome.
        _write_json(REP_DIR / "outputs" / "final_report.json", final)
    return final


def export_report_documents(incident_id: str | None, timeout: int = 180) -> dict:
    """Confirm all report sections and export combined DOCX + PDF via the
    reporting package's own exporters. Returns {docx, pdf, ...errors}.

    A returned path is guaranteed FRESH (written during this call) — a stale
    file from an earlier run is reported as an error, never as a success."""
    started = time.time()
    cmd = [sys.executable, str(REP_DIR / "adapters" / "export_documents.py")]
    if incident_id:
        cmd.append(str(incident_id))
    run = _run_subprocess(cmd, cwd=REP_DIR, timeout=timeout)
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
# 8.  FULL WORKFLOW
# ══════════════════════════════════════════════════════════════════════════════

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
                              progress_fn=None, host: str | None = None, token: str | None = None) -> dict:
    """The single Parsing -> Triage entry point. Both the Start Process
    button and the chat trigger in app.py call this through the shared
    _run_triage_workflow_with_ui() helper — there is no second,
    independently-sequenced path. Stops after the mandatory SOC Analyst
    approval pause; does not start Investigation.

    Raises workflow_state_store.WorkflowAlreadyRunningError if a run is
    already Processing or Awaiting Approval for this incident and
    allow_retry=False."""
    pipeline_db_init()
    inc_id = str(incident.get("id") or incident.get("incidentId") or "unknown")
    title  = incident.get("title") or incident.get("name") or "Untitled"
    
    # Enrich incident with comprehensive raw alerts using APIRetrieval FETCH API / disk exports
    incident = enrich_incident_with_apiretrieval_fetch(incident, host=host, token=token)
    
    ctx: dict = {"incident": incident, "errors": {}, "stages": {}}
    run_started = datetime.now()

    run_id = wss.start_run(inc_id, allow_retry=allow_retry)
    ctx["run_id"] = run_id

    pipeline_insert("alerts_to_triage", {
        "id": inc_id, "incident_id": inc_id, "title": title,
        "severity": str(incident.get("riskScore") or incident.get("severity") or ""),
        "summary": str(incident.get("summary") or "")[:500]})

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
            parsing_result = run_parsing(incident)
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
    wss.set_triage_status(inc_id, run_id, "Processing")
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


def run_full_workflow(incident: dict, *, use_mock_triage: bool = False,
                      force_triage: bool = False, progress_fn=None, **_ignored) -> dict:
    """Backward-compatible alias — grep confirms zero external callers in
    this repo today, so this exists purely as a safety net for an
    undiscovered script. Behavior has changed: it now stops at the
    mandatory Triage approval pause instead of continuing through
    Investigation/Reporting. New code should call
    run_until_triage_approval() directly."""
    return run_until_triage_approval(incident, use_mock_triage=use_mock_triage,
                                     force_triage=force_triage, progress_fn=progress_fn)


def resume_workflow_after_triage_approval(ctx: dict, *, skip_investigation: bool = False,
                                          force_investigation: bool = False,
                                          investigation_timeout: int = 600,
                                          reporting_timeout: int = 480,
                                          progress_fn=None) -> dict:
    """Continues a workflow run past the mandatory Triage approval pause.
    Not called by anything yet — reserved for the next plan phase, which
    will wire an explicit analyst 'Approve' action to this function. Body
    is the previous Investigation/Reporting logic, formerly inline in
    run_full_workflow(), extracted unmodified."""
    incident = ctx["incident"]
    triage_result = ctx["triage"]
    inc_id = str(incident.get("id") or incident.get("incidentId") or "unknown")
    title  = incident.get("title") or incident.get("name") or "Untitled"
    ticket = triage_result["ticket"]
    cls    = ticket.get("classification", "")
    run_started = datetime.now()
    run_stamp   = run_started.strftime("%Y%m%d-%H%M%S")

    investigate = force_investigation or (not skip_investigation
                                          and needs_investigation(triage_result))
    # ── Stage 2: Investigation (optional per routing) ─────────────────────────
    investigation_result: dict | None = None
    if investigate:
        _log("INVESTIGATION", "running investigation agent (subprocess)…")
        investigation_result = investigate_with_feedback(
            triage_result, incident, inc_id, timeout=investigation_timeout,
            feedback_cb=lambda ev, d: _log("FEEDBACK", f"{ev}: {d}"))
        ctx["investigation"] = investigation_result
        if investigation_result["status"] == "failed":
            # Degraded continue: reporting still runs, flagged with limitations.
            ctx["errors"]["investigation"] = investigation_result.get("error", "unknown")
            _log("INVESTIGATION", f"FAILED (continuing degraded): "
                                  f"{ctx['errors']['investigation'][:300]}")
            investigation_result = {
                "agent": "Investigation Agent", "status": "needs_more_data",
                "incident_id": inc_id,
                "summary": "Investigation agent failed; see orchestrator errors.",
                "missing_evidence": ["Investigation run failed."],
                "reporting_mode": "with_limitations",
            }
            ctx["stages"]["investigation"] = "failed"
        else:
            _log("INVESTIGATION", f"complete — {investigation_result['incident_folder']} "
                                  f"status={investigation_result['status']}")
            ctx["stages"]["investigation"] = investigation_result["status"]
            pipeline_insert("post_investigation",
                            build_post_investigation_record(
                                investigation_result, ticket, title,
                                run_stamp=run_stamp))
    else:
        _log("INVESTIGATION", "skipped (routing: no investigation needed)")
        ctx["stages"]["investigation"] = "skipped"

    # ── Stage 3: Reporting ────────────────────────────────────────────────────
    ticket_id = handoff_to_reporting(triage_result, incident, investigation_result)
    pipeline_insert("pending_ticket_report", {
        "id": f"pending_{ticket.get('unc') or inc_id}", "incident_id": inc_id,
        "title": f"[PENDING] {title}", "severity": cls,
        "summary": "Handed off to reporting agent."})

    _log("REPORTING", "running reporting agent (subprocess)…")
    reporting_result = run_reporting(ticket_id, timeout=reporting_timeout,
                                     run_stamp=run_stamp)
    ctx["reporting"] = reporting_result
    if reporting_result.get("status") == "failed":
        ctx["errors"]["reporting"] = reporting_result.get("error",
                                     reporting_result.get("error_summary", "unknown"))
        ctx["stages"]["reporting"] = "failed"
        _log("REPORTING", f"FAILED: {str(ctx['errors']['reporting'])[:300]}")
    else:
        ctx["stages"]["reporting"] = reporting_result.get("status", "completed")
        pipeline_insert("finalized_report", {
            "id": f"final_{ticket.get('unc') or inc_id}@{run_stamp}",
            "incident_id": inc_id, "ticket_unc": ticket.get("unc"),
            "title": f"[FINAL] {title}", "severity": cls,
            "summary": str(reporting_result.get("summary") or "Report generated.")[:500],
            "report": {k: v for k, v in reporting_result.items()
                       if k not in ("subprocess", "orchestrator_subprocess")}})
        _log("REPORTING", f"complete — status={ctx['stages']['reporting']}")

    # Audit trail: one NEW row per workflow execution (stage records REPLACE
    # in place for the same ticket, so this row is the always-visible signal).
    dur = int((datetime.now() - run_started).total_seconds())
    pipeline_insert("workflow_runs", {
        "id": f"run_{run_started.strftime('%Y%m%d-%H%M%S')}_{inc_id[:20]}",
        "incident_id": inc_id,
        "title": f"Run {run_started.strftime('%H:%M:%S')} — {title}",
        "severity": ticket.get("classification") or "",
        "summary": " · ".join(f"{k}: {v}" for k, v in ctx["stages"].items())
                   + f" · ticket {ticket.get('unc')} · {dur}s",
        "stages": ctx["stages"], "ticket_unc": ticket.get("unc"),
        "duration_seconds": dur})

    return ctx


# ══════════════════════════════════════════════════════════════════════════════
# 9.  CLI
# ══════════════════════════════════════════════════════════════════════════════

def main() -> int:
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
    ap.add_argument("--skip-investigation", action="store_true")
    ap.add_argument("--force-investigation", action="store_true")
    ap.add_argument("--investigation-timeout", type=int, default=600)
    ap.add_argument("--reporting-timeout", type=int, default=480)
    ap.add_argument("--force-triage", action="store_true",
                    help="Bypass the triage result cache and re-run Triage")
    args = ap.parse_args()

    incident = json.loads(Path(args.incident_file).read_text(encoding="utf-8"))

    ctx = run_until_triage_approval(
        incident, use_mock_triage=args.mock_triage, force_triage=args.force_triage)

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
    out_path = ROOT / "workflow_last_run.json"
    slim = {k: v for k, v in ctx.items() if k != "incident"}
    _write_json(out_path, slim)
    print(f"  full context written to {out_path.name}")
    return 1 if ctx["errors"].get("triage") else 0


if __name__ == "__main__":
    raise SystemExit(main())
