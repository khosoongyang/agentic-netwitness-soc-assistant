"""
# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, datetime, incident_map, json, re, soc_workflow, tactic_inference, triage_verdict.
# =============================================================================
# File: case_view.py
# Purpose: single backend aggregator for the "My Workspace" case-details
#   page AND the source of the Ask Aegis chatbot's cross-stage context.
# Main functionalities:
#   1. build_case_view(): one call that returns everything app.py needs to
#      render Overview/Output/Timeline/MITRE ATT&CK/Entity Graph/Evidence/
#      Activity for a case, replacing an earlier pattern where app.py
#      computed each field independently inline (the source of several
#      confirmed bugs — see the module docstring below).
#   2. [FYP-EVALUATOR] build_aegis_context(): THE Ask Aegis chatbot context
#      builder — cumulative, size-bounded, cross-stage. See its own
#      [FYP-FUNCTION] docstring further down this file.
# Inputs: incident_id/run_id, read via workflow_state_store (wss) and
#   soc_workflow (sw) — this module is READ-ONLY, it never runs a stage.
# Outputs: display-ready dicts, each non-trivial value wrapped in a
#   provenance envelope ({"value", "source_stage", "source_field",
#   "incident_id", "run_id", "updated_at", "evidence_status"}).
# Workflow position: consumed by app.py's My Workspace case-detail rendering
#   and by the Ask Aegis chat panel, AFTER stages have produced results —
#   this module never triggers stage execution itself.
# Called by [FYP-USED-BY]: app.py (`cv.build_case_view`, `cv.build_aegis_context`).
# Calls [FYP-CALLS]: workflow_state_store, soc_workflow, incident_map,
#   tactic_inference, triage_verdict.
# Key evaluator search terms: build_aegis_context, build_case_view,
#   [FYP-LLM], [FYP-RERUN]
# =============================================================================

case_view.py — single backend aggregator for the case-details page.

app.py must render Overview/Output/Timeline/MITRE ATT&CK/Entity Graph/Evidence/
Activity from ONE call to build_case_view(incident_id, run_id) rather than
computing each field independently inline (the old app.py pattern — the
source of several confirmed bugs: aggregate_verdict() called without the
persisted triage/threat-intel/investigation results, MITRE mappings looked
up in a location that never contained them, Timeline/Entity Graph/Evidence
silently empty because they read the slim, alerts-stripped incidents.raw_json
DB column instead of the run-scoped full-incident artifact).

This module is READ-ONLY: it loads persisted, run-matched data and derives
display structures from it. It never runs a workflow stage, never claims a
lease, never triggers a live corpus scan (ioc_correlation.correlate_iocs is
never called here — the Overview/Evidence builders read the ONE-TIME
persisted snapshot soc_workflow.run_until_triage_approval() computed, via
incidents.ioc_correlation_result_json).

Every non-trivial value returned carries a provenance envelope:
    {"value": ..., "source_stage": ..., "source_field": ...,
     "incident_id": ..., "run_id": ..., "updated_at": ..., "evidence_status": ...}
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from workflow import state_store as wss
from workflow import engine as sw
from agents.investigation.tools.incident_map import build_incident_map, to_dot as incident_map_to_dot
from agents.investigation.tools.tactic_inference import infer_tactics
from agents.investigation.tools.triage_verdict import aggregate_verdict


# ══════════════════════════════════════════════════════════════════════════
# Shared helpers
# ══════════════════════════════════════════════════════════════════════════

# =============================================================================
# [FYP-SECTION] SOC ANALYSIS SUPPORT EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `_provenance` — implements the provenance operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `value`, `source_stage`, `source_field`, `incident_id`, `run_id`, `updated_at`, `evidence_status`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:_extract_agent_key_findings, case_view.py:build_overview; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _provenance(value: Any, *, source_stage: str, source_field: str,
               incident_id: str, run_id: str | None, updated_at: str | None = None,
               evidence_status: str = "persisted") -> dict:
    return {"value": value, "source_stage": source_stage, "source_field": source_field,
            "incident_id": str(incident_id), "run_id": run_id, "updated_at": updated_at,
            "evidence_status": evidence_status}


# [FYP-FUNCTION] `_json_or_empty` — implements the json or empty operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `raw`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:_collect_alert_titles, case_view.py:_confirmed_facts_block, case_view.py:_slim_incident_from_state; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `isinstance`, `loads`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _json_or_empty(raw: Any) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


# [FYP-FUNCTION] `_slim_incident_from_state` — implements the slim incident from state operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `state`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:load_incident_for_case_view; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_json_or_empty`, `get`, `isinstance`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _slim_incident_from_state(state: dict) -> dict:
    raw = _json_or_empty(state.get("raw_json"))
    return raw if isinstance(raw, dict) else {}


# [FYP-FUNCTION] `load_incident_for_case_view` — retrieves load incident for case view data for the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:build_aegis_context, case_view.py:build_case_view; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_slim_incident_from_state`, `get`, `get_state`, `len`, `load_data_availability_for_run`, `load_raw_incident_for_run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def load_incident_for_case_view(incident_id: str, run_id: str) -> tuple[dict, dict, str]:
    """Returns (incident, data_availability, source). Tries the run-scoped
    full-incident artifact FIRST (soc_workflow.load_raw_incident_for_run —
    may include real alerts if the session had them cached at Start-Process
    time), falling back to the slim, alerts-stripped incidents.raw_json DB
    column only if that artifact is unavailable. Never silently claims
    completeness it can't back up — see soc_workflow._data_availability."""
    incident = sw.load_raw_incident_for_run(incident_id, run_id)
    if incident is not None:
        availability = sw.load_data_availability_for_run(incident_id, run_id) or {
            # Legacy artifact predating this metadata — assume incomplete
            # rather than complete, per the "never silently claim
            # completeness" rule.
            "incident_source": "netwitness_live", "alerts_fetch_attempted": None,
            "alerts_fetch_succeeded": None, "alerts_complete": False,
            "alerts_count": len(incident.get("alerts") or []),
            "journal_fetch_succeeded": None,
            "warnings": ["Completeness metadata unavailable for this run "
                        "(artifact predates this tracking)."],
        }
        return incident, availability, "run_artifact"
    state = wss.get_state(incident_id)
    incident = _slim_incident_from_state(state) if state else {}
    availability = {
        "incident_source": "sqlite_slim", "alerts_fetch_attempted": None,
        "alerts_fetch_succeeded": False, "alerts_complete": False,
        "alerts_count": 0, "journal_fetch_succeeded": None,
        "warnings": ["Full event-level data was unavailable for this workflow "
                    "run — reading the slim, alerts-stripped incident record."],
    }
    return incident, availability, "slim_db_fallback"


_UNIQUE_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# [FYP-FUNCTION] `_unique_ips` — implements the unique ips operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `alert_meta`, `*fields`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:build_overview; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `get`, `match`, `split`, `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _unique_ips(alert_meta: dict, *fields: str) -> list[str]:
    """Splits comma-joined artifacts (e.g. "1.2.3.4,5.6.7.8" counted as ONE
    list item by the old app.py code) and validates each candidate as a
    real IPv4 before counting it — the old count() was a bare list-length
    over possibly-malformed entries."""
    out: list[str] = []
    for field in fields:
        for entry in (alert_meta.get(field) or []):
            for candidate in str(entry).split(","):
                candidate = candidate.strip()
                if _UNIQUE_IP_RE.match(candidate) and candidate not in out:
                    out.append(candidate)
    return out


# ══════════════════════════════════════════════════════════════════════════
# Overview
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `_extract_agent_key_findings` — transforms extract agent key findings input into the stable representation required by downstream SOC analysis support processing.
# [FYP-INPUT] Parameters: `inv_result`, `triage_result`, `incident_id`, `run_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:build_overview; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_provenance`, `append`, `get`, `isinstance`, `len`, `lower`, `match`, `splitlines`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _extract_agent_key_findings(inv_result: dict | None, triage_result: dict | None,
                                incident_id: str, run_id: str) -> list[dict]:
    """Agent-narrated findings (as opposed to build_overview()'s own
    deterministic-signal findings, appended separately by its caller).

    Strict waterfall, each tier only consulted if the previous produced
    nothing: Investigation's structured key_findings list -> Investigation's
    one-line summary -> bullets regex-extracted from narrative_report's own
    "Key Finding(s)"/"Executive Summary" markdown section -> (only if
    Investigation gave NOTHING at all) Triage's key_findings/ticket.summary
    as a pre-investigation fallback. Investigation findings are never mixed
    with Triage findings in the same call — an approved Investigation
    result is treated as having superseded Triage's read of the incident,
    not as a peer source to merge with. Each returned item carries its own
    _provenance() envelope naming the exact source stage/field it was
    read from, e.g. investigation_result_json.narrative_report."""
    findings: list[dict] = []
    if inv_result and isinstance(inv_result, dict):
        raw_kf = inv_result.get("key_findings")
        if isinstance(raw_kf, list) and raw_kf:
            for item in raw_kf[:5]:
                text = str(item.get("title") if isinstance(item, dict) else item).strip()
                if text:
                    findings.append({
                        "icon": "⌕", "title": text[:120], "desc": "Investigation Agent interpretation",
                        "confidence": "high", "origin": "investigation_agent_finding",
                        "provenance": _provenance(text[:120], source_stage="investigation",
                                                  source_field="investigation_result_json.key_findings",
                                                  incident_id=incident_id, run_id=run_id),
                    })
        elif inv_result.get("summary"):
            summary_text = str(inv_result["summary"]).strip()
            if summary_text:
                findings.append({
                    "icon": "⌕", "title": summary_text[:120], "desc": "Investigation Agent summary",
                    "confidence": "high", "origin": "investigation_agent_summary",
                    "provenance": _provenance(summary_text[:120], source_stage="investigation",
                                              source_field="investigation_result_json.summary",
                                              incident_id=incident_id, run_id=run_id),
                })
        elif inv_result.get("narrative_report"):
            report = str(inv_result["narrative_report"])
            lines = report.splitlines()
            in_section = False
            extracted_bullets = []
            for line in lines:
                l_strip = line.strip()
                if l_strip.startswith("#"):
                    l_low = l_strip.lower()
                    if "key finding" in l_low or "executive summary" in l_low or "key analytical finding" in l_low:
                        in_section = True
                        continue
                    elif in_section:
                        in_section = False
                if in_section and (l_strip.startswith("- ") or l_strip.startswith("* ") or re.match(r"^\d+\.", l_strip)):
                    clean_line = re.sub(r"^\s*[-*\d.]+\s*", "", l_strip)
                    clean_line = re.sub(r"\*\*|\*", "", clean_line).strip()
                    if clean_line and len(clean_line) > 10:
                        extracted_bullets.append(clean_line)
                        if len(extracted_bullets) >= 4:
                            break
            for bullet in extracted_bullets:
                findings.append({
                    "icon": "⌕", "title": bullet[:120], "desc": "Investigation Agent narrative finding",
                    "confidence": "high", "origin": "investigation_agent_narrative",
                    "provenance": _provenance(bullet[:120], source_stage="investigation",
                                              source_field="investigation_result_json.narrative_report",
                                              incident_id=incident_id, run_id=run_id),
                })

    if not findings and triage_result and isinstance(triage_result, dict):
        ticket = triage_result.get("ticket") or {}
        tr_kf = triage_result.get("key_findings") or ticket.get("key_findings")
        if isinstance(tr_kf, list) and tr_kf:
            for item in tr_kf[:5]:
                text = str(item.get("title") if isinstance(item, dict) else item).strip()
                if text:
                    findings.append({
                        "icon": "⚡", "title": text[:120], "desc": "Triage Agent interpretation",
                        "confidence": "elevated", "origin": "triage_agent_finding",
                        "provenance": _provenance(text[:120], source_stage="triage",
                                                  source_field="triage_result_json.key_findings",
                                                  incident_id=incident_id, run_id=run_id),
                    })
        elif ticket.get("summary"):
            sum_text = str(ticket["summary"]).strip()
            if sum_text:
                findings.append({
                    "icon": "⚡", "title": sum_text[:120], "desc": "Triage Agent summary",
                    "confidence": "elevated", "origin": "triage_agent_summary",
                    "provenance": _provenance(sum_text[:120], source_stage="triage",
                                              source_field="triage_result_json.ticket.summary",
                                              incident_id=incident_id, run_id=run_id),
                })

    return findings


# [FYP-FUNCTION] `_collect_alert_titles` — implements the collect alert titles operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `incident`, `state`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:build_overview; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_json_or_empty`, `append`, `get`, `isinstance`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _collect_alert_titles(incident: dict, state: dict) -> list[str]:
    """Dedupes (order-preserving) alert titles across every stage that
    might name the underlying alert(s), in a fixed priority order: raw
    incident alertMeta.AlertTitles -> incident.alerts[].title/name/
    signature_id/type -> Parsing's alert_titles (or its single
    processed_alert.alert_name) -> Triage's ticket.title -> Investigation's
    alert_titles -> (only if still empty) the bare incident title/name.
    Feeds build_overview()'s deterministic keyword-icon key findings
    (below) — NOT the same list as _extract_agent_key_findings()'s
    agent-narrated findings."""
    titles: list[str] = []
    am = incident.get("alertMeta") or {}
    if am.get("AlertTitles"):
        for t in am["AlertTitles"]:
            if t and str(t) not in titles:
                titles.append(str(t))

    for alert in incident.get("alerts") or []:
        if isinstance(alert, dict):
            t = (alert.get("title") or alert.get("name") or alert.get("signature_id") or alert.get("type"))
            if t and str(t) not in titles:
                titles.append(str(t))

    parsed = _json_or_empty(state.get("parsing_result_json"))
    if parsed.get("alert_titles"):
        for t in parsed["alert_titles"]:
            if t and str(t) not in titles:
                titles.append(str(t))
    elif (parsed.get("processed_alert") or {}).get("alert_name"):
        aname = str(parsed["processed_alert"]["alert_name"])
        if aname not in titles:
            titles.append(aname)

    triage = _json_or_empty(state.get("triage_result_json"))
    t_ticket = triage.get("ticket") or {}
    if t_ticket.get("title") and t_ticket["title"] not in titles:
        titles.append(str(t_ticket["title"]))

    inv = _json_or_empty(state.get("investigation_result_json"))
    if inv.get("alert_titles"):
        for t in inv["alert_titles"]:
            if t and str(t) not in titles:
                titles.append(str(t))

    if not titles and (incident.get("title") or incident.get("name")):
        inc_title = str(incident.get("title") or incident.get("name"))
        if inc_title and inc_title != "?":
            titles.append(inc_title)

    return titles


def build_overview(state: dict, incident: dict, incident_id: str, run_id: str) -> dict:
    """
    [FYP-FUNCTION] Case Overview tab data — key findings + provenance-
    wrapped case_context fields (severity/classification/verdict/host/
    user/status/IOC count).

    [FYP-USED-BY]: internal only — build_case_view() (My Workspace
    Overview tab) and build_aegis_context() (flattened via
    _flatten_case_summary() into Ask Aegis's case_summary). Not called
    directly by app.py.

    [FYP-CALLS] triage_verdict.aggregate_verdict() — this is the fix for
    the bug class named in the module docstring: the OLD app.py called
    aggregate_verdict() with only the raw incident, never passing it the
    persisted triage/threat-intel/investigation/ioc_correlation results it
    needs to produce anything beyond a bare NetWitness-severity guess. Here
    those four result blobs are loaded and passed through explicitly,
    gated on each stage's own status (Threat Intel only once "Complete"/
    "Complete with Warnings"; Investigation only once "Awaiting Approval"/
    "Approved" — i.e. NOT "Approved" alone, since Overview must reflect an
    unapproved-but-produced Investigation result the same way the
    Investigation tab itself does, or the two tabs would visibly disagree).

    key_findings assembly order: collected alert titles (keyword-iconed,
    via _collect_alert_titles()) -> agent-narrated findings (via
    _extract_agent_key_findings()) -> deterministic verdict signals
    (aggregate_verdict()'s own per-signal rationale, sorted by severity
    level, zero/absent/errored signals skipped). host/user are populated
    ONLY from structured alertMeta/ticket fields — deliberately never
    scraped from investigation narrative prose or AlertTitles free text,
    since a name mentioned in either is not a confirmed User/Host.

    netwitness_severity and triage_classification are kept as two
    separately labeled fields (never collapsed into one "Base Severity")
    because they can legitimately disagree — NetWitness's own risk
    scoring is not the same claim as the Triage Agent's classification.
    """
    am = incident.get("alertMeta") or {}
    triage_result = _json_or_empty(state.get("triage_result_json"))
    ti_status = state.get("threat_intel_status")
    ti_result = (_json_or_empty(state.get("threat_intel_result_json"))
                if ti_status in ("Complete", "Complete with Warnings") else None)
    inv_status = state.get("investigation_status")
    inv_result = (_json_or_empty(state.get("investigation_result_json"))
                 if inv_status in ("Awaiting Approval", "Approved") else None)
    ioc_corr = (_json_or_empty(state.get("ioc_correlation_result_json"))
               if state.get("ioc_correlation_status") else None)

    verdict = aggregate_verdict(incident, triage_result=triage_result, ti_result=ti_result,
                               investigation_result=inv_result,
                               ioc_correlation_result=ioc_corr)

    key_findings: list[dict] = []
    _kw = [("hta", ""), ("c2", ""), ("command", ""), ("exfil", ""),
           ("autorun", ""), ("credential", ""), ("powershell", "⌘"),
           ("lateral", "↔"), ("ransom", ""), ("phish", ""), ("beacon", "")]
    collected_titles = _collect_alert_titles(incident, state)
    for t in list(dict.fromkeys(collected_titles))[:6]:
        tl = str(t).lower()
        icon = next((e for k, e in _kw if k in tl), "")
        key_findings.append({
            "icon": icon, "title": str(t)[:72], "desc": "Observed alert behaviour",
            "confidence": "", "origin": "collected_alert_title",
            "provenance": _provenance(str(t), source_stage="raw_incident",
                                      source_field="alert_titles",
                                      incident_id=incident_id, run_id=run_id),
        })

    agent_findings = _extract_agent_key_findings(
        inv_result, triage_result, incident_id, run_id)
    key_findings.extend(agent_findings)

    if verdict.get("available"):
        _conf = {3: "high", 2: "elevated", 1: "moderate", 0: "low"}
        _signal_display_name = {
            "base severity": {"triage classification": "Triage Classification",
                              "incident severity": "NetWitness Severity"},
        }
        for s in sorted(verdict.get("signals", []), key=lambda s: -s.get("level", 0)):
            if s.get("error") or s.get("absent") or s.get("level", 0) == 0:
                continue
            display_name = _signal_display_name.get(s["name"], {}).get(
                s.get("detail", ""), s["name"].title())
            key_findings.append({
                "icon": "!", "title": f"{display_name} — {s['label']}",
                "desc": s.get("detail", ""), "confidence": _conf.get(s["level"], ""),
                "origin": "deterministic_signal",
                "provenance": _provenance(s["label"], source_stage="unified_verdict",
                                          source_field=f"signals[{s['name']}]",
                                          incident_id=incident_id, run_id=run_id),
            })

    # NetWitness severity vs. Triage Classification — kept explicitly
    # distinct and separately named (never "Base Severity" again).
    raw_risk = incident.get("riskScore") or incident.get("severity")
    netwitness_sev = (state.get("severity") or "LOW")
    ticket = triage_result.get("ticket") or {}
    triage_cls = ticket.get("classification")

    host_val, host_stage, host_field = "—", None, None
    parsed_ctx = _json_or_empty(state.get("parsing_result_json"))
    if am.get("Hostname"):
        host_val = am["Hostname"][0]
        host_stage, host_field = "raw_incident", "alertMeta.Hostname[0]"
    elif incident.get("hostname"):
        host_val = incident["hostname"]
        host_stage, host_field = "raw_incident", "hostname"
    elif ticket.get("host"):
        host_val = ticket["host"]
        host_stage, host_field = "triage", "ticket.host"

    user_val, user_stage, user_field = "—", None, None
    if am.get("User"):
        user_val = am["User"][0]
        user_stage, user_field = "raw_incident", "alertMeta.User[0]"
    elif am.get("AdUser"):
        user_val = am["AdUser"][0]
        user_stage, user_field = "raw_incident", "alertMeta.AdUser[0]"
    # NOTE: deliberately never populated from investigation narrative/summary
    # prose, nor from a name embedded in AlertTitles free text — a name
    # mentioned in either is not a confirmed User/Host, full stop.

    unique_ips = _unique_ips(am, "SourceIp", "DestinationIp")

    case_context = {
        "netwitness_severity": _provenance(
            str(netwitness_sev).title(), source_stage="raw_incident",
            source_field="riskScore/severity", incident_id=incident_id, run_id=run_id),
        "triage_classification": _provenance(
            str(triage_cls).upper() if triage_cls else "—",
            source_stage="triage", source_field="triage_result_json.ticket.classification",
            incident_id=incident_id, run_id=run_id,
            evidence_status="persisted" if triage_cls else "unavailable"),
        "unified_verdict": {
            "value": verdict.get("level", "—") if verdict.get("available") else "—",
            "source_stages": [s["name"].replace(" ", "_") for s in verdict.get("signals", [])
                              if not s.get("error") and not s.get("absent")],
            "reasons": [f"{s['name']}: {s['label']}" for s in verdict.get("rationale", [])
                       if s.get("level", 0) > 0],
            "rule": "aggregate_verdict_v1",
            "incident_id": str(incident_id), "run_id": run_id,
        },
        "host": _provenance(host_val, source_stage=host_stage or "unavailable",
                            source_field=host_field or "", incident_id=incident_id,
                            run_id=run_id,
                            evidence_status="persisted" if host_stage else "unavailable"),
        "user": _provenance(user_val, source_stage=user_stage or "unavailable",
                            source_field=user_field or "", incident_id=incident_id,
                            run_id=run_id,
                            evidence_status="persisted" if user_stage else "unavailable"),
        "netwitness_status": _provenance(
            state.get("status") or "—", source_stage="raw_incident", source_field="status",
            incident_id=incident_id, run_id=run_id),
        "workflow_status": _provenance(
            state.get("workflow_status") or "—", source_stage="workflow",
            source_field="incidents.workflow_status", incident_id=incident_id, run_id=run_id),
        "ioc_ip_count": _provenance(
            len(unique_ips), source_stage="raw_incident",
            source_field="alertMeta.SourceIp/DestinationIp (deduped, IPv4-validated)",
            incident_id=incident_id, run_id=run_id),
    }
    return {"key_findings": key_findings, "case_context": case_context}


# ══════════════════════════════════════════════════════════════════════════
# MITRE — origin-tagged, no fabricated confidence, no new review workflow
# ══════════════════════════════════════════════════════════════════════════

# Mirrors soc_investigation_agent_revised/mitre_mapper.py's
# generate_markdown_table() format exactly (read-only reference to that
# format — this file does not import or depend on anything in that
# directory):
#   | Timeline Phase / Activity | Observed Evidence | MITRE Tactic |
#   | MITRE Technique Name | MITRE ID |
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


# [FYP-FUNCTION] `_split_table_row` — implements the split table row operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `line`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:_parse_mitre_markdown_table; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `endswith`, `replace`, `split`, `startswith`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _split_table_row(line: str) -> list[str]:
    """Splits a markdown table row on unescaped pipes, unescaping \\| within
    cells, tolerating leading/trailing pipes and surrounding whitespace."""
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    # Split on a pipe NOT preceded by a backslash.
    cells = re.split(r"(?<!\\)\|", line)
    return [c.replace("\\|", "|").strip() for c in cells]


# [FYP-FUNCTION] `_parse_mitre_markdown_table` — transforms parse mitre markdown table input into the stable representation required by downstream SOC analysis support processing.
# [FYP-INPUT] Parameters: `narrative_report`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:build_mitre, tests/test_investigation_stage.py:test_mitre_markdown_parser_extracts_rows, tests/test_investigation_stage.py:test_mitre_markdown_parser_handles_escaped_pipes; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_split_table_row`, `append`, `enumerate`, `items`, `len`, `lower`, `match`, `set`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _parse_mitre_markdown_table(narrative_report: str) -> tuple[list[dict], list[str]]:
    """Returns (mappings, warnings). Locates the table by its HEADER ROW
    (a line whose cells include MITRE Tactic / MITRE Technique Name /
    MITRE ID, in ANY order) rather than by position, so column reordering
    is tolerated. A missing column yields '' for that field rather than
    raising. Any row that can't be parsed is skipped with a warning
    appended rather than aborting the whole parse. Never fabricates
    confidence — the Investigation Agent's own schema (MitreTTPMapping)
    has no such field."""
    mappings: list[dict] = []
    warnings: list[str] = []
    if not narrative_report:
        return mappings, warnings
    lines = narrative_report.splitlines()
    header_idx = None
    col_map: dict[int, str] = {}
    for i, line in enumerate(lines):
        if "|" not in line:
            continue
        cells = [c.lower() for c in _split_table_row(line)]
        found = {idx: _MITRE_HEADER_ALIASES[c] for idx, c in enumerate(cells)
                if c in _MITRE_HEADER_ALIASES}
        # Only "tactic" + "technique_id" are required to positively identify
        # this AS the MITRE table (vs. e.g. the unrelated Playbook Execution
        # Trace table elsewhere in the same narrative) — technique_name,
        # observed_evidence, and timeline_phase may be absent from a
        # differently-shaped table and still get parsed (missing columns
        # default to "" per-row, never raise).
        if {"tactic", "technique_id"} <= set(found.values()):
            header_idx = i
            col_map = found
            break
    if header_idx is None:
        return mappings, warnings
    # Skip the header and an optional "| --- | --- |" separator row.
    row_start = header_idx + 1
    if row_start < len(lines) and re.match(r"^\s*\|?[\s:|-]+\|?\s*$", lines[row_start]):
        row_start += 1
    for line in lines[row_start:]:
        if "|" not in line.strip() or not line.strip().startswith("|"):
            break   # table ended
        cells = _split_table_row(line)
        row: dict[str, str] = {"timeline_phase": "", "observed_evidence": "",
                               "tactic": "", "technique_name": "", "technique_id": ""}
        try:
            for idx, field in col_map.items():
                if idx < len(cells):
                    row[field] = cells[idx]
        except Exception as exc:
            warnings.append(f"Skipped an unparseable MITRE table row: {exc}")
            continue
        if not (row["tactic"] or row["technique_id"] or row["technique_name"]):
            continue
        mappings.append({
            "tactic": row["tactic"] or "Unclassified",
            "technique_id": row["technique_id"] or "",
            "technique_name": row["technique_name"] or "",
            "evidence": [row["observed_evidence"]] if row["observed_evidence"] else [],
            "timeline_phase": row["timeline_phase"],
            "origin": "investigation_agent_suggestion",
            "source": "investigation_agent",
        })
    return mappings, warnings


def build_mitre(state: dict, incident: dict, incident_id: str, run_id: str) -> dict:
    """
    [FYP-FUNCTION] MITRE ATT&CK tab data — three origin-tagged tiers,
    additive not exclusive-or on tiers 1 vs 3 (both can contribute), never
    fabricating a confidence score the underlying source doesn't actually
    have.

    [FYP-USED-BY]: internal only — build_case_view() (MITRE ATT&CK tab)
    and build_aegis_context() (mitre list, tactic/technique_id/
    technique_name/origin only — evidence/timeline_phase dropped for the
    chat context's size budget). Not called directly by app.py.

    Tier 1 — netwitness_detection_mapping: NetWitness's own
    AlertTactics/AlertTechniques arrays, paired by index. Real detection
    data, but "detection" != "analyst-confirmed", hence the distinct
    origin label rather than a generic "confirmed" — see the module's
    honesty-in-labeling rule.

    Tier 2 — deterministic_keyword_inference (tactic_inference.infer_
    tactics()): fired ONLY when Tier 1 produced nothing, since this module
    never overrides real NetWitness data with a keyword guess. Only the
    inferrer's primary (index-0) technique gets technique_name populated —
    reusing that one name across every other technique in a multi-hit
    result would mislabel them (see inline comment at the loop).

    Tier 3 — investigation_agent_suggestion: parsed from Investigation's
    narrative_report markdown table via _parse_mitre_markdown_table(),
    gated on investigation_status in ("Awaiting Approval", "Approved") —
    same not-Approved-alone gating as build_overview(), for the same
    tab-consistency reason. Always additive to whatever Tier 1/2 already
    produced (investigation_result_json has no structured mitre_mappings
    field — the agent's FinalIncidentAnalysis is only ever rendered to
    markdown, never serialized to JSON, so markdown parsing is the only
    way to surface it here).
    """
    am = incident.get("alertMeta") or {}
    mappings: list[dict] = []
    warnings: list[str] = []

    # Tier 1: NetWitness-native detection data — real, but "detection" is
    # not the same claim as "analyst-confirmed", so it gets its own honest
    # origin label rather than "confirmed".
    nw_tactics = am.get("AlertTactics") or []
    nw_techs = am.get("AlertTechniques") or []
    for i in range(max(len(nw_tactics), len(nw_techs))):
        mappings.append({
            "tactic": nw_tactics[i] if i < len(nw_tactics) else (nw_tactics[-1] if nw_tactics else "Unclassified"),
            "technique_id": nw_techs[i] if i < len(nw_techs) else "",
            "technique_name": "", "evidence": [], "origin": "netwitness_detection_mapping",
            "source": "netwitness",
        })

    # Tier 2: deterministic keyword inference (tactic_inference.py) — only
    # when the incident carries no native MITRE data of its own (this
    # module's own honesty rule: never overrides real data).
    if not mappings:
        inf = infer_tactics(incident)
        if inf.get("available"):
            techniques = inf.get("techniques") or ([inf["technique"]] if inf.get("technique") else [])
            tactics = inf.get("tactics") or ([inf["tactic"]] if inf.get("tactic") else [])
            for i in range(max(len(techniques), 1)):
                mappings.append({
                    "tactic": tactics[i] if i < len(tactics) else (tactics[-1] if tactics else "Unclassified"),
                    "technique_id": techniques[i] if i < len(techniques) else "",
                    # infer_tactics() only names ONE technique (its primary
                    # pick, index 0 — see the module's own "foothold-first"
                    # ordering note); reusing that single name for every
                    # OTHER technique in a multi-hit result would mislabel
                    # them, so only the primary entry gets a name here.
                    "technique_name": (inf.get("technique_name") or "") if i == 0 else "",
                    "evidence": inf.get("evidence") or [],
                    "origin": "deterministic_keyword_inference",
                    "source": inf.get("source") or "tactic_inference",
                })

    # Tier 3: Investigation Agent's own MITRE table — parsed from
    # narrative_report markdown, since investigation_result_json has no
    # structured mitre_mappings field (confirmed: the agent's
    # FinalIncidentAnalysis is never serialized to JSON, only rendered to
    # markdown). Never promoted above "agent_suggestion".
    inv_status = state.get("investigation_status")
    if inv_status in ("Awaiting Approval", "Approved"):
        inv_result = _json_or_empty(state.get("investigation_result_json"))
        inv_mappings, inv_warnings = _parse_mitre_markdown_table(
            inv_result.get("narrative_report") or "")
        mappings.extend(inv_mappings)
        warnings.extend(inv_warnings)

    return {"mappings": mappings, "warnings": warnings}


# ══════════════════════════════════════════════════════════════════════════
# Timeline / Entity Graph / Evidence
# ══════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `_availability_warning` — implements the availability warning operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `data_availability`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:build_entity_graph, case_view.py:build_evidence, case_view.py:build_timeline; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _availability_warning(data_availability: dict) -> str | None:
    if data_availability.get("alerts_complete"):
        return None
    if data_availability.get("alerts_fetch_succeeded") is False and \
            data_availability.get("alerts_fetch_attempted"):
        return "Full event-level data was unavailable for this workflow run."
    if data_availability.get("incident_source") == "sqlite_slim":
        return "Full event-level data was unavailable for this workflow run."
    return "Full event-level data was unavailable for this workflow run."


# [FYP-FUNCTION] `_format_timestamp` — constructs format timestamp output for the next SOC analysis support consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `ts`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:build_timeline; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `float`, `fromtimestamp`, `str`, `strftime`, `strip`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _format_timestamp(ts: Any) -> str | None:
    if ts is None:
        return None
    s = str(ts).strip()
    if not s:
        return None
    try:
        val = float(s)
        if val > 1_000_000_000_000:
            val = val / 1000.0
        if val > 1_000_000_000:
            dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OverflowError):
        pass
    return s


def build_timeline(state: dict, incident: dict, incident_id: str, run_id: str,
                   data_availability: dict) -> list[dict]:
    """
    [FYP-FUNCTION] Timeline tab data — merges three independently-sourced
    event streams into one chronologically sorted, deduped list, each item
    tagged with event_type in {security, workflow, info, warning}.

    [FYP-USED-BY]: internal only — build_case_view() (Timeline tab). Not
    called by build_aegis_context() (Ask Aegis has no timeline section;
    see the module's [FYP-CALLS] note on why it reuses only build_overview/
    build_mitre/build_evidence) and not called directly by app.py.

    [FYP-CALLS] incident_map.build_incident_map() for the security-event
    stream (imap["timeline"]). Adds: (1) an explicit "no events" info item
    when the alert fetch itself succeeded but genuinely found nothing, vs.
    (2) an availability warning item when the fetch didn't succeed/wasn't
    attempted — these two states must never be conflated (see
    _availability_warning() and the module's "never silently claim
    completeness" rule); (3) workflow stage-completion timestamps read
    straight off `state`'s *_updated_at columns; (4) analyst approval
    decisions via workflow_state_store.get_approval_history(). Final
    sort/dedupe key is (timestamp, event) — None timestamps sort first,
    which is fine since they're only info/warning banners.
    """
    imap = build_incident_map(incident)
    items: list[dict] = []
    availability_note = _availability_warning(data_availability)

    for ev in imap.get("timeline", []):
        # Genuinely-empty (a successful fetch that found nothing) reads
        # differently from "we don't know" — see data_availability.
        items.append({
            "timestamp": _format_timestamp(ev.get("time")), "event": ev.get("event"),
            "event_type": "security", "source_stage": "raw_incident",
            "evidence_reference": "incident_map", "incident_id": str(incident_id),
            "run_id": run_id,
        })
    if not imap.get("timeline") and data_availability.get("alerts_fetch_succeeded"):
        items.append({"timestamp": None, "event": "No events were returned for this incident.",
                     "event_type": "info", "source_stage": "raw_incident",
                     "evidence_reference": "incident_map", "incident_id": str(incident_id),
                     "run_id": run_id})
    elif availability_note:
        items.append({"timestamp": None, "event": availability_note, "event_type": "warning",
                     "source_stage": "raw_incident", "evidence_reference": "data_availability",
                     "incident_id": str(incident_id), "run_id": run_id})

    # Workflow stage-completion timestamps.
    for stage, col in (("parsing", None), ("threat_intel", "threat_intel_updated_at"),
                      ("investigation", "investigation_updated_at"),
                      ("reporting", "reporting_updated_at")):
        if col and state.get(col):
            items.append({"timestamp": _format_timestamp(state[col]),
                          "event": f"{stage.replace('_', ' ').title()} completed",
                          "event_type": "workflow", "source_stage": stage,
                          "evidence_reference": col, "incident_id": str(incident_id),
                          "run_id": run_id})

    # Analyst approval decisions.
    for row in wss.get_approval_history(incident_id, run_id):
        items.append({
            "timestamp": _format_timestamp(row.get("decided_at")),
            "event": f"{row.get('approval_stage', '').title()} {row.get('decision')} "
                    f"by {row.get('analyst') or 'unknown'} "
                    f"(attempt {row.get('stage_attempt', 1)}/{row.get('approval_attempt', 1)})",
            "event_type": "workflow", "source_stage": row.get("approval_stage"),
            "evidence_reference": "workflow_approvals", "incident_id": str(incident_id),
            "run_id": run_id,
        })

    # Sort chronologically (None timestamps first is fine — they're
    # info/warning banners, not real events) and dedupe by (time, event).
    seen = set()
    deduped = []
    for it in sorted(items, key=lambda i: (i["timestamp"] or "")):
        key = (it["timestamp"], it["event"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(it)
    return deduped


def build_entity_graph(incident: dict, data_availability: dict) -> dict:
    """
    [FYP-FUNCTION] Entity Graph tab data — nodes/edges/stats from
    incident_map.build_incident_map(), with one honesty relabel applied on
    top: an edge whose ONLY evidence is "alertMeta co-occurrence" (e.g.
    every SourceIp paired with every DestinationIp in the same alert
    record) is relation "connected_to" from incident_map's own naming, but
    that is not an observed network connection — merely two values that
    appeared in the same alert. Relabeled here to "possibly_related" with
    evidence_status="co_occurrence_only" so the graph UI doesn't imply a
    confirmed link that was never actually observed. Every other edge is
    tagged evidence_status "observed" (has real evidence) or "unlabeled"
    (none recorded) instead.

    [FYP-USED-BY]: internal only — build_case_view() (Entity Graph tab).
    the frontend renders the returned nodes/edges via its graph view,
    importing incident_map.to_dot directly (as `_cv_to_dot`) rather than
    through this module's own `incident_map_to_dot` re-export at the top
    of this file — that re-export is currently unused, left available for
    a caller that wants the DOT conversion without importing incident_map
    separately. Not part of build_aegis_context()'s context (chat has no
    graph rendering) and no other function here calls build_entity_graph().
    """
    imap = build_incident_map(incident)
    edges = []
    for e in imap.get("edges", []):
        relation = e.get("relation", "")
        evidence = e.get("evidence") or []
        # Co-occurrence in alertMeta lists (e.g. every SourceIp paired with
        # every DestinationIp) is NOT an observed connection — relabel it
        # honestly rather than implying a confirmed network link.
        if relation.startswith("connected_to") and evidence == ["alertMeta co-occurrence"]:
            edges.append({**e, "relation": "possibly_related",
                         "evidence_status": "co_occurrence_only",
                         "provenance": "alertMeta co-occurrence (not an observed connection)"})
        else:
            edges.append({**e, "evidence_status": "observed" if evidence else "unlabeled",
                         "provenance": ", ".join(evidence) if evidence else ""})
    return {"nodes": imap.get("nodes", []), "edges": edges,
            "stats": imap.get("stats", {}),
            "data_availability_warning": _availability_warning(data_availability)}


def build_evidence(state: dict, incident: dict, incident_id: str, run_id: str,
                   data_availability: dict) -> list[dict]:
    """
    [FYP-FUNCTION] Evidence tab data — a flat, uniformly-shaped list
    ({evidence_id, evidence_type, source, timestamp, summary,
    raw_reference, related_entities, supported_findings, evidence_status,
    provenance}) unioning five independent evidence classes, each present
    only if its stage actually produced something:

    1. raw alerts (up to 20, evidence_type="alert"), or — if none —
       a single "warning" item explaining why (never both).
    2. Threat Intel enrichment (gated: threat_intel_status in ("Complete",
       "Complete with Warnings")) — one summary item plus one item per
       note. IOCs are read straight from the persisted threat_intel_
       result_json; this function does NOT call ioc_correlation.
       correlate_iocs() itself (see the module docstring's "READ-ONLY,
       never triggers a live corpus scan" guarantee).
    3. IOC correlation results (up to 20, evidence_type=
       "internal_correlation") — the ONE-TIME persisted snapshot from
       ioc_correlation_result_json, explicitly labeled with its own
       ioc_correlation_updated_at as "persisted snapshot (...)" so it
       reads as a point-in-time result, not a live lookup.
    4. Investigation's own narrative summary (evidence_type=
       "agent_inference"), gated the same not-Approved-alone way as
       build_overview()/build_mitre() (Awaiting Approval or Approved).
    5. Analyst approval decisions, via workflow_state_store.
       get_approval_history() (evidence_type="analyst_decision").

    [FYP-USED-BY]: build_case_view() (Evidence tab, full list) AND
    build_aegis_context() (evidence_highlights, capped to _MAX_LIST_ITEMS
    and reduced to evidence_type/source/summary only). Not called directly
    by app.py.
    """
    items: list[dict] = []
    availability_note = _availability_warning(data_availability)

    alerts = incident.get("alerts")
    if alerts:
        for i, alert in enumerate(alerts[:20]):
            items.append({
                "evidence_id": f"alert-{i}", "evidence_type": "alert", "source": "netwitness",
                "timestamp": alert.get("created") or alert.get("receivedTime"),
                "summary": alert.get("title") or alert.get("name") or "Untitled alert",
                "raw_reference": f"incident.alerts[{i}]", "related_entities": [],
                "supported_findings": [], "evidence_status": "observed",
                "provenance": "netwitness_live",
            })
    elif availability_note:
        items.append({"evidence_id": "availability-warning", "evidence_type": "warning",
                     "source": "system", "timestamp": None, "summary": availability_note,
                     "raw_reference": "", "related_entities": [], "supported_findings": [],
                     "evidence_status": "missing", "provenance": "data_availability"})

    ti_status = state.get("threat_intel_status")
    if ti_status in ("Complete", "Complete with Warnings"):
        ti_result = _json_or_empty(state.get("threat_intel_result_json"))
        ti_block = ti_result.get("threat_intelligence") or {}
        ti_iocs = ti_block.get("iocs") or {}
        related = [v for v in (
            [ti_iocs.get("file_hash")]
            + (ti_iocs.get("ip_indicators") or [])
            + (ti_iocs.get("domain_indicators") or [])
        ) if v]
        items.append({
            "evidence_id": "ti-summary", "evidence_type": "external_intelligence",
            "source": "threat_intel", "timestamp": ti_result.get("generated_at"),
            "summary": f"Threat Intelligence enrichment: "
                      f"{ti_result.get('enrichment_risk_level', 'Unknown')} risk "
                      f"(score {ti_result.get('enrichment_risk_score', 0)})",
            "raw_reference": "threat_intel_result_json.threat_intelligence",
            "related_entities": related,
            "supported_findings": ti_result.get("enrichment_risk_reasons") or [],
            "evidence_status": "external_intelligence",
            "provenance": "virustotal, abuseipdb, alienvault_otx",
        })
        for i, note in enumerate(ti_block.get("notes") or []):
            items.append({
                "evidence_id": f"ti-note-{i}", "evidence_type": "external_intelligence",
                "source": "threat_intel", "timestamp": ti_result.get("generated_at"),
                "summary": note,
                "raw_reference": "threat_intel_result_json.threat_intelligence.notes",
                "related_entities": [], "supported_findings": [],
                "evidence_status": "informational", "provenance": "threat_intel",
            })

    ioc_status = state.get("ioc_correlation_status")
    if ioc_status:
        corr = _json_or_empty(state.get("ioc_correlation_result_json"))
        for i, r in enumerate((corr.get("results") or [])[:20]):
            items.append({
                "evidence_id": f"ioc-corr-{i}", "evidence_type": "internal_correlation",
                "source": "ioc_correlation", "timestamp": state.get("ioc_correlation_updated_at"),
                "summary": f"{r.get('value')} — {r.get('confidence', 'none')} internal confidence",
                "raw_reference": "ioc_correlation_result_json.results",
                "related_entities": [r.get("value")], "supported_findings": [],
                "evidence_status": "internal_correlation",
                "provenance": f"persisted snapshot ({state.get('ioc_correlation_updated_at')})",
            })

    inv_status = state.get("investigation_status")
    if inv_status in ("Awaiting Approval", "Approved"):
        inv_result = _json_or_empty(state.get("investigation_result_json"))
        items.append({
            "evidence_id": "investigation-narrative", "evidence_type": "agent_inference",
            "source": "investigation_agent", "timestamp": state.get("investigation_updated_at"),
            "summary": (inv_result.get("summary") or "")[:280],
            "raw_reference": "investigation_result_json.narrative_report",
            "related_entities": [], "supported_findings": [],
            "evidence_status": "agent_inference", "provenance": "investigation_agent",
        })

    for row in wss.get_approval_history(incident_id, run_id):
        items.append({
            "evidence_id": f"approval-{row.get('id')}", "evidence_type": "analyst_decision",
            "source": "analyst", "timestamp": row.get("decided_at"),
            "summary": f"{row.get('approval_stage')} {row.get('decision')} — "
                      f"{row.get('comments') or ''}".strip(" —"),
            "raw_reference": "workflow_approvals", "related_entities": [],
            "supported_findings": [], "evidence_status": "analyst_evidence",
            "provenance": row.get("analyst") or "unknown",
        })

    return items


# [FYP-FUNCTION] `build_activity` — constructs build activity output for the next SOC analysis support consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>, case_view.py:build_case_view; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `get`, `get_activity`, `get_approval_history`, `sort`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def build_activity(incident_id: str, run_id: str | None) -> list[dict]:
    """Unions the workflow_activity ledger (atomic with each state
    transition — see workflow_state_store._insert_activity_row) with the
    permanent workflow_approvals decisions (projected, not duplicated —
    approvals are never also written into workflow_activity by
    _atomic_stage_transition). Does not claim coverage of events that
    aren't actually recorded (e.g. no "case closed" entry exists unless
    that UI action is wired to record_activity())."""
    items: list[dict] = []
    for row in wss.get_activity(incident_id, run_id):
        items.append({
            "actor": row.get("actor") or "system", "action": row.get("action"),
            "stage": row.get("stage"), "timestamp": row.get("occurred_at"),
            "comments": row.get("comments") or "", "source_table_or_file": "workflow_activity",
            "incident_id": str(incident_id), "run_id": row.get("run_id"),
        })
    for row in wss.get_approval_history(incident_id, run_id):
        items.append({
            "actor": row.get("analyst") or "unknown", "action": row.get("decision"),
            "stage": row.get("approval_stage"), "timestamp": row.get("decided_at"),
            "comments": row.get("comments") or "", "source_table_or_file": "workflow_approvals",
            "incident_id": str(incident_id), "run_id": row.get("run_id"),
        })
    items.sort(key=lambda i: i["timestamp"] or "")
    return items


# ══════════════════════════════════════════════════════════════════════════
# Output — Investigation Agent's persisted result, sanitized for display
# ══════════════════════════════════════════════════════════════════════════

_ALLOWED_TOP_LEVEL_KEYS = {
    "agent", "status", "incident_id", "incident_folder", "investigated_for",
    "cluster_alert_ids", "summary", "severity", "indicators", "narrative_report",
    "missing_evidence", "feedback_loop", "severity_divergence",
}
_SECRET_KEY_RE = re.compile(r"(key|token|secret|password|credential|authorization)", re.I)
_HIDDEN_FIELD_RE = re.compile(r"(reasoning|chain_of_thought|thinking|internal_notes)", re.I)
_MAX_STRING_LEN = 4000
_MAX_TOTAL_SIZE = 200_000
_LOCAL_PATH_RE = re.compile(r"([A-Za-z]:\\[^\"'\s]+|/[\w./-]{6,})")


# [FYP-FUNCTION] `_redact_local_paths` — implements the redact local paths operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `s`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:_sanitize_for_display; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `sub`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _redact_local_paths(s: str) -> str:
    # [FYP-FUNCTION] `_shorten` — implements the shorten operation used by the surrounding SOC analysis support workflow.
    # [FYP-INPUT] Parameters: `m`; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
    # [FYP-CALLS] Calls: `group`, `replace`, `rsplit`.
    # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

    def _shorten(m: re.Match) -> str:
        p = m.group(1)
        return p.replace("\\", "/").rsplit("/", 1)[-1]
    return _LOCAL_PATH_RE.sub(_shorten, s)


# [FYP-FUNCTION] `_sanitize_for_display` — implements the sanitize for display operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `value`, `_seen`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:_sanitize_for_display, case_view.py:sanitize_investigation_result_for_display, tests/test_investigation_stage.py:test_sanitize_handles_circular_reference_safely; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_redact_local_paths`, `_sanitize_for_display`, `id`, `isinstance`, `items`, `len`, `search`, `set`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _sanitize_for_display(value: Any, _seen: set | None = None) -> Any:
    """Recursive, cycle-safe. Dict keys matching _SECRET_KEY_RE are
    redacted at any depth; keys matching _HIDDEN_FIELD_RE are dropped
    outright. Local absolute paths are reduced to a basename. Strings over
    _MAX_STRING_LEN are truncated with an explicit marker."""
    if _seen is None:
        _seen = set()
    if isinstance(value, dict):
        obj_id = id(value)
        if obj_id in _seen:
            return "«circular reference»"
        _seen = _seen | {obj_id}
        out = {}
        for k, v in value.items():
            if _HIDDEN_FIELD_RE.search(str(k)):
                continue
            if _SECRET_KEY_RE.search(str(k)):
                out[k] = "«redacted»"
            else:
                out[k] = _sanitize_for_display(v, _seen)
        return out
    if isinstance(value, (list, tuple)):
        obj_id = id(value)
        if obj_id in _seen:
            return "«circular reference»"
        _seen = _seen | {obj_id}
        return [_sanitize_for_display(v, _seen) for v in value]
    if isinstance(value, str):
        v = _redact_local_paths(value)
        if len(v) > _MAX_STRING_LEN:
            v = v[:_MAX_STRING_LEN] + f"... [truncated, {len(value)} chars total]"
        return v
    return value


def sanitize_investigation_result_for_display(result: dict) -> dict:
    """
    [FYP-FUNCTION] [FYP-USED-BY]: app.py (`cv.sanitize_investigation_
    result_for_display`), called directly on the raw investigation_result
    dict just before an on-screen st.json() dump — NOT part of
    build_output()'s own return value (see build_output()'s docstring:
    that function deliberately returns the unsanitized result and leaves
    sanitization to the caller).

    The raw stored result (investigation_result_json) is never rendered
    directly — only this sanitized copy is. Allowlist-first: recognized
    safe top-level fields pass through (sanitized); anything else is
    bucketed into 'additional_output' (still sanitized, still shown — not
    silently dropped) rather than relying only on a blacklist."""
    if not isinstance(result, dict):
        return {}
    allowed = {k: v for k, v in result.items() if k in _ALLOWED_TOP_LEVEL_KEYS}
    extra = {k: v for k, v in result.items() if k not in _ALLOWED_TOP_LEVEL_KEYS}
    sanitized = _sanitize_for_display(allowed)
    if extra:
        sanitized["additional_output"] = _sanitize_for_display(extra)
    # Total-size budget, not just per-string length: if still too large
    # (e.g. a huge narrative_report plus a huge additional_output), trim
    # additional_output first, then narrative_report, before giving up.
    try:
        size = len(json.dumps(sanitized, default=str))
    except Exception:
        size = 0
    if size > _MAX_TOTAL_SIZE:
        if "additional_output" in sanitized:
            sanitized["additional_output"] = ("«omitted — total output exceeded the "
                                              "display size limit»")
        size = len(json.dumps(sanitized, default=str))
        if size > _MAX_TOTAL_SIZE and "narrative_report" in sanitized:
            keep = max(0, _MAX_TOTAL_SIZE - (size - len(sanitized["narrative_report"])))
            sanitized["narrative_report"] = (
                str(sanitized["narrative_report"])[:keep]
                + "\n\n... [truncated — total output exceeded the display size limit]")
    return sanitized


# [FYP-FUNCTION] `_reporting_trusted_path` — implements the reporting trusted path operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `raw_path`, `attempt_dir`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:_load_candidate_manifest_preview; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `Path`, `is_absolute`, `is_file`, `resolve`, `startswith`, `str`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _reporting_trusted_path(raw_path: str, *, attempt_dir) -> "Path | None":
    """Read-only twin of reporting_approval._resolve_trusted_path — this
    module never validates for approval purposes, only for safe preview
    display, so a failure here returns None (rendered as an unavailable
    preview) rather than raising."""
    from pathlib import Path
    try:
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = attempt_dir / raw_path
        resolved = candidate.resolve()
        trusted_root = sw._TRUSTED_OUTPUT_ROOT.resolve()
        if not str(resolved).startswith(str(trusted_root)):
            return None
        if not str(resolved).startswith(str(attempt_dir.resolve())):
            return None
        if not resolved.is_file():
            return None
        return resolved
    except Exception:
        return None


# [FYP-FUNCTION] `_load_candidate_manifest_preview` — retrieves load candidate manifest preview data for the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `incident_id`, `run_id`, `reporting_stage_attempt`, `candidate_manifest_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:build_reporting; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_reporting_trusted_path`, `append`, `get`, `hexdigest`, `loads`, `read_bytes`, `read_text`, `reporting_attempt_dir`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def _load_candidate_manifest_preview(incident_id: str, run_id: str, reporting_stage_attempt: int,
                                     candidate_manifest_path: str) -> dict[str, Any]:
    """Loads one Reporting attempt's candidate_manifest.json and, for each
    report, its structured_content blocks — re-verified against the
    manifest's own recorded SHA-256 at read time, so the preview can never
    silently drift from what was actually hashed at generation/approval
    time. Returns {"reports": [...], "warnings": [...]} — never raises;
    a report whose file can't be verified is included with an
    "unavailable" note instead of breaking the whole preview."""
    import hashlib
    import json as _json

    attempt_dir = sw.reporting_attempt_dir(incident_id, run_id, reporting_stage_attempt)
    manifest_path = _reporting_trusted_path(candidate_manifest_path, attempt_dir=attempt_dir)
    if manifest_path is None:
        return {"reports": [], "warnings": ["Candidate manifest could not be resolved for preview."]}
    try:
        manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"reports": [], "warnings": [f"Candidate manifest could not be read: {exc}"]}

    reports: list[dict[str, Any]] = []
    warnings: list[str] = []
    for report in manifest.get("reports") or []:
        report_type = report.get("report_type")
        entry: dict[str, Any] = {
            "report_type": report_type,
            "title": report.get("title") or report_type,
            "template": report.get("template"),
            "generated_at": report.get("generated_at"),
            "validation": report.get("validation") or {},
            "docx": report.get("docx") or {},
            "pdf": report.get("pdf") or {},
            "structured_content": [],
            "preview_available": False,
        }
        sc = report.get("structured_content") or {}
        sc_path = _reporting_trusted_path(sc.get("path"), attempt_dir=attempt_dir) if sc.get("path") else None
        if sc_path is not None:
            try:
                actual_sha256 = hashlib.sha256(sc_path.read_bytes()).hexdigest()
                if actual_sha256 == sc.get("sha256"):
                    entry["structured_content"] = _json.loads(sc_path.read_text(encoding="utf-8"))
                    entry["preview_available"] = True
                else:
                    entry["preview_unavailable_reason"] = (
                        "structured content no longer matches its recorded hash")
            except Exception as exc:
                entry["preview_unavailable_reason"] = f"structured content could not be read: {exc}"
        reports.append(entry)
    return {"reports": reports, "warnings": warnings,
           "report_set_id": manifest.get("report_set_id"),
           "candidate_manifest_sha256": manifest.get("candidate_manifest_sha256")}


def build_reporting(state: dict, incident_id: str, run_id: str) -> dict:
    """
    [FYP-FUNCTION] [FYP-USED-BY]: app.py — called both as part of
    build_case_view() (Reporting tab, full 5-tab case view) and
    STANDALONE as `cv.build_reporting(...)` (confirmed via grep, ~line
    5722) when app.py only needs the reporting-review model without
    recomputing the other four tabs — e.g. a lighter-weight refresh after
    an export/approval action on the Reporting tab alone. NOT used by
    build_aegis_context() (it uses _summarize_reporting_for_chat() instead,
    to skip this function's file I/O and SHA-256 verification).

    Reporting review model for the Reporting stage tab. Two distinct
    read paths, because reporting_result_json is CLEARED by rerun_stage()
    on every new attempt (see workflow_state_store.rerun_stage()):

    - current_attempt: whatever reporting_attempt is right now (Processing/
      Awaiting Approval/Approved/Failed), previewed from ITS OWN candidate
      manifest's hash-verified structured_content — never from the mutable
      report_manifest.json, drafts/editable directories, or a freshly
      parsed DOCX.
    - historical_approved_sets: every PRIOR approved decision (from
      workflow_state_store.get_approved_reporting_sets(), which reads the
      durable workflow_approvals.metadata_json — not a guessed path), so a
      previously approved package stays resolvable even after a later
      rerun clears reporting_result_json. Excludes whichever entry (if
      any) matches the current attempt's own report_set_id.

    export_all_available is true ONLY when the current attempt IS the most
    recently approved one — never merely "some approval exists somewhere
    in this run's history".
    """
    reporting_status = state.get("reporting_status") or "Pending"
    reporting_stage_attempt = int(state.get("reporting_attempt") or 1)
    raw_result = _json_or_empty(state.get("reporting_result_json"))
    document_exports = raw_result.get("document_exports") or {}
    candidate_manifest_path = document_exports.get("candidate_manifest_path")

    current_preview: dict[str, Any] = {"reports": [], "warnings": []}
    if candidate_manifest_path:
        current_preview = _load_candidate_manifest_preview(
            incident_id, run_id, reporting_stage_attempt, candidate_manifest_path)
    elif reporting_status not in ("Pending", "Processing"):
        current_preview["warnings"].append(
            "No candidate report set is available to preview for this attempt.")

    current_report_set_id = current_preview.get("report_set_id")

    try:
        approved_sets = wss.get_approved_reporting_sets(incident_id, run_id)
    except Exception:
        approved_sets = []
    latest_approved = approved_sets[-1] if approved_sets else None
    historical_approved_sets = [
        a for a in approved_sets
        if not (current_report_set_id and a.get("report_set_id") == current_report_set_id)
    ]

    export_all_available = bool(
        reporting_status == "Approved" and latest_approved
        and current_report_set_id and latest_approved.get("report_set_id") == current_report_set_id)

    try:
        approval_history = [
            a for a in wss.get_approval_history(incident_id, run_id)
            if a.get("approval_stage") == "reporting"]
    except Exception:
        approval_history = []

    return {
        "incident_id": str(incident_id),
        "run_id": run_id,
        "reporting_status": reporting_status,
        "reporting_stage_attempt": reporting_stage_attempt,
        "current_attempt": {
            "reporting_status": reporting_status,
            "reports": current_preview.get("reports", []),
            "report_set_id": current_report_set_id,
            "candidate_manifest_sha256": current_preview.get("candidate_manifest_sha256"),
            "summary": raw_result.get("summary"),
            "recommended_next_action": raw_result.get("recommended_next_action"),
            "last_error": raw_result.get("error") or state.get("last_error"),
        },
        "historical_approved_sets": historical_approved_sets,
        "export_all_available": export_all_available,
        "approval": approval_history[-1] if approval_history else {},
        "approval_history": approval_history,
        "worker_progress_note": state.get("worker_progress_note"),
        "reporting_updated_at": state.get("reporting_updated_at"),
        "warnings": current_preview.get("warnings", []),
    }


def reporting_blocks_to_render_ops(blocks: list[dict[str, Any]] | Any) -> list[dict[str, Any]]:
    """
    [FYP-FUNCTION] Converts structured report blocks into rendering operations
    for UI or export adapters.

    Pure mapping from structured report blocks (see
    soc_reporting_agent/reporting/structured_report.py) to a small,
    UI-framework-agnostic instruction list that is independently unit-testable: a
    {"type":"table",...} block MUST produce a {"op":"table",...}
    instruction (rendered as a structured table), never a
    {"op":"markdown", text containing raw "|" pipe syntax} instruction."""
    ops: list[dict[str, Any]] = []
    if not isinstance(blocks, list):
        return ops
    for block in blocks:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "heading":
            ops.append({"op": "heading", "level": int(block.get("level") or 2),
                       "text": str(block.get("text") or "")})
        elif btype == "table":
            ops.append({"op": "table", "columns": list(block.get("columns") or []),
                       "rows": [list(r or []) for r in block.get("rows") or []]})
        elif btype == "bullet_list":
            items = []
            for item in block.get("items") or []:
                if isinstance(item, dict):
                    items.append({"text": str(item.get("text") or ""), "level": int(item.get("level") or 0)})
                else:
                    items.append({"text": str(item or ""), "level": 0})
            ops.append({"op": "bullet_list", "items": items})
        elif btype == "page_break":
            ops.append({"op": "page_break"})
        else:
            ops.append({"op": "markdown", "text": str(block.get("text") or "")})
    return ops


def build_output(state: dict) -> dict:
    """
    [FYP-FUNCTION] Output tab data — the Investigation Agent's raw,
    UNCHANGED, complete result (investigation_result_json), plus a
    display_sections list naming which of summary/severity/indicators/
    narrative_report/feedback_loop/missing_evidence are actually populated
    (so app.py can skip rendering empty sections instead of showing blank
    headers).

    [FYP-USED-BY]: internal only — build_case_view() (Output tab). Note
    the raw investigation_result IS returned here, deliberately unsanitized
    — app.py must pass it through sanitize_investigation_result_for_
    display() (below) before ever putting it on screen; build_output()
    itself does not sanitize, since some internal callers may need the
    unredacted value. build_aegis_context() does NOT call this function at
    all (it uses _summarize_investigation_for_chat() instead, to avoid
    forwarding the full unbounded result into a size-capped chat prompt).
    warnings surfaces feedback_loop.gaps specifically (not the whole
    feedback_loop dict) since that is the one field meant to read as
    caveats to an analyst.
    """
    inv_status = state.get("investigation_status") or "Pending"
    raw_result = _json_or_empty(state.get("investigation_result_json"))
    display_sections = []
    for key in ("summary", "severity", "indicators", "narrative_report",
               "feedback_loop", "missing_evidence"):
        if raw_result.get(key):
            display_sections.append(key)
    return {
        "status": inv_status,
        "investigation_result": raw_result,   # UNCHANGED, complete, persisted
        "display_sections": display_sections,
        "warnings": raw_result.get("feedback_loop", {}).get("gaps", []) if isinstance(
            raw_result.get("feedback_loop"), dict) else [],
        "errors": [raw_result["error"]] if raw_result.get("error") else [],
        "worker_progress_note": state.get("worker_progress_note"),
        "last_error": state.get("last_error"),
        "investigation_updated_at": state.get("investigation_updated_at"),
    }


# ══════════════════════════════════════════════════════════════════════════
# Ask Aegis chat context — cross-stage, size-bounded, chat-appropriate
# ══════════════════════════════════════════════════════════════════════════
# build_case_view() below is shaped for the case-detail UI (full sanitized
# investigation result, entity graph, hash-verified report manifest
# previews) and is fine to recompute once per workspace request. A chat
# turn happens once per message SEND, so this section deliberately skips
# build_output()/build_reporting()'s file I/O and full-size payloads and
# enforces a hard character budget instead (see _MAX_CONTEXT_CHARS) — a
# chat prompt needs kilobytes, not build_case_view()'s 200KB display cap.

_MAX_CONTEXT_CHARS = 8000          # ~2K tokens; generous for a chat prompt,
                                   # far below _MAX_TOTAL_SIZE above
_MAX_NARRATIVE_EXCERPT = 800
_MAX_LIST_ITEMS = 10

_STAGE_COLUMNS = [
    ("Parsing", "parsing"),
    ("Triage", "triage"),
    ("Threat Intelligence Enrichment", "threat_intel"),
    ("Investigation", "investigation"),
    ("Reporting", "reporting"),
]
_NAME_TO_KEY = {name: key for name, key in _STAGE_COLUMNS}


def _stage_status_summary(state: dict) -> list[dict]:
    """
    [FYP-FUNCTION]

    Independent, deliberately-simplified 5-stage classifier for chat
    grounding: done | awaiting_approval | failed | in_progress |
    not_started.

    This is NOT a port of app.py:_case_stage_states() — that function
    additionally computes UI pipeline lock-cascades (which stage tab is
    clickable when an earlier approval gate is unresolved), which a
    chatbot has no use for, and touching that high-blast-radius UI
    function isn't necessary for this. This is only a FALLBACK for
    callers with no precomputed stage list in scope — build_aegis_context's
    primary caller (My Workspace) passes its own _case_stage_states()
    result instead, so this path is only exercised by standalone callers
    (e.g. the Ask a Question page).

    Threat Intelligence Enrichment has no analyst approval gate (confirmed
    via workflow_state_store.rerun_stage()'s allowed_current_statuses for
    "threat_intel", and workflow_validation.py's note that it "does not
    require a separate approval") — it never reports awaiting_approval,
    only done/failed/in_progress/not_started.
    """
    done_values = {
        "parsing": {"complete"},
        "triage": {"approved"},
        "threat_intel": {"complete", "complete with warnings"},
        "investigation": {"approved"},
        "reporting": {"approved"},
    }
    approval_values = {"awaiting approval", "pending approval"}
    out = []
    for name, key in _STAGE_COLUMNS:
        raw = str(state.get(f"{key}_status") or "").strip()
        norm = raw.lower()
        if key != "threat_intel" and norm in approval_values:
            classified = "awaiting_approval"
        elif norm in done_values[key]:
            classified = "done"
        elif norm == "failed":
            classified = "failed"
        elif norm in ("processing", "running"):
            classified = "in_progress"
        else:
            classified = "not_started"
        out.append({"name": name, "state": classified, "backend_status": raw})
    return out


# [FYP-FUNCTION] `_approval_label` — implements the approval label operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `status_state`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:_confirmed_facts_block; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _approval_label(status_state: str) -> str:
    return {
        "done": "confirmed",
        "awaiting_approval": "pending analyst approval — not yet confirmed",
        "failed": "failed — last run did not complete",
        "in_progress": "currently running",
        "not_started": "not available yet",
    }.get(status_state, "not available yet")


# [FYP-FUNCTION] `_cap_list` — implements the cap list operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `items`, `n`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:_confirmed_facts_block, case_view.py:_flatten_case_summary, case_view.py:_summarize_investigation_for_chat; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `list`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _cap_list(items: list, n: int = _MAX_LIST_ITEMS) -> list:
    return list(items or [])[:n]


# [FYP-FUNCTION] `_cap_text` — implements the cap text operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `value`, `n`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:_confirmed_facts_block, case_view.py:_summarize_investigation_for_chat, case_view.py:_summarize_reporting_for_chat; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `len`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _cap_text(value: Any, n: int = _MAX_NARRATIVE_EXCERPT) -> str | None:
    """Caps any free-text field before it enters the chat context. Several
    agent-produced text fields (investigation's `summary`, not just its
    `narrative_report`) are effectively unbounded multi-paragraph prose —
    every such field must go through this, not just the ones that were
    empirically observed to be long, or the size cap below silently stops
    being a guarantee again the next time an agent's output gets wordier."""
    if not value:
        return None
    text = str(value)
    if len(text) > n:
        text = text[:n] + "... [truncated]"
    return text


def _summarize_investigation_for_chat(state: dict) -> dict | None:
    """
    [FYP-FUNCTION] [FYP-USED-BY]: _confirmed_facts_block() only, itself
    called only from build_aegis_context() — this is chat-context-specific,
    never used by build_case_view()/build_output().

    Reads investigation_result_json directly off `state` — bypasses
    build_output()'s full-size sanitized forward (fine at one-page-render
    frequency, oversized for a chat prompt). Extracts only the fields a
    chat answer actually needs, with every free-text field capped via
    _cap_text (the investigation agent's `summary` is itself often a long
    multi-paragraph narrative, not a short one-liner — capping only
    `narrative_report` and leaving `summary` unbounded was the initial
    version of this function and is exactly the kind of gap that defeats
    the size budget below)."""
    raw = _json_or_empty(state.get("investigation_result_json"))
    if not raw:
        return None
    return {
        "summary": _cap_text(raw.get("summary")),
        "severity": raw.get("severity"),
        "classification": raw.get("classification"),
        "indicators": _cap_list(raw.get("indicators")),
        "missing_evidence": _cap_list(raw.get("missing_evidence")),
        "narrative_excerpt": _cap_text(raw.get("narrative_report")),
    }


def _summarize_reporting_for_chat(state: dict) -> dict | None:
    """
    [FYP-FUNCTION] [FYP-USED-BY]: _confirmed_facts_block() only, itself
    called only from build_aegis_context() — chat-context-specific, never
    used by build_case_view()/build_reporting().

    Reads reporting_result_json directly off `state` — bypasses
    build_reporting()'s file I/O + SHA-256 manifest verification, which
    exists for on-screen report preview, not chat grounding."""
    raw = _json_or_empty(state.get("reporting_result_json"))
    if not raw:
        return None
    return {
        "report_status": raw.get("report_status"),
        "summary": _cap_text(raw.get("summary")),
        "recommended_next_action": _cap_text(raw.get("recommended_next_action")),
    }


def _confirmed_facts_block(state: dict, stages: list[dict]) -> dict:
    """
    [FYP-FUNCTION] [FYP-USED-BY]: build_aegis_context() only.

    Per-stage dict: internal key -> {"label": ..., ...fields}. 'label'
    names which of confirmed / pending-approval / failed / not-available
    this stage's content is. Investigation and Reporting use their OWN
    Approved/Awaiting Approval/other status (not the coarser 5-way
    `stages` classification) because build_overview()/build_mitre()/
    build_evidence() above already surface "Awaiting Approval"
    investigation content elsewhere in this module (they gate on
    `inv_status in ("Awaiting Approval", "Approved")`, not "Approved"
    alone) — this block must label that content the same way, not omit
    it, or Ask Aegis would contradict the case-view UI tabs it's built
    from.
    """
    state_by_key = {_NAME_TO_KEY[s["name"]]: s["state"]
                   for s in stages if s["name"] in _NAME_TO_KEY}
    facts: dict[str, Any] = {}

    parsing_state = state_by_key.get("parsing", "not_started")
    if parsing_state == "done":
        parsed = _json_or_empty(state.get("parsing_result_json"))
        facts["parsing"] = {"label": "confirmed",
                            "summary": _cap_text(parsed.get("ai_summary")) or "Parsing completed."}
    else:
        facts["parsing"] = {"label": _approval_label(parsing_state)}

    triage_state = state_by_key.get("triage", "not_started")
    if triage_state == "done":
        # Phase 3 (canonical Triage Result contract migration) fix: the raw
        # persisted triage_result_json is TriageAgentSuccessOutput's shape
        # (metakeys_payload/ticket/trace/used_parsed_context/error[/cached],
        # plus generate_triage_ai_summary()'s ai_summary/ai_thinking/
        # ai_summary_model/ai_summary_generated_at) -- it has no top-level
        # "severity", "confidence", "classification", "confirmed_facts", or
        # "evidence_gaps" key, ever. The five reads previously here
        # (tri.get("severity"), tri.get("confidence"), the
        # `or tri.get("classification")` fallback, tri.get("confirmed_facts"),
        # tri.get("evidence_gaps")) always resolved to None/[] -- silently
        # confusing Triage's real classification field with a nonexistent
        # generic "severity", and inventing a Triage "confidence" that this
        # agent has never produced (see agents/triage/triage_result.py's own
        # scope docstring). No consumer depends on those dead keys being
        # present (grepped: only this module's own renderer in
        # soc_triage_agent.py::_format_case_context_for_prompt(), which
        # already skips None/empty values), so they are removed outright
        # rather than kept as always-null placeholders.
        tri = _json_or_empty(state.get("triage_result_json"))
        ticket = tri.get("ticket") or {}
        facts["triage"] = {
            "label": "confirmed",
            "classification": ticket.get("classification"),
            "summary": _cap_text(ticket.get("summary")),
            "recommended_actions": _cap_list(ticket.get("recommended_actions")),
        }
    else:
        facts["triage"] = {"label": _approval_label(triage_state)}

    ti_state = state_by_key.get("threat_intel", "not_started")
    if ti_state == "done":
        ti = _json_or_empty(state.get("threat_intel_result_json"))
        block = ti.get("threat_intelligence") or {}
        facts["threat_intel"] = {
            "label": "confirmed",
            "risk_level": ti.get("enrichment_risk_level"),
            "risk_score": ti.get("enrichment_risk_score"),
            "risk_reasons": _cap_list(ti.get("enrichment_risk_reasons")),
            "iocs": {k: v for k, v in (block.get("iocs") or {}).items() if v},
            "notes": _cap_list(block.get("notes")),
        }
    else:
        facts["threat_intel"] = {"label": _approval_label(ti_state)}

    inv_status = str(state.get("investigation_status") or "")
    if inv_status == "Approved":
        facts["investigation"] = {"label": "confirmed",
                                  **(_summarize_investigation_for_chat(state) or {})}
    elif inv_status == "Awaiting Approval":
        facts["investigation"] = {"label": _approval_label("awaiting_approval"),
                                  **(_summarize_investigation_for_chat(state) or {})}
    elif inv_status == "Failed":
        facts["investigation"] = {"label": _approval_label("failed")}
    else:
        facts["investigation"] = {"label": _approval_label("not_started")}

    rep_status = str(state.get("reporting_status") or "")
    if rep_status == "Approved":
        facts["reporting"] = {"label": "confirmed",
                              **(_summarize_reporting_for_chat(state) or {})}
    elif rep_status == "Awaiting Approval":
        facts["reporting"] = {"label": _approval_label("awaiting_approval"),
                              **(_summarize_reporting_for_chat(state) or {})}
    elif rep_status == "Failed":
        facts["reporting"] = {"label": _approval_label("failed")}
    else:
        facts["reporting"] = {"label": _approval_label("not_started")}

    return facts


# [FYP-FUNCTION] `_flatten_case_summary` — implements the flatten case summary operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `case_context`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:build_aegis_context; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_cap_list`, `get`, `isinstance`, `items`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _flatten_case_summary(case_context: dict) -> dict:
    """Strips build_overview()'s per-field provenance envelope (source_
    stage/source_field/incident_id/run_id/updated_at/evidence_status) down
    to bare values. That metadata exists so the case-detail UI can offer
    "click to see source" — a chat prompt doesn't need it, and repeating
    incident_id/run_id on every single field was a meaningful, avoidable
    share of the context budget for zero grounding benefit here (the
    STAGE STATUS section already conveys evidentiary confidence)."""
    flat: dict[str, Any] = {}
    for key, v in (case_context or {}).items():
        if key == "unified_verdict" and isinstance(v, dict):
            flat[key] = {"value": v.get("value"), "reasons": _cap_list(v.get("reasons"), 3)}
        elif isinstance(v, dict) and "value" in v:
            flat[key] = v.get("value")
        else:
            flat[key] = v
    return flat


def build_aegis_context(incident_id: str, run_id: str | None = None,
                        stage_states: list[dict] | None = None) -> dict:
    """
    [FYP-FUNCTION] Aegis Chatbot Context Construction
    [FYP-LLM] [FYP-ENTRY-POINT] [FYP-EVALUATOR] [FYP-RERUN]

    THE Ask Aegis chatbot context builder — do NOT confuse this with
    skills_sidecar.py's build_skills_context(), which is a different
    function used only in soc_workflow.handoff_to_reporting() to enrich the
    Investigation->Reporting handoff, NOT the chatbot.

    [FYP-USED-BY]: app.py's chat_respond() (confirmed via grep, called at
    app.py lines ~6660 and ~7575 as `cv.build_aegis_context(...)`, then
    passed into chat_respond() as `case_context`).

    Cumulative, size-bounded, cross-stage context for Ask Aegis.

    stage_states: an optional precomputed 5-stage list in the shape
    app.py's _case_stage_states() returns ([{"name", "state", ...
    "backend_status"}, ...] with state in {"done","current","approval",
    "locked"}). My Workspace already computes this before the chat panel
    renders — passing it through here guarantees Ask Aegis and the
    pipeline-stepper UI never disagree about what's done. When not
    supplied (e.g. the Ask a Question page, which has no such list in
    scope), falls back to _stage_status_summary()'s independent
    classification.

    Called fresh on every chat send — nothing here is cached anywhere.
    That is what makes rerun-invalidation automatic: workflow_state_store.
    rerun_stage() already nulls every downstream stage's result_json when
    an earlier stage is re-run, so the very next call to this function
    simply stops finding that data. No separate invalidation logic exists
    or is needed here.

    Reuses build_overview()/build_mitre()/build_evidence()/
    load_incident_for_case_view() above directly — cheap, pure, and
    already the correct cross-stage grounding logic this module exists to
    centralize (see the module docstring's aggregate_verdict() bug-class
    note). Deliberately does NOT call build_output() or build_reporting()
    (file I/O, SHA-256 manifest verification, full-size payloads sized
    for a 200KB display cap) — uses _summarize_investigation_for_chat()/
    _summarize_reporting_for_chat() instead.

    Returns {incident_id, run_id, available, data_availability,
    stage_status, case_summary, key_findings, mitre, confirmed_facts,
    evidence_highlights, warnings}. available=False (with an explanatory
    warning, never a guess) when no workflow state exists yet, or a
    stale/foreign run_id was requested — mirrors build_case_view()'s own
    guard clauses.
    """
    state = wss.get_state(incident_id)
    if state is None:
        return {"incident_id": str(incident_id), "run_id": run_id, "available": False,
                "warnings": [f"No workflow state found for incident {incident_id!r} — "
                            "this incident has not entered the SOC workflow yet."]}
    resolved_run_id = run_id or state.get("run_id")
    if run_id and state.get("run_id") != run_id:
        return {"incident_id": str(incident_id), "run_id": run_id, "available": False,
                "warnings": [f"run_id {run_id!r} does not match this incident's current "
                            f"run ({state.get('run_id')!r})."]}

    if stage_states:
        # Remap app.py's UI vocabulary (done/current/approval/locked) onto
        # this module's grounding vocabulary, using each stage's own
        # backend_status for the finer in_progress/failed distinction the
        # UI classifier collapses into "current" for pill-rendering
        # purposes (see app.py:_case_stage_states) — a chatbot benefits
        # from being able to say a stage failed outright.
        stages = []
        for s in stage_states:
            backend = str(s.get("backend_status") or "").strip().lower()
            if s.get("state") == "done":
                classified = "done"
            elif s.get("state") == "approval":
                classified = "awaiting_approval"
            elif backend == "failed":
                classified = "failed"
            elif backend in ("processing", "running"):
                classified = "in_progress"
            else:
                classified = "not_started"
            stages.append({"name": s["name"], "state": classified,
                           "backend_status": s.get("backend_status", "")})
        # Threat Intel has no real approval gate (see _stage_status_
        # summary's docstring); app.py's classifier tolerates a legacy
        # "Approved" value there defensively, but Aegis must never claim
        # an approval gate that doesn't exist.
        for s in stages:
            if s["name"] == "Threat Intelligence Enrichment" and s["state"] == "awaiting_approval":
                s["state"] = "done"
    else:
        stages = _stage_status_summary(state)

    incident, data_availability, incident_source = load_incident_for_case_view(
        incident_id, resolved_run_id)

    overview = build_overview(state, incident, incident_id, resolved_run_id)
    mitre = build_mitre(state, incident, incident_id, resolved_run_id)
    evidence = build_evidence(state, incident, incident_id, resolved_run_id, data_availability)

    context = {
        "incident_id": str(incident_id), "run_id": resolved_run_id, "available": True,
        "data_availability": data_availability,
        "stage_status": stages,
        "case_summary": _flatten_case_summary(overview.get("case_context", {})),
        "key_findings": overview.get("key_findings", [])[:_MAX_LIST_ITEMS],
        "mitre": [
            {"tactic": m.get("tactic"), "technique_id": m.get("technique_id"),
             "technique_name": m.get("technique_name"), "origin": m.get("origin")}
            for m in _cap_list(mitre.get("mappings", []))
        ],
        "confirmed_facts": _confirmed_facts_block(state, stages),
        "evidence_highlights": [
            {"evidence_type": e.get("evidence_type"), "source": e.get("source"),
             "summary": e.get("summary")}
            for e in _cap_list(evidence, _MAX_LIST_ITEMS)
        ],
        "warnings": list(data_availability.get("warnings") or []),
    }

    # Final defensive size cap — mirrors sanitize_investigation_result_for_
    # display()'s progressive total-size-budget pattern above (trim the
    # biggest contributor, re-measure, trim the next), at a chat-
    # appropriate scale (thousands of chars, not the 200KB display cap).
    # A single untargeted pass isn't enough here: for a busy case (e.g.
    # Investigation Awaiting Approval with a long narrative excerpt plus a
    # populated Triage/Threat-Intel confirmed_facts block), confirmed_facts
    # — not the capped lists trimmed first — is usually the largest
    # contributor, so trimming only converges if it's shrunk too.
    # [FYP-FUNCTION] `_context_size` — implements the context size operation used by the surrounding SOC analysis support workflow.
    # [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
    # [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
    # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
    # [FYP-USED-BY] Static symbol references include case_view.py:build_aegis_context; dynamic framework calls may add callers.
    # [FYP-CALLS] Calls: `dumps`, `len`.
    # [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

    def _context_size() -> int:
        try:
            return len(json.dumps(context, default=str))
        except Exception:
            return 0

    if _context_size() > _MAX_CONTEXT_CHARS:
        context["evidence_highlights"] = context["evidence_highlights"][:3]
        context["mitre"] = context["mitre"][:3]
        context["key_findings"] = context["key_findings"][:3]
        context.setdefault("warnings", []).append(
            "Some case detail was trimmed to fit the assistant's context budget.")

    if _context_size() > _MAX_CONTEXT_CHARS:
        for block in context["confirmed_facts"].values():
            if not isinstance(block, dict):
                continue
            excerpt = block.get("narrative_excerpt")
            if excerpt:
                block["narrative_excerpt"] = str(excerpt)[:200] + "... [excerpt shortened]"
            for list_key in ("recommended_actions", "confirmed_facts", "evidence_gaps",
                             "risk_reasons", "notes", "indicators", "missing_evidence"):
                if isinstance(block.get(list_key), list):
                    block[list_key] = block[list_key][:3]

    return context


# ══════════════════════════════════════════════════════════════════════════
# Top-level entry point
# ══════════════════════════════════════════════════════════════════════════

def build_case_view(incident_id: str, run_id: str | None = None) -> dict:
    """
    [FYP-FUNCTION] [FYP-ENTRY-POINT] Top-level aggregator for the My
    Workspace case-details page — ONE call that assembles all 5 case-view
    tabs (Overview/Output/Reporting/Timeline/MITRE/Entity Graph/Evidence/
    Activity) plus data_availability/incident_source/warnings, replacing
    the old app.py pattern of computing each independently inline (see
    the module docstring's bug-class note).

    [FYP-USED-BY]: app.py, `cv.build_case_view(...)` (confirmed via grep,
    ~line 5902) — the sole call site for the full case-detail render.

    [FYP-CALLS] (in order): load_incident_for_case_view() once, then
    build_overview(), build_mitre(), build_output(), build_reporting(),
    build_timeline(), build_entity_graph(), build_evidence(),
    build_activity() — each a pure function over the SAME already-loaded
    `state`/`incident`/`data_availability`, so this function does exactly
    one state fetch and one incident load for the whole page, not one per
    tab.

    Loads ONLY persisted, run-matched data. run_id=None resolves to the
    incident's current run. Never triggers a live corpus scan, never runs
    a workflow stage, never claims a lease."""
    state = wss.get_state(incident_id)
    if state is None:
        return {"incident_id": str(incident_id), "run_id": run_id, "warnings":
                [f"No workflow state found for incident {incident_id!r}."]}
    resolved_run_id = run_id or state.get("run_id")
    if run_id and state.get("run_id") != run_id:
        # A stale/foreign run_id was requested — never guess or fall back
        # to whatever the current run happens to be.
        return {"incident_id": str(incident_id), "run_id": run_id, "warnings":
                [f"run_id {run_id!r} does not match this incident's current "
                 f"run ({state.get('run_id')!r})."]}

    incident, data_availability, incident_source = load_incident_for_case_view(
        incident_id, resolved_run_id)

    overview = build_overview(state, incident, incident_id, resolved_run_id)
    mitre = build_mitre(state, incident, incident_id, resolved_run_id)
    output = build_output(state)
    reporting = build_reporting(state, incident_id, resolved_run_id)
    timeline = build_timeline(state, incident, incident_id, resolved_run_id, data_availability)
    entity_graph = build_entity_graph(incident, data_availability)
    evidence = build_evidence(state, incident, incident_id, resolved_run_id, data_availability)
    activity = build_activity(incident_id, resolved_run_id)

    return {
        "incident_id": str(incident_id), "run_id": resolved_run_id,
        "data_availability": data_availability, "incident_source": incident_source,
        "overview": overview,
        "output": output,
        "reporting": reporting,
        "timeline": timeline,
        "mitre": mitre.get("mappings", []),
        "mitre_warnings": mitre.get("warnings", []),
        "entity_graph": {"nodes": entity_graph["nodes"], "edges": entity_graph["edges"]},
        "evidence": evidence,
        "activity": activity,
        "warnings": [w for w in (data_availability.get("warnings") or [])],
    }
