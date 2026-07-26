"""
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

import workflow_state_store as wss
import soc_workflow as sw
from incident_map import build_incident_map, to_dot as incident_map_to_dot
from tactic_inference import infer_tactics
from triage_verdict import aggregate_verdict


# ══════════════════════════════════════════════════════════════════════════
# Shared helpers
# ══════════════════════════════════════════════════════════════════════════

def _provenance(value: Any, *, source_stage: str, source_field: str,
               incident_id: str, run_id: str | None, updated_at: str | None = None,
               evidence_status: str = "persisted") -> dict:
    return {"value": value, "source_stage": source_stage, "source_field": source_field,
            "incident_id": str(incident_id), "run_id": run_id, "updated_at": updated_at,
            "evidence_status": evidence_status}


def _json_or_empty(raw: Any) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _slim_incident_from_state(state: dict) -> dict:
    raw = _json_or_empty(state.get("raw_json"))
    return raw if isinstance(raw, dict) else {}


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

def build_overview(state: dict, incident: dict, incident_id: str, run_id: str) -> dict:
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

    # Key findings — same distilled-alert-title + elevated-signal shape the
    # old _build_case_findings() produced, but now backed by the CORRECT
    # aggregate_verdict() call above (persisted triage/TI/investigation),
    # not the bare aggregate_verdict(inc) bug.
    key_findings: list[dict] = []
    _kw = [("hta", ""), ("c2", ""), ("command", ""), ("exfil", ""),
           ("autorun", ""), ("credential", ""), ("powershell", "⌘"),
           ("lateral", "↔"), ("ransom", ""), ("phish", ""), ("beacon", "")]
    for t in list(dict.fromkeys(am.get("AlertTitles") or []))[:6]:
        tl = str(t).lower()
        icon = next((e for k, e in _kw if k in tl), "")
        key_findings.append({
            "icon": icon, "title": str(t)[:72], "desc": "Observed alert behaviour",
            "confidence": "", "origin": "netwitness_alert_title",
            "provenance": _provenance(str(t), source_stage="raw_incident",
                                      source_field="alertMeta.AlertTitles",
                                      incident_id=incident_id, run_id=run_id),
        })
    if verdict.get("available"):
        _conf = {3: "high", 2: "elevated", 1: "moderate", 0: "low"}
        # "base severity" is triage_verdict.py's internal signal name and
        # covers TWO different sources (triage classification, or a raw
        # incident-field fallback when no triage result exists) — display
        # the name that matches which one actually fired, per detail,
        # rather than the generic internal name (never "Base Severity").
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

def _availability_warning(data_availability: dict) -> str | None:
    if data_availability.get("alerts_complete"):
        return None
    if data_availability.get("alerts_fetch_succeeded") is False and \
            data_availability.get("alerts_fetch_attempted"):
        return "Full event-level data was unavailable for this workflow run."
    if data_availability.get("incident_source") == "sqlite_slim":
        return "Full event-level data was unavailable for this workflow run."
    return "Full event-level data was unavailable for this workflow run."


def build_timeline(state: dict, incident: dict, incident_id: str, run_id: str,
                   data_availability: dict) -> list[dict]:
    imap = build_incident_map(incident)
    items: list[dict] = []
    availability_note = _availability_warning(data_availability)

    for ev in imap.get("timeline", []):
        # Genuinely-empty (a successful fetch that found nothing) reads
        # differently from "we don't know" — see data_availability.
        items.append({
            "timestamp": ev.get("time"), "event": ev.get("event"),
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
            items.append({"timestamp": state[col], "event": f"{stage.replace('_', ' ').title()} completed",
                         "event_type": "workflow", "source_stage": stage,
                         "evidence_reference": col, "incident_id": str(incident_id),
                         "run_id": run_id})

    # Analyst approval decisions.
    for row in wss.get_approval_history(incident_id, run_id):
        items.append({
            "timestamp": row.get("decided_at"),
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
        for i, ioc in enumerate(ti_result.get("iocs") or []):
            items.append({
                "evidence_id": f"ti-ioc-{i}", "evidence_type": "external_intelligence",
                "source": "threat_intel", "timestamp": ti_result.get("generated_at"),
                "summary": f"{ioc.get('value')} — {ioc.get('verdict', 'UNKNOWN')}",
                "raw_reference": "threat_intel_result_json.iocs", "related_entities": [ioc.get("value")],
                "supported_findings": [], "evidence_status": "external_intelligence",
                "provenance": ", ".join(ioc.get("sources") or []) or "threat_intel",
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


def _redact_local_paths(s: str) -> str:
    def _shorten(m: re.Match) -> str:
        p = m.group(1)
        return p.replace("\\", "/").rsplit("/", 1)[-1]
    return _LOCAL_PATH_RE.sub(_shorten, s)


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
    """The raw stored result (investigation_result_json) is never rendered
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


def build_output(state: dict) -> dict:
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
# Top-level entry point
# ══════════════════════════════════════════════════════════════════════════

def build_case_view(incident_id: str, run_id: str | None = None) -> dict:
    """Loads ONLY persisted, run-matched data. run_id=None resolves to the
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
    timeline = build_timeline(state, incident, incident_id, resolved_run_id, data_availability)
    entity_graph = build_entity_graph(incident, data_availability)
    evidence = build_evidence(state, incident, incident_id, resolved_run_id, data_availability)
    activity = build_activity(incident_id, resolved_run_id)

    return {
        "incident_id": str(incident_id), "run_id": resolved_run_id,
        "data_availability": data_availability, "incident_source": incident_source,
        "overview": overview,
        "output": output,
        "timeline": timeline,
        "mitre": mitre.get("mappings", []),
        "mitre_warnings": mitre.get("warnings", []),
        "entity_graph": {"nodes": entity_graph["nodes"], "edges": entity_graph["edges"]},
        "evidence": evidence,
        "activity": activity,
        "warnings": [w for w in (data_availability.get("warnings") or [])],
    }
