"""
triage_ticket_editing.py — analyst "Open & Edit / Export Word / Export PDF"
layer for the TRIAGE stage's ticket, mirroring report_editing.py.

Scope note: this module is deliberately the triage-side twin of
report_editing.py and touches nothing the Reporting agent owns. It never
writes into reporting_attempt_dir(...)/<incident_id>/reports/exports/ (the
hash-pinned candidate set reporting_approval.py re-verifies on download) and
never calls anything in soc_reporting_agent except the two *stateless*
block renderers (reporting.editable_reports.render_blocks_to_docx/pdf) so a
triage ticket exports with exactly the same document styling as a report.

The ticket content itself is NOT reformatted here: build_ticket_blocks()
reproduces soc_triage_agent.format_ticket_display()'s section order and
wording one-for-one as structured blocks, then appends the Threat
Intelligence Enrichment section built from the persisted
threat_intel_result_json (VirusTotal / AbuseIPDB / AlienVault OTX), so an
exported ticket carries the enriched indicators alongside the triage
verdict.

Analyst edits reuse the existing report_edits table
(workflow_state_store.upsert_report_edit) under its own report_type,
TICKET_REPORT_TYPE — the table is keyed (incident_id, run_id, report_type),
so a ticket edit can never collide with a reporting edit.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import workflow_state_store as wss

# report_editing puts soc_reporting_agent/ on sys.path as an import side
# effect; importing it first is what makes `reporting.editable_reports`
# resolvable below. STATUS_TONES is reused so ticket status badges use the
# identical pill vocabulary as the Reports tab.
from report_editing import STATUS_TONES  # noqa: F401  (re-exported for app.py)
from soc_workflow import _artifact_dir as _run_artifact_dir

from reporting.editable_reports import (  # noqa: E402  (path insert must run first)
    render_blocks_to_docx, render_blocks_to_pdf)

# One synthetic "report type" for the ticket, kept distinct from every
# member of report_editing.CORE_REPORT_TYPES.
TICKET_REPORT_TYPE = "triage_ticket"
TICKET_TITLE = "Triage Ticket"
TICKET_DESCRIPTION = (
    "SOC triage ticket with risk rating, classification and threat "
    "intelligence enrichment.")

_DASH = "—"


def _txt(value: Any) -> str:
    """Plain-text cell/paragraph value. The docx/pdf block renderers write
    text verbatim (no markdown pass), so nothing here may carry ** or `."""
    if value is None:
        return _DASH
    text = str(value).strip()
    return text or _DASH


def _joined(values: Any) -> str:
    if not values:
        return _DASH
    if isinstance(values, str):
        return values
    return ", ".join(str(v) for v in values if str(v).strip()) or _DASH


# ══════════════════════════════════════════════════════════════════════════
# Ticket → blocks (same section order/wording as format_ticket_display)
# ══════════════════════════════════════════════════════════════════════════

def _threat_intel_blocks(ti: dict[str, Any]) -> list[dict[str, Any]]:
    """The enrichment section, sourced from the SAME persisted
    threat_intel_result_json the Threat Intelligence stage tab renders — the
    provider tables are rebuilt with identical columns so the exported
    ticket and the on-screen stage agree field for field. Never re-runs
    enrichment."""
    blocks: list[dict[str, Any]] = [
        {"type": "heading", "level": 2, "text": "Threat Intelligence Enrichment"}]

    if not ti:
        blocks.append({
            "type": "paragraph",
            "text": ("Threat Intelligence enrichment has not been completed for "
                     "this incident yet.")})
        return blocks

    block = ti.get("threat_intelligence") or {}
    iocs = block.get("iocs") or {}
    vt = block.get("virustotal") or {}
    abuse = block.get("abuseipdb") or {}
    otx = block.get("alienvault_otx") or {}

    blocks.append({
        "type": "paragraph",
        "text": (f"Status: {_txt(ti.get('status'))}  ·  "
                 f"Risk level: {_txt(ti.get('enrichment_risk_level'))}  ·  "
                 f"Risk score: {_txt(ti.get('enrichment_risk_score'))}  ·  "
                 f"Last enriched: {_txt(ti.get('generated_at'))}")})
    if ti.get("summary"):
        blocks.append({"type": "paragraph", "text": _txt(ti.get("summary"))})
    if ti.get("recommended_next_action"):
        blocks.append({"type": "paragraph",
                       "text": f"Recommended next action: {_txt(ti['recommended_next_action'])}"})

    blocks += [
        {"type": "heading", "level": 3, "text": "Extracted IOCs"},
        {"type": "table", "columns": ["Field", "Value"], "rows": [
            ["Possible file name", _txt(iocs.get("possible_file_name"))],
            ["File hash", _txt(iocs.get("file_hash"))],
            ["Public IP indicators", _joined(iocs.get("ip_indicators"))],
            ["Domain indicators", _joined(iocs.get("domain_indicators"))],
            ["URL indicators", _joined(iocs.get("url_indicators"))],
            ["PowerShell enrichment", _txt(iocs.get("powershell_enrichment_note"))],
        ]},
    ]

    vt_rows: list[list[str]] = []
    file_hash = vt.get("file_hash")
    if file_hash:
        vt_rows.append(["File hash", _txt(file_hash.get("indicator")),
                        _txt(file_hash.get("status")), _txt(file_hash.get("malicious")),
                        _txt(file_hash.get("suspicious")), _txt(file_hash.get("reputation"))])
    for label, key in (("IP", "ip_results"), ("Domain", "domain_results")):
        for row in vt.get(key) or []:
            vt_rows.append([label, _txt(row.get("indicator")), _txt(row.get("status")),
                            _txt(row.get("malicious")), _txt(row.get("suspicious")),
                            _txt(row.get("reputation"))])
    blocks.append({"type": "heading", "level": 3, "text": "VirusTotal"})
    blocks.append(
        {"type": "table",
         "columns": ["Type", "Indicator", "Status", "Malicious", "Suspicious", "Reputation"],
         "rows": vt_rows}
        if vt_rows else
        {"type": "paragraph", "text": "No VirusTotal results for this run."})

    abuse_rows = [[
        _txt(r.get("indicator")), _txt(r.get("abuse_confidence_score")),
        _txt(r.get("total_reports")), _txt(r.get("country_code")), _txt(r.get("isp")),
        _txt(r.get("domain")), _txt(r.get("usage_type")), _txt(r.get("last_reported_at")),
    ] for r in (abuse.get("ip_results") or [])]
    blocks.append({"type": "heading", "level": 3, "text": "AbuseIPDB"})
    blocks.append(
        {"type": "table",
         "columns": ["IP", "Abuse confidence", "Total reports", "Country", "ISP",
                     "Domain", "Usage type", "Last reported"],
         "rows": abuse_rows}
        if abuse_rows else
        {"type": "paragraph", "text": "No AbuseIPDB results for this run."})

    otx_rows = [[
        _txt(r.get("indicator")), _txt(r.get("indicator_type")), _txt(r.get("pulse_count")),
        _joined(r.get("related_pulses")), _joined(r.get("sections_available")),
    ] for r in (otx.get("otx_results") or [])]
    blocks.append({"type": "heading", "level": 3, "text": "AlienVault OTX"})
    blocks.append(
        {"type": "table",
         "columns": ["Indicator", "Type", "Pulse count", "Related pulses",
                     "Available sections"],
         "rows": otx_rows}
        if otx_rows else
        {"type": "paragraph", "text": "No AlienVault OTX results for this run."})

    reasons = [r for r in (ti.get("enrichment_risk_reasons") or []) if str(r).strip()]
    if reasons:
        blocks += [
            {"type": "heading", "level": 3, "text": "Enrichment Risk Assessment"},
            {"type": "bullet_list",
             "items": [{"text": _txt(r), "level": 0} for r in reasons]},
        ]

    notes = [n for n in (block.get("notes") or []) if str(n).strip()]
    if notes:
        blocks += [{"type": "heading", "level": 3, "text": "Notes"},
                   {"type": "bullet_list",
                    "items": [{"text": _txt(n), "level": 0} for n in notes]}]

    warnings = [w for w in (ti.get("warnings") or []) if str(w).strip()]
    if warnings:
        blocks += [{"type": "heading", "level": 3, "text": "Warnings"},
                   {"type": "bullet_list",
                    "items": [{"text": _txt(w), "level": 0} for w in warnings]}]

    return blocks


def build_ticket_blocks(ticket: dict[str, Any],
                        threat_intel: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Structured-block twin of soc_triage_agent.format_ticket_display() —
    same fields, same order, same labels — plus the Threat Intelligence
    Enrichment section. The ticket's UNC is not repeated in a body block
    because it is carried by the document title (see export_report())."""
    if not ticket:
        return []
    rr = ticket.get("risk_rating") or {}
    blocks: list[dict[str, Any]] = [
        {"type": "table", "columns": ["Field", "Value"], "rows": [
            ["Incident ID", _txt(ticket.get("incident_id"))],
            ["Title", _txt(ticket.get("title"))],
            ["Incident Time", _txt(ticket.get("incident_time"))],
            ["Ticket Created", _txt(ticket.get("created_at"))],
            ["Classification", _txt(ticket.get("classification")).upper()],
            ["Category", _txt(ticket.get("incident_category"))],
            ["MITRE Tactic", _txt(ticket.get("mitre_tactic") or "Unknown")],
            ["MITRE Technique", _txt(ticket.get("mitre_technique") or "Unknown")],
            ["Initial Response Time", _txt(ticket.get("initial_response_time"))],
            ["IOCs Matched", _txt(ticket.get("matched_ioc_count", 0))],
        ]},
        {"type": "heading", "level": 2, "text": "Risk Rating"},
        {"type": "table", "columns": ["Dimension", "Rating"], "rows": [
            ["Initiation", _txt(rr.get("likelihood_initiation"))],
            ["Occurrence", _txt(rr.get("likelihood_occurrence"))],
            ["Adverse Impact", _txt(rr.get("likelihood_adverse_impact"))],
            ["Overall", _txt(rr.get("overall_risk"))],
        ]},
        {"type": "heading", "level": 2, "text": "Triage Summary"},
        {"type": "paragraph", "text": _txt(ticket.get("summary"))},
        {"type": "heading", "level": 2, "text": "Recommended Actions"},
        {"type": "bullet_list", "items": [
            {"text": _txt(a), "level": 0}
            for a in (ticket.get("recommended_actions") or []) if str(a).strip()]},
    ]
    metakeys = ticket.get("metakeys") or []
    if metakeys:
        blocks += [{"type": "heading", "level": 2, "text": "Matched Meta-Keys"},
                   {"type": "paragraph", "text": _joined(metakeys)}]
    blocks += _threat_intel_blocks(threat_intel or {})
    return blocks


def _content_signature(blocks: list[dict[str, Any]]) -> str:
    """Stands in for the Reporting side's report_set_id: a hash of the
    AI-generated ticket content, so a re-triage or a fresh enrichment run
    that changes the ticket marks an existing analyst edit as stale exactly
    the way report_row_state() does with source_report_set_id."""
    payload = json.dumps(blocks, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:32]


# ══════════════════════════════════════════════════════════════════════════
# Row state / edit persistence (drop-in shaped like report_editing.py)
# ══════════════════════════════════════════════════════════════════════════

def ticket_row_state(incident_id: str, run_id: str, *, ticket: dict[str, Any],
                     threat_intel: dict[str, Any] | None,
                     triage_status: str | None = None,
                     triage_updated_at: str | None = None) -> dict[str, Any]:
    """Merges the agent-generated ticket with any saved analyst edit into the
    single dict the header actions and the editor both read. Never raises —
    worst case is a "Not generated" row with no blocks."""
    generated_blocks = build_ticket_blocks(ticket or {}, threat_intel or {})
    ticket_set_id = _content_signature(generated_blocks) if generated_blocks else None

    edit = wss.get_report_edit(incident_id, run_id, TICKET_REPORT_TYPE)
    has_edits = edit is not None
    edit_blocks = json.loads(edit["edited_blocks_json"]) if has_edits else []
    is_stale = bool(has_edits and edit.get("source_report_set_id") and ticket_set_id
                    and edit.get("source_report_set_id") != ticket_set_id)

    if not generated_blocks and not has_edits:
        status, last_saved_iso, display_blocks = "Not generated", None, []
    elif is_stale:
        status = "Outdated"
        last_saved_iso = edit.get("updated_at")
        display_blocks = edit_blocks   # keep the edit — see discard_report_edit()
    elif has_edits:
        status = "Edited"
        last_saved_iso = edit.get("updated_at")
        display_blocks = edit_blocks
    elif (triage_status or "") == "Approved":
        status = "Approved"
        last_saved_iso = ticket.get("created_at") or triage_updated_at
        display_blocks = generated_blocks
    else:
        status = "Draft ready"
        last_saved_iso = ticket.get("created_at") or triage_updated_at
        display_blocks = generated_blocks

    return {
        "report_type": TICKET_REPORT_TYPE,
        "title": TICKET_TITLE,
        "description": TICKET_DESCRIPTION,
        "unc": (ticket or {}).get("unc") or "",
        "status": status,
        "tone": STATUS_TONES.get(status, "info"),
        "last_saved_iso": last_saved_iso,
        "has_edits": has_edits,
        "is_stale": is_stale,
        "blocks": display_blocks,
        "original_blocks": generated_blocks,
        "edited_at": edit.get("updated_at") if has_edits else None,
        "edited_by": edit.get("last_edited_by") if has_edits else None,
        "version": edit.get("version") if has_edits else 0,
        "current_report_set_id": ticket_set_id,
        "has_threat_intel": bool(threat_intel),
        "exists": bool(generated_blocks or has_edits),
    }


def save_report_edit(incident_id: str, run_id: str, report_type: str,
                     blocks: list[dict[str, Any]], analyst: str,
                     *, original_blocks: list[dict[str, Any]],
                     source_report_set_id: str | None) -> dict[str, Any]:
    """Signature-compatible with report_editing.save_report_edit so app.py's
    shared block editor can drive either module. Activity is recorded
    against the triage stage, not reporting."""
    row = wss.upsert_report_edit(
        incident_id, run_id, report_type,
        edited_blocks=blocks, original_blocks=original_blocks,
        source_report_set_id=source_report_set_id, analyst=analyst)
    wss.record_activity(
        incident_id, run_id, "triage", "ticket_edit_saved", actor=analyst,
        metadata={"report_type": report_type, "version": row.get("version")})
    return row


def discard_report_edit(incident_id: str, run_id: str, report_type: str,
                        analyst: str) -> None:
    """"Replace with latest AI version" — drops the saved edit so the ticket
    reverts to the freshly generated triage + enrichment content."""
    wss.discard_report_edit(incident_id, run_id, report_type)
    wss.record_activity(
        incident_id, run_id, "triage", "ticket_edit_discarded", actor=analyst,
        metadata={"report_type": report_type})


def _ticket_export_dir(incident_id: str, run_id: str) -> Path:
    """A triage-owned leaf under the same run-scoped artifact root the rest
    of the workflow writes to — deliberately outside the reporting/ subtree
    so it can never collide with a hash-pinned candidate export set."""
    return _run_artifact_dir(incident_id, run_id) / "triage" / "ticket_exports"


def export_report(incident_id: str, run_id: str, report_type: str, file_type: str,
                  *, row_state: dict[str, Any], reporting_stage_attempt: int = 1,
                  analyst: str = "SOC Analyst") -> tuple[bytes, str]:
    """Exports the latest saved ticket content — edited if it exists, else
    the generated original (row_state["blocks"] already encodes that
    precedence) — to Word or PDF using the same block renderers the
    Reporting pipeline uses, so a ticket and a report look like one document
    family. reporting_stage_attempt is accepted only to stay signature-
    compatible with report_editing.export_report; the ticket is not part of
    any reporting attempt. Returns (file_bytes, filename)."""
    if file_type not in ("docx", "pdf"):
        raise ValueError(f"Unsupported file_type: {file_type!r}")
    blocks = row_state.get("blocks") or []
    if not blocks:
        raise FileNotFoundError("No triage ticket content available yet.")
    unc = str(row_state.get("unc") or "").strip()
    title = f"{TICKET_TITLE} {unc}".strip()
    out_dir = _ticket_export_dir(incident_id, run_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"triage_ticket_{incident_id}_{stamp}.{file_type}"
    path = out_dir / filename
    meta = {"confirmed_by": analyst}
    if file_type == "docx":
        render_blocks_to_docx(path, title, blocks, incident_id, meta)
    else:
        render_blocks_to_pdf(path, title, blocks, incident_id, meta)
    data = path.read_bytes()
    wss.record_activity(
        incident_id, run_id, "triage", f"ticket_export_{file_type}", actor=analyst,
        metadata={"has_edits": row_state.get("has_edits"),
                  "enriched": row_state.get("has_threat_intel"),
                  "filename": filename})
    return data, filename
