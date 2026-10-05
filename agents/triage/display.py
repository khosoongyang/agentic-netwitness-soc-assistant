"""agents/triage/display.py -- Markdown rendering of the triage trace and ticket (chat / CLI display).

[AUDIT T-22] Moved verbatim out of soc_triage_agent.py (2,500+ lines) to
split it by responsibility. soc_triage_agent re-exports every name
defined here, so existing imports and behaviour are unchanged.
"""
from __future__ import annotations

from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
# 10. DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

# [FYP-FUNCTION] `render_triage_trace` — constructs render triage trace output for the next triage consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `trace`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>, agents/triage/soc_triage_agent.py:soc_triage_chat_respond; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `capitalize`, `extend`, `get`, `items`, `join`, `upper`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def render_triage_trace(trace: list[dict]) -> str:
    lines: list[str] = ["## 🛡️ SOC Triage Report\n"]
    for step in trace:
        name   = step.get("step", "Step")
        status = "✅" if step.get("status") == "ok" else "❌"
        lines.append(f"### {status} Phase — {name}")

        if name == "IOC Checklist":
            count   = step.get("total_ioc_count") or 0
            summary = step.get("ioc_summary") or ""
            mkeys   = step.get("matched_metakeys") or []
            lines.append(f"**Total IOCs matched:** {count}")
            if summary:
                lines.append(f"**Summary:** {summary}")
            if mkeys:
                lines.append(f"**Meta-Keys:** `{'`, `'.join(mkeys)}`")
            for cat, cat_data in (step.get("per_category") or {}).items():
                matched = cat_data.get("matched_ioc_names") or []
                if matched:
                    lines.append(f"- **{cat.capitalize()}:** {', '.join(matched)}")
            if step.get("debug_note"):
                lines.append(f"\n> ⚠️ {step['debug_note']}")
                if step.get("raw_tail"):
                    lines.append(f"> Raw model output (tail): `{step['raw_tail'][-200:]}`")

        elif name == "Risk Rating":
            d = step.get("data") or {}
            lines.extend([
                "| Dimension | Rating |",
                "|-----------|--------|",
                f"| Likelihood of Initiation | **{d.get('likelihood_initiation') or '—'}** |",
                f"| Likelihood of Occurrence | **{d.get('likelihood_occurrence') or '—'}** |",
                f"| Likelihood of Adverse Impact | **{d.get('likelihood_adverse_impact') or '—'}** |",
                f"| **Overall Risk** | **{d.get('overall_risk') or '—'}** |",
            ])
            if d.get("rationale"):
                lines.append(f"\n*{d['rationale']}*")

        elif name == "SOC Classification":
            d   = step.get("data") or {}
            cls = (d.get("classification") or "—").upper()
            lines.append(f"- **Classification:** {cls}")
            lines.append(f"- **Category:** {d.get('incident_category') or '—'}")
            lines.append(f"- **Response Time:** {d.get('response_time') or '—'}")
            if d.get("summary"):
                lines.append(f"- **Summary:** {d['summary']}")
            for a in (d.get("recommended_actions") or []):
                lines.append(f"  - {a}")

        lines.append("")
    return "\n".join(lines)


# [FYP-FUNCTION] `format_ticket_display` — constructs format ticket display output for the next triage consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `ticket`, `include_header`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis triage workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include app.py:<module>, app.py:_run_triage_workflow_with_ui, agents/triage/soc_triage_agent.py:soc_triage_chat_respond; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `get`, `join`, `upper`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def format_ticket_display(ticket: dict, include_header: bool = True) -> str:
    """Markdown rendering of a triage ticket.

    include_header=False drops only the leading rule + "## <icon> Ticket
    <unc>" line, leaving every section below it byte-identical. The case
    detail page's Triage stage uses that so it can draw its own header row
    (ticket title on the left, Open & Edit / Export Word / Export PDF on the
    right) in place of the UNC; the chat and workflow-board renderings keep
    the header as-is.
    """
    rr    = ticket.get("risk_rating") or {}
    unc   = ticket.get("unc") or "—"
    cls   = (ticket.get("classification") or "—").upper()
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    icon  = icons.get(cls, "⚪")
    lines = [
        *(["---", f"## {icon} Ticket `{unc}`"] if include_header else []),
        "| Field | Value |",
        "|-------|-------|",
        f"| **Incident ID** | `{ticket.get('incident_id') or '—'}` |",
        f"| **Title** | {ticket.get('title') or '—'} |",
        f"| **Incident Time** | {ticket.get('incident_time') or '—'} |",
        f"| **Ticket Created** | {ticket.get('created_at') or '—'} |",
        f"| **Classification** | **{cls}** |",
        f"| **Category** | {ticket.get('incident_category') or '—'} |",
        f"| **MITRE Tactic** | {ticket.get('mitre_tactic') or 'Unknown'} |",
        f"| **MITRE Technique** | {ticket.get('mitre_technique') or 'Unknown'} |",
        f"| **Initial Response Time** | {ticket.get('initial_response_time') or '—'} |",
        f"| **IOCs Matched** | {ticket.get('matched_ioc_count', 0)} |",
        "",
        "### Risk Rating",
        "| Dimension | Rating |",
        "|-----------|--------|",
        f"| Initiation | {rr.get('likelihood_initiation') or '—'} |",
        f"| Occurrence | {rr.get('likelihood_occurrence') or '—'} |",
        f"| Adverse Impact | {rr.get('likelihood_adverse_impact') or '—'} |",
        f"| **Overall** | **{rr.get('overall_risk') or '—'}** |",
        "",
        "### Triage Summary",
        ticket.get("summary") or "—",
        "",
        "### Recommended Actions",
    ]
    for a in (ticket.get("recommended_actions") or []):
        lines.append(f"- {a}")
    mkeys = ticket.get("metakeys") or []
    if mkeys:
        lines += ["", "### Matched Meta-Keys",
                  f"`{'`, `'.join(mkeys)}`"]
    return "\n".join(lines)


