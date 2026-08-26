"""workflow/stage_summaries.py -- AI-summary / "Thinking Process" presentation layer.

Extracted from workflow/engine.py (Phase 4 of the orchestration cleanup):
this module owns exactly the presentation-layer responsibility for turning
each stage's raw agent output into the two analyst-facing text artefacts
every stage produces -- the short "AI-Generated Summary" (ai_summary, via an
LLM call) and the deterministic "Thinking Process" narrative (ai_thinking) --
plus the small Markdown/MITRE parsers those two responsibilities share.

Nothing here performs SQLite writes, stage locking, subprocess execution,
file handoffs, background threads, or routing decisions -- engine.py
retains all of that and calls into this module the same way it always did:
engine.py imports every name below back into its own namespace, so every
existing internal (unqualified) and external (workflow.engine.<name>) call
site keeps working unchanged.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any


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
    [FYP-CALLS]: _stage_ai_summary_context(),
    integrations.openai.client.invoke_openai_text(), limit_ai_summary_sentences().
    """
    from integrations.openai.client import invoke_openai_text

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
    Reuses the existing OpenAI helper (integrations/openai/client.py,
    already used by the reporting stage) — no separate LLM client is introduced."""
    from integrations.openai.client import invoke_openai_text

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
    _thinking_fragment() for investigation).
    [FYP-CALLS]: _render_stage_progress_plain(), render_triage_thinking_plain(),
    _thinking_fragment().
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
    from integrations.openai.client import invoke_openai_text

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
