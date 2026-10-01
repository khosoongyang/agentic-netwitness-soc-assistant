# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, json, pydantic, re, typing,
#   agents.triage.alert_triage, agents.triage.baseline.
# =============================================================================
# File: agents/triage/evidence_packet.py
# Purpose: Builds the Triage EVIDENCE PACKET -- one structured, citable record
#   of everything code (not the LLM) knows about an incident before the LLM
#   reasons about it: detection facts, the resolved entity, parser data
#   quality, the measured historical baseline, deterministic rule signals,
#   and (placeholder) business context.
# Main functionality: build_evidence_packet(), get_leaf(), iter_leaves(),
#   render_packet_for_prompt(). (The Pydantic models -- EvidencePacket,
#   EvidenceLeaf, ... -- live in agents/triage/triage_result.py.)
# Inputs: incident dict, optional parsed_context (Parsing stage's
#   processed_alert), baseline dict from agents/triage/baseline.py, and
#   [FYP-TRIAGE-STEP2] the optional data_availability recorded by ingestion.
# Outputs: a plain dict validated by EvidencePacket. Every leaf has the shape
#   {value, status: "measured"|"inferred"|"missing", source} and is
#   addressable by a dot-path such as "baseline.same_source_entity_30d".
# Workflow position: Triage stage, between the baseline and the LLM phases
#   (_run_risk/_run_cls read it; agents/triage/guards.py verifies against it).
# Called by: agents/triage/soc_triage_agent.py (TriageAgent.triage),
#   agents/triage/guards.py, workflow/engine.py (mock_triage_result).
# Important side effects: none (pure function; no I/O).
# Error and fallback behaviour: absent inputs become status "missing" leaves,
#   never omitted keys and never guessed values ("missing = unknown").
# Key evaluator search terms: build_evidence_packet, EvidencePacket,
#   [FYP-TRIAGE-EVIDENCE], [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================
"""
Triage evidence packet  --  evidence_packet.py
==============================================
[FYP-TRIAGE-EVIDENCE] The SOC triage method records WHICH evidence was checked
and whether it was actually observed. The packet makes that explicit:

  measured  -- read directly from the incident, the parser, or the database
  inferred  -- derived by deterministic code (classification, extrapolation,
               lower-bound counts); true but not directly observed
  missing   -- not available. Missing is UNKNOWN, never "safe".

The ``context`` section (asset / change / confirmed-benign history) is an
always-missing placeholder in this step, so "benign_expected" cannot be
evidenced yet -- intended: confirmed-benign requires evidence.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterator

from .alert_triage import _INDICATORS, _scan_text
from .baseline import BASELINE_WINDOWS_DAYS, extract_entity
# [FYP-TRIAGE-STEP2] raw-alert digest ("pull the raw log, never trust the
# alert summary alone").
from .raw_alerts import build_raw_alerts_section
# The Pydantic models live in the dependency-light contract module so the
# persisted result and the packet builder can never drift apart.
from .triage_result import EvidenceLeaf, EvidencePacket, EvidenceStatus

# Rule-signal labels that are "strong" enough to floor the disposition
# (see agents/triage/guards.py rule b). suspicious_ip (weight 1, any IPv4
# string) is deliberately NOT here -- it fires on nearly every incident.
STRONG_SIGNAL_LABELS: frozenset[str] = frozenset({
    "privilege_escalation", "malware", "lateral_movement", "persistence", "exfiltration",
})

# Rule-signal scan budget: the Respond-API export for a large incident can be
# >10 MB; the scan is bounded so Triage latency stays flat.
_SCAN_MAX_FIELDS = 6000
_SCAN_MAX_CHARS = 400_000
_MATCH_SAMPLES_PER_LABEL = 5
_MATCH_CONTEXT_CHARS = 30

_PLACEHOLDER_SOURCE = "not yet integrated (Triage Step 1 placeholder)"


# =============================================================================
# [FYP-SECTION] LEAF HELPERS
# =============================================================================

def _leaf(value: Any, status: str, source: str) -> dict:
    return {"value": value, "status": status, "source": source}


def _missing(source: str) -> dict:
    return _leaf(None, "missing", source)


def _present(value: Any) -> bool:
    return value not in (None, "", [], {})


def _field_leaf(incident: dict, key: str) -> dict:
    value = incident.get(key)
    if _present(value):
        return _leaf(value, "measured", f"incident.{key}")
    return _missing(f"incident.{key} (absent)")


# =============================================================================
# [FYP-SECTION] SECTION BUILDERS
# =============================================================================

def _detection(incident: dict, baseline: dict) -> dict:
    created_raw = None
    created_src = None
    for key in ("created", "createdDate", "createdAt", "created_at"):
        if _present(incident.get(key)):
            created_raw, created_src = incident.get(key), f"incident.{key}"
            break
    created_leaf = (_leaf(created_raw, "measured", created_src) if created_src
                    else _missing("incident.created (absent)"))
    return {
        "createdBy": _field_leaf(incident, "createdBy"),
        "ruleId": _field_leaf(incident, "ruleId"),
        "created": created_leaf,
        "sources": _field_leaf(incident, "sources"),
        "riskScore": _field_leaf(incident, "riskScore"),
        "priority": _field_leaf(incident, "priority"),
        "alertCount": _field_leaf(incident, "alertCount"),
        "eventCount": _field_leaf(incident, "eventCount"),
        "tactics": _field_leaf(incident, "tactics"),
        "techniques": _field_leaf(incident, "techniques"),
    }


def _entity(incident: dict, baseline: dict) -> dict:
    ent = extract_entity(incident)
    if ent["value"] is None:
        return {"value": _missing("title ' for <entity>' suffix and alertMeta.SourceIp/"
                                  "DestinationIp all absent"),
                "kind": _leaf("unresolved", "missing", "agents/triage/baseline.classify_entity")}
    # Title group-by entity = NetWitness's own grouping key (observed).
    # alertMeta fallback = our choice of which IP is "the" entity (inferred).
    value_status = "measured" if ent["source"] == "incident.title" else "inferred"
    # IP classes are exact (ipaddress module); name-based classes are heuristic.
    kind_status = "measured" if ent["kind"].startswith("ip_") else "inferred"
    return {
        "value": _leaf(ent["value"], value_status, ent["source"]),
        "kind": _leaf(ent["kind"], kind_status,
                      "agents/triage/baseline.classify_entity (ipaddress/RFC1918)"),
    }


def _data_quality(parsed_context: dict | None) -> dict:
    if not isinstance(parsed_context, dict) or not parsed_context:
        src = "parsed_context (Parsing stage output not supplied)"
        return {"parser_status": _missing(src), "parser_confidence": _missing(src),
                "missing_fields": _missing(src), "data_quality": _missing(src)}
    meta = parsed_context.get("parser_metadata") if isinstance(
        parsed_context.get("parser_metadata"), dict) else {}
    dq = parsed_context.get("data_quality") if isinstance(
        parsed_context.get("data_quality"), dict) else {}

    status = parsed_context.get("parser_status")
    confidence = meta.get("parser_confidence") or dq.get("parser_confidence")
    conf_src = ("parsed_context.parser_metadata.parser_confidence"
                if meta.get("parser_confidence") else "parsed_context.data_quality.parser_confidence")
    missing_fields = meta.get("missing_fields")
    if missing_fields is None and "missing_required_fields" in dq:
        missing_fields = dq.get("missing_required_fields")
    dq_summary = {k: dq.get(k) for k in (
        "parser_confidence", "parser_confidence_score", "confidence_explanation",
        "missing_required_fields", "warnings", "normalised_event_count") if k in dq}
    return {
        "parser_status": (_leaf(status, "measured", "parsed_context.parser_status")
                          if _present(status) else _missing("parsed_context.parser_status (absent)")),
        "parser_confidence": (_leaf(confidence, "measured", conf_src)
                              if _present(confidence) else _missing(f"{conf_src} (absent)")),
        # An empty list is a real measurement ("nothing missing").
        "missing_fields": (_leaf(list(missing_fields), "measured",
                                 "parsed_context.parser_metadata.missing_fields")
                           if isinstance(missing_fields, list)
                           else _missing("parsed_context.parser_metadata.missing_fields (absent)")),
        "data_quality": (_leaf(dq_summary, "measured", "parsed_context.data_quality")
                         if dq_summary else _missing("parsed_context.data_quality (absent)")),
    }


def _baseline(baseline: dict | None) -> dict:
    b = baseline if isinstance(baseline, dict) else {}
    measured = b.get("status") == "measured"
    db_src = b.get("db_source") or "soc_incidents.db:incidents"
    as_of = b.get("as_of")
    scope = f"{db_src} (created < {as_of}, own id excluded)"
    reason = b.get("reason") or "baseline not computed"

    out: dict[str, dict] = {
        "status": (_leaf("measured", "measured", scope) if measured
                   else _leaf(b.get("status") or "unknown", "missing", "agents/triage/baseline")),
        "reason": _leaf(reason, "measured", "agents/triage/baseline.compute_baseline"),
    }
    complete = b.get("window_complete") or {}
    for prefix, key in (("same_source_entity", "same_source_entity"),
                        ("same_entity", "same_entity_any_source")):
        counts = b.get(key) or {}
        for days in BASELINE_WINDOWS_DAYS:
            label = f"{days}d"
            n = counts.get(label)
            if not measured or n is None:
                out[f"{prefix}_{label}"] = _missing(f"{scope}: not measurable ({reason})")
            elif complete.get(label):
                out[f"{prefix}_{label}"] = _leaf(n, "measured", f"{scope}, last {label}")
            else:
                out[f"{prefix}_{label}"] = _leaf(
                    n, "inferred", f"{scope}, last {label} (window starts before DB "
                                   "coverage: lower bound)")
        n_all = counts.get("all_time")
        out[f"{prefix}_all_time"] = (
            _leaf(n_all, "measured", f"{scope}, since coverage_start")
            if measured and n_all is not None else _missing(f"{scope}: not measurable"))

    n90 = (b.get("same_source_entity") or {}).get("90d")
    if measured and n90 is not None and complete.get("90d"):
        out["same_source_entity_annualized"] = _leaf(
            round(n90 * 365 / 90, 1), "inferred",
            "same_source_entity_90d x 365/90 (extrapolated rate per year)")
    else:
        out["same_source_entity_annualized"] = _missing(
            "needs a complete, measured 90-day same-source window")

    for key in ("first_seen", "last_seen", "is_first_occurrence", "is_known_noisy",
                "coverage_start", "coverage_end"):
        value = b.get(key)
        if key in ("first_seen", "last_seen") and measured and b.get("is_first_occurrence"):
            out[key] = _leaf(None, "measured", f"{scope}: no prior occurrence")
        elif measured and value is not None:
            src = scope
            if key == "is_known_noisy":
                src = (f"{scope}: same_source_entity_30d >= "
                       f"{b.get('known_noisy_threshold_30d')}")
            out[key] = _leaf(value, "measured", src)
        elif key.startswith("coverage_") and value is not None:
            out[key] = _leaf(value, "measured", db_src)
        else:
            out[key] = _missing(f"{scope}: not measurable ({reason})")
    return out


def _iter_scan_fields(node: Any, path: str) -> Iterator[tuple[str, str]]:
    """Yield (dot-path, string) for every scalar VALUE (keys are not scanned:
    a key such as 'smb_bytes' is schema, not an observed event)."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _iter_scan_fields(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _iter_scan_fields(v, f"{path}[{i}]")
    elif isinstance(node, str):
        if node.strip():
            yield path, node
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        return  # numbers carry no indicator text


def _rule_signals(incident: dict, parsed_context: dict | None) -> dict:
    """Run the EXISTING deterministic scorer (alert_triage._scan_text over
    alert_triage._INDICATORS) across the incident's text values, recording
    label, weight, MITRE mapping and the matched text for each hit."""
    fields: list[tuple[str, str]] = []
    chars = 0
    truncated = False
    sources: list[tuple[str, Any]] = [("incident", incident)]
    if isinstance(parsed_context, dict):
        # Only parsed_context's top-level text (decoded commands, analyst
        # summary...) -- its nested normalised_alert duplicates the incident.
        sources.append(("parsed_context", {k: v for k, v in parsed_context.items()
                                           if isinstance(v, str)}))
    for root, node in sources:
        for path, text in _iter_scan_fields(node, root):
            if len(fields) >= _SCAN_MAX_FIELDS or chars >= _SCAN_MAX_CHARS:
                truncated = True
                break
            text = text[: _SCAN_MAX_CHARS - chars]
            fields.append((path, text))
            chars += len(text)

    by_label: dict[str, dict] = {}
    for path, text in fields:
        for hit in _scan_text(text):
            agg = by_label.setdefault(hit["label"], {
                "label": hit["label"], "weight": hit["weight"], "count": 0,
                "category": hit["category"], "mitre_tactic": hit["tactic"],
                "mitre_technique": hit["technique"], "matched": [],
            })
            agg["count"] += hit["count"]
            if len(agg["matched"]) < _MATCH_SAMPLES_PER_LABEL:
                pattern = next(p for lbl, p, *_ in _INDICATORS if lbl == hit["label"])
                m = re.search(pattern, text, re.I)
                if m:
                    lo = max(0, m.start() - _MATCH_CONTEXT_CHARS)
                    hi = min(len(text), m.end() + _MATCH_CONTEXT_CHARS)
                    agg["matched"].append({"path": path, "match": m.group(0),
                                           "excerpt": text[lo:hi]})

    src = "agents/triage/alert_triage._scan_text over incident text values"
    ordered = sorted(by_label.values(), key=lambda h: (-h["weight"], h["label"]))
    out = {
        "scan_summary": _leaf({
            "labels": [h["label"] for h in ordered],
            "strong_labels": [h["label"] for h in ordered if h["label"] in STRONG_SIGNAL_LABELS],
            "fields_scanned": len(fields), "chars_scanned": chars, "truncated": truncated,
        }, "measured", src),
    }
    for h in ordered:
        out[h["label"]] = _leaf(h, "measured", src)
    return out


def _context() -> dict:
    return {
        "asset_context": _missing(_PLACEHOLDER_SOURCE),
        "change_context": _missing(_PLACEHOLDER_SOURCE),
        "confirmed_benign_history": _missing(_PLACEHOLDER_SOURCE),
    }


# =============================================================================
# [FYP-SECTION] PUBLIC API
# =============================================================================

def build_evidence_packet(incident: dict, parsed_context: dict | None,
                          baseline: dict | None,
                          data_availability: dict | None = None) -> dict:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Assemble and validate the evidence packet.

    ``data_availability`` ([FYP-TRIAGE-STEP2]) is the fetch-outcome record
    ingestion stamped next to the raw incident (workflow/engine.py::
    _data_availability). ``None`` means UNKNOWN: the raw_alerts.available
    leaf is then "missing", so the alert cannot be closed as benign.

    Returns a JSON-safe dict (``EvidencePacket.model_dump(mode="json")``)."""
    incident = incident if isinstance(incident, dict) else {}
    packet = {
        "detection": _detection(incident, baseline or {}),
        "entity": _entity(incident, baseline or {}),
        "data_quality": _data_quality(parsed_context),
        "baseline": _baseline(baseline),
        "raw_alerts": build_raw_alerts_section(incident, data_availability,
                                               strong_labels=STRONG_SIGNAL_LABELS),
        "rule_signals": _rule_signals(incident, parsed_context),
        "context": _context(),
    }
    return EvidencePacket.model_validate(packet).model_dump(mode="json")


def _is_leaf(node: Any) -> bool:
    return isinstance(node, dict) and set(node) == {"value", "status", "source"}


def get_leaf(packet: dict, path: str) -> dict | None:
    """[FYP-FUNCTION] Resolve a dot-path (e.g. "baseline.same_source_entity_30d")
    to its leaf, or None if the path does not name a leaf."""
    if not isinstance(path, str) or not path.strip():
        return None
    node: Any = packet
    for part in path.strip().split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if _is_leaf(node) else None


def iter_leaves(packet: dict, prefix: str = "") -> Iterator[tuple[str, dict]]:
    """[FYP-FUNCTION] Yield (dot-path, leaf) for every leaf in the packet."""
    for key, node in (packet or {}).items():
        path = f"{prefix}.{key}" if prefix else key
        if _is_leaf(node):
            yield path, node
        elif isinstance(node, dict):
            yield from iter_leaves(node, path)


def _short(value: Any, limit: int = 220) -> str:
    text = json.dumps(value, default=str, ensure_ascii=False)
    return text if len(text) <= limit else text[:limit] + "…"


# [FYP-TRIAGE-STEP2] raw_alerts leaves are capped lists ({note, items, ...});
# they get a larger render budget, and the ranked signatures themselves are
# shown in the INCIDENT block (_compact_incident), so only their truncation
# note is repeated here.
_RAW_ALERTS_RENDER_CHARS = 600


def _render_value(path: str, value: Any) -> str:
    if path.startswith("raw_alerts.") and isinstance(value, dict) and "items" in value:
        if path == "raw_alerts.signatures":
            return _short({"note": value.get("note"),
                           "alerts_covered_by_shown": value.get("alerts_covered_by_shown")},
                          _RAW_ALERTS_RENDER_CHARS)
        return _short({"note": value.get("note"), "items": value.get("items")},
                      _RAW_ALERTS_RENDER_CHARS)
    if path.startswith(("raw_alerts.", "rule_signals.lolbas")):
        return _short(value, _RAW_ALERTS_RENDER_CHARS)
    return _short(value)


def render_packet_for_prompt(packet: dict) -> str:
    """[FYP-FUNCTION] One line per leaf -- ``path [status] = value`` -- so the
    model can cite exact dot-paths. Values quoted from the incident are
    escaped JSON strings, i.e. data, never instructions."""
    lines = []
    for path, leaf in iter_leaves(packet):
        value = "—" if leaf["status"] == "missing" else _render_value(path, leaf["value"])
        lines.append(f"{path} [{leaf['status']}] = {value}")
    return "\n".join(lines)


__all__ = [
    "EvidenceStatus",
    "EvidenceLeaf",
    "EvidencePacket",
    "STRONG_SIGNAL_LABELS",
    "build_evidence_packet",
    "get_leaf",
    "iter_leaves",
    "render_packet_for_prompt",
]
