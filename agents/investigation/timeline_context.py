"""
Case-structured, bounded Investigation timeline (canonical audit Phase 2D).

What Pass 1 and Pass 2 receive as `{timeline}` when the workflow names an
Investigation subject (INVESTIGATION_SUBJECT_ID). It replaces one flat,
cross-incident, timestamp-sorted list (orchestrator.build_timeline_text --
up to ~149k characters for the Incident-001 cluster, historical duplicates
repeated, nothing marking which entry is the case under investigation) with:

  1. a preamble naming the subject and stating that correlated cases are
     separate incidents (similarity/relationship evidence, not one event
     chain);
  2. CURRENT CASE -- the subject's own document (its Phase 2B Context Brief,
     incl. deep-dive answers) in full; never budgeted against history;
  3. CORRELATED HISTORICAL CASES -- one block per other case of the cluster,
     identical repeated entries collapsed, materially different versions
     summarised, ranked by existing deterministic signals, packed into
     HISTORICAL_BUDGET with explicit "shown / summarised / omitted" counts.

Pure and deterministic: no model call, no I/O; the persisted cluster, the
historical artifacts and every structured output are never modified -- this
selects and labels what the model reads, nothing else.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Iterable, List, Optional

TIMELINE_HEADER = "=== INVESTIGATION TIMELINE (structured by case; bounded) ==="
TIMELINE_FOOTER = "=== END INVESTIGATION TIMELINE ==="
CURRENT_CASE_LABEL = "CURRENT CASE"
CORRELATED_CASE_LABEL = "CORRELATED CASE"

# Characters. The current case is NOT counted here: its document is already
# bounded by ingest_pipeline (12,000 + marker) and is always rendered whole.
HISTORICAL_BUDGET = 16000
HISTORICAL_CASE_MAX = 2600          # one fully-rendered correlated case block
HISTORICAL_EXCERPT_MAX = 1700       # evidence excerpt inside that block
HISTORICAL_SUMMARY_LINE_MAX = 240   # one-line entry for lower-ranked cases
MAX_SUMMARY_LINES = 20              # beyond these, cases are counted and listed by id only
MAX_VERSION_LINES = 2               # "earlier version differs in" lines per correlated case
SHARED_INDICATOR_EXAMPLES = 6
LINE_MAX = 400
_SECTION_HEADER_RESERVE = 1100      # section title + correlation line (≤600) + count lines

_BRIEF_MARKER = "INVESTIGATION CONTEXT BRIEF"
# The pre-2D ingest template called a case's OWN NetWitness sub-alerts
# "correlated alert(s)"; renamed at presentation time for historical
# documents (the stored artifacts are never rewritten).
_LEGACY_SUBALERT_PHRASE = re.compile(r"\bcontains (\d+) correlated alert\(s\):")
SUBALERT_PHRASE = r"has \1 NetWitness sub-alert record(s) (this case's own source alerts):"
_NOISE = {"", "unknown", "none", "null", "n/a", "-", "0.0.0.0", "127.0.0.1", "localhost"}
# Metadata fields whose differences between two versions of the same case
# are reported (the evidence-bearing fields ingest_pipeline records).
_VERSION_FIELDS = (("severity", "Triage severity"), ("tactic", "tactic"), ("technique", "technique"),
                   ("source_type", "source type"), ("ips", "IPs"), ("sha256s", "SHA-256"),
                   ("md5s", "MD5"), ("hostname", "hostname"), ("username", "username"))
_LIST_FIELDS = {"ips", "sha256s", "md5s", "emails", "domains"}


def _clip(text, limit: int = LINE_MAX) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def _meta(entry: dict) -> dict:
    meta = entry.get("metadata")
    return meta if isinstance(meta, dict) else {}


def _epoch(entry: dict):
    try:
        return int(_meta(entry).get("timestamp_epoch"))
    except (TypeError, ValueError):
        return None


def _csv(value) -> List[str]:
    return [v.strip() for v in str(value or "").split(",") if v.strip()]


def _norm_field(meta: dict, key: str) -> str:
    if key in _LIST_FIELDS:
        return ",".join(sorted(set(_csv(meta.get(key)))))
    return str(meta.get(key) if meta.get(key) is not None else "")


def evidence_fingerprint(entry: dict) -> str:
    """Identity of one cluster entry's evidence: case id + whitespace-
    normalised document + metadata with list fields order-insensitive.
    Two entries with the same fingerprint are the same evidence ingested
    more than once."""
    meta = _meta(entry)
    payload = {
        "id": str(entry.get("id")),
        "document": " ".join(str(entry.get("document") or "").split()),
        "metadata": {k: _norm_field(meta, k) for k in sorted(meta)
                     if k not in ("threat_intelligence_summary",)},
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def entry_indicators(entry: dict) -> set:
    """Exact-match indicators of one entry, from the same metadata fields the
    CorrelationEngine uses (_extract_indicators) minus two that are not
    reliable overlap evidence: /24 subnet trackers (not observed values) and
    the regex-scanned `domains` field (it also captures JSON field names,
    filenames and malware family labels -- e.g. "incident.title")."""
    meta = _meta(entry)
    out = set()
    for key in ("ips", "sha256s", "md5s"):
        out.update(v.lower() for v in _csv(meta.get(key)) if v.lower() not in _NOISE)
    for key in ("hostname", "username"):
        value = str(meta.get(key) or "").strip().lower()
        if value not in _NOISE:
            out.add(value)
    return out


def _document_format(document: str) -> str:
    if _BRIEF_MARKER in document:
        return ("canonical Context Brief format (that case's own Investigation handoff; "
                "provenance-labelled)")
    return ("legacy narrative format (pre-canonical handoff: no provenance labels; per-alert "
            "values may be case-level or default values) -- lower evidential quality than the "
            "current case's Context Brief")


# Legacy narratives are "The <key path> is <value>." sentences plus
# "Alert #N ..." sub-alert records (ingest_pipeline.serialize_json_to_narrative).
# Their key paths make a deterministic evidence-first selection possible.
_SEGMENT_SPLIT = re.compile(r"(?<=\.)\s+(?=(?:The |Alert #|Incident \S+ (?:has|contains) |=== ))")
_SEGMENT_PRIORITY = (
    (0, ("alert #", "incident ", "the endpoint indicators", "the network indicators",
         "the email artifacts", "the incident details title", "the incident details timestamp",
         "the incident details mitre", "the triage deep dive", "the log indicators",
         "the authentication details")),
    (1, ("the incident details description", "the classification alert type",
         "the classification severity", "=== threat intelligence summary",
         "the classification source risk score")),
)


def _segment_priority(segment: str) -> int:
    lower = segment.lower()
    for priority, prefixes in _SEGMENT_PRIORITY:
        if lower.startswith(prefixes):
            return priority
    return 2


def _excerpt(document: str, limit: int) -> str:
    """Bounded digest of one historical document. Canonical-brief documents
    are front-loaded by design (CASE, TRIAGE, ENTITIES, TI first), so their
    head is kept. Legacy narratives keep evidence sentences first (indicators,
    sub-alert records, title/time/MITRE, deep-dive answers), then the
    description/classification, then the rest (risk-rating rationale,
    enrichment lists) -- selected whole, in original order, with an explicit
    count of what was left out."""
    text = " ".join(str(document or "").split())
    text = _LEGACY_SUBALERT_PHRASE.sub(SUBALERT_PHRASE, text)
    text = re.sub(r"^Incident \S+ details are as follows:\s*", "", text)
    if len(text) <= limit:
        return text
    if _BRIEF_MARKER in text:
        cut = text.rfind(" ", 0, limit)
        cut = cut if cut > limit * 0.8 else limit
        return (text[:cut].rstrip() + f" [... historical document truncated: {len(text) - cut} of "
                f"{len(text)} chars omitted from model context]")
    segments = [s for s in _SEGMENT_SPLIT.split(text) if s]
    order = sorted(range(len(segments)), key=lambda i: (_segment_priority(segments[i]), i))
    marker_reserve = 140
    chosen, used = set(), 0
    for i in order:
        piece = segments[i] if len(segments[i]) <= 400 else _clip(segments[i], 400)
        if used + len(piece) + 1 > limit - marker_reserve:
            continue
        chosen.add(i)
        used += len(piece) + 1
    kept = [segments[i] if len(segments[i]) <= 400 else _clip(segments[i], 400) for i in sorted(chosen)]
    dropped = len(segments) - len(chosen)
    return (" ".join(kept) + f" [... {dropped} of {len(segments)} statements of this historical document "
            f"omitted from model context (lowest-priority first: risk rationale, enrichment lists); "
            f"{len(text)} chars in full]")


def _version_differences(latest: dict, other: dict) -> List[str]:
    lm, om = _meta(latest), _meta(other)
    diffs = []
    for key, label in _VERSION_FIELDS:
        a, b = _norm_field(om, key), _norm_field(lm, key)
        if a != b:
            diffs.append(f"{label} {a or 'none'} (latest: {b or 'none'})")
    had_dd = "deep dive" in str(other.get("document") or "").lower() or \
        "DEEP-DIVE ANSWERS" in str(other.get("document") or "")
    has_dd = "deep dive" in str(latest.get("document") or "").lower() or \
        "DEEP-DIVE ANSWERS" in str(latest.get("document") or "")
    if had_dd != has_dd:
        diffs.append("deep-dive supplement " + ("present" if had_dd else "absent")
                     + f" (latest: {'present' if has_dd else 'absent'})")
    if not diffs:
        diffs.append(f"document text only ({len(str(other.get('document') or ''))} vs "
                     f"{len(str(latest.get('document') or ''))} chars; not shown)")
    return diffs


def _group_cases(entries: List[dict]) -> dict:
    """{case id: {"versions": [(fingerprint, entry, count)], "first": index}}
    in first-appearance order; versions in appearance order, the LAST one is
    the latest ingestion."""
    cases: dict = {}
    for index, entry in enumerate(entries):
        case_id = str(entry.get("id"))
        case = cases.setdefault(case_id, {"versions": {}, "first": index, "entries": 0})
        case["entries"] += 1
        fp = evidence_fingerprint(entry)
        if fp in case["versions"]:
            _prior, count, _pos = case["versions"][fp]
            case["versions"][fp] = (entry, count + 1, index)
        else:
            case["versions"][fp] = (entry, 1, index)
    for case in cases.values():
        ordered = sorted(case["versions"].values(), key=lambda v: v[2])
        case["versions"] = [(e, n) for e, n, _ in ordered]
    return cases


def _correlation_line(correlation: Optional[dict], n_correlated: int) -> str:
    c = correlation or {}
    cluster = c.get("cluster_id") or "this correlation cluster"
    decision = c.get("decision")
    score = c.get("score")
    if decision == "MERGE":
        line = (f"Correlation: the current case was merged into existing correlation cluster {cluster} "
                "(Tier-1 MERGE" + (f", cluster-level correlation score {float(score):.3f}" if score is not None else "")
                + "); the correlated cases below are earlier members of that cluster.")
    elif decision == "NEW_CLUSTER":
        line = (f"Correlation: the current case formed new correlation cluster {cluster} with other "
                "queued alert(s) (Tier-2 NEW_CLUSTER).")
    elif decision == "STANDALONE":
        line = f"Correlation: standalone (Tier-2 STANDALONE) in {cluster}."
    else:
        line = f"Correlation: members of {cluster} (correlation decision not recorded for this run)."
    if n_correlated:
        line += (" The correlation engine scores the cluster as a whole; it produces no per-case "
                 "relationship score, so per-case relationship below is limited to shared indicators.")
    return line


def build_case_timeline(entries: Iterable[dict], subject_id, *, correlation: Optional[dict] = None,
                        pivot_ids: Iterable[str] = ()) -> tuple[str, dict]:
    """(timeline text, measurement metadata). `subject_id` must be the id of
    one entry. `correlation` = {"cluster_id", "decision", "score"} from
    main.py's correlation step (optional); `pivot_ids` = entries added by
    Pass-1 pivot retrieval (labelled as such, not as cluster members)."""
    entries = [e for e in entries if isinstance(e, dict)]
    subject = str(subject_id)
    pivot_ids = {str(p) for p in pivot_ids}
    cases = _group_cases(entries)
    if subject not in cases:
        raise ValueError(f"investigation subject {subject} is not part of the alert group")
    current = cases.pop(subject)
    current_entry = current["versions"][-1][0]          # newest copy of the subject wins
    superseded = current["entries"] - 1
    current_epoch = _epoch(current_entry)
    current_inds = entry_indicators(current_entry)

    ranked = []
    for case_id, case in cases.items():
        latest = case["versions"][-1][0]
        shared = sorted(current_inds & entry_indicators(latest))
        epoch = _epoch(latest)
        distance = abs(epoch - current_epoch) if epoch is not None and current_epoch is not None else float("inf")
        ranked.append({"id": case_id, "case": case, "latest": latest, "shared": shared,
                       "distance": distance, "first": case["first"], "pivot": case_id in pivot_ids})
    # Existing deterministic signals only: indicator overlap with the current
    # case (the correlation engine's own relational signal), then time
    # proximity to the current case, then cluster order.
    ranked.sort(key=lambda r: (-len(r["shared"]), r["distance"], r["first"]))

    n_entries = len(entries)
    duplicates = sum(n - 1 for case in cases.values() for _e, n in case["versions"])
    current_ts = _meta(current_entry).get("timestamp_str") or "time not recorded"

    lines = [TIMELINE_HEADER,
             f"Investigation subject: {subject}. Only the CURRENT CASE section describes the case under "
             "investigation; all findings, the severity and the report are about this case.",
             ("CORRELATED CASES are separate incidents, provided as supporting evidence of "
              "similarity/relationship. They are not part of the current case's event sequence: do not "
              "read timestamps across different cases as one continuous chain or as cause and effect."
              if ranked else "No correlated cases are part of this investigation."),
             "",
             f"=== {CURRENT_CASE_LABEL}: {subject} (Investigation subject) ===",
             f"[{current_ts}] [{CURRENT_CASE_LABEL}: {subject}] {current_entry.get('document') or ''}"]
    if superseded:
        lines.append(f"({superseded} earlier cop{'y' if superseded == 1 else 'ies'} of the current case in "
                     "this group superseded -- the newest copy is used)")
    lines.append(f"=== END {CURRENT_CASE_LABEL} ===")
    current_chars = len("\n".join(lines))

    full_shown, summarised, omitted = [], [], []
    if ranked:
        hist: list[str] = []
        hist_used = 0
        # The whole correlated section (its header, the omitted-cases line and
        # the closing markers included) stays within HISTORICAL_BUDGET.
        available = HISTORICAL_BUDGET - _SECTION_HEADER_RESERVE - 2 * LINE_MAX
        mode = "full"
        for position, r in enumerate(ranked):
            if mode == "full":
                # Full blocks never eat the room the remaining (lower-ranked)
                # cases need for their one-line summaries.
                later = min(len(ranked) - position - 1, MAX_SUMMARY_LINES)
                summary_reserve = later * (HISTORICAL_SUMMARY_LINE_MAX + 1) + (60 if later else 0)
                block = _render_case_block(r, HISTORICAL_CASE_MAX)
                if hist_used + len(block) + 1 <= available - summary_reserve:
                    hist.append(block)
                    hist_used += len(block) + 1
                    full_shown.append(r["id"])
                    continue
                mode = "summary"
            line = _render_case_line(r)
            if len(summarised) < MAX_SUMMARY_LINES and hist_used + len(line) + 1 <= available:
                if not summarised:
                    hist.append("Lower-ranked correlated cases (one-line summaries):")
                    hist_used += 60
                hist.append(line)
                hist_used += len(line) + 1
                summarised.append(r["id"])
            else:
                omitted.append(r["id"])
        header = [f"=== CORRELATED HISTORICAL CASES (supporting evidence; NOT the Investigation subject) ===",
                  _clip(_correlation_line(correlation, len(ranked)), 600),
                  (f"Cluster entries: {n_entries} ({len(ranked) + 1} distinct cases: 1 current, "
                   f"{len(ranked)} correlated); {duplicates} identical repeated entr"
                   f"{'y' if duplicates == 1 else 'ies'} collapsed."),
                  (f"Showing {len(full_shown)} of {len(ranked)} correlated cases in full"
                   + (f", {len(summarised)} as one-line summaries" if summarised else "")
                   + (f" (+{len(omitted)} additional historical cases omitted from model context)" if omitted else "")
                   + ". Order: most indicators shared with the current case, then closest in time."),
                  ""]
        lines += header + hist
        if omitted:
            lines.append(_clip(f"(+{len(omitted)} additional historical cases omitted from model context: "
                               + ", ".join(omitted) + ")", LINE_MAX))
        lines.append("=== END CORRELATED HISTORICAL CASES ===")
    lines.append(TIMELINE_FOOTER)
    text = "\n".join(lines)
    return text, {
        "subject_id": subject,
        "entries": n_entries,
        "correlated_cases": len(ranked),
        "full": full_shown,
        "summarised": summarised,
        "omitted": omitted,
        "duplicates_collapsed": duplicates,
        "current_superseded": superseded,
        "pivot_entries": sorted(c for c in cases if c in pivot_ids),
        "chars": len(text),
        "current_chars": current_chars,
        "historical_chars": len(text) - current_chars,
    }


def _relationship(r: dict) -> str:
    origin = ("added by Pass-1 pivot retrieval (not a cluster member)" if r.get("pivot")
              else "member of the same correlation cluster")
    if r["shared"]:
        examples = r["shared"][:SHARED_INDICATOR_EXAMPLES]
        more = len(r["shared"]) - len(examples)
        return (f"{origin}; indicators shared with the current case ({len(r['shared'])}): "
                + ", ".join(examples) + (f" (+{more} more)" if more else ""))
    return f"{origin}; no exact indicator shared with the current case (IP/hash/host/user)"


def _render_case_block(r: dict, max_chars: int) -> str:
    latest = r["latest"]
    meta = _meta(latest)
    case = r["case"]
    versions = case["versions"]
    repeats = sum(n - 1 for _e, n in versions)
    head = f"[{CORRELATED_CASE_LABEL}: {r['id']}] (historical; {case['entries']} cluster entr" \
           f"{'y' if case['entries'] == 1 else 'ies'}"
    if repeats:
        head += f"; {repeats} identical repeat{'s' if repeats > 1 else ''} collapsed"
    if len(versions) > 1:
        head += f"; {len(versions)} distinct versions, latest shown"
    head += ")"
    body = [f"Case time: {meta.get('timestamp_str') or 'not recorded'} (this case's own time)",
            "Relationship: " + _relationship(r),
            (f"At ingestion: Triage severity {meta.get('severity') or 'not recorded'}; tactic "
             f"{meta.get('tactic') or 'not recorded'}; technique {meta.get('technique') or 'not recorded'}; "
             f"source type {meta.get('source_type') or 'not recorded'}")]
    earlier = versions[:-1]
    # Most recent earlier versions first (closest to what is shown).
    for index in range(len(earlier), max(0, len(earlier) - MAX_VERSION_LINES), -1):
        entry, count = earlier[index - 1]
        body.append(f"Earlier version {index}" + (f" (×{count})" if count > 1 else "") + " differs in: "
                    + "; ".join(_version_differences(latest, entry)))
    if len(earlier) > MAX_VERSION_LINES:
        body.append(f"(+{len(earlier) - MAX_VERSION_LINES} older distinct version(s) not compared here)")
    body.append(f"Document format: {_document_format(str(latest.get('document') or ''))}")
    fixed = "\n".join([_clip(head)] + ["  " + _clip(line) for line in body])
    # The evidence excerpt gets what the block budget leaves.
    room = max(300, min(HISTORICAL_EXCERPT_MAX, max_chars - len(fixed) - 40))
    evidence = "Evidence (latest version): " + _excerpt(latest.get("document"), room)
    return fixed + "\n  " + _clip(evidence, room + 200)


def _render_case_line(r: dict) -> str:
    meta = _meta(r["latest"])
    return _clip(f"- [{CORRELATED_CASE_LABEL}: {r['id']}] {meta.get('timestamp_str') or 'time not recorded'} | "
                 f"{meta.get('tactic') or 'tactic not recorded'} / {meta.get('technique') or 'technique not recorded'} | "
                 f"shared indicators: {len(r['shared'])}"
                 + (f" ({', '.join(r['shared'][:3])})" if r["shared"] else "")
                 + f" | {r['case']['entries']} cluster entr{'y' if r['case']['entries'] == 1 else 'ies'}"
                 + (f" ({len(r['case']['versions'])} distinct versions)" if len(r["case"]["versions"]) > 1 else "")
                 + (" | added by Pass-1 pivot retrieval" if r.get("pivot") else ""),
                 HISTORICAL_SUMMARY_LINE_MAX)
