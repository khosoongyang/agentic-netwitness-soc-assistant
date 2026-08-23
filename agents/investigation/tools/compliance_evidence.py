# ==============================================================================
# [FYP-FILE] compliance_evidence.py
# File: compliance_evidence.py
# Workflow position: Aegis SOC analysis support.
# Important dependencies: __future__, os, typing.
# Key evaluator search terms: _disabled, _s, _first, _as_list, _triage_bits, _detection_summary, [FYP-FUNCTION].
# ------------------------------------------------------------------------------
# Purpose: Deterministic mapping of one finalized incident's response onto SOC 2
#   Trust Services Criteria controls (mainly CC7 System Operations, plus CC2/CC4
#   and conditional A1/C1/P TSCs when the incident actually implicates them).
#   Produces analyst-facing audit EVIDENCE folded into the written report — not
#   a formal SOC 2 attestation.
# Main functionalities:
#   - build_compliance_evidence(): [FYP-FUNCTION] [FYP-PROCESS] main entry
#     point — evaluates each control against the incident/triage/investigation
#     dicts and returns MET/PARTIAL/NOT_MET status + evidence text per control.
#   - _build(): [FYP-FUNCTION] the actual control-by-control evaluation logic
#     (CC7.2 detect, CC7.3 evaluate, CC7.4 respond, CC7.5 recover, CC2.2, CC4.1,
#     plus conditional A1.2/C1.1/P4.2).
#   - format_compliance_evidence(): [FYP-FUNCTION] markdown table for the
#     report appendix.
# Inputs: incident (dict), triage_result / investigation_result / ti_result
#   (all optional dicts from earlier pipeline stages).
# Outputs: build_compliance_evidence() -> {available, controls, criteria_touched,
#   stats, meta}; never raises (caller-safe by construction).
# Called by [FYP-USED-BY]: skills_sidecar.py only (`_collect_compliance` /
#   report-handoff enrichment, confirmed via grep at import + call + dict
#   assembly sites) — feeds the compliance-evidence block into the generated
#   report.
# Calls [FYP-CALLS]: stdlib only (os, typing) — no I/O, no network, no DB.
# Kill switch: NW_DISABLE_COMPLIANCE_EVIDENCE env var (checked in _disabled()).
# ==============================================================================
"""
compliance_evidence.py — map an incident's response to SOC 2 controls (deterministic).

WHAT IT DOES
    Turns a finalized incident (+ its triage / investigation artifacts) into
    **audit evidence**: which SOC 2 Trust Services Criteria controls the SOC's
    handling of THIS incident satisfies, and the concrete evidence for each. The
    output is folded into the written report by skills_sidecar.py, so every report
    doubles as a control-attestation record ("build evidence into the workflow
    rather than bolting it on before audit season").

    Scope is honest and narrow: an incident-response process most directly
    evidences the SOC 2 **Common Criteria — CC7 System Operations** series
    (detect → evaluate → respond → recover) plus CC2 (communication of the report)
    and CC4 (monitoring / audit trail). Availability (A1), Confidentiality (C1) and
    Privacy (P) controls are added ONLY when the incident actually implicates them
    (e.g. ransomware → availability; exfiltration → confidentiality; affected users
    → privacy) — never claimed for an incident that doesn't touch them.

    This is NOT a formal SOC 2 attestation; it's analyst-facing evidence mapping.

DETERMINISM
    Pure: stdlib only, no LLM, no network, no DB. Reads only the dicts passed in.
    Never raises (callers wrap it too). Kill switch: NW_DISABLE_COMPLIANCE_EVIDENCE.

PUBLIC API
    build_compliance_evidence(incident, triage_result=None,
                              investigation_result=None, ti_result=None) -> dict
    format_compliance_evidence(evidence, compact=False) -> str
"""
from __future__ import annotations

import os
from typing import Any


def _disabled() -> bool:
    """[FYP-FUNCTION] Kill-switch check for NW_DISABLE_COMPLIANCE_EVIDENCE."""
    return bool(os.environ.get("NW_DISABLE_COMPLIANCE_EVIDENCE"))


# [FYP-SECTION] small safe accessors ──────────────────────────────────────────

def _s(v: Any) -> str:
    """[FYP-FUNCTION] Safe str-and-strip; None/falsy -> ''."""
    return str(v or "").strip()


def _first(*vals: Any, default: str = "") -> str:
    """[FYP-FUNCTION] First non-empty stringified value among `vals`."""
    for v in vals:
        s = _s(v)
        if s:
            return s
    return default


def _as_list(v: Any) -> list:
    """[FYP-FUNCTION] Normalise a scalar-or-list field into a list (empty
    values -> [])."""
    if v in (None, "", [], {}):
        return []
    return v if isinstance(v, list) else [v]


def _triage_bits(triage_result: dict | None) -> dict:
    """[FYP-FUNCTION] Pull classification/MITRE tactic-technique/category/unc
    out of a triage_result dict (ticket + metakeys_payload), defaulting to
    empty strings when absent."""
    t = triage_result or {}
    mk = t.get("metakeys_payload") or {}
    tk = t.get("ticket") or {}
    return {
        "classification": _first(tk.get("classification"), mk.get("classification"),
                                 mk.get("risk_level")),
        "mitre_tactic": _first(mk.get("mitre_tactic"), tk.get("mitre_tactic")),
        "mitre_technique": _first(mk.get("mitre_technique"), tk.get("mitre_technique")),
        "category": _first(tk.get("incident_category")),
        "unc": _first(tk.get("unc")),
    }


def _detection_summary(incident: dict) -> str:
    """[FYP-FUNCTION] One-line description of how the incident was detected
    (alert titles, attached alerts, or the incident title), for CC7.2
    evidence text. Empty string when nothing usable is present."""
    meta = incident.get("alertMeta") or {}
    titles = _as_list(meta.get("AlertTitles"))
    if titles:
        return f"{len(titles)} behavioural alert(s) (e.g. \"{_s(titles[0])[:60]}\")"
    if incident.get("alerts"):
        return f"{len(_as_list(incident.get('alerts')))} attached alert(s)"
    if _s(incident.get("title")):
        return f"detection signal \"{_s(incident.get('title'))[:60]}\""
    return ""


# [FYP-SECTION] control catalog + evaluators ──────────────────────────────────
# Each evaluator returns (status, evidence). status ∈ MET | PARTIAL | NOT_MET.

_STATUS_ORDER = {"MET": 2, "PARTIAL": 1, "NOT_MET": 0}


def _ctrl(cid, tsc, family, name, status, evidence) -> dict:
    """[FYP-FUNCTION] Build one control-result dict (id/TSC/family/name/
    status/evidence) — the row shape used throughout this module."""
    return {"id": cid, "tsc": tsc, "family": family, "name": name,
            "status": status, "evidence": evidence}


def build_compliance_evidence(incident: dict,
                              triage_result: dict | None = None,
                              investigation_result: dict | None = None,
                              ti_result: dict | None = None) -> dict:
    """[FYP-FUNCTION] [FYP-PROCESS] Map this incident's response onto SOC 2
    controls — module entry point. Returns
    {"available": bool, "controls": [...], "stats": {...}, ...}; never raises."""
    if _disabled():
        return {"available": False, "reason": "disabled via NW_DISABLE_COMPLIANCE_EVIDENCE"}
    try:
        return _build(incident or {}, triage_result, investigation_result, ti_result)
    except Exception as exc:  # deterministic, but never take the report down
        return {"available": False, "reason": f"error: {type(exc).__name__}"}


# [FYP-FUNCTION] `_build` — implements the build operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `incident`, `triage_result`, `investigation_result`, `ti_result`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include compliance_evidence.py:build_compliance_evidence, final_verdict.py:build_final_verdict; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_as_list`, `_ctrl`, `_detection_summary`, `_first`, `_rec_text`, `_s`, `_triage_bits`, `any`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _build(incident: dict, triage_result, investigation_result, ti_result) -> dict:
    tri = _triage_bits(triage_result)
    inv = investigation_result or {}

    incident_id = _first(incident.get("id"), incident.get("incident_id"),
                         tri["unc"], default="the incident")
    severity = _first(tri["classification"], incident.get("severity"), default="Unknown")

    detection = _detection_summary(incident)
    triaged = bool(tri["classification"] or tri["category"] or tri["mitre_tactic"])
    inv_summary = _first(inv.get("investigation_summary"), inv.get("summary"))
    inv_iocs = _as_list(inv.get("iocs"))
    inv_actions = _as_list(inv.get("recommended_actions"))
    investigated = bool(inv_summary or inv_iocs or inv_actions
                        or _s(inv.get("status")).lower() == "completed")
    affected_users = _as_list(inv.get("affected_users"))

    controls: list[dict] = []

    # ── CC7 — System Operations (the core incident-response lifecycle) ─────────
    # CC7.2 — detect anomalies / malicious acts
    if detection:
        controls.append(_ctrl(
            "CC7.2", "Security", "System Operations",
            "Detection of anomalies indicative of malicious acts",
            "MET", f"Incident {incident_id} detected via NetWitness — {detection}."))
    else:
        controls.append(_ctrl(
            "CC7.2", "Security", "System Operations",
            "Detection of anomalies indicative of malicious acts",
            "PARTIAL", f"Incident {incident_id} recorded, but no detection detail captured."))

    # CC7.3 — evaluate security events (triage)
    if triaged:
        ttp = " / ".join([x for x in (tri["mitre_tactic"], tri["mitre_technique"]) if x]) or "no MITRE mapping"
        controls.append(_ctrl(
            "CC7.3", "Security", "System Operations",
            "Evaluation of security events (triage & severity)",
            "MET", f"Triaged at severity **{severity}**"
                   + (f", category \"{tri['category']}\"" if tri["category"] else "")
                   + f"; MITRE ATT&CK: {ttp}."))
    else:
        controls.append(_ctrl(
            "CC7.3", "Security", "System Operations",
            "Evaluation of security events (triage & severity)",
            "NOT_MET", "No triage classification recorded for this incident."))

    # CC7.4 — respond to identified incidents (investigation + response actions)
    if investigated and inv_actions:
        controls.append(_ctrl(
            "CC7.4", "Security", "System Operations",
            "Response to identified security incidents",
            "MET", f"Investigation completed with {len(inv_iocs)} IOC(s) and "
                   f"{len(inv_actions)} documented response action(s)."))
    elif investigated:
        controls.append(_ctrl(
            "CC7.4", "Security", "System Operations",
            "Response to identified security incidents",
            "PARTIAL", "Investigation completed, but no response actions were documented."))
    else:
        controls.append(_ctrl(
            "CC7.4", "Security", "System Operations",
            "Response to identified security incidents",
            "NOT_MET", "No investigation record for this incident."))

    # CC7.5 — recover from identified incidents (remediation/recovery steps)
    rec_kw = ("remediat", "recover", "restore", "contain", "isolat", "reset",
              "re-image", "reimage", "patch", "block", "quarantine", "eradicat")
    rec_hit = any(any(k in _rec_text(a) for k in rec_kw) for a in inv_actions)
    if rec_hit:
        controls.append(_ctrl(
            "CC7.5", "Security", "System Operations",
            "Recovery from identified security incidents",
            "MET", "Response actions include containment / remediation / recovery steps."))
    elif inv_actions:
        controls.append(_ctrl(
            "CC7.5", "Security", "System Operations",
            "Recovery from identified security incidents",
            "PARTIAL", "Actions documented, but none explicitly cover recovery/remediation."))
    else:
        controls.append(_ctrl(
            "CC7.5", "Security", "System Operations",
            "Recovery from identified security incidents",
            "NOT_MET", "No recovery/remediation actions documented."))

    # ── CC2 — Communication (the report itself) ───────────────────────────────
    controls.append(_ctrl(
        "CC2.2", "Security", "Communication & Information",
        "Internal communication of security information",
        "MET", "A structured incident report was generated for this incident "
               "(this document) and retained for reviewers."))

    # ── CC4 — Monitoring activities (audit trail) ─────────────────────────────
    has_trail = bool(_s(incident.get("created")) or _s(incident.get("id")) or tri["unc"])
    controls.append(_ctrl(
        "CC4.1", "Security", "Monitoring Activities",
        "Ongoing evaluation with a retained audit trail",
        "MET" if has_trail else "PARTIAL",
        "Incident tracked with identifiers/timestamps through triage → investigation "
        "→ reporting; pipeline audit trail retained in the SOC datastore."))

    # ── Conditional TSC beyond Security — only when the incident implicates them ─
    hay = " ".join([
        _s(incident.get("title")), tri["category"], tri["mitre_tactic"],
        tri["mitre_technique"], inv_summary,
    ]).lower()

    avail_kw = ("ransom", "denial of service", "ddos", "dos", "impact", "outage",
                "encrypt", "wiper", "destruction", "availability")
    if any(k in hay for k in avail_kw):
        controls.append(_ctrl(
            "A1.2", "Availability", "Availability",
            "Recovery of availability-impacting incidents",
            "MET", "Availability-impacting incident (e.g. ransomware / disruption) "
                   "detected and handled through the response pipeline."))

    conf_kw = ("exfiltrat", "exfil", "data theft", "data leak", "leak", "collection",
               "confidential", "exposure", "breach", "staging")
    if any(k in hay for k in conf_kw):
        controls.append(_ctrl(
            "C1.1", "Confidentiality", "Confidentiality",
            "Protection of confidential information during an incident",
            "MET", "Confidentiality-impacting activity (e.g. exfiltration/exposure) "
                   "identified and addressed in the investigation."))

    privacy_kw = ("pii", "personal data", "gdpr", "privacy", "personal information")
    if affected_users or any(k in hay for k in privacy_kw):
        who = f"{len(affected_users)} affected user identit(y/ies)" if affected_users else "personal-data exposure"
        controls.append(_ctrl(
            "P4.2", "Privacy", "Privacy",
            "Handling of incidents involving personal information",
            "MET", f"Incident involves {who}; handled under the incident-response "
                   "program with user scope documented."))

    # ── stats + rollup ────────────────────────────────────────────────────────
    total = len(controls)
    met = sum(1 for c in controls if c["status"] == "MET")
    partial = sum(1 for c in controls if c["status"] == "PARTIAL")
    not_met = sum(1 for c in controls if c["status"] == "NOT_MET")
    criteria = []
    for c in controls:
        if c["tsc"] not in criteria:
            criteria.append(c["tsc"])

    return {
        "available": total > 0,
        "framework": "SOC 2 (AICPA Trust Services Criteria)",
        "disclaimer": "Analyst-facing evidence mapping — not a formal SOC 2 attestation.",
        "incident_id": incident_id,
        "controls": controls,
        "criteria_touched": criteria,
        "stats": {
            "total": total, "met": met, "partial": partial, "not_met": not_met,
            "coverage_pct": round(100 * met / total) if total else 0,
        },
        "meta": {"severity": severity, "scenario": _first(tri["category"], "Security incident")},
    }


# [FYP-FUNCTION] `_rec_text` — implements the rec text operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `action`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include compliance_evidence.py:_build; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_s`, `get`, `isinstance`, `join`, `lower`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _rec_text(action: Any) -> str:
    if isinstance(action, dict):
        return " ".join(_s(action.get(k)) for k in
                        ("recommendation", "action", "rationale", "risk_addressed")).lower()
    return _s(action).lower()


# ── rendering (markdown for the report appendix) ──────────────────────────────

_ICON = {"MET": "", "PARTIAL": "", "NOT_MET": ""}


# [FYP-FUNCTION] `format_compliance_evidence` — constructs format compliance evidence output for the next SOC analysis support consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `evidence`, `compact`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include compliance_evidence.py:<module>, skills_sidecar.py:_build_narrative; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_s`, `append`, `get`, `join`, `replace`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def format_compliance_evidence(evidence: dict | None, compact: bool = False) -> str:
    """Markdown block for the written report. `compact` trims the intro."""
    if not evidence or not evidence.get("available"):
        return ""
    st = evidence.get("stats") or {}
    crit = ", ".join(evidence.get("criteria_touched") or []) or "Security"
    lines = ["## Compliance Evidence — SOC 2 (Trust Services Criteria)"]
    if not compact:
        lines.append(
            "_Deterministic mapping of this incident's response to SOC 2 controls, "
            "auto-generated (read-only) as audit evidence. "
            + _s(evidence.get("disclaimer")) + "_")
    lines.append(
        f"**Coverage:** {st.get('met', 0)}/{st.get('total', 0)} controls MET "
        f"({st.get('coverage_pct', 0)}%)"
        + (f" · {st.get('partial')} partial" if st.get("partial") else "")
        + (f" · {st.get('not_met')} not met" if st.get("not_met") else "")
        + f" · criteria: {crit}")
    lines.append("")
    lines.append("| Control | Criterion | Status | Evidence |")
    lines.append("|---|---|---|---|")
    for c in evidence.get("controls") or []:
        icon = _ICON.get(c["status"], "")
        ev = _s(c["evidence"]).replace("|", "\\|")
        lines.append(f"| **{c['id']}** {c['name']} | {c['tsc']} | "
                     f"{icon} {c['status']} | {ev} |")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover — manual smoke test
    import json
    demo = {
        "id": "INC-53018", "title": "Malicious HTA + Potential C2 for KELLYWANG",
        "severity": "High", "created": "2025-11-18T03:18:37+00:00",
        "alertMeta": {"AlertTitles": ["Malicious HTA file detected",
                                      "Potential C2 Connection"]},
    }
    tri = {"metakeys_payload": {"classification": "high", "mitre_tactic": "Execution",
                                "mitre_technique": "T1059"},
           "ticket": {"classification": "High", "incident_category": "Compromised asset",
                      "unc": "#EVAL"}}
    inv = {"status": "completed",
           "iocs": [{"value": "192.168.10.204"}],
           "recommended_actions": [{"recommendation": "Isolate KELLYWANG and reset credentials"}],
           "affected_users": [{"username": "Kelly Wang"}],
           "investigation_summary": "Endpoint executed a malicious HTA reaching a C2 host."}
    ev = build_compliance_evidence(demo, tri, inv)
    print(json.dumps(ev["stats"], indent=2))
    print(f"criteria: {ev['criteria_touched']}")
    print()
    print(format_compliance_evidence(ev))
