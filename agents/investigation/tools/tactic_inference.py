# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, os, typing.
# =============================================================================
# File: tactic_inference.py
# Purpose: This module infers MITRE ATT&CK tactics from incident evidence using deterministic mappings.
# Main functionality: _as_str_list, _has_native_mitre, _keyword_scan, infer_tactics, augment_incident.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis SOC analysis support component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: __future__, os, typing.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: _as_str_list, _has_native_mitre, _keyword_scan, infer_tactics, augment_incident, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

"""
tactic_inference.py — deterministic pre-triage MITRE tactic/technique inference.

WHY
    Stored incidents carry empty `tactics`/`techniques` (0 of 1000 sampled), so
    the MITRE-gated skill panels (mitigation coverage, osquery pack, Velociraptor
    plan, threat hunting, detection rules, Diamond phase) stay dark until a
    triage run supplies a tactic. But the incident's own evidence often names the
    behaviour already: distilled `alertMeta.AlertTactics`/`AlertTechniques`
    (real NetWitness data), behavioural `alertMeta.AlertTitles` ("Malicious HTA
    file detected", "Potential C2 Connection"), or — rarely — a descriptive
    incident title ("Lateral Movement via SSH"). This module turns that evidence
    into a tactic/technique deterministically so the panels light up pre-triage.

HONESTY
    * Inference NEVER overrides real data: if the incident already carries
      tactics/techniques/mitre_tactic, nothing is inferred or changed.
    * Precedence = data quality: AlertTactics/AlertTechniques (high confidence,
      NetWitness-supplied) → AlertTitles keyword match (medium) → incident
      title/summary keyword match (low).
    * No signal → {"available": False}; panels stay dark rather than invent.
    * augment_incident() works on a COPY — the session incident is not mutated —
      and stamps `mitre_inferred` metadata so consumers can see provenance.

Keyword table mirrors diamond_model._TITLE_TO_MITRE (same behaviours must map
to the same techniques everywhere), extended with a few high-precision terms.
Kill switch: NW_DISABLE_TACTIC_INFERENCE=1.
"""
from __future__ import annotations

import os
from typing import Any

# keyword tuple → (technique_id, technique_name, tactic). First hit wins;
# ordered roughly foothold-first so the primary pick is the most actionable.
_KEYWORD_MITRE: list[tuple[tuple[str, ...], str, str, str]] = [
    (("hta", "mshta"), "T1218.005", "Mshta", "Execution"),
    (("autorun", "run key", "startup", "scheduled task"), "T1547", "Boot/Logon Autostart", "Persistence"),
    (("powershell", "script", "macro", "wscript", "cscript"), "T1059", "Command and Scripting Interpreter", "Execution"),
    (("credential", "mimikatz", "lsass", "dump"), "T1003", "OS Credential Dumping", "Credential Access"),
    (("brute force", "password spray", "brute-force"), "T1110", "Brute Force", "Credential Access"),
    (("lateral", "psexec", "wmi", "rdp", "smb"), "T1021", "Remote Services", "Lateral Movement"),
    ((" ssh", "ssh "), "T1021.004", "Remote Services: SSH", "Lateral Movement"),
    (("c2", "command and control", "command & control", "beacon", "callback"), "T1071", "Application Layer Protocol", "Command and Control"),
    (("dns tunnel", "dns-tunnel"), "T1071.004", "Application Layer Protocol: DNS", "Command and Control"),
    (("exfil", "exfiltration", "data transfer", "upload"), "T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    (("phishing", "spearphish", "malicious attachment", "malicious link"), "T1566", "Phishing", "Initial Access"),
    (("ransom", "encrypt"), "T1486", "Data Encrypted for Impact", "Impact"),
    (("privilege", "uac", "elevation"), "T1548", "Abuse Elevation Control", "Privilege Escalation"),
    (("process injection", "code injection", "injected"), "T1055", "Process Injection", "Defense Evasion"),
]


# =============================================================================
# [FYP-SECTION] SOC ANALYSIS SUPPORT EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `_as_str_list` — implements the as str list operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `value`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tactic_inference.py:_has_native_mitre, tactic_inference.py:augment_incident, tactic_inference.py:infer_tactics; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `get`, `isinstance`, `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _as_str_list(value: Any) -> list[str]:
    if value in (None, "", [], {}):
        return []
    if not isinstance(value, (list, tuple)):
        value = [value]
    out = []
    for v in value:
        if isinstance(v, dict):
            v = v.get("name") or v.get("id") or ""
        s = str(v).strip()
        if s:
            out.append(s)
    return out


# [FYP-FUNCTION] `_has_native_mitre` — evaluates has native mitre conditions so invalid or unsafe SOC analysis support processing is stopped early.
# [FYP-INPUT] Parameters: `incident`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tactic_inference.py:infer_tactics; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_as_str_list`, `bool`, `get`, `str`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _has_native_mitre(incident: dict) -> bool:
    return bool(_as_str_list(incident.get("tactics"))
                or _as_str_list(incident.get("techniques"))
                or str(incident.get("mitre_tactic") or "").strip())


# [FYP-FUNCTION] `_keyword_scan` — implements the keyword scan operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `texts`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include tactic_inference.py:infer_tactics; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `any`, `append`, `join`, `lower`, `next`, `strip`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def _keyword_scan(texts: list[str]) -> tuple[list[tuple[str, str, str]], list[str]]:
    """All keyword-table hits across the texts, table-ordered + deduped.
    Returns ([(tech_id, tech_name, tactic)...], [evidence snippets])."""
    joined = " " + " ".join(t.lower() for t in texts if t) + " "
    hits: list[tuple[str, str, str]] = []
    evidence: list[str] = []
    for needles, tid, name, tactic in _KEYWORD_MITRE:
        matched = next((n for n in needles if n in joined), None)
        if matched and not any(h[0] == tid for h in hits):
            hits.append((tid, name, tactic))
            evidence.append(f"'{matched.strip()}'")
    return hits, evidence


# [FYP-FUNCTION] `infer_tactics` — implements the infer tactics operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `incident`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include case_view.py:build_mitre, eval_harness.py:_c_tactic, final_verdict.py:_mitre_confirmation; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `_as_str_list`, `_has_native_mitre`, `_keyword_scan`, `fromkeys`, `get`, `list`, `str`, `title`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def infer_tactics(incident: dict) -> dict:
    """Deterministic MITRE inference from the incident's own evidence.
    Never raises. Returns {"available": bool, ...}."""
    if os.environ.get("NW_DISABLE_TACTIC_INFERENCE"):
        return {"available": False, "reason": "disabled via NW_DISABLE_TACTIC_INFERENCE"}
    incident = incident or {}

    if _has_native_mitre(incident):
        return {"available": False,
                "reason": "incident already carries MITRE data (nothing to infer)"}

    am = incident.get("alertMeta") or {}

    # 1) NetWitness-supplied alert tactics/techniques (distilled by the alerts
    #    fetch) — real structured data, just stored at alert level.
    nw_tactics = _as_str_list(am.get("AlertTactics"))
    nw_techs = _as_str_list(am.get("AlertTechniques"))
    if nw_tactics or nw_techs:
        tactic = nw_tactics[0].title() if nw_tactics else ""
        return {
            "available": True, "confidence": "high",
            "source": "alertMeta.AlertTactics/AlertTechniques (NetWitness alert data)",
            "tactic": tactic, "technique": (nw_techs or [""])[0],
            "technique_name": "",
            "tactics": [t.title() for t in nw_tactics],
            "techniques": nw_techs,
            "evidence": nw_tactics + nw_techs,
        }

    # 2) Behavioural alert titles (distilled) — keyword-mapped, same table as
    #    the Diamond Model so both agree on the technique.
    titles = _as_str_list(am.get("AlertTitles"))
    if titles:
        hits, ev = _keyword_scan(titles)
        if hits:
            tid, name, tactic = hits[0]
            return {
                "available": True, "confidence": "medium",
                "source": "alert titles (behavioural keywords)",
                "tactic": tactic, "technique": tid, "technique_name": name,
                "tactics": list(dict.fromkeys(h[2] for h in hits)),
                "techniques": [h[0] for h in hits],
                "evidence": ev,
            }

    # 3) Incident title + summary keywords — rare on this corpus (generic
    #    "High Risk Alerts: …" titles) but real when it fires.
    hits, ev = _keyword_scan([str(incident.get("title") or ""),
                              str(incident.get("summary") or "")])
    if hits:
        tid, name, tactic = hits[0]
        return {
            "available": True, "confidence": "low",
            "source": "incident title/summary keywords",
            "tactic": tactic, "technique": tid, "technique_name": name,
            "tactics": list(dict.fromkeys(h[2] for h in hits)),
            "techniques": [h[0] for h in hits],
            "evidence": ev,
        }

    return {"available": False,
            "reason": "no inferable attack signal pre-triage (generic title, "
                      "no distilled alert behaviours — run triage or Refresh Data)"}


# [FYP-FUNCTION] `augment_incident` — implements the augment incident operation used by the surrounding SOC analysis support workflow.
# [FYP-INPUT] Parameters: `incident`, `inference`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis SOC analysis support workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] No direct caller confidently identified; this may be an entry point, callback, or test helper.
# [FYP-CALLS] Calls: `_as_str_list`, `dict`, `get`, `infer_tactics`, `list`, `str`, `strip`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def augment_incident(incident: dict, inference: dict | None = None
                     ) -> tuple[dict, str | None]:
    """Return (incident-or-copy, note). When inference fires, the COPY gains the
    exact fields the skill suite reads — mitre_tactic/mitre_technique (strings:
    mitigation_mapping, threat_hunting, detection_rules) and tactics/techniques
    (lists: osquery, velociraptor, diamond) — filled ONLY where empty, plus a
    `mitre_inferred` provenance stamp. No signal → the ORIGINAL dict, untouched,
    with note=None. Never raises."""
    try:
        inf = inference if inference is not None else infer_tactics(incident)
        if not inf.get("available"):
            return incident, None
        aug = dict(incident or {})
        if not str(aug.get("mitre_tactic") or "").strip():
            aug["mitre_tactic"] = inf["tactic"]
        if not str(aug.get("mitre_technique") or "").strip() and inf.get("technique"):
            aug["mitre_technique"] = inf["technique"]
        if not _as_str_list(aug.get("tactics")):
            aug["tactics"] = list(inf.get("tactics") or ([inf["tactic"]] if inf.get("tactic") else []))
        if not _as_str_list(aug.get("techniques")) and inf.get("techniques"):
            aug["techniques"] = list(inf["techniques"])
        aug["mitre_inferred"] = {"source": inf.get("source"),
                                 "confidence": inf.get("confidence"),
                                 "evidence": inf.get("evidence")}
        tech = f" {inf['technique']}" if inf.get("technique") else ""
        note = (f"MITRE inferred pre-triage: {inf.get('tactic') or '?'}{tech} "
                f"from {inf.get('source')} ({inf.get('confidence')} confidence) — "
                "analyst validation required; triage output overrides this")
        return aug, note
    except Exception:
        return incident, None
