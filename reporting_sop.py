"""
reporting_sop.py — deterministic Incident-Response SOP / runbook generator.

Adapts the "SOP Structure & Documentation" skill (mcpmarket) to the SOC reporting
agent: it turns one incident's investigation findings into a STANDARDISED, validated
Standard Operating Procedure — the repeatable step-by-step containment/remediation
runbook an analyst executes — with the canonical SOP anatomy:

    metadata header · purpose · scope · roles & responsibilities · prerequisites ·
    numbered procedure (each step: owner, decision point, verification, on-failure,
    evidence to collect) · references · version history

WHY THIS IS DISTINCT
    The written report describes WHAT HAPPENED. This produces the actionable
    RUNBOOK the analyst follows next. It is also distinct from the SOP files the
    reporting agent READS (soc_reporting_agent/knowledge_base/procedures/*) — those
    are input guidance; this is an incident-specific output.

HOW IT STAYS SAFE
    * Standalone module — NEVER edits soc_reporting_agent/ or soc_investigation_agent/.
    * Deterministic: no LLM, no network. Reuses the other skills' deterministic
      outputs (asset_criticality PICERL checklist, mitigation_mapping roadmap,
      ioc_correlation indicators, MITRE from triage/inference), each guarded.
    * Never raises. Surfaced in the Map panel + folded into the written report via
      the existing skills_sidecar bridge (no agent-contract edits).

KILL SWITCH: NW_DISABLE_REPORTING_SOP=1.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

# ── PICERL phases (NIST/SANS incident-response lifecycle) ────────────────────
_PHASES = ("Identification", "Containment", "Eradication", "Recovery",
           "Lessons Learned")

# scenario → referenced response playbook (mirrors the reporting context builder)
_SCENARIO_PLAYBOOK: list[tuple[tuple[str, ...], str, str]] = [
    (("ransom", "wannacry", "encrypt"), "ransomware_response_playbook.md", "Ransomware"),
    (("phish", "spearphish", "malicious attachment", "malicious link"),
     "phishing_response_playbook.md", "Phishing"),
    (("lateral", "psexec", "rdp", "smb", "remote service"),
     "lateral_movement_playbook.md", "Lateral Movement"),
    (("c2", "command and control", "beacon", "exfil"),
     "c2_exfiltration_playbook.md", "C2 / Exfiltration"),
    (("privilege", "escalation", "uac"),
     "privilege_escalation_playbook.md", "Privilege Escalation"),
]


def _disabled() -> bool:
    return bool(os.environ.get("NW_DISABLE_REPORTING_SOP"))


def _safe(fn, *a, **k) -> Any:
    try:
        return fn(*a, **k)
    except Exception:
        return None


def _s(v: Any) -> str:
    return str(v if v is not None else "").strip()


def _as_list(v: Any) -> list:
    if v in (None, "", [], {}):
        return []
    return v if isinstance(v, list) else [v]


# ── source extraction (all reused from existing deterministic skills) ────────

def _identity(incident: dict) -> dict:
    am = incident.get("alertMeta") or {}
    host = (_as_list(am.get("Hostname")) or [None])[0] or _s(incident.get("hostname")) or None
    user = (_as_list(am.get("User")) or _as_list(am.get("AdUser")) or [None])[0] or None
    return {"host": host, "user": user,
            "src_ips": _as_list(am.get("SourceIp")),
            "dst_ips": _as_list(am.get("DestinationIp"))}


def _classification(incident: dict, triage_result: dict | None) -> str:
    t = triage_result or {}
    return (_s((t.get("ticket") or {}).get("classification"))
            or _s((t.get("metakeys_payload") or {}).get("classification"))
            or _s(incident.get("severity")) or "Unknown").capitalize()


def _mitre(incident: dict, triage_result: dict | None) -> tuple[str, str]:
    t = triage_result or {}
    mk = t.get("metakeys_payload") or {}
    tac = _s(mk.get("mitre_tactic")) or _s((t.get("ticket") or {}).get("mitre_tactic")) \
          or _s(incident.get("mitre_tactic"))
    tech = _s(mk.get("mitre_technique")) or _s((t.get("ticket") or {}).get("mitre_technique")) \
           or _s(incident.get("mitre_technique"))
    if not tac:
        # reuse the pre-triage inference so the SOP references a tactic when the
        # incident's own evidence names one (keeps every skill consistent).
        try:
            from tactic_inference import infer_tactics
            inf = infer_tactics(incident)
            if inf.get("available"):
                tac = tac or _s(inf.get("tactic"))
                tech = tech or _s(inf.get("technique"))
        except Exception:
            pass
    return tac, tech


def _pick_playbook(incident: dict, triage_result: dict | None,
                   investigation_result: dict | None, tactic: str) -> tuple[str, str]:
    hay = " ".join(_s(x).lower() for x in (
        incident.get("title"), incident.get("summary"), tactic,
        (triage_result or {}).get("ticket", {}).get("incident_category"),
        (investigation_result or {}).get("case_type"),
        (investigation_result or {}).get("selected_playbook"),
        " ".join(_as_list((incident.get("alertMeta") or {}).get("AlertTitles"))),
    ))
    for needles, pb, name in _SCENARIO_PLAYBOOK:
        if any(n in hay for n in needles):
            return pb, name
    return "generic_incident_response_playbook.md", "Generic IR"


def _asset(incident: dict, triage_result: dict | None) -> dict | None:
    try:
        from asset_criticality import assess_incident
    except Exception:
        return None
    cls = _classification(incident, triage_result)
    return _safe(assess_incident, incident, cls)


def _mitigation(incident: dict, triage_result: dict | None,
                ti_result: dict | None, asset: dict | None) -> dict | None:
    try:
        from mitigation_mapping import build_mitigation_coverage
    except Exception:
        return None
    m = _safe(build_mitigation_coverage, incident, triage_result, ti_result, asset)
    return m if isinstance(m, dict) and m.get("available") else None


def _iocs(incident: dict, triage_result: dict | None) -> list[dict]:
    try:
        from ioc_correlation import correlate_iocs
    except Exception:
        return []
    c = _safe(correlate_iocs, incident, triage_result)
    if not isinstance(c, dict) or not c.get("available"):
        return []
    # blockable indicators = external infra + notable internal, most-corroborated first
    return [r for r in (c.get("results") or []) if r.get("value")][:6]


# ── step builders ─────────────────────────────────────────────────────────────

def _step(n: int, phase: str, action: str, owner: str, decision: str = "",
          verification: str = "", on_failure: str = "", evidence: str = "") -> dict:
    return {"n": n, "phase": phase, "action": action, "owner": owner,
            "decision": decision, "verification": verification,
            "on_failure": on_failure, "evidence": evidence}


def _build_procedure(ident: dict, cls: str, asset: dict | None,
                     mitigation: dict | None, iocs: list[dict],
                     investigation_result: dict | None,
                     approval_required: bool) -> list[dict]:
    host = ident.get("host") or "the affected host"
    steps: list[dict] = []
    n = 1

    # ── Identification ───────────────────────────────────────────────────────
    steps.append(_step(
        n, "Identification",
        f"Confirm the alert on {host} is a true positive: correlate the triage "
        "IOCs against endpoint and network telemetry.",
        "SOC Tier-1 Analyst",
        decision="If false positive → document rationale, close, STOP here. "
                 "If true/undetermined → continue.",
        verification="Triage classification and at least one corroborating "
                     "telemetry source agree.",
        on_failure="Escalate to Tier-2 for a second review before proceeding.",
        evidence="Alert record, matched metakeys, triage ticket UNC.")); n += 1

    if ident.get("user"):
        steps.append(_step(
            n, "Identification",
            f"Identify and record the account context for {ident['user']} "
            "(logon type, source, privilege level).",
            "SOC Tier-1 Analyst",
            verification="User-to-host mapping captured from AD / auth logs.",
            evidence="Security event 4624/4648, AD lookup.")); n += 1

    # ── Approval gate (asset-criticality / severity driven) ──────────────────
    if approval_required:
        steps.append(_step(
            n, "Containment",
            "OBTAIN CONTAINMENT APPROVAL before any isolating action "
            "(business-impact gate).",
            "SOC Manager / IR Lead",
            decision="Approved → proceed. Denied/pending → hold containment, "
                     "continue monitoring, document.",
            verification="Recorded approver + timestamp.",
            on_failure="Do NOT isolate; escalate and keep the incident open.",
            evidence="Approval record.")); n += 1

    # ── Containment (reuse asset_criticality PICERL checklist, tier-scoped) ──
    checklist = (asset or {}).get("containment_checklist") or []
    for item in checklist:
        phase = "Eradication" if item.lower().startswith("eradication") else \
                ("Recovery" if item.lower().startswith("recovery") else "Containment")
        action = item.split(":", 1)[1].strip() if ":" in item else item
        steps.append(_step(
            n, phase, action,
            "SOC Tier-2/3 Analyst",
            verification="Action completed and logged in the case timeline.",
            on_failure="Note the blocker; escalate to the asset owner.",
            evidence="Command output / EDR action id.")); n += 1

    # ── IOC blocking (from internal correlation) ─────────────────────────────
    if iocs:
        vals = ", ".join(_s(r.get("value")) for r in iocs)
        steps.append(_step(
            n, "Containment",
            f"Block / watchlist the confirmed indicators at the perimeter and "
            f"EDR: {vals}.",
            "SOC Tier-2 Analyst",
            decision="Block external indicators outright; watchlist internal IPs "
                     "(avoid disrupting legitimate hosts).",
            verification="Block rules deployed; hits monitored.",
            on_failure="If an indicator is business-critical infra, watchlist "
                       "instead of block and flag for review.",
            evidence="Firewall/EDR rule ids.")); n += 1

    # ── Mitigation controls (from mitigation_mapping roadmap) ────────────────
    for c in (mitigation or {}).get("roadmap", [])[:4]:
        steps.append(_step(
            n, "Eradication",
            f"Deploy / verify control {_s(c.get('control_id'))} "
            f"{_s(c.get('control'))} ({_s(c.get('type'))}/{_s(c.get('layer'))}).",
            "SOC Engineering",
            verification=f"Control effective against: {_s(c.get('threat'))}.",
            evidence="Control config / change ticket.")); n += 1

    # ── Investigation-supplied recommended actions (fill any gaps) ───────────
    inv = investigation_result or {}
    inv_actions = _as_list(inv.get("recommended_containment")) \
        or _as_list(inv.get("recommended_actions"))
    for a in inv_actions[:6]:
        txt = a.get("recommendation") or a.get("action") if isinstance(a, dict) else _s(a)
        if not _s(txt):
            continue
        steps.append(_step(
            n, "Eradication",
            _s(txt), "SOC Tier-2/3 Analyst",
            verification="Investigation-recommended action completed.",
            evidence="Case note.")); n += 1

    # ── Recovery + Lessons (always) ──────────────────────────────────────────
    steps.append(_step(
        n, "Recovery",
        f"Return {host} to production only after a clean scan, credential reset "
        "for affected accounts, and monitoring is in place.",
        "SOC Tier-2 Analyst",
        decision="Residual indicators present → repeat Eradication. Clean → restore.",
        verification="Post-remediation scan clean; heightened monitoring active.",
        evidence="Scan report, restore ticket.")); n += 1
    steps.append(_step(
        n, "Lessons Learned",
        "Document the timeline, root cause, detection/response gaps, and update "
        "the relevant playbook + detection rules.",
        "SOC Analyst + IR Lead",
        verification="Post-incident review recorded; follow-up actions assigned.",
        evidence="PIR document.")); n += 1

    # Order by PICERL phase (stable within phase), then renumber so the runbook
    # reads as a clean lifecycle even though steps were gathered per-source.
    steps.sort(key=lambda s: _PHASES.index(s["phase"]) if s["phase"] in _PHASES else 99)
    for i, s in enumerate(steps, start=1):
        s["n"] = i
    return steps


def _roles(asset: dict | None, approval_required: bool) -> list[dict]:
    rank = (asset or {}).get("highest_rank", 0)
    roles = [
        {"role": "SOC Tier-1 Analyst",
         "responsibility": "Alert validation, identification, evidence capture."},
        {"role": "SOC Tier-2/3 Analyst",
         "responsibility": "Containment execution, eradication, forensic analysis."},
    ]
    if approval_required:
        roles.append({"role": "SOC Manager / IR Lead",
                      "responsibility": "Containment approval, escalation, PIR ownership."})
    if rank >= 3:
        roles.append({"role": "Infrastructure / Asset Owner",
                      "responsibility": "Critical-asset coordination; approves "
                                        "network segmentation and maintenance windows."})
    return roles


# ── public API ───────────────────────────────────────────────────────────────

def build_incident_sop(incident: dict, triage_result: dict | None = None,
                       investigation_result: dict | None = None,
                       ti_result: dict | None = None) -> dict:
    """Build a standardised incident-response SOP for one incident. Deterministic,
    never raises. Returns {"available": bool, ...}."""
    if _disabled():
        return {"available": False, "reason": "disabled via NW_DISABLE_REPORTING_SOP"}
    incident = incident or {}

    inc_id = _s(incident.get("id") or incident.get("incidentId")) or "UNKNOWN"
    title = _s(incident.get("title") or incident.get("name")) or "SOC incident"
    ident = _identity(incident)
    cls = _classification(incident, triage_result)
    tactic, technique = _mitre(incident, triage_result)
    asset = _asset(incident, triage_result)
    mitigation = _mitigation(incident, triage_result, ti_result, asset)
    iocs = _iocs(incident, triage_result)
    playbook, scenario = _pick_playbook(incident, triage_result,
                                        investigation_result, tactic)

    rank = (asset or {}).get("highest_rank", 0)
    approval_required = cls in ("High", "Critical") or rank >= 2

    procedure = _build_procedure(ident, cls, asset, mitigation, iocs,
                                 investigation_result, approval_required)

    scope_host = ident.get("host") or "the affected asset"
    meta = {
        "sop_id": f"SOP-IR-{inc_id}",
        "incident_id": inc_id,
        "title": f"Incident Response SOP — {title}",
        "version": "1.0",
        "classification": cls,
        "owner": "Security Operations Centre",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scenario": scenario,
    }
    sop = {
        "available": True,
        "meta": meta,
        "purpose": (f"Provide a repeatable, auditable procedure to contain, "
                    f"eradicate and recover from incident {inc_id} "
                    f"({cls} severity, {scenario} scenario)."),
        "scope": (f"Applies to {scope_host}"
                  + (f" and account {ident['user']}" if ident.get("user") else "")
                  + f". Covers the {cls.lower()} incident lifecycle from validated "
                  "detection through post-incident review."),
        "roles": _roles(asset, approval_required),
        "prerequisites": [
            "Access to the NetWitness console, EDR, and SIEM for the affected host.",
            "Authority to isolate/segment endpoints (or an approver on call).",
            f"The referenced playbook ({playbook}) and current asset inventory.",
        ],
        "procedure": procedure,
        "references": {
            "mitre": (f"{tactic} — {technique}".strip(" —") or "not mapped"),
            "playbook": playbook,
            "policies": ["incident_severity_policy.md", "report_writing_sop.md"],
            "approval_gate": ("Containment approval required "
                              f"({'critical/high severity or ' if cls in ('High','Critical') else ''}"
                              "asset criticality)") if approval_required
                             else "No approval gate (low-impact incident)",
        },
        "version_history": [
            {"version": "1.0", "date": meta["generated_at"][:10],
             "author": "SOC skill suite (auto-generated)",
             "change": "Initial SOP generated from investigation findings."},
        ],
        "stats": {"steps": len(procedure), "approval_required": approval_required,
                  "controls_referenced": len((mitigation or {}).get("roadmap", [])),
                  "indicators_blocked": len(iocs)},
    }
    sop["validation"] = validate_sop(sop)
    return sop


_REQUIRED_SECTIONS = ("purpose", "scope", "roles", "prerequisites",
                      "procedure", "references", "version_history")


def validate_sop(sop: dict) -> dict:
    """The skill's validation half: RFC-2119-style completeness check. MUST =
    required section/field absent; SHOULD = recommended detail missing."""
    must: list[str] = []
    should: list[str] = []
    for sec in _REQUIRED_SECTIONS:
        if not sop.get(sec):
            must.append(f"MUST: missing required section '{sec}'")
    if not (sop.get("meta") or {}).get("sop_id"):
        must.append("MUST: SOP metadata missing sop_id")
    for st in sop.get("procedure") or []:
        tag = f"step {st.get('n')}"
        if not _s(st.get("action")):
            must.append(f"MUST: {tag} has no action")
        if not _s(st.get("owner")):
            must.append(f"MUST: {tag} has no owner")
        if not _s(st.get("verification")):
            should.append(f"SHOULD: {tag} has no verification step")
    phases = {st.get("phase") for st in sop.get("procedure") or []}
    for want in ("Identification", "Containment", "Recovery"):
        if want not in phases:
            should.append(f"SHOULD: no '{want}' phase step present")
    return {"valid": not must, "must_fix": must, "should_fix": should,
            "checks": len(_REQUIRED_SECTIONS) + 1 + len(sop.get("procedure") or [])}


def format_sop(sop: dict, compact: bool = False) -> str:
    """Render the SOP as a markdown document. compact=True trims the per-step
    detail lines (used for the report-embedded appendix)."""
    if not sop.get("available"):
        return "INCIDENT RESPONSE SOP unavailable: " + sop.get("reason", "unknown")
    m = sop["meta"]
    L = [f"# {m['title']}",
         f"**SOP ID:** {m['sop_id']}  ·  **Incident:** {m['incident_id']}  ·  "
         f"**Version:** {m['version']}  ·  **Severity:** {m['classification']}  ·  "
         f"**Scenario:** {m['scenario']}",
         f"**Owner:** {m['owner']}  ·  **Generated:** {m['generated_at']}",
         "",
         "## Purpose", sop["purpose"], "",
         "## Scope", sop["scope"], "",
         "## Roles & Responsibilities"]
    for r in sop["roles"]:
        L.append(f"- **{r['role']}** — {r['responsibility']}")
    L += ["", "## Prerequisites"]
    L += [f"- {p}" for p in sop["prerequisites"]]
    L += ["", "## Procedure"]
    for st in sop["procedure"]:
        L.append(f"{st['n']}. **[{st['phase']}]** {st['action']}  _(Owner: {st['owner']})_")
        if not compact:
            if st.get("decision"):
                L.append(f"    - Decision: {st['decision']}")
            if st.get("verification"):
                L.append(f"    - Verify: {st['verification']}")
            if st.get("on_failure"):
                L.append(f"    - On failure: {st['on_failure']}")
            if st.get("evidence"):
                L.append(f"    - Evidence: {st['evidence']}")
    ref = sop["references"]
    L += ["", "## References",
          f"- MITRE ATT&CK: {ref['mitre']}",
          f"- Playbook: {ref['playbook']}",
          f"- Approval gate: {ref['approval_gate']}",
          f"- Policies: {', '.join(ref['policies'])}",
          "", "## Version History"]
    for v in sop["version_history"]:
        L.append(f"- v{v['version']} ({v['date']}) — {v['change']} [{v['author']}]")
    val = sop.get("validation") or {}
    status = "PASS" if val.get("valid") else "REVIEW REQUIRED"
    L += ["", f"_SOP validation: {status} "
          f"({val.get('checks', 0)} checks; {len(val.get('should_fix', []))} advisory)_"]
    if val.get("must_fix"):
        L += ["  - " + x for x in val["must_fix"]]
    return "\n".join(L)


if __name__ == "__main__":  # pragma: no cover — quick smoke test
    demo = {
        "id": "INC-53018", "title": "High Risk Alerts for KELLYWANG",
        "severity": "High", "status": "New",
        "alertMeta": {"Hostname": ["KELLYWANG"], "User": ["Kelly Wang"],
                      "SourceIp": ["192.168.10.204"], "DestinationIp": ["192.168.10.202"],
                      "AlertTitles": ["Malicious HTA file detected", "Potential C2 Connection"]},
    }
    tri = {"ticket": {"classification": "High", "mitre_tactic": "Execution",
                      "mitre_technique": "T1218.005"},
           "metakeys_payload": {"mitre_tactic": "Execution", "classification": "high"}}
    s = build_incident_sop(demo, triage_result=tri)
    print(format_sop(s))
    print("\n--- validation ---", s["validation"]["valid"], s["validation"]["should_fix"][:2])
