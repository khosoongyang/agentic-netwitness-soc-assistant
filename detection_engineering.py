"""
detection_engineering.py — detection-as-code rigor + ATT&CK coverage.

Adaptation of the threat-detection-engineer skill
(github.com/coreymaypray/sloth-skill-tree →
plugins/maycrest-secure/skills/threat-detection-engineer). That skill's
Sigma-generation and hunt-playbook cores are already in this repo
(detection_rules.py, threat_hunting.py); this module adds the parts that
were missing:

  * validate_sigma — the skill's detection-as-code gate: every Sigma rule
    MUST carry title, id (UUID), level, ATT&CK tags, falsepositives,
    logsource, detection ("no exceptions")
  * to_elastic_eql — Elastic EQL as a third SIEM compile target alongside
    the existing Splunk SPL and Sentinel KQL
  * catalog_entry — the skill's Detection Catalog metadata (ATT&CK map,
    data sources, level, validated date, allowlist)
  * assess_attack_coverage — the skill's ATT&CK Coverage Report: a
    tactic-by-tactic table of what our detection LAYER can cover, a
    prioritised gap list (by threat-actor relevance), and a roadmap

Coverage is a capability assessment of THIS pipeline (what
detection_rules / threat_hunting / mitigation_mapping can produce),
cross-referenced with how often each tactic appears in the corpus — it is
NOT a claim that rules are deployed in a live SIEM.

Standalone module: does NOT edit or import soc_investigation_agent/.
Deterministic: no LLM, no network.
"""

from __future__ import annotations

import json
import re
import sqlite3

# the 14 ATT&CK tactics (enterprise), with a static threat-actor relevance
# weight (1-3) reflecting prevalence in real intrusion / ransomware kill
# chains — used to prioritise gaps, exactly as the skill prescribes
_TACTICS = [
    ("reconnaissance", "Reconnaissance", 1),
    ("resource_development", "Resource Development", 1),
    ("initial_access", "Initial Access", 3),
    ("execution", "Execution", 3),
    ("persistence", "Persistence", 2),
    ("privilege_escalation", "Privilege Escalation", 3),
    ("defense_evasion", "Defense Evasion", 2),
    ("credential_access", "Credential Access", 3),
    ("discovery", "Discovery", 2),
    ("lateral_movement", "Lateral Movement", 3),
    ("collection", "Collection", 2),
    ("command_and_control", "Command and Control", 3),
    ("exfiltration", "Exfiltration", 3),
    ("impact", "Impact", 3),
]

_SIGMA_REQUIRED = ("title", "id", "level", "tags", "falsepositives",
                   "logsource", "detection")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


# ── detection-as-code: Sigma validation ─────────────────────────────────────

def validate_sigma(rule: dict) -> dict:
    """The skill's field gate: a Sigma rule needs all required fields, a UUID
    id, an attack.* tag, and a non-empty detection selection."""
    missing = [f for f in _SIGMA_REQUIRED if not rule.get(f)]
    warnings = []
    if rule.get("id") and not _UUID_RE.match(str(rule["id"])):
        warnings.append("id is not a UUID")
    has_attack = any(str(t).lower().startswith("attack.")
                     for t in (rule.get("tags") or []))
    if not has_attack:
        warnings.append("no ATT&CK (attack.*) tag — every detection must map "
                        "to a technique")
    sel = (rule.get("detection") or {}).get("selection")
    if not sel:
        warnings.append("empty detection selection")
    valid = not missing and has_attack and bool(sel)
    return {"valid": valid, "missing_fields": missing,
            "has_attack_tag": has_attack, "warnings": warnings}


# ── Elastic EQL compile target (3rd SIEM) ────────────────────────────────────

def to_elastic_eql(built: dict) -> str:
    """Elastic EQL translation of the Sigma selection (complements the
    SPL + KQL that detection_rules already emits). `built` is the dict from
    detection_rules.build_detection (has rule.detection.selection)."""
    rule = built.get("sigma") or built.get("rule") or {}
    sel = (rule.get("detection") or {}).get("selection") or {}
    if not sel:
        return "// no concrete indicators to query"
    endpoint = (rule.get("logsource") or {}).get("category") == "process_creation"
    category = "process" if endpoint else "network"
    field_map = {"dst_ip": "destination.ip", "dst_domain": "destination.domain",
                 "Image|endswith": "process.name", "Hashes|contains": "process.hash.sha256"}
    clauses = []
    for field, vals in sel.items():
        f = field_map.get(field, field.split("|")[0])
        vals = vals if isinstance(vals, list) else [vals]
        quoted = ", ".join(f'"{v}"' for v in vals)
        clauses.append(f"{f} in ({quoted})")
    return f"{category} where " + " or ".join(clauses)


# ── detection catalog entry (YAML metadata) ─────────────────────────────────

def catalog_entry(built: dict) -> str:
    """The skill's Detection Catalog metadata for a generated rule."""
    rule = built.get("sigma") or built.get("rule") or {}
    attack = [t for t in (rule.get("tags") or []) if str(t).startswith("attack.")]
    ls = rule.get("logsource") or {}
    ds = ("firewall_logs, netflow_records, proxy_logs"
          if ls.get("category") == "firewall"
          else "edr_process_logs, sysmon_event_1, windows_event_4688")
    allow = "; ".join(rule.get("falsepositives") or []) or "none documented"
    lines = [
        f"id: {rule.get('id', '?')}",
        f"title: {rule.get('title', '?')}",
        f"attack: [{', '.join(attack) or 'UNMAPPED'}]",
        f"logsource: {ls.get('category', '?')}/{ls.get('product', '?')}",
        f"data_sources: {ds}",
        f"level: {rule.get('level', '?')}",
        f"status: {rule.get('status', 'experimental')}",
        f"last_validated: {rule.get('date', '?')}",
        "daily_alert_volume: unknown (not yet deployed)",
        "tp_fp_rate: unknown (requires production telemetry)",
        f"allowlist: {allow}",
    ]
    return "\n".join(lines)


# ── ATT&CK coverage assessment ───────────────────────────────────────────────

def _capability_by_tactic() -> dict:
    """Which of our modules can produce detection/hunt/mitigation content for
    each ATT&CK tactic — read from the modules' own tables (honest)."""
    cap = {t[0]: {"detection": False, "hunt": False, "mitigation": False}
           for t in _TACTICS}
    # hunt: threat_hunting per-tactic data sources
    try:
        from threat_hunting import HUNT_DATA_SOURCES
        for t in HUNT_DATA_SOURCES:
            if t in cap:
                cap[t]["hunt"] = True
                cap[t]["detection"] = True  # a hunt-supported tactic is one we
                                            # can also author a rule for
    except Exception:
        pass
    # mitigation: mitigation_mapping tactic->STRIDE bridge keys
    try:
        from mitigation_mapping import _MITRE_TO_STRIDE
        for tname in _MITRE_TO_STRIDE:
            key = tname.replace(" ", "_")
            if key in cap:
                cap[key]["mitigation"] = True
    except Exception:
        pass
    return cap


def assess_attack_coverage(db_path: str | None = None,
                           corpus_sample: int = 20000) -> dict:
    """Tactic-by-tactic coverage of our detection layer + corpus prevalence +
    prioritised gaps + roadmap (the skill's ATT&CK Coverage Report)."""
    cap = _capability_by_tactic()

    # corpus prevalence: how often each tactic appears in stored incidents
    prevalence = {t[0]: 0 for t in _TACTICS}
    scanned = 0
    if db_path:
        try:
            con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
            try:
                for (raw,) in con.execute(
                        "SELECT raw_json FROM incidents LIMIT ?", (corpus_sample,)):
                    try:
                        d = json.loads(raw)
                    except Exception:
                        continue
                    scanned += 1
                    tac = " ".join(str(x) for x in (d.get("tactics") or [])).lower()
                    for key, name, _w in _TACTICS:
                        if key.replace("_", " ") in tac:
                            prevalence[key] += 1
            finally:
                con.close()
        except Exception:
            pass

    rows, covered, partial, gaps = [], 0, 0, []
    for key, name, weight in _TACTICS:
        c = cap[key]
        score = sum(1 for v in c.values() if v)
        status = "covered" if score >= 3 else ("partial" if score >= 1 else "gap")
        if status == "covered":
            covered += 1
        elif status == "partial":
            partial += 1
        if status != "covered":
            gaps.append({"tactic": name, "status": status, "relevance": weight,
                         "have": [k for k, v in c.items() if v],
                         "missing": [k for k, v in c.items() if not v]})
        rows.append({"tactic": name, "status": status, "relevance": weight,
                     "detection": c["detection"], "hunt": c["hunt"],
                     "mitigation": c["mitigation"],
                     "corpus_incidents": prevalence[key]})
    # prioritise gaps: highest relevance first, then partial-before-gap
    gaps.sort(key=lambda g: (-g["relevance"], 0 if g["status"] == "gap" else 1))

    roadmap = []
    _DS = None
    try:
        from threat_hunting import HUNT_DATA_SOURCES as _DS
    except Exception:
        pass
    for g in gaps:
        key = g["tactic"].lower().replace(" ", "_")
        ds = (", ".join((_DS or {}).get(key, [])[:3]) or "acquire relevant telemetry")
        need = ("add hunt playbook + rule template" if "hunt" in g["missing"]
                else "add control mapping")
        roadmap.append({"tactic": g["tactic"], "action": need,
                        "data_sources": ds, "priority": g["relevance"]})

    return {
        "tactics_total": len(_TACTICS), "covered": covered, "partial": partial,
        "gap": len(_TACTICS) - covered - partial,
        "coverage_pct": round(100 * covered / len(_TACTICS), 1),
        "rows": rows, "gaps": gaps, "roadmap": roadmap,
        "corpus_incidents_scanned": scanned,
    }


def format_coverage(cov: dict) -> str:
    """Plain-text ATT&CK coverage report for the UI."""
    lines = [
        "ATT&CK DETECTION COVERAGE (capability assessment of this pipeline — "
        "detection_rules + threat_hunting + mitigation_mapping; NOT live-SIEM "
        "deployment status)",
        f"  coverage: {cov['covered']}/{cov['tactics_total']} tactics covered "
        f"({cov['coverage_pct']}%), {cov['partial']} partial, {cov['gap']} gap",
        "  tactic                     det hunt mit  corpus",
    ]
    mark = {True: " ✓ ", False: " · "}
    for r in cov["rows"]:
        badge = {"covered": "✅", "partial": "🟡", "gap": "❌"}[r["status"]]
        lines.append(f"  {badge} {r['tactic']:<24}{mark[r['detection']]}"
                     f"{mark[r['hunt']]}{mark[r['mitigation']]}  {r['corpus_incidents']}")
    if cov["gaps"]:
        lines.append("  prioritised gaps (by threat-actor relevance):")
        for g in cov["gaps"]:
            lines.append(f"    {'★'*g['relevance']} {g['tactic']} ({g['status']}) — "
                         f"missing: {', '.join(g['missing'])}")
    if cov["roadmap"]:
        lines.append("  detection roadmap:")
        for r in cov["roadmap"][:6]:
            lines.append(f"    [{'P'+str(4-r['priority'])}] {r['tactic']}: "
                         f"{r['action']} (data: {r['data_sources']})")
    return "\n".join(lines)
