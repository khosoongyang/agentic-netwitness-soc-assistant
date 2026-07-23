"""
asset_criticality.py — incident-response asset-criticality model
(post-triage, pre-investigation).

Adapted from the incident-response skill in Masriyan/Claude-Code-
CyberSecurity-Skill (NIST SP 800-61 / SANS PICERL): severity handling
should reflect WHAT was hit, not just how the alert scored. A MEDIUM-risk
event on a file server is a different incident than the same event on a
workstation — until now this pipeline treated them identically.

Everything here is deterministic code:

  * asset tier classification from name patterns
        critical_infrastructure  — DC*, BACKUP*, FILESERV*, NAS/SAN, DB/SQL,
                                   MAIL/EXCH (domain control, backups, data
                                   stores: blast radius = the whole estate)
        production_server        — WIN-*, SRV*, SERVER*, APP/WEB hosts
        workstation              — DESKTOP-*, LAPTOP-*, PC-*, and personal
                                   user-account-style names (KELLYWANG)
        unclassified             — anything the patterns can't place (honest)
  * criticality-adjusted response urgency — an ANNOTATION next to the
    code-pinned triage classification, never a rewrite of it
  * a PICERL containment checklist scoped to the asset tier (servers get
    "snapshot before isolating", critical infra gets "never power off /
    engage owner", workstations get straightforward isolation)

The formatted block is embedded in the investigation alert (5th marker
block) so the analysis LLM weighs asset value in severity and containment
ordering. Kill-switch: WORKFLOW_ASSET_CRITICALITY=0.
"""

from __future__ import annotations

import re

_TITLE_ENTITY_RE = re.compile(r"\bfor\s+(.+?)\s*$")
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# tier rank: higher = more critical
_TIERS = {
    "critical_infrastructure": 3,
    "production_server": 2,
    "workstation": 1,
    "unclassified": 0,
}

_CRITICAL_RE = re.compile(
    r"^(DC\d*|DOMAIN|BACKUP\w*|BKP|FILESERV\w*|NAS|SAN|SQL\w*|DB\d*|"
    r"EXCH\w*|MAIL\w*|AD\d*)([-_].*)?$", re.I)
_PROD_RE = re.compile(r"^(WIN|SRV|SERVER|APP|WEB|IIS|ESX|HV)[-_]\w+", re.I)
_WORKSTATION_RE = re.compile(r"^(DESKTOP|LAPTOP|PC|WKS)[-_]\w+", re.I)
# personal account style: single token, letters only, not matching the above
_ACCOUNT_RE = re.compile(r"^[A-Za-z]{4,20}$")

# urgency guidance per effective tier (annotation, never a classification)
_URGENCY = {
    3: "IMMEDIATE (15 min) — critical infrastructure in scope",
    2: "URGENT (within 1 hour) — production server in scope",
    1: "STANDARD (per classification response window)",
    0: "STANDARD (per classification response window; asset role unverified)",
}


def classify_asset(name: str) -> dict:
    """{'name', 'tier', 'rank', 'reason'} for one asset/entity name."""
    v = (name or "").strip()
    if not v:
        return {"name": v, "tier": "unclassified", "rank": 0,
                "reason": "empty name"}
    if _IP_RE.match(v) or ":" in v:
        return {"name": v, "tier": "unclassified", "rank": 0,
                "reason": "IP address — host role unknown without inventory"}
    if _CRITICAL_RE.match(v):
        return {"name": v, "tier": "critical_infrastructure", "rank": 3,
                "reason": "name matches domain-control/backup/data-store pattern"}
    if _PROD_RE.match(v):
        return {"name": v, "tier": "production_server", "rank": 2,
                "reason": "name matches server naming pattern"}
    if _WORKSTATION_RE.match(v):
        return {"name": v, "tier": "workstation", "rank": 1,
                "reason": "name matches workstation naming pattern"}
    if _ACCOUNT_RE.match(v):
        return {"name": v, "tier": "workstation", "rank": 1,
                "reason": "personal user-account-style name (workstation-tier handling)"}
    return {"name": v, "tier": "unclassified", "rank": 0,
            "reason": "no naming pattern matched — verify against asset inventory"}


def _containment_checklist(rank: int, asset: str) -> list[str]:
    """PICERL containment/eradication guidance scoped to asset tier."""
    if rank >= 3:
        return [
            f"Containment: do NOT power off {asset} — volatile evidence and "
            "service dependencies; engage the infrastructure owner first",
            "Containment: verify recent backups are intact and OFFLINE before "
            "any remediation (ransomware kill-chain targets backups first)",
            f"Containment: segment {asset} at the network layer rather than "
            "host isolation; preserve service continuity where possible",
            "Eradication: coordinate a maintenance window; full credential "
            "rotation for accounts with access to this system",
            "Recovery: staged restore with integrity verification before "
            "rejoining production",
        ]
    if rank == 2:
        return [
            f"Containment: snapshot {asset} (memory + disk) BEFORE isolating "
            "— order of volatility",
            f"Containment: isolate {asset} via network segmentation; notify "
            "service owners of expected downtime",
            "Eradication: rebuild from known-good image preferred over "
            "in-place cleaning for servers",
            "Recovery: monitor closely for 72h after rejoin",
        ]
    return [
        f"Containment: isolate {asset} from the network (EDR isolation or "
        "port disable) — workstation isolation is low-risk",
        "Containment: preserve memory image if tampering is suspected",
        "Eradication: reimage is cheapest for workstations; reset the "
        "user's credentials and revoke active sessions",
        "Recovery: return to network after clean scan + credential reset",
    ]


def assess_incident(incident: dict, triage_classification: str | None = None) -> dict:
    """Deterministic asset-criticality assessment for one incident.

    Collects candidate assets (title entity + any harvested hostnames the
    incident carries), classifies each, and derives the criticality-adjusted
    urgency. The triage classification is NEVER modified — escalation is an
    annotation for the analyst and the analysis LLM.
    """
    names: list[str] = []
    m = _TITLE_ENTITY_RE.search(str(incident.get("title") or ""))
    if m:
        names.append(m.group(1).strip())
    for field in ("hostname", "computer_name"):
        if incident.get(field):
            names.append(str(incident[field]))
    seen: set[str] = set()
    assets = []
    for n in names:
        if n and n.upper() not in seen:
            seen.add(n.upper())
            assets.append(classify_asset(n))
    if not assets:
        assets = [{"name": "(no named asset in incident)", "tier": "unclassified",
                   "rank": 0, "reason": "incident carries no host/user entity"}]

    top = max(assets, key=lambda a: a["rank"])
    cls = (triage_classification or "").strip().lower()
    escalation = None
    if top["rank"] >= 3 and cls not in ("critical",):
        escalation = (f"ESCALATE: triage classified this {cls or 'unrated'} but "
                      f"{top['name']} is critical infrastructure — handle with "
                      "critical-tier urgency (classification unchanged)")
    elif top["rank"] == 2 and cls in ("low", "medium"):
        escalation = (f"ESCALATE: triage classified this {cls} but {top['name']} "
                      "is a production server — consider one tier higher "
                      "handling (classification unchanged)")

    return {
        "assets": assets,
        "highest_tier": top["tier"],
        "highest_rank": top["rank"],
        "triage_classification": triage_classification,
        "response_urgency": _URGENCY[top["rank"]],
        "escalation": escalation,
        "containment_checklist": _containment_checklist(top["rank"], top["name"]),
    }


def format_assessment(a: dict) -> str:
    """Plain-text block for the investigation alert / LLM prompt."""
    lines = ["ASSET CRITICALITY ASSESSMENT (deterministic, NIST SP 800-61 / "
             "PICERL asset model)"]
    for x in a["assets"]:
        lines.append(f"  {x['name']} — {x['tier'].replace('_', ' ')} "
                     f"({x['reason']})")
    lines.append(f"  response urgency: {a['response_urgency']}")
    if a["escalation"]:
        lines.append(f"  ⚠ {a['escalation']}")
    lines.append("  tier-scoped containment guidance:")
    for step in a["containment_checklist"]:
        lines.append(f"    · {step}")
    return "\n".join(lines)
