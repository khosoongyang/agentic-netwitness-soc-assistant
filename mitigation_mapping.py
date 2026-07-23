"""
mitigation_mapping.py — threat → security-control coverage mapping.

Faithful adaptation of the threat-mitigation-mapping skill
(github.com/ruslands/plugins → review2/security-scanning/skills/
threat-mitigation-mapping). Ports the skill's SecurityControl /
MitigationMapping / ControlLibrary / MitigationAnalyzer model verbatim
(coverage_score = effectiveness × status_multiplier; coverage %,
defense-in-depth, control-diversity, gap analysis, phased roadmap) and
bridges it into this pipeline:

  * the skill keys controls by STRIDE; our incidents carry MITRE ATT&CK
    tactics — a MITRE-tactic → STRIDE map bridges the two
  * the skill's library is app/web-centric; we extend it with the
    endpoint/network controls a NetWitness estate needs (EDR, patch
    management, network segmentation, host firewall, app allow-listing)

For each incident we derive its threats from the observed MITRE
technique(s) + threat-intel verdicts, map them to controls, and produce
coverage %, gaps, and a remediation roadmap.

HONESTY: we cannot know the org's real control posture, so controls are
emitted as RECOMMENDATIONS with status "unknown" (treated as
not-implemented for scoring). Coverage is therefore "achievable coverage
if these controls are deployed", clearly labelled — never a claim that a
control is already in place.

Deterministic: no LLM, no network.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum


class ControlType(Enum):
    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"


class ControlLayer(Enum):
    NETWORK = "network"
    APPLICATION = "application"
    DATA = "data"
    ENDPOINT = "endpoint"
    PROCESS = "process"
    PHYSICAL = "physical"


class ImplementationStatus(Enum):
    NOT_IMPLEMENTED = "not_implemented"
    PARTIAL = "partial"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"


class Effectiveness(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERY_HIGH = 4


# ── skill model (ported verbatim; formulas unchanged) ────────────────────────

@dataclass
class SecurityControl:
    id: str
    name: str
    description: str
    control_type: ControlType
    layer: ControlLayer
    effectiveness: Effectiveness
    implementation_cost: str
    maintenance_cost: str
    status: ImplementationStatus = ImplementationStatus.NOT_IMPLEMENTED
    mitigates_threats: list = field(default_factory=list)
    technologies: list = field(default_factory=list)
    compliance_refs: list = field(default_factory=list)

    def coverage_score(self) -> float:
        status_multiplier = {
            ImplementationStatus.NOT_IMPLEMENTED: 0.0,
            ImplementationStatus.PARTIAL: 0.5,
            ImplementationStatus.IMPLEMENTED: 0.8,
            ImplementationStatus.VERIFIED: 1.0,
        }
        return self.effectiveness.value * status_multiplier[self.status]


@dataclass
class Threat:
    id: str
    name: str
    category: str          # STRIDE category
    description: str
    impact: str            # Critical/High/Medium/Low
    likelihood: str
    risk_score: float


@dataclass
class MitigationMapping:
    threat: Threat
    controls: list
    residual_risk: str = "Unknown"
    notes: str = ""

    def calculate_coverage(self) -> float:
        if not self.controls:
            return 0.0
        total = sum(c.coverage_score() for c in self.controls)
        # "achievable coverage" variant: score controls at their effectiveness
        # (status unknown), so the % reflects how well the RECOMMENDED controls
        # would cover the threat if deployed and verified
        achievable = sum(c.effectiveness.value for c in self.controls)
        max_possible = len(self.controls) * Effectiveness.VERY_HIGH.value
        # use achievable (recommendation framing) — honest label in output
        return (achievable / max_possible) * 100 if max_possible else 0.0

    def has_defense_in_depth(self) -> bool:
        layers = {c.layer for c in self.controls}
        return len(layers) >= 2

    def has_control_diversity(self) -> bool:
        types = {c.control_type for c in self.controls}
        return len(types) >= 2


# ── MITRE tactic → STRIDE bridge ─────────────────────────────────────────────

_MITRE_TO_STRIDE = {
    "reconnaissance": ["INFORMATION_DISCLOSURE"],
    "resource development": ["SPOOFING"],
    "initial access": ["SPOOFING", "TAMPERING"],
    "execution": ["TAMPERING", "INJECTION"],
    "persistence": ["ELEVATION_OF_PRIVILEGE", "TAMPERING"],
    "privilege escalation": ["ELEVATION_OF_PRIVILEGE"],
    "defense evasion": ["REPUDIATION", "TAMPERING"],
    "credential access": ["SPOOFING"],
    "discovery": ["INFORMATION_DISCLOSURE"],
    "lateral movement": ["ELEVATION_OF_PRIVILEGE", "TAMPERING"],
    "collection": ["INFORMATION_DISCLOSURE"],
    "command and control": ["TAMPERING", "INFORMATION_DISCLOSURE"],
    "exfiltration": ["INFORMATION_DISCLOSURE"],
    "impact": ["DENIAL_OF_SERVICE", "TAMPERING"],
}

_STRIDE_NAMES = {
    "SPOOFING": "Spoofing / credential abuse",
    "TAMPERING": "Tampering / unauthorized change",
    "REPUDIATION": "Repudiation / audit evasion",
    "INFORMATION_DISCLOSURE": "Information disclosure / data theft",
    "DENIAL_OF_SERVICE": "Denial of service",
    "ELEVATION_OF_PRIVILEGE": "Elevation of privilege",
    "INJECTION": "Injection",
}


# ── control library (skill's standard controls + endpoint/network extensions) ─

def _c(*a, **k):
    return SecurityControl(*a, **k)


class ControlLibrary:
    STANDARD_CONTROLS = {
        "AUTH-001": _c("AUTH-001", "Multi-Factor Authentication",
                       "Require MFA for all user authentication",
                       ControlType.PREVENTIVE, ControlLayer.APPLICATION,
                       Effectiveness.HIGH, "Medium", "Low",
                       mitigates_threats=["SPOOFING"],
                       technologies=["TOTP", "WebAuthn"],
                       compliance_refs=["PCI-DSS 8.3", "NIST 800-63B"]),
        "AUTH-002": _c("AUTH-002", "Account Lockout Policy",
                       "Lock accounts after failed authentication attempts",
                       ControlType.PREVENTIVE, ControlLayer.APPLICATION,
                       Effectiveness.MEDIUM, "Low", "Low",
                       mitigates_threats=["SPOOFING"],
                       compliance_refs=["PCI-DSS 8.1.6"]),
        "ACC-001": _c("ACC-001", "Role-Based Access Control",
                      "Implement RBAC / least privilege for authorization",
                      ControlType.PREVENTIVE, ControlLayer.APPLICATION,
                      Effectiveness.HIGH, "Medium", "Medium",
                      mitigates_threats=["ELEVATION_OF_PRIVILEGE",
                                         "INFORMATION_DISCLOSURE"],
                      compliance_refs=["PCI-DSS 7.1", "SOC2"]),
        "VAL-001": _c("VAL-001", "Input Validation Framework",
                      "Validate and sanitize all input",
                      ControlType.PREVENTIVE, ControlLayer.APPLICATION,
                      Effectiveness.HIGH, "Medium", "Medium",
                      mitigates_threats=["TAMPERING", "INJECTION"],
                      compliance_refs=["OWASP ASVS V5"]),
        "NET-001": _c("NET-001", "Web Application Firewall / IPS",
                      "Filter malicious requests at the perimeter",
                      ControlType.PREVENTIVE, ControlLayer.NETWORK,
                      Effectiveness.MEDIUM, "Medium", "Medium",
                      mitigates_threats=["TAMPERING", "INJECTION",
                                         "DENIAL_OF_SERVICE"],
                      compliance_refs=["PCI-DSS 6.6"]),
        "ENC-001": _c("ENC-001", "Data Encryption at Rest",
                      "Encrypt sensitive data in storage",
                      ControlType.PREVENTIVE, ControlLayer.DATA,
                      Effectiveness.HIGH, "Medium", "Low",
                      mitigates_threats=["INFORMATION_DISCLOSURE"],
                      compliance_refs=["PCI-DSS 3.4", "GDPR Art. 32"]),
        "ENC-002": _c("ENC-002", "TLS Encryption in Transit",
                      "Encrypt data in transit using TLS 1.3",
                      ControlType.PREVENTIVE, ControlLayer.NETWORK,
                      Effectiveness.HIGH, "Low", "Low",
                      mitigates_threats=["INFORMATION_DISCLOSURE", "TAMPERING"],
                      compliance_refs=["PCI-DSS 4.1", "HIPAA"]),
        "LOG-001": _c("LOG-001", "Security Event Logging & Monitoring",
                      "Log and monitor all security-relevant events",
                      ControlType.DETECTIVE, ControlLayer.APPLICATION,
                      Effectiveness.MEDIUM, "Low", "Medium",
                      mitigates_threats=["REPUDIATION", "SPOOFING",
                                         "INFORMATION_DISCLOSURE"],
                      compliance_refs=["PCI-DSS 10.2", "SOC2"]),
        "AVL-001": _c("AVL-001", "Rate Limiting", "Limit request rates",
                      ControlType.PREVENTIVE, ControlLayer.APPLICATION,
                      Effectiveness.MEDIUM, "Low", "Low",
                      mitigates_threats=["DENIAL_OF_SERVICE"],
                      compliance_refs=["OWASP API Security"]),
        # ── endpoint / network extensions (this pipeline's estate) ──────────
        "EDR-001": _c("EDR-001", "Endpoint Detection & Response",
                      "Deploy EDR for behavioural detection + host isolation",
                      ControlType.DETECTIVE, ControlLayer.ENDPOINT,
                      Effectiveness.HIGH, "Medium", "Medium",
                      mitigates_threats=["TAMPERING", "ELEVATION_OF_PRIVILEGE",
                                         "INFORMATION_DISCLOSURE"],
                      technologies=["CrowdStrike", "Defender for Endpoint"],
                      compliance_refs=["PCI-DSS 11.5", "NIST CSF DE.CM"]),
        "PATCH-001": _c("PATCH-001", "Patch & Vulnerability Management",
                        "Timely patching of endpoints and servers",
                        ControlType.PREVENTIVE, ControlLayer.ENDPOINT,
                        Effectiveness.HIGH, "Medium", "Medium",
                        mitigates_threats=["TAMPERING", "ELEVATION_OF_PRIVILEGE",
                                           "INJECTION"],
                        compliance_refs=["PCI-DSS 6.2", "NIST CSF PR.IP"]),
        "SEG-001": _c("SEG-001", "Network Segmentation",
                      "Segment the network to contain lateral movement",
                      ControlType.PREVENTIVE, ControlLayer.NETWORK,
                      Effectiveness.HIGH, "High", "Medium",
                      mitigates_threats=["ELEVATION_OF_PRIVILEGE", "TAMPERING",
                                         "DENIAL_OF_SERVICE"],
                      compliance_refs=["PCI-DSS 1.3", "NIST CSF PR.AC"]),
        "HFW-001": _c("HFW-001", "Host-Based Firewall",
                      "Restrict inbound/outbound host connections",
                      ControlType.PREVENTIVE, ControlLayer.ENDPOINT,
                      Effectiveness.MEDIUM, "Low", "Low",
                      mitigates_threats=["TAMPERING", "DENIAL_OF_SERVICE"],
                      compliance_refs=["CIS Control 4"]),
        "APPW-001": _c("APPW-001", "Application Allow-Listing",
                       "Only permit approved executables to run",
                       ControlType.PREVENTIVE, ControlLayer.ENDPOINT,
                       Effectiveness.HIGH, "High", "Medium",
                       mitigates_threats=["TAMPERING", "INJECTION",
                                          "ELEVATION_OF_PRIVILEGE"],
                       compliance_refs=["NIST 800-167", "CIS Control 2"]),
        "BKP-001": _c("BKP-001", "Backup & Recovery",
                      "Maintain tested, offline backups for recovery",
                      ControlType.CORRECTIVE, ControlLayer.DATA,
                      Effectiveness.HIGH, "Medium", "Medium",
                      mitigates_threats=["DENIAL_OF_SERVICE", "TAMPERING"],
                      compliance_refs=["NIST CSF PR.IP-4", "ISO 27001 A.12.3"]),
        "IR-001": _c("IR-001", "Incident Response Plan",
                     "Documented IR playbooks + drills",
                     ControlType.CORRECTIVE, ControlLayer.PROCESS,
                     Effectiveness.MEDIUM, "Medium", "Medium",
                     mitigates_threats=["TAMPERING", "ELEVATION_OF_PRIVILEGE",
                                        "INFORMATION_DISCLOSURE",
                                        "DENIAL_OF_SERVICE"],
                     compliance_refs=["NIST 800-61", "SOC2 CC7.3"]),
    }

    def get_controls_for_threat(self, category: str) -> list:
        return [c for c in self.STANDARD_CONTROLS.values()
                if category in c.mitigates_threats]


_IMPACT_RISK = {"Critical": 9.0, "High": 7.0, "Medium": 5.0, "Low": 3.0}


def build_mitigation_coverage(incident: dict, triage_result: dict | None = None,
                              threat_intel: dict | None = None,
                              asset: dict | None = None,
                              max_controls_per_threat: int = 5) -> dict:
    """Map the incident's observed threats to recommended controls with
    coverage %, gaps and a roadmap. Deterministic; never raises here."""
    lib = ControlLibrary()
    ticket = (triage_result or {}).get("ticket", {})
    tactic = str(((triage_result or {}).get("metakeys_payload") or {}).get("mitre_tactic")
                 or ticket.get("mitre_tactic") or incident.get("mitre_tactic") or "").strip()
    technique = str(((triage_result or {}).get("metakeys_payload") or {}).get("mitre_technique")
                    or ticket.get("mitre_technique") or incident.get("mitre_technique") or "").strip()

    # impact from asset tier + TI verdict (reuse the pipeline's signals)
    rank = (asset or {}).get("highest_rank", 0)
    has_mal = bool(threat_intel and any(
        r.get("verdict", "").startswith("MALICIOUS")
        for r in threat_intel.get("results", [])))
    impact = ("Critical" if (has_mal and rank >= 2) else
              "High" if (has_mal or rank >= 3) else
              "Medium" if rank >= 1 else "Low")

    stride = _MITRE_TO_STRIDE.get(tactic.lower(), [])
    if not stride:
        return {"available": False, "reason":
                "no MITRE tactic on incident to map to controls"}

    mappings = []
    for cat in stride:
        controls = lib.get_controls_for_threat(cat)[:max_controls_per_threat]
        if not controls:
            continue
        threat = Threat(
            id=f"{technique or tactic}:{cat}",
            name=f"{tactic or 'Threat'} → {_STRIDE_NAMES.get(cat, cat)}",
            category=cat, description=f"Observed {tactic} activity",
            impact=impact, likelihood="High" if has_mal else "Medium",
            risk_score=_IMPACT_RISK[impact])
        mappings.append(MitigationMapping(threat, controls))

    if not mappings:
        return {"available": False, "reason": "no controls matched the threat"}

    # gaps (skill formulas)
    gaps = []
    for m in mappings:
        cov = m.calculate_coverage()
        if cov < 50:
            gaps.append({"threat": m.threat.name, "issue": "Insufficient coverage",
                         "coverage": round(cov, 1)})
        if not m.has_defense_in_depth():
            gaps.append({"threat": m.threat.name, "issue": "No defense in depth",
                         "recommendation": "Add controls at different layers"})
        if not m.has_control_diversity():
            gaps.append({"threat": m.threat.name, "issue": "No control diversity",
                         "recommendation": "Add detective/corrective controls"})

    # defense-in-depth layer coverage across all recommended controls
    layers = {}
    for m in mappings:
        for c in m.controls:
            layers.setdefault(c.layer.value, set()).add(c.id)

    # weighted achievable risk reduction
    tw = sum(m.threat.risk_score for m in mappings)
    wc = sum(m.threat.risk_score * m.calculate_coverage() for m in mappings)
    risk_reduction = round(wc / tw, 1) if tw else 0.0

    # roadmap: highest-effectiveness recommended control per threat first
    roadmap = []
    for m in sorted(mappings, key=lambda x: -x.threat.risk_score):
        top = sorted(m.controls, key=lambda c: -c.effectiveness.value)[:2]
        for c in top:
            roadmap.append({"threat": m.threat.name, "control_id": c.id,
                            "control": c.name, "type": c.control_type.value,
                            "layer": c.layer.value,
                            "effectiveness": c.effectiveness.name,
                            "compliance": c.compliance_refs})

    return {
        "available": True,
        "impact": impact,
        "achievable_risk_reduction": risk_reduction,
        "threats": [{"name": m.threat.name, "category": m.threat.category,
                     "coverage": round(m.calculate_coverage(), 1),
                     "defense_in_depth": m.has_defense_in_depth(),
                     "control_diversity": m.has_control_diversity(),
                     "controls": [{"id": c.id, "name": c.name,
                                   "type": c.control_type.value,
                                   "layer": c.layer.value,
                                   "effectiveness": c.effectiveness.name,
                                   "compliance": c.compliance_refs}
                                  for c in m.controls]}
                    for m in mappings],
        "layer_coverage": {k: sorted(v) for k, v in layers.items()},
        "gaps": gaps,
        "roadmap": roadmap[:8],
    }


def format_mitigation(cov: dict) -> str:
    """Plain-text block for the investigation alert / LLM prompt / UI."""
    if not cov.get("available"):
        return ("RECOMMENDED MITIGATIONS: " + cov.get("reason", "unavailable"))
    lines = [
        "RECOMMENDED MITIGATIONS & COVERAGE (auto-mapped from observed MITRE "
        "tactic; controls are RECOMMENDATIONS — deploy status assumed unknown, "
        "coverage % = achievable if deployed & verified)",
        f"  incident impact: {cov['impact']}  ·  achievable risk reduction if "
        f"deployed: {cov['achievable_risk_reduction']}%",
    ]
    for t in cov["threats"]:
        did = "✓" if t["defense_in_depth"] else "✗"
        div = "✓" if t["control_diversity"] else "✗"
        lines.append(f"  {t['name']} — achievable coverage {t['coverage']}% "
                     f"(defense-in-depth {did}, control-diversity {div})")
        for c in t["controls"]:
            refs = (" [" + ", ".join(c["compliance"][:2]) + "]") if c["compliance"] else ""
            lines.append(f"      · {c['id']} {c['name']} "
                         f"({c['type']}/{c['layer']}, eff {c['effectiveness']}){refs}")
    if cov["gaps"]:
        lines.append("  coverage gaps:")
        for g in cov["gaps"][:6]:
            extra = (" — " + g["recommendation"]) if g.get("recommendation") else ""
            lines.append(f"      ! {g['threat']}: {g['issue']}{extra}")
    if cov["roadmap"]:
        lines.append("  remediation roadmap (priority order):")
        for r in cov["roadmap"][:6]:
            lines.append(f"      {r['control_id']} {r['control']} "
                         f"({r['type']}/{r['layer']})")
    return "\n".join(lines)
