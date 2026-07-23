"""
skills_sidecar.py — bridge the deterministic SOC skill suite into the reporting
agent's written incident report.

WHY THIS EXISTS
    The project has ~16 standalone deterministic skills (Diamond Model, internal
    IOC correlation, the unified triage verdict, asset criticality, mitigation
    coverage, …). Until now they only rendered in the Streamlit Map panels — the
    investigation and reporting LLM agents never saw them, so the *written* report
    contained none of that analysis. This module closes that gap.

HOW IT STAYS SAFE (no working infrastructure is touched)
    * It NEVER edits soc_investigation_agent/ or soc_reporting_agent/ internals.
    * It feeds the report through the reporting agent's EXISTING input contract:
      the reporting context-builder already reads investigation_result.iocs,
      .mitre_mapping, .recommended_actions, .affected_assets, .affected_users and
      .investigation_summary. We only enrich those fields (additively) on the
      investigation_result dict our own orchestrator hands off.
    * enrich_investigation_result() is strictly NON-DESTRUCTIVE: it fills fields
      that are empty and unions/append-dedups list fields — it never overwrites a
      value the investigation agent actually produced.
    * Every skill call is wrapped: one failing skill degrades that section only;
      the sidecar (and therefore the handoff) never raises.

KILL SWITCH
    Set NW_DISABLE_SKILLS_SIDECAR=1 to disable the whole bridge — enrichment
    becomes a no-op and the pipeline behaves exactly as it did before this module.
    Each underlying skill keeps its own kill switch too (NW_DISABLE_DIAMOND, …).

PUBLIC API
    build_skills_context(incident, triage_result=None,
                         investigation_result=None, ti_result=None) -> dict
    enrich_investigation_result(investigation_result, bundle) -> dict
    format_skills_context(bundle) -> str
"""
from __future__ import annotations

import os
from typing import Any


# ── environment ──────────────────────────────────────────────────────────────

def _disabled() -> bool:
    return bool(os.environ.get("NW_DISABLE_SKILLS_SIDECAR"))


def _safe(fn, *args, **kwargs) -> Any:
    """Run a skill call; return its result or None on any failure. The skills are
    written never to raise, but a bad import / signature drift must not take the
    handoff down with it."""
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None


# ── individual skill adapters (each returns a small, report-ready fragment) ──

def _collect_diamond(incident: dict, triage_result: dict | None,
                     ti_result: dict | None) -> dict | None:
    try:
        from diamond_model import build_diamond
    except Exception:
        return None
    d = _safe(build_diamond, incident, triage_result, ti_result)
    if not isinstance(d, dict) or not d.get("available"):
        return None
    return d


def _collect_verdict(incident: dict, triage_result: dict | None,
                     ti_result: dict | None) -> dict | None:
    try:
        from triage_verdict import aggregate_verdict
    except Exception:
        return None
    v = _safe(aggregate_verdict, incident, triage_result, ti_result)
    if not isinstance(v, dict) or not v.get("available"):
        return None
    return v


def _collect_correlation(incident: dict, triage_result: dict | None) -> dict | None:
    try:
        from ioc_correlation import correlate_iocs
    except Exception:
        return None
    c = _safe(correlate_iocs, incident, triage_result)
    if not isinstance(c, dict) or not c.get("available"):
        return None
    return c


def _collect_asset(incident: dict, triage_result: dict | None) -> dict | None:
    try:
        from asset_criticality import assess_incident
    except Exception:
        return None
    cls = None
    if isinstance(triage_result, dict):
        cls = ((triage_result.get("ticket") or {}).get("classification")
               or (triage_result.get("metakeys_payload") or {}).get("risk_level"))
    a = _safe(assess_incident, incident, cls)
    if not isinstance(a, dict):
        return None
    return a


def _collect_mitigation(incident: dict, triage_result: dict | None,
                        ti_result: dict | None, asset: dict | None) -> dict | None:
    try:
        from mitigation_mapping import build_mitigation_coverage
    except Exception:
        return None
    m = _safe(build_mitigation_coverage, incident, triage_result, ti_result, asset)
    if not isinstance(m, dict) or not m.get("available"):
        return None
    return m


def _collect_sop(incident: dict, triage_result: dict | None,
                 investigation_result: dict | None, ti_result: dict | None) -> dict | None:
    try:
        from reporting_sop import build_incident_sop
    except Exception:
        return None
    s = _safe(build_incident_sop, incident, triage_result, investigation_result, ti_result)
    if not isinstance(s, dict) or not s.get("available"):
        return None
    return s


# ── field builders (skill output -> reporting-agent input shapes) ────────────

def _mitre_from_diamond(diamond: dict | None) -> list[str]:
    if not diamond:
        return []
    meta = diamond.get("meta") or {}
    tech = str(meta.get("mitre_technique") or "").strip()
    tac = str(meta.get("mitre_tactic") or "").strip()
    if tac and tech:
        return [f"{tac} — {tech}"]
    if tac:
        return [tac]
    if tech:
        return [tech]
    return []


def _iocs_from_correlation(corr: dict | None, limit: int = 8) -> list[dict]:
    """Turn correlation results into the reporting agent's IOC shape. Only the
    indicators that actually correlate (or are notable) are surfaced, so the
    report's IOC table leads with contextualised entries instead of bare metakeys.
    """
    if not corr:
        return []
    out: list[dict] = []
    for r in (corr.get("results") or [])[:limit]:
        value = r.get("value")
        if not value:
            continue
        band = str(r.get("confidence") or "").strip()
        mentions = r.get("raw_mentions")
        open_cases = r.get("open_cases") or []
        evidence_bits = []
        if r.get("rationale"):
            evidence_bits.append(str(r["rationale"]))
        if mentions is not None:
            evidence_bits.append(f"{mentions} corpus mention(s)")
        if open_cases:
            evidence_bits.append(f"{len(open_cases)} open SOC case(s)")
        out.append({
            "type": r.get("type") or "Indicator",
            "value": value,
            "source": "Internal corpus correlation (skills_sidecar)",
            "confidence": band.capitalize() if band else None,
            "reputation": None,
            "evidence": "; ".join(evidence_bits) or None,
        })
    return out


def _assets_from_skills(asset: dict | None, diamond: dict | None) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()

    def _add(hostname, criticality=None, ips=None, asset_type="Endpoint"):
        if not hostname:
            return
        key = str(hostname).upper()
        if key in seen or key.startswith("(NO NAMED"):
            return
        seen.add(key)
        ip = None
        if ips:
            ip = ips[0] if isinstance(ips, (list, tuple)) and ips else (ips if isinstance(ips, str) else None)
        out.append({
            "hostname": hostname, "asset_type": asset_type,
            "criticality": criticality, "ip_address": ip,
        })

    if diamond:
        victim = diamond.get("victim") or {}
        _add(victim.get("host"), victim.get("asset_tier"), victim.get("internal_ips"))
    if asset:
        for a in asset.get("assets") or []:
            _add(a.get("name"), a.get("tier"), None,
                 asset_type="Asset" if a.get("tier") != "unclassified" else "Endpoint")
    return out


def _users_from_diamond(diamond: dict | None) -> list[dict]:
    if not diamond:
        return []
    victim = diamond.get("victim") or {}
    out = []
    for u in victim.get("users") or []:
        if u:
            out.append({"username": u})
    return out


def _recs_from_skills(mitigation: dict | None, verdict: dict | None) -> list[dict]:
    """Recommended actions the reporting agent can render directly. Ordered:
    the unified-verdict headline action first, then the highest-effectiveness
    mitigation controls from the coverage roadmap."""
    out: list[dict] = []
    if verdict and verdict.get("action"):
        out.append({
            "priority": "P1",
            "recommendation": str(verdict["action"]),
            "rationale": f"Unified triage verdict: {verdict.get('level')} "
                         f"(scored from {verdict.get('stats', {}).get('scored_signals', 0)} "
                         "corroborating signal(s)).",
            "risk_addressed": "Prioritisation of response effort",
        })
    if mitigation:
        for i, step in enumerate(mitigation.get("roadmap") or [], start=len(out) + 1):
            refs = step.get("compliance") or []
            ref_txt = f" [{', '.join(refs[:2])}]" if refs else ""
            out.append({
                "priority": f"P{min(i, 5)}",
                "recommendation": f"Deploy/verify {step.get('control_id')} "
                                  f"{step.get('control')} "
                                  f"({step.get('type')}/{step.get('layer')})",
                "rationale": f"Mitigates: {step.get('threat')}. "
                             f"Effectiveness {step.get('effectiveness')}."
                             f"{ref_txt}",
                "risk_addressed": step.get("threat"),
            })
    return out


# ── narrative block (human-readable, routed into technical_analysis) ─────────

def _diamond_lines(d: dict) -> list[str]:
    v = d.get("victim") or {}
    infra = d.get("infrastructure") or {}
    cap = d.get("capability") or {}
    meta = d.get("meta") or {}
    stats = d.get("stats") or {}
    lines = ["### Diamond Model (structured event)"]
    if v.get("host") or v.get("internal_ips") or v.get("users"):
        who = v.get("host") or "unnamed host"
        users = ", ".join(v.get("users") or []) or "no user identified"
        ips = ", ".join(v.get("internal_ips") or []) or "—"
        lines.append(f"- **Victim:** {who} (users: {users}; internal IPs: {ips})")
    if cap.get("mitre_technique") or cap.get("items"):
        behav = ", ".join(i["value"] for i in cap.get("items", [])
                          if i.get("kind") == "behaviour") or "—"
        ttp = f"{cap.get('mitre_tactic')} / {cap.get('mitre_technique')}".strip(" /") or "—"
        lines.append(f"- **Capability:** MITRE {ttp}; observed behaviours: {behav}")
    infra_items = infra.get("items") or []
    if infra_items:
        vals = ", ".join(f"{i['value']} ({i['kind']})" for i in infra_items)
        lines.append(f"- **Infrastructure:** {vals}")
    else:
        lines.append("- **Infrastructure:** none observed (internal-only activity)")
    lines.append(f"- **Adversary:** {(d.get('adversary') or {}).get('label', 'unattributed')}")
    phase = meta.get("phase") or "unknown"
    lines.append(f"- **Kill-chain phase:** {phase}  ·  "
                 f"model completeness: {stats.get('completeness_pct', 0)}%")
    return lines


def _verdict_lines(v: dict) -> list[str]:
    lines = ["### Unified Triage Verdict",
             f"- **{v.get('level')}** — {v.get('action')}"]
    rationale = v.get("rationale") or []
    named = [f"{s.get('name')} ({s.get('label')})" for s in rationale
             if s.get("level", 0) > 0 and s.get("name") != "no elevated signals"]
    if named:
        lines.append(f"- Corroborating signals: {', '.join(named)}")
    if v.get("missing"):
        lines.append(f"- Signals unavailable: {', '.join(v['missing'])}")
    return lines


def _correlation_lines(c: dict, limit: int = 5) -> list[str]:
    lines: list[str] = []
    results = [r for r in (c.get("results") or []) if r.get("confidence") != "none"]
    if results:
        lines.append("### Internal IOC Correlation (against 53k-incident corpus + open cases)")
        for r in results[:limit]:
            oc = len(r.get("open_cases") or [])
            lines.append(f"- `{r.get('value')}` — **{str(r.get('confidence')).upper()}** "
                         f"({r.get('raw_mentions', 0)} corpus mentions"
                         + (f", {oc} open case(s)" if oc else "") + ")")
        note = (c.get("stats") or {}).get("corpus_note")
        if note:
            lines.append(f"- _{note}_")
    # ── /24 subnet neighbourhoods (subnet-aware correlation) — surface the
    # lateral-movement neighbours in the WRITTEN report, not just the Map panel.
    # Informational only: never raises an IOC's confidence (ubiquity guard stays
    # authoritative), so it renders as its own advisory sub-section.
    subnets = [s for s in (c.get("subnets") or []) if s.get("distinct_neighbours")]
    if subnets:
        if not lines:
            lines.append("### Internal IOC Correlation")
        lines.append("- **Subnet neighbourhoods (possible lateral movement):**")
        for s in subnets[:3]:
            nbs = ", ".join(str(n.get("ip")) for n in (s.get("neighbours") or [])[:5])
            lines.append(
                f"    - `{s.get('subnet')}` — {s.get('distinct_neighbours')} neighbour "
                f"IP(s) recur alongside this incident "
                f"({s.get('hi_sev_sample', 0)}/{s.get('sample_size', 0)} sampled "
                f"HIGH/CRITICAL): {nbs} "
                "_(informational — does not raise IOC confidence)_")
    if not lines:
        return ["### Internal IOC Correlation",
                "- No indicators correlated above the noise floor in the internal corpus."]
    return lines


def _mitigation_lines(m: dict, limit: int = 4) -> list[str]:
    lines = ["### Recommended Mitigations & Coverage",
             f"- Incident impact **{m.get('impact')}**; achievable risk reduction "
             f"if controls deployed & verified: **{m.get('achievable_risk_reduction')}%**"]
    for t in (m.get("threats") or [])[:limit]:
        lines.append(f"- {t.get('name')} — achievable coverage {t.get('coverage')}% "
                     f"(defense-in-depth {'yes' if t.get('defense_in_depth') else 'no'})")
    return lines


def _build_narrative(diamond, verdict, corr, mitigation, sop=None) -> str:
    blocks: list[list[str]] = []
    if verdict:
        blocks.append(_verdict_lines(verdict))
    if diamond:
        blocks.append(_diamond_lines(diamond))
    if corr:
        blocks.append(_correlation_lines(corr))
    if mitigation:
        blocks.append(_mitigation_lines(mitigation))
    if not blocks and not sop:
        return ""
    header = ("## Automated Analytical Intelligence\n"
              "_Deterministic skill analysis (read-only, no LLM) supplementing the "
              "investigation agent's findings. Generated by the SOC skill suite._\n")
    body = "\n\n".join("\n".join(b) for b in blocks)
    out = header + "\n" + body if blocks else header
    # Response SOP / runbook appendix — the actionable procedure the analyst
    # executes next (compact form so it enriches the report without bloating it).
    if sop:
        try:
            from reporting_sop import format_sop
            out += "\n\n" + format_sop(sop, compact=True)
        except Exception:
            pass
    return out


# ── public API ───────────────────────────────────────────────────────────────

def build_skills_context(incident: dict, triage_result: dict | None = None,
                         investigation_result: dict | None = None,
                         ti_result: dict | None = None) -> dict:
    """Run the deterministic skill suite over one incident and return a bundle of
    report-ready fields plus a human-readable narrative. Never raises; returns
    {"available": False, ...} when disabled or when no skill produced output."""
    if _disabled():
        return {"available": False, "reason": "disabled via NW_DISABLE_SKILLS_SIDECAR"}
    incident = incident or {}

    diamond = _collect_diamond(incident, triage_result, ti_result)
    verdict = _collect_verdict(incident, triage_result, ti_result)
    corr = _collect_correlation(incident, triage_result)
    asset = _collect_asset(incident, triage_result)
    mitigation = _collect_mitigation(incident, triage_result, ti_result, asset)
    sop = _collect_sop(incident, triage_result, investigation_result, ti_result)

    mitre_mapping = _mitre_from_diamond(diamond)
    iocs = _iocs_from_correlation(corr)
    affected_assets = _assets_from_skills(asset, diamond)
    affected_users = _users_from_diamond(diamond)
    recommended_actions = _recs_from_skills(mitigation, verdict)
    narrative = _build_narrative(diamond, verdict, corr, mitigation, sop)

    ran = [name for name, obj in (("diamond_model", diamond),
                                  ("triage_verdict", verdict),
                                  ("ioc_correlation", corr),
                                  ("asset_criticality", asset),
                                  ("mitigation_mapping", mitigation),
                                  ("reporting_sop", sop)) if obj]

    available = bool(mitre_mapping or iocs or affected_assets or
                     affected_users or recommended_actions or narrative)

    return {
        "available": available,
        "skills_ran": ran,
        "mitre_mapping": mitre_mapping,
        "iocs": iocs,
        "affected_assets": affected_assets,
        "affected_users": affected_users,
        "recommended_actions": recommended_actions,
        "analytical_intelligence": narrative,
        # structured raw bundle — preserved in the report's raw_inputs appendix
        "skills_intelligence": {
            "diamond_model": diamond,
            "unified_verdict": verdict,
            "ioc_correlation": corr,
            "asset_criticality": asset,
            "mitigation_coverage": mitigation,
            "response_sop": sop,
        },
    }


def _merge_lists(existing: Any, extra: list, key=lambda x: str(x).strip().lower()) -> list:
    """Union two lists, existing entries first, de-duplicated by ``key``."""
    out: list = []
    seen: set = set()
    for item in (existing if isinstance(existing, list) else ([existing] if existing else [])):
        k = key(item.get("value") if isinstance(item, dict) and "value" in item else item)
        if k not in seen:
            seen.add(k)
            out.append(item)
    for item in extra:
        k = key(item.get("value") if isinstance(item, dict) and "value" in item else item)
        if k not in seen:
            seen.add(k)
            out.append(item)
    return out


def enrich_investigation_result(investigation_result: dict | None,
                                bundle: dict) -> dict:
    """Additively merge the skills bundle into investigation_result, using ONLY
    fields the reporting context-builder already consumes. Non-destructive:
    fills empty fields; unions list fields; never overwrites real investigation
    output. Returns the (new) enriched dict; on any problem returns the input
    unchanged."""
    inv = dict(investigation_result or {})
    if not bundle or not bundle.get("available"):
        return inv
    try:
        # MITRE — union (keeps the investigation/triage mapping, adds skill-inferred)
        if bundle.get("mitre_mapping"):
            inv["mitre_mapping"] = _merge_lists(inv.get("mitre_mapping"),
                                                bundle["mitre_mapping"])

        # IOCs — lead with enriched entries, then keep the originals (deduped).
        if bundle.get("iocs"):
            inv["iocs"] = _merge_lists(bundle["iocs"], _as_list(inv.get("iocs")))

        # Scope tables — fill only if the investigation left them empty.
        if bundle.get("affected_assets") and not inv.get("affected_assets"):
            inv["affected_assets"] = bundle["affected_assets"]
        if bundle.get("affected_users") and not inv.get("affected_users"):
            inv["affected_users"] = bundle["affected_users"]

        # Recommended actions — fill if empty, else append skill recs (deduped).
        if bundle.get("recommended_actions"):
            if inv.get("recommended_actions"):
                inv["recommended_actions"] = _merge_lists(
                    inv["recommended_actions"], bundle["recommended_actions"],
                    key=lambda x: str(x.get("recommendation") if isinstance(x, dict) else x).strip().lower())
            else:
                inv["recommended_actions"] = bundle["recommended_actions"]

        # Narrative — route into technical_analysis via investigation_summary,
        # preserving the original summary text. Only set if not already present.
        narrative = bundle.get("analytical_intelligence")
        if narrative and not inv.get("investigation_summary"):
            base = str(inv.get("summary") or "").strip()
            inv["investigation_summary"] = (base + "\n\n" + narrative).strip() if base else narrative

        # Structured bundle — namespaced; harmless to the template, preserved in
        # the report's raw_inputs appendix for auditability.
        inv["skills_intelligence"] = bundle.get("skills_intelligence")
        inv["skills_sidecar_applied"] = True
    except Exception:
        return dict(investigation_result or {})
    return inv


def _as_list(value: Any) -> list:
    if value in (None, "", [], {}):
        return []
    return value if isinstance(value, list) else [value]


def format_skills_context(bundle: dict) -> str:
    """Plain-text rendering of the bundle (for logs / Map-panel reuse)."""
    if not bundle or not bundle.get("available"):
        return "Skills sidecar: " + (bundle or {}).get("reason", "no skill output")
    lines = [f"Skills sidecar — ran: {', '.join(bundle.get('skills_ran') or []) or 'none'}"]
    if bundle.get("analytical_intelligence"):
        lines.append(bundle["analytical_intelligence"])
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover — quick manual smoke test
    import json
    demo = {
        "id": "INC-53018", "title": "High Risk Alerts for KELLYWANG",
        "severity": "High", "status": "New",
        "created": "2025-11-18T03:18:37+00:00",
        # alertMeta values are LISTS in the real pipeline (see app._merge_alert_digest)
        "alertMeta": {
            "Hostname": ["KELLYWANG"], "User": ["Kelly Wang"],
            "SourceIp": ["192.168.10.204"], "DestinationIp": ["192.168.10.202"],
            "AlertTitles": ["Malicious HTA file detected", "Potential C2 Connection"],
        },
    }
    b = build_skills_context(demo, triage_result={"ticket": {"classification": "High"}})
    print(format_skills_context(b))
    print("\n--- enriched investigation_result keys ---")
    enriched = enrich_investigation_result({"summary": "orig summary", "status": "completed"}, b)
    print(json.dumps({k: (v if not isinstance(v, (list, dict)) else f"<{type(v).__name__} len={len(v)}>")
                      for k, v in enriched.items()}, indent=2, default=str))
