from __future__ import annotations

from typing import Any
from pathlib import Path
import json
import os
import re

from config import settings
from reporting.compact_renderer import is_placeholder

ALL_NARRATIVE_FIELDS = [
    "executive_summary",
    "technical_analysis",
    "business_impact_explanation",
    "attack_narrative",
    "conclusion",
    "analyst_friendly_explanation",
    "soc_analyst_review_checklist",
]

# Only these fields are allowed to be rewritten by an LLM.
# Structured incident details, IOCs, actions, timelines, and locked facts remain deterministic.
LLM_ENHANCEABLE_FIELDS = [
    "executive_summary",
    "technical_analysis",
    "business_impact_explanation",
    "attack_narrative",
    "conclusion",
    "analyst_friendly_explanation",
    "soc_analyst_review_checklist",
]

PROMPT_LEAKAGE_PHRASES = [
    "two paragraphs",
    "180 to 300 words",
    "use soc and cybersecurity terms",
    "do not exaggerate beyond evidence",
    "write a concise",
    "return only",
    "do not invent",
    "do not include headings",
    "use only the incident facts",
    "strict rules",
    "facts:",
    "task:",
    "you are writing",
    "you are a senior",
    "meets the requirements",
    "here's a rewritten",
    "here is a rewritten",
]

BAD_ENDINGS = [
    "including confirmation",
    "including",
    "because",
    "due to",
    "while",
    "although",
    "however",
    "and",
    "or",
    "that",
    "which",
    "with",
    "was",
    "is",
    "to",
    "for",
]

FIELD_DUMP_PREFIXES = [
    "incident id:",
    "alert id:",
    "severity:",
    "confidence:",
    "classification:",
    "likely scenario:",
    "evidence:",
    "timeline:",
]

UNCERTAINTY_TERMS = [
    "not confirmed",
    "unconfirmed",
    "pending",
    "pending validation",
    "requires validation",
    "requires further validation",
    "requires analyst validation",
    "available evidence does not",
    "current evidence does not",
    "evidence does not fully confirm",
    "has not been confirmed",
    "has not yet been confirmed",
    "remains open",
    "remain open",
    "remains pending",
    "to be validated",
    "to be confirmed",
    "cannot be confirmed",
    "no evidence currently confirms",
    "further investigation is required",
    "further investigation remains required",
    "requires additional evidence",
    "requires additional review",
    "before closure",
]

SECTION_RULES = {
    "executive_summary": {
        "min_words": 150,
        "max_words": 280,
        "require_uncertainty": True,
        "require_decision": True,
        "allow_numbered_list": False,
    },
    "technical_analysis": {
        "min_words": 220,
        "max_words": 400,
        "require_uncertainty": True,
        "require_decision": False,
        "allow_numbered_list": False,
    },
    "business_impact_explanation": {
        "min_words": 120,
        "max_words": 240,
        "require_uncertainty": True,
        "require_decision": False,
        "allow_numbered_list": False,
    },
    "attack_narrative": {
        "min_words": 160,
        "max_words": 340,
        "require_uncertainty": True,
        "require_decision": False,
        "allow_numbered_list": False,
    },
    "conclusion": {
        "min_words": 100,
        "max_words": 220,
        "require_uncertainty": True,
        "require_decision": True,
        "allow_numbered_list": False,
    },
    "analyst_friendly_explanation": {
        "min_words": 160,
        "max_words": 320,
        "require_uncertainty": True,
        "require_decision": True,
        "allow_numbered_list": False,
    },
    "soc_analyst_review_checklist": {
        "min_words": 90,
        "max_words": 420,
        "min_items": 8,
        "max_items": 8,
        "require_uncertainty": True,
        "require_decision": True,
        "allow_numbered_list": True,
    },
}



def selected_provider() -> str:
    return settings.LLM_PROVIDER


def selected_model() -> str:
    return settings.selected_llm_model()


def _cache_dir(context: dict[str, Any] | None = None) -> Path:
    if context and context.get("llm_cache_dir"):
        return Path(str(context["llm_cache_dir"]))
    return settings.LLM_CACHE_DIR


def _cache_file(context: dict[str, Any]) -> Path:
    incident_id = str(context.get("incident_id") or "UNKNOWN-INCIDENT").replace("/", "_").replace("\\", "_")
    return _cache_dir(context) / f"{incident_id}_llm_report.json"


def _load_cached_narrative(context: dict[str, Any]) -> dict[str, str] | None:
    if not settings.LLM_CACHE_ENABLED:
        return None
    path = _cache_file(context)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        narrative = data.get("llm_enhanced_narrative")
        if data.get("input_context_hash") != context.get("input_context_hash"):
            return None
        if isinstance(narrative, dict) and all(field in narrative for field in ALL_NARRATIVE_FIELDS):
            return {field: str(narrative.get(field, "")) for field in ALL_NARRATIVE_FIELDS}
    except Exception:
        return None
    return None


def _save_cached_narrative(context: dict[str, Any], narrative: dict[str, str], provider: str, model: str) -> None:
    if not settings.LLM_CACHE_ENABLED:
        return
    try:
        path = _cache_file(context)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "incident_id": context.get("incident_id"),
            "alert_id": context.get("alert_id"),
            "input_context_hash": context.get("input_context_hash"),
            "llm_provider": provider,
            "llm_model": model,
            "llm_enhanced_narrative": narrative,
        }
        path.write_text(json.dumps(payload, indent=4), encoding="utf-8")
    except Exception:
        # Caching must never break report generation.
        return


def _clean_sentence_join(items: list[str]) -> str:
    cleaned = []
    for item in items:
        text = str(item or "").strip()
        if not text:
            continue
        text = text.rstrip(" .;")
        cleaned.append(text)
    if not cleaned:
        return "Not Provided"
    return ". ".join(cleaned) + "."


def _asset_story(context: dict[str, Any]) -> tuple[str, str]:
    assets = context.get("affected_assets", [])
    users = context.get("affected_users", [])

    asset_text = "no confirmed affected asset" if not assets else ", ".join(
        f"{a.get('hostname')} ({a.get('business_function')}, {a.get('criticality')} criticality, {a.get('asset_type')})"
        for a in assets
    )
    user_text = "no confirmed affected user" if not users else ", ".join(
        f"{u.get('username')} ({u.get('role')}, {u.get('privilege_level')}, MFA: {u.get('mfa_status')})"
        for u in users
    )
    return asset_text, user_text


def _evidence_story(context: dict[str, Any]) -> tuple[str, str, str]:
    evidence = context.get("evidence", [])
    timeline = context.get("timeline", [])
    iocs = context.get("iocs", [])

    evidence_parts = [f"{item.get('id')}: {item.get('description')}" for item in evidence[:5]]
    timeline_parts = [str(item.get("event") or item.get("description")) for item in timeline[:5]]
    suspicious_iocs = [
        f"{ioc.get('value')} ({ioc.get('type')}, {ioc.get('reputation')})"
        for ioc in iocs
        if str(ioc.get("reputation", "")).lower() in ["malicious", "suspicious"]
    ]

    return (
        _clean_sentence_join(evidence_parts) if evidence_parts else "No evidence descriptions provided.",
        _clean_sentence_join(timeline_parts) if timeline_parts else "No timeline provided.",
        ", ".join(suspicious_iocs) if suspicious_iocs else "No malicious or suspicious IOCs provided",
    )


def _gap_story(context: dict[str, Any]) -> str:
    gaps = context.get("evidence_gaps", [])
    parts = []
    for gap in gaps[:6]:
        parts.append(f"{gap.get('priority', 'Unknown')}: {gap.get('gap', 'Not Provided')}")
    return _clean_sentence_join(parts) if parts else "No evidence gaps recorded."


def _mitre_story(context: dict[str, Any]) -> str:
    mappings = context.get("mitre_attack_mapping", [])
    parts = []
    for item in mappings[:5]:
        technique = " ".join(str(x) for x in [item.get("technique_id", ""), item.get("technique_name", "")] if x).strip()
        tactic = item.get("tactic", "Not Provided")
        if technique:
            parts.append(f"{tactic}: {technique}")
    return "; ".join(parts) if parts else "No MITRE ATT&CK mapping provided."


def _first_asset(context: dict[str, Any]) -> dict[str, Any]:
    assets = context.get("affected_assets", []) or []
    return assets[0] if assets else {}


def _first_user(context: dict[str, Any]) -> dict[str, Any]:
    users = context.get("affected_users", []) or []
    return users[0] if users else {}


def _event_phrase(event: str) -> str:
    text = str(event or "").strip().rstrip(".")
    lower = text.lower()
    if "email" in lower and "deliver" in lower:
        return "a suspicious email being delivered"
    if "powershell" in lower:
        return "endpoint telemetry showing suspicious PowerShell activity"
    return text[0].lower() + text[1:] if text else "an event recorded in the timeline"


def deterministic_narrative(context: dict[str, Any]) -> dict[str, str]:
    severity = context.get("severity", {}).get("label", "Not Provided")
    confidence = context.get("confidence", {}).get("label", "Not Provided")
    classification = context.get("classification", "Not Provided")
    scenario = context.get("likely_scenario", "Not Provided")
    asset_text, user_text = _asset_story(context)
    evidence_story, timeline_story, malicious_iocs = _evidence_story(context)
    gap_story = _gap_story(context)
    mitre_story = _mitre_story(context)
    approval_status = context.get("approval", {}).get("approval_status", "Not Provided")
    containment_status = context.get("containment", {}).get("status", "Not Provided")
    impact = context.get("impact_assessment", {})
    report_status = context.get("report_status", "Not Provided")
    first_asset = _first_asset(context)
    first_user = _first_user(context)
    host = first_asset.get("hostname", "the affected host")
    business_function = first_asset.get("business_function", "the affected business function")
    user = first_user.get("username", "the affected user")
    timeline_events = context.get("timeline", []) or []
    readable_events = [_event_phrase(item.get("event") or item.get("description")) for item in timeline_events[:3]]
    readable_sequence = ", followed by ".join(readable_events) if readable_events else "the available alert and investigation evidence"
    data_impact_summary = context.get("data_impact_summary") or "Data impact assessment: No data impact summary was generated from available context."
    chain_note = context.get("chain_of_custody_note") or ""
    approval_summary = context.get("approval_summary") or {}
    approval_text = "\n".join(approval_summary.values()) if approval_summary else f"Analyst approval is {approval_status}."
    containment_text = f"Containment is currently {containment_status}." if not is_placeholder(containment_status) else "Containment status is not recorded in available context."

    executive_summary = (
        f"This incident is assessed as a {severity}-severity, {confidence}-confidence {classification} involving {scenario}. "
        f"The known affected scope is {asset_text} and {user_text}. The case is supported by {evidence_story} "
        f"Malicious or suspicious indicators include {malicious_iocs}. {containment_text} {approval_text} "
        f"{data_impact_summary} "
        f"The report is not finalised because these validation items remain open: {gap_story}"
    )

    technical_analysis = (
        f"From a SOC investigation perspective, the available evidence shows {readable_sequence}. "
        f"This activity is consistent with {scenario}, supported by {evidence_story} MITRE ATT&CK context includes {mitre_story}.\n\n"
        f"The current evidence supports a {severity}-severity, {confidence}-confidence {classification}, but it does not fully confirm whether payload execution completed, "
        f"whether credentials or sessions were exposed, or whether follow-on access occurred. The analyst should validate script block logs, process completion status, "
        f"identity logs, mailbox audit logs, and outbound network telemetry before closure."
    )
    if chain_note:
        technical_analysis += f"\n\n{chain_note}"

    business_impact = (
        (str(impact.get("business") or "").replace("Current business impact is limited to", "Based on the current record, impact is limited to") if impact.get("business") else "")
        or f"Based on the current record, impact appears limited to {host}, which supports {business_function}, and {user}. Containment or credential reset may temporarily affect the related workflow."
    )
    if impact.get("security") or impact.get("unconfirmed"):
        business_impact += f" Security risk: {impact.get('security', 'Not Provided')} Not yet confirmed: {impact.get('unconfirmed', 'Not Provided')}"

    attack_narrative = (
        f"The likely attack sequence began with {readable_sequence}. This sequence is consistent with {scenario}, with observed evidence including {evidence_story} "
        f"The activity has been mapped to {mitre_story}.\n\n"
        f"However, the current evidence does not fully confirm payload completion, persistence, credential or session exposure, lateral movement, data access, or exfiltration. "
        f"These items should remain open until the SOC analyst validates the relevant endpoint, identity, network, and application logs. "
        f"{chain_note}"
    )

    conclusion = (
        f"The report is suitable for SOC analyst review with status {report_status}. "
        f"Before closure, the analyst should validate unresolved evidence gaps, confirm containment or approval decisions, and determine whether any business, data, regulatory, or recovery impact exists. "
        f"Any disruptive action, such as endpoint isolation or credential revocation, should follow the recorded approval workflow. "
        f"{data_impact_summary}"
    )

    analyst_explanation = (
        f"The SOC analyst should review this case by validating the evidence that supports the {severity} severity, {confidence} confidence, and {classification} classification. "
        f"The most important review areas are the affected scope ({asset_text}), the affected user context ({user_text}), suspicious indicators ({malicious_iocs}), and the timeline sequence ({timeline_story}). "
        f"The analyst should confirm whether the evidence supports containment, escalation, closure, or further investigation, especially because these validation items remain open: {gap_story} "
        f"If containment is disruptive, the analyst should confirm the approval status ({approval_status}) and containment status ({containment_status}) before action is taken. "
        f"{chain_note} "
        f"Any finding that cannot be verified from the provided evidence should remain marked as not confirmed rather than being treated as a confirmed compromise."
    )

    checklist_items = [
        f"1. Confirm that the incident ID, alert ID, severity ({severity}), confidence ({confidence}), and classification ({classification}) match the latest triage and investigation records.",
        f"2. Validate the affected scope by checking whether {asset_text} and {user_text} are present in the original alert, endpoint telemetry, identity logs, or NetWitness evidence.",
        f"3. Review the listed IOCs and supporting evidence references, especially {malicious_iocs}, before blocking, isolating, or escalating based on indicator reputation.",
        f"4. Reconstruct the timeline using the available events ({timeline_story}) and confirm whether payload execution, persistence, credential exposure, lateral movement, data access, or exfiltration is not confirmed in the provided evidence.",
        f"5. Compare the technical evidence against the mapped MITRE ATT&CK context ({mitre_story}) and record whether each mapped behaviour is observed, suggested, or still pending validation.",
        f"6. Review unresolved evidence gaps ({gap_story}) and collect the required endpoint, identity, network, email, or application logs before closure.",
        f"7. Decide whether containment or approval should proceed by checking the current approval status ({approval_status}) and containment status ({containment_status}).",
        "8. Record the final analyst decision, including whether the case should be escalated, contained, closed as false positive, or kept open for further investigation."
    ]
    soc_analyst_review_checklist = "\n".join(checklist_items)

    return {
        "executive_summary": executive_summary,
        "technical_analysis": technical_analysis,
        "business_impact_explanation": business_impact,
        "attack_narrative": attack_narrative,
        "conclusion": conclusion,
        "analyst_friendly_explanation": analyst_explanation,
        "soc_analyst_review_checklist": soc_analyst_review_checklist,
    }


def _compact_context(context: dict[str, Any]) -> dict[str, Any]:
    """Build compact, labelled, analyst-useful context for LLM rewriting.

    The LLM receives enough detail to write useful SOC review guidance, but it
    still does not receive unrestricted raw JSON dumps. Locked facts are clearly
    separated from interpretation and evidence gaps.
    """
    return {
        "locked_facts": {
            "incident_id": context.get("incident_id"),
            "alert_id": context.get("alert_id"),
            "case_title": context.get("case_title"),
            "severity": context.get("severity", {}).get("label"),
            "severity_reason": context.get("severity", {}).get("reason"),
            "confidence": context.get("confidence", {}).get("label"),
            "confidence_reason": context.get("confidence", {}).get("reason"),
            "classification": context.get("classification"),
            "approval_status": context.get("approval", {}).get("approval_status"),
            "report_generation_approval": context.get("report_generation_approval"),
            "containment_status": context.get("containment", {}).get("status"),
            "containment_approval_status": context.get("containment", {}).get("approval_status"),
            "containment_execution_status": context.get("containment", {}).get("execution_status"),
            "recommended_containment_action": context.get("containment", {}).get("recommended_action"),
        },
        "scenario": {
            "likely_scenario": context.get("likely_scenario"),
            "scenario_type": context.get("scenario_type"),
        },
        "affected_scope": {
            "assets": context.get("affected_assets", [])[:4],
            "users": context.get("affected_users", [])[:4],
        },
        "evidence_to_interpret": {
            "iocs": context.get("iocs", [])[:8],
            "evidence": context.get("evidence", [])[:8],
            "timeline": context.get("timeline", [])[:8],
            "mitre_attack_mapping": context.get("mitre_attack_mapping", [])[:8],
            "threat_intelligence_summary": context.get("threat_intelligence_summary", context.get("threat_intel_summary", "Not available")),
        },
        "analyst_review_context": {
            "investigation_status": context.get("investigation_status"),
            "investigation_completeness_status": context.get("investigation_completeness_status"),
            "investigation_completeness_note": context.get("investigation_completeness_note"),
            "reporting_mode": context.get("reporting_mode"),
            "investigation_limitations": context.get("investigation_limitations", [])[:8],
            "evidence_gaps": context.get("evidence_gaps", [])[:8],
            "recommended_actions": context.get("recommended_actions", [])[:6],
            "approval": context.get("approval", {}),
            "containment": context.get("containment", {}),
            "impact_assessment": context.get("impact_assessment", {}),
            "report_status": context.get("report_status"),
            "data_impact_summary": context.get("data_impact_summary"),
            "chain_of_custody_note": context.get("chain_of_custody_note"),
            "approval_summary": context.get("approval_summary", {}),
            "compact_evidence_register": context.get("compact_evidence_register", {}),
        },
    }


def _section_instruction(section: str) -> str:
    instructions = {
        "executive_summary": (
            "Write exactly 2 paragraphs, 160 to 240 words total. "
            "Paragraph 1: Summarise the incident classification, severity, confidence, affected scope, and key evidence. "
            "Paragraph 2: Explain why the case matters, what decision is needed next, and what remains unconfirmed. "
            "Include one sentence beginning exactly with: 'Not confirmed in the provided evidence:' "
            "Use management-friendly language, but keep the content useful for SOC review. End with a complete sentence."
        ),
        "technical_analysis": (
            "Write exactly 3 paragraphs, 240 to 360 words total. "
            "Paragraph 1: Explain the confirmed technical evidence, affected assets or users, IOCs, and alert context. "
            "Paragraph 2: Explain the likely technical risk, MITRE behaviour if available, and how the evidence supports the severity and confidence rating. "
            "Paragraph 3: Explain evidence gaps and what the SOC analyst should validate next. "
            "Include one sentence beginning exactly with: 'Not confirmed in the provided evidence:' "
            "Do not invent attack stages, execution details, lateral movement, credential access, or data access. End with a complete sentence."
        ),
        "business_impact_explanation": (
            "Write exactly 2 paragraphs, 140 to 220 words total. "
            "Paragraph 1: Explain possible business, operational, and security impact based only on the affected asset, affected user, severity, and recommended actions. "
            "Paragraph 2: Clearly separate confirmed impact from potential impact and explain why analyst validation is required before containment, escalation, or closure. "
            "Include one sentence beginning exactly with: 'Not confirmed in the provided evidence:' "
            "Do not claim confirmed business disruption, data loss, customer impact, or service outage unless explicitly present in the incident facts. End with a complete sentence."
        ),
        "attack_narrative": (
            "Write exactly 2 paragraphs, 180 to 300 words total. "
            "Paragraph 1: Describe the observed sequence from alert trigger to enrichment and triage using only the available timeline and evidence. "
            "Paragraph 2: Explain what the sequence suggests, what remains unconfirmed, and what the analyst should check next. "
            "Include one sentence beginning exactly with: 'Not confirmed in the provided evidence:' "
            "Do not create missing attack stages, lateral movement, persistence, privilege escalation, or exfiltration. End with a complete sentence."
        ),
        "conclusion": (
            "Write exactly 1 paragraph, 120 to 180 words total. State the current report status, severity, confidence, unresolved validation items, and next analyst decision. "
            "Include one sentence beginning exactly with: 'Not confirmed in the provided evidence:' "
            "End with a clear complete sentence stating whether the report is ready for analyst review."
        ),
        "analyst_friendly_explanation": (
            "Write exactly 2 paragraphs, 180 to 280 words total. "
            "Paragraph 1: Explain how the SOC analyst should review the evidence, including fields, artefacts, IOCs, assets, users, and timeline points that matter most. "
            "Paragraph 2: Explain the remaining uncertainty, approval or containment decision, and what would justify escalation, closure, or further investigation. "
            "Include one sentence beginning exactly with: 'Not confirmed in the provided evidence:' "
            "End with a complete sentence stating the next analyst decision."
        ),
        "soc_analyst_review_checklist": (
            "Return exactly 8 numbered SOC analyst review actions. Each item must begin with one of these verbs: Confirm, Validate, Review, Check, Decide, Record, or Escalate. "
            "At least one item must cover unresolved evidence gaps. At least one item must cover containment or approval decision-making. "
            "At least one item must cover business impact or operational disruption validation. Do not invent evidence, impact, compromise, or response actions."
        ),
    }
    return instructions[section]


def build_section_prompt(section: str, context: dict[str, Any], deterministic: dict[str, str]) -> str:
    compact = json.dumps(_compact_context(context), indent=2, ensure_ascii=False)
    return (
        "You are a SOC Reporting Agent assisting a human SOC analyst.\n\n"
        "Your task is to improve one section of an incident report using only the provided incident facts and deterministic factual reference. "
        "You are not investigating the incident, changing the decision, or adding new evidence.\n\n"
        "Write a detailed, analyst-useful section that helps the SOC analyst understand:\n"
        "1. what is confirmed,\n"
        "2. why it matters,\n"
        "3. what is not confirmed,\n"
        "4. what the analyst should validate next.\n\n"
        "Rules:\n"
        "1. Preserve the provided facts exactly. Do not change incident ID, severity, confidence, classification, affected assets, affected users, IOCs, MITRE mapping, recommended actions, approval status, or containment status.\n"
        "2. Do not invent users, hosts, IOCs, malware names, impact, timelines, techniques, evidence IDs, or response actions.\n"
        "3. Do not mention prompt rules, locked facts, guardrails, deterministic fallback, validation logic, retry logic, or internal system behaviour in the output.\n"
        "3a. If investigation_status, investigation_completeness_status, or reporting_mode indicates limitations, do not block report generation. Clearly document the missing telemetry as evidence gaps and avoid claiming persistence, lateral movement, data access, exfiltration, containment, or business impact is confirmed unless provided in the facts.\n"
        "4. Clearly separate confirmed evidence from unconfirmed possibilities.\n"
        "5. Every narrative section must include one sentence beginning exactly with: 'Not confirmed in the provided evidence:'\n"
        "6. Expand only on analyst-useful context: evidence interpretation, risk reasoning, validation gaps, containment considerations, and next review steps.\n"
        "7. Do not add generic cybersecurity theory.\n"
        "8. Write only the body text for the requested section. Do not include headings, markdown labels, JSON, or these instructions.\n"
        "9. For the checklist section only, return numbered action items. For all other sections, use paragraphs only.\n"
        "10. Write complete sentences and end with a complete sentence. Do not stop mid-sentence.\n\n"
        f"Section to write:\n{section}\n\n"
        f"Section requirement:\n{_section_instruction(section)}\n\n"
        f"Incident facts:\n{compact}\n\n"
        f"Deterministic factual reference:\n{deterministic.get(section, '')}\n"
    )

def _normalise_llm_output(text: str) -> str:
    text = str(text or "").strip()
    text = text.replace("```markdown", "").replace("```", "").strip()
    text = re.sub(r"(?i)^here(?:'|’)s.*?:\s*", "", text).strip()
    text = re.sub(r"(?i)^sure[,.]?\s*", "", text).strip()
    # Remove accidental markdown section headings if the model adds them.
    text = re.sub(r"(?im)^#{1,6}\s*[A-Za-z _-]+\s*$", "", text).strip()
    return text


def _invoke_ollama(prompt: str, model: str | None = None) -> str:
    try:
        from langchain_ollama import OllamaLLM
    except Exception:
        from langchain_community.llms import Ollama as OllamaLLM

    llm_kwargs: dict[str, Any] = {
        "model": model or settings.OLLAMA_MODEL,
        "temperature": settings.LLM_TEMPERATURE,
        "num_predict": settings.LLM_NUM_PREDICT,
    }
    # langchain_ollama supports base_url, while older community Ollama uses base_url too.
    if getattr(settings, "OLLAMA_BASE_URL", None):
        llm_kwargs["base_url"] = settings.OLLAMA_BASE_URL
    llm = OllamaLLM(**llm_kwargs)
    return str(llm.invoke(prompt)).strip()


def supports_temperature(model_name: str) -> bool:
    model = (model_name or "").lower()
    # Some newer reasoning/frontier models reject temperature in the Responses API.
    return not model.startswith("gpt-5")


def _invoke_openai_chat(client: Any, selected: str, prompt: str) -> str:
    """Classic chat-completions call. Used for OpenAI-compatible endpoints
    that do not implement the newer Responses API."""
    request_args: dict[str, Any] = {
        "model": selected,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": settings.LLM_NUM_PREDICT,
    }
    if supports_temperature(selected):
        request_args["temperature"] = settings.LLM_TEMPERATURE
    if getattr(settings, "LLM_SEED", None) is not None:
        request_args["seed"] = settings.LLM_SEED
    try:
        response = client.chat.completions.create(**request_args)
    except Exception as error:
        # Some gateways reject the seed parameter — drop it rather than fail.
        if "seed" in request_args and "seed" in str(error).lower():
            request_args.pop("seed", None)
            response = client.chat.completions.create(**request_args)
        else:
            raise
    return str(response.choices[0].message.content or "").strip()


def _invoke_openai(prompt: str, model: str | None = None) -> str:
    if not settings.OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY is not set")
    try:
        from openai import OpenAI
    except Exception as error:
        raise RuntimeError(f"openai package is not installed: {error}") from error

    selected = model or settings.LLM_MODEL
    client_kwargs: dict[str, Any] = {"api_key": settings.OPENAI_API_KEY, "timeout": settings.LLM_TIMEOUT_SECONDS}
    if settings.OPENAI_BASE_URL:
        client_kwargs["base_url"] = settings.OPENAI_BASE_URL
    client = OpenAI(**client_kwargs)

    # REPORTING_OPENAI_API=chat forces chat-completions (set by the SOC
    # workflow when routing to the Cisco endpoint). Default stays "responses".
    if os.getenv("REPORTING_OPENAI_API", "responses").strip().lower() == "chat":
        return _invoke_openai_chat(client, selected, prompt)

    request_args: dict[str, Any] = {
        "model": selected,
        "input": prompt,
        "max_output_tokens": settings.LLM_NUM_PREDICT,
    }
    if supports_temperature(selected):
        request_args["temperature"] = settings.LLM_TEMPERATURE

    try:
        response = client.responses.create(**request_args)
    except Exception as error:
        error_text = str(error).lower()
        if "unsupported parameter" in error_text and "temperature" in error_text:
            request_args.pop("temperature", None)
            response = client.responses.create(**request_args)
        elif any(t in error_text for t in ("401", "404", "unauthorized", "not found", "unknown route")):
            # Endpoint lacks the Responses API — retry via chat completions.
            return _invoke_openai_chat(client, selected, prompt)
        else:
            raise
    return str(response.output_text).strip()


def _extract_section_from_prompt(prompt: str) -> str:
    match = re.search(r"Section to write:\s*([a-zA-Z0-9_]+)", str(prompt or ""))
    return match.group(1) if match else "technical_analysis"


def _invoke_mock(prompt: str, model: str | None = None) -> str:
    # Test-only provider used to validate pipeline behaviour without internet or local Ollama.
    mode = settings.LLM_MOCK_MODE
    if mode == "prompt_leak":
        return "Two paragraphs, 180 to 300 words total. Use SOC and cybersecurity terms. This leaked instruction should be rejected."
    if mode == "truncated":
        return "The incident involved suspicious endpoint activity and requires analyst validation, including confirmation"

    section = _extract_section_from_prompt(prompt)
    if mode == "missing_uncertainty":
        return (
            "This section summarises the incident using the listed alert records, affected scope, evidence, and analyst decision context. "
            "The activity should be reviewed by the SOC analyst because it may require containment, escalation, or closure decisions based on the provided case facts. "
            "The analyst should compare the evidence, timeline, IOCs, affected assets, affected users, and recommended actions before recording the final decision. "
            "The report wording remains grounded in the supplied incident context and does not add new entities or impact claims."
        )
    if mode == "short":
        return "This incident requires SOC analyst review before containment or closure."
    if mode == "incomplete":
        return (
            "This incident is assessed from the available alert and investigation context. Not confirmed in the provided evidence: payload execution, lateral movement, credential access, data exposure, and business disruption. "
            "The analyst should validate the affected scope, IOCs, timeline, and approval decision before"
        )
    if mode == "checklist_short" and section == "soc_analyst_review_checklist":
        return (
            "1. Confirm that the incident ID, severity, confidence, and classification match the latest records.\n"
            "2. Validate the affected assets and users against the original alert and endpoint telemetry.\n"
            "3. Review unresolved evidence gaps before containment or closure.\n"
            "4. Decide whether approval, escalation, closure, or further investigation is required."
        )
    if mode == "issue_sensitive_retry" and "Your previous response" not in prompt:
        return "This incident requires SOC analyst review before containment or closure."
    if section == "soc_analyst_review_checklist":
        return (
            "1. Confirm that the incident ID, severity, confidence, and classification match the latest triage and investigation records.\n"
            "2. Validate the affected assets and users against the original alert, endpoint telemetry, and identity logs before containment.\n"
            "3. Review each listed IOC and confirm whether the reputation is supported by the provided evidence and threat intelligence.\n"
            "4. Reconstruct the timeline and verify whether execution, persistence, credential exposure, lateral movement, data access, or exfiltration is not confirmed in the provided evidence.\n"
            "5. Check the mapped MITRE ATT&CK behaviour and record whether each behaviour is observed, suggested, or pending validation.\n"
            "6. Review unresolved evidence gaps and collect the required endpoint, identity, network, email, or application logs.\n"
            "7. Decide whether containment approval, escalation, closure, or further investigation is appropriate based only on validated evidence.\n"
            "8. Record the final analyst decision and ensure any disruptive action follows the approval workflow."
        )

    common = (
        "This incident is assessed from the available alert, evidence, and timeline records, with the affected scope limited to the listed assets and users. "
        "The narrative preserves the supplied severity, confidence, classification, IOCs, MITRE mapping, approval status, and containment status without adding unsupported entities or impact claims. "
        "The available evidence indicates suspicious activity that requires SOC review, and the analyst should validate the endpoint, identity, network, email, and application artefacts before deciding whether the case should proceed to containment, escalation, closure, or further investigation. "
        "Not confirmed in the provided evidence: payload completion, credential exposure, persistence, lateral movement, data access, exfiltration, confirmed business disruption, and containment completion. "
    )
    if section == "executive_summary":
        return common + (
            "From a management perspective, the case matters because it may involve malicious activity affecting a listed asset or user, and the response decision may have operational impact if containment is approved. "
            "The report is ready for analyst review because the core case fields and evidence references are available, but closure should remain pending until unresolved evidence gaps and the approval decision are recorded. "
            "The next decision is whether the SOC analyst should approve containment, escalate for deeper investigation, or keep the case open while collecting missing evidence."
        )
    if section == "technical_analysis":
        return common + (
            "Technically, the analyst should compare the observable evidence with the incident timeline, IOC reputation, affected assets, affected users, and MITRE mapping to confirm whether the activity is observed or only suggested. "
            "The available data supports a security investigation because the alert and supporting evidence describe suspicious activity that may be associated with execution, phishing, endpoint compromise, or identity misuse depending on the case facts. "
            "The evidence should be reviewed against process execution logs, parent-child process relationships, command-line arguments, script block logs, authentication events, DNS activity, proxy records, endpoint detections, and any available NetWitness session reconstruction. "
            "The analyst should avoid treating suggested behaviour as confirmed compromise until the relevant log source supports it, and any unsupported assumption should remain marked as not confirmed in the provided evidence."
        )
    if section == "business_impact_explanation":
        return common + (
            "The confirmed business impact is limited to what is stated in the provided incident context, so the report should not claim outage, customer exposure, data loss, or operational disruption unless those facts are explicitly present. "
            "Potential disruption may occur if endpoint isolation, account revocation, email blocking, or other containment actions are approved, especially if the affected asset supports an important business workflow. "
            "Analyst validation is required before disruptive containment, escalation, or closure because the difference between suspected activity and confirmed compromise changes the operational response."
        )
    if section == "attack_narrative":
        return common + (
            "Chronologically, the case should be read from alert generation through enrichment, triage, investigation, and approval or containment review. "
            "The available sequence suggests a security event that may require response, but the analyst should document which parts of the sequence are directly observed, which parts are inferred from threat intelligence or MITRE mapping, and which parts remain unresolved. "
            "The report should not create missing attack stages such as persistence, privilege escalation, lateral movement, exfiltration, or ransomware impact unless those stages are present in the timeline or evidence. "
            "The next review step is to compare the timeline with endpoint, identity, network, email, and application logs so the analyst can decide whether the incident scope is limited or requires escalation."
        )
    if section == "conclusion":
        return common + (
            "The case should remain under SOC analyst review until unresolved validation items are addressed and the next decision is recorded. "
            "The report can support analyst review because it preserves the key case facts, separates evidence from assumptions, and identifies the decision points that affect containment, escalation, closure, or further investigation. "
            "The report is ready for analyst review, but containment or closure should only proceed after the analyst confirms the evidence and approval status."
        )
    return common + (
        "During review, the analyst should prioritise evidence that could change the severity, confidence, classification, containment decision, escalation path, or closure outcome. "
        "The most useful checks are to confirm the affected assets and users, validate IOC reputation, reconstruct the timeline, compare evidence with mapped MITRE behaviour, and decide whether the recommended actions are justified by confirmed evidence. "
        "Any missing fact should stay marked as not confirmed in the provided evidence until a trusted log source, analyst note, or approved investigation result supports it. "
        "The next analyst decision should record whether the case proceeds to containment, escalation, closure, or further investigation."
    )


def invoke_llm(prompt: str, provider: str | None = None, model: str | None = None) -> str:
    provider = (provider or selected_provider()).strip().lower()
    selected = model or settings.selected_model_for_provider(provider)
    if provider == "openai":
        return _invoke_openai(prompt, selected)
    if provider == "ollama":
        return _invoke_ollama(prompt, selected)
    if provider == "mock":
        return _invoke_mock(prompt, selected)
    raise RuntimeError(f"Unsupported LLM provider: {provider}")


def invoke_llm_with_retries(prompt: str, *, section: str) -> tuple[str, str, str, list[str], int]:
    """Invoke the configured LLM with retries and optional provider fallback.

    Returns output, provider, model, issues, attempts. Any exception is captured
    as a structured issue so the caller can fall back deterministically.
    """
    issues: list[str] = []
    attempts = 0
    max_retries = max(1, settings.LLM_MAX_RETRIES)
    for provider in settings.configured_llm_providers():
        model = settings.selected_model_for_provider(provider)
        for attempt in range(1, max_retries + 1):
            attempts += 1
            try:
                return invoke_llm(prompt, provider, model), provider, model, issues, attempts
            except Exception as error:
                issues.append(f"{section}:provider={provider}:attempt={attempt}:llm_error:{error}")
                # Second and later attempts use a smaller, stricter prompt.
                if attempt < max_retries:
                    if section == "soc_analyst_review_checklist":
                        retry_instruction = (
                            "Retry instruction: Your previous response did not pass validation. "
                            "Return 6 to 10 numbered checklist items only. Use only provided facts, preserve locked facts exactly, do not invent evidence, and include analyst validation or decision steps."
                        )
                    else:
                        retry_instruction = (
                            "Retry instruction: Your previous response did not pass validation. Rewrite the section again using only the provided facts. "
                            "Keep the response detailed but evidence-bound, preserve locked facts exactly, do not add headings or bullets, do not add new facts, "
                            "and clearly state uncertainty where evidence is missing."
                        )
                    prompt = prompt + "\n\n" + retry_instruction
    raise RuntimeError("; ".join(issues[-6:]) or "LLM invocation failed")

def _contains_uncertainty(text: str) -> bool:
    lower = str(text or "").lower()
    return any(term in lower for term in UNCERTAINTY_TERMS)


def _detect_business_impact_overstatement(text: str, context: dict[str, Any] | None) -> bool:
    if not context:
        return False
    lower = str(text or "").lower()
    if "critical" not in lower:
        return False
    assets = context.get("affected_assets", []) or []
    has_critical_asset = any(str(asset.get("criticality", "")).lower() == "critical" for asset in assets)
    # Avoid false positives for phrases such as "not critical" or "criticality".
    if "criticality" in lower or "not critical" in lower:
        return False
    return not has_critical_asset



def _numbered_checklist_count(text: str) -> int:
    return len(re.findall(r"(?m)^\s*(?:\d+[\).]|[-*])\s+\S+", str(text or "")))


def _detect_locked_fact_contradictions(text: str, context: dict[str, Any] | None) -> list[str]:
    if not context:
        return []
    lower = str(text or "").lower()
    issues: list[str] = []

    severity = str(context.get("severity", {}).get("label", "") or "").lower()
    severity_groups = {
        "critical": ["low severity", "medium severity", "minor incident", "informational case"],
        "high": ["low severity", "minor incident", "informational case"],
        "medium": ["critical severity", "severe compromise"],
        "low": ["critical severity", "high severity", "severe compromise"],
    }
    for phrase in severity_groups.get(severity, []):
        if phrase in lower:
            issues.append("locked_fact_contradiction:severity")
            break

    confidence = str(context.get("confidence", {}).get("label", "") or "").lower()
    if confidence == "high" and any(term in lower for term in ["low confidence", "weak confidence", "very uncertain confidence"]):
        issues.append("locked_fact_contradiction:confidence")
    if confidence == "low" and any(term in lower for term in ["high confidence", "strong confidence"]):
        issues.append("locked_fact_contradiction:confidence")

    classification = str(context.get("classification", "") or "").lower()
    if "false positive" in classification and any(term in lower for term in ["confirmed compromise", "confirmed malicious compromise"]):
        issues.append("locked_fact_contradiction:classification")
    if "true positive" in classification and any(term in lower for term in ["false positive", "benign case"]):
        issues.append("locked_fact_contradiction:classification")

    return list(dict.fromkeys(issues))


def _detect_unsupported_fact_creation(text: str, context: dict[str, Any] | None) -> list[str]:
    if not context:
        return []
    issues: list[str] = []
    raw = str(text or "")
    lower = raw.lower()
    known_evidence_ids = {
        str(item.get("id") or item.get("evidence_id"))
        for item in context.get("evidence", []) or []
        if isinstance(item, dict) and (item.get("id") or item.get("evidence_id"))
    }
    for evidence_id in re.findall(r"\bEV-\d{3,}\b", raw):
        if evidence_id not in known_evidence_ids:
            issues.append("unsupported_fact_creation:evidence_id")
            break

    execution_status = str((context.get("containment") or {}).get("execution_status") or "").lower()
    execution_not_confirmed = execution_status in {"", "not_contained", "not evidenced in source telemetry", "not_evidenced", "not executed", "not_executed"}
    if execution_not_confirmed and any(term in lower for term in ["containment was executed", "host was isolated", "endpoint was isolated", "isolation was completed", "contained successfully"]):
        issues.append("unsupported_fact_creation:containment_execution")

    impact_text = json.dumps(context.get("data_impact_assessment") or {}, default=str).lower()
    no_data_impact_facts = not any(term in impact_text for term in ["confirmed", "exfiltrat", "accessed", "personal data", "encrypted"])
    if no_data_impact_facts and any(term in lower for term in ["data was exfiltrated", "personal data was exposed", "sensitive data was accessed", "data loss occurred"]):
        issues.append("unsupported_fact_creation:data_impact")
    return list(dict.fromkeys(issues))


def validate_llm_section_quality(section: str, text: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    rules = SECTION_RULES.get(section, {"min_words": 30, "max_words": 250, "require_uncertainty": False, "require_decision": False})
    hard_fail_issues: list[str] = []
    soft_warnings: list[str] = []
    raw = str(text or "").strip()
    lower = raw.lower()
    words = re.findall(r"\b\w+\b", raw)

    if not raw or len(words) < 8:
        hard_fail_issues.append("empty_or_too_short_section")
    elif len(words) < rules["min_words"]:
        soft_warnings.append("section_slightly_short")
    if len(words) > rules["max_words"]:
        soft_warnings.append("section_slightly_long")
    if any(phrase in lower for phrase in PROMPT_LEAKAGE_PHRASES):
        hard_fail_issues.append("prompt_leakage")
    # Reject raw field dumps only when the model starts lines with metadata labels.
    # Normal analyst guidance may mention words such as severity or confidence in prose.
    lines = [line.strip().lower() for line in raw.splitlines() if line.strip()]
    field_dump_lines = sum(1 for line in lines if any(line.startswith(prefix) for prefix in FIELD_DUMP_PREFIXES))
    if field_dump_lines >= 2:
        hard_fail_issues.append("field_dump")
    stripped = lower.rstrip(".。!?)\"' ")
    if stripped.endswith(tuple(BAD_ENDINGS)):
        hard_fail_issues.append("incomplete_sentence")
    if raw.count("(") > raw.count(")"):
        hard_fail_issues.append("unbalanced_parentheses_possible_truncation")
    if raw.endswith((",", ":", "-", ";")):
        hard_fail_issues.append("possibly_truncated")
    if rules.get("require_uncertainty") and not _contains_uncertainty(raw):
        soft_warnings.append("does_not_state_uncertainty")
    if rules.get("require_decision") and not any(term in lower for term in ["approval", "containment", "decision", "closure", "review", "escalation"]):
        soft_warnings.append("does_not_mention_decision_or_containment_status")

    if section == "soc_analyst_review_checklist":
        item_count = _numbered_checklist_count(raw)
        min_items = int(rules.get("min_items", 6))
        max_items = int(rules.get("max_items", 10))
        if item_count < 4:
            hard_fail_issues.append("checklist_too_few_action_items")
        elif item_count < min_items:
            soft_warnings.append("checklist_slightly_short")
        if item_count > max_items + 2:
            soft_warnings.append("checklist_slightly_long")
        if not any(term in lower for term in ["confirm", "validate", "review", "check", "decide", "record"]):
            soft_warnings.append("checklist_not_action_oriented")

    hard_fail_issues.extend(_detect_locked_fact_contradictions(raw, context))
    hard_fail_issues.extend(_detect_unsupported_fact_creation(raw, context))

    if _detect_business_impact_overstatement(raw, context):
        soft_warnings.append("possible_business_impact_overstatement")

    # Soft warnings should warn the analyst, not automatically reject a usable LLM section.
    # Only hard guardrail failures trigger deterministic section fallback.
    accepted = not hard_fail_issues
    return {
        "accepted": accepted,
        "hard_fail_issues": hard_fail_issues,
        "soft_warnings": soft_warnings,
        "issues": hard_fail_issues + soft_warnings,
    }


def assess_llm_section_quality(section: str, text: str) -> tuple[bool, list[str]]:
    """Backward-compatible wrapper for older tests."""
    result = validate_llm_section_quality(section, text, None)
    return bool(result["accepted"]), list(result["issues"])


def _normalise_issue_for_status(issue: str) -> str:
    lower = issue.lower()
    if "unsupported parameter" in lower:
        return "llm_api_unsupported_parameter"
    if "model_not_found" in lower or "does not exist" in lower:
        return "llm_api_model_not_found"
    if "rate limit" in lower or "rate_limit" in lower:
        return "llm_api_rate_limited"
    if issue.startswith("llm_error"):
        return "llm_api_error"
    return issue


def _section_result(status: str, hard: list[str] | None = None, soft: list[str] | None = None, repairs: list[str] | None = None, retry_attempted: bool = False) -> dict[str, Any]:
    hard_fail_issues = hard or []
    soft_warnings = soft or []
    repair_actions = repairs or []
    return {
        "status": status,
        "hard_fail_issues": hard_fail_issues,
        "soft_warnings": soft_warnings,
        "repair_actions": repair_actions,
        "retry_attempted": retry_attempted,
        "issues": hard_fail_issues + soft_warnings,
    }


REPAIRABLE_ISSUES = {
    "does_not_state_uncertainty",
    "checklist_slightly_short",
    "incomplete_sentence",
    "possibly_truncated",
}


def _uncertainty_sentence(context: dict[str, Any] | None) -> str:
    gaps = []
    if context:
        for gap in (context.get("evidence_gaps", []) or [])[:4]:
            value = gap.get("gap") if isinstance(gap, dict) else str(gap)
            if value:
                gaps.append(str(value).strip().rstrip("."))
    if gaps:
        return "Not confirmed in the provided evidence: " + "; ".join(gaps) + "."
    return "Not confirmed in the provided evidence: payload execution, lateral movement, credential access, data exposure, business disruption, and containment completion."


def _trim_to_last_complete_sentence(text: str) -> str:
    raw = str(text or "").strip()
    matches = list(re.finditer(r"[.!?][\)\]\"']?(?=\s|$)", raw))
    if not matches:
        return raw
    end = matches[-1].end()
    return raw[:end].strip()


def _split_checklist_lines(text: str) -> list[str]:
    return [line.strip() for line in str(text or "").splitlines() if line.strip()]


def _repair_checklist(text: str, context: dict[str, Any] | None) -> tuple[str, list[str]]:
    lines = _split_checklist_lines(text)
    repairs: list[str] = []
    if not lines:
        return text, repairs

    numbered = [line for line in lines if re.match(r"^\s*\d+[\).]\s+", line)]
    if len(numbered) >= 8:
        lines = numbered[:8]

    item_count = _numbered_checklist_count("\n".join(lines))
    while item_count < 8:
        next_no = item_count + 1
        if next_no == 5:
            addition = f"{next_no}. Check whether payload execution, lateral movement, credential access, data exposure, and business disruption are not confirmed in the provided evidence."
        elif next_no == 6:
            addition = f"{next_no}. Review unresolved evidence gaps and collect the required endpoint, identity, network, email, or application logs before closure."
        elif next_no == 7:
            addition = f"{next_no}. Decide whether containment approval, escalation, closure, or further investigation is appropriate based only on validated evidence."
        else:
            addition = f"{next_no}. Record the final analyst decision and ensure any disruptive action follows the approval workflow."
        lines.append(addition)
        item_count += 1
        repairs.append("checklist_item_count_repair")

    joined = "\n".join(lines)
    if not _contains_uncertainty(joined):
        lines[-1] = lines[-1].rstrip(".") + " and record any items not confirmed in the provided evidence."
        repairs.append("checklist_uncertainty_repair")
    return "\n".join(lines), list(dict.fromkeys(repairs))


def repair_llm_section(section: str, text: str, quality: dict[str, Any], context: dict[str, Any] | None = None) -> tuple[str, dict[str, Any], list[str]]:
    repaired = str(text or "").strip()
    repairs: list[str] = []
    hard = set(quality.get("hard_fail_issues", []))
    soft = set(quality.get("soft_warnings", []))

    if section == "soc_analyst_review_checklist":
        repaired, checklist_repairs = _repair_checklist(repaired, context)
        repairs.extend(checklist_repairs)
    else:
        if hard.intersection({"incomplete_sentence", "possibly_truncated", "unbalanced_parentheses_possible_truncation"}):
            trimmed = _trim_to_last_complete_sentence(repaired)
            if trimmed and trimmed != repaired:
                repaired = trimmed
                repairs.append("trailing_sentence_repair")
        if "does_not_state_uncertainty" in soft and not _contains_uncertainty(repaired):
            sep = "\n\n" if "\n\n" in repaired else " "
            repaired = repaired.rstrip() + sep + _uncertainty_sentence(context)
            repairs.append("uncertainty_sentence_repair")

    if repairs:
        new_quality = validate_llm_section_quality(section, repaired, context)
        return repaired, new_quality, list(dict.fromkeys(repairs))
    return text, quality, []


def build_validation_retry_prompt(original_prompt: str, section: str, issues: list[str]) -> str:
    issue_set = set(issues)
    instructions: list[str] = [
        "Your previous response did not pass the reporting quality checks.",
        "Rewrite the requested section using only the provided incident facts.",
        "Preserve all incident facts exactly and do not add unsupported evidence.",
        "Do not mention prompts, guardrails, validation checks, retries, or internal system behaviour.",
    ]
    if "does_not_state_uncertainty" in issue_set:
        instructions.append("Include one sentence beginning exactly with: 'Not confirmed in the provided evidence:'.")
    if "section_slightly_short" in issue_set or "empty_or_too_short_section" in issue_set:
        instructions.append("Your previous response was too short. Use the required paragraph count and word range, and add analyst-useful detail about evidence, uncertainty, validation gaps, and next decision points.")
    if "possibly_truncated" in issue_set or "incomplete_sentence" in issue_set or "unbalanced_parentheses_possible_truncation" in issue_set:
        instructions.append("Your previous response appeared incomplete or truncated. Rewrite it completely, more concisely if needed, and end with a complete sentence.")
    if "checklist_slightly_short" in issue_set or "checklist_too_few_action_items" in issue_set:
        instructions.append("For the checklist, return exactly 8 numbered analyst review actions. Each item must begin with Confirm, Validate, Review, Check, Decide, Record, or Escalate.")
    if "possible_business_impact_overstatement" in issue_set:
        instructions.append("Clearly separate confirmed impact from potential impact. Do not claim confirmed disruption, data loss, customer impact, or outage unless it is explicitly present in the incident facts.")
    return original_prompt + "\n\nRetry instruction:\n" + "\n".join(f"- {item}" for item in instructions)


def enhance_narrative(context: dict[str, Any]) -> dict[str, Any]:
    deterministic = deterministic_narrative(context)
    provider = selected_provider()
    model = selected_model()
    result: dict[str, Any] = {
        "deterministic_narrative": deterministic,
        "llm_enhanced_narrative": deterministic.copy(),
        "llm_used": False,
        "llm_provider": provider if settings.USE_LLM else "not_used",
        "llm_model": model if settings.USE_LLM else "not_used",
        "llm_status": "llm_disabled_deterministic_generation",
        "llm_quality_status": "not_used",
        "llm_quality_issues": [],
        "llm_section_results": {},
        "llm_attempt_count": 0,
        "llm_cache_status": "not_used",
    }

    if not settings.USE_LLM:
        for section in ALL_NARRATIVE_FIELDS:
            result["llm_section_results"][section] = _section_result("not_used")
        return result

    accepted = deterministic.copy()
    all_issues: list[str] = []
    any_success = False
    any_warning = False
    any_fallback = False
    any_retry_success = False
    selected_success_provider = provider
    selected_success_model = model
    api_error_count = 0
    attempted_count = 0
    total_attempts = 0

    def _enhance_one_section(section: str) -> dict[str, Any]:
        """Self-contained per-section enhancement — same logic as the original
        inline loop body, but writing into an outcome dict so sections can run
        concurrently. Aggregation happens afterwards in fixed section order,
        keeping the overall result deterministic."""
        oc: dict[str, Any] = {
            "section": section, "output": None, "section_result": None,
            "issues": [], "attempts": 0, "had_retry_calls": False,
            "success": False, "warning": False, "api_error": False,
            "provider": None, "model": None,
        }
        try:
            prompt = build_section_prompt(section, context, deterministic)
            raw_output, used_provider, used_model, retry_issues, attempts = invoke_llm_with_retries(prompt, section=section)
            oc["attempts"] += attempts
            if attempts > 1:
                oc["had_retry_calls"] = True
                oc["issues"].extend(retry_issues)

            raw_output = _normalise_llm_output(raw_output)
            quality = validate_llm_section_quality(section, raw_output, context)
            repaired_output, repaired_quality, repairs = repair_llm_section(section, raw_output, quality, context)

            final_output = repaired_output
            final_quality = repaired_quality
            final_repairs = repairs
            retry_attempted_for_quality = False
            retry_was_used = False

            # If the section still has hard failures, or if it has soft warnings that would reduce quality,
            # perform an issue-specific validation retry before falling back or accepting with warnings.
            # REPORTING_QUALITY_RETRY=hard_only skips retries for cosmetic soft
            # warnings (e.g. "section slightly long") — halves request volume
            # in the common case while hard failures still retry.
            _retry_mode = os.getenv("REPORTING_QUALITY_RETRY", "all").strip().lower()
            initial_issues = list(final_quality.get("hard_fail_issues", []))
            if _retry_mode != "hard_only":
                initial_issues += list(final_quality.get("soft_warnings", []))
            non_retryable = {"prompt_leakage", "field_dump", "locked_fact_contradiction:severity", "locked_fact_contradiction:confidence", "locked_fact_contradiction:classification"}
            should_retry_for_quality = bool(initial_issues) and not any(issue in non_retryable for issue in initial_issues)
            if should_retry_for_quality:
                retry_attempted_for_quality = True
                retry_prompt = build_validation_retry_prompt(prompt, section, initial_issues)
                try:
                    retry_output, retry_provider, retry_model, retry_call_issues, retry_attempts = invoke_llm_with_retries(retry_prompt, section=section)
                    oc["attempts"] += retry_attempts
                    oc["had_retry_calls"] = True
                    oc["issues"].extend(retry_call_issues)
                    retry_output = _normalise_llm_output(retry_output)
                    retry_quality = validate_llm_section_quality(section, retry_output, context)
                    retry_repaired_output, retry_repaired_quality, retry_repairs = repair_llm_section(section, retry_output, retry_quality, context)

                    current_hard = len(final_quality.get("hard_fail_issues", []))
                    current_soft = len(final_quality.get("soft_warnings", []))
                    retry_hard = len(retry_repaired_quality.get("hard_fail_issues", []))
                    retry_soft = len(retry_repaired_quality.get("soft_warnings", []))

                    # Prefer retry if it removes hard failures, reduces warnings, or gives a fully clean accepted section.
                    if (retry_hard < current_hard) or (retry_hard == 0 and retry_soft < current_soft) or (retry_repaired_quality.get("accepted") and not retry_repaired_quality.get("soft_warnings")):
                        final_output = retry_repaired_output
                        final_quality = retry_repaired_quality
                        final_repairs = retry_repairs
                        used_provider = retry_provider
                        used_model = retry_model
                        retry_was_used = True
                except Exception as retry_error:
                    oc["issues"].append(f"{section}:quality_retry_error:{retry_error}")

            hard = list(final_quality["hard_fail_issues"])
            soft = list(final_quality["soft_warnings"])
            if final_quality["accepted"]:
                oc["output"] = final_output
                oc["provider"] = used_provider
                oc["model"] = used_model
                if retry_was_used and final_repairs:
                    status = "llm_retry_successful_after_repair"
                elif retry_was_used:
                    status = "llm_retry_successful"
                elif final_repairs:
                    if "uncertainty_sentence_repair" in final_repairs:
                        status = "llm_used_after_uncertainty_repair"
                    elif "trailing_sentence_repair" in final_repairs:
                        status = "llm_used_after_sentence_repair"
                    elif any(r.startswith("checklist") for r in final_repairs):
                        status = "llm_used_after_checklist_repair"
                    else:
                        status = "llm_used_after_repair"
                elif attempts > 1:
                    status = "llm_retry_successful"
                else:
                    status = "llm_used"

                if soft:
                    oc["section_result"] = _section_result(status + "_with_warning", [], soft, final_repairs, retry_attempted_for_quality)
                    oc["warning"] = True
                    oc["issues"].extend([f"{section}:{issue}" for issue in soft])
                else:
                    oc["section_result"] = _section_result(status, [], [], final_repairs, retry_attempted_for_quality)
                oc["success"] = True
            else:
                oc["section_result"] = _section_result("fallback_used_after_retry_failed" if retry_attempted_for_quality else "fallback_used", hard, soft, final_repairs, retry_attempted_for_quality)
                oc["issues"].extend([f"{section}:{issue}" for issue in hard + soft])
        except Exception as error:
            issue_raw = f"llm_error:{error}"
            issue = _normalise_issue_for_status(issue_raw)
            oc["section_result"] = _section_result("fallback_used", [issue])
            oc["issues"].append(f"{section}:{issue_raw}")
            oc["api_error"] = True
        return oc

    # Sections are independent of each other, so enhance them concurrently —
    # wall time drops from sum(section latencies) to roughly the slowest one.
    # REPORTING_LLM_PARALLEL=1 restores the sequential behaviour.
    sections_to_enhance = [s for s in ALL_NARRATIVE_FIELDS if s in LLM_ENHANCEABLE_FIELDS]
    try:
        _workers = max(1, int(os.getenv("REPORTING_LLM_PARALLEL", "3").strip()))
    except ValueError:
        _workers = 3
    outcomes: dict[str, dict[str, Any]] = {}
    if _workers > 1 and len(sections_to_enhance) > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(_workers, len(sections_to_enhance))) as _pool:
            for oc in _pool.map(_enhance_one_section, sections_to_enhance):
                outcomes[oc["section"]] = oc
    else:
        for _s in sections_to_enhance:
            outcomes[_s] = _enhance_one_section(_s)

    # Deterministic aggregation in canonical section order (matches the
    # original sequential loop's semantics exactly).
    for section in ALL_NARRATIVE_FIELDS:
        if section not in LLM_ENHANCEABLE_FIELDS:
            accepted[section] = deterministic[section]
            result["llm_section_results"][section] = _section_result("deterministic_locked")
            continue
        oc = outcomes[section]
        attempted_count += 1
        total_attempts += oc["attempts"]
        if oc["had_retry_calls"]:
            any_retry_success = True
        all_issues.extend(oc["issues"])
        result["llm_section_results"][section] = oc["section_result"]
        if oc["success"]:
            accepted[section] = oc["output"]
            selected_success_provider = oc["provider"]
            selected_success_model = oc["model"]
            any_success = True
            if oc["warning"]:
                any_warning = True
        else:
            accepted[section] = deterministic[section]
            any_fallback = True
            if oc["api_error"]:
                api_error_count += 1

    result["llm_attempt_count"] = total_attempts

    if any_success:
        _save_cached_narrative(context, accepted, selected_success_provider, selected_success_model)
        result["llm_cache_status"] = "cache_updated"
    elif any_fallback:
        cached = _load_cached_narrative(context)
        if cached:
            accepted = cached
            result["llm_cache_status"] = "cached_report_used"
            result["llm_status"] = "llm_failed_cached_report_used"
            result["llm_quality_status"] = "cached_fallback_used"
            result["llm_enhanced_narrative"] = accepted
            result["llm_used"] = True
            result["llm_provider"] = provider
            result["llm_model"] = model
            result["llm_quality_issues"] = all_issues
            return result
        result["llm_cache_status"] = "cache_miss"

    result["llm_enhanced_narrative"] = accepted
    result["llm_used"] = True
    result["llm_provider"] = selected_success_provider if any_success else provider
    result["llm_model"] = selected_success_model if any_success else model
    result["llm_quality_issues"] = all_issues

    if any_success and not any_fallback:
        if any_retry_success:
            result["llm_status"] = "llm_retry_successful" if not any_warning else "llm_retry_successful_with_warnings"
        else:
            result["llm_status"] = "llm_enhancement_successful" if not any_warning else "llm_enhancement_successful_with_warnings"
        result["llm_quality_status"] = "accepted" if not any_warning else "accepted_with_warnings"
    elif any_success and any_fallback:
        # This now means at least one section had a hard guardrail failure, such as
        # prompt leakage, truncation, field dumping, or empty output. Soft warnings
        # alone are accepted and reported as llm_enhancement_successful_with_warnings.
        result["llm_status"] = "partial_llm_enhancement_with_guardrails"
        result["llm_quality_status"] = "partial_fallback_used_due_to_hard_guardrail_failure"
    else:
        if attempted_count and api_error_count == attempted_count:
            result["llm_status"] = "llm_failed_all_providers_fallback_used"
            result["llm_quality_status"] = "api_error_full_fallback_used"
        else:
            result["llm_status"] = "deterministic_fallback_after_llm_guardrail_rejection"
            result["llm_quality_status"] = "full_fallback_used"

    return result
