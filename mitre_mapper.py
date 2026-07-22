import os
import json
import re
from typing import Dict, List, Any, Optional, Tuple, Union
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

# --- PYDANTIC SCHEMAS FOR INPUT & STRUCTURED OUTPUT ---

class TimelineEvent(BaseModel):
    timestamp: str = Field(default="N/A", description="Event timestamp (ISO string or human-readable format)")
    source: str = Field(default="Unknown", description="Log source type (e.g., Endpoint, Network, Firewall, POP3)")
    user_or_host: str = Field(default="Unknown", description="Target user and/or host associated with the event")
    log_summary: str = Field(description="Raw log text, document summary, or alert details")
    alert_context: Dict[str, Any] = Field(default_factory=dict, description="Additional context such as alert ID, risk score, or raw indicators")

class MitreTTPMapping(BaseModel):
    timeline_phase: str = Field(description="Summary of the timeline phase or activity in chronological order.")
    observed_evidence: str = Field(description="Concrete evidence from logs (e.g., users, hosts, IPs, commands, URLs, filenames).")
    tactic: str = Field(description="MITRE ATT&CK Tactic name (e.g., Initial Access, Execution, Defense Evasion, Lateral Movement).")
    technique_name: str = Field(description="MITRE ATT&CK Technique or Sub-technique Name (e.g., Phishing: Spearphishing Link).")
    technique_id: str = Field(description="Precise MITRE ATT&CK ID including sub-technique if applicable (e.g., T1566.002).")

class IncidentMitreAnalysis(BaseModel):
    incident_id: str = Field(description="Unique identifier of the correlated incident.")
    attack_chain_summary: str = Field(description="Chronological narrative of the overall attack chain progression across all events.")
    mappings: List[MitreTTPMapping] = Field(description="List of MITRE ATT&CK TTP mappings in strict chronological order (first to last).")


# --- INPUT HANDLING & NORMALIZATION ---

def parse_event_timestamp(event_dict: Dict[str, Any]) -> str:
    """Extracts a normalized timestamp string from event dict/metadata."""
    meta = event_dict.get("metadata", {})
    if isinstance(meta, dict):
        if "timestamp_str" in meta and meta["timestamp_str"]:
            return str(meta["timestamp_str"])
        if "timestamp_epoch" in meta and meta["timestamp_epoch"]:
            return str(meta["timestamp_epoch"])
    for ts_key in ["timestamp", "timestamp_str", "created_at", "time"]:
        if ts_key in event_dict and event_dict[ts_key]:
            return str(event_dict[ts_key])
    return "N/A"

def parse_user_host(event_dict: Dict[str, Any]) -> str:
    """Extracts user/host information from event dict/metadata."""
    meta = event_dict.get("metadata", {}) if isinstance(event_dict.get("metadata"), dict) else {}
    username = meta.get("username") or event_dict.get("username") or event_dict.get("user") or "Unknown"
    hostname = meta.get("hostname") or event_dict.get("hostname") or event_dict.get("host") or "Unknown"
    
    parts = []
    if username != "Unknown":
        parts.append(f"user: {username}")
    if hostname != "Unknown":
        parts.append(f"host: {hostname}")
    
    return " | ".join(parts) if parts else "Unknown"

def normalize_incident_input(incident_input: Any) -> Tuple[str, List[TimelineEvent]]:
    """
    Ingests a correlated incident object (Pydantic model, dictionary, or event list)
    and returns a tuple of (incident_id, List[TimelineEvent]).
    """
    incident_id = "Incident-Unknown"
    events: List[TimelineEvent] = []

    # Case 1: Pydantic Incident object (from sync_engine / correlation_engine)
    if hasattr(incident_input, "id") and hasattr(incident_input, "raw_alerts"):
        incident_id = getattr(incident_input, "id", "Incident-Unknown")
        raw_alerts = getattr(incident_input, "raw_alerts", [])
        for alert in raw_alerts:
            if isinstance(alert, dict):
                doc = alert.get("document") or alert.get("summary") or alert.get("raw_log") or json.dumps(alert)
                meta = alert.get("metadata", {}) if isinstance(alert.get("metadata"), dict) else {}
                source = meta.get("source_type") or alert.get("source") or "Default"
                ts = parse_event_timestamp(alert)
                uh = parse_user_host(alert)
                events.append(TimelineEvent(
                    timestamp=ts,
                    source=str(source),
                    user_or_host=uh,
                    log_summary=str(doc),
                    alert_context=alert
                ))
            elif isinstance(alert, TimelineEvent):
                events.append(alert)

    # Case 2: Dictionary input
    elif isinstance(incident_input, dict):
        incident_id = incident_input.get("id") or incident_input.get("incident_id") or "Incident-Unknown"
        raw_alerts = incident_input.get("raw_alerts") or incident_input.get("timeline") or incident_input.get("events") or []
        for alert in raw_alerts:
            if isinstance(alert, dict):
                doc = alert.get("document") or alert.get("summary") or alert.get("log_summary") or alert.get("raw_log") or json.dumps(alert)
                meta = alert.get("metadata", {}) if isinstance(alert.get("metadata"), dict) else {}
                source = meta.get("source_type") or alert.get("source") or alert.get("source_type") or "Default"
                ts = parse_event_timestamp(alert)
                uh = parse_user_host(alert)
                events.append(TimelineEvent(
                    timestamp=ts,
                    source=str(source),
                    user_or_host=uh,
                    log_summary=str(doc),
                    alert_context=alert
                ))
            elif isinstance(alert, TimelineEvent):
                events.append(alert)

    # Case 3: Direct List of TimelineEvent or dicts
    elif isinstance(incident_input, list):
        for idx, item in enumerate(incident_input):
            if isinstance(item, TimelineEvent):
                events.append(item)
            elif isinstance(item, dict):
                doc = item.get("log_summary") or item.get("document") or item.get("summary") or json.dumps(item)
                ts = parse_event_timestamp(item)
                uh = parse_user_host(item)
                source = item.get("source") or item.get("source_type") or "Default"
                events.append(TimelineEvent(
                    timestamp=ts,
                    source=str(source),
                    user_or_host=uh,
                    log_summary=str(doc),
                    alert_context=item
                ))

    # Sort events chronologically if epoch/timestamp metadata is available
    def get_sort_key(ev: TimelineEvent):
        meta = ev.alert_context.get("metadata", {}) if isinstance(ev.alert_context, dict) else {}
        if isinstance(meta, dict) and "timestamp_epoch" in meta and meta["timestamp_epoch"]:
            return float(meta["timestamp_epoch"])
        return 0.0

    events.sort(key=get_sort_key)
    return incident_id, events


# --- PROMPT TEMPLATE ---

SYSTEM_PROMPT = """You are a Principal SOC Cyber Threat Intelligence & Incident Response Specialist.
Your task is to analyze an entire correlated incident timeline as a SINGLE, HOLISTIC attack progression and map the attack steps to precise MITRE ATT&CK TTPs.

CRITICAL INSTRUCTIONS & CONSTRAINTS:
1. COMPREHENSIVE CHRONOLOGICAL ATTACK CHAIN NARRATIVE (`attack_chain_summary`):
   - You MUST construct a detailed, unified chronological narrative that weaves together the entire attack progression into a comprehensive timeline.
   - For every stage in the sequence, clearly specify:
     a) WHAT HAPPENED: Detailed explanation of the threat activity and phase progression.
     b) WHEN: Explicit event timestamps (ISO 8601 or epoch).
     c) RECORDED IOCs & ASSETS: Concrete forensic indicators including affected usernames, hostnames, IP addresses, domain names, file paths, cryptographic hashes (MD5/SHA256), URLs, and executed command lines.
     d) ATTACK LINKAGE: Explain how each action enabled the subsequent attack stage (e.g. initial phishing link -> payload download -> AppData execution -> command shell spawning -> SMB lateral movement).

2. HOLISTIC INCIDENT-LEVEL ANALYSIS:
   - DO NOT evaluate events in isolation or alert-by-alert.
   - Evaluate how the events connect together across time to form a multi-stage attack chain.

3. PRECISE SUB-TECHNIQUE RESOLUTION:
   - Always resolve precise sub-techniques (e.g., 'T1566.002' for Spearphishing Link or 'T1566.001' for Spearphishing Attachment, instead of generic 'T1566'; 'T1569.002' for Service Execution instead of 'T1569'; 'T1021.002' for SMB/Windows Admin Shares instead of 'T1021').
   - Use standard MITRE ATT&CK Technique names and sub-technique IDs.

4. CHRONOLOGICAL ORDERING:
   - The mapped attack steps in `mappings` MUST be strictly ordered chronologically from the initial compromise to the final observed activity.

5. STRUCTURED OUTPUT:
   - Return your findings matching the required JSON schema with fields: `incident_id`, `attack_chain_summary`, and `mappings`.
   - Each mapping in `mappings` must include:
     - `timeline_phase`: Concise phase description of the activity step.
     - `observed_evidence`: Concrete evidence extracted from the logs (users, hosts, commands, URLs, IPs, file paths).
     - `tactic`: MITRE ATT&CK Tactic.
     - `technique_name`: Precise MITRE ATT&CK Technique / Sub-technique Name.
     - `technique_id`: Precise MITRE ATT&CK ID (e.g., T1566.002).
"""

HUMAN_PROMPT_TEMPLATE = """Correlated Incident ID: {incident_id}

Full Correlated Event Timeline Sequence (Context Block):
========================================================
{event_sequence_text}

Analyze the full event sequence holistically and generate the MITRE ATT&CK TTP mapping and comprehensive chronological narrative detailing what happened, when, and all recorded IOCs.
"""


def format_event_sequence(events: List[TimelineEvent]) -> str:
    """Formats event sequence into a single context block for the LLM prompt."""
    blocks = []
    for idx, ev in enumerate(events, 1):
        ctx_str = ""
        if ev.alert_context:
            meta = ev.alert_context.get("metadata", {}) if isinstance(ev.alert_context, dict) else {}
            if isinstance(meta, dict):
                tactic = meta.get("tactic", "N/A")
                technique = meta.get("technique", "N/A")
                ips = meta.get("ips", "")
                ctx_str = f" Context: tactic={tactic}, technique={technique}, ips={ips}"
        
        block = (
            f"[Event #{idx}]\n"
            f"Timestamp: {ev.timestamp}\n"
            f"Source: {ev.source}\n"
            f"User/Host: {ev.user_or_host}\n"
            f"Log Details: {ev.log_summary}{ctx_str}"
        )
        blocks.append(block)
    return "\n\n".join(blocks)


# --- RESPONSE PARSER & MARKDOWN TABLE GENERATOR ---

def generate_markdown_table(analysis: IncidentMitreAnalysis) -> str:
    """
    Renders the IncidentMitreAnalysis into a formatted Markdown summary table with headers:
    | Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
    """
    lines = []
    lines.append("| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |")
    lines.append("| --- | --- | --- | --- | --- |")

    for item in analysis.mappings:
        phase = item.timeline_phase.replace("|", "\\|")
        evidence = item.observed_evidence.replace("|", "\\|")
        tactic = item.tactic.replace("|", "\\|")
        tech_name = item.technique_name.replace("|", "\\|")
        tech_id = item.technique_id.replace("|", "\\|")
        lines.append(f"| {phase} | {evidence} | {tactic} | {tech_name} | {tech_id} |")

    return "\n".join(lines)


# --- FALLBACK HEURISTIC MAPPER (FOR OFFLINE / MOCK RUNS) ---

def fallback_heuristic_mapper(incident_id: str, events: List[TimelineEvent]) -> IncidentMitreAnalysis:
    """Generates a structured IncidentMitreAnalysis using incident-level heuristics when LLM is unavailable."""
    mappings = []
    narrative_lines = [f"Comprehensive Chronological Attack Narrative for Incident {incident_id}:"]
    
    for idx, ev in enumerate(events, 1):
        summary_lower = ev.log_summary.lower()
        meta = ev.alert_context.get("metadata", {}) if isinstance(ev.alert_context, dict) else {}
        ts = ev.timestamp
        uh = ev.user_or_host
        
        # Extract IOCs
        iocs = []
        if isinstance(meta, dict):
            if meta.get("ips"): iocs.append(f"IPs: {meta['ips']}")
            if meta.get("domains"): iocs.append(f"Domains: {meta['domains']}")
            if meta.get("sha256s"): iocs.append(f"SHA256: {meta['sha256s']}")
            if meta.get("md5s"): iocs.append(f"MD5: {meta['md5s']}")
            if meta.get("emails"): iocs.append(f"Emails: {meta['emails']}")

        ioc_str = f" | Recorded IOCs: ({', '.join(iocs)})" if iocs else ""

        # Initial Access / Phishing
        if "spearphishing" in summary_lower or "phishing" in summary_lower or "email" in summary_lower:
            if "link" in summary_lower or "http" in summary_lower:
                tactic = "Initial Access"
                tech_name = "Phishing: Spearphishing Link"
                tech_id = "T1566.002"
            else:
                tactic = "Initial Access"
                tech_name = "Phishing: Spearphishing Attachment"
                tech_id = "T1566.001"
            phase = f"Initial Access - Email Activity ({ts})"
            evidence = f"{uh} received email/attachment: {ev.log_summary[:80]}..."
            narrative_lines.append(f"- Step {idx} [{ts}]: Initial Access - {uh} was targeted via phishing email. {ev.log_summary}{ioc_str}")
        
        # Outbound / Evasion / Unsigned AppData
        elif "appdata" in summary_lower or "unsigned" in summary_lower or "outbound" in summary_lower:
            tactic = "Defense Evasion"
            tech_name = "Hide Artifacts: Conceal Execution Directory"
            tech_id = "T1564.001"
            phase = f"Defense Evasion - Execution from AppData ({ts})"
            evidence = f"{uh} executed binary from AppData temp directory"
            narrative_lines.append(f"- Step {idx} [{ts}]: Defense Evasion / Execution - {uh} executed suspicious binary from AppData temp directory. {ev.log_summary}{ioc_str}")

        # Command Shell / Service execution
        elif "cmd.exe" in summary_lower or "command shell" in summary_lower or "services.exe" in summary_lower:
            tactic = "Execution"
            tech_name = "System Services: Service Execution"
            tech_id = "T1569.002"
            phase = f"Execution - Command Shell Spawned ({ts})"
            evidence = f"services.exe spawned cmd.exe on {uh}"
            narrative_lines.append(f"- Step {idx} [{ts}]: Execution - System services spawned command shell (cmd.exe) on {uh}. {ev.log_summary}{ioc_str}")

        # Lateral Movement / Net utility / SMB
        elif "net use" in summary_lower or "lateral movement" in summary_lower or "net.exe" in summary_lower:
            tactic = "Lateral Movement"
            tech_name = "Remote Services: SMB/Windows Admin Shares"
            tech_id = "T1021.002"
            phase = f"Lateral Movement - SMB Connection ({ts})"
            evidence = f"{uh} used net use to connect to remote SMB share"
            narrative_lines.append(f"- Step {idx} [{ts}]: Lateral Movement - Attacker established remote SMB share connection from {uh} using credentials. {ev.log_summary}{ioc_str}")

        else:
            tactic = str(meta.get("tactic", "Execution")).capitalize()
            tech_name = str(meta.get("technique", "Command and Scripting Interpreter: PowerShell")).capitalize()
            tech_id = "T1059.001"
            phase = f"Attack Phase #{idx} ({ts})"
            evidence = f"Activity on {uh}: {ev.log_summary[:80]}..."
            narrative_lines.append(f"- Step {idx} [{ts}]: {tactic} - Security event detected on {uh}. {ev.log_summary}{ioc_str}")

        mappings.append(MitreTTPMapping(
            timeline_phase=phase,
            observed_evidence=evidence,
            tactic=tactic,
            technique_name=tech_name,
            technique_id=tech_id
        ))

    narrative = "\n".join(narrative_lines)

    return IncidentMitreAnalysis(
        incident_id=incident_id,
        attack_chain_summary=narrative,
        mappings=mappings
    )


# --- MAIN HANDLER FUNCTION ---

def map_incident_mitre_ttps(
    incident_input: Any,
    llm: Optional[Any] = None,
    mock_response: Optional[Union[Dict[str, Any], IncidentMitreAnalysis]] = None
) -> Tuple[IncidentMitreAnalysis, str]:
    """
    Main handler taking correlated timeline input and producing structured MITRE ATT&CK mapping
    and a formatted Markdown summary table.

    Args:
        incident_input: Correlated incident object, dict, or list of timeline events.
        llm: Optional LangChain ChatOpenAI or compatible LLM instance.
        mock_response: Optional mock structured response or dict for testing/offline use.

    Returns:
        Tuple of (IncidentMitreAnalysis, markdown_table_string)
    """
    incident_id, events = normalize_incident_input(incident_input)

    # 1. Mock / Explicit Response Override
    if mock_response is not None:
        if isinstance(mock_response, IncidentMitreAnalysis):
            analysis = mock_response
        elif isinstance(mock_response, dict):
            analysis = IncidentMitreAnalysis.model_validate(mock_response)
        else:
            raise ValueError("mock_response must be an IncidentMitreAnalysis or dict matching schema.")
        return analysis, generate_markdown_table(analysis)

    # 2. LLM Orchestration
    if llm is None and os.getenv("OPENAI_API_KEY"):
        try:
            from langchain_openai import ChatOpenAI
            llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, openai_api_key=os.getenv("OPENAI_API_KEY"))
        except Exception:
            llm = None

    if llm is not None:
        from langchain_core.prompts import ChatPromptTemplate
        event_sequence_text = format_event_sequence(events)
        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT),
            ("human", HUMAN_PROMPT_TEMPLATE)
        ])

        try:
            structured_chain = prompt | llm.with_structured_output(IncidentMitreAnalysis, method="json_schema")
            analysis = structured_chain.invoke({
                "incident_id": incident_id,
                "event_sequence_text": event_sequence_text
            })
            return analysis, generate_markdown_table(analysis)
        except Exception as e:
            # Fallback to standard invoke if structured output chain failed
            try:
                chain = prompt | llm
                res = chain.invoke({
                    "incident_id": incident_id,
                    "event_sequence_text": event_sequence_text
                })
                text_content = res.content if hasattr(res, "content") else str(res)
                # Parse JSON out of markdown block if present
                json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text_content, re.DOTALL)
                raw_json = json_match.group(1) if json_match else text_content
                parsed_dict = json.loads(raw_json)
                analysis = IncidentMitreAnalysis.model_validate(parsed_dict)
                return analysis, generate_markdown_table(analysis)
            except Exception as inner_e:
                print(f"[!] LLM MITRE Mapping call failed: {e} / {inner_e}. Using fallback mapper.")

    # 3. Fallback Heuristic Mapping if LLM is not provided or fails
    analysis = fallback_heuristic_mapper(incident_id, events)
    return analysis, generate_markdown_table(analysis)
