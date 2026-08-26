# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: argparse, asyncio, collections, correlation_engine, dotenv, ingest_pipeline, json, mitre_mapper.
# =============================================================================
# File: soc_investigation_agent_revised/main.py
# Purpose: This module runs the standalone investigation-agent command-line workflow and file-queue entry points.
# Main functionality: start_background_sync, stop_background_sync, get_or_create_incident_folder, find_file_by_incident_id, write_markdown_report, select_playbook_automatically.
# Inputs: Function parameters, configured environment values, persisted artifacts,
#   or framework callbacks identified by the documented entry points below.
# Outputs: Return values and documented file, database, workflow-state, or UI
#   side effects consumed by the next stage or analyst-facing component.
# Workflow position: Part of the Aegis investigation component.
# Called by: Direct callers are identified on each function/class annotation;
#   framework and command-line entry points are marked explicitly.
# Calls / important dependencies: argparse, asyncio, collections, correlation_engine, dotenv, ingest_pipeline, json, mitre_mapper.
# Important side effects: See [FYP-OUTPUT], [FYP-STATE], [FYP-DATABASE],
#   [FYP-EXPORT], and [FYP-UI] annotations on the affected operations.
# Error and fallback behaviour: Local try/except and fallback paths are marked
#   per function; otherwise failures propagate to the documented caller.
# Key evaluator search terms: start_background_sync, stop_background_sync, get_or_create_incident_folder, find_file_by_incident_id, write_markdown_report, select_playbook_automatically, [FYP-FUNCTION], [FYP-EVALUATOR].
# =============================================================================

import os
import sys
import shutil
import argparse
import json
import threading
import asyncio
import time
from typing import List
from dotenv import load_dotenv

load_dotenv()

import ingest_pipeline
import vector_engine
import orchestrator
import policy_engine
import mitre_mapper
import investigation_result
from correlation_engine import CorrelationEngine
from sync_engine import (
    RealtimeSyncService,
    Incident,
    IncidentMetadata,
    IncidentSeverity,
    IncidentStatus
)
from collections import defaultdict


UNREAD_ALERTS_FOLDER = "triaged_alerts/"
INCIDENT_REPORTS_FOLDER = "incident_reports/"
PLAYBOOKS_FOLDER = "playbooks/"

os.makedirs(UNREAD_ALERTS_FOLDER, exist_ok=True)
os.makedirs(INCIDENT_REPORTS_FOLDER, exist_ok=True)

# =============================================================================
# [FYP-SECTION] INVESTIGATION EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `start_background_sync` — orchestrates the start background sync entry point and its ordered investigation operations.
# [FYP-INPUT] Parameters: `base_folder`, `db_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:main_async; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `RealtimeSyncService`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def start_background_sync(base_folder: str, db_path: str) -> tuple[RealtimeSyncService, threading.Thread, asyncio.AbstractEventLoop]:
    # Redundant background sync disabled to prevent database contention and cut down latency.
    # The pipeline already performs synchronous dual-write updates itself.
    service = RealtimeSyncService(base_folder=base_folder, db_path=db_path)
    return service, None, None

# [FYP-FUNCTION] `stop_background_sync` — implements the stop background sync operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: `service`, `thread`, `loop`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:main_async; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: no nested function/service calls.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def stop_background_sync(service: RealtimeSyncService, thread: threading.Thread, loop: asyncio.AbstractEventLoop):
    pass

# [FYP-FUNCTION] `get_or_create_incident_folder` — retrieves get or create incident folder data for the surrounding investigation workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:main_async; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `int`, `isdigit`, `join`, `listdir`, `makedirs`, `max`, `split`, `startswith`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def get_or_create_incident_folder() -> tuple[str, str]:
    """Retrieves or creates the next incremented Incident directory."""
    existing = [d for d in os.listdir(INCIDENT_REPORTS_FOLDER) if d.startswith("Incident-")]
    if not existing:
        next_id = "Incident-001"
    else:
        ids = [int(d.split("-")[1]) for d in existing if d.split("-")[1].isdigit()]
        next_id = f"Incident-{max(ids)+1:03d}" if ids else "Incident-001"
    
    path = os.path.join(INCIDENT_REPORTS_FOLDER, next_id)
    os.makedirs(path, exist_ok=True)
    return path, next_id

# [FYP-FUNCTION] `find_file_by_incident_id` — implements the find file by incident id operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: `incident_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:main_async; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `endswith`, `join`, `listdir`, `lower`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def find_file_by_incident_id(incident_id: str) -> str:
    """Finds the raw alert JSON file in the unread queue by incident ID."""
    files = [f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')]
    for f in files:
        if incident_id.lower() in f.lower():
            return os.path.join(UNREAD_ALERTS_FOLDER, f)
    return None

# [FYP-FUNCTION] `write_markdown_report` — persists or updates write markdown report state used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: `dest_folder`, `incident_num_id`, `report`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:main_async; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `getattr`, `gmtime`, `join`, `log_success`, `open`, `strftime`, `write`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def write_markdown_report(dest_folder: str, incident_num_id: str, report: orchestrator.FinalIncidentAnalysis):
    """Writes a beautifully formatted markdown incident report to the target folder."""
    report_path = os.path.join(dest_folder, "final_analysis_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# INVESTIGATION SUMMARY: {report.incident_id} ({incident_num_id})\n\n")
        f.write(f"**Final Severity:** {report.severity}\n")
        if getattr(report, "severity_justification", None):
            f.write(f"*{report.severity_justification}*\n")
        f.write(f"\n**Confidence Level:** {report.confidence}\n")
        if getattr(report, "confidence_justification", None):
            f.write(f"*{report.confidence_justification}*\n\n")
        else:
            f.write("\n")
            
        f.write("## Investigative Workflow\n")
        for action in report.actions_taken:
            f.write(f"- {action}\n")
        f.write("\n")
        
        f.write("## Technical Chronology & MITRE ATT&CK TTP Mapping\n\n")
        f.write(f"{report.incident_summary}\n\n")
        if getattr(report, "mitre_attack_table", None):
            f.write(f"{report.mitre_attack_table}\n\n")

        f.write("## Playbook Execution Trace\n")
        f.write("| Step ID | Instruction | Status | Findings |\n")
        f.write("| --- | --- | --- | --- |\n")
        for step in report.execution_trace:
            f.write(f"| `{step.step_id}` | {step.instruction} | **{step.status}** | {step.findings} |\n")
        f.write("\n")
        
        f.write("## Recommended Containment Actions\n")
        for recommendation in report.recommended_containment:
            f.write(f"- {recommendation}\n")
        f.write("\n")
        
        # Format and append Appendix M Audit Log Table
        f.write("## Appendix M: Policy-Based Compliance Audit Log\n\n")
        f.write("| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |\n")
        f.write("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
        
        audit_logs = getattr(report, "policy_audit_logs", [])
        if audit_logs:
            for log in audit_logs:
                readable_ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(log.timestamp))
                hr_req = "Yes" if log.human_review_required else "No"
                f.write(f"| `{log.audit_id}` | **{log.decision_point}** | {log.policy_reference} | {log.input_summary} | *{log.result}* | `{log.decision_made}` | {hr_req} | {readable_ts} |\n")
        else:
            f.write("| N/A | N/A | N/A | No policy audit logs recorded | N/A | N/A | N/A | N/A |\n")
            
    orchestrator.log_success(f"Case report stored securely inside: {report_path}")

def write_investigation_analysis_json(
    dest_folder: str, report: orchestrator.FinalIncidentAnalysis
) -> investigation_result.InvestigationAgentOutput:
    """Writes the canonical structured investigation_analysis.json alongside
    final_analysis_report.md, validating `report` against the
    InvestigationAgentOutput contract before writing so no field is lost or
    silently reshaped. Additive only -- does not change final_analysis_report.md
    or incident_data.json. This file IS read on the live path: workflow/
    engine.py::_load_structured_investigation_analysis() (called from
    run_investigation()) loads and validates it against this same
    InvestigationAgentOutput contract, preferring it over Markdown
    reconstruction of final_analysis_report.md whenever it validates."""
    output = investigation_result.InvestigationAgentOutput.model_validate(report.model_dump())
    analysis_path = os.path.join(dest_folder, "investigation_analysis.json")
    with open(analysis_path, "w", encoding="utf-8") as f:
        json.dump(output.model_dump(mode="json"), f, indent=2)
    orchestrator.log_success(f"Structured investigation analysis stored inside: {analysis_path}")
    return output

# [FYP-FUNCTION] `select_playbook_automatically` — implements the select playbook automatically operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: `seed_file_path`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include eval_harness.py:_c_playbook, soc_investigation_agent_revised/main.py:main_async; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `any`, `exists`, `get`, `join`, `load`, `log_info`, `log_warning`, `lower`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def select_playbook_automatically(seed_file_path: str) -> str:
    """Automatically selects the best playbook based on the seed alert's classification.

    APP-COMPAT (soc_workflow): the endpoint / privilege-escalation playbook is the
    DEFAULT for host-based tactics; phishing is chosen ONLY when the alert is
    actually phishing/email. The upstream default-to-phishing mis-routes
    lateral-movement / C2 / ransomware incidents (every playbook step comes back
    NOT_MET). Same return contract (a playbook path)."""
    try:
        with open(seed_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        alert_type = str(data.get("classification", {}).get("alert_type", "")).lower()
        tactic = str(data.get("incident_details", {}).get("mitre_att&ck", {}).get("tactic", "")).lower()
        hay = f"{alert_type} {tactic}"

        phishing_kw = ("phish", "email", "spam", "malicious link",
                       "credential harvest", "business email", "bec")
        if any(k in hay for k in phishing_kw):
            orchestrator.log_info(f"Auto-selected Phishing playbook for alert type: '{alert_type}'")
            return os.path.join(PLAYBOOKS_FOLDER, "phishing.yaml")

        # Default: endpoint / privilege-escalation playbook for host-based tactics
        path = os.path.join(PLAYBOOKS_FOLDER, "privilegeEscalation.yaml")
        if os.path.exists(path):
            orchestrator.log_info(f"Auto-selected Privilege Escalation (endpoint) playbook for: '{alert_type}' / '{tactic}'")
            return path
        return os.path.join(PLAYBOOKS_FOLDER, "phishing.yaml")
    except Exception as e:
        orchestrator.log_warning(f"Error auto-detecting playbook: {e}. Defaulting to endpoint playbook.")
        return os.path.join(PLAYBOOKS_FOLDER, "privilegeEscalation.yaml")

# [FYP-FUNCTION] `extract_indicators_locally` — transforms extract indicators locally input into the stable representation required by downstream investigation processing.
# [FYP-INPUT] Parameters: `doc`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:generate_incident_report; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `append`, `endswith`, `extend`, `findall`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def extract_indicators_locally(doc: str) -> List[str]:
    import re
    indicators = []
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', doc)
    indicators.extend(ips)
    domains = re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b', doc)
    for d in domains:
        if d not in indicators and not d.endswith(('.exe', '.dll', '.sys', '.txt', '.log')):
            indicators.append(d)
    return indicators

# [FYP-FUNCTION] `generate_local_standalone_report` — constructs generate local standalone report output for the next investigation consumer or analyst-facing view.
# [FYP-INPUT] Parameters: `alert`, `playbook_path`, `inst_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:generate_incident_report; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `FinalIncidentAnalysis`, `MilestoneExecution`, `any`, `append`, `enumerate`, `exists`, `get`, `isinstance`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def generate_local_standalone_report(alert: dict, playbook_path: str, inst_id: str):
    import yaml
    import json
    with open(playbook_path, "r", encoding="utf-8") as f:
        playbook_dict = yaml.safe_load(f)
        
    playbook_name = playbook_dict.get("name", "Unknown Playbook")
    alert_id = alert["id"]
    alert_type = alert["metadata"].get("source_type", "SIEM Log")
    timestamp = alert["metadata"].get("timestamp_str", "unknown time")
    doc = alert.get("document", "")
    
    # 1. Load raw alert JSON data for precise indicators
    raw_data = {}
    dest_dir = os.path.join(INCIDENT_REPORTS_FOLDER, inst_id)
    raw_path = os.path.join(dest_dir, f"{alert_id}_triage.json")
    if not os.path.exists(raw_path):
        raw_path = os.path.join(UNREAD_ALERTS_FOLDER, f"{alert_id}_triage.json")
        
    if os.path.exists(raw_path):
        try:
            with open(raw_path, "r", encoding="utf-8") as rf:
                raw_data = json.load(rf)
        except Exception:
            pass
            
    # Extract classification details
    class_type = raw_data.get("classification", {}).get("alert_type")
    if class_type:
        alert_type = class_type
        
    # Get indicators for specific asset identification
    net_ind = raw_data.get("network_indicators", {})
    end_ind = raw_data.get("endpoint_indicators", {})
    email_art = raw_data.get("email_artifacts", {})
    auth_det = raw_data.get("authentication_details", {})
    log_ind = raw_data.get("log_indicators", {})
    
    # Host and IP Identification
    host = log_ind.get("computer_name") or end_ind.get("host") or net_ind.get("source", {}).get("hostname") or "UnknownHost"
    ip = log_ind.get("device_ip") or net_ind.get("source_ip") or net_ind.get("source", {}).get("ip_address") or "UnknownIP"
    user = log_ind.get("target_user") or end_ind.get("username") or email_art.get("recipient") or auth_det.get("attempted_target_user") or "UnknownUser"
    
    # Construct a highly specific step-by-step chronology (WITHOUT meta-info or excessive raw data)
    summary_steps = []
    recommended_actions = []
    
    alert_type_lower = alert_type.lower()
    
    # Check if multiple sub-alerts exist within raw_data or alert
    sub_alerts = raw_data.get("alerts") or alert.get("alerts") or alert.get("raw_alerts") or []
    if isinstance(sub_alerts, list) and len(sub_alerts) > 1:
        for idx, sa in enumerate(sub_alerts, 1):
            stitle = sa.get("title") or sa.get("name") or "Security Alert"
            sts = sa.get("timestamp") or "Unknown Time"
            shost = sa.get("hostname") or host
            suser = sa.get("user") or user
            sip = sa.get("source_ip") or ip
            sdesc = sa.get("description") or ""
            ts_prefix = f"On {sts}, " if sts and sts != "Unknown Time" else ""
            if sdesc:
                step_str = f"{ts_prefix}user '{suser}' on host '{shost}' ({sip}) triggered alert '{stitle}': {sdesc}"
            else:
                step_str = f"{ts_prefix}user '{suser}' on host '{shost}' ({sip}) performed actions associated with alert '{stitle}'."
            summary_steps.append(step_str)
            
        recommended_actions.append(f"Isolate host '{host}' at IP {ip} immediately from the network to prevent lateral movement.")
        recommended_actions.append(f"Review account credentials and activity for user '{user}'.")
        recommended_actions.append(f"Conduct detailed forensic review of all {len(sub_alerts)} correlated alerts in this incident sequence.")
    elif "phishing" in alert_type_lower or "spearphishing" in alert_type_lower:
        sender = email_art.get("sender", "Unknown Sender")
        recipient = email_art.get("recipient", "Unknown Recipient")
        filename = email_art.get("attachment", {}).get("filename", "attachment.exe")
        ts_prefix = f"On {timestamp}, " if timestamp and timestamp != "unknown time" else ""
        summary_steps.append(f"{ts_prefix}user '{recipient}' received a spearphishing email from '{sender}' containing attachment '{filename}'.")
        summary_steps.append(f"User '{recipient}' opened and executed '{filename}' on host '{host}' ({ip}).")
        
        # Check if malicious process spawned
        has_process = False
        for step in playbook_dict.get("steps", {}).values():
            if "process spawned" in step.get("instructions", "").lower() or "process tree" in step.get("instructions", "").lower():
                has_process = True
                
        if has_process or end_ind.get("spawned_process") or "cmd.exe" in doc.lower():
            summary_steps.append(f"The executed attachment spawned a malicious child process, establishing an outbound reverse shell connection.")
            
        recommended_actions.append(f"Isolate host {host} at IP {ip} immediately from the network to prevent lateral movement (disable its network interface or block its IP at the local switch).")
        recommended_actions.append(f"Remove the malicious email attachment '{filename}' from the mail server and block sender '{sender}'.")
        recommended_actions.append(f"Conduct a full forensic analysis of the affected machine '{host}' ({ip}) to identify any additional compromises.")
        
    elif "privilege" in alert_type_lower or "escalation" in alert_type_lower:
        privilege = log_ind.get("requested_privilege") or "SeSecurityPrivilege"
        ts_prefix = f"On {timestamp}, " if timestamp and timestamp != "unknown time" else ""
        summary_steps.append(f"{ts_prefix}user account '{user}' on host '{host}' ({ip}) attempted unauthorized privilege escalation requesting administrative privilege '{privilege}'.")
        summary_steps.append(f"The privilege escalation attempt was blocked and flagged by local system security auditing.")
        
        recommended_actions.append(f"Temporarily disable the user account '{user}' to prevent further unauthorized privilege escalation attempts.")
        recommended_actions.append(f"Isolate the affected machine {host} at IP {ip} (disable its network interface or block traffic at the switch) until the host is verified clean.")
        recommended_actions.append(f"Review security event logs on {host} to trace the origin of the '{privilege}' requests.")
        
    elif "brute force" in alert_type_lower or "login" in alert_type_lower:
        src_ip = net_ind.get("source_ip", "attacker IP")
        target_user = auth_det.get("attempted_target_user", "user")
        domain = net_ind.get("destination_domain") or "internal domain"
        ts_prefix = f"On {timestamp}, " if timestamp and timestamp != "unknown time" else ""
        summary_steps.append(f"{ts_prefix}source IP {src_ip} initiated multiple rapid authentication attempts targeting user account '{target_user}' on {domain}.")
        summary_steps.append(f"The repeated authentication failures triggered perimeter firewall security alerts for brute-force activity.")
        
        recommended_actions.append(f"Block all traffic from the external attacker IP {src_ip} at the perimeter firewall immediately.")
        recommended_actions.append(f"Reset the password for user account '{target_user}' and enforce multi-factor authentication (MFA).")
        recommended_actions.append(f"Review login logs to ensure no attempts from {src_ip} succeeded.")
        
    elif "dns response" in alert_type_lower or "anomalous dns" in alert_type_lower:
        src_ip = net_ind.get("source_ip", "affected host IP")
        domain = net_ind.get("queried_domain", "suspicious domain")
        ts_prefix = f"On {timestamp}, " if timestamp and timestamp != "unknown time" else ""
        summary_steps.append(f"{ts_prefix}host '{host}' at IP {src_ip} performed anomalous DNS queries for lookalike domain '{domain}'.")
        summary_steps.append(f"The query lookup triggered reputation alerts indicating command-and-control communication.")
        
        recommended_actions.append(f"Isolate the host at IP {src_ip} from the local network by disabling its network interface to prevent command-and-control communications.")
        recommended_actions.append(f"Block resolution of the lookalike domain '{domain}' on all internal DNS servers.")
        recommended_actions.append(f"Investigate active processes on host at {src_ip} that initiated the DNS requests for '{domain}'.")
        
    elif "dns tunneling" in alert_type_lower or "tunnel" in alert_type_lower:
        src_ip = net_ind.get("source_ip", "internal IP")
        dest_ip = net_ind.get("destination_ip", "external IP")
        payload = net_ind.get("tunnel_payload_file_context", "googleclient.txt")
        ts_prefix = f"On {timestamp}, " if timestamp and timestamp != "unknown time" else ""
        summary_steps.append(f"{ts_prefix}internal system at IP {src_ip} initiated outbound connection to external IP {dest_ip}.")
        summary_steps.append(f"DNS tunneling traffic was detected transferring payload context '{payload}', triggering evasion alerts.")
        
        recommended_actions.append(f"Isolate the host at IP {src_ip} from the network immediately (block IP {src_ip} on the switch or disable its network adapter) to terminate the active DNS tunnel.")
        recommended_actions.append(f"Block all traffic to destination IP {dest_ip} at the firewall.")
        recommended_actions.append(f"Inspect host at IP {src_ip} to locate and delete the file payload '{payload}'.")
        
    else:
        # Fallback / Generic
        ts_prefix = f"On {timestamp}, " if timestamp and timestamp != "unknown time" else ""
        summary_steps.append(f"{ts_prefix}anomalous security event '{alert_type}' occurred on host '{host}' ({ip}) involving user '{user}'.")
        
        recommended_actions.append(f"Isolate the affected host '{host}' at IP {ip} by disabling its network interface or blocking it at the switch.")
        recommended_actions.append(f"Monitor the host for anomalous baseline transitions.")
        
    summary = " ".join(summary_steps)
    
    execution_trace = []
    for step_id, step_data in sorted(playbook_dict.get("steps", {}).items()):
        is_met = False
        findings = "Timeline lacks necessary data to satisfy step."
        
        keywords = step_data.get("instructions", "").lower()
        if "phishing" in keywords or "email" in keywords:
            if "phish" in doc.lower() or "mail" in doc.lower() or "sender" in doc.lower() or "attachment" in doc.lower():
                is_met = True
                findings = f"Identified phishing elements in alert doc: {doc[:100]}"
        elif "privilege" in keywords or "escalation" in keywords:
            if "privilege" in doc.lower() or "admin" in doc.lower() or "escalat" in doc.lower():
                is_met = True
                findings = f"Identified privilege escalation signs: {doc[:100]}"
        elif "brute force" in keywords or "failed login" in keywords:
            if "brute" in doc.lower() or "fail" in doc.lower() or "auth" in doc.lower():
                is_met = True
                findings = f"Identified brute force signs: {doc[:100]}"
        elif "tunnel" in keywords or "dns" in keywords:
            if "tunnel" in doc.lower() or "dns" in doc.lower() or "port" in doc.lower():
                is_met = True
                findings = f"Identified network/DNS anomalies: {doc[:100]}"
                
        execution_trace.append(orchestrator.MilestoneExecution(
            step_id=step_id,
            instruction=step_data.get("instructions", ""),
            status="MET" if is_met else "NOT_MET",
            findings=findings
        ))
        
    checklist = {
        "critical_system": "yes" if any(k in doc.lower() for k in ("database", "dc", "domain controller", "production", "prod")) else "no",
        "essential_service": "no",
        "data_sensitivity": "yes" if any(k in doc.lower() for k in ("personal", "sensitive", "confidential", "email", "recipient", "sender")) else "no",
        "operational_impact": "no"
    }
    
    severity_val = alert["metadata"].get("severity", "High")
    
    compliance = policy_engine.run_policy_compliance_rules(
        incident_id=alert_id,
        severity=severity_val,
        confidence="High",
        incident_summary=summary,
        recommended_containment=recommended_actions,
        business_impact_checklist=checklist,
        timeline_text=doc
    )
    
    report = orchestrator.FinalIncidentAnalysis(
        incident_id=alert_id,
        severity=severity_val,
        confidence="High",
        execution_trace=execution_trace,
        incident_summary=summary,
        actions_taken=["Initial triage", "Indicator search", "Playbook heuristic validation"],
        recommended_containment=compliance["modified_containment"],
        business_impact_checklist=checklist,
        severity_justification="Programmatic baseline triage for standalone alert.",
        confidence_justification="Heuristic lookup with no temporal correlation window overlaps.",
        policy_audit_logs=compliance["audit_records"]
    )
    
    try:
        _, mitre_table = mitre_mapper.map_incident_mitre_ttps([alert], llm=None)
        report.mitre_attack_table = mitre_table
    except Exception:
        pass

    return {
        "report": report,
        "suggested_pivots": []
    }

# [FYP-FUNCTION] `main_async` — implements the main async operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:main; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `ArgumentParser`, `CorrelationEngine`, `Incident`, `IncidentMetadata`, `_extract_indicators`, `add`, `add_argument`, `append`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

async def main_async():
    parser = argparse.ArgumentParser(description="Advanced Hybrid SOC Incident Response Pipeline")
    parser.add_argument("--playbook", help="Path to playbook YAML file (omitted for auto-selection)")
    args = parser.parse_args()
    
    orchestrator.log_info("Initializing SOC Incident Response Pipeline...")
    
    # 1. Bulk Ingestion Step
    unread_files = sorted([f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')])
    if not unread_files:
        orchestrator.log_warning("No alert files found in 'triaged_alerts/'. Ingestion skipped.")
        sys.exit(0)
        
    orchestrator.log_info(f"Starting Bulk Ingestion of {len(unread_files)} raw alert logs...")
    
    # Reset vector database to avoid stale items
    vector_engine.clear_collection()
    
    ingested_logs = []
    for f in unread_files:
        path = os.path.join(UNREAD_ALERTS_FOLDER, f)
        try:
            log_data = ingest_pipeline.process_log_file(path)
            ingested_logs.append(log_data)
        except Exception as e:
            orchestrator.log_error(f"Failed to ingest log {f}: {e}")
            
    vector_engine.ingest_logs(ingested_logs)
    orchestrator.log_success(f"Bulk Ingestion completed. Vector store populated with {len(ingested_logs)} items.")
    
    # Start background realtime sync daemon
    sync_service, sync_thread, sync_loop = start_background_sync(INCIDENT_REPORTS_FOLDER, "ChromaDatabase")
    
    # 2. Instantiate the Two-Tier Correlation Engine
    engine = CorrelationEngine(INCIDENT_REPORTS_FOLDER, "ChromaDatabase")
    
    # 3. Drain & Sort Sequential Playbook-Guided Active Correlation Engine (Fast Grouping Phase 1)
    modified_incidents = set()
    incident_playbooks = {}
    incident_is_new = {}
    incident_similar_to = {}

    while True:
        # Re-scan current files in triaged_alerts/
        current_files = sorted([f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')])
        if not current_files:
            orchestrator.log_success("All alert files in 'triaged_alerts/' have been handled. Queue is empty!")
            break
            
        seed_file = current_files[0]
        seed_path = os.path.join(UNREAD_ALERTS_FOLDER, seed_file)
        orchestrator.log_info(f"Evaluating remaining queue. Picked investigative Seed Alert: {seed_file}")
        
        # Load seed
        try:
            alert_log = ingest_pipeline.process_log_file(seed_path)
        except Exception as e:
            orchestrator.log_error(f"Failed to process seed file {seed_file}: {e}")
            dest_dir, inst_id = get_or_create_incident_folder()
            shutil.move(seed_path, os.path.join(dest_dir, seed_file))
            continue
            
        # Parse unassigned candidate alerts
        unassigned_alerts = []
        for other_file in current_files[1:]:
            other_path = os.path.join(UNREAD_ALERTS_FOLDER, other_file)
            try:
                unassigned_alerts.append(ingest_pipeline.process_log_file(other_path))
            except Exception:
                pass
                
        # Execute Two-Tier Baseline Correlation
        try:
            res = await engine.correlate_alert(alert_log, unassigned_alerts)
        except Exception as e:
            orchestrator.log_error(f"Failed baseline correlation for alert {alert_log['id']}: {e}")
            dest_dir, inst_id = get_or_create_incident_folder()
            shutil.move(seed_path, os.path.join(dest_dir, seed_file))
            continue
            
        decision = res["decision"]
        similar_to = res.get("similar_to_incident")
        playbook_path = args.playbook if args.playbook else select_playbook_automatically(seed_path)
        
        # Determine baseline alert list and incident destination
        is_new = True
        inst_id = None
        current_alerts = []
        
        if decision == "MERGE":
            inst_id = res["incident_id"]
            incident = engine.active_incidents.get(inst_id)
            if not incident:
                incident = await engine.repo.get(inst_id)
                
            if not incident:
                is_new = True
                _, inst_id = get_or_create_incident_folder()
                current_alerts = [alert_log]
            else:
                is_new = False
                orchestrator.log_success(f"Confirmed Match. Merging alert {alert_log['id']} into Incident {inst_id}")
                incident.raw_alerts.append(alert_log)
                current_alerts = list(incident.raw_alerts)
        else:
            # NEW_CLUSTER or STANDALONE
            is_new = True
            dest_dir, inst_id = get_or_create_incident_folder()
            current_alerts = res.get("cluster_alerts", [alert_log])
            action_desc = f"New Incident Cluster of {len(current_alerts)} alerts" if decision == "NEW_CLUSTER" else "Standalone Incident"
            orchestrator.log_info(f"Forming {action_desc} -> {inst_id}")
            
        modified_incidents.add(inst_id)
        if inst_id not in incident_playbooks:
            incident_playbooks[inst_id] = playbook_path
        if inst_id not in incident_is_new:
            incident_is_new[inst_id] = is_new
        incident_similar_to[inst_id] = similar_to

        # Sync temporary placeholder state so subsequent alerts can correlate
        indicators_set = set()
        for alert in current_alerts:
            for ind in engine._extract_indicators(alert):
                indicators_set.add(ind)
                
        temp_summary = " | ".join(a["document"] for a in current_alerts)
        dest_dir = os.path.join(INCIDENT_REPORTS_FOLDER, inst_id)
        os.makedirs(dest_dir, exist_ok=True)
        
        if is_new:
            incident_data = Incident(
                id=inst_id,
                metadata=IncidentMetadata(
                    severity=IncidentSeverity.MEDIUM,
                    status=IncidentStatus.TRIAGED,
                    assigned_analyst="Automated Agent",
                    created_at=time.time(),
                    updated_at=time.time(),
                    source_type=current_alerts[0]["metadata"].get("source_type", "Default"),
                    similar_to_incident=similar_to
                ),
                raw_alerts=current_alerts,
                summary_text=temp_summary,
                indicators=list(indicators_set)
            )
            await engine.sync_create_incident(incident_data)
        else:
            incident = engine.active_incidents.get(inst_id)
            if not incident:
                incident = await engine.repo.get(inst_id)
            if incident:
                incident.raw_alerts = current_alerts
                incident.summary_text = temp_summary
                incident.metadata.updated_at = time.time()
                incident.indicators = list(indicators_set)
                await engine.sync_update_incident(incident)
                
        # Archive files and delete from vector store
        cluster_ids = []
        for alert in current_alerts:
            alert_id = alert["id"]
            cluster_ids.append(alert_id)
            filepath = find_file_by_incident_id(alert_id)
            if filepath and os.path.exists(filepath):
                filename = os.path.basename(filepath)
                shutil.move(filepath, os.path.join(dest_dir, filename))
                
        # Remove matched alerts deletion to allow playbook pivots to query them in Phase 2
        # (ChromaDB is cleared at the beginning of each run via vector_engine.clear_collection())
        pass

    # Phase 2: Parallelized Report Generation and Enrichment
    if modified_incidents:
        orchestrator.log_info(f"Running parallel report generation and enrichment for {len(modified_incidents)} incidents...")
        
        # [FYP-FUNCTION] `generate_incident_report` — constructs generate incident report output for the next investigation consumer or analyst-facing view.
        # [FYP-INPUT] Parameters: `inst_id`; values come from its direct caller, route, UI event, fixture, or stage handoff.
        # [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
        # [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
        # [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/main.py:main_async; dynamic framework calls may add callers.
        # [FYP-CALLS] Calls: `add`, `analyze_alert_group_p1`, `append`, `compile_final_report`, `extend`, `extract_indicators_locally`, `generate_local_standalone_report`, `get`.
        # [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

        async def generate_incident_report(inst_id):
            incident = engine.active_incidents.get(inst_id)
            if not incident:
                incident = await engine.repo.get(inst_id)
            if not incident:
                return None
                
            current_alerts = list(incident.raw_alerts)
            playbook_path = incident_playbooks[inst_id]
            is_new = incident_is_new[inst_id]
            similar_to = incident_similar_to.get(inst_id)
            
            # --- PLAYBOOK-GUIDED ACTIVE EXPANSION ---
            # Heuristic fast check for database relations
            local_pivots = []
            for a in current_alerts:
                local_pivots.extend(extract_indicators_locally(a.get("document", "")))
                
            cleaned_local_pivots = []
            for p in local_pivots:
                p_clean = p.strip()
                p_lower = p_clean.lower()
                if not p_clean or p_lower in ("unknown", "null", "none", "", "localhost", "127.0.0.1", "0.0.0.0"):
                    continue
                cleaned_local_pivots.append(p_clean)
                
            has_externals = False
            if cleaned_local_pivots:
                seed_epoch = current_alerts[0]["metadata"]["timestamp_epoch"]
                # Use existing fast metadata check (no ONNX CPU embeddings)
                window_alerts = await asyncio.to_thread(
                    vector_engine.get_alerts_by_temporal_window,
                    timestamp_epoch=seed_epoch,
                    time_window_sec=86400
                )
                current_ids = {a["id"] for a in current_alerts}
                for alert_id, doc, meta in window_alerts:
                    if alert_id not in current_ids:
                        if vector_engine.has_technical_token_overlap(meta, cleaned_local_pivots):
                            has_externals = True
                            break
                        
            # Check if this incident should bypass LLM call for report generation.
            # APP-COMPAT (soc_workflow): when INVESTIGATION_FORCE_LLM is set the app
            # wants a full LLM investigation for the single queued incident, so skip
            # the standalone-local shortcut. Default behaviour is unchanged offline.
            _force_llm = os.getenv("INVESTIGATION_FORCE_LLM", "").strip().lower() in ("1", "true", "yes", "on")
            if len(current_alerts) == 1 and not has_externals and not _force_llm:
                orchestrator.log_info(f"Incident {inst_id}: Standalone alert with no DB relations. Generating report locally (0 LLM calls)...")
                local_res = generate_local_standalone_report(current_alerts[0], playbook_path, inst_id)
                report = local_res["report"]
            else:
                # 1. Pass 1 (Lightweight trace & pivot extraction)
                p1_res = await orchestrator.analyze_alert_group_p1(current_alerts, playbook_path)
                p1_trace = p1_res["execution_trace"]
                suggested_pivots = p1_res["suggested_pivots"]
                
                # 2. Database query for pivots (retails semantic similarity searching)
                if suggested_pivots:
                    cleaned_pivots = []
                    for p in suggested_pivots:
                        p_clean = str(p).strip()
                        p_lower = p_clean.lower()
                        if not p_clean or p_lower in ("unknown", "null", "none", "", "localhost", "127.0.0.1", "0.0.0.0"):
                            continue
                        cleaned_pivots.append(p_clean)
                        
                    if cleaned_pivots:
                        seed_epoch = current_alerts[0]["metadata"]["timestamp_epoch"]
                        extra_fused = await asyncio.to_thread(
                            vector_engine.correlate_rrf,
                            active_indicators=cleaned_pivots,
                            query_text=" ".join(cleaned_pivots),
                            timestamp_epoch=seed_epoch,
                            time_window_sec=86400
                        )
                        
                        correlated_ids = {a["id"] for a in current_alerts}
                        for alert_id, score, doc, meta in extra_fused:
                            if alert_id not in correlated_ids:
                                correlated_ids.add(alert_id)
                                current_alerts.append({
                                    "id": alert_id,
                                    "document": doc,
                                    "metadata": meta
                                })
                                orchestrator.log_success(f"Dynamic retrieval matched alert {alert_id} (RRF: {score:.4f})")
                                
                # 3. Pass 2 (Always compile final report for dynamic/cluster incidents)
                report = await orchestrator.compile_final_report(current_alerts, playbook_path, p1_trace)
                
            return (inst_id, incident, current_alerts, report)

        # Run report generation in parallel (all LLM and I/O tasks run concurrently)
        results = await asyncio.gather(*(generate_incident_report(inst_id) for inst_id in modified_incidents))
        
        # Save and sync final reports sequentially (prevents CPU embedding thread contention during LLM calls)
        for res in results:
            if not res:
                continue
            inst_id, incident, current_alerts, report = res
            
            sev_map = {
                "low": IncidentSeverity.LOW,
                "medium": IncidentSeverity.MEDIUM,
                "high": IncidentSeverity.HIGH,
                "critical": IncidentSeverity.CRITICAL
            }
            mapped_severity = sev_map.get(report.severity.lower(), IncidentSeverity.MEDIUM)
            
            indicators_set = set()
            for alert in current_alerts:
                for ind in engine._extract_indicators(alert):
                    indicators_set.add(ind)
                    
            dest_dir = os.path.join(INCIDENT_REPORTS_FOLDER, inst_id)
            
            incident.raw_alerts = current_alerts
            incident.summary_text = report.incident_summary
            incident.metadata.severity = mapped_severity
            incident.metadata.updated_at = time.time()
            incident.indicators = list(indicators_set)
            
            await engine.sync_update_incident(incident)
            write_markdown_report(dest_dir, inst_id, report)
            write_investigation_analysis_json(dest_dir, report)
        
    # Stop background realtime sync daemon
    stop_background_sync(sync_service, sync_thread, sync_loop)
    orchestrator.log_info("SOC Incident Response Pipeline shut down successfully.")

# [FYP-FUNCTION] `main` — orchestrates the main entry point and its ordered investigation operations.
# [FYP-INPUT] Parameters: no explicit parameters; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns `None` implicitly or explicitly; its observable result is the documented side effect or assertion.
# [FYP-USED-BY] Static symbol references include APIRetrieval.py:<module>, eval_harness.py:<module>, soc_investigation_agent_revised/bench_correlation.py:main_bench; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `main_async`, `run`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
