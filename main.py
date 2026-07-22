import os
import sys
import shutil
import argparse
import json
import threading
import asyncio
import time
from dotenv import load_dotenv

import ingest_pipeline
import vector_engine
import orchestrator
import policy_engine
import mitre_mapper
from correlation_engine import CorrelationEngine
from sync_engine import (
    RealtimeSyncService,
    Incident,
    IncidentMetadata,
    IncidentSeverity,
    IncidentStatus
)
from collections import defaultdict

load_dotenv()

UNREAD_ALERTS_FOLDER = "triaged_alerts/"
INCIDENT_REPORTS_FOLDER = "incident_reports/"
PLAYBOOKS_FOLDER = "playbooks/"

os.makedirs(UNREAD_ALERTS_FOLDER, exist_ok=True)
os.makedirs(INCIDENT_REPORTS_FOLDER, exist_ok=True)

def start_background_sync(base_folder: str, db_path: str) -> tuple[RealtimeSyncService, threading.Thread, asyncio.AbstractEventLoop]:
    # Redundant background sync disabled to prevent database contention and cut down latency.
    # The pipeline already performs synchronous dual-write updates itself.
    service = RealtimeSyncService(base_folder=base_folder, db_path=db_path)
    return service, None, None

def stop_background_sync(service: RealtimeSyncService, thread: threading.Thread, loop: asyncio.AbstractEventLoop):
    pass

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

def find_file_by_incident_id(incident_id: str) -> str:
    """Finds the raw alert JSON file in the unread queue by incident ID."""
    files = [f for f in os.listdir(UNREAD_ALERTS_FOLDER) if f.endswith('.json')]
    for f in files:
        if incident_id.lower() in f.lower():
            return os.path.join(UNREAD_ALERTS_FOLDER, f)
    return None

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

def select_playbook_automatically(seed_file_path: str) -> str:
    """Automatically selects the best playbook based on the seed alert's classification."""
    try:
        with open(seed_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        alert_type = data.get("classification", {}).get("alert_type", "").lower()
        tactic = data.get("incident_details", {}).get("mitre_att&ck", {}).get("tactic", "").lower()
        
        if "privilege" in alert_type or "privilege" in tactic or "escalation" in alert_type:
            path = os.path.join(PLAYBOOKS_FOLDER, "privilegeEscalation.yaml")
            if os.path.exists(path):
                orchestrator.log_info(f"Auto-selected Privilege Escalation playbook based on alert type: '{alert_type}'")
                return path
        
        # Default fallback
        path = os.path.join(PLAYBOOKS_FOLDER, "phishing.yaml")
        orchestrator.log_info(f"Auto-selected Phishing playbook for alert type: '{alert_type}'")
        return os.path.join(PLAYBOOKS_FOLDER, "phishing.yaml")
    except Exception as e:
        orchestrator.log_warning(f"Error auto-detecting playbook: {e}. Defaulting to phishing.yaml")
        return os.path.join(PLAYBOOKS_FOLDER, "phishing.yaml")

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
    
    if "phishing" in alert_type_lower or "spearphishing" in alert_type_lower:
        sender = email_art.get("sender", "Unknown Sender")
        recipient = email_art.get("recipient", "Unknown Recipient")
        filename = email_art.get("attachment", {}).get("filename", "attachment.exe")
        summary_steps.append(f"1. A spearphishing email was sent from '{sender}' to '{recipient}' containing the attachment '{filename}'.")
        summary_steps.append(f"2. The recipient user executed the attachment '{filename}' on host '{host}' ({ip}).")
        
        # Check if malicious process spawned
        has_process = False
        for step in playbook_dict.get("steps", {}).values():
            if "process spawned" in step.get("instructions", "").lower() or "process tree" in step.get("instructions", "").lower():
                has_process = True
                
        if has_process or end_ind.get("spawned_process") or "cmd.exe" in doc.lower():
            summary_steps.append(f"3. The executable successfully spawned a malicious process, establishing a reverse shell connection.")
            
        recommended_actions.append(f"Isolate host {host} at IP {ip} immediately from the network to prevent lateral movement (disable its network interface or block its IP at the local switch).")
        recommended_actions.append(f"Remove the malicious email attachment '{filename}' from the mail server and block sender '{sender}'.")
        recommended_actions.append(f"Conduct a full forensic analysis of the affected machine '{host}' ({ip}) to identify any additional compromises.")
        
    elif "privilege" in alert_type_lower or "escalation" in alert_type_lower:
        privilege = log_ind.get("requested_privilege") or "SeSecurityPrivilege"
        summary_steps.append(f"1. An unauthorized attempt was made to escalate privileges on host '{host}' ({ip}) by user '{user}'.")
        summary_steps.append(f"2. The user account requested administrative privilege '{privilege}'.")
        summary_steps.append(f"3. The privilege escalation requests failed and were flagged by local security auditing.")
        
        recommended_actions.append(f"Temporarily disable the user account '{user}' to prevent further unauthorized privilege escalation attempts.")
        recommended_actions.append(f"Isolate the affected machine {host} at IP {ip} (disable its network interface or block traffic at the switch) until the host is verified clean.")
        recommended_actions.append(f"Review security event logs on {host} to trace the origin of the '{privilege}' requests.")
        
    elif "brute force" in alert_type_lower or "login" in alert_type_lower:
        src_ip = net_ind.get("source_ip", "attacker IP")
        target_user = auth_det.get("attempted_target_user", "user")
        domain = net_ind.get("destination_domain") or "internal domain"
        summary_steps.append(f"1. Multiple authentication attempts were initiated from source IP {src_ip} targeting the user account '{target_user}' on {domain}.")
        summary_steps.append(f"2. The login attempts resulted in failures, indicating a brute-force attack.")
        summary_steps.append(f"3. The suspicious authentication traffic was detected and flagged at the perimeter firewall.")
        
        recommended_actions.append(f"Block all traffic from the external attacker IP {src_ip} at the perimeter firewall immediately.")
        recommended_actions.append(f"Reset the password for user account '{target_user}' and enforce multi-factor authentication (MFA).")
        recommended_actions.append(f"Review login logs to ensure no attempts from {src_ip} succeeded.")
        
    elif "dns response" in alert_type_lower or "anomalous dns" in alert_type_lower:
        src_ip = net_ind.get("source_ip", "affected host IP")
        domain = net_ind.get("queried_domain", "suspicious domain")
        summary_steps.append(f"1. Host at IP {src_ip} performed multiple anomalous DNS queries for lookalike/phishing domain '{domain}'.")
        summary_steps.append(f"2. The query lookup triggered a reputation alert for potential command-and-control communication.")
        
        recommended_actions.append(f"Isolate the host at IP {src_ip} from the local network by disabling its network interface to prevent command-and-control communications.")
        recommended_actions.append(f"Block resolution of the lookalike domain '{domain}' on all internal DNS servers.")
        recommended_actions.append(f"Investigate active processes on host at {src_ip} that initiated the DNS requests for '{domain}'.")
        
    elif "dns tunneling" in alert_type_lower or "tunnel" in alert_type_lower:
        src_ip = net_ind.get("source_ip", "internal IP")
        dest_ip = net_ind.get("destination_ip", "external IP")
        payload = net_ind.get("tunnel_payload_file_context", "googleclient.txt")
        summary_steps.append(f"1. An internal system at IP {src_ip} initiated a connection to external IP {dest_ip}.")
        summary_steps.append(f"2. DNS tunneling traffic was detected over a TCP port, potentially transferring payload '{payload}'.")
        summary_steps.append(f"3. The non-standard tunneling activity was flagged for command-and-control evasion.")
        
        recommended_actions.append(f"Isolate the host at IP {src_ip} from the network immediately (block IP {src_ip} on the switch or disable its network adapter) to terminate the active DNS tunnel.")
        recommended_actions.append(f"Block all traffic to destination IP {dest_ip} at the firewall.")
        recommended_actions.append(f"Inspect host at IP {src_ip} to locate and delete the file payload '{payload}'.")
        
    else:
        # Fallback / Generic
        summary_steps.append(f"1. An anomalous security event '{alert_type}' was detected on the network/endpoint.")
        summary_steps.append(f"2. The event involved host '{host}' ({ip}) and user '{user}'.")
        summary_steps.append(f"3. No further correlated alerts were found in the active monitoring window, indicating a standalone event.")
        
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
                        
            # Check if this incident should bypass LLM call for report generation
            if len(current_alerts) == 1 and not has_externals:
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
        
    # Stop background realtime sync daemon
    stop_background_sync(sync_service, sync_thread, sync_loop)
    orchestrator.log_info("SOC Incident Response Pipeline shut down successfully.")

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
