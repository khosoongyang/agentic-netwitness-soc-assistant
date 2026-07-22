import os
import re
import time
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

class PolicyAuditRecord(BaseModel):
    audit_id: str
    incident_id: str
    agent_name: str = "Investigation Agent"
    policy_reference: str
    decision_point: str
    input_summary: str
    result: str  # Pass, Fail, Warning, Unknown, N/A
    decision_made: str  # Route, Close, Investigate, Escalate, Contain, Report, Learn
    timestamp: float
    evidence_reference: str
    human_review_required: bool
    final_reviewer: Optional[str] = None

class PolicyManager:
    def __init__(self, policy_file_path: str):
        self.policy_file_path = policy_file_path
        self.last_modified: float = 0.0
        self.policies: Dict[str, str] = {}
        self.raw_text: str = ""
        self._load_policies()

    def _load_policies(self) -> None:
        """Loads and parses the policy file if it has been updated on disk."""
        try:
            mtime = os.path.getmtime(self.policy_file_path)
            if mtime > self.last_modified:
                with open(self.policy_file_path, "r", encoding="utf-8") as f:
                    self.raw_text = f.read()
                self._parse_policies()
                self.last_modified = mtime
        except Exception as e:
            # Fall back to empty dict if error
            pass

    def _parse_policies(self) -> None:
        """Parses markdown text by headers and appendices into a key-value dictionary."""
        sections = {}
        current_section = "Purpose"
        current_content = []
        
        # Regex to detect major sections (e.g., "Appendix A", "5. General Escalation Rule")
        section_pattern = re.compile(
            r'^(?:#+\s*|\*\*|\b)(Appendix\s+[A-Z0-9]+|\d+\.\s+[\w\s]+)(?:\*\*|\b)',
            re.IGNORECASE
        )
        
        for line in self.raw_text.splitlines():
            match = section_pattern.match(line.strip())
            if match:
                if current_content:
                    sections[current_section.strip().lower()] = "\n".join(current_content).strip()
                current_section = match.group(1)
                current_content = [line]
            else:
                current_content.append(line)
                
        if current_content:
            sections[current_section.strip().lower()] = "\n".join(current_content).strip()
            
        self.policies = sections

    def get_section(self, section_name: str) -> str:
        """Retrieves a specific policy section dynamically, updating if modified."""
        self._load_policies()
        search_key = section_name.lower().strip()
        for key, content in self.policies.items():
            if search_key in key:
                return content
        return ""


def run_policy_compliance_rules(
    incident_id: str,
    severity: str,
    confidence: str,
    incident_summary: str,
    recommended_containment: List[str],
    business_impact_checklist: Dict[str, str],
    timeline_text: str
) -> Dict:
    """
    Enforces Section 5, Appendix G, H, and I rules on the agent's findings.
    Modifies recommended containment steps and generates the Appendix M audit logs.
    Returns:
        Dict with "escalation_required", "reasons", "modified_containment", "audit_records"
    """
    reasons = []
    modified_containment = list(recommended_containment)
    timestamp = time.time()
    
    # 1. Parse checklist values
    if hasattr(business_impact_checklist, "model_dump"):
        checklist_dict = business_impact_checklist.model_dump()
    else:
        checklist_dict = dict(business_impact_checklist)
        
    is_critical_system = any(
        checklist_dict.get(k, "no").lower() in ("yes", "true")
        for k in ("critical_system", "essential_service")
    )
    has_sensitive_data = checklist_dict.get("data_sensitivity", "no").lower() in ("yes", "true")
    
    # 2. Check for suspected ransomware
    suspect_ransomware = False
    if "ransomware" in incident_summary.lower() or "ransomware" in timeline_text.lower():
        suspect_ransomware = True
        
    # Check for suspected Guest OS Compromise
    suspect_guest_os = False
    if any(k in incident_summary.lower() or k in timeline_text.lower() for k in ("guest os", "virtual machine", " vm ", "esxi", "hyper-v", "hypervisor")):
        suspect_guest_os = True

    # Check for operational disruption in containment
    containment_disruptive = checklist_dict.get("operational_impact", "no").lower() in ("yes", "true", "outage", "degradation")

    # Extract specific host/IP details to make containment overrides specific
    import re
    full_text = f"{incident_summary} {timeline_text}"
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', full_text)
    hostnames = re.findall(r'\b[rR][pP]-[sS][oO][cC]-[wW][sS]-[a-zA-Z0-9-]+\b', full_text)
    
    local_ips = []
    for ip_addr in ips:
        if ip_addr.startswith("10.") or ip_addr.startswith("192.168.") or any(ip_addr.startswith(f"172.{i}.") for i in range(16, 32)):
            if ip_addr not in local_ips:
                local_ips.append(ip_addr)
                
    unique_hosts = []
    for h in hostnames:
        h_clean = h.strip()
        if h_clean.lower() not in [uh.lower() for uh in unique_hosts]:
            unique_hosts.append(h_clean)
            
    asset_str = ""
    target_host = unique_hosts[0] if unique_hosts else ""
    target_ip = local_ips[0] if local_ips else ""
    
    if target_host and target_ip:
        asset_str = f" host {target_host} ({target_ip})"
    elif target_ip:
        asset_str = f" computer at IP {target_ip}"
    elif target_host:
        asset_str = f" host {target_host}"
    else:
        asset_str = " affected computer"

    # 3. Apply Appendix H Ransomware containment overrides
    if suspect_ransomware:
        r_rules = [
            f"Disconnect the infected{asset_str} from the network and storage devices to limit spread.",
            f"Do not immediately shut down the affected{asset_str}.",
            "Escalate the case to the SOC Analyst or Incident Response Team."
        ]
        for r_rule in r_rules:
            match_prefix = r_rule.lower()[:20]
            if not any(existing.lower().startswith(match_prefix) for existing in modified_containment):
                modified_containment.insert(0, r_rule)
                
    # Apply Appendix I VM compromise containment overrides
    if suspect_guest_os:
        host_suffix = f" (host: {target_host})" if target_host else ""
        vm_rules = [
            f"Treat guest operating systems on the same hardware host as potentially compromised{host_suffix}.",
            "Conduct checks on each guest operating system and look for signs of compromise.",
            "Recommend recovery from the last-known good image where required."
        ]
        for vm_rule in vm_rules:
            match_prefix = vm_rule.lower()[:20]
            if not any(existing.lower().startswith(match_prefix) for existing in modified_containment):
                modified_containment.insert(0, vm_rule)

    # 4. Evaluate Escalation Rules (Section 5 / Appendix G.2)
    escalation_required = False
    
    if severity.lower() in ("high", "critical"):
        escalation_required = True
        reasons.append(f"Final severity is {severity}")
        
    if confidence.lower() in ("low", "medium"):
        escalation_required = True
        reasons.append(f"Confidence score is {confidence}")
        
    if is_critical_system:
        escalation_required = True
        reasons.append("Critical or essential system is affected")
        
    if has_sensitive_data:
        escalation_required = True
        reasons.append("Sensitive or personal data is involved")
        
    if suspect_ransomware:
        escalation_required = True
        reasons.append("Ransomware is suspected")
        
    if suspect_guest_os:
        escalation_required = True
        reasons.append("Compromised guest OS is suspected in a virtualised environment")
        
    if containment_disruptive:
        escalation_required = True
        reasons.append("Containment may disrupt operations")

    # 5. Generate Audit Records (Appendix M)
    audit_records = []
    
    # DP-07: Assess business impact
    dp07_result = "Pass"
    dp07_decision = "Investigate"
    if is_critical_system or has_sensitive_data:
        dp07_result = "Warning"
    audit_records.append(PolicyAuditRecord(
        audit_id=f"AUD-DP07-{int(timestamp)}-1",
        incident_id=incident_id,
        policy_reference="Appendix C",
        decision_point="DP-07",
        input_summary=f"Critical System: {is_critical_system}, Sensitive Data: {has_sensitive_data}",
        result=dp07_result,
        decision_made=dp07_decision,
        timestamp=timestamp,
        evidence_reference="business_impact_checklist",
        human_review_required=escalation_required
    ))
    
    # DP-08: Final severity score
    dp08_result = "Pass"
    dp08_decision = "Investigate"
    if severity.lower() in ("high", "critical"):
        dp08_result = "Warning"
        dp08_decision = "Escalate"
    audit_records.append(PolicyAuditRecord(
        audit_id=f"AUD-DP08-{int(timestamp)}-2",
        incident_id=incident_id,
        policy_reference="Appendix A",
        decision_point="DP-08",
        input_summary=f"Severity classification: {severity}",
        result=dp08_result,
        decision_made=dp08_decision,
        timestamp=timestamp,
        evidence_reference="incident_summary",
        human_review_required=escalation_required
    ))
    
    # DP-09: Generate confidence score
    dp09_result = "Pass"
    dp09_decision = "Investigate"
    if confidence.lower() in ("low", "medium"):
        dp09_result = "Warning"
        dp09_decision = "Escalate"
    audit_records.append(PolicyAuditRecord(
        audit_id=f"AUD-DP09-{int(timestamp)}-3",
        incident_id=incident_id,
        policy_reference="Appendix F",
        decision_point="DP-09",
        input_summary=f"Confidence level: {confidence}",
        result=dp09_result,
        decision_made=dp09_decision,
        timestamp=timestamp,
        evidence_reference="execution_trace",
        human_review_required=escalation_required
    ))
    
    # DP-10 / DP-11: Containment Approval Check
    dp10_result = "Pass" if not escalation_required else "Fail"
    dp10_decision = "Contain" if not escalation_required else "Escalate"
    audit_records.append(PolicyAuditRecord(
        audit_id=f"AUD-DP10-{int(timestamp)}-4",
        incident_id=incident_id,
        policy_reference="Appendix G",
        decision_point="DP-10/DP-11",
        input_summary=f"Severity: {severity}, Confidence: {confidence}, Ransomware: {suspect_ransomware}, Guest OS: {suspect_guest_os}",
        result=dp10_result,
        decision_made=dp10_decision,
        timestamp=timestamp,
        evidence_reference="recommended_containment",
        human_review_required=escalation_required
    ))
    
    # DP-15: Data incident check
    if has_sensitive_data:
        audit_records.append(PolicyAuditRecord(
            audit_id=f"AUD-DP15-{int(timestamp)}-5",
            incident_id=incident_id,
            policy_reference="Appendix B",
            decision_point="DP-15",
            input_summary="Sensitive or personal data accessed or exfiltrated.",
            result="Warning",
            decision_made="Escalate",
            timestamp=timestamp,
            evidence_reference="business_impact_checklist",
            human_review_required=True
        ))

    return {
        "escalation_required": escalation_required,
        "reasons": reasons,
        "modified_containment": modified_containment,
        "audit_records": audit_records
    }


def extract_actionable_rules(section_text: str) -> str:
    """
    Parses a Markdown policy section to extract only headings, bulleted lists, and tables,
    stripping out boilerplate blocks like Purpose, Scope, or intro text.
    """
    lines = []
    in_purpose_or_intro = False
    
    for line in section_text.splitlines():
        line_strip = line.strip()
        if not line_strip:
            if lines and lines[-1] != "":
                lines.append("")
            continue
            
        # Detect headings (e.g. ## Heading or **Heading**)
        is_header = line_strip.startswith('#') or (line_strip.startswith('**') and line_strip.endswith('**'))
        
        # If it's a Purpose or Scope header, we skip it and skip subsequent paragraph lines
        if is_header and any(keyword in line_strip.lower() for keyword in ("purpose", "scope", "definitions", "use of", "standards", "requirements")):
            in_purpose_or_intro = True
            continue
        elif is_header:
            in_purpose_or_intro = False
            
        # We keep headers, list items (starts with -, *, or digit.), and table rows (starts with |)
        is_bullet = line_strip.startswith('-') or line_strip.startswith('*') or bool(re.match(r'^\d+\.', line_strip))
        is_table = line_strip.startswith('|')
        
        if is_header:
            lines.append(line)
        elif not in_purpose_or_intro and (is_bullet or is_table):
            lines.append(line)
            
    return "\n".join(lines).strip()

