# Investigation SOP

## 1. Purpose

This Standard Operating Procedure (SOP) defines how the Investigation Agent performs deeper security investigation after receiving a triage result from the Orchestration Agent.

The purpose of the Investigation Agent is to validate the triage decision, collect deeper evidence, build an event timeline, map observed behaviour to MITRE ATT&CK, update severity and confidence, recommend containment where needed, and produce a structured investigation result.

The Investigation Agent should not replace SOC analyst judgement. If evidence is incomplete, containment requires approval, or analyst decision-making is required, the case should be routed to the appropriate workflow step.

---

## 2. Scope

This SOP applies to alerts and incidents that have already passed through parsing, normalisation, threat intelligence enrichment, and triage.

This SOP is used by:

- Investigation Agent
- Orchestration Agent
- Triage Agent
- Data Collection Agent
- Reporting Agent
- SOC analyst approval workflow
- Containment execution workflow

---

## 3. Required Inputs

The Investigation Agent should receive the triage output from the Orchestration Agent.

Expected input:

```text
outputs/triage_result.json
```

The triage output should include:

- Alert ID
- Incident ID
- Alert name
- Severity
- Confidence
- Classification
- Likely scenario
- Affected host
- Affected user
- Source IP addresses
- Destination IP addresses
- Domains
- URLs
- File hashes
- Process details
- Email details, if available
- Threat intelligence enrichment results
- Triage summary
- Recommended next step
- Containment status
- SOC analyst approval status
- Escalation status

---

## 4. Required Knowledge Base References

During investigation, the Investigation Agent should retrieve and apply relevant knowledge from:

- `policies/incident_severity_policy.md`
- `policies/containment_approval_policy.md`
- `policies/escalation_policy.md`
- `procedures/evidence_collection_sop.md`
- `procedures/threat_intel_enrichment_sop.md`
- Relevant incident playbooks from `playbooks/`
- Relevant MITRE ATT&CK references from `mitre_attack/`
- Similar prior cases from `prior_cases/`

---

## 5. Investigation Responsibilities

The Investigation Agent is responsible for:

1. Receiving the triage output from the Orchestration Agent
2. Identifying the investigation starting point
3. Selecting the most relevant playbook using RAG and LLM reasoning
4. Collecting deeper evidence based on the selected playbook
5. Performing proactive profiling and threat hunting using NetWitness, PostgreSQL, and ChromaDB
6. Building an event timeline
7. Identifying and mapping the attack behaviour sequence
8. Expanding IOC correlation
9. Mapping evidence to possible attack behaviour and MITRE ATT&CK tactics
10. Assessing business impact
11. Updating final severity score
12. Updating confidence score
13. Checking whether another playbook is required
14. Checking whether required evidence is complete
15. Recommending additional containment actions if needed
16. Handling auto-containment and SOC analyst approval decisions
17. Recommending eradication and recovery actions
18. Producing the final investigation result

---

## 6. Investigation Procedure

### Step 1: Ingest Triage Brief

The Investigation Agent should begin by ingesting the triage result from the Orchestration Agent.

The agent should review:

- Severity
- Confidence
- Classification
- Likely scenario
- Triage summary
- Affected entities
- Extracted IOCs
- Threat intelligence results
- Recommended next action
- Containment status
- Escalation status

If severity, confidence, classification, or likely scenario is missing, the Investigation Agent should attempt to retrieve the missing values from `outputs/triage_result.json`.

If the fields are still missing, the case should be marked as incomplete and returned to the Orchestration Agent.

---

### Step 2: Identify Investigation Starting Point

The Investigation Agent should determine where to begin the investigation based on the triage output.

Possible starting points include:

| Triage Scenario | Investigation Starting Point |
|---|---|
| Phishing email | Email sender, recipient, attachment, URL, file hash |
| Malware alert | Host, file hash, process, parent process, network connections |
| Suspicious login | User account, source IP, login time, geolocation, authentication logs |
| C2 communication | Destination IP, domain, URL, host, process responsible for connection |
| Credential compromise | User account, login history, privilege use, suspicious access |
| Lateral movement | Source host, destination host, authentication events, remote access method |
| Data exfiltration | Source host, destination address, data volume, protocol, time window |

The selected starting point should be recorded in the investigation output.

---

### Step 3: Select Relevant Playbook Using RAG and LLM

The Investigation Agent should use RAG and LLM reasoning to select the most relevant playbook from ChromaDB.

Possible playbooks include:

- Phishing response playbook
- Malware response playbook
- Ransomware response playbook
- Credential compromise playbook
- Suspicious login playbook
- Command-and-control investigation playbook
- Data exfiltration playbook
- Lateral movement playbook

The selected playbook should guide the evidence collection and investigation steps.

Expected output field:

```json
{
  "selected_playbook": "malware_response_playbook.md",
  "playbook_selection_reason": "The alert contains a suspicious file hash and endpoint malware indicators"
}
```

---

### Step 4: Collect Deeper Evidence Based on Selected Playbook

The Investigation Agent should collect deeper evidence according to the selected playbook.

Evidence may include:

- Related NetWitness events
- Source and destination IP addresses
- Hostnames
- User accounts
- Process names
- Parent process names
- Command-line arguments
- File names
- File paths
- File hashes
- Email sender and recipient information
- URLs
- Domains
- DNS queries
- HTTP requests
- Authentication logs
- Endpoint activity
- Historical alerts
- Similar prior cases
- Threat intelligence enrichment results

Evidence should be collected from available sources such as:

- NetWitness SIEM
- PostgreSQL
- ChromaDB
- Knowledge base
- Prior cases
- Threat intelligence results

---

### Step 5: Perform Proactive Profiling and Threat Hunting

The Investigation Agent should perform proactive profiling and threat hunting using NetWitness, PostgreSQL, and ChromaDB.

The purpose is to find related activity beyond the original alert.

The agent should search for:

- Same IOC appearing on other hosts
- Same file hash appearing in past alerts
- Same domain or IP contacted by other machines
- Same suspicious user behaviour across accounts
- Similar process execution patterns
- Related MITRE ATT&CK behaviour
- Similar prior cases
- Repeated alerts linked to the same entity

Expected output field:

```json
{
  "proactive_hunting_performed": true,
  "hunting_summary": "Related IOC search was performed across NetWitness, PostgreSQL, and ChromaDB"
}
```

---

### Step 6: Build Event Timeline

The Investigation Agent should build a timeline of relevant events.

The timeline should show:

- When the alert occurred
- When the first suspicious activity was observed
- When the IOC appeared
- When the affected user or host was involved
- When suspicious process execution occurred
- When network communication occurred
- When threat intelligence enrichment was completed
- When containment was recommended or approved, if applicable

Example output:

```json
{
  "event_timeline": [
    {
      "time": "2026-05-20T10:12:00Z",
      "event": "Suspicious file attachment detected"
    },
    {
      "time": "2026-05-20T10:13:00Z",
      "event": "Endpoint contacted suspicious external IP"
    },
    {
      "time": "2026-05-20T10:15:00Z",
      "event": "Threat intelligence confirmed malicious file hash"
    }
  ]
}
```

---

### Step 7: Identify and Map Attack Behaviour Sequence

The Investigation Agent should analyse the evidence and identify the likely attack behaviour sequence.

The sequence should explain what likely happened in order.

Example:

```text
Phishing email delivered -> User opened attachment -> Suspicious file executed -> Endpoint contacted malicious infrastructure -> Malware compromise suspected
```

The behaviour sequence should be short, clear, and evidence-based.

---

### Step 8: Analyse Behaviour Using LLM Reasoning

The Investigation Agent may use LLM reasoning to interpret the collected evidence.

The LLM should help with:

- Explaining the likely attack path
- Connecting related evidence
- Identifying suspicious behaviour patterns
- Selecting relevant MITRE ATT&CK techniques
- Summarising technical findings
- Recommending next steps

The LLM must not invent evidence.

If evidence is missing, the output should state what is missing instead of guessing.

---

### Step 9: Expand IOC Correlation

The Investigation Agent should expand IOC correlation using available data sources.

The agent should check whether extracted IOCs appear in:

- Other alerts
- Other hosts
- Other users
- Past incidents
- NetWitness events
- PostgreSQL case records
- ChromaDB prior case references
- Threat intelligence results

IOC correlation should include:

- IP addresses
- Domains
- URLs
- File hashes
- Email senders
- User accounts
- Hostnames
- Process names

Expected output field:

```json
{
  "ioc_correlation": {
    "related_hosts": [],
    "related_users": [],
    "related_alerts": [],
    "historical_matches": []
  }
}
```

---

### Step 10: Map Evidence to MITRE ATT&CK

The Investigation Agent should map the evidence to possible MITRE ATT&CK tactics and techniques.

Examples:

| Observed Evidence | Possible MITRE Mapping |
|---|---|
| Phishing email attachment | T1566.001 Spearphishing Attachment |
| Suspicious PowerShell execution | T1059.001 PowerShell |
| Credential dumping behaviour | T1003 OS Credential Dumping |
| Suspicious outbound C2 traffic | T1071 Application Layer Protocol |
| Lateral movement over SMB/RDP | T1021 Remote Services |
| Data sent to external destination | T1041 Exfiltration Over C2 Channel |

The output should include both the mapping and the reason.

Example output:

```json
{
  "mitre_attack_mapping": [
    {
      "tactic": "Initial Access",
      "technique": "T1566.001 Spearphishing Attachment",
      "reason": "The alert involved a suspicious email attachment"
    }
  ]
}
```

---

### Step 11: Assess Business Impact

The Investigation Agent should assess the possible business impact of the incident.

Business impact may include:

- User workstation disruption
- Server compromise
- Privileged account compromise
- Sensitive data exposure
- Operational downtime
- Spread to other hosts
- Loss of system availability
- Reputation damage
- Compliance or reporting impact

Expected output field:

```json
{
  "business_impact": "Potential endpoint compromise may affect user productivity and could allow malware spread if not contained"
}
```

---

### Step 12: Update Final Severity Score

The Investigation Agent should update the final severity based on deeper evidence.

Severity may increase if:

- Malicious IOC is confirmed
- Malware execution is found
- C2 communication is confirmed
- Credential compromise is suspected or confirmed
- Lateral movement is found
- Data exfiltration is suspected
- More hosts or users are affected
- Business-critical systems are involved

Severity may decrease if:

- Threat intelligence is clean
- Evidence suggests authorised activity
- No compromise evidence is found
- Similar prior cases were false positives
- The suspicious activity was blocked before impact

Expected output field:

```json
{
  "updated_severity": "Critical",
  "severity_change_reason": "Severity remains Critical because malicious IOC evidence and endpoint compromise indicators were confirmed"
}
```

---

### Step 13: Update Confidence Score

The Investigation Agent should update the confidence level based on evidence quality.

Confidence may increase if:

- Multiple evidence sources agree
- Threat intelligence confirms malicious activity
- Timeline supports the likely scenario
- IOC correlation finds related activity
- MITRE mapping is strongly supported
- Prior cases show similar malicious patterns

Confidence may decrease if:

- Key evidence is missing
- Threat intelligence is unavailable
- Evidence is conflicting
- Activity may be authorised
- The timeline does not support the likely scenario

Expected output field:

```json
{
  "updated_confidence": "High",
  "confidence_change_reason": "Confidence remains High because alert evidence, threat intelligence, and behaviour timeline support the finding"
}
```

---

### Step 14: Check Whether Another Playbook Is Required

The Investigation Agent should determine whether another playbook is needed.

Another playbook may be required when the investigation reveals an additional scenario.

Examples:

| Original Playbook | Additional Finding | Additional Playbook |
|---|---|---|
| Phishing | Malicious attachment executed | Malware playbook |
| Malware | C2 traffic detected | C2 investigation playbook |
| Suspicious login | Admin account misuse found | Credential compromise playbook |
| Malware | Lateral movement found | Lateral movement playbook |
| C2 communication | Data transfer detected | Data exfiltration playbook |

If another playbook is required, the Investigation Agent should retrieve it from ChromaDB and continue investigation using that playbook.

Expected output field:

```json
{
  "additional_playbook_required": true,
  "additional_playbook": "command_and_control_playbook.md",
  "additional_playbook_reason": "Investigation found outbound communication to suspected C2 infrastructure"
}
```

If no additional playbook is needed:

```json
{
  "additional_playbook_required": false
}
```

---

### Step 15: Check Whether Required Evidence Is Complete

The Investigation Agent should check whether the required evidence is complete.

Required evidence may include:

- Alert context
- Affected user
- Affected host
- Key IOCs
- Threat intelligence results
- Timeline of events
- Attack behaviour sequence
- MITRE ATT&CK mapping
- Business impact
- Severity
- Confidence
- Containment recommendation
- Eradication recommendation
- Recovery recommendation

If evidence is complete, the Investigation Agent should continue to containment recommendation and final output.

If evidence is incomplete, the Investigation Agent should submit a missing evidence request to the Orchestration Agent.

Example output:

```json
{
  "required_evidence_complete": false,
  "missing_evidence": [
    "affected_host",
    "process_command_line",
    "file_hash"
  ],
  "recommended_next_step": "Submit missing evidence request to Orchestration Agent"
}
```

The Orchestration Agent may then route the case to the Triage Agent or Data Collection Agent.

---

### Step 16: Recommend Additional Containment Actions

Based on investigation findings, the Investigation Agent should recommend additional containment actions where needed.

Possible containment actions:

- Isolate endpoint
- Disable user account
- Reset credentials
- Revoke active sessions
- Block IP address
- Block domain
- Block URL
- Quarantine file
- Remove malicious email
- Kill suspicious process
- Add IOC to watchlist
- Increase monitoring

The recommendation must include:

- Recommended action
- Reason
- Affected entity
- Business impact
- Risk of not containing
- Whether approval is required

Example output:

```json
{
  "additional_containment_recommended": true,
  "recommended_additional_containment_action": "isolate endpoint",
  "containment_reason": "Endpoint shows likely malware compromise and communication with malicious infrastructure",
  "approval_required": true
}
```

---

### Step 17: Check Whether Auto-Containment Is Allowed by Policy

The Investigation Agent should check `containment_approval_policy.md` before any additional containment action is executed.

If auto-containment is allowed by policy, the system may execute policy-approved additional containment.

Examples of low-risk actions that may be allowed:

- Add IOC to watchlist
- Increase monitoring
- Generate investigation task
- Tag alert for review

Examples of disruptive actions that should not be automatic:

- Isolate endpoint
- Disable user account
- Disable privileged account
- Kill process
- Block internal host
- Quarantine system file
- Remove emails from multiple inboxes

If auto-containment is not allowed, the case must be routed for SOC analyst approval.

---

### Step 18: Execute Policy-Approved Additional Containment

If auto-containment is allowed by policy, the system may execute the approved low-risk action.

The Investigation Agent should record:

- Action executed
- Target entity
- Time of action
- Reason
- Policy justification
- Outcome

Expected output:

```json
{
  "containment_execution_type": "policy_approved_auto_containment",
  "containment_action_executed": "add IOC to watchlist",
  "containment_outcome": "success"
}
```

---

### Step 19: Handle SOC Analyst Containment Decision

If auto-containment is not allowed, the system should request SOC analyst approval.

The SOC analyst may decide:

- Approved
- Rejected
- Modified
- More investigation required

#### Approved

If approved, execute the analyst-approved additional containment and verify containment success.

Expected output:

```json
{
  "soc_analyst_containment_decision": "approved",
  "containment_action_executed": "isolate endpoint",
  "containment_outcome": "success"
}
```

#### Rejected

If rejected, record the containment rejection and reason.

Expected output:

```json
{
  "soc_analyst_containment_decision": "rejected",
  "containment_action_executed": "none",
  "containment_rejection_reason": "SOC analyst rejected containment due to insufficient evidence"
}
```

#### Modified

If modified, record the SOC analyst's modification, execute the analyst-modified additional containment, and verify the additional containment outcome.

Expected output:

```json
{
  "soc_analyst_containment_decision": "modified",
  "modified_containment_action": "block malicious domain instead of isolating endpoint",
  "containment_action_executed": "block malicious domain",
  "containment_outcome": "success"
}
```

#### More Investigation Required

If more investigation is required, record the SOC analyst's request and route the case back to the Investigation Agent.

Expected output:

```json
{
  "soc_analyst_containment_decision": "more_investigation_required",
  "recommended_next_step": "Return to Investigation Agent for additional evidence collection"
}
```

---

### Step 20: Verify Containment Success

After any approved or policy-approved containment action, the system should verify whether containment was successful.

Verification may include checking:

- Endpoint isolation status
- Block rule status
- Account disabled status
- Session revocation status
- File quarantine status
- Reduced communication to malicious IP/domain
- No further related alerts after containment
- Confirmation from containment tool or SOC analyst

Expected output:

```json
{
  "containment_verified": true,
  "containment_verification_summary": "No further communication to the malicious destination was observed after containment"
}
```

---

### Step 21: Identify Control Failures

The Investigation Agent should identify any control failures that allowed the incident to occur or continue.

Examples:

- Email gateway failed to block attachment
- Endpoint detection failed to prevent execution
- Firewall allowed outbound traffic to malicious destination
- User account lacked MFA
- Excessive user privileges
- Missing detection rule
- Weak allowlist or blocklist coverage
- Delayed alert response
- Insufficient logging

Expected output:

```json
{
  "control_failures": [
    "Email gateway did not block the suspicious attachment",
    "Endpoint allowed suspicious process execution"
  ]
}
```

---

### Step 22: Recommend Eradication Actions

The Investigation Agent should recommend eradication actions to remove the root cause or malicious artefacts.

Examples:

- Remove malware
- Delete malicious files
- Remove persistence mechanisms
- Disable malicious scheduled tasks
- Remove suspicious registry keys
- Reset compromised credentials
- Patch exploited vulnerability
- Remove malicious email from inboxes
- Update detection rules
- Block malicious infrastructure

Expected output:

```json
{
  "eradication_recommendations": [
    "Remove malicious file from affected endpoint",
    "Reset affected user's credentials",
    "Block malicious file hash and related domain"
  ]
}
```

---

### Step 23: Recommend Recovery Actions

The Investigation Agent should recommend recovery actions to restore normal operations safely.

Examples:

- Reconnect cleaned endpoint
- Restore files from clean backup
- Re-enable user account after password reset
- Validate endpoint health
- Monitor affected host for recurrence
- Confirm no further malicious communication
- Conduct user awareness follow-up
- Update firewall, EDR, or SIEM rules
- Review incident lessons learned

Expected output:

```json
{
  "recovery_recommendations": [
    "Validate endpoint is clean before reconnecting to network",
    "Monitor affected user and host for 7 days",
    "Review detection rule coverage for similar behaviour"
  ]
}
```

---

## 7. Missing Evidence Handling

If required evidence is incomplete, the Investigation Agent should not finalise the investigation.

The agent should produce a missing evidence request.

Expected output:

```json
{
  "current_stage": "investigation_incomplete",
  "required_evidence_complete": false,
  "missing_evidence": [
    "process_command_line",
    "affected_host",
    "file_hash"
  ],
  "recommended_next_step": "Submit missing evidence request to Orchestration Agent"
}
```

The Orchestration Agent should then route the case to the Triage Agent or Data Collection Agent.

---

## 8. Expected Investigation Output

The Investigation Agent should produce:

```text
outputs/investigation_result.json
```

Required fields:

```json
{
  "current_stage": "investigation_completed",
  "alert_id": "example-alert-id",
  "incident_id": "example-incident-id",
  "selected_playbook": "malware_response_playbook.md",
  "investigation_starting_point": "file_hash",
  "investigation_summary": "Short summary of investigation findings",
  "event_timeline": [],
  "attack_behaviour_sequence": [],
  "ioc_correlation": {},
  "mitre_attack_mapping": [],
  "business_impact": "Short business impact assessment",
  "updated_severity": "Low | Medium | High | Critical",
  "updated_confidence": "Low | Medium | High",
  "severity_change_reason": "Reason for severity update",
  "confidence_change_reason": "Reason for confidence update",
  "required_evidence_complete": true,
  "missing_evidence": [],
  "additional_playbook_required": false,
  "additional_containment_recommended": false,
  "recommended_additional_containment_action": "None",
  "containment_status": "not_required | recommended | pending_approval | approved | rejected | executed",
  "soc_analyst_containment_decision": "not_required | pending | approved | rejected | modified | more_investigation_required",
  "containment_outcome": "not_performed | success | failed | partially_successful",
  "containment_verified": false,
  "control_failures": [],
  "eradication_recommendations": [],
  "recovery_recommendations": [],
  "recommended_next_step": "Send to Reporting Agent"
}
```

---

## 9. Quality Checks Before Saving Investigation Result

Before saving `investigation_result.json`, the Investigation Agent should confirm that:

- Alert ID is present
- Incident ID is present, if available
- Investigation summary is present
- Event timeline is present or a reason is given if unavailable
- Attack behaviour sequence is present
- Updated severity is present
- Updated confidence is present
- Business impact is assessed
- Required evidence completeness is stated
- Missing evidence is listed if incomplete
- Containment recommendation is stated
- SOC analyst containment decision is recorded if applicable
- Eradication recommendations are included
- Recovery recommendations are included
- Recommended next step is clear

If critical fields are missing, the investigation should not be marked as completed.

---

## 10. Routing Summary

Use the following routing logic:

| Investigation Condition | Next Step |
|---|---|
| Required evidence incomplete | Submit missing evidence request to Orchestration Agent |
| More data collection required | Route to Triage/Data Collection Agent |
| Another playbook required | Continue Investigation Agent with additional playbook |
| Auto-containment allowed | Execute policy-approved additional containment |
| Auto-containment not allowed | Request SOC analyst containment decision |
| SOC analyst approved containment | Execute approved containment and verify success |
| SOC analyst rejected containment | Record rejection and continue to reporting |
| SOC analyst modified containment | Execute modified containment and verify outcome |
| SOC analyst requests more investigation | Return to Investigation Agent |
| Investigation completed | Send to Reporting Agent |
| Final severity or confidence changed | Send updated result to Orchestration Agent |

---

## 11. SOP Summary

Use this simplified process:

1. Receive triage output from the Orchestration Agent.
2. Identify the investigation starting point.
3. Use RAG and LLM to select a relevant playbook from ChromaDB.
4. Collect deeper evidence based on the selected playbook.
5. Perform proactive profiling and threat hunting using NetWitness, PostgreSQL, and ChromaDB.
6. Build an event timeline.
7. Identify and map the attack behaviour sequence.
8. Analyse behaviour using LLM reasoning.
9. Expand IOC correlation.
10. Map evidence to MITRE ATT&CK.
11. Assess business impact.
12. Update final severity.
13. Update confidence.
14. Check whether another playbook is required.
15. Check whether required evidence is complete.
16. Submit missing evidence request if evidence is incomplete.
17. Recommend additional containment actions if needed.
18. Check whether auto-containment is allowed by policy.
19. Execute policy-approved containment or request SOC analyst approval.
20. Handle analyst decision: approved, rejected, modified, or more investigation required.
21. Verify containment outcome if containment is executed.
22. Identify control failures.
23. Recommend eradication actions.
24. Recommend recovery actions.
25. Produce investigation result with updated severity, confidence, and containment outcome.
26. Send result to the Orchestration Agent or Reporting Agent.