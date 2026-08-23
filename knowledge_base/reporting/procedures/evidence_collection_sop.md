# Evidence Collection SOP

## 1. Purpose

This Standard Operating Procedure (SOP) defines how evidence should be collected, organised, validated, and passed to the Investigation Agent within the Agentic AI Threat Hunting and Autonomous Investigation Assistant.

The purpose of evidence collection is to ensure that the Investigation Agent has enough reliable information to build an event timeline, analyse attack behaviour, correlate IOCs, map activity to MITRE ATT&CK, assess business impact, and update severity and confidence.

Evidence collection should be structured, repeatable, and traceable. The system should not guess missing evidence.

---

## 2. Scope

This SOP applies to evidence collected from:

- NetWitness SIEM
- Parsed and normalised alert data
- Threat intelligence enrichment results
- PostgreSQL case or alert database
- ChromaDB knowledge base or prior case references
- Endpoint-related evidence, if available
- Network-related evidence, if available
- Email-related evidence, if available
- User and authentication evidence, if available

This SOP is used by:

- Investigation Agent
- Triage Agent
- Data Collection Agent
- Orchestration Agent
- Threat Intelligence module
- Reporting Agent

---

## 3. Position in Workflow

Evidence collection occurs after triage and during investigation.

Expected workflow:

```text
Triage Result
      ↓
Orchestration Agent
      ↓
Investigation Agent
      ↓
Evidence Collection
      ↓
Timeline Building
      ↓
IOC Correlation
      ↓
MITRE Mapping
      ↓
Updated Severity and Confidence
      ↓
Investigation Result
```

If required evidence is incomplete, the Investigation Agent should submit a missing evidence request to the Orchestration Agent. The Orchestration Agent may route the request to the Triage Agent or Data Collection Agent.

---

## 4. Required Inputs

The evidence collection process should begin with the triage output.

Expected input file:

```text
outputs/triage_result.json
```

The input should include:

- Alert ID
- Incident ID
- Alert name
- Alert timestamp
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
- Email information, if available
- Process information, if available
- Threat intelligence enrichment results
- Triage summary
- Recommended next step

If triage fields are missing, the evidence collection process should record the missing fields and avoid overwriting them with empty values.

---

## 5. Evidence Collection Principles

Evidence collection should follow these principles:

1. **Preserve original context**

   Do not remove or overwrite original alert, triage, or enrichment fields.

2. **Collect based on the likely scenario**

   Evidence should match the suspected incident type, such as phishing, malware, C2, credential compromise, lateral movement, or data exfiltration.

3. **Prioritise high-value evidence**

   Prioritise evidence that helps confirm severity, confidence, classification, containment, and impact.

4. **Maintain traceability**

   Each evidence item should record its source, timestamp, and reason for collection.

5. **Avoid unsupported assumptions**

   If evidence is unavailable, mark it as missing instead of inventing details.

6. **Support reporting**

   Evidence should be structured so the Reporting Agent can generate clear technical and executive summaries.

---

## 6. Evidence Sources

The system may collect evidence from the following sources:

| Source | Evidence Type |
|---|---|
| NetWitness SIEM | Events, logs, sessions, alerts, meta keys, network activity |
| PostgreSQL | Stored alerts, cases, parsed outputs, investigation history |
| ChromaDB | Playbooks, prior cases, MITRE references, policy references |
| Threat Intelligence results | IOC reputation, malicious detections, related reports |
| Parsed alert output | Extracted entities and normalised fields |
| Triage result | Severity, confidence, classification, triage summary |
| Investigation result | Deeper evidence, timeline, containment outcome |
| SOC analyst input | Approval decision, rejection reason, modification request |

---

## 7. Evidence Categories

The evidence collection process should organise evidence into categories.

### 7.1 Alert Evidence

Alert evidence includes:

- Alert ID
- Incident ID
- Alert name
- Alert description
- Alert timestamp
- Alert source
- Original severity or priority
- Detection rule name
- Triggering condition
- Related NetWitness event IDs

Example:

```json
{
  "alert_evidence": {
    "alert_id": "INC-6125",
    "incident_id": "INC-6125",
    "alert_name": "Suspicious Attachment Detected",
    "alert_timestamp": "2026-05-20T10:12:00Z",
    "detection_source": "NetWitness SIEM"
  }
}
```

---

### 7.2 Host Evidence

Host evidence includes:

- Hostname
- Host IP address
- Operating system, if available
- Host role
- Asset criticality
- Logged-in user
- Related alerts on the same host
- Historical activity on the same host
- Endpoint compromise indicators

Example:

```json
{
  "host_evidence": {
    "hostname": "RPSOCWSWin2",
    "host_ip": "10.100.20.16",
    "asset_criticality": "normal_user_workstation",
    "related_alerts_found": true
  }
}
```

---

### 7.3 User Evidence

User evidence includes:

- Username
- Email address
- User role
- Privilege level
- Login activity
- Failed login attempts
- Successful login events
- Unusual login locations
- Related alerts involving the user
- Signs of credential compromise

Example:

```json
{
  "user_evidence": {
    "username": "jolin_j",
    "user_role": "standard_user",
    "privileged_account": false,
    "suspicious_login_activity": false
  }
}
```

---

### 7.4 Network Evidence

Network evidence includes:

- Source IP address
- Destination IP address
- Destination port
- Protocol
- Session duration
- Bytes sent
- Bytes received
- DNS queries
- HTTP requests
- TLS indicators
- Repeated outbound connections
- Connections to suspicious or malicious infrastructure

Example:

```json
{
  "network_evidence": {
    "source_ip": "10.100.20.16",
    "destination_ip": "185.199.110.153",
    "protocol": "HTTPS",
    "suspicious_external_connection": true
  }
}
```

---

### 7.5 File Evidence

File evidence includes:

- File name
- File path
- File hash
- File type
- File size
- File origin
- Attachment name
- Malware detection result
- Quarantine status
- Related process

Example:

```json
{
  "file_evidence": {
    "file_name": "invoice.exe",
    "file_hash": "example-sha256-hash",
    "file_reputation": "malicious",
    "source": "email_attachment"
  }
}
```

---

### 7.6 Process Evidence

Process evidence includes:

- Process name
- Parent process name
- Command-line arguments
- Process start time
- User running the process
- File path
- Network connections created by process
- Suspicious child processes
- Script execution activity

Example:

```json
{
  "process_evidence": {
    "process_name": "powershell.exe",
    "parent_process": "winword.exe",
    "command_line": "powershell.exe -ExecutionPolicy Bypass",
    "suspicious_process_activity": true
  }
}
```

---

### 7.7 Email Evidence

Email evidence includes:

- Sender
- Recipient
- Subject
- Email timestamp
- Reply-to address
- Attachment names
- Attachment hashes
- Embedded URLs
- Delivery status
- User interaction, if available
- Email gateway verdict

Example:

```json
{
  "email_evidence": {
    "sender": "itadmin@example.com",
    "recipient": "jolin_j@example.com",
    "subject": "Invoice Payment",
    "attachments": ["invoice.exe"],
    "suspicious_attachment_detected": true
  }
}
```

---

### 7.8 Threat Intelligence Evidence

Threat intelligence evidence includes:

- IOC type
- IOC value
- Source used
- Malicious detection count
- Suspicious detection count
- Reputation score
- Related pulses or reports
- Malware family, if available
- Confidence level
- Risk score

Example:

```json
{
  "threat_intelligence_evidence": {
    "ioc": "example-sha256-hash",
    "ioc_type": "file_hash",
    "source": "VirusTotal",
    "malicious_detections": 66,
    "reputation": "malicious"
  }
}
```

---

### 7.9 Prior Case Evidence

Prior case evidence includes:

- Similar prior incidents
- Same IOC in previous cases
- Same host in previous alerts
- Same user in previous alerts
- Same attack behaviour pattern
- Previous classification
- Previous severity
- Previous containment action
- Previous false positive pattern

Example:

```json
{
  "prior_case_evidence": [
    {
      "case_id": "CASE-002",
      "match_type": "same_file_hash",
      "previous_classification": "True Positive",
      "previous_severity": "High"
    }
  ]
}
```

---

## 8. Scenario-Based Evidence Collection

Evidence should be collected based on the likely scenario.

### 8.1 Phishing Evidence

For phishing cases, collect:

- Sender
- Recipient
- Subject
- Attachment names
- Attachment hashes
- URLs
- Email delivery status
- User click or open activity
- Email gateway verdict
- Similar emails sent to other users
- Threat intelligence for sender, URL, domain, and hash

---

### 8.2 Malware Evidence

For malware cases, collect:

- File hash
- File name
- File path
- Malware detection result
- Process execution evidence
- Parent process
- Command-line arguments
- Network connections from host
- Persistence indicators
- Related alerts on same host
- Threat intelligence for file hash, domain, and IP

---

### 8.3 Command-and-Control Evidence

For C2 cases, collect:

- Destination IP
- Domain
- URL
- Protocol
- Connection frequency
- Beaconing pattern
- Bytes sent and received
- Process responsible for connection
- Host involved
- Threat intelligence reputation
- Related hosts contacting same infrastructure

---

### 8.4 Credential Compromise Evidence

For credential compromise cases, collect:

- User account
- Login history
- Failed login attempts
- Successful unusual logins
- Privileged activity
- MFA status, if available
- Source IP addresses
- Geolocation, if available
- Impossible travel evidence
- Access to sensitive systems
- Similar activity across other accounts

---

### 8.5 Lateral Movement Evidence

For lateral movement cases, collect:

- Source host
- Destination host
- User account used
- Remote access method
- SMB, RDP, WinRM, SSH, or PsExec activity
- Authentication events
- Privileged account use
- File transfer activity
- Process execution on remote host
- Multiple hosts affected

---

### 8.6 Data Exfiltration Evidence

For data exfiltration cases, collect:

- Source host
- Destination IP or domain
- Protocol
- Data volume
- Time window
- User account involved
- Files accessed
- External upload activity
- Suspicious compression or archiving
- Cloud storage access
- Sensitive data indicators

---

## 9. Event Timeline Collection

The evidence collection process should support event timeline creation.

Each timeline event should include:

- Timestamp
- Event type
- Source
- Host
- User
- IOC involved
- Description
- Evidence reference

Example:

```json
{
  "event_timeline": [
    {
      "timestamp": "2026-05-20T10:12:00Z",
      "event_type": "email_delivery",
      "host": "RPSOCWSWin2",
      "user": "jolin_j",
      "description": "Suspicious email delivered to user inbox",
      "source": "NetWitness"
    },
    {
      "timestamp": "2026-05-20T10:14:00Z",
      "event_type": "file_execution",
      "host": "RPSOCWSWin2",
      "user": "jolin_j",
      "description": "Suspicious attachment executed",
      "source": "Endpoint evidence"
    }
  ]
}
```

---

## 10. IOC Correlation Collection

The evidence collection process should support IOC correlation.

The system should check whether IOCs appear in:

- Other alerts
- Other hosts
- Other users
- Historical NetWitness events
- PostgreSQL records
- Prior cases
- Threat intelligence records
- ChromaDB case summaries

IOC correlation should include:

- Same file hash
- Same source IP
- Same destination IP
- Same domain
- Same URL
- Same email sender
- Same process
- Same host
- Same user

Example:

```json
{
  "ioc_correlation": {
    "same_file_hash_seen_before": true,
    "related_hosts": ["RPSOCWSWin2"],
    "related_users": ["jolin_j"],
    "historical_matches": ["CASE-002"]
  }
}
```

---

## 11. Evidence Completeness Check

Before the investigation result is produced, the system should check whether required evidence is complete.

Minimum required evidence:

- Alert ID
- Incident ID, if available
- Alert timestamp
- Affected host or user
- Key IOCs
- Threat intelligence result, if IOCs exist
- Evidence summary
- Timeline or reason timeline is unavailable
- Updated severity
- Updated confidence
- Recommended next step

For higher severity incidents, collect additional evidence:

- MITRE ATT&CK mapping
- Business impact
- Containment recommendation
- Eradication recommendation
- Recovery recommendation
- Control failure analysis

Example output:

```json
{
  "required_evidence_complete": false,
  "missing_evidence": [
    "process_command_line",
    "affected_host",
    "file_hash"
  ],
  "recommended_next_step": "Submit missing evidence request to Orchestration Agent"
}
```

---

## 12. Missing Evidence Handling

If required evidence is missing, the system should not finalise the investigation.

The agent should:

1. List the missing evidence.
2. Explain why the missing evidence is needed.
3. Identify the likely source of the missing evidence.
4. Submit a missing evidence request to the Orchestration Agent.
5. Recommend routing to the Triage Agent or Data Collection Agent.

Example:

```json
{
  "current_stage": "evidence_collection_incomplete",
  "required_evidence_complete": false,
  "missing_evidence_request": [
    {
      "missing_field": "process_command_line",
      "reason_needed": "Required to determine whether PowerShell execution was malicious",
      "suggested_source": "NetWitness endpoint/process logs"
    }
  ],
  "recommended_next_step": "Return to Orchestration Agent for additional data collection"
}
```

---

## 13. Evidence Quality Scoring

Each evidence item may be assigned an evidence quality level.

| Evidence Quality | Meaning |
|---|---|
| High | Directly supports or disproves malicious activity |
| Medium | Supports investigation but does not confirm the incident alone |
| Low | Weak, incomplete, indirect, or contextual evidence |

Examples:

| Evidence | Quality |
|---|---|
| Confirmed malicious file hash | High |
| Endpoint process execution with suspicious command line | High |
| Known malicious domain contacted by host | High |
| Suspicious domain with low reputation | Medium |
| Single failed login attempt | Low |
| Missing or incomplete log field | Low |

Example output:

```json
{
  "evidence_quality_summary": {
    "high_quality_evidence_count": 2,
    "medium_quality_evidence_count": 3,
    "low_quality_evidence_count": 1
  }
}
```

---

## 14. Evidence Preservation

Important evidence should be preserved for reporting and review.

The system should preserve:

- Original alert details
- Parsed alert output
- Threat intelligence results
- Triage result
- Investigation evidence
- Timeline
- SOC analyst comments
- Containment decisions
- Final report

The system should avoid deleting or overwriting evidence files.

Important outputs should be stored in:

```text
outputs/
```

Longer-term structured records may be stored in:

```text
PostgreSQL
```

Knowledge and prior case summaries may be stored in:

```text
ChromaDB
```

---

## 15. Required Output

The evidence collection process should produce a structured evidence bundle that can be used by the Investigation Agent.

Expected output:

```text
outputs/evidence_bundle.json
```

Required fields:

```json
{
  "current_stage": "evidence_collection_completed",
  "alert_id": "example-alert-id",
  "incident_id": "example-incident-id",
  "evidence_sources_used": [
    "NetWitness",
    "PostgreSQL",
    "ChromaDB",
    "Threat Intelligence Results"
  ],
  "alert_evidence": {},
  "host_evidence": {},
  "user_evidence": {},
  "network_evidence": {},
  "file_evidence": {},
  "process_evidence": {},
  "email_evidence": {},
  "threat_intelligence_evidence": {},
  "prior_case_evidence": [],
  "event_timeline": [],
  "ioc_correlation": {},
  "evidence_quality_summary": {},
  "required_evidence_complete": true,
  "missing_evidence": [],
  "recommended_next_step": "Send to Investigation Agent"
}
```

---

## 16. Quality Checks Before Saving Evidence Bundle

Before saving `evidence_bundle.json`, the system should check that:

- Alert ID is preserved
- Incident ID is preserved, if available
- Original alert context is not lost
- Triage severity and confidence are preserved
- IOC values are preserved
- Evidence sources are recorded
- Missing evidence is listed
- Evidence is grouped by category
- Timeline events are sorted by timestamp where possible
- IOC correlation is recorded
- Recommended next step is clear

---

## 17. Routing Summary

Use the following routing logic:

| Condition | Next Step |
|---|---|
| Evidence collection completed | Send to Investigation Agent |
| Required evidence incomplete | Send missing evidence request to Orchestration Agent |
| More NetWitness data required | Route to Data Collection Agent |
| More IOC enrichment required | Route to Threat Intelligence module |
| More playbook context required | Retrieve from ChromaDB |
| Evidence supports confirmed compromise | Continue Investigation Agent |
| Evidence suggests false positive | Continue Investigation Agent for classification update |

---

## 18. SOP Summary

Use this simplified process:

1. Receive triage result or investigation request.
2. Preserve original alert, triage, and enrichment context.
3. Identify required evidence based on the likely scenario.
4. Collect alert, host, user, network, file, process, email, threat intelligence, and prior case evidence.
5. Build event timeline evidence.
6. Perform IOC correlation.
7. Score evidence quality.
8. Check whether required evidence is complete.
9. If evidence is missing, submit missing evidence request to Orchestration Agent.
10. If evidence is complete, save `outputs/evidence_bundle.json`.
11. Send evidence bundle to the Investigation Agent.