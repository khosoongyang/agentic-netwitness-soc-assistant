# Reporting Timeline Policy

## 1. Purpose

This policy defines when incident reports should be generated, reviewed, escalated, and finalised within the Agentic AI Threat Hunting and Autonomous Investigation Assistant.

The purpose is to ensure that alerts and incidents are reported according to their severity, confidence, business impact, and investigation status.

This policy supports the Reporting Agent, Triage Agent, Investigation Agent, and Orchestration Agent in deciding:

- Whether a report is required
- How urgent the report is
- What type of report should be generated
- Whether SOC analyst review is required
- Whether escalation is required
- What information must be included before the report can be finalised

---

## 2. Scope

This policy applies to all alerts and incidents processed by the system, including:

- Low severity alerts
- Medium severity alerts
- High severity incidents
- Critical severity incidents
- Confirmed true positives
- False positives
- Incidents requiring containment
- Incidents requiring SOC analyst approval
- Incidents requiring threat hunting

---

## 3. Report Types

The system may generate the following report types:

| Report Type | Purpose |
|---|---|
| Triage Summary | Short summary of the alert, severity, confidence, and next action |
| Investigation Report | Detailed technical report after investigation |
| Containment Report | Records containment recommendation, approval, and action taken |
| Final Incident Report | Complete incident report for confirmed or serious cases |
| False Positive Report | Documents why an alert was closed as benign or non-malicious |
| Executive Summary | Short non-technical summary for management or stakeholders |

---

## 4. Reporting Requirements by Severity

| Severity | Reporting Requirement | Timeline |
|---|---|---|
| Low | Triage summary only | Before closure |
| Medium | Triage summary and investigation notes | After investigation |
| High | Investigation report and SOC analyst review | As soon as investigation evidence is available |
| Critical | Immediate incident report draft and SOC analyst review | Immediately after triage or investigation confirms critical risk |

---

## 5. Low Severity Reporting

Low severity alerts usually do not require a full incident report.

### Conditions

A Low severity alert should receive a short triage summary when:

- The alert is suspicious but low impact
- There is no confirmed malicious IOC
- No compromise is observed
- No containment is required
- No escalation is required
- The alert may be closed or monitored

### Required Report Content

The triage summary should include:

- Alert ID
- Incident ID, if available
- Alert name
- Severity
- Confidence
- Classification
- Reason for low severity
- Evidence reviewed
- Final recommended action

### Recommended Timeline

The triage summary should be generated before the alert is closed or marked for monitoring.

### Example Output Status

```json
{
  "report_required": true,
  "report_type": "triage_summary",
  "report_priority": "low",
  "report_status": "ready_for_closure"
}
```

---

## 6. Medium Severity Reporting

Medium severity alerts require investigation notes because they may become more serious if additional evidence is discovered.

### Conditions

A Medium severity alert should receive investigation documentation when:

- Suspicious activity is present
- Threat intelligence shows mixed or moderate risk
- User or endpoint behaviour is abnormal
- The case requires further investigation
- No confirmed compromise has been found yet

### Required Report Content

The report should include:

- Alert ID
- Incident ID
- Alert summary
- Severity
- Confidence
- Suspicious indicators
- Affected user, host, IP address, domain, URL, or file hash
- Threat intelligence findings
- Investigation steps performed
- Findings
- Recommended next action

### Recommended Timeline

The report should be generated after the Investigation Agent completes its initial investigation.

### Example Output Status

```json
{
  "report_required": true,
  "report_type": "investigation_notes",
  "report_priority": "medium",
  "report_status": "pending_investigation_completion"
}
```

---

## 7. High Severity Reporting

High severity incidents require a more complete investigation report and SOC analyst review.

### Conditions

A High severity incident should receive a formal investigation report when:

- Strong malicious evidence is found
- Malware execution is suspected
- Credential misuse is suspected
- Command-and-control communication is suspected
- A business-important asset is affected
- Containment may be required
- SOC analyst review is needed

### Required Report Content

The report should include:

- Alert ID
- Incident ID
- Severity
- Confidence
- Classification
- Likely scenario
- Affected assets
- Affected users
- IOCs
- Timeline of events
- Threat intelligence enrichment results
- MITRE ATT&CK mapping, if available
- Investigation findings
- Containment recommendation
- SOC analyst approval status
- Business impact
- Recommended remediation actions

### Recommended Timeline

A High severity report should be drafted as soon as the investigation has enough evidence to support the finding.

The report should not be finalised until SOC analyst review is completed.

### Example Output Status

```json
{
  "report_required": true,
  "report_type": "investigation_report",
  "report_priority": "high",
  "report_status": "pending_soc_review"
}
```

---

## 8. Critical Severity Reporting

Critical severity incidents require immediate reporting because they may involve confirmed compromise, ransomware, credential theft, lateral movement, data exfiltration, or command-and-control activity.

### Conditions

A Critical severity incident should receive an immediate incident report draft when one or more of the following are true:

- Confirmed malware infection
- Ransomware activity
- Confirmed credential compromise
- Lateral movement
- Command-and-control communication
- Data exfiltration
- Privileged account abuse
- Multiple affected systems
- Business-critical asset compromise
- Urgent containment recommendation

### Required Report Content

The report should include:

- Alert ID
- Incident ID
- Severity
- Confidence
- Classification
- Executive summary
- Technical summary
- Affected users
- Affected hosts
- Affected IP addresses
- Affected domains or URLs
- File hashes
- Malware name, if available
- Timeline of events
- Threat intelligence results
- Evidence of compromise
- Containment recommendation
- Approval status
- Containment action taken, if approved
- Threat hunting activation status
- Business impact
- Immediate next steps
- Long-term remediation recommendations

### Recommended Timeline

A Critical severity report draft should be generated immediately after the alert is classified as Critical.

If containment approval is pending, the report should be marked as a draft and updated after the SOC analyst approves or rejects containment.

### Example Output Status

```json
{
  "report_required": true,
  "report_type": "critical_incident_report",
  "report_priority": "urgent",
  "report_status": "draft_pending_soc_approval"
}
```

---

## 9. Reporting Based on Classification

| Classification | Reporting Requirement |
|---|---|
| True Positive | Generate investigation or incident report |
| False Positive | Generate false positive closure note |
| Needs Review | Generate draft report with missing fields listed |
| Unknown | Do not finalise report, request more investigation |

---

## 10. False Positive Reporting

False positives should still be documented so that the system can improve over time.

### Conditions

A false positive report should be created when:

- Activity is confirmed benign
- IOC reputation is clean
- User activity is expected
- Host activity is caused by approved software
- Alert was triggered by a known safe process
- SOC analyst confirms no incident occurred

### Required Report Content

The false positive report should include:

- Alert ID
- Incident ID
- Alert name
- Original severity
- Final classification
- Reason for false positive classification
- Evidence reviewed
- Analyst comments, if available
- Rule tuning recommendation, if relevant

### Example Output Status

```json
{
  "report_required": true,
  "report_type": "false_positive_report",
  "report_priority": "low",
  "report_status": "ready_for_closure"
}
```

---

## 11. Missing Information Handling

The Reporting Agent must not finalise a report if key fields are missing.

### Required Fields for Final Reports

A final report should include:

- Alert ID
- Incident ID
- Severity
- Confidence
- Classification
- Likely scenario
- Affected entities
- Evidence summary
- Recommended action
- Report status

### Missing Field Behaviour

If required fields are missing, the Reporting Agent should return:

```json
{
  "report_status": "missing_information_required",
  "missing_report_fields": [
    "severity",
    "confidence",
    "classification",
    "likely_scenario"
  ],
  "recommended_next_step": "Return to Investigation Agent or Triage Agent for missing context"
}
```

The report should remain in draft form until the missing fields are provided.

---

## 12. SOC Analyst Review Requirements

SOC analyst review is required before finalising reports for:

- High severity incidents
- Critical severity incidents
- Any incident involving containment
- Any incident involving business-critical assets
- Any incident involving privileged accounts
- Any incident involving data exfiltration
- Any incident where confidence is Low but severity is High or Critical
- Any incident where the system recommends escalation

### SOC Analyst Review Output

```json
{
  "soc_review_required": true,
  "soc_review_status": "pending",
  "review_reason": "High or Critical severity incident requires human validation"
}
```

---

## 13. Threat Hunting Reporting

Threat hunting results should be added to the incident report when hunting is activated.

Threat hunting should be documented when:

- Severity is Critical
- Malware or ransomware is confirmed
- Credential compromise is suspected or confirmed
- Lateral movement is detected
- Command-and-control activity is detected
- Multiple related alerts are found
- Similar IOCs are found in historical data

### Required Threat Hunting Report Fields

- Hunting trigger
- Hunting scope
- Related IOCs searched
- Related hosts found
- Related users found
- Historical matches
- Additional suspicious activity
- Recommended follow-up actions

---

## 14. Containment Reporting

When containment is recommended, the report must record:

- Recommended containment action
- Reason for containment
- Approval requirement
- Approval status
- Analyst decision
- Action executed, if approved
- Business impact
- Risk of not containing
- Follow-up remediation steps

### Example Containment Report Section

```json
{
  "containment_recommended": true,
  "recommended_containment_action": "isolate endpoint",
  "containment_status": "pending_approval",
  "soc_analyst_approval_status": "pending",
  "containment_reason": "Confirmed malicious IOC and likely endpoint compromise"
}
```

---

## 15. Escalation Reporting

A report should be marked for escalation when:

- Severity is Critical
- Business-critical asset is affected
- Multiple systems are affected
- Privileged account is compromised
- Ransomware is detected
- Data exfiltration is detected
- SOC analyst requests escalation

### Example Escalation Output

```json
{
  "escalation_required": true,
  "escalation_reason": "Critical incident involving likely malware compromise",
  "escalation_target": "SOC Analyst or Incident Response Team"
}
```

---

## 16. Report Status Values

The Reporting Agent should use the following report status values:

| Status | Meaning |
|---|---|
| `not_required` | No report is needed |
| `draft_created` | Report draft has been generated |
| `pending_investigation_completion` | More investigation is needed |
| `pending_soc_review` | SOC analyst review is needed |
| `draft_pending_soc_approval` | Containment or major decision is pending approval |
| `missing_information_required` | Required fields are missing |
| `ready_for_closure` | Report can be closed |
| `finalised` | Report is complete and reviewed |

---

## 17. Recommended Report Routing Logic

The Orchestration Agent should route reporting based on report status:

| Report Status | Next Step |
|---|---|
| `missing_information_required` | Return to Triage Agent or Investigation Agent |
| `pending_investigation_completion` | Continue Investigation Agent |
| `pending_soc_review` | Send to SOC Analyst Review |
| `draft_pending_soc_approval` | Send to Approval Step |
| `ready_for_closure` | Close case or store final report |
| `finalised` | Store report and update case history |

---

## 18. Required Reporting Agent Output Fields

When this policy is applied, the Reporting Agent should produce:

```json
{
  "report_required": true,
  "report_type": "critical_incident_report",
  "report_priority": "urgent",
  "report_status": "draft_pending_soc_approval",
  "soc_review_required": true,
  "soc_review_status": "pending",
  "missing_report_fields": [],
  "executive_summary": "Short non-technical summary",
  "technical_summary": "Technical explanation of the incident",
  "recommended_next_step": "Send to SOC Analyst Review"
}
```

---

## 19. Policy Summary

Use this simplified logic:

| Situation | Reporting Decision |
|---|---|
| Low severity | Generate short triage summary |
| Medium severity | Generate investigation notes after investigation |
| High severity | Generate investigation report and require SOC review |
| Critical severity | Generate urgent incident report draft and require SOC review |
| Missing severity or confidence | Do not finalise report |
| Containment pending approval | Keep report as draft |
| False positive | Generate false positive closure report |
| SOC review complete | Finalise report |

The Reporting Agent must always explain why a report is required and what information is still missing.