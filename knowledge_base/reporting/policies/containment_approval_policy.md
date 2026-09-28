# Containment Approval Policy

## 1. Purpose

This policy defines when containment actions may be recommended, approved, rejected, or executed within the Agentic AI Threat Hunting and Autonomous Investigation Assistant.

The purpose of this policy is to ensure that containment actions are controlled, justified, and approved by a SOC analyst before any disruptive response is performed.

Containment actions may affect endpoints, user accounts, network access, emails, files, or other business systems. Therefore, the system must avoid unnecessary disruption and must only proceed with containment when there is sufficient evidence.

---

## 2. Scope

This policy applies to all containment recommendations made by the Triage Agent, Investigation Agent, Orchestration Agent, or any automated response module.

It covers containment actions such as:

- Isolating an endpoint
- Disabling a user account
- Resetting user credentials
- Blocking an IP address
- Blocking a domain
- Blocking a URL
- Quarantining a file
- Blocking an email sender
- Removing a malicious email from inboxes
- Revoking active user sessions
- Disabling suspicious processes
- Preventing further communication with command-and-control infrastructure

---

## 3. Containment Principles

Containment must follow these principles:

1. **Evidence-based decision-making**  
   Containment should only be recommended when alert evidence, threat intelligence, or investigation results suggest actual or likely compromise.

2. **Human approval for disruptive actions**  
   Actions that may affect business operations must require SOC analyst approval before execution.

3. **Least-disruptive response**  
   The system should recommend the smallest containment action that can reduce risk.

4. **Evidence preservation**  
   Where possible, evidence should be preserved before containment, especially for malware, ransomware, credential compromise, or lateral movement cases.

5. **Clear justification**  
   Every containment recommendation must include a reason, supporting evidence, affected entities, and expected impact.

---

## 4. Containment Approval Levels

The system uses four containment approval levels:

| Approval Level | Meaning |
|---|---|
| Not Required | No containment is needed |
| Recommended | Containment may be useful but is not urgent |
| Pending Approval | Containment is recommended and must be reviewed by a SOC analyst |
| Approved | SOC analyst has approved containment |
| Rejected | SOC analyst has rejected containment |

---

## 5. When Containment Is Not Required

Containment is not required when the alert has low impact or weak evidence.

### Conditions

Containment should be marked as `not_required` when most of the following are true:

- Severity is Low
- Confidence is Low or Medium
- No confirmed malicious IOC is found
- No malware execution is observed
- No account compromise is suspected
- No lateral movement is detected
- No command-and-control communication is detected
- No data exfiltration is detected
- Affected asset is not business-critical
- Activity may be benign or policy-related

### Example Scenarios

- Single failed login attempt
- Suspicious domain visited once but not confirmed malicious
- Low-confidence SIEM alert
- Benign file hash
- Internal admin scan from an authorised host

### Required Output

```json
{
  "containment_required": false,
  "containment_status": "not_required",
  "soc_analyst_approval_status": "not_required"
}
```

---

## 6. When Containment Is Recommended

Containment should be recommended when there is suspicious or malicious activity, but the evidence does not yet prove urgent compromise.

### Conditions

Containment may be marked as `recommended` when one or more of the following are true:

- Severity is Medium
- Suspicious IOC is present
- Threat intelligence shows moderate risk
- Suspicious endpoint activity is detected
- User behaviour appears abnormal
- The alert may become more serious if left uninvestigated
- Investigation is needed before taking disruptive action

### Example Scenarios

- Suspicious email attachment was delivered but not executed
- User clicked a suspicious link but no payload is confirmed
- Suspicious PowerShell command observed without confirmed malware
- External IP has abuse reports but limited evidence of active attack

### Required Output

```json
{
  "containment_required": false,
  "containment_status": "recommended",
  "soc_analyst_approval_status": "not_required",
  "recommended_next_step": "Send to Investigation Agent"
}
```

---

## 7. When SOC Analyst Approval Is Required

SOC analyst approval is required before containment when the action may disrupt users, systems, services, or business operations.

### Conditions

Containment should be marked as `pending_approval` when one or more of the following are true:

- Severity is High or Critical
- Confidence is Medium or High
- Malware execution is suspected or confirmed
- Endpoint compromise is likely
- Credential compromise is suspected or confirmed
- Privileged account misuse is detected
- Lateral movement is detected
- Command-and-control communication is detected
- Data exfiltration is suspected or confirmed
- Ransomware activity is suspected or confirmed
- Business-critical asset is affected
- Multiple hosts or users are affected
- Threat intelligence confirms malicious IOCs

### Example Scenarios

- Endpoint communicates with known command-and-control infrastructure
- File hash is confirmed malicious by multiple threat intelligence sources
- User account shows signs of compromise
- Suspicious process creates persistence
- Ransomware-like encryption activity is detected
- Multiple endpoints show the same malicious IOC
- Domain controller or server is affected

### Required Output

```json
{
  "containment_required": true,
  "containment_status": "pending_approval",
  "soc_analyst_approval_status": "pending",
  "approval_type": "containment_approval"
}
```

---

## 8. Actions That Always Require Approval

The following actions must always require SOC analyst approval:

| Containment Action | Reason |
|---|---|
| Isolate endpoint | May disrupt user work or business operations |
| Disable user account | May block legitimate access |
| Disable privileged account | High business and operational impact |
| Block internal host | May affect internal services |
| Quarantine system file | May affect system stability |
| Kill process on endpoint | May affect running applications |
| Remove email from multiple inboxes | May affect evidence and business communication |
| Block domain across organisation | May block legitimate services |
| Block IP across organisation | May block legitimate services |
| Revoke user sessions | May interrupt active work |

---

## 9. Actions That May Be Automated With Lower Risk

The following actions may be automatically recommended, but should still be logged:

| Action | Condition |
|---|---|
| Add IOC to watchlist | Allowed when IOC is suspicious or malicious |
| Increase monitoring | Allowed for Medium severity and above |
| Generate investigation task | Allowed for Medium severity and above |
| Create incident report draft | Allowed for High and Critical severity |
| Search for related IOCs | Allowed when threat hunting is activated |
| Tag alert for review | Allowed for any severity |

These actions do not directly disrupt business operations, so they do not require containment approval.

---

## 10. Approval Workflow

When containment approval is required, the workflow should be:

1. Triage Agent or Investigation Agent recommends containment.
2. Orchestration Agent detects `containment_status = pending_approval`.
3. Orchestration Agent routes the case to `approval_step`.
4. SOC analyst reviews the recommendation.
5. SOC analyst approves or rejects the containment action.
6. If approved, Orchestration Agent routes to containment execution.
7. If rejected, Orchestration Agent routes back to investigation or reporting.
8. The final decision is recorded in the report.

---

## 11. Approval Request Requirements

Every containment approval request must include:

- Alert ID
- Incident ID
- Severity
- Confidence
- Affected host
- Affected user
- Affected IP address
- Affected file hash, if available
- Recommended containment action
- Reason for containment
- Supporting evidence
- Threat intelligence results
- Expected business impact
- Risk of not containing
- Alternative lower-risk action, if available

### Approval Request Example

```json
{
  "approval_type": "containment_approval",
  "severity": "Critical",
  "confidence": "High",
  "recommended_containment_action": "isolate endpoint",
  "affected_host": "RPSOCWSWin2",
  "reason": "Confirmed malicious file hash and endpoint compromise indicators detected",
  "supporting_evidence": [
    "VirusTotal shows high malicious detections",
    "AlienVault OTX shows related malicious pulses",
    "Endpoint activity indicates likely malware execution"
  ],
  "business_impact": "User workstation will be disconnected from the network",
  "risk_of_not_containing": "Possible malware spread, command-and-control communication, or data loss"
}
```

---

## 12. Approved Containment

If containment is approved, the approval result should include:

```json
{
  "current_stage": "approved",
  "approval_status": "approved",
  "approval_type": "containment_approval",
  "approved_by": "SOC Analyst",
  "approved_containment_action": "isolate endpoint",
  "soc_analyst_comments": "Approved endpoint isolation due to confirmed malware evidence."
}
```

The Orchestration Agent should then route to containment execution.

### Expected Orchestration Decision

```json
{
  "next_agent": "containment_executor",
  "workflow_decision": "execute_approved_containment"
}
```

---

## 13. Rejected Containment

If containment is rejected, the approval result should include:

```json
{
  "current_stage": "rejected",
  "approval_status": "rejected",
  "approval_type": "containment_approval",
  "rejected_by": "SOC Analyst",
  "rejection_reason": "Insufficient evidence to isolate endpoint at this stage.",
  "soc_analyst_comments": "Continue investigation and monitor related IOCs."
}
```

The Orchestration Agent should not execute containment.

The case should be routed to one of the following:

- Investigation Agent, if more evidence is needed
- Reporting Agent, if investigation is complete
- Monitoring workflow, if no immediate action is required

---

## 14. Containment Action Mapping

| Scenario | Recommended Containment Action |
|---|---|
| Malware on endpoint | Isolate endpoint, quarantine file |
| Ransomware activity | Isolate endpoint immediately after approval |
| Credential compromise | Disable account, reset password, revoke sessions |
| Privileged account misuse | Disable privileged account, escalate immediately |
| C2 communication | Block IP/domain, isolate affected endpoint |
| Phishing email delivered | Remove email from inboxes, block sender/domain |
| Malicious attachment | Quarantine attachment, block hash |
| Data exfiltration | Block destination, isolate host, escalate |
| Lateral movement | Isolate affected hosts, disable compromised accounts |
| Suspicious but unconfirmed activity | Monitor, investigate, add IOC to watchlist |

---

## 15. Severity-Based Containment Rules

| Severity | Containment Rule |
|---|---|
| Low | No containment |
| Medium | Investigation first, containment usually not required |
| High | Recommend containment if compromise is likely, approval required |
| Critical | Recommend urgent containment, approval required |

---

## 16. Confidence-Based Containment Rules

| Confidence | Containment Rule |
|---|---|
| Low | Do not contain automatically, investigate further |
| Medium | Recommend containment only if impact is significant |
| High | Recommend containment if malicious activity is likely or confirmed |

A Critical severity alert with Low confidence should still be reviewed by a SOC analyst before containment.

A High severity alert with High confidence should normally generate a containment approval request.

---

## 17. Evidence Preservation

Before executing containment, the system should preserve important evidence where possible.

Evidence may include:

- Alert details
- Raw NetWitness logs
- Parsed alert output
- Enriched IOC results
- File hashes
- Process details
- Network connections
- User activity
- Host information
- Threat intelligence results
- Screenshots or analyst notes, if available

Evidence preservation is especially important for:

- Malware cases
- Ransomware cases
- Credential compromise
- Data exfiltration
- Lateral movement
- Privileged account abuse

---

## 18. Final Report Requirements

The final incident report should record:

- Whether containment was recommended
- Whether approval was required
- Whether approval was granted or rejected
- Who approved or rejected the action
- What containment action was taken
- Why the action was taken
- What evidence supported the action
- What business impact was expected
- What follow-up actions are required

---

## 19. Required Output Fields

When this policy is applied, the agent output should include:

```json
{
  "containment_required": true,
  "containment_status": "pending_approval",
  "soc_analyst_approval_status": "pending",
  "approval_type": "containment_approval",
  "recommended_containment_action": "isolate endpoint",
  "containment_reason": "Confirmed malicious IOC and likely endpoint compromise",
  "containment_impact": "Affected endpoint may be disconnected from the network",
  "risk_of_no_containment": "Malware may spread or continue command-and-control communication"
}
```

---

## 20. Policy Summary

Use this simplified logic:

| Situation | Decision |
|---|---|
| Low severity, weak evidence | No containment |
| Medium severity, suspicious activity | Investigate first |
| High severity, likely compromise | Recommend containment, require approval |
| Critical severity, confirmed compromise | Urgent containment recommendation, require approval |
| Approval granted | Execute approved containment |
| Approval rejected | Do not execute containment, continue investigation or reporting |

The system must never perform disruptive containment actions without SOC analyst approval.