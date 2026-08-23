# Incident Severity Policy

## 1. Purpose

This policy defines how security alerts should be classified by severity within the **Agentic AI Threat Hunting and Autonomous Investigation Assistant**.

The purpose is to help the Triage Agent assign a consistent severity level based on alert evidence, affected assets, threat intelligence results, business impact, and confidence level.

Severity classification supports the following workflow decisions:

- Whether the alert should be closed as low risk
- Whether deeper investigation is required
- Whether SOC analyst approval is needed
- Whether containment should be recommended
- Whether threat hunting should be activated
- Whether the incident should be escalated

---

## 2. Severity Levels

The system uses four severity levels:

| Severity | Meaning |
|---|---|
| Low | Suspicious activity with limited evidence and low impact |
| Medium | Confirmed suspicious activity requiring investigation, but no immediate severe impact |
| High | Strong evidence of malicious activity with possible compromise or business impact |
| Critical | Confirmed or highly likely compromise requiring urgent SOC analyst attention and containment |

---

## 3. Low Severity

An alert should be classified as **Low** when the activity appears suspicious but has limited evidence of compromise.

### Conditions

Classify as Low if most of the following are true:

- No confirmed malicious IOC
- No known malware detected
- No successful exploitation observed
- No sensitive asset involved
- No repeated suspicious behaviour
- No evidence of lateral movement
- No evidence of credential compromise
- No data exfiltration detected
- Threat intelligence results are clean or low risk
- Alert may be caused by normal user activity or benign software

### Example Scenarios

- A single failed login attempt
- A user visits a suspicious but unconfirmed domain
- A low-confidence SIEM rule triggers once
- Benign file hash with no malicious detections
- Internal network scan from an authorised admin machine

### Recommended Action

- Record the alert
- Continue monitoring
- No containment required
- No immediate escalation required

---

## 4. Medium Severity

An alert should be classified as **Medium** when there is suspicious activity that requires investigation, but there is not enough evidence to confirm a serious compromise.

### Conditions

Classify as Medium if one or more of the following are true:

- Suspicious IOC is present but not strongly confirmed as malicious
- Unusual user behaviour is detected
- Multiple failed login attempts are observed
- Suspicious attachment, URL, IP address, or domain is detected
- Endpoint activity looks abnormal but not clearly malicious
- Threat intelligence shows mixed or moderate-risk results
- The affected asset is not business-critical
- There is no confirmed lateral movement, malware execution, or data exfiltration

### Example Scenarios

- Suspicious email attachment blocked before execution
- User clicks a suspicious link but no payload is confirmed
- Multiple failed login attempts from an unusual source
- Suspicious PowerShell command without confirmed malicious payload
- IP address has some abuse reports but no strong malicious reputation

### Recommended Action

- Send to Investigation Agent
- Enrich IOCs using threat intelligence
- Review user, host, process, network, and email evidence
- Escalate if additional malicious evidence is found
- Containment is usually not required unless confidence increases

---

## 5. High Severity

An alert should be classified as **High** when there is strong evidence of malicious activity or likely compromise.

### Conditions

Classify as High if one or more of the following are true:

- Confirmed malicious IOC is detected
- Malware execution is suspected or observed
- Suspicious process execution is detected
- Credential misuse is suspected
- Multiple related alerts are linked to the same host or user
- A suspicious external connection is made to known malicious infrastructure
- Threat intelligence shows strong malicious reputation
- The affected asset is important to business operations
- There is evidence of persistence, privilege escalation, or command-and-control activity

### Example Scenarios

- Endpoint connects to a known malicious IP address
- File hash is detected as malicious by multiple threat intelligence sources
- Suspicious PowerShell activity downloads a payload
- User account shows abnormal login behaviour from impossible travel or unusual geolocation
- Malware is detected but spread is not confirmed

### Recommended Action

- Send to Investigation Agent immediately
- Recommend SOC analyst review
- Recommend containment if endpoint, account, or network compromise is likely
- Increase monitoring of related users, hosts, and IOCs
- Prepare evidence for incident reporting

---

## 6. Critical Severity

An alert should be classified as **Critical** when there is confirmed or highly likely compromise with significant impact or urgent containment needs.

### Conditions

Classify as Critical if one or more of the following are true:

- Confirmed malware infection on an endpoint
- Ransomware activity is detected or strongly suspected
- Credential compromise is confirmed
- Lateral movement is detected
- Data exfiltration is detected or strongly suspected
- Command-and-control communication is confirmed
- Multiple systems are affected
- A business-critical asset is compromised
- Privileged account abuse is detected
- Threat intelligence confirms highly malicious IOCs
- The incident may cause major operational, reputational, or security impact

### Example Scenarios

- Malware hash has high malicious detections on VirusTotal
- AlienVault OTX shows multiple related malicious pulses
- Endpoint shows signs of active compromise
- Internal host communicates with known C2 infrastructure
- Ransomware encryption behaviour is detected
- Admin account is used suspiciously after credential theft
- Multiple endpoints show the same malicious IOC

### Recommended Action

- Send to SOC analyst approval immediately
- Recommend containment
- Do not perform containment automatically unless approval has been granted
- Preserve evidence before containment where possible
- Escalate to the appropriate incident response team
- Activate threat hunting for related IOCs, hosts, users, and attack patterns
- Generate an incident report after investigation

---

## 7. Threat Intelligence Severity Guidance

Threat intelligence results should influence severity classification.

| Threat Intelligence Result | Severity Impact |
|---|---|
| No malicious detections | May remain Low or Medium |
| Low number of suspicious detections | Consider Medium |
| Multiple malicious detections | Consider High |
| Strong malicious reputation across multiple sources | Consider High or Critical |
| Known malware, ransomware, C2, or phishing infrastructure | Consider Critical |
| IOC linked to active campaigns or multiple threat reports | Increase severity by at least one level |

### Examples of Threat Intelligence Sources

- VirusTotal
- AbuseIPDB
- AlienVault OTX
- Internal threat intelligence
- Known blocklists
- Previous incident records

---

## 8. Asset Criticality Guidance

Severity should increase when the affected system, user, or service is important.

| Asset Type | Severity Impact |
|---|---|
| Normal user workstation | No automatic increase |
| Shared department machine | May increase severity |
| Server | Increase severity |
| Domain controller | High or Critical |
| Database server | High or Critical |
| Email server | High or Critical |
| Security tool or SIEM system | High or Critical |
| Privileged user account | High or Critical |
| Executive or administrator account | High or Critical |

---

## 9. Confidence Consideration

Severity and confidence are not the same.

- **Severity** measures the potential impact of the incident.
- **Confidence** measures how sure the system is about the classification.

| Confidence | Meaning |
|---|---|
| Low | Evidence is weak, incomplete, or unclear |
| Medium | Some evidence supports the classification |
| High | Strong evidence supports the classification |

A **High severity alert with Low confidence** should still be reviewed by a SOC analyst.

A **Low severity alert with High confidence** may be safely monitored or closed, depending on the workflow.

---

## 10. Severity Upgrade Rules

The Triage Agent should increase severity when any of the following are present:

- Confirmed malicious IOC
- Multiple threat intelligence sources agree
- Repeated suspicious activity
- Multiple affected users or hosts
- Privileged account involved
- Business-critical asset involved
- Signs of malware execution
- Signs of credential compromise
- Signs of lateral movement
- Signs of data exfiltration
- Signs of command-and-control communication
- Similar behaviour found in prior cases

---

## 11. Severity Downgrade Rules

The Triage Agent may reduce severity when most of the following are true:

- IOC is clean across threat intelligence sources
- Activity is explained by normal business operations
- No malware execution is observed
- No user or host compromise is confirmed
- No repeated activity is observed
- No sensitive asset is involved
- Alert is caused by a known benign tool
- Previous similar cases were false positives

---

## 12. Containment Guidance by Severity

| Severity | Containment Recommendation |
|---|---|
| Low | No containment required |
| Medium | Usually no containment, unless evidence increases |
| High | Recommend containment if compromise is likely |
| Critical | Recommend urgent containment with SOC analyst approval |

### Containment Actions

Containment actions may include:

- Isolate endpoint
- Disable user account
- Block IP address
- Block domain
- Quarantine file
- Revoke session tokens
- Reset credentials
- Block email sender or attachment

Containment for **High** and **Critical** severity incidents should require SOC analyst approval before execution.

---

## 13. Threat Hunting Activation

Threat hunting should be activated when:

- Severity is Critical
- Lateral movement is detected
- Confirmed malware or ransomware is detected
- Credential compromise is suspected or confirmed
- Command-and-control activity is detected
- Multiple related alerts appear across users or hosts
- Threat intelligence links the IOC to known campaigns

The Threat Hunting module should search for related IOCs, affected hosts, affected users, similar behaviours, and historical matches.

---

## 14. Final Severity Decision

The final severity should be determined using:

1. Alert evidence
2. IOC reputation
3. Threat intelligence enrichment
4. Asset criticality
5. User criticality
6. Number of affected systems
7. Evidence of compromise
8. Business impact
9. Confidence level
10. Similar prior cases

The Triage Agent should explain the reason for the selected severity in the triage output.

---

## 15. Required Triage Output Fields

When applying this policy, the Triage Agent should produce the following fields:

```json
{
  "severity": "Low | Medium | High | Critical",
  "confidence": "Low | Medium | High",
  "classification": "True Positive | False Positive",
  "likely_scenario": "Short explanation of what likely happened",
  "severity_reason": "Explanation of why this severity was selected",
  "recommended_action": "Next recommended SOC action",
  "containment_required": true,
  "containment_status": "not_required | recommended | pending_approval",
  "soc_analyst_approval_status": "not_required | pending | approved | rejected"
}
```

---

## 16. Policy Summary

Use this simplified logic:

| Evidence | Suggested Severity |
|---|---|
| Weak suspicious activity only | Low |
| Suspicious activity requiring review | Medium |
| Strong malicious evidence or likely compromise | High |
| Confirmed compromise, C2, ransomware, credential theft, lateral movement, or business-critical impact | Critical |

The Triage Agent should always prioritise safety when evidence suggests active compromise.