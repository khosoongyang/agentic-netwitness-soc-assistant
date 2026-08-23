# Report Writing SOP

## 1. Purpose

This Standard Operating Procedure (SOP) defines how the Reporting Agent generates, validates, updates, and finalises incident reports within the Agentic AI Threat Hunting and Autonomous Investigation Assistant.

The purpose of the Reporting Agent is to consolidate triage output, investigation findings, IOCs, behavioural patterns, MITRE ATT&CK mappings, containment actions, eradication actions, recovery actions, SOC analyst decisions, and lessons learnt into a structured incident report.

The Reporting Agent should not invent missing evidence. If required information is missing, it should request missing information from the Orchestration Agent before finalising the report.

---

## 2. Scope

This SOP applies to reports generated after triage and investigation.

This SOP is used by:

- Reporting Agent
- Orchestration Agent
- Triage Agent
- Investigation Agent
- SOC analyst review workflow
- Learning loop workflow
- ChromaDB knowledge base update process

This SOP applies to:

- Triage summaries
- Investigation reports
- Critical incident reports
- Containment reports
- False positive reports
- Final incident reports
- Lessons learnt and improvement summaries

---

## 3. Required Inputs

The Reporting Agent should receive triage output and investigation findings from the Orchestration Agent.

Expected input files may include:

```text
outputs/triage_result.json
outputs/investigation_result.json
outputs/approval_result.json
outputs/evidence_bundle.json
```

The inputs should include:

- Alert ID
- Incident ID
- Alert name
- Severity
- Confidence
- Classification
- Likely scenario
- Triage summary
- Investigation summary
- Affected users
- Affected hosts
- Source IP addresses
- Destination IP addresses
- Domains
- URLs
- File hashes
- Threat intelligence results
- Event timeline
- IOC correlation
- Behavioural patterns
- MITRE ATT&CK mapping
- Business impact
- Containment recommendation
- Containment approval status
- Containment outcome
- Eradication recommendations
- Recovery recommendations
- SOC analyst decision and feedback, if available

---

## 4. Required Knowledge Base References

During report writing, the Reporting Agent should retrieve and apply guidance from:

- `policies/reporting_timeline_policy.md`
- `policies/incident_severity_policy.md`
- `policies/containment_approval_policy.md`
- `policies/escalation_policy.md`
- `policies/false_positive_handling_policy.md`
- `procedures/investigation_sop.md`
- `report_templates/incident_report_template.md`
- `report_templates/executive_summary_template.md`
- `report_templates/technical_findings_template.md`
- Relevant playbooks and prior cases

---

## 5. Reporting Agent Responsibilities

The Reporting Agent is responsible for:

1. Receiving triage output and investigation findings from the Orchestration Agent
2. Extracting IOCs, findings, and behavioural patterns
3. Consolidating final IOCs
4. Building the incident timeline
5. Summarising triage and investigation findings
6. Including MITRE ATT&CK mapping
7. Including containment, eradication, and recovery actions
8. Generating a structured incident report
9. Checking whether the report is complete
10. Requesting missing information from the Orchestration Agent if needed
11. Sending the report to a SOC analyst for review
12. Capturing SOC analyst decision and feedback
13. Updating the report draft when corrections are provided
14. Recording edited fields
15. Updating report version history
16. Extracting lessons learnt and improvement points
17. Comparing analyst decisions with LLM recommendations
18. Identifying playbook gaps and scoring biases
19. Storing analyst-approved recommended actions in ChromaDB
20. Updating behavioural baseline references
21. Storing analyst-approved learning points in ChromaDB

---

## 6. Report Writing Procedure

### Step 1: Receive Triage and Investigation Findings

The Reporting Agent should begin by receiving triage output and investigation findings from the Orchestration Agent.

The agent should confirm that the following minimum fields are available:

- Alert ID
- Incident ID
- Severity
- Confidence
- Classification
- Likely scenario
- Triage summary
- Investigation summary
- Recommended next step

If these fields are missing, the report should not be finalised.

---

### Step 2: Extract IOCs, Findings, and Behavioural Patterns

The Reporting Agent should extract important technical details from the triage and investigation results.

IOCs may include:

- IP addresses
- Domains
- URLs
- File hashes
- Email senders
- Email recipients
- Hostnames
- User accounts
- Process names
- File names

Findings may include:

- Confirmed malicious IOC
- Suspicious process execution
- Suspicious network communication
- Phishing delivery
- Malware execution
- Credential compromise
- Lateral movement
- Data exfiltration
- False positive reason
- Control failure

Behavioural patterns may include:

- Repeated outbound communication
- Multiple affected hosts
- Same IOC seen across different alerts
- User behaviour anomaly
- Similar activity to prior cases
- Behaviour matching a known attack technique

Expected output field:

```json
{
  "extracted_iocs": [],
  "key_findings": [],
  "behavioural_patterns": []
}
```

---

### Step 3: Consolidate Final IOCs

The Reporting Agent should consolidate IOCs into a clean final IOC list.

The final IOC list should:

- Remove duplicates
- Group IOCs by type
- Include reputation result where available
- Include source of evidence
- Indicate whether the IOC is malicious, suspicious, clean, or unknown

Example output:

```json
{
  "final_iocs": {
    "ip_addresses": [],
    "domains": [],
    "urls": [],
    "file_hashes": [],
    "email_senders": [],
    "hosts": [],
    "users": []
  }
}
```

---

### Step 4: Build Incident Timeline

The Reporting Agent should build a clear incident timeline using timestamps from the alert, triage, investigation, threat intelligence, containment, and analyst review stages.

The timeline should include:

- Alert trigger time
- First suspicious activity
- IOC detection time
- Threat intelligence enrichment time
- Triage completion time
- Investigation findings
- Containment recommendation
- SOC analyst decision
- Containment execution, if applicable
- Report generation and review time

Example output:

```json
{
  "incident_timeline": [
    {
      "timestamp": "2026-05-20T10:12:00Z",
      "event": "Suspicious attachment alert triggered"
    },
    {
      "timestamp": "2026-05-20T10:15:00Z",
      "event": "Threat intelligence confirmed malicious file hash"
    },
    {
      "timestamp": "2026-05-20T10:20:00Z",
      "event": "Triage classified alert as Critical"
    }
  ]
}
```

---

### Step 5: Summarise Triage Findings

The Reporting Agent should summarise the triage result in SOC-friendly language.

The triage summary should include:

- Severity
- Confidence
- Classification
- Likely scenario
- Main reason for severity
- Main reason for confidence
- Containment requirement
- Escalation requirement

Example:

```text
The alert was classified as Critical with High confidence due to a confirmed malicious file hash, suspicious endpoint activity, and threat intelligence evidence from multiple sources.
```

---

### Step 6: Summarise Investigation Findings

The Reporting Agent should summarise the investigation result.

The investigation summary should include:

- Investigation starting point
- Selected playbook
- Evidence collected
- Event timeline summary
- IOC correlation result
- Behavioural analysis
- MITRE ATT&CK mapping
- Business impact
- Updated severity
- Updated confidence
- Control failures
- Eradication recommendations
- Recovery recommendations

Example:

```text
The investigation confirmed that the affected endpoint was associated with a malicious file hash and suspicious outbound communication. The behaviour was mapped to phishing attachment delivery and possible malware execution.
```

---

### Step 7: Include MITRE ATT&CK Mapping

The report should include MITRE ATT&CK tactics and techniques where available.

The MITRE section should include:

- Tactic
- Technique ID
- Technique name
- Evidence supporting the mapping
- Confidence of mapping

Example:

```json
{
  "mitre_attack_mapping": [
    {
      "tactic": "Initial Access",
      "technique": "T1566.001 Spearphishing Attachment",
      "reason": "Suspicious email attachment was involved in the alert"
    }
  ]
}
```

---

### Step 8: Include Containment, Eradication, and Recovery Actions

The report should include all response actions recommended or taken.

Containment section should include:

- Whether containment was recommended
- Recommended containment action
- Reason for containment
- Approval requirement
- SOC analyst approval status
- Containment action executed, if any
- Containment outcome
- Containment verification result

Eradication section should include:

- Malware removal recommendation
- Malicious file removal
- Persistence removal
- Credential reset
- Blocking malicious infrastructure
- Detection rule update

Recovery section should include:

- Endpoint validation
- Reconnection steps
- User account restoration
- Monitoring period
- Follow-up checks
- Lessons learnt

---

### Step 9: Generate Structured Incident Report

The Reporting Agent should generate a structured report using the relevant report template.

Recommended report sections:

1. Report Metadata
2. Executive Summary
3. Incident Overview
4. Severity and Confidence
5. Classification
6. Affected Entities
7. Final IOC List
8. Timeline of Events
9. Triage Summary
10. Investigation Summary
11. Threat Intelligence Summary
12. MITRE ATT&CK Mapping
13. Business Impact
14. Containment Actions
15. Eradication Actions
16. Recovery Actions
17. SOC Analyst Review
18. Lessons Learnt
19. Recommendations
20. Final Status

---

## 7. Report Completeness Check

After generating the report, the Reporting Agent should check whether the report is complete.

A report is complete only if the required fields are present.

Required fields:

- Alert ID
- Incident ID
- Severity
- Confidence
- Classification
- Likely scenario
- Executive summary
- Technical summary
- Affected entities
- Evidence summary
- IOC list
- Timeline
- Recommended action
- Report status

For High and Critical incidents, the report should also include:

- Business impact
- MITRE ATT&CK mapping
- Containment recommendation
- SOC analyst review status
- Eradication recommendation
- Recovery recommendation
- Escalation status

If the report is incomplete, the Reporting Agent should request missing information from the Orchestration Agent.

Example output:

```json
{
  "report_status": "missing_information_required",
  "missing_report_fields": [
    "severity",
    "confidence",
    "classification",
    "likely_scenario"
  ],
  "recommended_next_step": "Request missing information from Orchestration Agent"
}
```

---

## 8. Missing Information Handling

If required information is missing, the Reporting Agent should not finalise the report.

The agent should:

1. List the missing fields
2. Explain why each field is required
3. Request missing information from the Orchestration Agent
4. Keep the report as draft
5. Avoid inventing values

Example:

```json
{
  "current_stage": "reporting_incomplete",
  "report_complete": false,
  "missing_information_request": [
    {
      "missing_field": "updated_confidence",
      "reason_needed": "Required to justify the reliability of the investigation finding",
      "suggested_source": "investigation_result.json"
    }
  ],
  "recommended_next_step": "Return to Orchestration Agent"
}
```

---

## 9. SOC Analyst Review

If the report is complete, the Reporting Agent should send it to the SOC analyst for review.

SOC analyst review is required when:

- Severity is High
- Severity is Critical
- Containment was recommended
- Containment was executed
- Escalation is required
- Business-critical asset is involved
- Confidence is Low but severity is High or Critical
- Report updates will affect learning loop or ChromaDB

The SOC analyst may:

- Approve the report
- Reject the report
- Request changes
- Provide comments
- Edit the report directly

Expected output:

```json
{
  "soc_review_required": true,
  "soc_review_status": "pending",
  "report_status": "pending_soc_review"
}
```

---

## 10. Handling SOC Analyst Corrections

If the SOC analyst does not approve the report or requests changes, the Reporting Agent should update the report draft.

The workflow supports two correction methods:

1. Corrections via prompts or comments
2. Direct report edits

### 10.1 Corrections via Prompts or Comments

If the SOC analyst provides corrections through prompts or comments, the Reporting Agent should:

1. Interpret the correction instructions
2. Modify the report draft
3. Record edited fields
4. Update report version history
5. Send the updated report back to the SOC analyst for review

Example output:

```json
{
  "correction_method": "prompts_or_comments",
  "correction_summary": "SOC analyst requested clearer containment justification",
  "edited_fields": [
    "containment_reason",
    "business_impact"
  ],
  "report_version": "v2",
  "recommended_next_step": "Send updated report to SOC Analyst for review"
}
```

### 10.2 Direct Report Edits

If the SOC analyst edits the report directly, the Reporting Agent should:

1. Detect or receive the edited report
2. Record which fields were changed
3. Preserve the analyst-edited content
4. Update report version history
5. Send the updated report for review or finalisation

Example output:

```json
{
  "correction_method": "direct_report_edit",
  "edited_fields": [
    "executive_summary",
    "recovery_recommendations"
  ],
  "report_version": "v2",
  "recommended_next_step": "Send updated report to SOC Analyst for review"
}
```

---

## 11. Report Approval Handling

If the SOC analyst approves the report, the Reporting Agent should mark the report as approved and ready for finalisation.

Example output:

```json
{
  "soc_review_status": "approved",
  "report_status": "approved_for_finalisation",
  "approved_by": "SOC Analyst"
}
```

If the SOC analyst requests changes, the report should remain in draft form.

Example output:

```json
{
  "soc_review_status": "changes_required",
  "report_status": "draft_revision_required",
  "recommended_next_step": "Update report draft based on analyst feedback"
}
```

---

## 12. Report Version History

The Reporting Agent should maintain report version history whenever the report is changed.

The version history should record:

- Report version
- Timestamp
- Changed fields
- Reason for change
- Change source
- SOC analyst feedback, if available

Example:

```json
{
  "report_version_history": [
    {
      "version": "v1",
      "change_source": "Reporting Agent",
      "changed_fields": [
        "initial_report_created"
      ],
      "reason": "Initial report generated from triage and investigation findings"
    },
    {
      "version": "v2",
      "change_source": "SOC Analyst",
      "changed_fields": [
        "containment_reason"
      ],
      "reason": "Analyst requested clearer containment justification"
    }
  ]
}
```

---

## 13. Learning Loop and Knowledge Base Update

After the SOC analyst reviews the report, the Reporting Agent should extract lessons learnt and improvement points.

Possible learning points include:

- Better containment recommendations
- More accurate severity scoring
- More accurate confidence scoring
- Playbook gaps
- Missing evidence types
- False positive patterns
- New behavioural baseline references
- New analyst-approved recommended actions
- Improvements to report wording
- Improvements to detection or triage logic

The Reporting Agent should compare analyst decisions and LLM recommendations to identify:

- Where the LLM was correct
- Where the LLM overestimated severity
- Where the LLM underestimated severity
- Where confidence scoring was too high or too low
- Where containment recommendation was accepted, rejected, or modified
- Where playbook guidance was incomplete

---

## 14. Learning Update Approval

Learning updates must be approved by the SOC analyst before they are stored in ChromaDB.

If the SOC analyst approves learning updates, the Reporting Agent may store:

- Analyst-approved recommended actions
- Analyst-approved learning points
- Updated behavioural baseline references
- Confirmed false positive patterns
- Confirmed prior case summaries
- Playbook gap notes
- Scoring bias notes

Example output:

```json
{
  "learning_updates_approved": true,
  "learning_updates_stored": true,
  "stored_in": "ChromaDB",
  "stored_items": [
    "analyst_approved_recommended_actions",
    "learning_points",
    "behavioural_baseline_references"
  ]
}
```

If learning updates are not approved or changes are required, the Reporting Agent should not store them permanently.

Example output:

```json
{
  "learning_updates_approved": false,
  "learning_updates_stored": false,
  "reason": "SOC analyst requested changes before knowledge base update"
}
```

---

## 15. Required Output

The Reporting Agent should produce:

```text
outputs/report_result.json
```

Required fields:

```json
{
  "current_stage": "reporting_completed",
  "alert_id": "example-alert-id",
  "incident_id": "example-incident-id",
  "report_required": true,
  "report_type": "incident_report",
  "report_complete": true,
  "report_status": "pending_soc_review",
  "report_version": "v1",
  "severity": "Low | Medium | High | Critical",
  "confidence": "Low | Medium | High",
  "classification": "True Positive | False Positive | Likely False Positive | Needs Review",
  "executive_summary": "Short non-technical summary",
  "technical_summary": "Technical investigation summary",
  "final_iocs": {},
  "incident_timeline": [],
  "triage_summary": "Summary of triage findings",
  "investigation_summary": "Summary of investigation findings",
  "mitre_attack_mapping": [],
  "business_impact": "Business impact summary",
  "containment_actions": [],
  "eradication_actions": [],
  "recovery_actions": [],
  "soc_review_required": true,
  "soc_review_status": "pending",
  "missing_report_fields": [],
  "report_version_history": [],
  "learning_update_recommended": false,
  "learning_updates_approved": false,
  "recommended_next_step": "Send to SOC Analyst for review"
}
```

---

## 16. Quality Checks Before Saving Report Result

Before saving `report_result.json`, the Reporting Agent should confirm that:

- Alert ID is present
- Incident ID is present, if available
- Severity is present
- Confidence is present
- Classification is present
- Executive summary is present
- Technical summary is present
- IOCs are consolidated
- Timeline is included or a reason is given if unavailable
- Triage summary is included
- Investigation summary is included
- MITRE ATT&CK mapping is included, if available
- Containment, eradication, and recovery actions are included
- SOC analyst review status is recorded
- Missing fields are listed if the report is incomplete
- Report version history is updated when changes occur
- Learning updates are not stored unless approved

---

## 17. Routing Summary

Use the following routing logic:

| Reporting Condition | Next Step |
|---|---|
| Report missing required information | Request missing information from Orchestration Agent |
| Report complete | Send to SOC Analyst for review |
| SOC analyst approves report | Finalise report |
| SOC analyst requests changes | Update report draft |
| Corrections via prompts or comments | Interpret instructions and modify draft |
| Corrections via direct edit | Record edited fields and update version history |
| Updated report ready | Send updated report to SOC Analyst for review |
| Learning updates approved | Store approved learning points in ChromaDB |
| Learning updates not approved | Do not update ChromaDB |

---

## 18. SOP Summary

Use this simplified process:

1. Receive triage output and investigation findings from the Orchestration Agent.
2. Extract IOCs, findings, and behavioural patterns.
3. Consolidate final IOCs.
4. Build the incident timeline.
5. Summarise triage findings.
6. Summarise investigation findings.
7. Include MITRE ATT&CK mapping.
8. Include containment, eradication, and recovery actions.
9. Generate a structured incident report.
10. Check whether the report is complete.
11. If incomplete, request missing information from the Orchestration Agent.
12. If complete, send the report to the SOC analyst for review.
13. Capture SOC analyst decision and feedback.
14. If changes are required, update the report draft.
15. Record edited fields.
16. Update report version history.
17. Send the updated report back for review.
18. Extract lessons learnt and improvement points.
19. Compare analyst decisions against LLM recommendations.
20. Identify playbook gaps and scoring biases.
21. Store only analyst-approved recommended actions and learning points in ChromaDB.
22. Update behavioural baseline references only after approval.