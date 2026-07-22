**CYBERSECURITY POLICIES BOOK FOR POLICY-BASED CHECKS**

**1\. Purpose**

This Policies Book defines the policy-based checks used by the SOC system to support decision-making during alert triage, investigation, escalation, containment, reporting, and post-incident learning.

This document does not replace the workflow diagrams. The workflow diagrams define how the AI agents operate. This Policies Book defines the rules that support specific decision points in the workflow.

The purpose of this document is to ensure that AI agents do not rely only on LLM reasoning when handling cybersecurity alerts. Instead, the agents shall apply approved policy rules before deciding whether an alert is authorised, suspicious, severe, reportable, or requires SOC Analyst review.

**2\. Scope**

This document applies to policy-based decision points used by the following SOC components:

| **Component**                | **Policy Relevance**                                                                                             |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Triage Agent                 | Uses policy checks to determine whether an alert is whitelisted, authorised, expected, or requires LLM reasoning |
| Investigation Agent          | Uses policy checks to assess evidence, business impact, severity, confidence, and containment eligibility        |
| Reporting and Learning Agent | Uses policy checks before generating reports, updating baselines, or storing cases in ChromaDB                   |
| Orchestrator Agent           | Uses policy checks to enforce routing decisions based on severity, uncertainty, and approval requirements        |
| SOC Analyst                  | Reviews high-risk, uncertain, or containment-sensitive cases                                                     |
| Incident Response Team       | Performs approved response, containment, eradication, recovery, and forensic handling where required             |

**3\. Use of Policy-Based Checks**

Policy-based checks shall be used as decision rules that support the SOC workflow.

The system shall refer to this Policies Book when it needs to determine:

- Whether an alert is complete enough to process.
- Whether an activity is whitelisted.
- Whether an activity is authorised.
- Whether an activity is expected behaviour.
- Whether LLM reasoning is required.
- How an alert should be classified.
- What severity should be assigned.
- Whether deeper investigation is required.
- Whether containment can be performed autonomously.
- Whether SOC Analyst approval is required.
- Whether the report is complete.
- Whether the case can be stored for future learning.

**4\. Policy-Based Decision Point Register**

| **Decision Point ID** | **Workflow Location**                                                 | **Policy Reference**      | **Decision Supported**                                                       |
| --------------------- | --------------------------------------------------------------------- | ------------------------- | ---------------------------------------------------------------------------- |
| DP-01                 | Triage Agent: Retrieve similar historical cases from ChromaDB         | Appendix E                | Supports historical case outcome check                                       |
| DP-02                 | Triage Agent: Check internal records and whitelists                   | Appendix E                | Determines whether the activity matches approved records or trusted entities |
| DP-03                 | Triage Agent: Validate authorisation and expected behaviour           | Appendix E                | Determines whether the activity is permitted and normal                      |
| DP-04                 | Triage Agent: Whitelisted, authorised and expected?                   | Appendix E                | Routes the case to Reporting Agent or LLM reasoning                          |
| DP-05                 | Triage Agent: Classify alert type                                     | Appendix D                | Assigns the correct threat action category                                   |
| DP-06                 | Triage Agent: Initial severity and threshold check                    | Appendix A and Appendix C | Assigns initial severity                                                     |
| DP-07                 | Investigation Agent: Assess business impact                           | Appendix C                | Determines operational, user, system, and data impact                        |
| DP-08                 | Investigation Agent: Generate final severity score                    | Appendix A                | Confirms final severity after investigation                                  |
| DP-09                 | Investigation Agent: Generate confidence score                        | Appendix F                | Determines whether the conclusion is reliable                                |
| DP-10                 | Investigation Agent: Low or medium severity and high confidence?      | Appendix G                | Determines whether autonomous containment may be allowed                     |
| DP-11                 | Investigation Agent: High or critical severity, or uncertain?         | Appendix G                | Determines whether SOC Analyst approval is required                          |
| DP-12                 | Reporting Agent: Generate post-incident report                        | Appendix J                | Ensures the report contains required fields                                  |
| DP-13                 | Reporting Agent: Update recommended actions and behavioural baselines | Appendix K                | Determines whether learning updates are allowed                              |
| DP-14                 | Reporting Agent: Store incident case in ChromaDB                      | Appendix K                | Determines whether the case can be stored as approved memory                 |
| DP-15                 | Data security incident identified                                     | Appendix B and Appendix L | Determines whether enhanced reporting and response are required              |

**5\. General Escalation Rule**

The system shall escalate the case to a SOC Analyst when any of the following conditions are met:

| **Condition**                                                  | **Required Action** |
| -------------------------------------------------------------- | ------------------- |
| Final severity is High or Critical                             | Send to SOC Analyst |
| Evidence is uncertain or incomplete                            | Send to SOC Analyst |
| Confidence score is Low or Medium                              | Send to SOC Analyst |
| Critical system is involved                                    | Send to SOC Analyst |
| Sensitive or personal data is involved                         | Send to SOC Analyst |
| Ransomware is suspected                                        | Send to SOC Analyst |
| Compromised guest OS is suspected in a virtualised environment | Send to SOC Analyst |
| Containment may disrupt operations                             | Send to SOC Analyst |
| LLM recommendation conflicts with policy result                | Send to SOC Analyst |

**6\. General Reporting and Learning Rule**

The Reporting and Learning Agent shall only update recommendations, behavioural baselines, or ChromaDB memory when:

- The case has a confirmed final outcome.
- Evidence is sufficient.
- Severity and confidence are recorded.
- The report is complete.
- SOC Analyst decision is included where applicable.
- The update does not normalise malicious behaviour.

The Reporting and Learning Agent shall not update learning records when:

- Evidence is incomplete.
- Confidence is Low.
- The case is still open.
- The SOC Analyst decision conflicts with the LLM recommendation.
- The activity is malicious and should not be treated as normal behaviour.
- Sensitive raw data would be unnecessarily embedded into ChromaDB.

**Appendix A**

**Incident Severity Classification and Reporting Matrix**

**A.1 Purpose**

This appendix defines the severity levels used by the SOC system during triage and investigation.

The SOC severity model consists of four levels:

- Low
- Medium
- High
- Critical

This appendix supports:

- Triage Agent initial severity assessment.
- Investigation Agent final severity assessment.
- Orchestrator Agent escalation decisions.
- SOC Analyst review prioritisation.

**A.2 Incident Severity Classification Matrix**

| **Rating** | **Nature and Impact of Incident**                                                                                                          | **Examples of Incidents**                                                                                                                          | **SOC Required Action**                                                              |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Critical   | Major compromise, sensitive data exposure, ransomware, widespread service outage, critical system impact, or severe operational disruption | Ransomware, data exfiltration, compromise of critical server, multiple systems affected, major outage, serious sensitive data exposure             | Mandatory SOC Analyst review, urgent escalation, formal incident report              |
| High       | Strongly suspected or confirmed cyber attack affecting important assets, users, or systems                                                 | Successful unauthorised access, malicious IOC, privilege misuse, server attack, repeated suspicious activity, attack against important application | Route to Investigation Agent and require SOC Analyst review if containment is needed |
| Medium     | Suspicious activity with limited impact or contained consequences                                                                          | Phishing attempt, suspicious login, failed brute force attempt, unusual connection, limited endpoint alert, suspicious but unconfirmed IOC         | Continue triage or investigation, monitor, and escalate if evidence increases        |
| Low        | Minimal impact, localised alert, or confirmed authorised activity                                                                          | Approved vulnerability scan, benign endpoint notification, expected service account activity, authorised admin action                              | Record, monitor, or route to Reporting Agent for closure                             |

**A.3 Severity Escalation Factors**

The SOC system shall increase severity when any of the following are present:

- Critical or sensitive system affected.
- Internet-facing service affected.
- Personal, confidential, or sensitive data involved.
- Multiple users or systems affected.
- Repeated or spreading activity.
- Malware, ransomware, or privilege misuse suspected.
- Service outage or degradation observed.
- External threat intelligence confirms malicious activity.
- Similar historical cases were previously confirmed as true incidents.
- The affected system supports an important business or operational function.

**A.4 Severity Reduction Factors**

The SOC system may reduce severity when:

- Activity is confirmed as authorised.
- Activity occurred during an approved maintenance window.
- The alert is caused by an approved scanner or service account.
- No critical system is involved.
- No sensitive data is involved.
- No user or operational impact is observed.
- Similar historical cases were confirmed false positives and the current case closely matches them.
- Evidence confirms that the alert was generated by expected behaviour.

**A.5 Reporting Timeline**

| **Severity** | **SOC Reporting Expectation**                                                |
| ------------ | ---------------------------------------------------------------------------- |
| Critical     | Generate urgent incident report draft immediately and route to SOC Analyst   |
| High         | Generate investigation report and route to SOC Analyst if action is required |
| Medium       | Generate investigation summary after triage or investigation                 |
| Low          | Generate closure record or monitoring record                                 |

**Appendix B**

**Significance of Data Incident**

**B.1 Purpose**

This appendix defines how incidents involving personal, confidential, or sensitive data are assessed.

It supports escalation decisions when the alert suggests possible data exposure, data leakage, unauthorised access, or data exfiltration.

**B.2 Data Incident Significance Matrix**

| **Significance of Incident** | **Implications**                                                                                    | **SOC Action**                                                                 |
| ---------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Highly significant incident  | Could cause public harm, endanger safety or health, or seriously affect public trust                | Classify as Critical, escalate to SOC Analyst, and generate urgent report      |
| Significant incident         | Could cause serious physical, financial, reputational, or personal harm, or affect a sizeable group | Classify as High or Critical depending on impact, mandatory SOC Analyst review |
| All other incidents          | Temporary or minor inconvenience only                                                               | Record, investigate if needed, and generate report                             |

**B.3 Data Security Trigger Conditions**

The SOC system shall treat an alert as a possible data security incident when:

- Personal data is exposed.
- Confidential or sensitive records are accessed without authorisation.
- Database exposure is detected.
- Data exfiltration is suspected.
- Lost ICT equipment may contain sensitive data.
- Unauthorised third-party access is suspected.
- A user, system, or vendor accessed data outside expected scope.
- Unusual download, copy, export, or transfer of sensitive data is observed.

**Appendix C**

**Impact and Severity Assessment Factors**

**C.1 Purpose**

This appendix defines the factors that the SOC system shall consider before assigning initial or final severity.

It supports:

- Initial severity checks by the Triage Agent.
- Business impact checks by the Investigation Agent.
- Escalation decisions by the Orchestrator Agent.

**C.2 Impact and Severity Assessment Checklist**

| **Factor**           | **Policy Check Question**                                                    |
| -------------------- | ---------------------------------------------------------------------------- |
| Essential service    | Is an important or essential service affected?                               |
| Critical system      | Is a critical or significant system impacted?                                |
| Service exposure     | Is the affected service internet-facing, intranet-facing, or internal-only?  |
| Users affected       | How many users are affected?                                                 |
| Recurrence frequency | Is the activity repeated or spreading?                                       |
| Time of incident     | Did it occur during unusual hours or outside an approved maintenance window? |
| Data sensitivity     | Is personal, confidential, or sensitive data involved?                       |
| Alternative service  | Is there an alternative service available?                                   |
| Operational impact   | Is there outage, degradation, or loss of business function?                  |
| Historical pattern   | Did similar past cases result in confirmed incidents?                        |
| Asset ownership      | Is the affected system owned by a critical department or function?           |
| External impact      | Could the incident affect external users, partners, or public trust?         |

**Appendix D**

**Threat Action Classification Matrix**

**D.1 Purpose**

This appendix defines the threat action categories used by the Triage Agent and Investigation Agent.

It supports alert type classification after the Triage Agent identifies likely attack scenarios.

**D.2 Threat Action Matrix**

| **Threat Action** | **Definition**                                                                            | **Example**                                                                        |
| ----------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| DoS/DDoS          | Attacks that aim to make an ICT system, service, or network unavailable to intended users | Service unavailability, high resource utilisation, flood traffic                   |
| Error             | Actions that are done incorrectly or accidentally                                         | Misconfiguration, programming error, accidental exposure                           |
| Hacking           | Any attempt to intentionally access or harm ICT assets without authorisation              | Brute force, SQL injection, web defacement, buffer overflow, remote file inclusion |
| Malware           | Malicious software designed to cause damage or unwanted actions                           | Ransomware, trojan, spyware, rootkit, keylogger, backdoor, botnet                  |
| Misuse            | Abuse of trusted organisation resources or privileges for purposes other than intended    | Abuse of administrator privileges, user policy violation, non-approved asset usage |
| Social            | Deception, manipulation, intimidation, or nuisance used to exploit users                  | Phishing, impersonation, spam                                                      |
| Unknown           | Insufficient evidence to classify the alert                                               | Incomplete or unclear alert                                                        |

**Appendix E**

**Triage Agent Policy-Based Checks**

**E.1 Purpose**

This appendix defines the policy checks that support the Triage Agent's early decision-making.

The Triage Agent workflow should show the following operational steps:

- Check internal records and whitelists.
- Validate authorisation and expected behaviour.
- Decide whether the alert is whitelisted, authorised, and expected.

The detailed TRI checks in this appendix are internal validation rules used to support those workflow steps and the final triage decision.

**E.2 Triage Agent Policy-Based Check Table**

| **Check ID** | **Policy-Based Check**        | **Supports Workflow Step**                      | **Purpose**                                                                                                     |
| ------------ | ----------------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| TRI-01       | Alert completeness check      | Validate authorisation and expected behaviour   | Checks whether the alert has enough information for triage                                                      |
| TRI-02       | Internal records check        | Check internal records and whitelists           | Checks asset records, approved changes, maintenance windows, known scanners, and known service accounts         |
| TRI-03       | Whitelist check               | Check internal records and whitelists           | Checks approved IPs, domains, users, service accounts, scanners, and tools                                      |
| TRI-04       | Authorisation check           | Validate authorisation and expected behaviour   | Checks whether the action is allowed for the user, system, time, and purpose                                    |
| TRI-05       | Expected behaviour check      | Validate authorisation and expected behaviour   | Checks whether the behaviour is normal even if the entity is trusted                                            |
| TRI-06       | Historical case outcome check | Retrieve similar historical cases from ChromaDB | Uses retrieved ChromaDB cases to check whether similar alerts were benign, authorised, suspicious, or malicious |

**E.3 Whitelisted, Authorised and Expected Decision Matrix**

| **Result**                                      | **Meaning**                                                                                                             | **Required Action**                              |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| Yes                                             | The alert is complete, the activity is authorised, the entity is whitelisted or approved, and the behaviour is expected | Send to Reporting Agent for closure record       |
| No                                              | The activity is not authorised, not whitelisted, or has no approved business reason                                     | Trigger LLM reasoning                            |
| Unclear                                         | The evidence is incomplete, partially authorised, or conflicting                                                        | Trigger LLM reasoning or route for manual review |
| Whitelisted but unusual                         | The entity is trusted, but the behaviour is abnormal                                                                    | Trigger LLM reasoning                            |
| Historically suspicious                         | Similar historical cases were confirmed malicious or required investigation                                             | Trigger LLM reasoning                            |
| Historically benign and current context matches | Similar historical cases were benign, and current behaviour matches closely                                             | May support closure through Reporting Agent      |

**Appendix F**

**Investigation Evidence and Confidence Rules**

**F.1 Purpose**

This appendix defines the evidence and confidence rules used by the Investigation Agent.

**F.2 Evidence Sufficiency Matrix**

| **Evidence Status**           | **Meaning**                                      | **Required Action**                                |
| ----------------------------- | ------------------------------------------------ | -------------------------------------------------- |
| Sufficient evidence           | Multiple reliable sources support the conclusion | Proceed with final severity and confidence scoring |
| Partially sufficient evidence | Some evidence exists, but there are gaps         | Continue investigation or treat as uncertain       |
| Insufficient evidence         | Evidence is missing, weak, or conflicting        | Route to SOC Analyst if action is required         |
| Conflicting evidence          | Sources do not support the same conclusion       | Treat as uncertain and require further review      |

**F.3 Confidence Score Matrix**

| **Confidence Level** | **Meaning**                                                            | **Example Condition**                                                 |
| -------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------- |
| High                 | Strong evidence from multiple reliable sources supports the conclusion | Logs, internal records, threat intelligence, and timeline are aligned |
| Medium               | Some evidence supports the conclusion, but there are gaps              | IOC is suspicious, but endpoint evidence is missing                   |
| Low                  | Evidence is weak, incomplete, or conflicting                           | Alert has limited fields or conflicting investigation results         |

**Appendix G**

**Human Approval and Containment Rules**

**G.1 Purpose**

This appendix defines when autonomous containment is allowed and when SOC Analyst approval is required.

**G.2 Containment Decision Matrix**

| **Condition**                                                  | **Required Action**                                                         |
| -------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Low or Medium severity and High confidence                     | Approved autonomous low-risk containment may be executed                    |
| Autonomous containment is executed                             | Send containment outcome to Reporting Agent                                 |
| High or Critical severity                                      | Send to SOC Analyst for mandatory approval                                  |
| Evidence is uncertain                                          | Send to SOC Analyst for mandatory approval                                  |
| SOC Analyst approves containment                               | Execute containment and send outcome to Reporting Agent                     |
| SOC Analyst rejects containment                                | Do not execute containment, update case status, and send to Reporting Agent |
| Confidence is Low or Medium                                    | Treat as uncertain and send to SOC Analyst                                  |
| Critical system is involved                                    | Send to SOC Analyst                                                         |
| Sensitive or personal data is involved                         | Send to SOC Analyst                                                         |
| Ransomware is suspected                                        | Send to SOC Analyst                                                         |
| Compromised guest OS is suspected in a virtualised environment | Send to SOC Analyst                                                         |
| Containment may disrupt operations                             | Send to SOC Analyst                                                         |
| LLM recommendation conflicts with policy result                | Send to SOC Analyst                                                         |

**Appendix H**

**Ransomware Incident Handling Rules**

**H.1 Purpose**

This appendix defines special handling rules when ransomware is suspected.

It shall be used when the threat action category is Malware and ransomware indicators are observed.

**H.2 Containment**

- Do not immediately shut down the affected computer as the first action.
- Disconnect the infected computer from the network and storage devices to limit the spread of ransomware and prevent encryption of backup files.
- Escalate the case to the SOC Analyst or Incident Response Team.
- Prevent further access to shared drives or backup locations where possible, subject to approval.

**H.3 Preserve, Gather, and Handle Evidence**

- Take a screenshot or picture of the ransomware note where possible.
- Hibernate the infected computer if possible.
- If hibernation is not possible, acquire the memory image.
- Shut down the computer only if memory acquisition is not possible or after memory acquisition.
- Acquire a forensic image if required.
- Analyse the ransomware to determine whether recovery or decryption is possible.
- Record file extensions, ransom note text, affected paths, usernames, hostnames, and timestamps.

**H.4 Determine Extent of Compromise**

- Assess what data was encrypted.
- Check whether backups are available.
- Search for related ransomware indicators across NetWitness, PostgreSQL, and ChromaDB.
- Identify whether other hosts show similar ransomware behaviour.
- Record all affected users, hosts, files, and systems.

**Appendix I**

**Virtualised Guest OS Compromise Handling Rules**

**I.1 Purpose**

This appendix defines handling rules when a compromised guest operating system is detected in a virtualised hosting environment.

**I.2 Required Handling Actions**

- Treat related guest operating systems on the same hardware host and connected hosts as potentially compromised until assessed.
- Identify the affected guest operating system.
- Identify guest operating systems on the same hardware host.
- Identify connected hosts or related virtual machines.
- Conduct checks on each guest operating system.
- Look for signs of compromise across related systems.
- Recommend recovery from the last-known good image where required.
- Route recovery actions to the SOC Analyst or Incident Response Team for approval.

**Appendix J**

**Post-Incident Inquiry Report Requirements**

**J.1 Purpose**

This appendix defines the required information for post-incident reporting.

**J.2 Required Report Fields**

| **Field**                     | **Required**  |
| ----------------------------- | ------------- |
| Incident ID                   | Yes           |
| Detection time                | Yes           |
| Reporting time                | Yes           |
| Alert source                  | Yes           |
| Affected system or asset      | Yes           |
| Key IOCs                      | If available  |
| Threat action category        | Yes           |
| Severity rating               | Yes           |
| Confidence level              | Yes           |
| Timeline of events            | Yes           |
| Investigation summary         | Yes           |
| Actions taken                 | Yes           |
| Containment outcome           | If applicable |
| Analyst decision              | If reviewed   |
| Final outcome                 | Yes           |
| Lessons learnt                | Yes           |
| Recommended follow-up actions | Yes           |

**J.3 Post-Incident Report Timeline**

The Reporting Agent shall generate a post-incident report after investigation completion.

Where a formal post-incident inquiry report is required, it should be prepared within 14 days.

**Appendix K**

**Reporting and Learning Agent Rules**

**K.1 Purpose**

This appendix defines the rules used by the Reporting and Learning Agent before updating recommended actions, behavioural baselines, or ChromaDB memory.

**K.2 Reporting and Learning Checks**

| **Check ID** | **Policy Check**                                | **Decision Rule**                                  |
| ------------ | ----------------------------------------------- | -------------------------------------------------- |
| REP-01       | Ingest investigation brief including IOCs       | Ensure the report has sufficient evidence          |
| REP-02       | Compare analyst decision and LLM recommendation | Identify agreement, partial agreement, or mismatch |
| REP-03       | Identify playbook gaps and scoring bias         | Flag weaknesses for improvement                    |
| REP-04       | Update recommended actions                      | Update only when the outcome is reliable           |
| REP-05       | Update behavioural baseline                     | Update only when activity is confirmed legitimate  |
| REP-06       | Store incident case in ChromaDB                 | Store only complete and approved cases             |
| REP-07       | Generate post-incident report                   | Produce final report after investigation           |

**Appendix L**

**Service Standards for Data Security Incident Response**

**L.1 Purpose**

This appendix defines service response expectations when a data security incident may involve members of the public.

**L.2 Service Response Standards**

| **Category** | **Definition**                                                    | **SOC Response Expectation**        |
| ------------ | ----------------------------------------------------------------- | ----------------------------------- |
| Simple       | Straightforward case with readily available information           | Generate response summary quickly   |
| Standard     | Case requires some investigation                                  | Investigation Agent review required |
| Complex      | Case requires significant investigation or cross-team involvement | Mandatory SOC Analyst review        |

**Appendix M**

**Audit Log Requirements for Policy-Based Checks**

**M.1 Purpose**

This appendix defines the audit information that should be recorded whenever a policy-based check influences an AI agent decision.

**M.2 Required Audit Fields**

| **Field**             | **Description**                                                        |
| --------------------- | ---------------------------------------------------------------------- |
| Audit ID              | Unique audit record identifier                                         |
| Incident ID           | Related incident or alert ID                                           |
| Agent Name            | Agent that performed the action or decision                            |
| Policy Reference      | Appendix or policy rule used                                           |
| Decision Point        | Workflow decision supported by the policy                              |
| Input Summary         | Summary of evidence used                                               |
| Result                | Pass, fail, warning, unknown, or not applicable                        |
| Decision Made         | Route, close, investigate, escalate, contain, report, or learn         |
| Timestamp             | Time the decision was made                                             |
| Evidence Reference    | Link or reference to logs, IOCs, reports, screenshots, or case records |
| Human Review Required | Yes or no                                                              |
| Final Reviewer        | SOC Analyst name or role, if applicable                                |

**Appendix N**

**Policy Review and Maintenance**

**N.1 Purpose**

This appendix defines when the Policies Book should be reviewed and updated.

**N.2 Review Triggers**

The Policies Book should be reviewed when:

- The workflow diagram changes.
- New use cases are added.
- New detection logic is added.
- New playbooks are added.
- Testing identifies false positives or false negatives.
- Severity or confidence scoring logic changes.
- The system's autonomous action scope changes.

**N.3 Change Record Fields**

| **Field**         | **Description**                  |
| ----------------- | -------------------------------- |
| Change ID         | Unique change reference          |
| Section Updated   | Main section or appendix changed |
| Reason for Change | Why the update was needed        |
| Updated By        | Person who made the change       |
| Review Status     | Draft, reviewed, or approved     |
| Effective Date    | Date the change takes effect     |

**END**