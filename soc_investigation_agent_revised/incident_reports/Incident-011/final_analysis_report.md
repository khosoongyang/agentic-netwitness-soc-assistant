# INVESTIGATION SUMMARY: INC-52825 (Incident-011)

**Final Severity:** Critical
*Critical is justified because the incident shows active internal compromise with 1558 alerts, lateral movement, privileged account abuse, UAC-disabling behavior, high CPU usage, and traffic to known-bad/unusual IPs. Appendix A escalation factors apply: repeated/spreading activity, malware/privilege misuse suspected, internet-facing or external communications observed, and likely impact on an important endpoint supporting business operations. Appendix B also supports Critical because the event is an active compromise with potential sensitive data exposure and significant operational disruption.*

**Confidence Level:** High
*High confidence is appropriate because multiple aligned sources support the conclusion: triage summary, enrichment summary, behavioral alerts, IOC summaries, and incident metadata all consistently indicate active lateral movement and privilege-related malicious activity. Evidence is strong at the incident level even though process-tree telemetry is missing; therefore the certainty is high for the overall compromise assessment but not for exact spawned-process attribution.*

## Investigative Workflow
- Validated incident metadata and identified affected host, users, source IPs, and destination IPs.
- Confirmed the incident is horizontal movement / lateral movement rather than vertical escalation alone.
- Reviewed behavioral evidence for privilege escalation indicators, including UAC-disabling activity and SYSTEM account usage.
- Assessed timeline for process-level evidence and determined it is absent from the provided dataset.
- Determined the incident requires urgent containment and escalation due to active compromise indicators and scale of alerts.

## Technical Chronology & MITRE ATT&CK TTP Mapping

2025-07-14T11:21:34+00:00: Incident INC-52825 on host BETHANYCHUCHU was raised as Internal Hacking / CRITICAL. The host name was BETHANYCHUCHU, with user context observed as BETHANYCHUCHU\Bethany Chu plus NT AUTHORITY\SYSTEM, NT AUTHORITY\NETWORK SERVICE, and NT AUTHORITY\LOCAL SERVICE. The incident contained 1558 alerts and 1558 events with risk score 70 and 11 matched IOCs. Behavioral alerts included 'Chu Wen - Lateral Move Detected' and 'Disables UAC'. Evidence showed internal source IPs 192.168.10.204, 192.168.20.201, 192.168.10.207, fe80::9706:3f55:e752:75ca, fe80::f7c4:bff3:4c73:f8d1, and traffic to multiple destination IPs including 124.155.222.24, 150.171.28.12, 42.99.140.9, 104.208.16.91, 43.175.138.227, 20.42.73.26, 199.232.214.172, 203.116.175.105, plus other destinations such as 4.175.87.197 and 111.223.64.89 highlighted in the IOC summary as known-bad / unusual. The triage summary reported high CPU usage, configuration changes, unexplained privileged account activity, and unknown traffic originating from/terminating on the device, consistent with active lateral movement and privilege escalation behavior. No endpoint process tree, process creation record, or command-line evidence was provided, so the exact malicious execution chain could not be reconstructed from the supplied timeline.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial access / remote activity | Host BETHANYCHUCHU with internal source IPs 192.168.10.204, 192.168.20.201, 192.168.10.207 and behavioral alert 'Chu Wen - Lateral Move Detected' indicating internal remote access activity. | Lateral Movement | Remote Services | T1021 |
| Privilege escalation / defense modification | Behavioral alert 'Disables UAC' plus privileged contexts NT AUTHORITY\SYSTEM, NT AUTHORITY\NETWORK SERVICE, and NT AUTHORITY\LOCAL SERVICE on host BETHANYCHUCHU. | Privilege Escalation | Access Token Manipulation | T1134 |
| Privilege escalation / system modification | Configuration changes and unexplained privileged account activity reported in IOC summaries, with high CPU usage and active compromise indicators on BETHANYCHUCHU. | Defense Evasion | System Checks | T1497 |
| Lateral movement / remote services | Traffic from internal host toward multiple destination IPs including 124.155.222.24, 150.171.28.12, 42.99.140.9, 104.208.16.91, 43.175.138.227, 20.42.73.26, 199.232.214.172, and 203.116.175.105; incident classified as Lateral Movement. | Lateral Movement | Remote Services | T1021 |
| Active compromise / suspected post-exploitation | 1558 alerts, 1558 events, high CPU usage, configuration changes, and known-bad IPs 4.175.87.197 and 111.223.64.89 in the IOC summary. | Command and Control | Proxy: Multi-hop Proxy | T1090 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Username: BETHANYCHUCHU\Bethany Chu, with privileged context also observed as NT AUTHORITY\SYSTEM, NT AUTHORITY\NETWORK SERVICE, and NT AUTHORITY\LOCAL SERVICE. IPs observed: internal source IPs 192.168.10.204, 192.168.20.201, 192.168.10.207, fe80::9706:3f55:e752:75ca, fe80::f7c4:bff3:4c73:f8d1; destination IPs include 124.155.222.24, 150.171.28.12, 42.99.140.9, 104.208.16.91, 43.175.138.227, and additional external/internal destinations. Login details: active internal hacking with lateral movement, remote service activity, and SYSTEM account usage; exact auth/session details are not provided. Computer name: BETHANYCHUCHU. Operating system: Unknown. |
| `step_2` | Was it horizontal or vertical | **MET** | Horizontal movement. The incident is explicitly classified as Lateral Movement, with behavioral alerts 'Chu Wen - Lateral Move Detected' and 'Disables UAC', and the incident-level MITRE tactic is Lateral Movement. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | No endpoint process creation telemetry, process names, PIDs, command lines, or parent-child process evidence was provided for INC-52825. The available data indicates active compromise indicators but does not prove a specific malicious process spawn on the victim machine. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | A process tree cannot be reconstructed from the supplied evidence because no process ancestry, command lines, session IDs, or host-level telemetry are present. Privilege escalation is suspected due to the 'Disables UAC' alert and SYSTEM usage, but it cannot be confirmed from process evidence. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary and urgent containment is warranted. The host shows high-volume activity, lateral movement, privilege-related behavioral alerts, known-bad destination IPs, and high CPU usage consistent with active compromise. |

## Recommended Containment Actions
- Immediately isolate host BETHANYCHUCHU from all network segments except the management channel required for forensic acquisition.
- Block outbound and inbound connections to the flagged malicious/unusual destination IPs 4.175.87.197, 111.223.64.89, 124.155.222.24, 150.171.28.12, 42.99.140.9, 104.208.16.91, 43.175.138.227, 20.42.73.26, 199.232.214.172, and 203.116.175.105 at the EDR, host firewall, and perimeter controls.
- Suspend or reset the credentials for BETHANYCHUCHU\Bethany Chu and investigate all sessions executed under NT AUTHORITY\SYSTEM, NETWORK SERVICE, and LOCAL SERVICE on the host.
- Preserve volatile evidence now: capture RAM, running processes, active network connections, logged-on users, and Windows event logs before remediation or reboot.
- Collect endpoint telemetry for process creation, authentication, remote service use, and UAC/configuration changes covering the full incident window on BETHANYCHUCHU and adjacent internal hosts 192.168.10.204, 192.168.10.207, and 192.168.20.201.
- Hunt for lateral movement artifacts across the internal subnet using the observed internal IPs and look for repeat SSH/remote service use, privileged logons, and abnormal child processes spawned under SYSTEM.
- Disable any newly created or unexpectedly modified local admin accounts and verify local Administrators group membership on the affected host.
- If persistence is found, remove malicious services, scheduled tasks, startup items, WMI subscriptions, and registry run keys only after forensic acquisition is complete.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1785041075-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: True | *Warning* | `Investigate` | Yes | 2026-07-26T04:44:35Z |
| `AUD-DP08-1785041075-2` | **DP-08** | Appendix A | Severity classification: Critical | *Warning* | `Escalate` | Yes | 2026-07-26T04:44:35Z |
| `AUD-DP09-1785041075-3` | **DP-09** | Appendix F | Confidence level: High | *Pass* | `Investigate` | Yes | 2026-07-26T04:44:35Z |
| `AUD-DP10-1785041075-4` | **DP-10/DP-11** | Appendix G | Severity: Critical, Confidence: High, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-07-26T04:44:35Z |
| `AUD-DP15-1785041075-5` | **DP-15** | Appendix B | Sensitive or personal data accessed or exfiltrated. | *Warning* | `Escalate` | Yes | 2026-07-26T04:44:35Z |
