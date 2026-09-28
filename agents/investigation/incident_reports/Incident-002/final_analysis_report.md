# INVESTIGATION SUMMARY: INC-52970 (Incident-002)

**Final Severity:** Medium
*Medium is appropriate because the incident is suspicious and involves repeated outbound network activity with some IOC enrichment, but the available evidence is network-only and does not confirm malware execution, privilege escalation, data exposure, or service impact. The escalation factors for Critical or High are not met because no critical system, sensitive data, or confirmed compromise is shown, and the severe impact indicators required by Appendix A are absent.*

**Confidence Level:** Medium
*Medium confidence is warranted because the timeline provides consistent network evidence and repeated alert context, but the investigation is missing endpoint telemetry, process lineage, user identity, host identity, and operating system data. Under Appendix F, the evidence is partially sufficient: the network behavior is real, but the conclusion about malicious execution or lateral movement remains uncertain.*

## Investigative Workflow
- Reviewed the incident timeline and correlated all repeated alert entries for INC-52970 and related ESA outputs.
- Compared destination IPs, domains, ports, and extracted artifacts across the network-only alerts.
- Assessed external reputation/enrichment for 8.8.8.8 and 4.145.79.81 and noted the lack of direct malicious confirmation.
- Mapped the playbook steps against the available evidence and marked process, login, and movement questions as unresolved due to missing endpoint telemetry.
- Identified the need for endpoint, authentication, and EDR process-tree validation before escalation beyond cautious containment.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2025-07-15 at 09:38:52 UTC, NetWitness generated incident INC-52970 for internal host 192.168.10.200 with the title “High Risk Alerts: ESA for 192.168.10.200.” The alert was classified as a policy violation and described unusual network activity with repeated DNS/HTTP/HTTPS traffic and suspicious file/process artifacts, but no decoded PowerShell payload and no confirmed malicious execution. The visible indicators in the timeline show outbound traffic from 192.168.10.200 to 8.8.8.8:53, 4.145.79.81:443, and other public destinations, alongside multicast activity to 224.0.0.251. The extracted artifacts include the files authrootstl.cab and pR5k1Jb0=, and the incident notes identify ctldl.windowsupdate.com and ocsp.digicert.com as hostname candidates. Threat enrichment for 8.8.8.8 was benign, while 4.145.79.81 had some related OTX pulses but no direct confirmation of compromise. The timeline also contains a source trail of admin2@192.168.20.14:50005, but this appears to be an investigation or session trail rather than proof of the victim user. Across the playbook trace, no endpoint process telemetry, user logon data, hostname, or operating system details were available, so no spawned process or process tree could be confirmed. The best-supported interpretation from the available evidence is suspicious outbound remote connectivity or possible command-and-control behavior from 192.168.10.200, with lateral movement remaining unproven.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial network anomaly and alert generation | NetWitness generated INC-52970 for source IP 192.168.10.200 with outbound DNS traffic to 8.8.8.8:53 and repeated suspicious network activity. The alert title was 'Chu Wen - Lateral Move Detected' and the classification also referenced suspicious outbound remote connectivity / possible C2. | Command and Control | Application Layer Protocol | T1071 |
| Outbound DNS communication to public resolver | Traffic from 192.168.10.200 to 8.8.8.8 over UDP/53 was observed, with repeated DNS activity and no endpoint or PowerShell evidence. | Command and Control | Application Layer Protocol: DNS | T1071.004 |
| Suspicious outbound HTTPS egress to cloud infrastructure | The host 192.168.10.200 connected to 4.145.79.81:443, identified as Microsoft Azure / Microsoft Corporation in enrichment, with additional repeated outbound HTTPS traffic and no process context. | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Multicast discovery traffic observed on the local network | Repeated multicast traffic from 192.168.1.64-style cases appears in the playbook history, and in this incident 192.168.10.200 also showed multicast destination activity to 224.0.0.251, indicating local discovery-style network behavior in the same ESA family. | Discovery | Network Service Discovery | T1046 |
| Suspicious file/artifact association without execution confirmation | The endpoint indicators list authrootstl.cab and pR5k1Jb0=, but the timeline provides no hash, command line, or process creation event tying them to execution. | Execution | User Execution | T1204 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **NOT_MET** | The timeline does not provide enough evidence to identify the username, login details, computer name, or operating system for the victim endpoint. The only concrete host identifier tied to this incident is source IP 192.168.10.200. A source trail of admin2@192.168.20.14:50005 appears in the timeline, but it is more consistent with an analyst or investigation trail than confirmed endpoint login context, so it cannot be treated as the victim user's identity. |
| `step_2` | Was it horizontal or vertical | **NOT_MET** | The timeline does not clearly establish whether the activity was horizontal or vertical. The alert is labeled 'Lateral Move Detected', but the evidence shown is network-only outbound activity from 192.168.10.200 to public destinations including 8.8.8.8:53 and 4.145.79.81:443, plus multicast traffic. That supports suspicious outbound connectivity or possible command-and-control more than proven internal lateral movement. No second internal host, subnet relationship, or authentication trail is present to resolve horizontal versus vertical movement. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | There is no endpoint process telemetry in the timeline to determine whether a malicious process spawned on the victim machine. No process names, parent-child lineage, command lines, hashes, Sysmon Event ID 1, or Windows Event ID 4688 evidence is provided. The available data is network-only. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | A process tree cannot be analyzed from the provided evidence because no process execution data is included. There is no visibility into privilege escalation, remote execution, service creation, or data exfiltration indicators at the process level. The only observed behavior is outbound network activity from 192.168.10.200, which is insufficient to validate malicious process behavior. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary. The alert remains unconfirmed but suspicious because it is network-only, shows repeated outbound activity, and lacks endpoint context. Recommended containment is cautious and proportional: isolate the host associated with 192.168.10.200 if risk tolerance requires it, preserve volatile evidence, and collect endpoint/authentication telemetry before destructive remediation. The timeline specifically recommends querying Security 4624/4625/4672/4688, Sysmon process/network events, EDR host inventory, and DHCP/AD mapping to validate the situation. |

## Recommended Containment Actions
- Immediately isolate 192.168.10.200 from the network using EDR host containment or NAC quarantine, while preserving current volatile state for forensic collection.
- Preserve and export Windows Security logs, Sysmon logs, EDR telemetry, and NetWitness session data covering at least 2025-07-15 08:45 UTC through 2025-07-15 10:15 UTC.
- Acquire a full process snapshot from 192.168.10.200, including running processes, command lines, parent/child lineage, loaded modules, and active network sockets.
- Query Security Event IDs 4624, 4625, 4672, and 4688 on 192.168.10.200, and correlate with DHCP/AD/EDR asset inventory to recover username, hostname, and OS.
- Hunt for any additional connections from 192.168.10.200 to 4.145.79.81, 52.123.129.14, 8.8.8.8, and 224.0.0.251; block only if the same host continues to generate anomalous repeated outbound sessions after validation.
- Review authrootstl.cab and pR5k1Jb0= as endpoint artifacts for source path, creation time, hash, and parent process; quarantine if they are observed outside expected Windows update activity.
- If EDR confirms suspicious execution, terminate the responsible process tree, remove persistence artifacts, and rotate any credentials used on the host during the alert window.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1790423004-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-09-26T11:43:24Z |
| `AUD-DP08-1790423004-2` | **DP-08** | Appendix A | Severity classification: Medium | *Pass* | `Investigate` | Yes | 2026-09-26T11:43:24Z |
| `AUD-DP09-1790423004-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-09-26T11:43:24Z |
| `AUD-DP10-1790423004-4` | **DP-10/DP-11** | Appendix G | Severity: Medium, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-09-26T11:43:24Z |
