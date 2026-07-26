# INVESTIGATION SUMMARY: INC-52825 (Incident-011)

**Final Severity:** Critical
*Critical is justified because the timeline and enrichment show active compromise indicators: CRITICAL SOC classification, 1558 alerts, SYSTEM account usage, 'Disables UAC', suspected lateral movement, high CPU usage, and traffic to known malicious IPs. Appendix A escalation factors are met, including privileged-account misuse, repeated activity, malicious IOC indicators, and likely impact on an important business endpoint.*

**Confidence Level:** Medium
*Confidence is Medium because multiple timeline sources consistently support the compromise narrative, but the most important execution-level evidence is incomplete. The record lacks direct process creation, command line, hash, and process-tree telemetry for Sandy.exe, so the exact execution chain and post-execution behavior cannot be fully verified under Appendix F.*

## Investigative Workflow
- Reviewed incident timeline and enrichment fields for host BETHANYCHUCHU.
- Assessed severity using Appendix A/B/C factors and preserved the CRITICAL classification due to active compromise indicators.
- Mapped available evidence to a chronological incident summary and identified unconfirmed gaps for Sandy.exe execution and process tree visibility.
- Evaluated the playbook steps against the timeline and marked process-spawn and process-tree steps as not conclusively proven from the supplied telemetry.
- Identified suspicious destination IPs and privileged-account activity for containment planning.

## Technical Chronology & MITRE ATT&CK TTP Mapping

2025-07-14T11:21:34+00:00: Host BETHANYCHUCHU triggered an Internal Hacking (active) incident with CRITICAL SOC classification. Telemetry showed 1558 endpoint alerts and 11 matched IOCs, with behavioral alerts including 'Chu Wen - Lateral Move Detected' and 'Disables UAC'. Evidence linked the host to privileged accounts (NT AUTHORITY\SYSTEM, NT AUTHORITY\NETWORK SERVICE, NT AUTHORITY\LOCAL SERVICE, and BETHANYCHUCHU\Bethany Chu), indicating privileged activity on host BETHANYCHUCHU. Observed source IPs included 192.168.10.204, 192.168.20.201, and 192.168.10.207, while destination IPs included 124.155.222.24, 150.171.28.12, 42.99.140.9, 104.208.16.91, 43.175.138.227, 20.42.73.26, 199.232.214.172, and 203.116.175.105. The IOC summary reported high CPU usage, configuration changes, unexplained privileged-account activity, unknown traffic, and known-bad IP activity. 2025-07-22T06:03:00+00:00: A later NetWitness alert on the same host referenced 'Potential Malicious File: Sandy.exe (Bethany)' but the parsed telemetry contained no process, file, network, PowerShell, or endpoint execution evidence to confirm this as an executed payload. The follow-on investigation notes repeatedly state that Sandy.exe execution, a process tree, privilege escalation, lateral movement, and exfiltration could not be proven from the available record alone. The alert remained an endpoint high-risk detection with no usable IOC matches in the enriched low-confidence record. Overall, the incident evidence most strongly supports an active compromise on BETHANYCHUCHU with suspicious privileged activity and lateral movement indicators, but the Sandy.exe process execution chain itself is not confirmed in the provided telemetry.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial endpoint compromise / suspicious file detection | Host BETHANYCHUCHU was associated with the alert title 'Potential Malicious File: Sandy.exe (Bethany)' and the incident repeatedly references suspicious executable activity on the endpoint. | Execution | User Execution: Malicious File | T1204.002 |
| Privilege escalation / security control tampering | Behavioral alert 'Disables UAC' and usage of NT AUTHORITY\SYSTEM / privileged service accounts on host BETHANYCHUCHU indicate attempts to bypass local security controls and operate with elevated privileges. | Privilege Escalation | Abuse Elevation Control Mechanism: Bypass User Account Control | T1548.002 |
| Execution under elevated context | Telemetry references NT AUTHORITY\SYSTEM activity on BETHANYCHUCHU alongside the suspicious file alert, suggesting code or actions executed with system-level privileges if the file was launched. | Execution | System Services | T1569.002 |
| Suspicious internal movement | Behavioral alert 'Chu Wen - Lateral Move Detected' and destination/source IP activity across multiple internal addresses (192.168.10.204, 192.168.20.201, 192.168.10.207 and destination IPs 124.155.222.24, 150.171.28.12, 42.99.140.9, 104.208.16.91, 43.175.138.227) indicate lateral movement activity involving the host. | Lateral Movement | Remote Services | T1021 |
| Internal remote administration / service-based movement | The playbook and incident context reference remote-services behavior with SYSTEM usage and lateral movement indicators, but no specific protocol is proven in the supplied telemetry. | Lateral Movement | Remote Services | T1021 |
| Malicious outbound communications | Traffic to known malicious or suspicious external IPs including 4.175.87.197 and 111.223.64.89, plus additional unusual destination IPs, was observed from host BETHANYCHUCHU. | Command and Control | Application Layer Protocol | T1071 |
| Potential defense evasion through security control change | The 'Disables UAC' alert and unexplained privileged-account activity indicate modification of local security posture to evade controls on BETHANYCHUCHU. | Defense Evasion | Impair Defenses | T1562 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Username evidence includes BETHANYCHUCHU\Bethany Chu, NT AUTHORITY\SYSTEM, NT AUTHORITY\NETWORK SERVICE, and NT AUTHORITY\LOCAL SERVICE. IPs observed include source IPs fe80:0:0:0:9706:3f55:e752:75ca, fe80:0:0:0:f7c4:bff3:4c73:f8d1, 192.168.10.204, 192.168.20.201, and 192.168.10.207, with destination IPs including 124.155.222.24, 150.171.28.12, 42.99.140.9, 104.208.16.91, and 43.175.138.227. Login details are not fully available; SYSTEM account usage and a 'Disables UAC' behavioral alert indicate privileged activity, but no explicit logon type/session record is provided. Computer name is BETHANYCHUCHU. Operating system is Unknown. |
| `step_2` | Was it horizontal or vertical | **MET** | Vertical movement / privilege escalation is indicated. The incident is classified as Internal Hacking (active) with CRITICAL SOC classification, and the enrichment references 'Disables UAC' plus SYSTEM account usage, which align with privilege escalation rather than purely horizontal movement. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | The available timeline does not confirm process execution. The incident repeatedly references 'Potential Malicious File: Sandy.exe (Bethany)' and suspicious endpoint behavior, but there is no process creation telemetry, parent-child lineage, command line, hash, or EDR process-start evidence proving Sandy.exe spawned as a process on BETHANYCHUCHU. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | A process-tree analysis cannot be completed from the provided evidence because the record lacks process names, PIDs, parent/child relationships, command lines, execution timestamps, privilege tokens, and correlated network/file/process telemetry. While the host shows signs consistent with active compromise, the process tree itself is not present. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation and immediate containment are required because the incident is CRITICAL and includes indicators of active compromise: high alert volume (1558), SYSTEM account activity, 'Disables UAC', laterally moving behavior, high CPU usage, and traffic to suspected malicious destinations including 4.175.87.197 and 111.223.64.89. Containment should prioritize host isolation, blocking suspicious egress, and forensic preservation. |

## Recommended Containment Actions
- Immediately isolate host BETHANYCHUCHU from the network using EDR network containment or switch port quarantine while preserving volatile memory and disk state.
- Block outbound connections to 4.175.87.197, 111.223.64.89, 124.155.222.24, 150.171.28.12, 42.99.140.9, 104.208.16.91, 43.175.138.227, 20.42.73.26, 199.232.214.172, and 203.116.175.105 at perimeter firewall, proxy, and DNS control points.
- Search EDR and Windows telemetry on BETHANYCHUCHU for Sandy.exe execution, including process creation (Sysmon Event ID 1 / Security 4688), parent process, command line, hash, signer, and child processes; quarantine the executable and any identical hash across the fleet if found.
- Acquire a forensic memory capture and a full triage package from BETHANYCHUCHU before rebooting: running processes, services, autoruns, scheduled tasks, recent file writes, and network connections.
- Hunt for UAC tampering and privilege escalation on BETHANYCHUCHU by reviewing Security Event ID 4672, 4688, and any registry/service changes related to UAC policy or elevation prompts; revert unauthorized changes only after evidence capture.
- Review authentication logs across nearby hosts for lateral movement from the source IPs 192.168.10.204, 192.168.20.201, and 192.168.10.207 and investigate any reuse of BETHANYCHUCHU\Bethany Chu or SYSTEM-equivalent tokens.
- Reset credentials and invalidate sessions for accounts associated with the host, including BETHANYCHUCHU\Bethany Chu and any service accounts observed on the endpoint, after confirming business-impact dependencies.
- Enable high-fidelity monitoring for the affected subnet and hunt for repeated connections to the suspicious destination IPs and any post-compromise tools such as PsExec, WMI, RDP, WinRM, powershell.exe, cmd.exe, and ssh-related binaries.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1785056237-1` | **DP-07** | Appendix C | Critical System: True, Sensitive Data: True | *Warning* | `Investigate` | Yes | 2026-07-26T08:57:17Z |
| `AUD-DP08-1785056237-2` | **DP-08** | Appendix A | Severity classification: Critical | *Warning* | `Escalate` | Yes | 2026-07-26T08:57:17Z |
| `AUD-DP09-1785056237-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-07-26T08:57:17Z |
| `AUD-DP10-1785056237-4` | **DP-10/DP-11** | Appendix G | Severity: Critical, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-07-26T08:57:17Z |
| `AUD-DP15-1785056237-5` | **DP-15** | Appendix B | Sensitive or personal data accessed or exfiltrated. | *Warning* | `Escalate` | Yes | 2026-07-26T08:57:17Z |
