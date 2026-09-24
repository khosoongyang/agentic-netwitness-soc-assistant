# INVESTIGATION SUMMARY: INC-52825 (Incident-001)

**Final Severity:** High
*High severity is warranted because the incident shows SYSTEM-context suspicious execution, outbound network communication, repeated correlated alerts, and credible lateral-movement indicators on an important endpoint. However, the provided data does not confirm ransomware, destructive impact, confirmed data exfiltration, or compromise of a critical server, so Critical is not supported by the current evidence.*

**Confidence Level:** Medium
*Confidence is Medium because multiple timeline elements align on the same host, user context, file hash, and suspicious network behavior, but the incident lacks a full process tree, definitive parent-child lineage, and direct proof of privilege escalation or exfiltration. The evidence is substantial but still partially incomplete.*

## Investigative Workflow
- Reviewed the incident timeline and correlated alert entries for INC-52825 and related prior host activity on BETHANYCHUCHU.
- Validated that the host is a Windows 10 Pro endpoint and that the active process context includes NT AUTHORITY\SYSTEM.
- Confirmed suspicious outbound HTTPS activity attributed to vmtoolsd.exe with the file hash 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c.
- Correlated the incident with observed Windows administration and service-control artifacts including cmd.exe, sc.exe, reg.exe, and wevtutil.exe.
- Reviewed the prior triage deep-dive conclusions indicating lateral-movement concern and incomplete process-tree visibility.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2025-07-14 at 11:21:34+00:00, the BETHANYCHUCHU endpoint generated a high-risk NetWitness alert while running vmtoolsd.exe as NT AUTHORITY\SYSTEM. The alert package shows the host making outbound HTTPS connections to the external IP 4.145.79.81, which is mapped in the telemetry to destination 124.155.222.24, with the endpoint source address recorded as fe80:0:0:0:9706:3f55:e752:75ca. The primary suspicious binary in scope is vmtoolsd.exe with SHA256 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c, and the incident also includes nearby command activity involving cmd.exe, reg.exe, sc.exe, wevtutil.exe, powershell.exe, and multiple Windows service and update components.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial suspicious execution and endpoint compromise context | Host BETHANYCHUCHU generated a high-risk NetWitness alert; vmtoolsd.exe executed under NT AUTHORITY\SYSTEM with SHA256 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c and was associated with outbound HTTPS activity. | Execution | System Services: Service Execution | T1569.002 |
| Command and control over web protocol | The endpoint initiated outbound HTTPS traffic to external IP 4.145.79.81 (telemetry destination 124.155.222.24) from host BETHANYCHUCHU while running vmtoolsd.exe in SYSTEM context. | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Service control and administrative manipulation | Command-line telemetry includes sc.exe start wuauserv, multiple service-oriented svchost.exe instances, and wevtutil.exe manifest installation/uninstallation activity on BETHANYCHUCHU. | Defense Evasion | System Binary Proxy Execution | T1218 |
| Privilege weakening and elevation preparation | Command-line telemetry shows cmd.exe /c reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f, indicating UAC was disabled or attempted to be disabled. | Privilege Escalation | System Registry Modification | T1112 |
| Lateral movement indicators across internal hosts | The incident scope includes multiple internal RFC1918 source/destination relationships across 192.168.10.x and 192.168.20.x, and prior related alerts explicitly identified lateral movement behavior on the same host family. | Lateral Movement | Remote Services: Windows Admin Shares | T1021.002 |
| Potential post-execution staging and script activity | Suspicious accompanying artifacts include resume-vm-default.bat, upfc.exe, NWEAgent.exe /runasservice, mousocoreworker.exe, and related Windows update/service activity in the same incident context. | Persistence | Scheduled Task/Job | T1053 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Username on the active alert context is NT AUTHORITY\SYSTEM, with the named endpoint user also referenced as Bethany Chu. Source IP is fe80:0:0:0:9706:3f55:e752:75ca and the alert destination IP is 124.155.222.24. No explicit interactive logon type, session ID, or credential source is provided. Computer name is BETHANYCHUCHU. Operating system is Windows / Windows 10 Pro. |
| `step_2` | Was it horizontal or vertical | **MET** | This is horizontal movement. The incident bundle and triage deep dive point to lateral movement across internal RFC1918 addresses (including 192.168.10.x and 192.168.20.x hosts). There is no direct evidence of a higher-privilege account takeover that would support vertical movement. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **MET** | Yes. The host shows suspicious execution consistent with malicious activity, including vmtoolsd.exe running as NT AUTHORITY\SYSTEM, cmd.exe and reg.exe use to modify HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA, sc.exe service control activity, and associated suspicious file artifacts such as resume-vm-default.bat and upfc.exe. The telemetry also ties the incident to outbound HTTPS activity from the SYSTEM context. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | The available timeline is insufficient to reconstruct a complete process tree with parent-child lineage and exact execution order. Suspicious indicators are present, including SYSTEM-context execution, UAC disabling via reg.exe, service manipulation via sc.exe, and internal host-to-host activity, but the data does not conclusively prove the full escalation chain or any data exfiltration path. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is required and containment is warranted. The incident is high risk, shows repeated suspicious endpoint/network activity, includes likely lateral-movement indicators, and contains privileged-context process behavior. Recommended immediate containment is host isolation, preservation of volatile evidence, and correlation of service creation, logon, and network telemetry across the related internal hosts. |

## Recommended Containment Actions
- Immediately isolate host BETHANYCHUCHU from all network segments using EDR network containment, while preserving management-plane access only if required for acquisition.
- Capture volatile evidence from BETHANYCHUCHU before reboot: running processes, open network sockets, active services, loaded modules, and current logged-on sessions.
- Export the full process tree and parent-child lineage for vmtoolsd.exe, cmd.exe, reg.exe, sc.exe, powershell.exe, NWEAgent.exe, upfc.exe, and mousocoreworker.exe from EDR/Sysmon around 2025-07-14T11:21:34Z.
- Quarantine or acquire the identified binary vmtoolsd.exe (SHA256 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c) and associated script/batch artifacts such as resume-vm-default.bat for offline analysis.
- Hunt for the same hash, filename, and command-line patterns across adjacent hosts and internal subnets, especially systems in 192.168.10.0/24 and 192.168.20.0/24.
- Review and revert any unauthorized registry changes under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, including EnableLUA modifications, if confirmed malicious.
- Disable or suspend any suspicious services created or started during the alert window and preserve service-install artifacts from Security 4697/7045 and Sysmon events for evidence.
- Block the external IP 4.145.79.81 at egress controls pending validation and review any related Microsoft/Azure CDN telemetry to ensure the destination is not a decoy or misattribution.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1790267884-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-09-24T16:38:04Z |
| `AUD-DP08-1790267884-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-09-24T16:38:04Z |
| `AUD-DP09-1790267884-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-09-24T16:38:04Z |
| `AUD-DP10-1790267884-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-09-24T16:38:04Z |
