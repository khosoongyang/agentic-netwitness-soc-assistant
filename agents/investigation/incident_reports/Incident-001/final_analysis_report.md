# INVESTIGATION SUMMARY: INC-52825 (Incident-001)

**Final Severity:** High
*High is appropriate because the incident shows strongly suspicious endpoint activity on a Windows host with SYSTEM-context execution, repeated correlated alerts, outbound HTTPS to a flagged external IP, internal host-to-host activity, service control behavior, and registry changes that weaken security controls. These are strong compromise indicators but the record does not prove widespread outage, confirmed data exfiltration, or multi-system impact required for Critical.*

**Confidence Level:** Medium
*Confidence is Medium because multiple independent observations align: endpoint process command lines, repeated alerting, internal network connections, and threat-intelligence correlation. However, the dataset is incomplete for exact process lineage and does not fully confirm the full attack chain, so the conclusion is well-supported but not fully closed.*

## Investigative Workflow
- Reviewed the incident timeline and correlated prior playbook trace for host BETHANYCHUCHU/KELLYWANG.
- Mapped the observable activity to the incident-level sequence of execution, service manipulation, UAC weakening, and outbound network connections.
- Assessed the available telemetry for evidence of privilege escalation, lateral movement, and exfiltration.
- Prepared containment guidance aligned to the observed behaviors and evidence gaps.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2025-07-14 at 11:21:34+00:00, host BETHANYCHUCHU generated a high-risk NetWitness endpoint alert tied to vmtoolsd.exe running as NT AUTHORITY\SYSTEM and initiating outbound HTTPS connections to 4.145.79.81, with the endpoint also referencing internal telemetry from the host over an IPv6 source address fe80:0:0:0:9706:3f55:e752:75ca. The incident bundle associates the machine with multiple suspicious executables and administrative tools, including vmtoolsd.exe, NWEAgent.exe, upfc.exe, mousocoreworker.exe, resume-vm-default.bat, cmd.exe, powershell.exe, reg.exe, sc.exe, wevtutil.exe, and wmiprvse.exe. The command-line evidence shows a batch-driven VMware Tools sequence, Windows update and Defender-manifest activity, and a registry modification command that sets HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA to 0, indicating UAC weakening. The same incident scope also includes earlier high-risk telemetry for the host involving Sandy.exe launched from a public path with PowerShell using Invoke-WebRequest to retrieve adduser.msi from 192.168.10.205, followed by msiexec installation and a net user / net localgroup sequence that created admin2 and added it to Administrators. Across the correlated alerts, the host communicated with internal addresses in the 192.168.10.x network and generated repeated security alerts, which collectively point to staged execution, service and registry manipulation, privileged process activity, and lateral-movement-oriented behavior rather than a benign administrative event.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial suspicious execution on host BETHANYCHUCHU | vmtoolsd.exe executed as NT AUTHORITY\SYSTEM on BETHANYCHUCHU and produced outbound HTTPS traffic to 4.145.79.81; the incident repeatedly flagged the binary as anomalous and linked it to high-risk NetWitness alerts. | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Scripted activity and tool chaining on the endpoint | The host shows powershell.exe, cmd.exe, reg.exe, sc.exe, and wevtutil.exe in the same incident scope, including PowerShell with ExecutionPolicy Bypass and command-driven Windows administration behavior. | Execution | Command and Scripting Interpreter | T1059 |
| Privilege weakening and local security modification | cmd.exe invoked reg.exe to modify HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA /d 0 /f, directly changing the UAC policy on the host. | Privilege Escalation | Abuse Elevation Control Mechanism | T1548 |
| Service control and Windows service manipulation | The command lines include sc.exe start wuauserv and other service-oriented activity, with service context present alongside SYSTEM execution and batch-based VMware tool actions. | Persistence | Windows Service | T1543.003 |
| Potential internal host-to-host movement | The incident contains internal RFC1918 network activity from 192.168.10.204 toward 192.168.10.202, and earlier related alerts reference 192.168.10.205 and 192.168.20.16/201, consistent with movement across internal systems. | Lateral Movement | Remote Services | T1021 |
| Suspicious file retrieval and staged payload execution in related incident context | Earlier correlated telemetry in the same case family showed powershell.exe using Invoke-WebRequest to download adduser.msi from http://192.168.10.205/adduser.msi to C:\Users\Public\adduser.msi, followed by msiexec /quiet /qn /i and net user / net localgroup account creation activity. | Execution | PowerShell | T1059.001 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Username observed in the incident context is Bethany Chu / KELLYWANG\Bethany Chu, with some alert contexts also running as NT AUTHORITY\SYSTEM. Source IPs include 192.168.10.204 and fe80:0:0:0:9706:3f55:e752:75ca. Login details are not explicitly provided in the timeline, so no definitive logon type or authentication event can be confirmed. Computer name is BETHANYCHUCHU / KELLYWANG. Operating system is Windows / Microsoft Windows 10 Pro. |
| `step_2` | Was it horizontal or vertical | **MET** | Horizontal movement is the strongest fit. The incident contains internal host-to-host traffic between private RFC1918 addresses, especially 192.168.10.204 to 192.168.10.202, and the triage notes explicitly assess this as lateral movement rather than privilege escalation. No clear evidence shows a change to a higher privilege tier via new credentials or token elevation. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **MET** | Yes. The endpoint telemetry shows suspicious process execution on the victim host, including vmtoolsd.exe running as NT AUTHORITY\SYSTEM, powershell.exe, cmd.exe, sc.exe, reg.exe, wmiprvse.exe, and wevtutil.exe. The timeline also includes a high-risk executable context and internal network activity consistent with hostile execution, although the exact parent-child chain is incomplete. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | The full process tree is not available, so the exact lineage cannot be reconstructed. However, available telemetry is still suspicious: command lines include reg.exe modifying HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA to 0, sc.exe start wuauserv, PowerShell with ExecutionPolicy Bypass, and vmtoolsd.exe issuing outbound HTTPS. These behaviors suggest privilege weakening, service control, and possible post-execution staging, but the dataset does not conclusively prove privilege escalation, data exfiltration, or the complete execution chain. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is required. The incident is high risk, includes repeated alerts, SYSTEM-context execution, suspicious service/registry activity, and internal lateral-movement indicators. Containment should be immediate and proportionate: isolate the host, preserve volatile evidence, and collect EDR telemetry, process lineage, network sockets, and service/registry modification logs before remediation. |

## Recommended Containment Actions
- Immediately isolate host BETHANYCHUCHU from the network using EDR network containment, while preserving access for forensic acquisition if your tooling supports quarantine with collection.
- Capture volatile evidence before reboot: running processes, active network sockets, loaded modules, command history, and current user/session context from the endpoint.
- Preserve and export the full EDR process tree for vmtoolsd.exe, powershell.exe, cmd.exe, reg.exe, sc.exe, wmiprvse.exe, and wevtutil.exe, including parent PID, child PID, command line, integrity level, and hash values.
- Block or quarantine the suspicious binaries and scripts identified in the timeline: Sandy.exe, adduser.msi, WinDefender_Update_2025.ps1, Password_Reset.hta, splunkd.exe from C:\Users\Public\, and any related BAT files such as resume-vm-default.bat and suspend-vm-default.bat until validation is complete.
- Disable or reset any newly created or modified local accounts observed in the timeline, especially admin2, and remove any unauthorized membership changes in the local Administrators group.
- Revert the UAC policy change by restoring HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA to its approved value, then verify whether additional policy tampering occurred.
- Investigate and, if necessary, suspend Windows services or scheduled tasks introduced during the incident that correspond to the suspicious process activity, especially any service changes tied to wuauserv or other service-control actions.
- Collect and preserve Windows Security, Sysmon, and PowerShell Operational logs covering the event window, focusing on 4624, 4672, 4688, 4697, 7045, 5140, 5156, and Sysmon Event IDs 1, 3, 7, 10, 11, 12, 13, and 22.
- Identify and block the internal and external network indicators associated with the incident, including 192.168.10.205, 192.168.10.202, 192.168.20.16, 192.168.20.201, 4.145.79.81, 239.255.255.250, and 255.255.255.255, where applicable to your environment and validation results.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1791452023-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-10-08T09:33:43Z |
| `AUD-DP08-1791452023-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-10-08T09:33:43Z |
| `AUD-DP09-1791452023-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-10-08T09:33:43Z |
| `AUD-DP10-1791452023-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-10-08T09:33:43Z |
