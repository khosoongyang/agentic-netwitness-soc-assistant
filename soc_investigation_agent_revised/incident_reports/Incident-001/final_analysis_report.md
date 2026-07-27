# INVESTIGATION SUMMARY: INC-52825 (Incident-001)

**Final Severity:** High
*High severity is appropriate because the incident shows strongly suspected malicious activity on an important user workstation with SYSTEM-context execution, suspicious HTTPS command-and-control to a flagged IP, privilege misuse, UAC weakening, local admin creation, and explicit lateral-movement context. However, the provided evidence does not confirm ransomware, data exfiltration, critical system compromise, or widespread outage, so Critical is not supported.*

**Confidence Level:** High
*High confidence is supported by multiple aligned evidence sources: the NetWitness alert, concrete command-line telemetry, threat-intel enrichment on the IP and file hash, and the timeline's consistent lateral-movement and post-compromise indicators. Although some deeper host forensic details are missing, the core conclusion is well supported and not materially conflicting.*

## Investigative Workflow
- Reviewed playbook milestones against the updated timeline and confirmed all required steps were met.
- Correlated the privileged vmtoolsd.exe SYSTEM-context execution with outbound HTTPS to 4.145.79.81.
- Identified malicious post-compromise commands: reg.exe EnableLUA=0, cmd.exe net user admin2 /ADD, and net localgroup Administrators admin2 /ADD.
- Pivoted on related process telemetry to assess lateral movement and defense evasion indicators.
- Captured relevant IOCs from the timeline, including vmtoolsd.exe hash 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c and IP 4.145.79.81.
- Assessed business impact factors and determined the impacted system is a Windows workstation with no confirmed service outage or data exfiltration.
- Prepared containment guidance focused on isolation, account remediation, and enterprise IOC hunting.

## Technical Chronology & MITRE ATT&CK TTP Mapping

2025-07-14T11:21:34+00:00 on host BETHANYCHUCHU (Windows), NetWitness detected a high-risk endpoint event involving vmtoolsd.exe running as NT AUTHORITY\SYSTEM and making outbound HTTPS connections to 4.145.79.81. The alert was classified as compromised asset / lateral movement with high risk. Related telemetry on the same host showed additional suspicious privileged activity, including cmd.exe, sc.exe, powershell.exe, msiexec.exe, reg.exe, and wevtutil.exe, alongside internal lateral-movement context across RFC1918 addresses (192.168.10.201/204/205/207 and 192.168.20.16/201). The parsed process sequence includes commands to disable UAC via reg.exe set EnableLUA=0, service-control activity via sc.exe, silent MSI installation via msiexec.exe, and account manipulation via cmd.exe/net user creating local admin admin2 with password Iaminside!. Recorded IOCs include file hash 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c for vmtoolsd.exe, network IOC 4.145.79.81, and related historical/adjacent indicators from the timeline such as 150.171.27.12, 239.255.255.250, and Sandy.exe in prior linked incidents. No confirmed destructive action or exfiltration was evidenced in the provided telemetry, but the event chain strongly indicates post-compromise system modification and lateral movement activity on the affected workstation.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial suspicious execution on endpoint | vmtoolsd.exe running as NT AUTHORITY\SYSTEM on BETHANYCHUCHU with outbound HTTPS to 4.145.79.81; file hash 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c. | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Privileged system-context execution and suspicious host behavior | vmtoolsd.exe executed in SYSTEM context with unusual network telemetry and VMware Tools path usage on host BETHANYCHUCHU. | Execution | System Services | T1569.002 |
| Privilege and security-control weakening | reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f. | Defense Evasion | Modify Registry | T1112 |
| Service and process control activity | sc.exe start wuauserv and other service-control activity observed in command lines on BETHANYCHUCHU. | Execution | System Services: Service Execution | T1569.002 |
| Silent software installation / payload deployment | powershell.exe and msiexec.exe used to install C:\Users\Public\adduser.msi with quiet flags (/quiet /qn /i). | Execution | User Execution: Malicious File | T1204.002 |
| Local account creation for persistence or privilege escalation | cmd.exe /c net user admin2 Iaminside! /ADD && net localgroup Administrators admin2 /ADD. | Persistence | Create Account: Local Account | T1136.001 |
| Privilege escalation / local admin group assignment | net localgroup Administrators admin2 /ADD on BETHANYCHUCHU, followed by confirmation in command-line telemetry. | Privilege Escalation | Account Manipulation | T1098 |
| Defensive log and artifact manipulation | wevtutil.exe install-manifest and uninstall-manifest activity across Microsoft Antimalware/Defender manifests; powershell history clearing observed in prior related telemetry patterns. | Defense Evasion | Indicator Removal on Host: Clear Windows Event Logs | T1070.001 |
| Lateral movement context across internal hosts | Incident classification explicitly marked Lateral Movement with internal RFC1918 hosts 192.168.10.201/204/205/207 and 192.168.20.16/201 referenced in the triage context. | Lateral Movement | Remote Services | T1021 |
| Use of Windows remote/system management pathways | WmiPrvSE.exe, services.exe, and sc.exe appear in the deep-dive context alongside lateral-movement indicators. | Lateral Movement | Windows Management Instrumentation | T1047 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Username observed in telemetry: Bethany Chu; privileged context also observed as NT AUTHORITY\SYSTEM. Relevant internal source IPs mentioned across the timeline include 192.168.10.201, 192.168.10.204, 192.168.10.205, 192.168.10.207, 192.168.20.16, and 192.168.20.201. Login details are incomplete, but execution occurred under SYSTEM and user-attributed activity exists for Bethany Chu. Computer name: BETHANYCHUCHU. Operating system: Windows. |
| `step_2` | Was it horizontal or vertical | **MET** | Horizontal movement (lateral movement). The timeline explicitly labels the event as Lateral Movement, and the deep-dive context cites internal RFC1918-to-RFC1918 activity across peer hosts rather than elevation to a higher local privilege level. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **MET** | Yes. Suspicious and likely malicious process activity was observed on BETHANYCHUCHU, including vmtoolsd.exe in SYSTEM context, cmd.exe, sc.exe, powershell.exe, msiexec.exe, reg.exe, wevtutil.exe, and evidence of a malicious-looking software install chain via adduser.msi. The timeline also includes creation of local admin account admin2 with password Iaminside!. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **MET** | The process tree and command-line telemetry show post-compromise behavior consistent with privilege escalation and defense evasion: powershell.exe downloading adduser.msi, msiexec.exe silently installing it, cmd.exe creating local admin admin2 and adding it to Administrators, reg.exe modifying HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA to 0, sc.exe service control usage, and wevtutil.exe manifest install/uninstall activity. No direct evidence of exfiltration was provided, but the chain strongly supports compromise and malicious system modification. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary. Containment should include immediate host isolation, termination of active malicious processes if present, reset or disable the suspicious admin2 account, credential reset for Bethany Chu and any potentially exposed accounts, triage of registry/service changes for persistence, full EDR process-tree collection, and enterprise-wide IOC hunting for vmtoolsd.exe, Sandy.exe, adduser.msi, 4.145.79.81, 150.171.27.12, and related hashes. |

## Recommended Containment Actions
- Immediately isolate BETHANYCHUCHU from the network using EDR network containment or switch port quarantine, but preserve host access for memory capture before reboot.
- Terminate any live instances of vmtoolsd.exe, powershell.exe, cmd.exe, sc.exe, msiexec.exe, reg.exe, and wevtutil.exe associated with the incident after volatile evidence is collected.
- Disable and reset the suspicious local account admin2, remove it from the local Administrators group, and verify whether any additional accounts were created or modified.
- Revert HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA to its approved value and confirm the change via registry audit logs.
- Collect a full volatile package from BETHANYCHUCHU: memory image, process tree, active network connections, autoruns, scheduled tasks, services list, and recent PowerShell history.
- Pull Windows Security, System, Sysmon, and EDR logs covering 2025-07-14 10:00:00Z through 2025-07-14 12:00:00Z, with emphasis on Event IDs 4688, 4697, 7045, 4624, 4648, 4672, 13, and 1.
- Hunt enterprise-wide for the IP 4.145.79.81, the hash 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c, vmtoolsd.exe anomalies, adduser.msi, Sandy.exe, and any repeated reg.exe EnableLUA=0 activity.
- Review VMware Tools execution paths on affected endpoints and validate the legitimacy of vmtoolsd.exe parent/child lineage against golden baseline process trees.
- Reset credentials for Bethany Chu and any privileged accounts that authenticated to or from the workstation during the incident window.
- Check for persistence by reviewing services, scheduled tasks, Run/RunOnce keys, WMI event subscriptions, and startup folders, then remove any unauthorized entries under change control.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1785124864-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-07-27T04:01:04Z |
| `AUD-DP08-1785124864-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-07-27T04:01:04Z |
| `AUD-DP09-1785124864-3` | **DP-09** | Appendix F | Confidence level: High | *Pass* | `Investigate` | Yes | 2026-07-27T04:01:04Z |
| `AUD-DP10-1785124864-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: High, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-07-27T04:01:04Z |
