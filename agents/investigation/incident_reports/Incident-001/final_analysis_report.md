# INVESTIGATION SUMMARY: INC-52825 (Incident-001)

**Final Severity:** High
*Severity is High because the incident shows privileged SYSTEM-context activity on a non-critical endpoint, explicit lateral-movement indicators in the timeline, suspicious administrative command execution, service manipulation, registry modification, and outbound HTTPS to an external IP associated with threat intel. The evidence suggests real adversary activity, but there is no proof of ransomware, widespread outage, confirmed exfiltration, or critical-system impact, so Critical is not justified.*

**Confidence Level:** Medium
*Confidence is Medium because multiple independent sources align on suspicious privileged behavior and lateral-movement concern, including repeated correlated alerts, command-line evidence, and threat-intel hits. However, the evidence is still incomplete: the bundle lacks a full process tree, definitive parent-child lineage, and direct proof of payload execution or exfiltration, so the conclusion remains well-supported but not fully certain.*

## Investigative Workflow
- Reviewed the incident timeline and correlated alert entries for INC-52825.
- Reconciled endpoint context, host identity, user context, file indicators, hashes, and command lines from the telemetry.
- Mapped the observed activity to incident-level MITRE ATT&CK techniques based on the full sequence of privileged execution, service manipulation, registry modification, and outbound web traffic.
- Applied policy-based severity and confidence assessment using impact, evidence sufficiency, and historical risk indicators.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2025-07-14T11:21:34+00:00, NetWitness raised a high-risk incident on host BETHANYCHUCHU with the active context running as NT AUTHORITY\SYSTEM. The telemetry shows vmtoolsd.exe executing on the endpoint alongside a large cluster of Windows and administrative processes, including cmd.exe, sc.exe, powershell.exe, reg.exe, wevtutil.exe, Upfc.exe, and other service and update-related binaries. The command-line set includes service-control activity such as sc.exe start wuauserv and sc.exe start pushtoinstall login, registry modification with cmd.exe reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f, and repeated Windows Defender manifest installation and removal via wevtutil.exe. The alert bundle also includes suspicious helper artifacts such as resume-vm-default.bat, suspend-vm-default.bat, and NWEAgent.exe /runasservice, with the endpoint communicating outbound over HTTPS to an external IP flagged in the telemetry, 4.145.79.81, while the incident record also notes destination 124.155.222.24 and SYSTEM-context activity. The available data indicates a host operating in privileged context with suspicious administrative and network behavior, but the bundle does not include a complete parent-child process tree or explicit post-execution payload chain to prove the exact execution source or any confirmed exfiltration.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial privileged host activity and service context | BETHANYCHUCHU generated alerts with NT AUTHORITY\SYSTEM context and vmtoolsd.exe / NWEAgent.exe / svchost.exe activity, including vmtoolsd.exe -n vmusr and NWEAgent.exe /runasservice. | Execution | System Services | T1569.002 |
| Userland command execution and script-driven administration | cmd.exe /c, powershell.exe -ExecutionPolicy Bypass -C, sc.exe start wuauserv, and reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f were observed on the host. | Execution | Command and Scripting Interpreter | T1059 |
| Registry-based privilege weakening | The telemetry shows cmd.exe invoking reg.exe to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA to 0, indicating UAC weakening on BETHANYCHUCHU. | Defense Evasion | Modify Registry | T1112 |
| Service manipulation and Windows component control | Command lines include sc.exe start wuauserv and other service-control activity, with service-oriented binaries such as services.exe, svchost.exe, and vmtoolsd.exe appearing in the same incident scope. | Persistence | System Service | T1543.003 |
| Suspicious Windows update / helper artifacts and launcher execution | The endpoint shows Upfc.exe /launchtype periodic /cv ..., resume-vm-default.bat, suspend-vm-default.bat, setup.exe --msedgewebview --delete-old-versions --system-level --verbose-logging --on-logon, and related helper processes in the same incident window. | Execution | Scheduled Task/Job | T1053.005 |
| Lateral-movement-style internal host-to-host activity | The incident bundle includes lateral-movement labels and internal IP-to-IP activity across 192.168.10.x and 192.168.20.x ranges, with BETHANYCHUCHU correlated to internal endpoints 192.168.10.201, 192.168.10.205, 192.168.10.207, and 192.168.20.201. | Lateral Movement | Remote Services | T1021 |
| Outbound web-based command-and-control communication | NetWitness flagged vmtoolsd.exe on BETHANYCHUCHU making outbound HTTPS traffic to external IP 4.145.79.81 and the incident record also references external destination 124.155.222.24. | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Username observed in the alert context is NT AUTHORITY\SYSTEM. Network context includes source IPv6 fe80:0:0:0:9706:3f55:e752:75ca and source host IP 192.168.10.201, with destination IP 124.155.222.24. No explicit interactive logon event is provided, but the activity is executing in SYSTEM context. Computer name is BETHANYCHUCHU. Operating system is Windows 10 Pro / Windows. |
| `step_2` | Was it horizontal or vertical | **MET** | Horizontal movement. The evidence shows internal host-to-host activity within RFC1918 ranges and the triage analysis explicitly assesses the case as lateral movement rather than vertical escalation. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **MET** | Yes. Suspicious process activity is present on BETHANYCHUCHU, including vmtoolsd.exe running as NT AUTHORITY\SYSTEM, cmd.exe, sc.exe, powershell.exe, reg.exe, wevtutil.exe, Upfc.exe, and other administrative/script artifacts. The alert context and associated indicators are consistent with malicious execution on the endpoint. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | The timeline does not provide a full parent-child process tree or sufficient execution lineage to conclusively prove privilege escalation, lateral movement mechanics, or data exfiltration. Suspicious admin and script activity is visible, but the missing process-tree telemetry prevents definitive reconstruction of the malicious chain. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary. The incident is high risk, includes explicit lateral-movement indicators, and shows suspicious privileged process activity. Immediate containment should prioritize host isolation, evidence preservation, and collection of endpoint telemetry before any recovery or closure. |

## Recommended Containment Actions
- Immediately isolate BETHANYCHUCHU from the network through EDR host containment to stop further outbound HTTPS communication and potential lateral movement.
- Preserve volatile evidence before remediation: capture a memory image, running process list, open network sockets, loaded modules, and current command lines for vmtoolsd.exe, cmd.exe, sc.exe, powershell.exe, reg.exe, wevtutil.exe, Upfc.exe, and NWEAgent.exe.
- Quarantine or retrieve the suspicious binaries and scripts referenced in telemetry, including vmtoolsd.exe, resume-vm-default.bat, suspend-vm-default.bat, and any associated dropped files with hashes 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c, 9d7738bb9f12a783d7656b8051321ada1c45f18d68d541c34b99fcc704ad507e, 463c6c8a6655107ce45b4121988ebe3f, 9e63d657b41e13b75aebb261e7f93c0655d52ee82811b37e7470f4119e5b6054, and ecfd9b55800aebb164a07d9a402dc9dd.
- Hunt across the environment for the external IP 4.145.79.81 and related internal hosts 192.168.10.201, 192.168.10.205, 192.168.10.207, and 192.168.20.201 to identify any additional hosts showing the same service-control, registry, or vmtoolsd.exe indicators.
- Collect Windows Security, Sysmon, and EDR telemetry for process creation, service installation, registry changes, and outbound connections around 2025-07-14T11:21:34+00:00, especially Event IDs 4688, 4697, 7045, 1, 3, 11, 12, and 13.
- Disable or reset any accounts or credentials observed in the incident context if they are confirmed to have been used for unauthorized actions, and review local administrator membership changes or newly created accounts on BETHANYCHUCHU.
- Block the external destination and associated indicators at the network perimeter and EDR web controls pending validation, then reimage the host if the malicious execution path is confirmed.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1790475695-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-09-27T02:21:35Z |
| `AUD-DP08-1790475695-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-09-27T02:21:35Z |
| `AUD-DP09-1790475695-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-09-27T02:21:35Z |
| `AUD-DP10-1790475695-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-09-27T02:21:35Z |
