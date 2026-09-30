# INVESTIGATION SUMMARY: INC-52825 (Incident-001)

**Final Severity:** High
*High is appropriate because the incident shows a strong suspected compromise on a non-critical asset with SYSTEM-context execution, lateral-movement labeling, privileged command activity, service/registry manipulation, and outbound HTTPS to an external IP. The activity matches multiple High severity escalation factors, but there is no confirmed widespread outage, ransomware, or verified data exfiltration to justify Critical.*

**Confidence Level:** Medium
*Medium confidence is appropriate because multiple independent timeline elements align on suspicious behavior, including privileged process execution, internal lateral-movement context, and malicious-looking administrative commands. However, the evidence is still incomplete: the timeline lacks a full parent-child process tree, exact logon context, and direct proof of payload execution or exfiltration, so the conclusion remains strongly supported but not definitive.*

## Investigative Workflow
- Reviewed incident timeline and correlated alert entries for INC-52825 and related historical alert context on BETHANYCHUCHU.
- Reconciled the playbook trace against the updated timeline and confirmed horizontal movement, suspicious privileged execution, and the need for continued investigation.
- Identified the key suspicious artifacts and commands: vmtoolsd.exe, NWEAgent.exe, upfc.exe, resume-vm-default.bat, sc.exe, reg.exe, wevtutil.exe, and SYSTEM-context HTTPS traffic to 4.145.79.81 / 124.155.222.24.
- Determined that the available telemetry is insufficient to prove full process lineage, privilege escalation, or exfiltration from execution telemetry alone.
- Prepared containment guidance to isolate the host and preserve volatile evidence pending SOC analyst review.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2025-07-14T11:21:34+00:00, host BETHANYCHUCHU generated a high-risk NetWitness endpoint alert while running as NT AUTHORITY\SYSTEM. The primary observed activity was vmtoolsd.exe executing in SYSTEM context and generating outbound HTTPS traffic to the external IP 4.145.79.81, which the timeline associates with the destination 124.155.222.24 in the alert record. The same incident scope also included the executable and artifact set vmtoolsd.exe, NWEAgent.exe, upfc.exe, mousocoreworker.exe, and resume-vm-default.bat, alongside command-line activity such as vmtoolsd.exe -n vmusr, cmd.exe /c "C:\Program Files\VMware\VMware Tools\suspend-vm-default.bat", cmd.exe /c "C:\Program Files\VMware\VMware Tools\resume-vm-default.bat", sc.exe start wuauserv, reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f, and wevtutil.exe install-manifest / uninstall-manifest operations against Windows Defender manifests. The telemetry shows repeated internal host-to-host alerting within the same incident context and also includes vmtoolsd.exe, search/webview, update, and service-control artifacts executing under privileged context. The event bundle repeatedly labels the activity as lateral movement / compromised asset behavior and links it to internal network activity and Windows administration changes, but the provided data does not include a full parent-child process tree or direct network session detail that would conclusively prove the exact execution chain, privilege escalation sequence, or any data exfiltration.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial privileged execution and suspicious host activity | On BETHANYCHUCHU, vmtoolsd.exe executed as NT AUTHORITY\SYSTEM and the incident bundle included vmtoolsd.exe -n vmusr, NWEAgent.exe /runasservice, and repeated SYSTEM-context process activity on 2025-07-14T11:21:34+00:00. | Execution | System Services | T1569.002 |
| Administrative command execution and script/control activity | The timeline shows cmd.exe /c "C:\Program Files\VMware\VMware Tools\suspend-vm-default.bat", cmd.exe /c "C:\Program Files\VMware\VMware Tools\resume-vm-default.bat", sc.exe start wuauserv, powershell.exe -ExecutionPolicy Bypass, reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f, and wevtutil.exe manifest install/uninstall operations on BETHANYCHUCHU. | Execution | Command and Scripting Interpreter | T1059 |
| Privilege weakening via registry modification | The incident includes command-line registry editing to set EnableLUA to 0 using reg.exe under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, which is a UAC-disabling modification on the host. | Defense Evasion | User Account Control Bypass / Disabling | T1548.002 |
| Service manipulation and potential persistence/support for elevated execution | sc.exe start wuauserv and NWEAgent.exe /runasservice appeared in the same alert set, along with other service-oriented Windows processes such as svchost.exe and service-hosted components on BETHANYCHUCHU. | Persistence | Create or Modify System Process | T1543.003 |
| Outbound communication to external network destination | The host generated outbound HTTPS traffic from fe80:0:0:0:9706:3f55:e752:75ca to 4.145.79.81 / 124.155.222.24 while running as SYSTEM, and the incident detail explicitly flagged application-layer web traffic over HTTPS. | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Internal host-to-host activity consistent with lateral movement | The incident context repeatedly references internal RFC1918 source and destination addresses, including 192.168.10.204 to 192.168.10.202, and labels the activity as Lateral Movement on the BETHANYCHUCHU host. | Lateral Movement | Remote Services | T1021 |
| Potential remote execution / lateral movement via Windows administration tooling | The alert set includes WmiPrvSE.exe, sc.exe, cmd.exe, and privileged SYSTEM-context activity across internal hosts, indicating a probable Windows remote-administration or service-based movement path even though full lineage is missing. | Lateral Movement | Windows Management Instrumentation | T1047 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | User: NT AUTHORITY\SYSTEM. Source IP: fe80:0:0:0:9706:3f55:e752:75ca. Login details: SYSTEM-context execution on BETHANYCHUCHU, with no explicit interactive logon type provided in the timeline. Computer name: BETHANYCHUCHU. Operating system: Windows. |
| `step_2` | Was it horizontal or vertical | **MET** | Horizontal movement. The timeline explicitly labels the alert as 'Lateral Movement' and shows host-to-host activity between internal RFC1918 addresses (notably 192.168.10.204 and 192.168.10.202), which supports lateral movement rather than privilege gain on the same host. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **MET** | Yes. Suspicious/malicious process activity is present on the victim machine, including vmtoolsd.exe running as NT AUTHORITY\SYSTEM, cmd.exe, sc.exe, reg.exe, wevtutil.exe, powershell.exe, and a suspicious file/IOC set including resume-vm-default.bat and upfc.exe. The timeline also indicates a SYSTEM-run process making outbound HTTPS connections. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | The timeline does not contain a full process tree with parent-child lineage, so malicious activity can be suspected but not conclusively mapped through privilege escalation, lateral movement steps, or data exfiltration from execution telemetry alone. The needed process hierarchy, exact parent process for each suspicious binary, and corroborating logon/service-creation context are missing. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary. Containment should include isolating host BETHANYCHUCHU, preserving volatile evidence, collecting full process-tree telemetry and Windows/Sysmon logs, and reviewing suspicious artifacts such as vmtoolsd.exe, upfc.exe, resume-vm-default.bat, sc.exe, reg.exe, and any process invoking PowerShell or wevtutil. Because the incident is high risk and lateral movement is indicated, host containment is warranted pending confirmation. |

## Recommended Containment Actions
- Immediately isolate BETHANYCHUCHU from the network using EDR containment while preserving console access for live response.
- Capture a volatile triage package from BETHANYCHUCHU before reboot: running processes, active network connections, logged-on users, services, scheduled tasks, autoruns, and loaded modules.
- Collect full process creation telemetry for the incident window, including Windows Security 4688, 4624/4672, 4697/7045, and Sysmon Event IDs 1, 3, 7, 10, 11, and 13 to reconstruct the vmtoolsd.exe / cmd.exe / sc.exe / reg.exe / wevtutil.exe chain.
- Quarantine and retrieve the exact binaries and scripts referenced in the timeline for offline analysis: vmtoolsd.exe, NWEAgent.exe, upfc.exe, resume-vm-default.bat, suspend-vm-default.bat, and any Defender-manifest modification artifacts.
- Block the observed external destination 4.145.79.81 and the associated session target 124.155.222.24 at the gateway and EDR network control layer until the host is cleared.
- Review and, if unauthorized, revert the EnableLUA registry modification under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System and validate other service/manifests modified by wevtutil.exe.
- Search the environment for the same hashes and command patterns on other endpoints, especially internal hosts 192.168.10.204 and 192.168.10.202, to identify any spread or follow-on activity.
- If evidence confirms compromise, reset credentials for the affected user context and any privileged accounts associated with the host, then perform a full forensic image acquisition of BETHANYCHUCHU.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1790780117-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-09-30T14:55:17Z |
| `AUD-DP08-1790780117-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-09-30T14:55:17Z |
| `AUD-DP09-1790780117-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-09-30T14:55:17Z |
| `AUD-DP10-1790780117-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-09-30T14:55:17Z |
