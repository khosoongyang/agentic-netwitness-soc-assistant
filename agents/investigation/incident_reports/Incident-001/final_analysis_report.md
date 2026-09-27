# INVESTIGATION SUMMARY: INC-52825 (Incident-001)

**Final Severity:** High
*High severity is justified because the incident shows a likely compromised asset with SYSTEM-context execution, suspicious administrative tooling, outbound HTTPS to a listed external IP, repeated correlated alerts, and prior lateral-movement indicators. The evidence does not confirm ransomware, widespread outage, or proven data exfiltration, so Critical is not supported by the provided telemetry.*

**Confidence Level:** Medium
*Confidence is Medium because multiple reliable signals align on suspicious host activity, but the dataset lacks full parent-child process lineage, detailed network payload context, and direct proof of the exact malicious action chain. The conclusion is well supported, but key investigative gaps remain.*

## Investigative Workflow
- Reviewed the full incident timeline and correlated prior alerts for the same host and user context.
- Validated the playbook steps against the available telemetry and marked process-tree analysis as not fully satisfied due to missing lineage data.
- Assessed the host as a likely compromised non-critical asset based on SYSTEM-context execution, suspicious administrative command usage, and repeated correlated alerts.
- Mapped the observed behavior to lateral movement, command-and-control, and system administration abuse patterns at the incident level.
- Prepared containment guidance focused on host isolation, evidence preservation, and EDR reconstruction of the execution chain.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2025-07-14T11:21:34+00:00, NetWitness generated a high-risk alert on host BETHANYCHUCHU for vmtoolsd.exe executing as NT AUTHORITY\SYSTEM and making outbound HTTPS connections to a listed external IP. The incident centered on a file hash of 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c, with the file name vmtoolsd.exe and related process artifacts including NWEAgent.exe, upfc.exe, mousocoreworker.exe, cmd.exe, sc.exe, reg.exe, powershell.exe, and resume-vm-default.bat. The alert context also included a VMware-related cmd execution chain, Windows service and update utilities, and registry modification behavior referencing HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA being set to 0, which is consistent with UAC weakening. The same host had prior high-risk activity in the incident history, including repeated internal host-to-host communications involving 192.168.10.x and 192.168.20.x systems, and separate alerts in the broader case set flagged lateral-movement and suspicious endpoint behavior. Threat intelligence on the external IP 4.145.79.81 returned low-confidence reputation results, while the endpoint telemetry itself remained the strongest signal: SYSTEM-context execution, suspicious administrative tooling, and outbound HTTPS from the affected workstation without enough process-tree detail to prove the exact spawning chain or confirm exfiltration.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial suspicious execution on compromised host | Host BETHANYCHUCHU executed vmtoolsd.exe as NT AUTHORITY\SYSTEM, with related artifacts NWEAgent.exe, upfc.exe, mousocoreworker.exe, resume-vm-default.bat, and cmd.exe /c ""C:\Program Files\VMware\VMware Tools\suspend-vm-default.bat"" / resume-vm-default.bat in the incident scope. | Execution | System Services: Service Execution | T1569.002 |
| Service and administrative tooling abuse | Command-line telemetry includes sc.exe start wuauserv and multiple service-related Windows components under SYSTEM context on BETHANYCHUCHU, indicating service control activity. | Execution | System Services | T1569 |
| Privileged command and script activity | The incident includes powershell.exe -ExecutionPolicy Bypass, cmd.exe, reg.exe, and other administrative utilities executed from the host telemetry. | Execution | Command and Scripting Interpreter | T1059 |
| UAC weakening / privilege elevation preparation | The command line cmd.exe reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f appears in the incident, indicating modification of UAC-related policy settings. | Privilege Escalation | Abuse Elevation Control Mechanism: Bypass User Account Control | T1548.002 |
| Potential remote service or host-to-host movement | The broader incident set contains explicit lateral-movement labels, internal host-to-host IP activity across 192.168.10.x and 192.168.20.x, and service-control behavior consistent with remote execution patterns. | Lateral Movement | Remote Services | T1021 |
| Outbound command-and-control over web protocols | vmtoolsd.exe on BETHANYCHUCHU generated outbound HTTPS traffic to 4.145.79.81, which is a Microsoft-hosted IP with external reputation correlation and was flagged by the alert as suspicious web protocol traffic. | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Possible masquerading / trusted process abuse | A legitimate-looking VMware process name (vmtoolsd.exe) was associated with anomalous SYSTEM-context HTTPS activity and additional suspicious artifacts within the same incident, suggesting abuse of a trusted process path or masquerading behavior. | Defense Evasion | Masquerading | T1036 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Primary observed context is NT AUTHORITY\SYSTEM on host BETHANYCHUCHU. Source IP observed in the incident is fe80:0:0:0:9706:3f55:e752:75ca, with the alert also showing prior internal host activity and an external destination target. Related telemetry references user Bethany Chu as the interactive account context in the same host scope. Operating system is Windows / Microsoft Windows 10 Pro. |
| `step_2` | Was it horizontal or vertical | **MET** | Horizontal movement. The incident repeatedly references internal RFC1918-to-RFC1918 activity and explicitly labels the behavior as lateral movement in related alerts. There is no direct evidence of privilege escalation to a higher user tier that would support vertical movement. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **MET** | Yes. The telemetry shows vmtoolsd.exe executing in NT AUTHORITY\SYSTEM context with outbound HTTPS activity, alongside suspicious companion artifacts including NWEAgent.exe, upfc.exe, mousocoreworker.exe, cmd.exe, sc.exe, reg.exe, powershell.exe, and the batch artifact resume-vm-default.bat. The incident also includes a malicious reputation-linked IP indicator and multiple internal alert correlations consistent with active adversary-driven process activity. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | The available evidence supports suspicion of malicious endpoint activity, but it does not provide a full parent-child process tree, process IDs, or execution lineage sufficient to prove how the suspicious processes were spawned. Privilege escalation is suggested by SYSTEM-context execution and registry/UAC-related behavior in the wider incident scope, but it cannot be confirmed from the provided telemetry. Data exfiltration is also not proven; only outbound HTTPS and internal host-to-host behavior are observed. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary. The endpoint should be treated as potentially compromised and contained immediately while telemetry gaps are closed. Full EDR triage, process lineage reconstruction, service-installation review, and network connection validation are required before any relaxation of containment. |

## Recommended Containment Actions
- Immediately isolate host BETHANYCHUCHU at the EDR/network layer while preserving the current session state and volatile memory.
- Collect a live triage package from BETHANYCHUCHU: running processes, full command lines, network sockets, autoruns, scheduled tasks, loaded services, and recent file writes.
- Export Windows Security and Sysmon telemetry for the window around 2025-07-14T11:21:34+00:00, especially Event IDs 4688, 4697, 7045, 4624, 4672, 5156, 1, 3, 11, 12, and 13.
- Quarantine or hash-validate vmtoolsd.exe, resume-vm-default.bat, Sandy.exe references, and any associated binaries matching hashes from the incident before allowing further execution.
- Disable or reset any local administrative credentials used on the host, including accounts appearing in the incident scope, and review for unauthorized group membership changes.
- Block outbound connections to 4.145.79.81 and any other destinations observed in the host telemetry until the execution chain and purpose are confirmed.
- Investigate registry modifications to HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA and restore UAC settings if unauthorized changes are confirmed.
- Search adjacent hosts in the 192.168.10.0/24 and 192.168.20.0/24 ranges for the same hashes, process names, and service-installation patterns to determine spread.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1790488870-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-09-27T06:01:10Z |
| `AUD-DP08-1790488870-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-09-27T06:01:10Z |
| `AUD-DP09-1790488870-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-09-27T06:01:10Z |
| `AUD-DP10-1790488870-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-09-27T06:01:10Z |
