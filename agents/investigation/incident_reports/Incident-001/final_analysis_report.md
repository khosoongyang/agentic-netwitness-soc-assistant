# INVESTIGATION SUMMARY: INC-52825 (Incident-001)

**Final Severity:** High
*High severity is warranted because the incident shows suspicious privileged execution on a workstation, outbound HTTPS to a listed external IP, repeated SYSTEM-context process activity, and indicators of service/registry abuse. However, the dataset does not provide sufficient proof of confirmed exfiltration, ransomware, or widespread outage, so Critical is not supported by the available evidence.*

**Confidence Level:** Medium
*Confidence is Medium because multiple reliable sources align on suspicious endpoint behavior, privileged context, and network activity, but the incident lacks a full process tree, clear parent-child lineage, and direct proof of payload execution or impact. The evidence is sufficient to support a high-risk assessment, but not strong enough for High confidence under the evidence sufficiency rules.*

## Investigative Workflow
- Reviewed the full incident timeline and correlated alert context for INC-52825.
- Re-evaluated the playbook steps against the updated telemetry and confirmed suspicious SYSTEM-context execution and outbound HTTPS activity.
- Assessed enrichment results for the file hash and destination IP and noted no decisive benign explanation from threat intelligence.
- Mapped the available behavior to incident-level MITRE ATT&CK techniques in chronological order.
- Prepared containment guidance focused on host isolation, volatile evidence preservation, and process-tree reconstruction.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2025-07-14 at 11:21:34+00:00, NetWitness raised a high-risk incident on host BETHANYCHUCHU involving vmtoolsd.exe running as NT AUTHORITY\SYSTEM and making outbound HTTPS connections to the external IP 4.145.79.81, with the destination endpoint recorded as 124.155.222.24 and the source address as fe80:0:0:0:9706:3f55:e752:75ca. The alert set also included multiple correlated events showing VMware and Windows service activity, with vmtoolsd.exe invoking VMware tools commands such as suspend-vm-default.bat and resume-vm-default.bat, alongside NWEAgent.exe /runasservice, Upfc.exe /launchtype periodic, mousocoreworker.exe -Embedding, and several Microsoft Edge WebView and Windows maintenance processes. Within the same incident scope, command-line telemetry showed service and registry manipulation behavior, including cmd.exe /c reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f, sc.exe start wuauserv, multiple wevtutil install-manifest and uninstall-manifest commands against Microsoft Defender manifest files, and other SYSTEM-context activity from svchost.exe, smss.exe, and wmiprvse.exe. The bundled enrichment did not show decodable PowerShell EncodedCommand content, but the overall sequence indicates privileged execution on the endpoint with abnormal external network communication and repeated system-level process activity rather than a single isolated benign event.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial suspicious execution and service-context activity on BETHANYCHUCHU | vmtoolsd.exe executed as NT AUTHORITY\SYSTEM on host BETHANYCHUCHU, with VMware batch artifacts such as suspend-vm-default.bat and resume-vm-default.bat appearing in the same incident scope. | Execution | System Services | T1569.002 |
| Abnormal script and command interpreter activity during the incident window | cmd.exe, powershell.exe -ExecutionPolicy Bypass, reg.exe ADD, sc.exe start wuauserv, and msiexec.exe /quiet /qn /i C:\Users\Public\adduser.msi were present in the telemetry around the suspicious activity. | Execution | Command and Scripting Interpreter | T1059 |
| Privileged context and policy weakening behavior | The command line reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f indicates modification of the UAC policy key on the endpoint. | Privilege Escalation | Abuse Elevation Control Mechanism | T1548 |
| Service control and Windows component manipulation | sc.exe start wuauserv and multiple wevtutil install-manifest / uninstall-manifest commands were observed alongside svchost.exe and wmiprvse.exe system activity. | Defense Evasion | Impair Defenses | T1562 |
| Host-to-host and internal network activity associated with suspected lateral movement | The incident includes same-site RFC1918 traffic and lateral-movement classification context, with internal IPs such as 192.168.10.201, 192.168.10.205, 192.168.10.207, and 192.168.20.201 referenced in the grouped alerts. | Lateral Movement | Remote Services | T1021 |
| Outbound HTTPS communication to external destination | vmtoolsd.exe on BETHANYCHUCHU generated outbound HTTPS to 4.145.79.81, with NetWitness flagging the connection as high risk and correlating it with the SYSTEM-context process activity. | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Username observed in the incident is NT AUTHORITY\SYSTEM, with Bethany Chu also referenced in the surrounding telemetry. IP evidence includes source IPv6 fe80:0:0:0:9706:3f55:e752:75ca and source IPv4 192.168.10.201. No explicit interactive logon details were provided in the timeline. Computer name is BETHANYCHUCHU. Operating system is Windows / Microsoft Windows 10 Pro. |
| `step_2` | Was it horizontal or vertical | **MET** | The evidence supports horizontal movement/lateral activity rather than vertical privilege escalation. The incident includes internal RFC1918 host-to-host activity and an explicit lateral-movement classification, but no direct proof of a higher-privilege account being gained through a new logon token or credential escalation event. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **MET** | Yes. The timeline shows suspicious process activity on BETHANYCHUCHU including vmtoolsd.exe running as NT AUTHORITY\SYSTEM and making outbound HTTPS connections, along with cmd.exe, powershell.exe, sc.exe, reg.exe, msedgewebview2.exe, wevtutil.exe, and vmtoolsd-related VMware command lines. The playbook trace also references adminUAC modification activity and service-control behavior consistent with malicious execution. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | The provided timeline does not include a full reconstructable parent-child process tree, integrity levels, or per-spawn lineage sufficient to prove privilege escalation or data exfiltration. The telemetry strongly suggests malicious Windows administration abuse and suspicious SYSTEM-context execution, but the exact chain of process creation cannot be fully confirmed from the available data. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary and containment is warranted. The host should be isolated, volatile evidence preserved, and endpoint/Security/Sysmon telemetry collected to reconstruct process lineage and confirm whether the SYSTEM-context activity represented lateral movement or a false positive. Focus investigation on vmtoolsd.exe, cmd.exe, powershell.exe, reg.exe, wevtutil.exe, and the internal and external network targets referenced in the telemetry. |

## Recommended Containment Actions
- Immediately isolate host BETHANYCHUCHU from the network using EDR network containment while preserving the current session state.
- Capture a full volatile triage package from BETHANYCHUCHU before reboot or remediation: running processes, parent-child process tree, active network sockets, logged-on users, scheduled tasks, services, and autoruns.
- Quarantine and preserve vmtoolsd.exe, resume-vm-default.bat, suspend-vm-default.bat, upfc.exe, and any associated temporary files or hashes for forensic review.
- Block outbound HTTPS to 4.145.79.81 and investigate any other connections made by vmtoolsd.exe or child processes during the incident window.
- Collect Windows Security, Sysmon, and EDR telemetry for Event IDs 4688, 4624, 4672, 4697, 7045, 5156, and Sysmon 1/3/11 to reconstruct the execution chain and identify any service or registry abuse.
- Review and revert any unauthorized policy changes, especially HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA, only after confirming the malicious scope and preserving evidence.
- Search the environment for the same SHA256, filename, and command lines on other endpoints and isolate any additional affected systems if matches are found.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1790423792-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-09-26T11:56:32Z |
| `AUD-DP08-1790423792-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-09-26T11:56:32Z |
| `AUD-DP09-1790423792-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-09-26T11:56:32Z |
| `AUD-DP10-1790423792-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-09-26T11:56:32Z |
