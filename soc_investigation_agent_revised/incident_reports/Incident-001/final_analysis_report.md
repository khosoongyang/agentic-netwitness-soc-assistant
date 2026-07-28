# INVESTIGATION SUMMARY: INC-52825 (Incident-001)

**Final Severity:** High
*High severity is appropriate because the incident shows strong suspicion of adversary activity affecting an important endpoint with SYSTEM context, lateral movement indicators, privileged service/control and registry abuse, and potential privilege-escalation preparation. However, there is no confirmed ransomware, widespread outage, sensitive data exposure, or proven multi-system compromise in the provided evidence, so Critical is not supported.*

**Confidence Level:** High
*Confidence is High because multiple aligned sources support the conclusion: NetWitness alerting, endpoint process telemetry, registry-modification evidence, internal lateral-movement indicators, and threat-intel enrichment on the external IP. The main gap is the absence of full parent-child process lineage and direct malware confirmation, but the available evidence is sufficiently consistent to support the final assessment.*

## Investigative Workflow
- Reviewed NetWitness and triage enrichment for incident INC-52825.
- Confirmed affected host as BETHANYCHUCHU and user context as NT AUTHORITY\SYSTEM.
- Correlated lateral movement indicators across 192.168.10.x and 192.168.20.x.
- Identified suspicious process and administrative artifacts: vmtoolsd.exe, cmd.exe, sc.exe, reg.exe, wmiprvse.exe.
- Validated UAC-disabling registry modification evidence: EnableLUA=0.
- Captured observed external IOC 4.145.79.81 and destination IP 124.155.222.24 for threat hunting and blocking.
- Determined that additional investigation and containment are required due to likely hostile admin activity.

## Technical Chronology & MITRE ATT&CK TTP Mapping

2025-07-14T11:21:34+00:00: NetWitness generated a High severity alert for host BETHANYCHUCHU (Windows) after vmtoolsd.exe, running as NT AUTHORITY\SYSTEM, made outbound HTTPS connections associated with external IOC 4.145.79.81 and destination 124.155.222.24. The endpoint telemetry also recorded additional suspicious process activity on the same host, including cmd.exe, sc.exe, reg.exe, and wmiprvse.exe artifacts. Triage data linked the event to lateral movement across internal RFC1918 ranges 192.168.10.x and 192.168.20.x, and the alert title indicated lateral movement plus UAC disabling behavior. Process lineage evidence showed cmd.exe invoking reg.exe to modify HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=0, indicating UAC weakening/privilege-escalation preparation. Service-control and WMI-related artifacts suggest remote execution or service abuse on BETHANYCHUCHU. No clear evidence of data theft or confirmed malware payload execution was present in the provided telemetry, but the event set is consistent with hostile administrative activity and lateral movement attempts.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial access / first observed host activity | Host BETHANYCHUCHU generated a high-risk alert involving vmtoolsd.exe running as NT AUTHORITY\SYSTEM with outbound HTTPS to external IOC 4.145.79.81 and destination 124.155.222.24. | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Host-to-host movement observed across internal private ranges | Triage noted activity between 192.168.10.x and 192.168.20.x, with the incident explicitly labeled as lateral movement and internal source/destination IPs including 192.168.10.204, 192.168.10.205, 192.168.10.207, and 192.168.20.201. | Lateral Movement | Remote Services | T1021 |
| Remote execution / administrative abuse on victim host | Process telemetry on BETHANYCHUCHU included wmiprvse.exe / WmiPrvSE.exe artifacts along with cmd.exe and sc.exe activity, consistent with remote WMI-based execution or administration. | Lateral Movement | Windows Management Instrumentation | T1047 |
| Service abuse and control activity | Command-line telemetry showed sc.exe start wuauserv and other service-control behavior on BETHANYCHUCHU, indicating service manipulation and possible execution via Windows services. | Execution | System Services: Service Execution | T1569.002 |
| Privilege escalation preparation / security control weakening | cmd.exe invoked reg.exe to add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA /d 0 /f, disabling UAC on the host. | Privilege Escalation | Modify Registry | T1112 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Username identified as NT AUTHORITY\SYSTEM, with additional user context Bethany Chu present in telemetry. Network indicators include source 4.145.79.81 and fe80:0:0:0:9706:3f55:e752:75ca, and destination 124.155.222.24. Login context is SYSTEM execution via vmtoolsd.exe making outbound HTTPS. Computer name is BETHANYCHUCHU. Operating system is Windows. |
| `step_2` | Was it horizontal or vertical | **MET** | Horizontal movement. The incident is explicitly labeled as Lateral Movement, and supporting evidence shows host-to-host activity across RFC1918 ranges 192.168.10.x and 192.168.20.x, consistent with lateral rather than privilege-upward movement. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **MET** | Yes. Suspicious and likely malicious process activity is present on BETHANYCHUCHU, including vmtoolsd.exe running as SYSTEM with outbound HTTPS, cmd.exe, sc.exe, reg.exe, and wmiprvse.exe-related administrative behavior. The telemetry strongly supports malicious process spawning and service manipulation, although the exact malware payload is not fully identified. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **MET** | The process indicators align with hostile admin abuse and privilege-escalation preparation: cmd.exe invoked reg.exe to set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=0, sc.exe activity suggests service control or service abuse, vmtoolsd.exe performed outbound HTTPS beaconing, and wmiprvse.exe artifacts are consistent with remote execution/lateral movement. No direct evidence of data exfiltration is present in the provided telemetry. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary. Recommended containment includes host isolation for BETHANYCHUCHU, blocking external IOC 4.145.79.81 and destination 124.155.222.24, preserving memory/disk and EDR telemetry, hunting pivot hosts in 192.168.10.x and 192.168.20.x, reviewing service creation and registry modification evidence, and validating/resetting any privileged credentials used on the system. |

## Recommended Containment Actions
- Immediately isolate host BETHANYCHUCHU from the network using EDR network containment, while preserving live memory for acquisition before power-off.
- Block egress and ingress traffic to 4.145.79.81 and 124.155.222.24 at the firewall, secure web gateway, and EDR network-control layers.
- Quarantine or suspend vmtoolsd.exe on the host only after memory capture, then validate VMware Tools binaries against trusted vendor signatures and hashes.
- Hunt and contain any internal pivot hosts in 192.168.10.0/24 and 192.168.20.0/24 that show 4624 Type 3/10, 4648, 4672, 4688, 4697, 7045, WMI, PsExec, or service-control activity tied to BETHANYCHUCHU.
- Remotely collect and preserve Security, Sysmon, and EDR telemetry from BETHANYCHUCHU, including process creation, service-install, registry-change, and network-connection events around 2025-07-14T11:21:34+00:00.
- Revert HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA to the approved value and document who/what changed it, then verify no other UAC or policy tampering occurred.
- Reset and invalidate any privileged credentials used on or from BETHANYCHUCHU, especially accounts associated with remote service creation, WMI execution, or administrative logons.
- Perform IOC hunting for the listed file hash 8f490791f7164633e2bc3bfe129c829986a45b918566c2fe1d63f3c77b0eb28c, vmtoolsd.exe anomalies, and any matching service-control or WMI execution chains across the enterprise.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1785220762-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-07-28T06:39:22Z |
| `AUD-DP08-1785220762-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-07-28T06:39:22Z |
| `AUD-DP09-1785220762-3` | **DP-09** | Appendix F | Confidence level: High | *Pass* | `Investigate` | Yes | 2026-07-28T06:39:22Z |
| `AUD-DP10-1785220762-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: High, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-07-28T06:39:22Z |
