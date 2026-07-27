# INVESTIGATION SUMMARY: INC-52981 (Incident-002)

**Final Severity:** Medium
*Medium is appropriate because the incident shows suspicious repeated network activity and a lateral-movement label, but the evidence is network-only with no confirmed malicious process execution, privilege misuse, endpoint compromise, service outage, or data exposure. Appendix A supports Medium for suspicious activity with limited impact or contained consequences, and Appendix C does not indicate a confirmed critical system, essential service, or operational degradation.*

**Confidence Level:** Medium
*Medium confidence is assigned because multiple reliable sources align on the observed network behavior and lateral classification, but the evidence is incomplete. Per Appendix F, the conclusion is supported by ESA telemetry and threat enrichment, yet there is no endpoint/process/logon evidence to confirm malicious execution or intent, so the overall evidence is partially sufficient rather than sufficient.*

## Investigative Workflow
- Reviewed RSA NetWitness ESA alert metadata for source IP 192.168.10.14, destination 255.255.255.255, UDP/7989, and sessionid 6216976.
- Reviewed classification, enrichment, and threat intelligence results for the broadcast indicator 255.255.255.255.
- Checked PowerShell enrichment results and confirmed no decodable EncodedCommand or PowerShell indicator was present.
- Assessed the timeline for endpoint, process, file, or exfiltration evidence and found none.
- Mapped the observed behavior to lateral movement/discovery-style activity and determined the case required further investigation rather than urgent containment based on current evidence.

## Technical Chronology & MITRE ATT&CK TTP Mapping

2025-07-15T10:01:02+00:00: RSA NetWitness ESA generated incident INC-52981 ('High Risk Alerts: ESA for 192.168.10.14') for repeated abnormal network activity from source IP 192.168.10.14 to broadcast destination 255.255.255.255 on UDP port 7989 (source port 38370), sessionid 6216976, with network analysis marked 'single sided udp' and direction 'lateral'. The alert context included the source trail 'admin2@192.168.20.14:50005', but no hostname, OS, process tree, PowerShell execution, file activity, or exfiltration evidence was present. Threat enrichment for 255.255.255.255 was non-malicious/low-confidence: AbuseIPDB abuse confidence 0, OTX pulse count 0, VirusTotal IP reputation -95 with 0 malicious and 53 harmless detections; no usable domain or file hash indicators were available. No decodable PowerShell EncodedCommand content was found. Overall, the incident remained a network-only suspicious lateral/discovery-style event affecting 192.168.10.14, with insufficient endpoint evidence to confirm privilege escalation or malicious process execution.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial network alerting and abnormal broadcast activity | RSA NetWitness ESA alert on source 192.168.10.14 communicating to broadcast destination 255.255.255.255 over UDP port 7989; sessionid 6216976; network.direction=lateral; network.analysis='single sided udp'; source trail 'admin2@192.168.20.14:50005'. | Discovery | System Network Configuration Discovery | T1016 |
| Observed lateral broadcast-style network behavior without endpoint confirmation | Repeated high-risk UDP broadcast traffic from 192.168.10.14 to 255.255.255.255:7989 with no process, file, or PowerShell telemetry; alert labeled 'Lateral Movement'. | Lateral Movement | Remote Services | T1021 |
| Threat enrichment and validation of indicator | AbuseIPDB abuse confidence score 0 for 255.255.255.255; OTX pulse_count 0; VirusTotal IP results malicious 0, suspicious 0, harmless 53, undetected 38, reputation -95; no usable domains or file hashes. | Defense Evasion | Indicator Removal on Host | T1070 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **NOT_MET** | Partially identifiable, but not enough to fully satisfy all requested fields. Available evidence identifies the source IP as 192.168.10.14 and suggests the username context 'admin2' from the source trail 'admin2@192.168.20.14:50005'. However, login details (logon type, logon ID, workstation, authentication event), computer name/hostname, and operating system are not present in the timeline. |
| `step_2` | Was it horizontal or vertical | **MET** | Horizontal/lateral movement. The alert is explicitly labeled 'Lateral Movement' and the network direction is marked 'lateral'. The event is also cross-subnet contextually associated with admin2@192.168.20.14 while the victim/source IP is 192.168.10.14. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | No evidence in the timeline confirms that a malicious process spawned on the victim machine. The incident data is network-only (single-sided UDP broadcast activity) and contains no process creation, command line, or endpoint telemetry. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | A process tree cannot be analyzed from the provided evidence because no process lineage exists in the timeline. There is no executable name, parent/child relationship, privilege escalation evidence, lateral movement tool, or exfiltration utility recorded. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary, but urgent containment is not clearly supported by the current evidence. The incident is suspicious and consistent with lateral/discovery-style network activity, yet there is no confirmed malware execution, endpoint compromise, or exfiltration. Recommended containment steps: isolate 192.168.10.14 from the network if risk tolerance is low, preserve EDR/Windows event logs, collect 4624/4625/4688/4672/4104 telemetry, and validate whether admin2 activity from 192.168.20.14 is authorized. |

## Recommended Containment Actions
- Temporarily isolate host 192.168.10.14 at the EDR or NAC layer while preserving network capture and host state, because the activity is repeated and lateral in nature even though endpoint compromise is unconfirmed.
- Block or rate-limit UDP traffic from 192.168.10.14 to 255.255.255.255 on port 7989 at internal segmentation controls to stop further broadcast activity until the source process is identified.
- Preserve volatile and non-volatile evidence on 192.168.10.14 by collecting EDR live response artifacts, Windows Security logs, Sysmon logs, and any available packet capture around 2025-07-15 09:00:19 to 09:20:19 UTC.
- Query domain controller and workstation logs for account context 'admin2' and correlate with source trail 192.168.20.14:50005 to determine whether the activity was authorized administrative traffic or misuse.
- Hunt for the parent process and command line associated with UDP/7989 activity on 192.168.10.14, then terminate only the identified responsible process if it is confirmed unauthorized.
- If additional hosts are found sending similar broadcast traffic to 255.255.255.255:7989, contain the pattern as a cluster by isolating the affected subnet segment and searching for the same session behavior across the fleet.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1785125318-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-07-27T04:08:38Z |
| `AUD-DP08-1785125318-2` | **DP-08** | Appendix A | Severity classification: Medium | *Pass* | `Investigate` | Yes | 2026-07-27T04:08:38Z |
| `AUD-DP09-1785125318-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-07-27T04:08:38Z |
| `AUD-DP10-1785125318-4` | **DP-10/DP-11** | Appendix G | Severity: Medium, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-07-27T04:08:38Z |
