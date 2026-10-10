# INVESTIGATION SUMMARY: INC-53035 (Incident-004)

**Final Severity:** Medium
*Medium is appropriate because the case shows repeated suspicious internal Modbus activity with a high NetWitness risk score and multiple alerts, but there is no endpoint, user, process, or data-impact evidence to confirm compromise, privilege misuse, outage, or sensitive-data exposure. The available evidence supports suspicious contained activity rather than confirmed attack impact.*

**Confidence Level:** Medium
*Confidence is Medium because the network evidence is strong and internally consistent across 67 alerts, but it is limited to traffic metadata and lacks endpoint, identity, command-line, or host context. The conclusion that this is suspicious anomalous Modbus communication is well supported, but the absence of corroborating endpoint evidence prevents High confidence.*

## Investigative Workflow
- Reviewed the 67 NetWitness alerts associated with INC-53035 and consolidated them as repeated Modbus non-whitelisted source events.
- Verified that the only concrete observed indicators were internal network connections from 192.168.0.19 to 192.168.0.34 over port 502.
- Checked the available triage and deep-dive notes for identity, host, endpoint, process, and PowerShell evidence and confirmed those artifacts were absent.
- Compared the case with correlated historical incidents to validate that the pattern is similar to prior internal Modbus anomaly cases, while keeping the current case analytically separate.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2026-07-25 at 08:36:34.979+00:00, NetWitness began generating repeated alerts titled "Modbus Non-Whitelisted Source" for traffic from 192.168.0.19 to 192.168.0.34 on destination port 502, with source ports including 55179 and 53728. The alert stream continued in rapid succession through the 08:36:35 window, with dozens of nearly identical events showing the same pair of internal hosts and the same industrial protocol destination, indicating sustained Modbus activity rather than an isolated connection. The observed records describe the network action as preset single register and data push, but the case telemetry does not provide any user identity, host name, operating system, process execution, or command-line evidence for either endpoint. No endpoint telemetry, file activity, PowerShell activity, or process tree data accompanies the network alerts, so the incident can only be described as repeated anomalous Modbus communication between 192.168.0.19 and 192.168.0.34 during the brief observation window.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial anomalous industrial protocol communication | Repeated NetWitness alerts titled "Modbus Non-Whitelisted Source" show 192.168.0.19 connecting to 192.168.0.34 on TCP/502, including source ports 55179 and 53728, with actions described as preset single register and data push. | Discovery | Network Service Scanning | T1046 |
| Sustained internal host-to-host Modbus interaction | Dozens of repeated internal connections between 192.168.0.19 and 192.168.0.34 over port 502 occurred within seconds, indicating persistent communication across a private RFC1918 subnet. | Lateral Movement | Remote Services | T1021 |
| Industrial control command delivery over Modbus | The deep-dive extracted network actions of "preset single register" and "data push" map to direct protocol-level control commands sent from 192.168.0.19 to 192.168.0.34. | Command and Control | Non-Application Layer Protocol | T1095 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **NOT_MET** | The case only provides source IP 192.168.0.19 and destination IP 192.168.0.34, plus repeated Modbus connection details to port 502. No username, login details, computer name, or operating system are present in the telemetry or context brief. |
| `step_2` | Was it horizontal or vertical | **MET** | The activity is assessed as horizontal movement rather than vertical movement because the observed traffic is between two private RFC1918 hosts on the same 192.168.0.0/16 network, 192.168.0.19 to 192.168.0.34, over Modbus port 502. No evidence indicates elevation within a single host. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | No malicious process spawn is confirmed. The incident data is network-only and explicitly lacks endpoint process evidence, process creation logs, PowerShell telemetry, or parent-child process information. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | A process tree analysis cannot be performed because no process, user, host, or command-line artifacts are available. There is insufficient evidence to evaluate privilege escalation, execution chains, or exfiltration from endpoint telemetry. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **NOT_MET** | Further investigation is warranted because the case contains repeated suspicious internal Modbus communication and a high NetWitness risk score, but the available evidence is insufficient to confirm malicious execution or impact. Containment should be scoped only after endpoint and network validation. |

## Recommended Containment Actions
- Immediately block or restrict Modbus/TCP traffic from 192.168.0.19 to 192.168.0.34 at the network control point while validation is performed.
- Place 192.168.0.19 and 192.168.0.34 on heightened monitoring for all port 502 sessions, including packet capture of request/response function codes, source ports, and transaction IDs.
- Collect endpoint telemetry from both hosts for the incident window, including process creation, logon events, service creation, and PowerShell logs, before making any operational changes.
- Validate asset ownership and approved industrial-control communications for both IPs with the OT/engineering team and remove any source that is not in the whitelist.
- If either host is confirmed to be unauthorized for Modbus control traffic, isolate that host from the OT subnet pending forensic review.
- Preserve firewall, switch, and NetWitness logs for the full alert burst so the repeated session pattern can be reconstructed and compared to normal baseline communications.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1791629665-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-10-10T10:54:25Z |
| `AUD-DP08-1791629665-2` | **DP-08** | Appendix A | Severity classification: Medium | *Pass* | `Investigate` | Yes | 2026-10-10T10:54:25Z |
| `AUD-DP09-1791629665-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-10-10T10:54:25Z |
| `AUD-DP10-1791629665-4` | **DP-10/DP-11** | Appendix G | Severity: Medium, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-10-10T10:54:25Z |
