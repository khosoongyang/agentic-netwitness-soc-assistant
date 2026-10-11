# INVESTIGATION SUMMARY: INC-53035 (Incident-004)

**Final Severity:** High
*High is appropriate because the case shows repeated internal non-whitelisted Modbus/TCP activity across 67 alerts between two internal hosts on port 502, which is a strong suspicious indicator affecting an important operational protocol and fits the policy for strongly suspected cyber activity affecting important systems. The evidence is insufficient to elevate to Critical because there is no confirmation of malware, exfiltration, outage, or sensitive data exposure, and no endpoint telemetry confirms compromise. The repeated nature and industrial-style protocol traffic support a High severity investigation.*

**Confidence Level:** Medium
*Medium confidence is warranted because the conclusion is supported by multiple consistent NetWitness alerts and a coherent timeline of repeated internal Modbus connections, but the evidence is still partial. The case lacks user, host, process, authentication, and endpoint telemetry, and the timeline explicitly notes missing protocol context and absent process fields. Under the evidence sufficiency and confidence rules, this supports a suspicious but unconfirmed assessment rather than a high-confidence confirmed compromise.*

## Investigative Workflow
- Reviewed the 67 NetWitness alerts for common source and destination IPs, ports, and recurring patterns.
- Confirmed the repeated internal Modbus/TCP traffic from 192.168.0.19 to 192.168.0.34 on port 502.
- Checked for supporting user, host, authentication, and process telemetry in the case context and found none.
- Assessed historical correlation for similar prior cases involving the same IP pair and related internal network activity.
- Determined that additional endpoint and authentication telemetry is required before any confirmation of privilege escalation or malicious process activity.

## Technical Chronology & MITRE ATT&CK TTP Mapping

At 2026-07-25T08:36:34.979+00:00, NetWitness began generating repeated high-risk alerts labeled "Modbus Non-Whitelisted Source" for traffic from 192.168.0.19 to 192.168.0.34 over destination port 502, with the first observed connection using source port 55179. Within milliseconds, additional alerts repeated the same internal Modbus session pattern, including recurring connections from 192.168.0.19:55179 and 192.168.0.19:53728 to 192.168.0.34:502, indicating sustained internal protocol activity rather than a single isolated connection. The case brief identifies 67 related NetWitness alerts in total, all tied to the same two IPs and the same destination service, while no username, host name, operating system, process creation, or authentication telemetry was available. The deep-dive context states that the event action was a preset single register / data push and that the source was labeled as a non-whitelisted Modbus source, but no endpoint evidence confirms a spawned process, privilege escalation, or any user-interactive execution on either host. The observable behavior in this case is therefore repeated internal Modbus communications between 192.168.0.19 and 192.168.0.34 on TCP/502 with no corroborating host telemetry to show who initiated the traffic or whether the activity was authorized.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial network activity and repeated internal connection attempts | NetWitness generated 67 alerts labeled 'Modbus Non-Whitelisted Source' for traffic from 192.168.0.19 to 192.168.0.34 over TCP/502, including connections 192.168.0.19:55179 -> 192.168.0.34:502 and 192.168.0.19:53728 -> 192.168.0.34:502. | Command and Control | Application Layer Protocol | T1071 |
| Observed industrial protocol write activity across the same internal session pattern | Deep-dive context identifies the event action as 'preset single register / data push' over Modbus between 192.168.0.19 and 192.168.0.34, indicating application-layer register manipulation rather than ordinary web or file traffic. | Impact | Data Manipulation | T1565.001 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **NOT_MET** | The case confirms source IP 192.168.0.19 and destination IP 192.168.0.34, with repeated internal Modbus/TCP sessions over destination port 502. Username, login details, computer name, and operating system are not available in the telemetry, so identity and endpoint context remain unconfirmed. |
| `step_2` | Was it horizontal or vertical | **NOT_MET** | The evidence shows host-to-host internal communication between 192.168.0.19 and 192.168.0.34, which is more consistent with lateral activity than privilege escalation. However, no authentication, process, or privilege telemetry is present, so horizontal versus vertical movement cannot be conclusively determined. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | No malicious process can be confirmed. The alert set is network-only, and the case brief explicitly notes that process fields were absent across all 67 alerts, leaving no endpoint evidence of process creation on the victim host. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | A process tree analysis cannot be performed because there are no process, parent-child, user, or host telemetry fields in the available data. No evidence supports privilege escalation, process-driven lateral movement, or data exfiltration from endpoint telemetry in this case. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary due to repeated unauthorized-looking internal Modbus communications on port 502 between two internal hosts. Containment should prioritize isolating the involved assets or segmenting the traffic path, preserving logs, and collecting endpoint/authentication telemetry to determine whether the activity was authorized or malicious. |

## Recommended Containment Actions
- Immediately segment or temporarily block Modbus/TCP traffic on port 502 between 192.168.0.19 and 192.168.0.34 at the nearest switch, firewall, or industrial security gateway until the traffic owner is identified.
- Place both 192.168.0.19 and 192.168.0.34 into a monitored containment VLAN or equivalent network quarantine to prevent continued internal protocol exchange while preserving reachability for IR collection.
- Preserve and export the full NetWitness event set for all 67 alerts, including raw packet metadata, timestamps, source/destination ports, and any protocol decoding fields, before any log rotation occurs.
- Collect endpoint telemetry from both hosts immediately: Sysmon Event IDs 1, 3, 5, 7, 11, 13, 22; Windows Security Event IDs 4624, 4625, 4648, 4672, 4688; and any EDR network/process logs covering the alert window.
- Validate whether 192.168.0.19 is an authorized industrial controller, engineering workstation, or automation host, and confirm whether the repeated Modbus writes to 192.168.0.34 align with an approved change window or maintenance activity.
- If either host is not expected to initiate Modbus writes, disable the interface or service generating the traffic and perform controlled packet capture to identify the specific Modbus function code, register target, and source application.
- Hunt for the same source IP, destination IP, or Modbus function pattern in other network sensors to determine whether the activity is isolated to one segment or recurring across the environment.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1791712160-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-10-11T09:49:20Z |
| `AUD-DP08-1791712160-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-10-11T09:49:20Z |
| `AUD-DP09-1791712160-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-10-11T09:49:20Z |
| `AUD-DP10-1791712160-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-10-11T09:49:20Z |
