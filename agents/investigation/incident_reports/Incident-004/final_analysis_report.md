# INVESTIGATION SUMMARY: INC-53020 (Incident-004)

**Final Severity:** High
*High is appropriate because the case contains a high-risk NetWitness endpoint alert involving internal host-to-host communication on an important internal asset, with suspicious activity credible enough to warrant investigation. However, the evidence is incomplete and does not confirm malware, privilege misuse, data exposure, repeated activity, or service impact, so the incident does not meet Critical. It is above Medium because the alert is high-risk and touches a business user/host with an internal IOC, but the available evidence remains partial.*

**Confidence Level:** Medium
*Confidence is Medium because the record provides a consistent high-risk NetWitness alert and a clear internal source and destination IP pair, but the case lacks destination port, protocol, attached alert details, process telemetry, and authenticated session data. The evidence is therefore partially sufficient, with no conflicting data but significant gaps preventing a high-confidence conclusion.*

## Investigative Workflow
- Reviewed the NetWitness high-risk alert metadata for INC-53020.
- Mapped the available telemetry to host 192.168.10.204 and destination 192.168.10.202.
- Validated that no destination port, protocol, or attached alert payload was available in the incident record.
- Checked the playbook steps for evidence of process creation, privilege escalation, or lateral movement; none was present.
- Determined that further investigation is required due to incomplete telemetry and unresolved suspicion.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2025-12-01T07:11:11+00:00, NetWitness generated a high-risk endpoint alert for internal host 192.168.10.204 associated with user and host name KELLYWANG. The available record shows a single internal network interaction from 192.168.10.204 to 192.168.10.202, but the case data does not include destination port, protocol, or an attached alert payload, so the activity cannot be tied to a confirmed login type, authenticated session, or specific service. The deep-dive metadata confirms the alert was first seen at 2025-12-01T06:16:40.811Z and last updated at 2025-12-01T07:11:11.142Z, but no endpoint process telemetry, command lines, parent-child process tree, hashes, or privilege-change evidence was available. As a result, the observable behavior in this case remains limited to suspicious internal host-to-host communication between 192.168.10.204 and 192.168.10.202, with no confirmed malicious process execution, no verified privilege escalation sequence, and no demonstrated lateral movement beyond the network connection itself.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial internal network activity | NetWitness high-risk alert on 2025-12-01T07:11:11+00:00 involving source IP 192.168.10.204 and destination IP 192.168.10.202 on internal network telemetry; host name associated with the source is KELLYWANG. | Lateral Movement | Internal Remote Services | T1021 |
| Suspicious host-to-host communication without port/protocol context | A single internal connection from 192.168.10.204 to 192.168.10.202 was observed, but the incident record lacks destination port, protocol, and authenticated session data needed to confirm the exact service used. | Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Unhandled unresolved suspicious network interaction | The alert remained high-risk with no supporting endpoint telemetry, process tree, or decoded command line, leaving the activity as an unresolved suspicious internal connection rather than a confirmed execution chain. | Command and Control | Application Layer Protocol | T1071 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Username identified as KELLYWANG. Source IP identified as 192.168.10.204. Login details are not fully available; the case references authenticated session context as missing. Computer name is KELLYWANG. Operating system was not provided in the available telemetry. |
| `step_2` | Was it horizontal or vertical | **NOT_MET** | Insufficient evidence to determine whether movement was horizontal or vertical. The timeline only shows internal host-to-host communication between 192.168.10.204 and 192.168.10.202, but lacks destination port, protocol, and authenticated session details needed to classify the movement. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | No process telemetry is present for the victim host. The timeline does not show process creation events, parent-child process chains, command lines, or hashes, so malicious process spawning cannot be confirmed. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | Process tree analysis could not be performed because the record lacks process creation telemetry, parent/child relationships, command lines, privilege changes, and endpoint evidence of lateral movement or exfiltration. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary. The case is only partially substantiated, so containment should begin with collection of the missing NetWitness alert attachment and endpoint telemetry, and host isolation should be considered if suspicious activity persists or additional evidence confirms malicious behavior. |

## Recommended Containment Actions
- Query EDR and NetWitness for the full alert attachment for 2025-12-01T06:16:40.811Z through 2025-12-01T07:11:11.142Z and preserve the raw event payload before any tuning or suppression.
- Collect process creation, command-line, parent-child tree, and hash telemetry for host 192.168.10.204 for at least the surrounding two-hour window, including Windows Security 4688, Sysmon Event ID 1, and PowerShell 4104 if enabled.
- Pull authentication records for user KELLYWANG and host 192.168.10.204, including logon type, source workstation, and any 4624/4625/4672 events correlated to the time window.
- If the same internal connection recurs or any suspicious process is confirmed, isolate 192.168.10.204 in EDR and block host-to-host communication to 192.168.10.202 pending analyst review.
- Hunt for any additional connections from 192.168.10.204 to adjacent internal assets in the 192.168.10.0/24 subnet and verify whether 192.168.10.202 is expected for the user or device role.
- Preserve volatile evidence on 192.168.10.204, including active network connections, logged-on sessions, and running processes, before remediation actions are taken.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1791639068-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-10-10T13:31:08Z |
| `AUD-DP08-1791639068-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-10-10T13:31:08Z |
| `AUD-DP09-1791639068-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-10-10T13:31:08Z |
| `AUD-DP10-1791639068-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-10-10T13:31:08Z |
