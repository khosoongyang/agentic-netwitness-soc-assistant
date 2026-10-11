# INVESTIGATION SUMMARY: INC-52813 (Incident-004)

**Final Severity:** Medium
*Medium is appropriate because the case contains suspicious network activity and a high-risk alert burst, but the available evidence does not confirm compromise, privileged access, malware execution, sensitive data exposure, or service impact. Severity-reduction factors are strong: no process telemetry, no user context, no observed outage, and the visible destinations and filenames are consistent with Microsoft update/connectivity behavior. Escalation factors are limited to repeated network activity and a rule aligned to lateral movement, but the impact remains unconfirmed.*

**Confidence Level:** Medium
*Medium confidence is warranted because multiple sources align on the same network behavior pattern: NetWitness alerts, domain/IP metadata, and the deep-dive review all point to Microsoft update/connectivity traffic and the absence of process evidence. Confidence is not high because critical fields are missing, including username, hostname, operating system, command line, and endpoint process telemetry, leaving the conclusion partially inferred rather than fully proven.*

## Investigative Workflow
- Reviewed the NetWitness alert burst for source host 192.168.10.207 and extracted observed destination IPs, ports, and related Microsoft update/connectivity domains.
- Checked the case telemetry for username, host name, operating system, process creation, command line, and process ancestry details; none were present.
- Compared the alert content against available historical/correlated cases for pattern similarity and false-positive indicators.
- Assessed the case for signs of malicious execution, lateral movement, and data exfiltration; none were confirmed from the provided evidence.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2025-07-14 at 11:02:49 UTC, NetWitness generated a high-risk alert sequence titled "Chu Wen - Lateral Move Detected" for source host 192.168.10.207. The earliest visible events show repeated DNS traffic from 192.168.10.207 to 8.8.8.8:53 from multiple source ports, alongside outbound HTTPS sessions to Microsoft-related infrastructure including 52.123.129.14:443 and 4.145.79.81:443. Additional alerts in the same burst show multicast name-resolution traffic from 192.168.10.207 to 224.0.0.252:5355 and 224.0.0.251:5353, consistent with local network discovery and service resolution behavior. The incident metadata associates the traffic with Windows update and connectivity domains such as ctldl.windowsupdate.com, download.windowsupdate.com, www.msftconnecttest.com, msedge.f.dl.delivery.mp.microsoft.com, msedge.b.tlu.dl.delivery.mp.microsoft.com, and adl.windows.com, with related files observed in the alert metadata including disallowedcertstl.cab, connecttest.txt, authrootstl.cab, pieceshash, and 43584905_a7b4453f15ca0abbac4b199cc68a19b73cc63bc9.cab. The telemetry does not include username, hostname, operating system, command line, or process creation data, and no malicious process execution, privilege escalation, or lateral movement was directly observed in the available evidence. The case therefore documents a burst of update/connectivity-related network activity from 192.168.10.207 with no confirmed host compromise or downstream malicious execution.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial network burst from source host | On 2025-07-14T11:02:49Z, 192.168.10.207 generated repeated DNS queries to 8.8.8.8:53 from multiple source ports while the NetWitness rule 'Chu Wen - Lateral Move Detected' fired. | Command and Control | Non-Application Layer Protocol | T1095 |
| Follow-on connectivity and update infrastructure access | The same source host 192.168.10.207 established outbound HTTPS sessions to Microsoft-related infrastructure including 52.123.129.14:443, 4.145.79.81:443, and 52.231.186.36:443, with associated domains such as ctldl.windowsupdate.com, download.windowsupdate.com, msedge.f.dl.delivery.mp.microsoft.com, and adl.windows.com. | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Local network discovery and name-resolution activity | Alerts from 192.168.10.207 show multicast traffic to 224.0.0.252:5355 and 224.0.0.251:5353 during the same burst, matching local name-resolution/discovery behavior. | Discovery | Multicast DNS | T1046 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **NOT_MET** | Primary source IP identified as 192.168.10.207, with 192.168.20.14 appearing as an additional heuristic source IP in supporting metadata. No username, login details, hostname/computer name, or operating system are present in the provided telemetry. |
| `step_2` | Was it horizontal or vertical | **NOT_MET** | The evidence does not establish horizontal versus vertical movement. The alerting behavior is network-rule based and lacks authentication, host identity, or process context needed to determine movement direction. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | No malicious process execution is evidenced. The case explicitly states process fields were absent across the alerts, and there is no process creation, command line, or endpoint telemetry confirming execution on 192.168.10.207. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | A process tree cannot be assessed because there is no process telemetry, no parent-child ancestry, no PowerShell logs, and no spawned child processes available in the record. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is warranted because key host and process details are missing, but the current evidence most strongly supports benign or false-positive Microsoft update/connectivity traffic rather than confirmed compromise. Containment should be conditional and evidence-driven. |

## Recommended Containment Actions
- Escalate the case to the SOC Analyst or Incident Response Team.
- Do not immediately shut down the affected computer at IP 192.168.10.207.
- Disconnect the infected computer at IP 192.168.10.207 from the network and storage devices to limit spread.
- Validate host identity and recent activity for 192.168.10.207 using EDR and endpoint telemetry, then confirm whether the observed traffic aligns with Windows Update, certificate list retrieval, or connectivity-check activity.
- Query Windows Security logs and EDR process-creation telemetry on 192.168.10.207 for the alert window (2025-07-14 11:02:49 UTC onward) to confirm whether any suspicious child processes, PowerShell activity, or script execution occurred.
- If the endpoint generates any additional non-update network indicators, immediately isolate 192.168.10.207 from the network segment pending analyst review.
- Block or restrict outbound access only to newly observed suspicious destinations not associated with Microsoft update/connectivity infrastructure; do not disrupt known update domains until benignity is verified.
- Collect a full memory and disk triage package from 192.168.10.207 if endpoint telemetry later shows process execution or authentication anomalies, preserving evidence before remediation.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1791723737-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-10-11T13:02:17Z |
| `AUD-DP08-1791723737-2` | **DP-08** | Appendix A | Severity classification: Medium | *Pass* | `Investigate` | Yes | 2026-10-11T13:02:17Z |
| `AUD-DP09-1791723737-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-10-11T13:02:17Z |
| `AUD-DP10-1791723737-4` | **DP-10/DP-11** | Appendix G | Severity: Medium, Confidence: Medium, Ransomware: True, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-10-11T13:02:17Z |
