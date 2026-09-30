# INVESTIGATION SUMMARY: INC-52970 (Incident-002)

**Final Severity:** High
*High severity is appropriate because the incident shows repeated suspicious outbound activity from an internal host, includes suspicious file/process artifacts, and has a rule classification of elevated risk with multiple related alerts. However, the available evidence does not confirm compromise, exfiltration, or privilege escalation, so Critical is not supported.*

**Confidence Level:** Medium
*Confidence is Medium because the network telemetry, filenames, and repeated alerting consistently support that something unusual occurred, but the record lacks endpoint process telemetry, logon context, hostname/OS identity, and any direct proof of malicious execution. The evidence is partially sufficient but still incomplete.*

## Investigative Workflow
- Reviewed the incident timeline and preserved all observed source/destination IPs, ports, and associated filenames from the alert record.
- Re-evaluated the playbook steps against the updated timeline and marked host identity, movement type, process spawning, and process-tree analysis as not evidenced.
- Assessed threat intelligence results for 8.8.8.8, 4.145.79.81, and 224.0.0.251 and noted that the available reputation data did not confirm malicious activity on its own.
- Determined that the evidence remains network-only and insufficient to confirm compromise or privilege escalation.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2025-07-15T09:38:52+00:00, NetWitness generated incident INC-52970 for internal host 192.168.10.200. The alert sequence showed repeated DNS, HTTP, and HTTPS activity from 192.168.10.200 toward public infrastructure including 8.8.8.8 and 4.145.79.81, along with multicast traffic to 224.0.0.251 on mDNS port 5353. The timeline also noted suspicious endpoint artifacts, including filenames authrootstl.cab and pR5k1Jb0=, but no decoded PowerShell payload, no confirmed malicious executable, and no process creation or parent-child lineage were present in the record. The network behavior was repeatedly described as outbound and suspicious, with one rule labeling it as lateral movement, but the raw telemetry showed only single-sided network flows and no internal host-to-host access, authenticated remote session, or privilege escalation evidence. The source trail admin2@192.168.20.14:50005 appeared in the metadata, but it was not tied to a verified user logon on the affected endpoint. Across the related alerts, the evidence consistently pointed to suspicious network communications from 192.168.10.200 without endpoint corroboration, making the activity unconfirmed for malware execution, lateral movement, or exfiltration.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial network discovery and multicast LAN activity | Internal host 192.168.10.200 generated traffic to 224.0.0.251 on UDP/5353, with repeated mDNS-style discovery behavior and no endpoint process telemetry. | Discovery | Network Service Discovery | T1046 |
| Outbound DNS and web communications to external infrastructure | Host 192.168.10.200 repeatedly connected to 8.8.8.8 over DNS and to 4.145.79.81:443 over HTTPS, with the timeline describing repeated DNS/HTTP/HTTPS activity and an outbound session. | Command and Control | Application Layer Protocol | T1071 |
| Suspicious external web egress to cloud-hosted destination | The alert set included outbound HTTPS activity from 192.168.10.200 to 4.145.79.81 and other public IPs, with the source trail admin2@192.168.20.14:50005 present in metadata but no host process lineage or authenticated remote session evidence on the victim endpoint. | Command and Control | Web Protocols | T1071.001 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **NOT_MET** | The incident data does not provide a confirmed username, login details, computer name, or operating system for the victim endpoint. The source IP is 192.168.10.200. The only user-like clue is the upstream/source trail admin2@192.168.20.14:50005, which appears to be an investigation/session reference rather than verified logon context on the affected host. |
| `step_2` | Was it horizontal or vertical | **NOT_MET** | Horizontal vs vertical movement cannot be confirmed from the timeline. The observable activity is outbound network traffic from 192.168.10.200 to public/Microsoft-related IPs and to 224.0.0.251, with no authenticated access to a second internal host, no peer-to-peer internal destination, and no logon trail that would support confirmed lateral or privilege-based movement. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | No malicious process spawn is evidenced. There is no process creation telemetry, parent-child chain, command line, hash, or endpoint execution artifact for 192.168.10.200 in the provided record. The alert is network-only, so process execution cannot be confirmed. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | A process tree cannot be analyzed because no endpoint process telemetry is present. There are no signs of privilege escalation, remote execution, service creation, or file/process activity in the evidence set. The available data only shows outbound network behavior, which is insufficient to validate escalation or exfiltration from process lineage. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary. The alert remains suspicious because of repeated outbound DNS/HTTPS activity and the presence of suspicious file/process artifacts, but compromise is not confirmed. Recommended containment is conservative and evidence-preserving: isolate 192.168.10.200 if risk tolerance requires, preserve volatile state, and collect endpoint, authentication, DNS, and network telemetry before any destructive action. |

## Recommended Containment Actions
- Isolate host 192.168.10.200 from the network using EDR network containment or NAC port shutdown until endpoint telemetry is collected and reviewed.
- Preserve volatile evidence on 192.168.10.200 immediately, including running processes, active connections, logged-on users, services, autoruns, and recent DNS cache.
- Collect Windows Security logs 4624, 4625, 4648, 4672, 4688, 4697, 7045, and 4103/4104 for the incident window on the affected endpoint and any associated domain controller.
- Export Sysmon Event IDs 1, 3, 7, 11, 12, 13, and 22 from the host to reconstruct process creation, network connections, file writes, registry changes, and DNS resolution.
- Hunt for the suspicious filenames authrootstl.cab and pR5k1Jb0= across EDR, file-share, proxy, and endpoint inventories to determine whether they were created, downloaded, or executed.
- Validate whether 224.0.0.251 traffic was benign mDNS/Bonjour discovery by comparing the host’s network behavior against baseline LAN discovery activity and DHCP/asset records.
- Quarantine and inspect any files or scripts associated with outbound connections to 4.145.79.81 and 8.8.8.8, and block the specific destination IPs only if they are confirmed in your environment as malicious infrastructure.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1790602970-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-09-28T13:42:50Z |
| `AUD-DP08-1790602970-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-09-28T13:42:50Z |
| `AUD-DP09-1790602970-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-09-28T13:42:50Z |
| `AUD-DP10-1790602970-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-09-28T13:42:50Z |
