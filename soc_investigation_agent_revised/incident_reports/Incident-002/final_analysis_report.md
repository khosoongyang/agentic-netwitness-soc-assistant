# INVESTIGATION SUMMARY: INC-52970 (Incident-002)

**Final Severity:** High
*High is justified because the incident is a strongly suspected cyber event affecting an important internal endpoint with repeated suspicious outbound activity, IOC-bearing network connections, and multiple recurrence indicators. Per policy, suspected malicious activity against an important asset with repeated suspicious behavior fits High. It is not Critical because there is no confirmed compromise, outage, exfiltration, ransomware, or sensitive-data exposure in the available evidence.*

**Confidence Level:** Medium
*Medium confidence is appropriate because multiple timeline entries and threat-intel checks align on suspicious outbound network behavior, but endpoint/process evidence is missing and several key contextual fields remain unknown. Per the evidence sufficiency matrix, this is partially sufficient evidence with important gaps, so the conclusion is supported but not definitive.*

## Investigative Workflow
- Reviewed the incident timeline and prior playbook execution trace.
- Correlated all available network indicators, including 192.168.10.200, 4.145.79.81, 8.8.8.8, 34.107.243.93, and multicast 224.0.0.251.
- Assessed enrichment results from AbuseIPDB, AlienVault OTX, and VirusTotal.
- Reviewed the provided triage deep-dive findings for host identity, movement type, process spawn, and process-tree gaps.
- Re-evaluated the playbook steps against the updated incident context.

## Technical Chronology & MITRE ATT&CK TTP Mapping

2025-07-15T09:38:52+00:00: NetWitness raised 'Chu Wen - Lateral Move Detected' for internal host 192.168.10.200. The alert showed repeated outbound DNS/HTTPS activity and suspicious file artifacts, including filename indicators authrootstl.cab and pR5k1Jb0=, with destination 8.8.8.8 and a Microsoft-related hostname ctldl.windowsupdate.com. Threat intel on 8.8.8.8 was not malicious, and no decodable PowerShell was found. 2025-07-15T09:46:25+00:00: Additional alerts for 192.168.10.205 reported repeated outbound HTTPS/DNS to 34.107.243.93 (googleusercontent.com), with source trail admin2@192.168.20.14:50005 and no endpoint/process evidence; these were assessed as suspicious outbound remote connectivity / possible C2 rather than proven lateral movement. 2025-07-15T09:49:52+00:00 and 2025-07-15T10:00:56+00:00: Further alerts for 192.168.10.200 showed outbound HTTPS to 4.145.79.81 (Microsoft Azure, Singapore) plus additional DNS/multicast traffic to 8.8.8.8 and 224.0.0.251:5353. OTX reported limited related pulses for 4.145.79.81, while VirusTotal showed no malicious verdict. No Windows Security logs, Sysmon process creation, hostname, OS, or user logon data were present. Across the timeline, the recurring pattern is internal host 192.168.10.200 generating suspicious outbound network connections to external cloud/DNS infrastructure and multicast mDNS traffic, but without host-side telemetry, malicious process execution, privilege escalation, lateral movement, or exfiltration cannot be confirmed.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial suspicious network discovery / local multicast activity | 192.168.10.200 sent UDP/mDNS traffic to 224.0.0.251:5353; source MAC a8:1e:84:9b:3e:9d and multicast destination MAC 01:00:5e:00:00:fb were observed; no endpoint telemetry was present. | Discovery | Multicast DNS | T1046 |
| Suspicious outbound DNS/HTTP(S) egress to public infrastructure | 192.168.10.200 generated outbound DNS/HTTPS activity to 8.8.8.8 and 4.145.79.81:443, with related destinations including 34.107.243.93 and 52.123.129.14; hostname indicators included ctldl.windowsupdate.com, googleusercontent.com, and Microsoft/Azure-related infrastructure. | Command and Control | Application Layer Protocol | T1071 |
| Web-based outbound communication over HTTPS | Traffic from 192.168.10.200 to 4.145.79.81:443 (Microsoft Azure, Singapore) and 34.107.243.93:443 (Google Cloud / googleusercontent.com) was observed with no endpoint process context and small payloads. | Command and Control | Web Protocols | T1071.001 |
| DNS-based communication observed in the alert set | Repeated DNS activity involved 8.8.8.8:53 and mDNS to 224.0.0.251:5353 from 192.168.10.200, with no decodable PowerShell or file-hash evidence. | Command and Control | Application Layer Protocol: DNS | T1071.004 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **NOT_MET** | The timeline does not provide a confirmed victim username, login details, computer name, or operating system. The only confirmed victim asset is internal host 192.168.10.200. The source trail 'admin2@192.168.20.14:50005' appears to be investigation/session context rather than confirmed endpoint user identity. |
| `step_2` | Was it horizontal or vertical | **NOT_MET** | The evidence does not prove either horizontal or vertical movement. The alert label says 'Lateral Move Detected,' but the concrete telemetry is outbound network activity from 192.168.10.200 to external destinations including 4.145.79.81:443 (Microsoft Azure) and 8.8.8.8, plus DNS/mDNS traffic. No internal peer host, credentialed remote session, or privilege-level transition is shown. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | No process creation telemetry is present. There is no process name, PID, command line, parent-child chain, hash, or Windows/Sysmon process event to confirm a malicious process on 192.168.10.200. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | A process tree cannot be reconstructed from the provided evidence because endpoint telemetry is missing. There is no service creation, privilege escalation artifact, spawned shell, or exfiltration process chain. The observable behavior is limited to suspicious outbound connectivity and DNS/mDNS traffic. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is required. The activity is suspicious and high-priority but remains unconfirmed due to lack of endpoint context. Recommended response is conservative containment: isolate or restrict 192.168.10.200 if additional host-side evidence confirms malicious behavior, preserve volatile evidence, and collect endpoint logs and process telemetry before remediation. |

## Recommended Containment Actions
- Immediately place 192.168.10.200 into a monitored network containment VLAN or quarantine group while preserving access for forensic acquisition.
- Block outbound connections from 192.168.10.200 to 4.145.79.81:443, 34.107.243.93:443, 8.8.8.8:53, and any other observed external destinations until host telemetry validates them as benign.
- Collect volatile endpoint evidence from 192.168.10.200 before remediation: running processes, active network connections, logged-on users, scheduled tasks, services, autoruns, and DNS cache.
- Pull Windows Security logs and EDR telemetry for 192.168.10.200 covering the alert window, specifically Event IDs 4624, 4625, 4648, 4672, 4688, 7045, and Sysmon 1/3/7/11/22.
- Search the host for the extracted artifacts 'authrootstl.cab' and 'pR5k1Jb0=' and preserve any matching files, hashes, and parent process lineage.
- Review proxy, DNS, and TLS/SNI logs for 192.168.10.200 to determine whether the HTTPS sessions to Microsoft/Azure and Google-hosted infrastructure were benign updates or command-and-control traffic.
- If any spawned shell, unusual service, scheduled task, or credentialed remote session is discovered, escalate to full host isolation and reset credentials associated with the affected account(s).
- Hunt laterally across the subnet for the same destination IPs, multicast mDNS behavior, and the same source-trail pattern to determine whether this is isolated or part of broader compromise.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1785258894-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-07-28T17:14:54Z |
| `AUD-DP08-1785258894-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-07-28T17:14:54Z |
| `AUD-DP09-1785258894-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-07-28T17:14:54Z |
| `AUD-DP10-1785258894-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-07-28T17:14:54Z |
