# INVESTIGATION SUMMARY: INC-52970 (Incident-002)

**Final Severity:** High
*High is appropriate because the alert is a strongly suspected cyber event affecting an important internal asset, with repeated suspicious network activity, potential lateral-movement labeling, and suspicious artifacts. However, the evidence remains network-only with no confirmed malicious execution, data exposure, or service outage, so Critical is not supported.*

**Confidence Level:** Medium
*Medium confidence is warranted because multiple sources align on suspicious network activity and recurring IOCs, but key evidence gaps remain: no endpoint process telemetry, no hostname/OS confirmation, no decoded PowerShell, and no file hash. The conclusion is therefore plausible but not fully substantiated.*

## Investigative Workflow
- Reviewed the ESA alert timeline and extracted network IOCs, file indicators, and classification metadata.
- Checked threat-intelligence enrichment for destination IPs and domains (AbuseIPDB, AlienVault OTX, VirusTotal).
- Verified PowerShell enrichment status and confirmed no decodable EncodedCommand content was present.
- Compared related timeline entries to assess recurrence and whether the activity was isolated or spreading.
- Performed policy-based severity and impact assessment using the available network-only evidence.

## Technical Chronology & MITRE ATT&CK TTP Mapping

2025-07-15T09:38:52+00:00: Incident INC-52970 generated a medium-severity ESA alert for internal host 192.168.10.200. The alert labeled 'High Risk Alerts: ESA for 192.168.10.200' and 'Chu Wen - Lateral Move Detected' reported suspicious network activity / policy violations with repeated DNS/HTTP/HTTPS activity and suspicious file/process artifacts, but no decoded PowerShell and no confirmed malicious execution. Recorded IOCs included source IP 192.168.10.200, destination IP 8.8.8.8, destination domain starhub.net.sg, source hostname ctldl.windowsupdate.com, and file names authrootstl.cab and pR5k1Jb0=. The network data showed single-sided UDP DNS activity to 8.8.8.8:53 and additional outbound contacts to public/Microsoft-related infrastructure. Threat-intel enrichment for 8.8.8.8 returned benign/low-risk results (AbuseIPDB abuse score 0; VirusTotal 0 malicious, 54 harmless, 37 undetected), and no usable file hash or decoded PowerShell was available. The triage deep dive identified the main gap as lack of endpoint telemetry: no hostname, OS, process creation, process tree, or authentication logs were present to prove privilege escalation, spawned malware, or true lateral movement. A second related NetWitness case (INC-52975) at 2025-07-15T09:49:52+00:00 showed the same source host 192.168.10.200 making outbound TCP/443 connections to 4.145.79.81 (Microsoft/Azure) with additional DNS/multicast traffic; OTX reported 2 related pulses for 4.145.79.81, but no endpoint/process evidence or PowerShell indicators were present. A third related case (INC-52982) at 2025-07-15T10:04:13+00:00 showed 192.168.1.64 sending single-sided UDP/mDNS traffic to 224.0.0.251:5353, again without process or host telemetry. Overall chronology: suspicious network alert on 192.168.10.200 -> repeated DNS/HTTP/HTTPS to public and Microsoft-related destinations -> suspicious filenames observed (authrootstl.cab, pR5k1Jb0=) -> no decoded PowerShell or file hash -> threat-intel largely benign/low-confidence -> related network-only alerts at 09:49:52 and 10:04:13 reinforced the pattern of suspicious network behavior but did not confirm compromise or process-level malicious activity.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial network anomaly on internal host | 192.168.10.200 generated repeated DNS/HTTP/HTTPS activity; recorded DNS destination 8.8.8.8:53 and external domain starhub.net.sg; suspicious artifacts authrootstl.cab and pR5k1Jb0= were noted. | Command and Control | Application Layer Protocol | T1071 |
| DNS-based communication observed | Source host 192.168.10.200 communicated with 8.8.8.8 over UDP/53; the alert itself referenced DNS activity and T1071.004. | Command and Control | Application Layer Protocol: DNS | T1071.004 |
| Potential staged retrieval or download artifact | Endpoint indicators included authrootstl.cab and hostname ctldl.windowsupdate.com, suggesting possible remote file retrieval or masqueraded Windows-related content, though no hash or execution was confirmed. | Command and Control | Ingress Tool Transfer | T1105 |
| Related outbound HTTPS activity to cloud infrastructure | Follow-on alert INC-52975 showed 192.168.10.200 connecting to 4.145.79.81:443 with additional DNS/multicast traffic and no endpoint telemetry. | Command and Control | Application Layer Protocol | T1071 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Source IP is 192.168.10.200. A user-like string 'admin2' appears only in the source trail 'admin2@192.168.20.14:50005' and is not confirmed as the victim user. Login details are not directly available; the session appears authenticated on port 50005 but the exact logon type/protocol is unknown. Computer name is not present. Operating system is not present. |
| `step_2` | Was it horizontal or vertical | **MET** | More consistent with horizontal movement than vertical, but not proven. The sensor labeled the event as lateral movement, yet the concrete traffic is internal host 192.168.10.200 making outbound connections to public/Internet destinations including 4.145.79.81:443 and 8.8.8.8. There is no evidence of privilege escalation or access to a higher-privileged host, so vertical movement is not supported. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | No malicious process spawn is evidenced. The incident data is network-only and includes no process name, PID, parent/child lineage, command line, executable path, or host-side telemetry confirming a spawned process on 192.168.10.200. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | A process tree cannot be analyzed from the available evidence. There is no endpoint process telemetry, no parent-child chain, and no host actions proving privilege escalation, lateral tooling, or exfiltration. The alert remains network-centric and unconfirmed from the host perspective. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation is necessary because endpoint/process confirmation is missing and the alert remains unconfirmed. Recommended containment is conservative: isolate 192.168.10.200 if risk tolerance requires it, preserve volatile evidence, and collect endpoint telemetry, authentication logs, and process creation data before deciding on remediation. |

## Recommended Containment Actions
- Immediately query EDR for host identity, logged-on users, process tree, and network connections on 192.168.10.200 and preserve the results before any remediation.
- If the host is still active and business impact permits, place 192.168.10.200 into network isolation/quarantine at the EDR level while retaining administrative access for evidence collection.
- Collect volatile evidence from 192.168.10.200: running processes, open sockets, DNS cache, autoruns, recent logons, and recent command history.
- Pull Windows Security logs and Sysmon from 192.168.10.200 for Event IDs 4624, 4648, 4688, 4672, 4697, 7045, 4103, 4104, and Sysmon 1/3/7/11/22 around 2025-07-15T09:00Z to 2025-07-15T10:10Z.
- Block or monitor the observed outbound destinations and indicators at the DNS/proxy/EDR layer: 8.8.8.8, 4.145.79.81, ctldl.windowsupdate.com, starhub.net.sg, authrootstl.cab, and pR5k1Jb0= pending validation.
- Search for the same source host behavior across the environment: repeated DNS to 8.8.8.8, outbound TCP/443 to Microsoft/Azure ranges, and multicast/mDNS traffic to 224.0.0.251:5353.
- If authentication telemetry shows an unexpected admin2 session or explicit credential use, reset affected credentials, invalidate active sessions, and review remote access paths from 192.168.20.14.
- Escalate to full incident response if host telemetry confirms spawned processes, remote execution, or internal host-to-host movement.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1785253517-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-07-28T15:45:17Z |
| `AUD-DP08-1785253517-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-07-28T15:45:17Z |
| `AUD-DP09-1785253517-3` | **DP-09** | Appendix F | Confidence level: Medium | *Warning* | `Escalate` | Yes | 2026-07-28T15:45:17Z |
| `AUD-DP10-1785253517-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: Medium, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-07-28T15:45:17Z |
