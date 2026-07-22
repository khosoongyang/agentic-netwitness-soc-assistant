# INVESTIGATION SUMMARY: INC-6142 (Incident-005)

**Final Severity:** High
*Programmatic baseline triage for standalone alert.*

**Confidence Level:** High
*Heuristic lookup with no temporal correlation window overlaps.*

## Investigative Workflow
- Initial triage
- Indicator search
- Playbook heuristic validation

## Technical Chronology & MITRE ATT&CK TTP Mapping

1. Host at IP 10.100.20.121 performed multiple anomalous DNS queries for lookalike/phishing domain 'bankofmoney.com'. 2. The query lookup triggered a reputation alert for potential command-and-control communication.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Initial Detection of Anomalous DNS Activity | Timestamp: 2026-01-31T02:30:46.024Z; Source IP: 10.100.20.121; Destination IP: 10.100.10.3; Queried Domain: bankofmoney.com; Source Port: 53; Destination Port: 64659; Incident ID: INC-6142; Risk Score: 70; Severity: High. | Command and Control | Application Layer Protocol: DNS | T1071.004 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. datetime, 2. Email address of sender/receiver, 3 IP address of sender/receiver and 4. subject of email. | **MET** | Identified phishing elements in alert doc: Incident INC-6142 details are as follows: The classification alert type is Multiple DNS Response on  |
| `step_2` | Does phishing attempt contain a URL or attachment? | **MET** | Identified phishing elements in alert doc: Incident INC-6142 details are as follows: The classification alert type is Multiple DNS Response on  |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | Timeline lacks necessary data to satisfy step. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | Timeline lacks necessary data to satisfy step. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **NOT_MET** | Timeline lacks necessary data to satisfy step. |

## Recommended Containment Actions
- Isolate the host at IP 10.100.20.121 from the local network by disabling its network interface to prevent command-and-control communications.
- Block resolution of the lookalike domain 'bankofmoney.com' on all internal DNS servers.
- Investigate active processes on host at 10.100.20.121 that initiated the DNS requests for 'bankofmoney.com'.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1784713773-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-07-22T09:49:33Z |
| `AUD-DP08-1784713773-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-07-22T09:49:33Z |
| `AUD-DP09-1784713773-3` | **DP-09** | Appendix F | Confidence level: High | *Pass* | `Investigate` | Yes | 2026-07-22T09:49:33Z |
| `AUD-DP10-1784713773-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: High, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-07-22T09:49:33Z |
