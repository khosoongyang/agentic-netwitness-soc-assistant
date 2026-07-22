# INVESTIGATION SUMMARY: INC-6133 (Incident-003)

**Final Severity:** High
*Programmatic baseline triage for standalone alert.*

**Confidence Level:** High
*Heuristic lookup with no temporal correlation window overlaps.*

## Investigative Workflow
- Initial triage
- Indicator search
- Playbook heuristic validation

## Technical Chronology & MITRE ATT&CK TTP Mapping

1. Multiple authentication attempts were initiated from source IP 5.1.57.22 targeting the user account 'sally' on bnpparibasgroup.com. 2. The login attempts resulted in failures, indicating a brute-force attack. 3. The suspicious authentication traffic was detected and flagged at the perimeter firewall.

| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |
| --- | --- | --- | --- | --- |
| Brute Force Login Attempt | User: sally, Source IP: 5.1.57.22, Destination IP: 155.140.254.100, Destination Domain: bnpparibasgroup.com, Authentication Outcome: Failure, Risk Score: 70 | Credential Access | Brute Force | T1110 |

## Playbook Execution Trace
| Step ID | Instruction | Status | Findings |
| --- | --- | --- | --- |
| `step_1` | Identify 1. datetime, 2. Email address of sender/receiver, 3 IP address of sender/receiver and 4. subject of email. | **NOT_MET** | Timeline lacks necessary data to satisfy step. |
| `step_2` | Does phishing attempt contain a URL or attachment? | **NOT_MET** | Timeline lacks necessary data to satisfy step. |
| `step_3` | Was any malicious process spawned on the victim's machine? | **NOT_MET** | Timeline lacks necessary data to satisfy step. |
| `step_4` | Analyze the process tree for signs of malicious activity, such as privilege escalation, lateral movement, or data exfiltration. | **NOT_MET** | Timeline lacks necessary data to satisfy step. |
| `step_5` | Based on the analysis, determine if further investigation is necessary and the containment steps | **NOT_MET** | Timeline lacks necessary data to satisfy step. |

## Recommended Containment Actions
- Block all traffic from the external attacker IP 5.1.57.22 at the perimeter firewall immediately.
- Reset the password for user account 'sally' and enforce multi-factor authentication (MFA).
- Review login logs to ensure no attempts from 5.1.57.22 succeeded.

## Appendix M: Policy-Based Compliance Audit Log

| Audit ID | Decision Point | Policy Reference | Input Summary | Result | Decision Made | Human Review? | Timestamp |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUD-DP07-1784713776-1` | **DP-07** | Appendix C | Critical System: False, Sensitive Data: False | *Pass* | `Investigate` | Yes | 2026-07-22T09:49:36Z |
| `AUD-DP08-1784713776-2` | **DP-08** | Appendix A | Severity classification: High | *Warning* | `Escalate` | Yes | 2026-07-22T09:49:36Z |
| `AUD-DP09-1784713776-3` | **DP-09** | Appendix F | Confidence level: High | *Pass* | `Investigate` | Yes | 2026-07-22T09:49:36Z |
| `AUD-DP10-1784713776-4` | **DP-10/DP-11** | Appendix G | Severity: High, Confidence: High, Ransomware: False, Guest OS: False | *Fail* | `Escalate` | Yes | 2026-07-22T09:49:36Z |
