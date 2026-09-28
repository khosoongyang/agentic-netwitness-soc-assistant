# Ransomware Response Playbook

> Reporting context playbook for ransomware, WannaCry, malware/ransomware, or ransomware-related execution cases.
> The Reporting Agent uses this file for report guidance only. It does not decide or execute containment.

## Reporting Objectives

- Preserve the distinction between suspected ransomware execution, confirmed encryption impact, and unverified business impact.
- Clearly identify affected hosts, users, file/process indicators, network indicators, and MITRE ATT&CK techniques from supplied evidence.
- Document containment approval and containment execution separately.
- Keep missing telemetry visible as evidence gaps rather than inferring spread, encryption, or recovery status.

## Evidence To Validate

- Host identity, source IP, logged-on user, process name, process path, command line, parent process, file hash, and first observed time.
- Ransomware family indicators such as WannaCry, `mssecsvc.exe`, service creation, SMB activity, kill-switch domain lookups, or encryption behaviour.
- Network indicators including destination IPs, domains, URLs, ports, protocols, DNS, proxy, firewall, and NetWitness evidence references.
- Impact evidence including encrypted files, ransom notes, service disruption, lateral movement, recovery activity, and backup integrity.
- Containment evidence including isolation approval, isolation execution time, host network state, EDR action records, and analyst notes.

## Report Wording Guidance

- Use "ransomware-related activity" when execution indicators exist but encryption impact is not confirmed.
- Use "confirmed ransomware impact" only when supplied evidence shows encryption, ransom notes, or operational disruption.
- Use "Not Contained" when containment execution is not evidenced, even if report generation was approved.
- Refer to unresolved telemetry once in the Evidence Gaps section and cross-reference it later.

## Recommended Reporting Actions

- Recommend immediate SOC analyst validation of affected host isolation when ransomware execution is suspected.
- Recommend IOC blocking, host triage, memory/disk evidence preservation, and backup/recovery validation when supported by local policy.
- Escalate to incident response leadership for Critical ransomware cases where production impact, spread, or sensitive-data exposure is plausible but unconfirmed.
