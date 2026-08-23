# Phishing Response Playbook

> Source converted from uploaded phishing playbook YAML for this Reporting Agent version.
> The Reporting Agent uses this playbook only as reporting context. It does not investigate or decide containment.

```yaml
name: Phishing Triage Playbook
version: 1.1

steps:
  step_1:
    instructions: Analyze the given telemetry and identify who all the victim endpoints are and group their characteristics (IP, Host, process trees).
    routing: step_2

  step_2:
    instructions: Does the phishing attempt contain a URL or attachment?
    routing: step_3

  step_3:
    instructions: Has the URL or attachment been clicked or opened by the user?
    routing: step_4

  step_4:
    instructions: Was a process spawned as a result of the URL or attachment being clicked or opened?
    routing: step_5

  step_5:
    instructions: If a process was spawned, analyze the process tree for any suspicious activity (e.g. parent-child relationships, command line arguments).
    routing: step_6

  step_6:
    instructions: Based on the analysis, determine if the phishing attempt was successful and if any further containment or investigation steps are necessary.
    routing: complete
```

## Reporting Notes

For phishing incidents, document sender, recipient, subject, attachment names, attachment hashes, URLs, domains, delivery status, user interaction, email gateway verdict, endpoint evidence, threat intelligence reputation, similar recipients, evidence gaps, containment and approval status.

## Human Review Requirement

Missing facts must be listed as evidence gaps rather than guessed.
