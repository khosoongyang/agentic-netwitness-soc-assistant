# Lab replay cases (`label.source = lab_ground_truth`)

Case files written by `scripts/wazuh_alert_to_incident.py` from alerts exported
from YOUR isolated Wazuh lab after running Atomic Red Team tests. The label is
ground truth by construction: you ran the technique yourself, on a lab VM, at a
known time.

`scripts/eval_triage.py` picks these up automatically (`tests/triage_eval/lab/*.json`).
A file with a `canary.role = "malicious"` block is a canary: if it is ever closed as
`false_positive` or `benign_expected`, the evaluation exits with code 1.

See `docs/triage-evaluation.md`, section "Canaries in your Wazuh lab", for the full
procedure and the safety rules (lab VMs only, snapshot first, never on corporate or
production machines).
