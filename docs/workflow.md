# Aegis workflow

How `workflow/engine.py` (orchestration) and `workflow/state_store.py` (the
durable state machine, one row per incident in `soc_db/soc_incidents.db`)
actually behave. Every mechanism below is quoted or paraphrased from the
functions' own docstrings, not inferred - if this file and the code
disagree, the code is right.

## Stage order

```
parsing -> triage -[approval]-> threat_intel -> investigation -[approval]-> reporting -[approval]
```

`parsing` and `triage` run together as one unit, kicked off by `start_run()`
- there is no separate "start parsing" action. `threat_intel` and
`investigation` are always advanced by the durable resume path once their
upstream approval lands, never re-triggered manually.

## Run IDs and attempts

- **Run ID**: `{incident_id}@{timestamp}-{6 hex chars}`, generated fresh by
  `start_run()`. A run is the top-level unit of "one pass through the
  pipeline for this incident."
- **Attempt**: each of the four post-parsing stages (`triage_attempt`,
  `threat_intel_attempt`, `investigation_attempt`, `reporting_attempt`) has
  its own counter, starting at 1 and incremented only by `rerun_stage()` -
  never by `claim_stage()`, which only *reads* the current attempt to stamp
  it on whatever result gets persisted. This is what lets a rerun's result
  be told apart from the original attempt's.

## Stage claims and leases

Before a stage's worker function runs, it calls `claim_stage()`, which
atomically (single transaction) requires: the caller's `run_id` matches the
row's current `run_id`, the stage's status column equals the expected
value, **and** no unexpired lease is already held by another worker - then
writes a fresh `worker_id`, stamps `worker_lease_expires_at = now + 45s`,
and logs a `stage_started` activity row. Checking status alone isn't
enough (two workers could both observe it true before either writes) -
the unexpired-lease check closes that race.

A running worker renews its lease every 15s (`_HEARTBEAT_RENEW_SECONDS`)
while it's alive; if a worker dies without releasing its claim, the lease
simply expires after 45s (`_LEASE_DURATION_SECONDS`) and a later
claim attempt succeeds again - no manual unstick needed.

Investigation additionally acquires a **global workspace lock**
(`acquire_global_lock`, `"investigation_workspace"`) before it starts,
because the investigation subprocess shares one on-disk
`triaged_alerts/`/`incident_reports/` queue across every case - only one
investigation may run at a time, repository-wide, with bounded backoff
while waiting rather than an indefinite hang.

## Stale-write rejection

Every simple status/result setter (`set_parsing_status`,
`save_triage_result`, `set_worker_progress_note`, ...) is built on
`_guarded_update()`, which raises `StaleWriteError` if the caller's
`run_id` no longer matches the row's *current* `run_id`. This is what
stops a slow or abandoned background write - from a run a rerun already
superseded - from corrupting the newer run's state.

## Approval / rejection / rerun

Every approve/reject/rerun/retry transition goes through
`_atomic_stage_transition()` (or `rerun_stage()`/`retry_threat_intel()`/
`begin_stage()`, which use the same pattern), which requires the row to be
in the **exact** state the action expects - not already approved/rejected
by someone else, not superseded by a newer run, upstream stage actually in
the required state. A double-click or two analysts racing on the same
action can only have one succeed; the other gets `ApprovalConflictError`
with a message showing both what was expected and what the row actually
held. This is the whole system's compare-and-swap primitive - duplicate
approvals are structurally prevented, not just discouraged by the UI.

Rejecting `triage` or `investigation` records the rejection in approval
history and returns the case to analyst review rather than silently
retrying. `reporting` rejection works the same way but at the section
level as well as the whole-report level (see **Report approval** below).

**Downstream invalidation**: rerunning an earlier stage invalidates
whatever downstream results existed for the prior attempt, since they were
computed from data the rerun is about to replace - the (now-orphaned)
downstream result stays in history but is no longer the "current" one a
fresh continuation would build on.

## Evidence-gap handling

Investigation can finish in a `completed_with_evidence_gaps` state instead
of a clean pass - meaning it found usable findings but is missing specific
telemetry. This does **not** silently block Reporting; the reporting
subprocess's own gate (`agents/reporting/backend/reporting_context_resolver.py`,
via `ticket_workflow.is_investigation_usable_for_reporting()`) decides
whether the investigation result is *usable* for reporting despite the
gaps, producing a `reporting_mode: "with_limitations"` report rather than
blocking outright when it is.

## Restart / recovery

Because every write is guarded by `run_id` matching and every claim is
lease-based, a killed/restarted process (crashed worker, server restart
mid-stage) self-heals: the stale lease expires within 45s, and the next
claim attempt for that `(incident_id, run_id, stage)` succeeds again. There
is no separate "resume" state to manage by hand - `POST /api/cases/<id>/workflow/resume`
just re-triggers the durable claim path, which either finds a claimable
stage or reports that one is already legitimately in flight.

## Report approval and integrity

- Each report section (`executive_summary`, `technical_findings`,
  `soc_analyst_review`, `final_incident_report`) can be individually
  edited (draft state) and confirmed.
- `agents/reporting/reporting_approval.py` re-verifies a report candidate's
  identity/hash **on every download**, not just at confirmation time - a
  download for the wrong case or the wrong attempt is rejected, not served.
- **Report-attempt tracking** mirrors the stage-attempt mechanism above:
  every reporting rerun gets a fresh `report_set_id`
  (`reporting_attempt_dir()`), so a stale draft from a prior attempt can
  never be confirmed against a newer attempt's manifest.

## Known test gaps

Three pre-existing test failures (unchanged since before this migration
began, not introduced by it):

- `test_evidence_gap_branch_and_reporting_wrapper.py` / `test_merged_context`
  / `test_context_and_templates` / `test_adapter_success_wrapper` (one of
  the original four was removed in Phase 9 after confirming it tested only
  dead donor-application code, not Aegis's real evidence-gap handling
  described above) - the remaining three are stale reporting-fixture data
  (a fixture JSON expecting `INC-TI-RAW-0001` instead of the fixture's
  actual `INC-EG-0001`, and similar) rather than application bugs.
