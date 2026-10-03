# Triage review, feedback routing and labelled verdicts (Triage Step 3)

[FYP-TRIAGE-STEP3] This step puts the **analyst** in charge of the triage verdict,
routes the analyst's feedback to the right place (rule tuning vs. scoped,
expiring suppression proposals), and turns the reviews into a **labelled-verdict
store** that can be checked by blind re-review and agreement metrics.

Nothing here closes, suppresses or responds to an incident automatically.

## 1. Method principles and where they are enforced

| Principle | Where |
|---|---|
| Step 9 "Document the verdict AND the evidence trail"; confirmed-benign vs assumed-benign = recording WHAT was checked | `agents/triage/review.py::TriageReview` (>= 1 `evidence_checked`, justification); `workflow/review_store.py` stores the evidence packet snapshot **at decision time** + its sha256 and the raw-incident sha256 (chain of custody) |
| Step 10 "FP from a broken rule -> flag for tuning"; FP != Benign-Expected | FP requires `rule_tuning_note` -> `GET /api/triage/tuning-backlog`, `scripts/export_tuning_backlog.py` (Palantir ADS stubs, TODO never invented). Benign-Expected requires `benign_context {who, when, why}` -> optional scoped suppression proposal |
| Feedback-loop circularity: human verdicts are not ground truth until blind re-review agrees | `triage_reviews.label_provenance` = `analyst` until `scripts/blind_review.py import` marks `mentor_agreed` / `mentor_disputed`; only `mentor_agreed` rows become eval cases (`export_labelling_sheet.py import-reviews`); metrics caveat when no blind labels |
| Automation bias | Review dropdown starts **empty** (never the AI value); disagreement needs a reason; `review_mode = blind_first` hides AI verdict + hypotheses until the analyst commits, stores `analyst_initial_disposition` + `revised_after_ai_reveal`; `revision_after_reveal_rate` metric |
| Tier 3: the verdict stays human | Analyst disposition is `triage_review.final_disposition` in the investigation alert, the reporting `triage_result.json` and the exported ticket ("AI: X -> Analyst: Y"); `ticket.classification` (severity) is unchanged |
| Tier 2 hard rule: never auto-close / auto-suppress | Suppressions are proposals; approval needs a **different** analyst who types the exact scope; they always expire (default 30 days, max 90); an approved match only adds `context.suppression_match` evidence |
| Adversarial mimicry | `agents/triage/guards.py`: a suppression match **never** satisfies the strong-signal floor (rule b), and is ignored entirely when strong rule signals / strong LOLBAS hits / path_mismatch are present; the UI says why |
| Missing = unknown, not safe | "Unknown != safe" banner for missing mandatory evidence; expired / unparseable suppressions are no match; no analyst note -> `context.analyst_note` is `missing` |

## 2. Data model (workflow DB, `CREATE TABLE IF NOT EXISTS`, additive)

* `triage_reviews` - identity (incident, run, triage_attempt, analyst, decision, decided_at),
  AI side (proposed / final disposition, uncertainty), analyst side (disposition,
  agrees_with_ai, evidence_checked, justification, lookalike_considered,
  rule_tuning_note, benign_context, disagreement_reason, suppression_proposal_id),
  evidence snapshot + sha256, raw_incident_sha256, prompt_version, model,
  review_mode, analyst_initial_disposition, revised_after_ai_reveal, label_provenance.
* `suppression_proposals` - scope (detection_source, entity, optional alert_signature),
  benign_context, proposed_by, created/expires_at, status
  proposed | approved | rejected | expired | revoked, decided_by/at.
* `blind_reviews` - review_id, reviewer, disposition, evidence_note, reviewed_at.
* `triage_analyst_notes` - the note attached to a Triage re-run (per triage_attempt).

**Same transaction.** `workflow/state_store.py::_atomic_stage_transition()` gained an
optional `in_tx(con, ctx)` hook that runs inside the existing `BEGIN IMMEDIATE`
after the CAS check and the `workflow_approvals` insert. The Triage gate uses it to
insert the review (and any suppression proposal); if it raises, the status change
and the approval row roll back too. Nothing else about the CAS changed; every other
caller passes nothing.

## 3. Re-triage with an analyst note

`POST /api/cases/<id>/stages/triage/reruns {analyst_note, analyst}` stores the note
for the new triage attempt; the durable triage worker hands it to
`TriageAgent.triage(analyst_note=...)`, which puts it in the evidence packet as
`context.analyst_note` (status `measured`, source `analyst <name> @ <iso time>`).
The prompt delimits it as `<analyst_provided_context>"..."</analyst_provided_context>`
(delimiter text inside the note is defanged). A **valid cite** to it counts as
context evidence for guard rules b/c - the only way `benign_expected` is reachable
in this step, because confirmed-benign requires a human-attested fact.
`TRIAGE_PROMPT_VERSION` = `2026-10-step3-analyst-note-suppression`.

## 4. Scripts

```bash
python scripts/export_tuning_backlog.py              # -> runtime/tuning_backlog/ADS_*.md + index.md
python scripts/blind_review.py export --sample 30 --seed 7 --stratify disposition
python scripts/blind_review.py import runtime/eval_reports/blind_review_<ts>.csv --reviewer Mentor
python scripts/triage_metrics.py                     # -> runtime/eval_reports/triage_metrics_<ts>.{json,md}
python scripts/export_labelling_sheet.py import-reviews --workflow-db soc_db/soc_incidents.db
```

All accept `--workflow-db` to point at a copy. Outputs are git-ignored.

## 5. Metrics

Pure-Python Cohen's kappa `(p_o - p_e) / (1 - p_e)` with confusion matrices for
analyst vs mentor, AI-final vs mentor, AI-final vs analyst and AI-proposed vs
AI-final (= how often the guards intervene), plus override rate, needs_info rate,
per-disposition counts and the blind_first revision-after-reveal rate. With
`n < 30` every report carries the small-sample caveat; a degenerate case (both
raters used a single identical label) is flagged instead of silently reported.

## 6. Manual QA checklist (UI)

Run `python app.py`, open http://127.0.0.1:5000. Automated equivalents run in
`tests/test_triage_step3_frontend.py` (Node) and were executed in headless Chrome
against a seeded copy of the DB (see the Step 3 report).

1. Review screen renders above the Triage ticket: AI final + proposed disposition,
   uncertainty as a word, plain-language guard change, "Unknown != safe" banner when
   mandatory evidence is missing.
2. Clicking a citation chip scrolls to and highlights its evidence leaf; invalid
   citations are struck through.
3. Form rules: empty dropdown; no submit without disposition, >= 1 evidence item and
   justification; lookalike for non-TP; rule tuning note for FP; who/when/why for
   benign-expected; disagreement reason when overriding the AI.
4. Approve / Reject with review: review appears in "Recorded analyst reviews" and in
   `GET /api/cases/<id>/triage/reviews`; Reject and re-triage starts a Triage re-run
   with the note as `context.analyst_note`.
5. blind_first (Settings -> Triage review mode): AI verdict and hypotheses hidden until
   "Record initial verdict & reveal AI"; a revision needs a reason; stored flags.
6. Triage Feedback page: backlog, suppression proposals (approve requires typing the
   exact scope, by a second analyst; reject; revoke), noisy rules, quality metrics.
7. Sidebar links for Overview, Cases, Triage Feedback, Reports, Search, Chat,
   Pipeline, Integrations, Settings; the active link is marked.
8. XSS probe: an incident whose title, alert name, command line and threat_desc
   contain `<img src=x onerror=alert(1)>` renders the payload as inert text, creates
   no `<img>` element and raises no dialog.
