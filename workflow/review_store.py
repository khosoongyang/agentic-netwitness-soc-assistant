# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, datetime, json, sqlite3,
#   agents.triage.review, agents.triage.suppression, workflow.state_store.
# =============================================================================
# File: workflow/review_store.py
# Purpose: [FYP-TRIAGE-STEP3] Persistence for the analyst triage review (X1),
#   Triage re-run analyst notes, scoped suppression proposals (X3) and the
#   mentor's blind re-review labels (X6). Tables are created by
#   workflow/state_store.py::db_init() (_create_triage_review_tables).
# Main functionality: build_review_inserter() (the same-transaction hook for
#   approve_triage/reject_triage), list_reviews(), latest_review(),
#   add_analyst_note()/latest_analyst_note(), suppression proposal lifecycle
#   (propose/approve/reject/revoke/expire/list), blind review import/list.
# Inputs: validated TriageReview objects, persisted triage results, analyst
#   identity strings.
# Outputs: dict rows; raises SuppressionError / ReviewStoreError.
# Workflow position: the Triage approval gate and the feedback page.
# Called by: workflow/commands.py, workflow/engine.py,
#   backend/services/triage_feedback_service.py, scripts/blind_review.py.
# Important side effects: writes ONLY the workflow DB (wss.DB_FILE), never
#   soc_db baseline tables; nothing here closes or suppresses an incident.
# Error and fallback behaviour: every write uses wss._tx (BEGIN IMMEDIATE,
#   all-or-nothing); lifecycle transitions are compare-and-swap on status.
# Key evaluator search terms: triage_reviews, suppression_proposals,
#   blind_reviews, label_provenance, [FYP-TRIAGE-STEP3].
# =============================================================================
"""
Triage review store  --  review_store.py
========================================
[FYP-TRIAGE-STEP3] Method principles:

* Step 9 "document the verdict AND the evidence trail": a review row stores
  the evidence-packet snapshot AT DECISION TIME plus its sha256, and the
  sha256 of the raw incident artifact (chain of custody).
* Feedback-loop circularity: a human verdict is not ground truth until a
  blind re-review agrees -- label_provenance starts as 'analyst' and becomes
  'mentor_agreed' only when an imported blind label matches.
* Never auto-close / never auto-suppress: suppression proposals need a
  second human, a typed scope confirmation, and they always expire.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agents.triage import review as triage_review
from agents.triage import suppression as supp
from workflow import state_store as wss


class ReviewStoreError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 400):
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _json(value: Any) -> str | None:
    return None if value is None else json.dumps(value, default=str, ensure_ascii=False)


def _loads(value: Any, default: Any = None) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def file_sha256(path: str | Path | None) -> str | None:
    if not path:
        return None
    try:
        p = Path(path)
        if not p.is_file():
            return None
        h = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# =============================================================================
# [FYP-SECTION] TRIAGE REVIEWS (X1 / X6 labelled-verdict store)
# =============================================================================

_REVIEW_JSON_COLUMNS = ("evidence_checked", "benign_context", "evidence_packet_json")


def _review_row(row: Any, *, include_packet: bool = False) -> dict:
    d = dict(row)
    d["evidence_checked"] = _loads(d.get("evidence_checked"), [])
    d["benign_context"] = _loads(d.get("benign_context"))
    packet = _loads(d.pop("evidence_packet_json", None))
    if include_packet:
        d["evidence_packet"] = packet
    for key in ("agrees_with_ai", "revised_after_ai_reveal"):
        if d.get(key) is not None:
            d[key] = bool(d[key])
    return d


def build_review_inserter(review: "triage_review.TriageReview", *, triage_result: dict,
                          raw_incident_path: str | None = None,
                          provenance: dict | None = None):
    """[FYP-FUNCTION] [FYP-EVALUATOR] Returns the in_tx(con, ctx) callable
    passed to wss.approve_triage()/reject_triage(). It inserts the
    triage_reviews row (and, for a benign_expected review with a proposal,
    the suppression_proposals row) INSIDE the approval transaction, so the
    decision and its review are all-or-nothing."""
    tr = triage_result if isinstance(triage_result, dict) else {}
    packet = tr.get("evidence_packet") if isinstance(tr.get("evidence_packet"), dict) else None
    ai = triage_review.ai_side(tr)
    prov = provenance or tr.get("triage_provenance") or {}
    scope = supp.scope_from_packet(packet)
    raw_sha = file_sha256(raw_incident_path)
    packet_json = _json(packet) if packet else None
    packet_sha = triage_review.packet_sha256(packet)
    signature = scope["signatures"][0] if scope["signatures"] else None

    def _insert(con, ctx: dict) -> dict:
        row = ctx["row"]
        run_id = row["run_id"]
        incident_id = row["id"]
        triage_attempt = int(row.get("triage_attempt") or 1)
        cur = con.execute(
            "INSERT INTO triage_reviews (incident_id, run_id, triage_attempt, approval_attempt, "
            "analyst, decision, decided_at, ai_proposed_disposition, ai_final_disposition, "
            "uncertainty, analyst_disposition, agrees_with_ai, evidence_checked, justification, "
            "lookalike_considered, rule_tuning_note, benign_context, disagreement_reason, "
            "evidence_packet_json, evidence_packet_sha256, raw_incident_sha256, prompt_version, "
            "model, review_mode, analyst_initial_disposition, revised_after_ai_reveal, "
            "revision_reason, detection_source, entity, alert_signature, label_provenance) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(incident_id), run_id, triage_attempt, ctx.get("approval_attempt"),
             ctx["analyst"], ctx["decision"], ctx["decided_at"],
             ai["ai_proposed_disposition"], ai["ai_final_disposition"], ai["uncertainty"],
             review.analyst_disposition,
             None if review.agrees_with_ai is None else int(review.agrees_with_ai),
             _json(review.evidence_checked), review.justification,
             review.lookalike_considered, review.rule_tuning_note,
             _json(review.benign_context.model_dump()) if review.benign_context else None,
             review.disagreement_reason, packet_json, packet_sha, raw_sha,
             prov.get("prompt_version"), prov.get("model"), review.review_mode,
             review.analyst_initial_disposition, int(review.revised_after_ai_reveal),
             review.revision_reason, scope["detection_source"], scope["entity"],
             signature, "analyst"))
        review_id = cur.lastrowid
        proposal_id = None
        if review.suppression_proposal is not None and review.benign_context is not None:
            proposal_id = _insert_proposal(
                con, scope=review.suppression_proposal.scope.model_dump(),
                benign_context=review.benign_context.model_dump(),
                proposed_by=ctx["analyst"],
                expiry_days=review.suppression_proposal.expiry_days,
                source_review_id=review_id, incident_id=str(incident_id), run_id=run_id)
            con.execute("UPDATE triage_reviews SET suppression_proposal_id=? WHERE id=?",
                        (proposal_id, review_id))
        return {"review_id": review_id, "suppression_proposal_id": proposal_id}

    return _insert


def list_reviews(incident_id: str | None = None, *, include_packet: bool = False,
                 dispositions: tuple[str, ...] | None = None) -> list[dict]:
    """Reviews, newest first. incident_id=None lists every review (used by
    metrics / backlog / blind export)."""
    wss.db_init()
    sql = "SELECT * FROM triage_reviews"
    args: list[Any] = []
    where = []
    if incident_id is not None:
        where.append("incident_id=?")
        args.append(str(incident_id))
    if dispositions:
        where.append(f"analyst_disposition IN ({','.join('?' * len(dispositions))})")
        args.extend(dispositions)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY decided_at DESC, id DESC"
    with wss.db_connect() as con:
        rows = con.execute(sql, args).fetchall()
    return [_review_row(r, include_packet=include_packet) for r in rows]


def get_review(review_id: int, *, include_packet: bool = False) -> dict | None:
    wss.db_init()
    with wss.db_connect() as con:
        row = con.execute("SELECT * FROM triage_reviews WHERE id=?", (int(review_id),)).fetchone()
    return _review_row(row, include_packet=include_packet) if row else None


def latest_review(incident_id: str, run_id: str, *, decision: str | None = "approved") -> dict | None:
    """The review attached to the CURRENT triage decision of this run (the
    newest one; a re-triage + re-approval supersedes an earlier review)."""
    wss.db_init()
    sql = "SELECT * FROM triage_reviews WHERE incident_id=? AND run_id=?"
    args: list[Any] = [str(incident_id), run_id]
    if decision:
        sql += " AND decision=?"
        args.append(decision)
    sql += " ORDER BY triage_attempt DESC, decided_at DESC, id DESC LIMIT 1"
    with wss.db_connect() as con:
        row = con.execute(sql, args).fetchone()
    return _review_row(row) if row else None


def latest_review_block(incident_id: str, run_id: str) -> dict | None:
    """[FYP-FUNCTION] The `triage_review` handoff block for this run, or
    None when the approval carried no structured review (old contract)."""
    try:
        return triage_review.build_triage_review_block(latest_review(incident_id, run_id))
    except Exception:
        return None


# =============================================================================
# [FYP-SECTION] ANALYST NOTES ON A TRIAGE RE-RUN
# =============================================================================

ANALYST_NOTE_MAX_CHARS = 2000


def add_analyst_note(incident_id: str, run_id: str, *, triage_attempt: int,
                     analyst: str, note: str) -> dict:
    note = str(note or "").strip()
    analyst = str(analyst or "").strip()
    if not note:
        raise ReviewStoreError("INVALID_REQUEST", "analyst_note must not be empty.")
    if len(note) > ANALYST_NOTE_MAX_CHARS:
        raise ReviewStoreError("INVALID_REQUEST",
                               f"analyst_note is limited to {ANALYST_NOTE_MAX_CHARS} characters.")
    if not analyst:
        raise ReviewStoreError("INVALID_REQUEST", "analyst is required with an analyst_note.")
    wss.db_init()
    now = _now().isoformat()

    def _do(con):
        cur = con.execute(
            "INSERT INTO triage_analyst_notes (incident_id, run_id, triage_attempt, analyst, "
            "note, created_at) VALUES (?,?,?,?,?,?)",
            (str(incident_id), run_id, int(triage_attempt), analyst, note, now))
        return cur.lastrowid
    note_id = wss._tx(_do)
    return {"id": note_id, "incident_id": str(incident_id), "run_id": run_id,
            "triage_attempt": int(triage_attempt), "analyst": analyst, "note": note,
            "created_at": now}


def analyst_note_for_attempt(incident_id: str, run_id: str, triage_attempt: int) -> dict | None:
    """The note attached to exactly this triage attempt (None if the re-run
    carried no note -- a later re-run without a note does NOT inherit it)."""
    wss.db_init()
    with wss.db_connect() as con:
        row = con.execute(
            "SELECT * FROM triage_analyst_notes WHERE incident_id=? AND run_id=? "
            "AND triage_attempt=? ORDER BY id DESC LIMIT 1",
            (str(incident_id), run_id, int(triage_attempt))).fetchone()
    return dict(row) if row else None


# =============================================================================
# [FYP-SECTION] SUPPRESSION PROPOSALS (X3)
# =============================================================================

class SuppressionError(ReviewStoreError):
    pass


def _proposal_row(row: Any) -> dict:
    d = dict(row)
    d["benign_context"] = _loads(d.get("benign_context"), {})
    d["scope"] = {"detection_source": d.get("detection_source"), "entity": d.get("entity"),
                  "alert_signature": d.get("alert_signature")}
    return d


def _insert_proposal(con, *, scope: dict, benign_context: dict, proposed_by: str,
                     expiry_days: Any, source_review_id: int | None,
                     incident_id: str | None, run_id: str | None) -> int:
    try:
        days = supp.clamp_expiry_days(expiry_days)
    except ValueError as exc:
        raise SuppressionError("INVALID_SUPPRESSION", str(exc)) from exc
    ds = str(scope.get("detection_source") or "").strip()
    ent = str(scope.get("entity") or "").strip()
    sig = str(scope.get("alert_signature") or "").strip() or None
    if not ds or not ent:
        raise SuppressionError("INVALID_SUPPRESSION",
                               "A suppression scope needs both detection_source and entity.")
    bc = benign_context or {}
    if not all(str(bc.get(k) or "").strip() for k in ("who", "when", "why")):
        raise SuppressionError("INVALID_SUPPRESSION",
                               "benign_context {who, when, why} is required for a suppression.")
    created = _now()
    cur = con.execute(
        "INSERT INTO suppression_proposals (detection_source, entity, alert_signature, scope_text, "
        "benign_context, proposed_by, created_at, expires_at, status, source_review_id, "
        "incident_id, run_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (ds, ent, sig, supp.scope_text(ds, ent, sig), _json(bc), proposed_by,
         created.isoformat(), supp.expiry_from(created, days), "proposed",
         source_review_id, incident_id, run_id))
    return int(cur.lastrowid)


def propose_suppression_from_review(review_id: int, *, proposed_by: str,
                                    scope: dict | None = None,
                                    expiry_days: Any = None) -> dict:
    """Propose a suppression from an existing benign_expected review (the
    'propose' endpoint). Scope defaults to the review's own source/entity."""
    proposed_by = str(proposed_by or "").strip()
    if not proposed_by:
        raise SuppressionError("INVALID_REQUEST", "proposed_by is required.")
    rv = get_review(review_id)
    if rv is None:
        raise SuppressionError("REVIEW_NOT_FOUND", "Triage review was not found.", 404)
    if rv.get("analyst_disposition") != "benign_expected":
        raise SuppressionError("INVALID_SUPPRESSION",
                               "Suppressions can only be proposed from a benign_expected review "
                               "(false positives go to the rule-tuning backlog instead).")
    scope = dict(scope or {})
    scope.setdefault("detection_source", rv.get("detection_source"))
    scope.setdefault("entity", rv.get("entity"))

    def _do(con):
        pid = _insert_proposal(con, scope=scope, benign_context=rv.get("benign_context") or {},
                               proposed_by=proposed_by, expiry_days=expiry_days,
                               source_review_id=int(review_id),
                               incident_id=rv.get("incident_id"), run_id=rv.get("run_id"))
        con.execute("UPDATE triage_reviews SET suppression_proposal_id=? WHERE id=? "
                    "AND suppression_proposal_id IS NULL", (pid, int(review_id)))
        return pid
    wss.db_init()
    return get_suppression(wss._tx(_do))


def expire_suppressions(now: datetime | None = None) -> int:
    """Flip proposed/approved rows past expires_at to 'expired' (bookkeeping
    only: matching already treats them as expired via is_active())."""
    wss.db_init()
    now_s = (now or _now()).isoformat()

    def _do(con):
        cur = con.execute("UPDATE suppression_proposals SET status='expired' "
                          "WHERE status IN ('proposed','approved') AND expires_at <= ?", (now_s,))
        return cur.rowcount
    return int(wss._tx(_do))


def get_suppression(proposal_id: int) -> dict | None:
    wss.db_init()
    with wss.db_connect() as con:
        row = con.execute("SELECT * FROM suppression_proposals WHERE id=?",
                          (int(proposal_id),)).fetchone()
    return _proposal_row(row) if row else None


def list_suppressions(status: str | None = None) -> list[dict]:
    expire_suppressions()
    sql = "SELECT * FROM suppression_proposals"
    args: list[Any] = []
    if status:
        sql += " WHERE status=?"
        args.append(status)
    sql += " ORDER BY created_at DESC, id DESC"
    with wss.db_connect() as con:
        rows = con.execute(sql, args).fetchall()
    return [_proposal_row(r) for r in rows]


def active_suppressions() -> list[dict]:
    """Approved, unexpired proposals -- what Triage is handed for
    context.suppression_match. Never raises (no DB -> no suppressions)."""
    try:
        return [p for p in list_suppressions("approved") if supp.is_active(p)]
    except Exception:
        return []


def _transition(proposal_id: int, *, from_statuses: tuple[str, ...], to_status: str,
                actor: str, note: str | None = None, confirm_scope: str | None = None,
                require_scope: bool = False) -> dict:
    actor = str(actor or "").strip()
    if not actor:
        raise SuppressionError("INVALID_REQUEST", "analyst is required.")
    wss.db_init()
    expire_suppressions()

    def _do(con):
        row = con.execute("SELECT * FROM suppression_proposals WHERE id=?",
                          (int(proposal_id),)).fetchone()
        if row is None:
            raise SuppressionError("SUPPRESSION_NOT_FOUND", "Suppression proposal was not found.", 404)
        if row["status"] not in from_statuses:
            raise SuppressionError(
                "SUPPRESSION_CONFLICT",
                f"Suppression #{proposal_id} is {row['status']}; cannot move it to {to_status}.", 409)
        if require_scope and str(confirm_scope or "") != row["scope_text"]:
            raise SuppressionError(
                "CONFIRMATION_REQUIRED",
                "Type the exact scope text to confirm this suppression.", 403)
        if to_status == "approved" and actor.casefold() == str(row["proposed_by"]).casefold():
            raise SuppressionError(
                "FORBIDDEN_OPERATION",
                "A suppression must be approved by a different analyst than its proposer.", 403)
        con.execute("UPDATE suppression_proposals SET status=?, decided_by=?, decided_at=?, "
                    "decision_note=? WHERE id=? AND status=?",
                    (to_status, actor, _now().isoformat(), note, int(proposal_id), row["status"]))
        return int(proposal_id)
    return get_suppression(wss._tx(_do))


def approve_suppression(proposal_id: int, *, analyst: str, confirmation: str) -> dict:
    return _transition(proposal_id, from_statuses=("proposed",), to_status="approved",
                       actor=analyst, confirm_scope=confirmation, require_scope=True)


def reject_suppression(proposal_id: int, *, analyst: str, note: str | None = None) -> dict:
    return _transition(proposal_id, from_statuses=("proposed",), to_status="rejected",
                       actor=analyst, note=note)


def revoke_suppression(proposal_id: int, *, analyst: str, note: str | None = None) -> dict:
    return _transition(proposal_id, from_statuses=("approved",), to_status="revoked",
                       actor=analyst, note=note)


# =============================================================================
# [FYP-SECTION] BLIND RE-REVIEW (X6)
# =============================================================================

def import_blind_reviews(rows: list[dict]) -> dict:
    """[FYP-FUNCTION] Load the mentor's blind labels. Each row needs
    review_id, reviewer, disposition (+ optional evidence_note,
    reviewed_at). Re-importing the same (review_id, reviewer) replaces the
    label. A review whose mentor label equals the analyst label gets
    label_provenance='mentor_agreed'; disagreement -> 'mentor_disputed'."""
    wss.db_init()
    from agents.triage.triage_result import DISPOSITIONS
    imported, skipped = 0, []
    now = _now().isoformat()

    def _do(con):
        nonlocal imported
        for i, r in enumerate(rows):
            try:
                rid = int(str(r.get("review_id") or "").strip())
            except ValueError:
                skipped.append({"row": i + 1, "reason": "review_id is not an integer"})
                continue
            reviewer = str(r.get("reviewer") or "").strip()
            disp = str(r.get("disposition") or "").strip().lower().replace("-", "_").replace(" ", "_")
            if not reviewer or disp not in DISPOSITIONS:
                skipped.append({"row": i + 1, "reason": "reviewer missing or disposition invalid"})
                continue
            rv = con.execute("SELECT analyst_disposition FROM triage_reviews WHERE id=?",
                             (rid,)).fetchone()
            if rv is None:
                skipped.append({"row": i + 1, "reason": f"review_id {rid} not found"})
                continue
            con.execute(
                "INSERT INTO blind_reviews (review_id, reviewer, disposition, evidence_note, "
                "reviewed_at, imported_at) VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(review_id, reviewer) DO UPDATE SET disposition=excluded.disposition, "
                "evidence_note=excluded.evidence_note, reviewed_at=excluded.reviewed_at, "
                "imported_at=excluded.imported_at",
                (rid, reviewer, disp, str(r.get("evidence_note") or "").strip() or None,
                 str(r.get("reviewed_at") or "").strip() or now, now))
            prov = "mentor_agreed" if rv["analyst_disposition"] == disp else "mentor_disputed"
            con.execute("UPDATE triage_reviews SET label_provenance=? WHERE id=?", (prov, rid))
            imported += 1
        return imported
    wss._tx(_do)
    return {"imported": imported, "skipped": skipped}


def list_blind_reviews() -> list[dict]:
    wss.db_init()
    with wss.db_connect() as con:
        rows = con.execute("SELECT * FROM blind_reviews ORDER BY review_id, reviewer").fetchall()
    return [dict(r) for r in rows]


__all__ = [
    "ReviewStoreError",
    "SuppressionError",
    "build_review_inserter",
    "list_reviews",
    "get_review",
    "latest_review",
    "latest_review_block",
    "add_analyst_note",
    "analyst_note_for_attempt",
    "propose_suppression_from_review",
    "expire_suppressions",
    "get_suppression",
    "list_suppressions",
    "active_suppressions",
    "approve_suppression",
    "reject_suppression",
    "revoke_suppression",
    "import_blind_reviews",
    "list_blind_reviews",
    "file_sha256",
]
