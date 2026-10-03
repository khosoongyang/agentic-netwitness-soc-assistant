"""Investigation observability.

Investigation is a mixed stage, and runs mostly OUT of process:

  in the Flask worker (observed directly, origin=wrapper/langchain_callback):
    stage claim, the shared-workspace lock, context handed to the agent, the
    handoff file, each agent subprocess run, the structured-vs-Markdown
    result read-back, severity-divergence check and ticket annotation,
    rule-based evidence-gap detection, the in-process deep-triage
    supplement LLM call (real LangChain callbacks), the post-stage summary,
    result persistence and the approval gate;

  inside the agent subprocess (python main.py; observed via its own log
  output, origin=subprocess_log):
    ingestion into the vector store, the correlation engine, playbook
    selection, AI Pass 1 / Pass 2, pivot retrieval matches, policy
    classification, fallbacks and report writing.

Subprocess lines are read live through the streaming runner's existing
line callback. Only lines matching a KNOWN template (taken verbatim from
the agent's source) become events; every other line is kept, sanitised and
capped, in a collapsed "raw agent log" block on the run's completion event -
never interpreted. Model name, token usage and per-call duration of the
subprocess's own LLM calls are not observable from outside that process; the
only timing shown for them is the gap between the agent's call and response
log lines, labelled as such.

Naming: each subprocess execution is an "Investigation run" (run 2 only
exists when the evidence-gap feedback loop re-runs it); "AI Pass 1/Pass 2"
are the agent's two LLM passes inside one run.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Callable

from .. import context, details
from ..emitter import emit
from ..events import new_span_id
from ..instrument import Hooks, Patcher, Target
from ..sanitize import describe_exception, sanitize_text

STAGE = "investigation"
_POST_STAGE_NOTE = "Generated after Investigation. Not used in Investigation decisions."
_SUBPROCESS_NOTE = ("Observed from the Investigation agent's own log output (separate process). "
                    "Model name, token usage and exact call duration are not observable from outside "
                    "that process.")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_LEVEL = re.compile(r"^\[(\*|\+|~|!|-)\]\s*(?:ERROR:\s*)?(.*)$")
_RAW_CAP = 150


def _scope() -> context.RunScope | None:
    scope = context.current_scope()
    return scope if scope is not None and scope.stage == STAGE else None


def _str(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _state(incident_id: str) -> dict:
    from workflow import state_store

    return state_store.get_state(str(incident_id)) or {}


def _approval_span(run_id: Any, attempt: Any) -> str:
    return f"approval:{run_id}:{STAGE}:{attempt or 1}"


def _group(scope: context.RunScope) -> dict:
    run_no = scope.data.get("run_no")
    if not run_no:
        return {}
    label = f"Investigation run {run_no}" + (" (evidence-gap feedback loop)" if run_no > 1 else "")
    return {"group": label, "investigation_run": run_no}


# ── Subprocess log reader ───────────────────────────────────────────────────

class _LogReader:
    """Classifies one agent subprocess run's output, line by line, live."""

    def __init__(self, scope: context.RunScope, run_span: str):
        self.scope = scope
        self.run_span = run_span
        self.spans: dict[str, tuple[str, float]] = {}
        self.raw: list[str] = []
        self.unclassified = 0
        self.classified = 0
        self.pivot_matches = 0
        self.in_traceback = False

    # helpers --------------------------------------------------------------
    def _emit(self, *, child: bool, source: str, event_type: str, status: str, title: str,
              detail: str = "", kind: str | None = None, span: str | None = None,
              metadata: dict | None = None) -> None:
        meta = {"log_template": event_type, **_group(self.scope), **(metadata or {})}
        emit(source=source, event_type=event_type, status=status, title=title, detail=detail,
             ai_content_kind=kind, span_id=span, parent_span_id=self.run_span if child else None,
             origin="subprocess_log", metadata=meta)

    def _open(self, key: str) -> str:
        span = new_span_id()
        self.spans[key] = (span, time.monotonic())
        return span

    def _close(self, key: str) -> tuple[str | None, str]:
        span, started = self.spans.pop(key, (None, None))
        gap = details.format_duration_ms((time.monotonic() - started) * 1000) if started else ""
        return span, gap

    def _ai_start(self, key: str, title: str) -> None:
        span = self._open(key)
        self._emit(child=False, source="ai", kind="assessment", event_type="ai_pass", status="running",
                   title=title, span=span, metadata={"phase": key, "details": details.blocks(
                       details.note(_SUBPROCESS_NOTE))})

    def _ai_done(self, key: str, title: str, detail: str, blocks: list | None = None) -> None:
        span, gap = self._close(key)
        self._emit(child=False, source="ai", kind="explanation", event_type="ai_pass", status="completed",
                   title=title, detail=detail, span=span or new_span_id(),
                   metadata={"phase": key, "details": details.blocks(
                       *(blocks or []),
                       details.fields([("Time between call and response log lines", gap)]),
                       details.note(_SUBPROCESS_NOTE))})

    def _ai_fail(self, key: str, title: str, error: str, fallback: str | None = None) -> None:
        span, gap = self._close(key)
        self._emit(child=False, source="ai", kind="assessment", event_type="ai_pass", status="failed",
                   title=title, detail=sanitize_text(error, max_len=300), span=span or new_span_id(),
                   metadata={"phase": key})
        if fallback:
            self._emit(child=False, source="system", event_type="fallback", status="warning",
                       title=fallback, metadata={"fallback": True})

    # line handling ------------------------------------------------------------
    def feed(self, line: str) -> None:
        original = _ANSI.sub("", str(line))
        text = original.strip()
        if not text:
            return
        # Stack traces never reach the analyst UI: drop the whole frame block
        # and keep only the final exception line (sanitised, below).
        if text.startswith("Traceback (most recent call last)"):
            self.in_traceback = True
            self._keep_raw("«stack trace removed»")
            return
        if self.in_traceback:
            if original[:1].isspace():
                return
            self.in_traceback = False
        match = _LEVEL.match(text)
        message = match.group(2).strip() if match else text
        for pattern, handler in _TEMPLATES:
            found = pattern.match(message)
            if found:
                self.classified += 1
                handler(self, found)
                return
        self.unclassified += 1
        self._keep_raw(text)

    def _keep_raw(self, text: str) -> None:
        if len(self.raw) >= _RAW_CAP:
            self.raw.pop(0)
        self.raw.append(sanitize_text(text, max_len=300))


def _t(pattern: str):
    def register(fn: Callable[[_LogReader, re.Match], None]):
        _TEMPLATES.append((re.compile(pattern), fn))
        return fn
    return register


_TEMPLATES: list[tuple[re.Pattern[str], Callable[[_LogReader, re.Match], None]]] = []


@_t(r"^Initializing SOC Incident Response Pipeline")
def _(r, m): r._emit(child=True, source="system", event_type="agent_started", status="info",
                     title="Investigation agent started")


@_t(r"^No alert files found in 'triaged_alerts/'")
def _(r, m): r._emit(child=True, source="system", event_type="ingestion", status="warning",
                     title="No queued alert found — ingestion skipped")


@_t(r"^Starting Bulk Ingestion of (\d+) raw alert logs")
def _(r, m): r._emit(child=True, source="tool", event_type="ingestion", status="running",
                     title=f"Ingesting {m.group(1)} queued alert(s) into the vector store",
                     span=r._open("ingest"))


@_t(r"^Failed to ingest log (.+?): (.*)$")
def _(r, m): r._emit(child=True, source="tool", event_type="ingestion", status="failed",
                     title="A queued alert could not be ingested", detail=sanitize_text(m.group(2), 200))


@_t(r"^Bulk Ingestion completed\. Vector store populated with (\d+) items")
def _(r, m):
    span, gap = r._close("ingest")
    r._emit(child=True, source="tool", event_type="ingestion", status="completed",
            title=f"Vector store updated with {m.group(1)} alert(s)", detail=gap, span=span)


@_t(r"^CorrelationEngine: Loaded (\d+) active incidents into memory cache")
def _(r, m): r._emit(child=True, source="system", event_type="correlation", status="info",
                     title=f"Correlation engine loaded {m.group(1)} active incident(s)")


@_t(r"^CorrelationEngine: Failed to load incident (\S+) into cache: (.*)$")
def _(r, m): r._emit(child=True, source="system", event_type="correlation", status="warning",
                     title="Correlation engine could not load an existing incident",
                     detail=sanitize_text(m.group(2), 200))


@_t(r"^All alert files in 'triaged_alerts/' have been handled")
def _(r, m): r._emit(child=True, source="system", event_type="queue", status="info",
                     title="Alert queue fully processed")


@_t(r"^Evaluating remaining queue\. Picked investigative Seed Alert: (.+)$")
def _(r, m): r._emit(child=True, source="system", event_type="queue", status="info",
                     title="Seed alert selected", detail=m.group(1))


@_t(r"^Failed to process seed file (.+?): (.*)$")
def _(r, m): r._emit(child=True, source="system", event_type="queue", status="failed",
                     title="Seed alert could not be processed", detail=sanitize_text(m.group(2), 200))


@_t(r"^CorrelationEngine: Processing alert (\S+) through two-tier engine")
def _(r, m): r._emit(child=True, source="tool", event_type="correlation", status="info",
                     title="Correlating the alert against existing incidents",
                     detail="Two-tier correlation engine (vector similarity + rules)")


@_t(r"^CorrelationEngine: Tier 1 took ([\d.]+)ms\. Decision: (\S+) \(Score: (-?[\d.]+)\)")
def _(r, m): r._emit(child=True, source="tool", event_type="correlation", status="completed",
                     title=f"Correlation tier 1 decision: {m.group(2)}",
                     detail=f"score {m.group(3)} · {m.group(1)} ms")


@_t(r"^CorrelationEngine: Flagged Similar but Unrelated to (\S+)\. Routing to Tier 2")
def _(r, m): r._emit(child=True, source="tool", event_type="correlation", status="info",
                     title="Similar to another incident but unrelated — routed to tier 2",
                     detail=f"Similar to {m.group(1)}")


@_t(r"^CorrelationEngine: Alert clusters with (\d+) other alerts at window size ([\d.]+)m")
def _(r, m): r._emit(child=True, source="tool", event_type="correlation", status="info",
                     title=f"Alert clusters with {m.group(1)} other alert(s)",
                     detail=f"time window {m.group(2)} min")


@_t(r"^CorrelationEngine: Alert remains isolated after dynamic window searches")
def _(r, m): r._emit(child=True, source="tool", event_type="correlation", status="info",
                     title="Alert remains isolated after time-window searches")


@_t(r"^CorrelationEngine: Tier 2 took ([\d.]+)ms\. Decision: (\S+)\. Total Latency: ([\d.]+)ms")
def _(r, m): r._emit(child=True, source="tool", event_type="correlation", status="completed",
                     title=f"Correlation tier 2 decision: {m.group(2)}",
                     detail=f"{m.group(1)} ms (total {m.group(3)} ms)")


@_t(r"^Failed baseline correlation for alert (\S+): (.*)$")
def _(r, m): r._emit(child=True, source="tool", event_type="correlation", status="failed",
                     title="Correlation failed for the alert", detail=sanitize_text(m.group(2), 200))


@_t(r"^Auto-selected (.+?) playbook for(?: alert type)?: (.*)$")
def _(r, m): r._emit(child=False, source="rule", event_type="playbook_selection", status="completed",
                     title=f"Playbook selected: {m.group(1)}", detail=f"Matched on {m.group(2)}")


@_t(r"^Error auto-detecting playbook: (.*?)\. Defaulting to endpoint playbook")
def _(r, m): r._emit(child=False, source="rule", event_type="playbook_selection", status="warning",
                     title="Playbook auto-detection failed — default endpoint playbook used",
                     detail=sanitize_text(m.group(1), 200), metadata={"fallback": True})


@_t(r"^Confirmed Match\. Merging alert (\S+) into Incident (\S+)")
def _(r, m): r._emit(child=True, source="system", event_type="incident_formation", status="completed",
                     title=f"Alert merged into existing incident {m.group(2)}")


@_t(r"^Forming (.+?) -> (\S+)$")
def _(r, m): r._emit(child=True, source="system", event_type="incident_formation", status="completed",
                     title=f"Forming {m.group(1)}", detail=m.group(2))


@_t(r"^Running parallel report generation and enrichment for (\d+) incidents")
def _(r, m): r._emit(child=True, source="system", event_type="analysis_started", status="info",
                     title=f"Report generation started for {m.group(1)} incident(s)")


@_t(r"^Incident (\S+): Standalone alert with no DB relations\. Generating report locally \(0 LLM calls\)")
def _(r, m): r._emit(child=False, source="rule", event_type="local_report", status="completed",
                     title="Local deterministic report path chosen (no model calls)",
                     detail=f"{m.group(1)}: standalone alert with no related alerts")


@_t(r"^\[LLM CALL\] Pass 1:")
def _(r, m): r._ai_start("pass1", "AI Pass 1 started — playbook evaluation and pivot extraction")


@_t(r"^\[LLM RESPONSE\] Pass 1 completed for (\S+)\. Suggested pivots: (.*)$")
def _(r, m):
    pivots = [p.strip(" '\"") for p in m.group(2).strip("[] ").split(",") if p.strip(" '\"")]
    r._ai_done("pass1", "AI Pass 1 completed",
               f"{len(pivots)} suggested pivot(s)" + (f": {', '.join(pivots[:6])}" if pivots else ""),
               [details.items("Suggested pivots (returned by the model)", pivots)])


@_t(r"^Pass 1 LLM call failed: (.*)$")
def _(r, m): r._ai_fail("pass1", "AI Pass 1 failed", m.group(1),
                        fallback="Agent continued without Pass 1 results (no pivots; playbook steps marked NOT_MET)")


@_t(r"^Dynamic retrieval matched alert (\S+) \(RRF: ([\d.]+)\)")
def _(r, m):
    r.pivot_matches += 1
    r._emit(child=False, source="tool", event_type="pivot_retrieval", status="completed",
            title=f"Pivot retrieval matched alert {m.group(1)}",
            detail=f"Vector + keyword (RRF) score {m.group(2)}")


@_t(r"^\[LLM CALL\] Pass 2:")
def _(r, m): r._ai_start("pass2", "AI Pass 2 started — final analysis")


@_t(r"^\[LLM RESPONSE\] Pass 2 completed for (\S+) \(Severity: (\w+)\)")
def _(r, m): r._ai_done("pass2", "AI Pass 2 completed", f"Severity returned by the model: {m.group(2)}")


@_t(r"^Pass 2 LLM call failed: (.*)$")
def _(r, m): r._ai_fail("pass2", "AI Pass 2 failed", m.group(1),
                        fallback="Deterministic fallback report used (no AI analysis in this result)")


@_t(r"^\[LLM CALL\] Running one-time AI Policy Parser")
def _(r, m): r._ai_start("policy", "AI policy-section classification started")


@_t(r"^\[LLM RESPONSE\] AI Policy Parser classified relevant sections: (.*)$")
def _(r, m): r._ai_done("policy", "AI policy-section classification completed",
                        sanitize_text(m.group(1), 300))


@_t(r"^Failed to run AI Policy Parser: (.*?)\. Falling back to default whitelist")
def _(r, m): r._ai_fail("policy", "AI policy-section classification failed", m.group(1),
                        fallback="Default policy-section whitelist used")


@_t(r"^PolicyVectorIndex: Loaded relevant sections classification from cache")
def _(r, m): r._emit(child=True, source="system", event_type="policy_index", status="info",
                     title="Policy-section classification loaded from cache (no model call)")


@_t(r"^PolicyVectorIndex: Successfully populated with (\d+) relevant sections")
def _(r, m): r._emit(child=True, source="tool", event_type="policy_index", status="completed",
                     title=f"Policy vector index populated with {m.group(1)} section(s)")


@_t(r"^PolicyVectorIndex: Skipping population")
def _(r, m): r._emit(child=True, source="system", event_type="policy_index", status="info",
                     title="Existing policy vector index reused")


@_t(r"^PolicyVectorIndex: Retrieve failed: (.*)$")
def _(r, m): r._emit(child=True, source="tool", event_type="policy_index", status="warning",
                     title="Policy retrieval failed", detail=sanitize_text(m.group(1), 200))


@_t(r"^\[LLM CALL\] Invoking Micro-Task 1: Intelligent Indicator Filter on (\d+) tokens")
def _(r, m): r._ai_start("filter", f"AI indicator filter started ({m.group(1)} tokens)")


@_t(r"^\[LLM RESPONSE\] Filtered tokens: (.*)$")
def _(r, m): r._ai_done("filter", "AI indicator filter completed", sanitize_text(m.group(1), 300))


@_t(r"^Failed to filter seeds with LLM: (.*?)\. Falling back to original tokens")
def _(r, m): r._ai_fail("filter", "AI indicator filter failed", m.group(1),
                        fallback="Original, unfiltered indicators used")


@_t(r"^\[LLM CALL\] Invoking Micro-Task 2: Milestone Sufficiency Check for step (\S+?)\.*$")
def _(r, m): r._ai_start(f"milestone:{m.group(1)}", f"AI milestone check started — {m.group(1)}")


@_t(r"^\[LLM RESPONSE\] Step (\S+) Met: (\w+) \| Reasoning: (.*)$")
def _(r, m): r._ai_done(f"milestone:{m.group(1)}", f"AI milestone check completed — {m.group(1)}",
                        f"Met: {m.group(2)}",
                        [details.text("Explanation returned by the model", sanitize_text(m.group(3), 1000))])


@_t(r"^Failed to verify milestone with LLM: (.*)$")
def _(r, m):
    key = next((k for k in reversed(list(r.spans)) if k.startswith("milestone:")), "milestone:?")
    r._ai_fail(key, "AI milestone check failed", m.group(1))


@_t(r"^\[LLM CALL\] Invoking Final Structural Reporting for incident (\S+?)\.*$")
def _(r, m): r._ai_start("final_report", "AI final structured report started")


@_t(r"^\[LLM RESPONSE\] Generated final report with severity: (\w+) \| confidence: (\w+)")
def _(r, m): r._ai_done("final_report", "AI final structured report completed",
                        f"Severity {m.group(1)} · confidence {m.group(2)}")


@_t(r"^Failed to generate final structured report: (.*)$")
def _(r, m): r._ai_fail("final_report", "AI final structured report failed", m.group(1),
                        fallback="Deterministic fallback report used (no AI analysis in this result)")


@_t(r"^LLM MITRE Mapping call failed: (.*?)\. Using fallback mapper")
def _(r, m):
    r._emit(child=False, source="ai", kind="assessment", event_type="ai_pass", status="failed",
            title="AI MITRE mapping failed", detail=sanitize_text(m.group(1), 300))
    r._emit(child=False, source="rule", event_type="fallback", status="warning",
            title="Heuristic MITRE mapper used", metadata={"fallback": True})


@_t(r"^Starting orchestration for Seed Alert: (\S+)")
def _(r, m): r._emit(child=True, source="system", event_type="orchestration_path", status="info",
                     title="Iterative correlation started", detail=m.group(1))


@_t(r"^Pivoting Hop \[(\d+)\] on seeds: (.*)$")
def _(r, m): r._emit(child=True, source="tool", event_type="pivot_retrieval", status="info",
                     title=f"Correlation hop {m.group(1)}", detail=sanitize_text(m.group(2), 300))


@_t(r"^Correlated related alert (\S+) \(RRF Score: ([\d.]+)\)")
def _(r, m): r._emit(child=False, source="tool", event_type="pivot_retrieval", status="completed",
                     title=f"Correlated related alert {m.group(1)}", detail=f"RRF score {m.group(2)}")


@_t(r"^Transitive closure complete in (\d+) hops\. Total correlated alerts: (\d+)")
def _(r, m): r._emit(child=True, source="tool", event_type="pivot_retrieval", status="completed",
                     title=f"Correlation complete — {m.group(2)} alert(s) in {m.group(1)} hop(s)")


@_t(r"^CIRCUIT BREAKER TRIGGERED: (.*)$")
def _(r, m): r._emit(child=True, source="rule", event_type="pivot_retrieval", status="warning",
                     title="Correlation depth limit reached", detail=sanitize_text(m.group(1), 200))


@_t(r"^Playbook step (\S+) requested extra queries for: (.*)$")
def _(r, m): r._emit(child=True, source="tool", event_type="pivot_retrieval", status="info",
                     title=f"Extra evidence queries for {m.group(1)}", detail=sanitize_text(m.group(2), 300))


@_t(r"^Case report stored securely inside: ")
def _(r, m): r._emit(child=True, source="system", event_type="report_written", status="completed",
                     title="Final analysis report written")


@_t(r"^Structured investigation analysis stored inside: ")
def _(r, m): r._emit(child=True, source="system", event_type="report_written", status="completed",
                     title="Structured analysis (JSON) written")


@_t(r"^SOC Incident Response Pipeline shut down successfully")
def _(r, m): r._emit(child=True, source="system", event_type="agent_finished", status="info",
                     title="Investigation agent finished")


# ── Stage entry and lifecycle ───────────────────────────────────────────────

def _stage_scope(call: dict) -> context.RunScope:
    return context.RunScope(case_id=str(call.get("incident_id")), run_id=call.get("run_id"), stage=STAGE)


def _stage_error(call: dict, token: Any, exc: BaseException) -> None:
    scope = _scope()
    if scope is None:
        return
    message = str(exc)
    if type(exc).__name__ in ("StageClaimError", "GlobalLockBusyError"):
        lock = scope.data.get("lock") or {}
        if "could not acquire the shared workspace" in message:
            title, detail = "Gave up waiting for Investigation capacity", sanitize_text(message, 300)
        elif "lock lost" in message or "lock_lost" in message:
            title, detail = ("Shared workspace lock lost — this run's result was discarded",
                             "The stage stays Processing and can be resumed.")
        else:
            title, detail = ("Investigation worker stopped without saving a result",
                             "The stage lease was not held by this worker (another worker owns it, or the run was superseded).")
        if lock.get("span") and not lock.get("acquired"):
            emit(source="orchestration", event_type="workspace_lock", status="failed",
                 title="Investigation capacity not acquired", span_id=lock["span"])
        emit(source="orchestration", event_type="worker_stopped", status="warning", title=title, detail=detail)
    else:
        emit(source="orchestration", event_type="worker_stopped", status="failed",
             title="Investigation worker raised an error", detail=describe_exception(exc))


def _claim_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None or call.get("stage") != STAGE:
        return
    try:
        scope.stage_attempt = int(result[1])
    except Exception:
        pass
    emit(source="orchestration", event_type="stage_claimed", status="completed",
         origin="state_transition", title="Investigation stage claimed by a worker",
         detail=f"Attempt {scope.stage_attempt or '—'} · worker lease acquired")


def _claim_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or call.get("stage") != STAGE:
        return
    emit(source="orchestration", event_type="stage_claimed", status="warning", origin="state_transition",
         title="Investigation stage could not be claimed", detail=describe_exception(exc))


def _lock_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None or call.get("lock_name") != "investigation_workspace":
        return
    lock = scope.data.setdefault("lock", {})
    lock["acquired"] = True
    if lock.get("span"):
        waited = details.format_duration_ms((time.monotonic() - lock["since"]) * 1000)
        emit(source="orchestration", event_type="workspace_lock", status="completed",
             origin="state_transition", title="Investigation capacity acquired",
             detail=f"Shared Investigation workspace acquired after waiting {waited} ({lock['attempts']} busy check(s)).",
             span_id=lock["span"])
    else:
        emit(source="orchestration", event_type="workspace_lock", status="completed",
             origin="state_transition", title="Investigation workspace acquired",
             detail="The shared Investigation workspace was free — no wait.")


def _lock_error(call: dict, token: Any, exc: BaseException) -> None:
    scope = _scope()
    if scope is None or call.get("lock_name") != "investigation_workspace":
        return
    if type(exc).__name__ != "GlobalLockBusyError":
        return
    lock = scope.data.setdefault("lock", {})
    lock["attempts"] = lock.get("attempts", 0) + 1
    if not lock.get("span"):
        lock["span"] = new_span_id()
        lock["since"] = time.monotonic()
        emit(source="orchestration", event_type="workspace_lock", status="running",
             origin="state_transition", title="Waiting for Investigation capacity",
             detail="Another investigation is using the shared Investigation workspace; only one runs at a time.",
             span_id=lock["span"])


def _complete_after(call: dict, token: Any, ok: Any) -> None:
    scope = _scope()
    if scope is None or call.get("stage") != STAGE:
        return
    updates = call.get("status_updates") or {}
    status = updates.get("investigation_status")
    if not ok:
        emit(source="orchestration", event_type="stage_settled", status="warning", origin="state_transition",
             title="Investigation result was not saved",
             detail="The stage lease was reassigned before the result could be written.")
        return
    if status == "Awaiting Approval":
        emit(source="orchestration", event_type="stage_settled", status="completed", origin="state_transition",
             title="Investigation result saved", detail="Workflow paused at the SOC analyst approval gate.",
             metadata={"status_updates": updates})
        emit(source="human", event_type="approval_required", status="waiting", origin="state_transition",
             title="SOC analyst approval required",
             detail="Waiting for an analyst to approve or reject the Investigation result.",
             span_id=_approval_span(scope.run_id, scope.stage_attempt))
    elif status == "Failed":
        emit(source="orchestration", event_type="stage_settled", status="failed", origin="state_transition",
             title="Investigation marked Failed",
             detail=_str(updates.get("last_error")) or "Reporting is blocked until Investigation is re-run.",
             metadata={"status_updates": updates})


def _complete_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or call.get("stage") != STAGE:
        return
    emit(source="orchestration", event_type="stage_settled", status="failed", origin="state_transition",
         title="Saving the Investigation result failed", detail=describe_exception(exc))


# ── Context, handoff, feedback loop ────────────────────────────────────────

def _feedback_before(call: dict):
    """investigate_with_feedback() receives exactly the context the stage
    loaded; report what was (and was not) available, then return nothing."""
    scope = _scope()
    if scope is None:
        return None
    triage = call.get("triage_result") or {}
    ticket = triage.get("ticket") or {}
    ti = call.get("threat_intel_result") or {}
    parsing = call.get("parsing_result") or {}
    incident = call.get("incident") or {}
    emit(source="system", event_type="context_loaded", status="completed" if ticket else "warning",
         title="Loaded Triage result" if ticket else "No Triage result available",
         detail=(" · ".join(p for p in (f"classification {ticket.get('classification')}" if ticket.get("classification") else "",
                                         f"ticket {ticket.get('unc')}" if ticket.get("unc") else "") if p)))
    emit(source="system", event_type="context_loaded",
         status="completed" if ti.get("status") and ti.get("status") != "failed" else "warning",
         title=("Loaded Threat Intelligence result" if ti.get("status") and ti.get("status") != "failed"
                else "No usable Threat Intelligence result available"),
         detail=(f"enrichment risk {ti.get('enrichment_risk_level')} (score {ti.get('enrichment_risk_score')})"
                 if ti.get("enrichment_risk_level") else ""))
    emit(source="system", event_type="context_loaded",
         status="completed" if parsing.get("processed_alert") else "warning",
         title="Loaded Parsing result" if parsing.get("processed_alert") else "No persisted Parsing result available")
    emit(source="system", event_type="context_loaded", status="completed" if incident else "warning",
         title="Loaded raw incident" if incident else "Raw incident artifact unavailable",
         detail=_str(incident.get("title") or incident.get("name")))
    return None


def _feedback_after(call: dict, token: Any, inv: Any) -> None:
    scope = _scope()
    if scope is None or not isinstance(inv, dict):
        return
    status = _str(inv.get("status"))
    if status == "lock_lost":
        return  # reported by the stage entry point when it discards the result
    if status == "failed":
        emit(source="decision", event_type="stage_result", status="failed", title="Investigation failed",
             detail=sanitize_text(inv.get("error") or "The Investigation agent did not produce a result.", 400),
             metadata=_group(scope))
        return
    loop = inv.get("feedback_loop") or {}
    divergence = inv.get("severity_divergence") or {}
    limited = status == "completed_limited"
    emit(source="decision", event_type="stage_result", status="warning" if limited else "completed",
         title=("Investigation completed with limitations" if limited else "Investigation completed"),
         detail=" · ".join(p for p in (
             f"Severity {inv.get('severity')}" if inv.get("severity") else "",
             f"confidence {inv.get('confidence')}" if inv.get("confidence") else "",
             f"{loop.get('passes')} feedback re-run(s)" if loop.get("triggered") else "",
         ) if p),
         metadata={"details": details.blocks(
             details.fields([
                 ("Status", status.replace("_", " ")),
                 ("Severity", inv.get("severity")),
                 ("Confidence", inv.get("confidence")),
                 ("Incident folder", inv.get("incident_folder")),
                 ("Correlated alerts", ", ".join(inv.get("cluster_alert_ids") or [])),
                 ("Result source", (inv.get("workflow") or {}).get("investigation_source", "").replace("_", " ")),
                 ("Severity vs Triage", f"{divergence.get('direction')} (Triage {divergence.get('triage')}, "
                                        f"Investigation {divergence.get('investigation')})" if divergence else None),
                 ("Classification suggested by the deep-dive (not applied)", loop.get("suggested_classification")),
             ]),
             details.items("Recommended containment", inv.get("recommended_containment")),
             details.items("Evidence gaps that triggered the feedback loop", loop.get("gaps")),
             details.items("Missing evidence", inv.get("missing_evidence")),
         )})


def _alert_after(call: dict, token: Any, alert: Any) -> None:
    scope = _scope()
    if scope is not None and isinstance(alert, dict):
        scope.data["last_alert"] = alert


def _handoff_after(call: dict, token: Any, path: Any) -> None:
    scope = _scope()
    if scope is None:
        return
    alert = scope.data.pop("last_alert", {}) or {}
    classification = alert.get("classification") or {}
    mitre = (alert.get("incident_details") or {}).get("mitre_att&ck") or {}
    supplement = call.get("supplement")
    if supplement:
        first = scope.data.get("first_handoff_tactic")
        now = _str(mitre.get("tactic"))
        redirected = f"MITRE tactic for playbook selection: '{first}' → '{now}'" if first and now and first != now else None
        emit(source="system", event_type="handoff", status="completed",
             title="Investigation handoff rewritten with the triage deep-dive supplement",
             detail=f"Feedback pass {supplement.get('feedback_pass')} · {len(supplement.get('requested_gaps') or [])} gap(s) addressed",
             metadata={"details": details.blocks(details.fields([("Playbook redirection", redirected)]))})
        return
    scope.data["first_handoff_tactic"] = _str(mitre.get("tactic"))
    emit(source="system", event_type="handoff", status="completed",
         title="Investigation handoff written",
         detail="Alert queued for the Investigation agent",
         metadata={"details": details.blocks(details.fields([
             ("Triage classification", classification.get("severity")),
             ("Incident category", classification.get("alert_type")),
             ("MITRE tactic", mitre.get("tactic")),
             ("MITRE technique", mitre.get("technique")),
             ("Related alerts included", len(alert.get("alerts") or []) or None),
             ("Threat Intelligence context included", "yes" if alert.get("threat_intelligence_summary") else "no"),
         ]))})


def _gaps_after(call: dict, token: Any, gaps: Any) -> None:
    scope = _scope()
    if scope is None or not isinstance(gaps, list):
        return
    emit(source="rule", event_type="evidence_gaps", status="warning" if gaps else "completed",
         title=f"Evidence-gap check: {len(gaps)} gap(s) detected" if gaps
         else "Evidence-gap check: no significant gaps",
         detail=("The feedback loop asks the triage deep-dive to address them." if gaps
                 else "No re-run is needed."),
         metadata={**_group(scope), "gap_count": len(gaps),
                   "details": details.blocks(details.items("Gaps (rule-based, from the playbook trace)", gaps))})


def _deep_dive_before(call: dict):
    scope = _scope()
    if scope is None:
        return None
    span = new_span_id()
    gaps = call.get("gaps") or []
    emit(source="ai", ai_content_kind="assessment", event_type="deep_dive", status="running",
         title="Triage deep-dive supplement started",
         detail=f"Model asked to answer {len(gaps)} evidence gap(s) from the raw incident", span_id=span)
    return {"span": span, "parent_token": context.set_parent_span(span), "start": time.monotonic()}


def _deep_dive_after(call: dict, token: Any, supp: Any) -> None:
    if _scope() is None or not token or not isinstance(supp, dict):
        return
    findings = supp.get("gap_findings") or {}
    confidence = supp.get("confidence_per_gap") or {}
    answered = [k for k, v in findings.items() if "not present" not in str(v).lower()]
    emit(source="ai", ai_content_kind="explanation", event_type="deep_dive", status="completed",
         title="Triage deep-dive supplement completed",
         detail=f"{len(answered)} of {len(findings)} gap(s) answered" + (
             f" · {supp.get('deep_dive_summary')}" if supp.get("deep_dive_summary") else ""),
         span_id=token["span"],
         metadata={"duration_ms": int((time.monotonic() - token["start"]) * 1000),
                   "details": details.blocks(
                       details.text("Deep-dive summary (returned by the model)", supp.get("deep_dive_summary")),
                       details.items("Gap findings (returned by the model)",
                                     [f"{gap} — {finding}" + (f" (confidence {confidence.get(gap)})" if confidence.get(gap) else "")
                                      for gap, finding in findings.items()]),
                       details.fields([
                           ("Suggested MITRE tactic", supp.get("mitre_tactic")),
                           ("Suggested incident category", supp.get("incident_category")),
                           ("Suggested classification (recorded for the analyst, never applied)", supp.get("classification")),
                       ], label="Suggestions returned by the model"),
                       details.items("Suggested evidence queries",
                                     [f"{k}: {v}" for k, v in (supp.get("actionable_queries") or {}).items()]),
                   )})


def _deep_dive_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or not token:
        return
    emit(source="ai", ai_content_kind="assessment", event_type="deep_dive", status="failed",
         title="Triage deep-dive supplement failed", detail=describe_exception(exc), span_id=token["span"])
    emit(source="system", event_type="fallback", status="warning",
         title="Feedback loop stopped — the first run's findings are kept", metadata={"fallback": True})


def _cleanup_parent(call: dict, token: Any) -> None:
    if token and token.get("parent_token") is not None:
        context.reset_parent_span(token["parent_token"])


# ── Agent subprocess runs ───────────────────────────────────────────────────

def _run_before(call: dict):
    scope = _scope()
    if scope is None:
        return None
    scope.data["run_no"] = scope.data.get("run_no", 0) + 1
    run_no = scope.data["run_no"]
    if run_no > 1:
        emit(source="orchestration", event_type="feedback_rerun", status="completed",
             title="Starting a second Investigation run",
             detail="Re-running the Investigation agent with the triage deep-dive supplement.",
             metadata=_group(scope))
    span = new_span_id()
    reader = _LogReader(scope, span)
    scope.data["log_reader"] = reader
    emit(source="system", event_type="agent_run", status="running",
         title=f"Investigation agent run {run_no} started",
         detail="Separate process: python main.py (the agent's progress appears below as it logs it).",
         span_id=span, metadata=_group(scope))
    return {"span": span, "reader": reader, "start": time.monotonic()}


def _run_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None or not token or not isinstance(result, dict):
        return
    reader: _LogReader = token["reader"]
    status = _str(result.get("status"))
    elapsed = details.format_duration_ms((time.monotonic() - token["start"]) * 1000)
    sub = result.get("subprocess") or {}
    raw_block = ({"type": "log", "label": f"Raw agent log — {reader.unclassified} unclassified line(s), sanitised",
                  "lines": list(reader.raw)} if reader.raw else None)
    titles = {"completed": "completed", "completed_limited": "completed with limitations",
              "failed": "failed", "lock_lost": "stopped — workspace lock lost"}
    emit(source="system", event_type="agent_run",
         status={"completed": "completed", "completed_limited": "warning"}.get(status, "failed"),
         title=f"Investigation agent run {scope.data.get('run_no')} {titles.get(status, status or 'ended')}",
         detail=" · ".join(p for p in (
             f"exit code {sub.get('returncode')}" if sub.get("returncode") is not None else "",
             f"{reader.classified} recognised log line(s)", elapsed) if p),
         span_id=token["span"],
         metadata={**_group(scope), "details": details.blocks(
             details.fields([("Incident folder", result.get("incident_folder")),
                             ("Run status", status.replace("_", " ")),
                             ("Pivot retrieval matches", reader.pivot_matches or None)]),
             details.text("Error", sanitize_text(result.get("error"), 400) if status == "failed" else None),
             raw_block)})
    analysis = result.get("investigation_analysis") or {}
    justification = _str(analysis.get("severity_justification") or result.get("severity_justification"))
    if justification.lower().startswith("fallback due to error"):
        emit(source="system", event_type="fallback", status="warning",
             title="Result is the deterministic fallback report — not an AI analysis",
             detail=justification[:300], metadata={**_group(scope), "fallback": True})
    elif analysis:
        trace = analysis.get("execution_trace") or []
        met = sum(1 for s in trace if s.get("status") == "MET")
        emit(source="ai", ai_content_kind="explanation", event_type="analysis_output", status="completed",
             title="Final analysis returned by the Investigation agent",
             detail=f"Severity {analysis.get('severity')} · confidence {analysis.get('confidence')} · "
                    f"{met} of {len(trace)} playbook step(s) met",
             metadata={**_group(scope), "details": details.blocks(
                 details.text("Severity justification", analysis.get("severity_justification")),
                 details.text("Confidence justification", analysis.get("confidence_justification")),
                 details.text("Incident summary", analysis.get("incident_summary")),
                 details.items("Playbook steps", [f"{s.get('step_id')} — {s.get('status')}: {s.get('findings')}"
                                                  for s in trace]),
                 details.items("Recommended containment", analysis.get("recommended_containment")),
                 details.items("MITRE ATT&CK mappings", [f"{m.get('technique_id')} {m.get('technique_name')} "
                                                         f"({m.get('tactic')})" for m in analysis.get("mitre_mappings") or []]),
                 details.note("Fields returned by the agent's final model pass; not a record of the model's private reasoning."),
             )})


def _run_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or not token:
        return
    emit(source="system", event_type="agent_run", status="failed",
         title="Investigation agent run raised an error", detail=describe_exception(exc), span_id=token["span"])


def _tee_lines(call: dict, original: Any):
    scope = _scope()
    reader = scope.data.get("log_reader") if scope is not None else None
    if reader is None:
        return None

    def observed_line_cb(line):
        try:
            reader.feed(line)
        except Exception:
            pass
        if original is not None:
            original(line)

    return observed_line_cb


def _structured_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None or not isinstance(result, tuple) or len(result) != 2:
        return
    output, source = result
    if source == "structured_json" and output is not None:
        emit(source="system", event_type="result_source", status="completed",
             title="Structured Investigation result validated",
             detail="investigation_analysis.json matched the Investigation result contract.",
             metadata=_group(scope))
        return
    try:
        present = (Path(call.get("target")) / "investigation_analysis.json").exists()
    except Exception:
        present = None
    emit(source="system", event_type="result_source", status="warning",
         title="Structured Investigation result unavailable — result reconstructed from the Markdown report",
         detail=("investigation_analysis.json was present but rejected (malformed, invalid or for another incident)."
                 if present else "investigation_analysis.json was not written by the agent."),
         metadata={**_group(scope), "fallback": True})


def _divergence_after(call: dict, token: Any, result: Any) -> None:
    scope = _scope()
    if scope is None:
        return
    inv = call.get("inv") or {}
    div = inv.get("severity_divergence")
    if div:
        emit(source="rule", event_type="severity_divergence", status="warning",
             title=f"Investigation {div.get('direction')} severity relative to Triage",
             detail=f"Triage {div.get('triage')} → Investigation {div.get('investigation')}; an analyst should reconcile.",
             metadata=_group(scope))
    elif inv.get("severity") and call.get("triage_classification"):
        emit(source="rule", event_type="severity_divergence", status="completed",
             title="Investigation severity consistent with the Triage classification",
             detail=f"{inv.get('severity')} / {call.get('triage_classification')}", metadata=_group(scope))


def _reconcile_after(call: dict, token: Any, result: Any) -> None:
    if _scope() is None or not call.get("unc") or not call.get("final_severity"):
        return
    # reconcile_incident_severity() does not report whether a matching
    # ticket was found (it skips silently), so claim only the attempt.
    emit(source="system", event_type="severity_recorded", status="completed",
         title=f"Ticket {call.get('unc')} annotation with the Investigation severity attempted",
         detail="Best effort: the Triage classification is kept unchanged; the annotation step does not "
                "report whether a matching ticket was found.")


# ── Post-stage summary (raw SDK) ────────────────────────────────────────────

def _summary_before(call: dict):
    scope = _scope()
    if scope is None or _str(call.get("stage")) != "Investigation":
        return None
    span = new_span_id()
    scope.data["summary_span"] = span
    emit(source="ai", ai_content_kind="summary", event_type="ai_summary", status="running",
         title="Post-stage AI summary started", detail=_POST_STAGE_NOTE, span_id=span,
         metadata={"post_stage": True})
    return {"span": span, "start": time.monotonic()}


def _summary_after(call: dict, token: Any, result: Any) -> None:
    if _scope() is None or not token or not isinstance(result, dict):
        return
    elapsed_ms = int((time.monotonic() - token["start"]) * 1000)
    summary = _str(result.get("ai_summary"))
    unavailable = summary.lower().startswith("ai summary unavailable")
    emit(source="ai", ai_content_kind="summary", event_type="ai_summary",
         status="warning" if unavailable else "completed",
         title="Post-stage AI summary unavailable" if unavailable else "Post-stage AI summary generated",
         detail=summary, span_id=token["span"],
         metadata={"post_stage": True, "model": result.get("ai_summary_model"), "duration_ms": elapsed_ms,
                   "details": details.blocks(details.note(_POST_STAGE_NOTE), details.text("Summary", summary),
                                             details.fields([("Model", result.get("ai_summary_model")),
                                                             ("Duration", details.format_duration_ms(elapsed_ms))]))})


def _summary_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or not token:
        return
    emit(source="ai", ai_content_kind="summary", event_type="ai_summary", status="failed",
         title="Post-stage AI summary failed", detail=describe_exception(exc), span_id=token["span"],
         metadata={"post_stage": True})


def _summary_cleanup(call: dict, token: Any) -> None:
    scope = _scope()
    if scope is not None:
        scope.data.pop("summary_span", None)


def _model_request_before(call: dict):
    scope = _scope()
    if scope is None or not scope.data.get("summary_span"):
        return None
    model = _str(call.get("model")) or "default (OPENAI_MODEL)"
    span = new_span_id()
    emit(source="ai", ai_content_kind="summary", event_type="llm_call", status="running",
         title="Model request sent", detail=f"Model: {model}", span_id=span,
         parent_span_id=scope.data["summary_span"], metadata={"model": model})
    return {"span": span, "model": model, "parent": scope.data["summary_span"], "start": time.monotonic()}


def _model_request_after(call: dict, token: Any, result: Any) -> None:
    if _scope() is None or not token:
        return
    elapsed_ms = int((time.monotonic() - token["start"]) * 1000)
    emit(source="ai", ai_content_kind="summary", event_type="llm_call", status="completed",
         title="Model response received",
         detail=f"Model: {token['model']} · {details.format_duration_ms(elapsed_ms)}",
         span_id=token["span"], parent_span_id=token["parent"],
         metadata={"model": token["model"], "duration_ms": elapsed_ms})


def _model_request_error(call: dict, token: Any, exc: BaseException) -> None:
    if _scope() is None or not token:
        return
    emit(source="ai", ai_content_kind="summary", event_type="llm_call", status="failed",
         title="Model request failed", detail=describe_exception(exc),
         span_id=token["span"], parent_span_id=token["parent"], metadata={"model": token["model"]})


# ── Analyst actions ────────────────────────────────────────────────────────

def _request_after(kind: str):
    def after(call: dict, token: Any, result: Any) -> None:
        if call.get("stage") != STAGE:
            return
        incident_id = str(call.get("incident_id"))
        attempt = _state(incident_id).get("investigation_attempt")
        emit(source="orchestration", event_type="stage_requested", status="completed", origin="state_transition",
             title="Investigation re-run requested" if kind == "rerun" else "Investigation run requested",
             detail=f"Attempt {attempt or '—'} · stage set to Processing and a worker dispatched.",
             case_id=incident_id, run_id=call.get("run_id"), stage=STAGE, stage_attempt=attempt)

    return after


def _decision_after(decision: str):
    def after(call: dict, token: Any, result: Any) -> None:
        incident_id = str(call.get("incident_id"))
        state = _state(incident_id)
        attempt = state.get("investigation_attempt")
        analyst = _str(call.get("approved_by") if decision == "approve" else call.get("rejected_by"))
        comment = _str(call.get("comments") if decision == "approve" else call.get("reason"))
        ids = {"case_id": incident_id, "run_id": call.get("run_id"), "stage": STAGE, "stage_attempt": attempt}
        emit(source="human", event_type="approval_decision", status="completed", origin="state_transition",
             title=f"Investigation {'approved' if decision == 'approve' else 'rejected'} by {analyst or 'analyst'}",
             detail=comment or ("No comment provided." if decision == "approve" else ""),
             span_id=_approval_span(call.get("run_id"), attempt),
             metadata={"decision": decision, "analyst": analyst}, **ids)
        if decision == "approve" and state.get("reporting_status"):
            emit(source="orchestration", event_type="routing", status="info", origin="state_transition",
                 title="Reporting unlocked",
                 detail=f"Reporting status: {state.get('reporting_status')} (it runs only when an analyst starts it).",
                 **ids)

    return after


def install(patcher: Patcher) -> None:
    engine = "workflow.engine"
    patcher.wrap(Target(engine, "run_investigation_stage", ("incident_id", "run_id")),
                 Hooks(scope=_stage_scope, error=_stage_error))
    patcher.wrap(Target(engine, "claim_stage",
                        ("incident_id", "run_id", "stage", "status_column", "expect_status")),
                 Hooks(after=_claim_after, error=_claim_error))
    patcher.wrap(Target(engine, "acquire_global_lock",
                        ("lock_name", "owner_id", "incident_id", "run_id", "ttl_seconds")),
                 Hooks(after=_lock_after, error=_lock_error))
    patcher.wrap(Target(engine, "investigate_with_feedback",
                        ("triage_result", "incident", "inc_id", "timeout", "line_cb", "feedback_cb",
                         "max_passes", "threat_intel_result", "watchdog_cb", "parsing_result")),
                 Hooks(before=_feedback_before, after=_feedback_after))
    patcher.wrap(Target(engine, "build_investigation_alert",
                        ("triage_result", "incident", "supplement", "threat_intel_result", "parsing_result")),
                 Hooks(after=_alert_after))
    patcher.wrap(Target(engine, "handoff_to_investigation",
                        ("triage_result", "incident", "supplement", "threat_intel_result", "parsing_result")),
                 Hooks(after=_handoff_after))
    patcher.wrap(Target(engine, "run_investigation",
                        ("incident_id", "timeout", "line_cb", "triage_classification", "watchdog_cb")),
                 Hooks(before=_run_before, after=_run_after, error=_run_error))
    patcher.wrap(Target(engine, "_run_subprocess_streaming",
                        ("cmd", "cwd", "timeout", "extra_env", "line_cb", "watchdog_cb", "watchdog_interval")),
                 Hooks(tee_callback=("line_cb", _tee_lines)))
    patcher.wrap(Target(engine, "_load_structured_investigation_analysis", ("target", "cluster_ids")),
                 Hooks(after=_structured_after))
    patcher.wrap(Target(engine, "_annotate_severity_divergence", ("inv", "triage_classification")),
                 Hooks(after=_divergence_after))
    patcher.wrap(Target(engine, "reconcile_incident_severity", ("incident_id", "unc", "final_severity")),
                 Hooks(after=_reconcile_after))
    patcher.wrap(Target(engine, "detect_evidence_gaps", ("inv",)), Hooks(after=_gaps_after))
    patcher.wrap(Target("agents.triage", "deep_triage_supplement", ("incident", "gaps", "cfg", "thinking_container")),
                 Hooks(before=_deep_dive_before, after=_deep_dive_after, error=_deep_dive_error,
                       cleanup=_cleanup_parent))
    patcher.wrap(Target(engine, "generate_stage_ai_summary", ("stage", "stage_result", "model")),
                 Hooks(before=_summary_before, after=_summary_after, error=_summary_error,
                       cleanup=_summary_cleanup))
    patcher.wrap(Target("integrations.openai.client", "invoke_openai_text",
                        ("prompt", "system", "model", "temperature", "max_output_tokens", "timeout", "text_format")),
                 Hooks(before=_model_request_before, after=_model_request_after, error=_model_request_error))
    patcher.wrap(Target(engine, "complete_stage",
                        ("incident_id", "run_id", "worker_id", "stage", "result_column", "result",
                         "status_updates", "expected_stage_attempt")),
                 Hooks(after=_complete_after, error=_complete_error))
    patcher.wrap(Target("workflow.state_store", "begin_stage", ("incident_id", "run_id", "stage")),
                 Hooks(after=_request_after("start")))
    patcher.wrap(Target("workflow.state_store", "rerun_stage", ("incident_id", "run_id", "stage")),
                 Hooks(after=_request_after("rerun")))
    patcher.wrap(Target("workflow.state_store", "approve_investigation",
                        ("incident_id", "run_id", "approved_by", "comments")),
                 Hooks(after=_decision_after("approve")))
    patcher.wrap(Target("workflow.state_store", "reject_investigation",
                        ("incident_id", "run_id", "rejected_by", "reason")),
                 Hooks(after=_decision_after("reject")))
