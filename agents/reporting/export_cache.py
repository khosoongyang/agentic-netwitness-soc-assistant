# ==============================================================================
# [FYP-FILE] File: soc_reporting_agent/backend/export_cache.py
# Important dependencies: __future__, datetime, hashlib, json, pathlib, typing.
#
# Purpose:
#   Content-hash-based caching layer for generated report/agent export
#   artifacts (Word .docx / PDF / JSON). Generating a Word document (and
#   converting it to PDF) is comparatively expensive and involves an LLM
#   call in the caller (see reporting/template_document_exporter.py), so
#   this module lets callers skip regeneration when the underlying source
#   data has not changed since the last successful export.
#
# Main functionalities:
#   - calculate_source_hash / file_digest: [FYP-EXPORT] compute a stable
#     SHA-256 fingerprint over a set of source files (+ optional extra
#     payload), used as the cache key's "is the input the same" check.
#   - load_metadata / save_metadata: read/write the per-export-directory
#     `_export_cache.json` metadata file (version + entries keyed by format,
#     e.g. "docx"/"pdf"/"json").
#   - is_cache_ready: [FYP-EXPORT] [FYP-EVALUATOR] the core cache-hit check
#     -- true only when a metadata entry exists, is marked "ready", its
#     stored source_hash matches the freshly computed one, AND the actual
#     output file still exists on disk with non-zero size.
#   - mark_export_status: [FYP-EXPORT] record a cache entry's status
#     (e.g. "generating" / "ready" / "failed") plus source_hash/path/message,
#     merging onto any previous entry for that key.
#   - normalise_status / collect_ticket_export_status: read-only helpers
#     that summarise cache readiness for the dashboard's export-status UI,
#     without generating anything.
#
# Inputs:
#   - export_dir: Path -- the directory holding a given export's
#     `_export_cache.json` and generated file(s) (typically
#     outputs/exports/<ticket>/agents/<agent>/ or
#     outputs/exports/<ticket>/reporting/<report>/).
#   - source_files: Iterable[Path] -- the files whose content determines
#     whether a cached export is still valid (e.g. the agent's *_result.json).
#   - output_dir / ticket_id -- for collect_ticket_export_status, to locate
#     the ticket's exports/ tree.
#
# Outputs:
#   - calculate_source_hash() -> str (hex SHA-256).
#   - is_cache_ready() -> bool.
#   - mark_export_status() -> None (side effect: writes `_export_cache.json`
#     via save_metadata).
#   - collect_ticket_export_status() -> dict[str, Any] summarising cache
#     status per agent/report and format.
#
# Workflow position:
#   Used exclusively around export generation (Word/PDF/JSON document
#   creation for an agent's output or a full incident report), which itself
#   runs after the corresponding pipeline stage has produced a result. This
#   module does not know about stage_workflow/orchestration_service at all
#   -- it is a narrow, stage-agnostic caching utility.
#
# Called by:
#   - soc_reporting_agent/backend/app.py
#     (`from backend.export_cache import collect_ticket_export_status`),
#     used by the dashboard's export-status API endpoint.
#   - soc_reporting_agent/reporting/template_document_exporter.py
#     (`from backend.export_cache import calculate_source_hash, is_cache_ready,
#     mark_export_status`), used around the actual docx/pdf generation calls
#     to skip regenerating an export whose inputs have not changed.
#
# Calls:
#   - Standard library only (hashlib, json, pathlib, datetime). No calls
#     into other backend/ modules.
#
# Key evaluator search terms:
#   export cache, is_cache_ready, mark_export_status, source_hash,
#   calculate_source_hash, _export_cache.json, collect_ticket_export_status.
# ==============================================================================

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


# =============================================================================
# [FYP-SECTION] REPORTING BACKEND AND API EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================


def utc_now() -> str:
    """[FYP-FUNCTION] Current UTC timestamp, ISO-8601. Used to stamp cache entry updated_at/generated_at fields."""
    return datetime.now(timezone.utc).isoformat()


def safe_filename(value: Any) -> str:
    """[FYP-FUNCTION] Sanitise an arbitrary value into a filesystem-safe filename fragment (alnum/underscore/dot/hyphen only, truncated to 120 chars, "unknown" fallback)."""
    import re
    text = str(value or "unknown")
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_")
    return text[:120] or "unknown"


def _json_default(value: Any) -> str:
    """[FYP-FUNCTION] [FYP-FALLBACK] json.dumps default= hook: stringify anything not natively JSON-serialisable, or a placeholder if even str() fails."""
    try:
        return str(value)
    except Exception:
        return "<unserialisable>"


def stable_json(value: Any) -> bytes:
    """[FYP-FUNCTION] Serialise `value` to JSON bytes deterministically (sorted keys, stable float/str formatting) so identical logical content always hashes the same."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=_json_default).encode("utf-8")


def file_digest(path: Path) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-EXPORT] Compute a SHA-256 content digest plus size/mtime metadata for one file.

    Params: path -- file to hash.
    Returns: {"path", "exists": False} if the file is missing/not a file;
    otherwise {"path", "exists": True, "size", "mtime_ns", "sha256"}.
    Reads the file in 1 MiB chunks to avoid loading large exports fully into
    memory.
    Called by: calculate_source_hash (below).
    """
    path = Path(path)
    if not path.exists() or not path.is_file():
        return {"path": str(path), "exists": False}
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    stat = path.stat()
    return {
        "path": str(path),
        "exists": True,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "sha256": h.hexdigest(),
    }


def calculate_source_hash(*, source_files: Iterable[Path], extra_payload: Any | None = None) -> str:
    """[FYP-FUNCTION] [FYP-EXPORT] Compute the cache key's "source fingerprint": one SHA-256 over the digests of all source_files plus an optional extra_payload.

    Params: source_files -- the files whose content determines cache
    validity (e.g. the agent's *_result.json); extra_payload -- any
    additional JSON-serialisable data that should also invalidate the cache
    when it changes (e.g. a template version marker).
    Returns: hex SHA-256 string.
    Called by: reporting/template_document_exporter.py, before calling
    is_cache_ready()/mark_export_status() around export generation.
    Calls: file_digest, stable_json.
    """
    payload = {
        "files": [file_digest(Path(path)) for path in source_files],
        "extra": extra_payload or {},
    }
    return hashlib.sha256(stable_json(payload)).hexdigest()


def metadata_path(export_dir: Path) -> Path:
    """[FYP-FUNCTION] Path to the per-export-directory cache metadata file, `_export_dir/_export_cache.json`."""
    return Path(export_dir) / "_export_cache.json"


def load_metadata(export_dir: Path) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-FALLBACK] Read `_export_cache.json` for export_dir, tolerating a missing/empty/corrupt file.

    Returns: {"version": 1, "entries": {...}} -- always this shape, even
    when the file does not exist or fails to parse (falls back to an empty
    {"version": 1, "entries": {}} rather than raising).
    Called by: cache_entry, is_cache_ready, mark_export_status,
    collect_ticket_export_status (this file).
    """
    path = metadata_path(export_dir)
    if not path.exists() or path.stat().st_size == 0:
        return {"version": 1, "entries": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data.setdefault("version", 1)
            data.setdefault("entries", {})
            return data
    except Exception:
        pass
    return {"version": 1, "entries": {}}


def save_metadata(export_dir: Path, metadata: dict[str, Any]) -> Path:
    """[FYP-FUNCTION] [FYP-OUTPUT] Write the cache metadata dict to `_export_cache.json`, creating export_dir if needed. Returns the written path."""
    path = metadata_path(export_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def cache_entry(export_dir: Path, key: str) -> dict[str, Any] | None:
    """[FYP-FUNCTION] Read a single cache entry (by format key, e.g. "docx") for export_dir, or None if absent/malformed."""
    entry = load_metadata(export_dir).get("entries", {}).get(key)
    return entry if isinstance(entry, dict) else None


def is_cache_ready(export_dir: Path, key: str, file_path: Path, source_hash: str) -> bool:
    """[FYP-FUNCTION] [FYP-EXPORT] [FYP-EVALUATOR] Decide whether a previously generated export can be reused as-is (cache hit).

    Params: export_dir -- directory holding the cache metadata; key --
    format key ("docx"/"pdf"/"json"); file_path -- expected generated file
    location; source_hash -- freshly computed calculate_source_hash() value
    to compare against the stored one.
    Returns: True only if ALL of: a cache entry exists for key, its status
    is "ready", its stored source_hash equals the passed-in source_hash
    (i.e. nothing the export depends on has changed), AND file_path actually
    exists on disk with non-zero size (guards against the metadata saying
    "ready" while the file was deleted/moved out from under it).
    Called by: reporting/template_document_exporter.py, immediately before
    regenerating a Word/PDF/JSON export -- this is the actual cache-hit
    decision point that skips expensive regeneration (including the LLM
    call used to build report content) when nothing has changed.
    Calls: cache_entry.
    """
    entry = cache_entry(export_dir, key)
    if not entry:
        return False
    if entry.get("status") != "ready":
        return False
    if entry.get("source_hash") != source_hash:
        return False
    return Path(file_path).exists() and Path(file_path).stat().st_size > 0


def mark_export_status(
    export_dir: Path,
    *,
    key: str,
    status: str,
    source_hash: str | None = None,
    file_path: Path | None = None,
    message: str | None = None,
    related_paths: dict[str, str] | None = None,
) -> None:
    """[FYP-FUNCTION] [FYP-EXPORT] [FYP-STATE] Record/update a cache entry's status for one export format.

    Params: export_dir -- directory holding the cache metadata; key --
    format key; status -- new status string (e.g. "generating"/"ready"/
    "failed"); source_hash/file_path/message/related_paths -- optional
    fields to set/update on the entry.
    Returns: None. Side effect: [FYP-OUTPUT] merges the new fields onto any
    previous entry for `key` (previous fields are preserved unless
    overwritten) and persists via save_metadata(). When status == "ready",
    also stamps a fresh generated_at timestamp.
    Called by: reporting/template_document_exporter.py, before starting
    generation (status="generating"), after success (status="ready", with
    source_hash/file_path), and after failure (status="failed", with
    message).
    Calls: load_metadata, utc_now, save_metadata.
    """
    metadata = load_metadata(export_dir)
    entries = metadata.setdefault("entries", {})
    previous = entries.get(key, {}) if isinstance(entries.get(key), dict) else {}
    entry = {
        **previous,
        "status": status,
        "updated_at": utc_now(),
    }
    if source_hash is not None:
        entry["source_hash"] = source_hash
    if file_path is not None:
        entry["path"] = str(file_path)
    if message is not None:
        entry["message"] = message
    if related_paths:
        entry["related_paths"] = related_paths
    if status == "ready":
        entry["generated_at"] = utc_now()
    entries[key] = entry
    save_metadata(export_dir, metadata)


def normalise_status(entry: dict[str, Any] | None, file_path: Path | None = None) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-VALIDATION] Turn a raw cache entry into the small status dict the dashboard displays.

    Params: entry -- raw cache_entry() dict (or None); file_path -- optional
    override path to verify existence against (defaults to entry["path"]).
    Returns: {"status", "generated_at", "updated_at", "message", "path"}.
    If the entry claims "ready" but the file no longer exists on disk, the
    reported status is downgraded to "not_generated" (and path omitted) so
    the UI never claims an export is ready when it is not actually present.
    Called by: collect_ticket_export_status (below).
    """
    if not entry:
        return {"status": "not_generated"}
    status = entry.get("status") or "not_generated"
    path = Path(file_path or entry.get("path") or "") if (file_path or entry.get("path")) else None
    if status == "ready" and path and not path.exists():
        status = "not_generated"
    return {
        "status": status,
        "generated_at": entry.get("generated_at"),
        "updated_at": entry.get("updated_at"),
        "message": entry.get("message"),
        "path": entry.get("path") if status == "ready" else None,
    }


def collect_ticket_export_status(output_dir: Path, ticket_id: str) -> dict[str, Any]:
    """Return cache readiness for dashboard display.

    This does not generate any files. It only reads export metadata and checks
    known export directories.

    [FYP-FUNCTION] [FYP-EXPORT] Params: output_dir -- outputs/ root;
    ticket_id -- ticket identifier (sanitised via safe_filename internally
    through the exports/<ticket_safe>/ path convention).
    Returns: {"ticket_id", "agents": {<agent>: {"docx": status, "pdf":
    status, "json": status}}, "reporting": {<report>: {...same...}}} where
    each per-format status comes from normalise_status().
    Called by: backend/app.py, the dashboard's export-status API endpoint
    (read-only status query, no generation triggered).
    Calls: safe_filename, load_metadata, normalise_status.
    """
    ticket_safe = safe_filename(ticket_id)
    root = Path(output_dir) / "exports" / ticket_safe
    result: dict[str, Any] = {"ticket_id": ticket_id, "agents": {}, "reporting": {}}

    agents_root = root / "agents"
    if agents_root.exists():
        for agent_dir in sorted(p for p in agents_root.iterdir() if p.is_dir()):
            meta = load_metadata(agent_dir)
            agent_status: dict[str, Any] = {}
            for fmt in ["docx", "pdf", "json"]:
                entry = meta.get("entries", {}).get(fmt)
                agent_status[fmt] = normalise_status(entry)
            result["agents"][agent_dir.name] = agent_status

    reporting_root = root / "reporting"
    if reporting_root.exists():
        for report_dir in sorted(p for p in reporting_root.iterdir() if p.is_dir()):
            meta = load_metadata(report_dir)
            report_status: dict[str, Any] = {}
            for fmt in ["docx", "pdf", "json"]:
                entry = meta.get("entries", {}).get(fmt)
                report_status[fmt] = normalise_status(entry)
            result["reporting"][report_dir.name] = report_status

    return result
