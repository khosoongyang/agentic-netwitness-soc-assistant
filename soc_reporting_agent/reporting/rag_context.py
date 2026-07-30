"""
[FYP-FILE] reporting/rag_context.py (144 lines)
# File: soc_reporting_agent/reporting/rag_context.py
# Purpose: This module implements report generation and export behaviour for rag context.
# Inputs: Receives function arguments, configured state, and persisted artifacts described below.
# Outputs: Produces return values and documented state, file, database, export, or UI effects.
# Workflow position: Aegis report generation and export.
# Important dependencies: __future__, config, pathlib, typing.
# Key evaluator search terms: _chunk_text, _score, _context_text, _is_ransomware_context, _required_files_for_context, direct_file_retrieval, [FYP-FUNCTION].

[FYP-SECTION] Responsibility
[FYP-RAG] [FYP-KNOWLEDGE-BASE] Implements the Reporting Agent's
retrieval-augmented-generation (RAG) layer: given a built context dict,
retrieves relevant excerpts from the Reporting Agent's own local Markdown
knowledge base to ground report narratives/policy references. Two
retrieval backends are implemented and selected by settings.USE_CHROMADB:

- direct_file_retrieval(): no vector DB at all — reads a fixed,
  policy-driven list of whole Markdown files from disk
  (settings.KNOWLEDGE_BASE_DIR, defaulting to
  `soc_reporting_agent/knowledge_base/`), splits each into
  paragraph-batched ~1400-char chunks (_chunk_text()), and ranks chunks by
  a simple keyword-overlap heuristic (_score()) against a query string
  built from the incident's scenario/classification/severity.
- chromadb_retrieval(): [FYP-KNOWLEDGE-BASE] queries a persistent ChromaDB
  vector store at settings.CHROMA_DB_PATH (default
  `soc_reporting_agent/database/chromadb/chroma_store`), collection name
  settings.CHROMA_COLLECTION_NAME (default "reporting_knowledge_base"),
  embedded via OpenAI's "text-embedding-3-small" model
  (chromadb.utils.embedding_functions.OpenAIEmbeddingFunction, keyed by
  settings.OPENAI_API_KEY) — i.e. this backend is the one genuine
  vector-similarity knowledge-base query in this file; it requires both
  the `chromadb` package and a reachable OpenAI embeddings endpoint.

[FYP-KNOWLEDGE-BASE] The knowledge base itself (both backends draw from
the same underlying Markdown corpus) is the fixed policy/procedure/
playbook set in settings.REQUIRED_KB_FILES: incident_severity_policy.md,
containment_approval_policy.md, reporting_timeline_policy.md,
report_writing_sop.md, evidence_collection_sop.md, investigation_sop.md,
phishing_response_playbook.md, and (conditionally, see
_is_ransomware_context()) ransomware_response_playbook.md.

[FYP-EVALUATOR] retrieve_reporting_context() — the module's sole public
entry point — has NO confirmed in-repo caller as of this documentation
pass (searched agents/, scripts/, tests/, and the rest of reporting/: only
this file's own definition and a description in reporting/__init__.py's
pipeline-overview docstring reference it). context_builder.build_context()
does NOT call it; instead it hardcodes `"rag_used": True` and derives
`rag_status`/`rag_status_display` from a `reporting.get("rag_status")`
value sourced elsewhere (e.g. an upstream ticket_context/legacy export),
defaulting to the literal string "Local template export context built"
when absent (see context_builder.py around line 610-612). Confirm at
evaluation time whether this RAG module is wired in via a code path this
search missed, is legacy/planned-but-unwired, or is exercised only through
manual/ad-hoc invocation outside the standard pipeline run.

[FYP-USED-BY] No confirmed caller found in-repo (see [FYP-EVALUATOR] note
above); reporting/__init__.py's package overview docstring describes it as
the pipeline's knowledge-base retrieval step.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from config import settings


def _chunk_text(text: str, size: int = 1400) -> list[str]:
    """[FYP-FUNCTION] Split `text` on blank-line paragraph boundaries and
    greedily pack consecutive paragraphs into chunks no longer than `size`
    characters (default 1400), used to keep each retrieved knowledge-base
    excerpt small enough to be useful as report grounding context. A
    single paragraph longer than `size` is hard-truncated rather than
    split further."""
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: list[str] = []
    current = ""
    for paragraph in paragraphs:
        if len(current) + len(paragraph) + 2 <= size:
            current = f"{current}\n\n{paragraph}".strip()
        else:
            if current:
                chunks.append(current)
            current = paragraph[:size]
    if current:
        chunks.append(current)
    return chunks


def _score(query: str, chunk: str) -> int:
    """[FYP-FUNCTION] Keyword-overlap relevance score for
    direct_file_retrieval()'s non-vector ranking: tokenises `query` on
    whitespace (dropping words of length <=3 as too generic), lowercases,
    and counts how many distinct query terms appear as a substring of
    `chunk`. Higher is more relevant; used purely for relative ranking, not
    calibrated as a probability/similarity score."""
    terms = {term.lower() for term in query.replace("_", " ").split() if len(term) > 3}
    chunk_lower = chunk.lower()
    return sum(1 for term in terms if term in chunk_lower)


def _context_text(context: dict[str, Any]) -> str:
    """[FYP-FUNCTION] Flatten the incident-identifying fields of `context`
    (likely_scenario, classification, scenario_type, case_title,
    malware_family, relevant_playbook, severity label) into one lowercased
    space-joined string, used by _is_ransomware_context() to keyword-match
    against ransomware-related terms."""
    fields = [
        context.get("likely_scenario"),
        context.get("classification"),
        context.get("scenario_type"),
        context.get("case_title"),
        context.get("malware_family"),
        context.get("relevant_playbook"),
        context.get("severity", {}).get("label") if isinstance(context.get("severity"), dict) else context.get("severity"),
    ]
    return " ".join(str(value or "") for value in fields).lower()


def _is_ransomware_context(context: dict[str, Any]) -> bool:
    """[FYP-FUNCTION] Heuristic ransomware detector: True if any of a fixed
    term list ("wannacry", "wanna cry", "ransomware", "malware/ransomware",
    "ransomware-related") appears in _context_text(context). Drives
    _required_files_for_context()'s decision to include/exclude
    ransomware_response_playbook.md from the knowledge-base retrieval set,
    so non-ransomware incidents don't get an irrelevant playbook mixed
    into their report grounding context."""
    text = _context_text(context)
    return any(term in text for term in ("wannacry", "wanna cry", "ransomware", "malware/ransomware", "ransomware-related"))


def _required_files_for_context(context: dict[str, Any]) -> tuple[list[str], list[str]]:
    """[FYP-FUNCTION] [FYP-KNOWLEDGE-BASE] Build the (required, excluded)
    knowledge-base file lists for this incident from
    settings.REQUIRED_KB_FILES, conditionally swapping in/out the
    ransomware playbook based on _is_ransomware_context().

    [FYP-PROCESS] Starts from settings.REQUIRED_KB_FILES (policies +
    procedures + phishing_response_playbook.md, which is always included)
    and always excludes the legacy `malware_response_playbook.md` name. If
    the incident is ransomware-related, adds
    `playbooks/ransomware_response_playbook.md` to required and removes it
    from excluded; otherwise excludes it. The returned `excluded` list is
    surfaced to analysts (as `excluded_playbooks` in the RAG result) so
    it's visible *why* a given playbook wasn't consulted, not just that it
    wasn't.
    [FYP-USED-BY] direct_file_retrieval(), chromadb_retrieval(),
    retrieve_reporting_context() (for the disabled/error-path
    excluded_playbooks value)."""
    required = list(settings.REQUIRED_KB_FILES)
    excluded = ["malware_response_playbook.md"]
    ransomware_file = "playbooks/ransomware_response_playbook.md"
    if _is_ransomware_context(context):
        if ransomware_file not in required:
            required.append(ransomware_file)
        excluded = [item for item in excluded if item != "ransomware_response_playbook.md"]
    else:
        excluded.append("ransomware_response_playbook.md")
    return required, excluded


def direct_file_retrieval(context: dict[str, Any], kb_dir: Path, max_chunks: int = 5) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """[FYP-FUNCTION] [FYP-RAG] [FYP-KNOWLEDGE-BASE] No-vector-DB retrieval
    backend: reads the required Markdown knowledge-base files directly off
    disk under `kb_dir`, chunks each (_chunk_text()), scores every chunk
    against a context-derived query via keyword overlap (_score()), and
    returns the top `max_chunks` chunks sorted by score descending.

    [FYP-INPUT] context: the build_context() dict (only
    likely_scenario/classification/scenario_type/severity are read to
    build the query); kb_dir: root of the knowledge base (normally
    settings.KNOWLEDGE_BASE_DIR); max_chunks: cap on returned excerpts
    (default 5).

    [FYP-PROCESS] Determines the required/excluded file set via
    _required_files_for_context(), reads each required file that exists
    under kb_dir (missing files are silently skipped, not errored), chunks
    and scores every file's content, and returns
    (top-N candidate dicts [{source, chunk_id, content, score}], list of
    filenames actually loaded, list of excluded playbook filenames).
    [FYP-USED-BY] retrieve_reporting_context() — as the primary path when
    settings.USE_CHROMADB is False, and as the fallback path when
    chromadb_retrieval() raises."""
    query = " ".join([
        str(context.get("likely_scenario", "")),
        str(context.get("classification", "")),
        str(context.get("scenario_type", "")),
        str(context.get("severity", {}).get("label", "") if isinstance(context.get("severity"), dict) else context.get("severity", "")),
        "reporting severity containment approval evidence collection ransomware phishing playbook analyst review",
    ])
    required, excluded = _required_files_for_context(context)
    loaded: list[str] = []
    candidates: list[dict[str, Any]] = []
    for rel in required:
        path = kb_dir / rel
        if not path.exists():
            continue
        loaded.append(rel)
        text = path.read_text(encoding="utf-8", errors="replace")
        for idx, chunk in enumerate(_chunk_text(text)):
            candidates.append({"source": rel, "chunk_id": f"{rel}::chunk-{idx}", "content": chunk, "score": _score(query, chunk)})
    candidates.sort(key=lambda item: item["score"], reverse=True)
    return candidates[:max_chunks], loaded, excluded


def chromadb_retrieval(context: dict[str, Any], kb_dir: Path, max_chunks: int = 5) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """[FYP-FUNCTION] [FYP-RAG] [FYP-KNOWLEDGE-BASE] Vector-similarity
    retrieval backend against a persistent local ChromaDB store.

    [FYP-KNOWLEDGE-BASE] Opens `chromadb.PersistentClient` at
    settings.CHROMA_DB_PATH (default
    `soc_reporting_agent/database/chromadb/chroma_store`) and gets/creates
    the collection named settings.CHROMA_COLLECTION_NAME (default
    "reporting_knowledge_base"), embedding function
    `OpenAIEmbeddingFunction(api_key=settings.OPENAI_API_KEY,
    model_name="text-embedding-3-small")` — i.e. both the collection's
    stored embeddings and this query's embedding must come from the same
    OpenAI embedding model for similarity search to be meaningful, and a
    reachable OpenAI API key is a hard requirement for this backend.

    [FYP-INPUT] context: build_context() dict (likely_scenario/severity/
    classification feed the query string); kb_dir: accepted for signature
    symmetry with direct_file_retrieval() but not read here — ChromaDB
    reads from its own persistent store, not from files on `kb_dir`;
    max_chunks: `n_results` cap passed to collection.query().

    [FYP-PROCESS] Builds a natural-language query string from
    scenario/severity/classification plus a fixed set of reporting-domain
    keywords, calls collection.query(), and reshapes ChromaDB's
    documents/metadatas response into this module's common
    {source, chunk_id, content, score} shape (`score` is the literal
    string "chromadb" here, not a numeric similarity — ChromaDB result
    ordering is already relevance-ranked). `loaded` is the de-duplicated
    set of `source` metadata values seen in the results, not the required
    file list.
    [FYP-USED-BY] retrieve_reporting_context(), only when
    settings.USE_CHROMADB is True; any exception here (missing `chromadb`
    package, unreachable OpenAI endpoint, empty/uninitialised collection,
    etc.) is caught by the caller and triggers a fallback to
    direct_file_retrieval()."""
    import chromadb
    from chromadb.utils import embedding_functions

    _required, excluded = _required_files_for_context(context)
    client = chromadb.PersistentClient(path=str(settings.CHROMA_DB_PATH))
    ef = embedding_functions.OpenAIEmbeddingFunction(
        api_key=settings.OPENAI_API_KEY, model_name="text-embedding-3-small")
    collection = client.get_or_create_collection(settings.CHROMA_COLLECTION_NAME, embedding_function=ef)
    query = (
        f"Scenario: {context.get('likely_scenario')} Severity: "
        f"{context.get('severity', {}).get('label') if isinstance(context.get('severity'), dict) else context.get('severity')} "
        f"Classification: {context.get('classification')} reporting policy severity policy containment approval evidence collection ransomware phishing playbook"
    )
    result = collection.query(query_texts=[query], n_results=max_chunks)
    docs = result.get("documents", [[]])[0]
    metas = result.get("metadatas", [[]])[0]
    out: list[dict[str, Any]] = []
    loaded: set[str] = set()
    for doc, meta in zip(docs, metas):
        source = meta.get("source", "unknown") if isinstance(meta, dict) else "unknown"
        loaded.add(source)
        out.append({
            "source": source,
            "chunk_id": str(meta.get("chunk_id", "unknown")) if isinstance(meta, dict) else "unknown",
            "content": doc,
            "score": "chromadb",
        })
    return out, sorted(loaded), excluded


def _empty(status: str, excluded: list[str]) -> dict[str, Any]:
    """[FYP-FUNCTION] Build the standard "no retrieval happened" result
    shape (rag_used=False, empty retrieved_context/loaded_knowledge_files)
    tagged with the given `status` code and `excluded` playbook list —
    used by retrieve_reporting_context() for every disabled/no-results
    outcome so callers always see the same dict shape regardless of why
    retrieval didn't happen."""
    return {"rag_used": False, "rag_status": status, "retrieved_context": [], "loaded_knowledge_files": [], "excluded_playbooks": excluded}


def retrieve_reporting_context(context: dict[str, Any], kb_dir: Path | None = None) -> dict[str, Any]:
    """[FYP-FUNCTION] [FYP-ENTRY-POINT] [FYP-RAG] [FYP-KNOWLEDGE-BASE]
    Module's sole public entry point: retrieves knowledge-base context for
    a given incident `context`, choosing between the ChromaDB and
    direct-file backends and handling every disabled/failure path.

    [FYP-INPUT] context: build_context() dict; kb_dir: overrides
    settings.KNOWLEDGE_BASE_DIR.

    [FYP-PROCESS] Short-circuits to _empty() with status "disabled" if
    settings.USE_RAG is False, or "forced_failure_for_test" if
    settings.FORCE_RAG_FAILURE is True (a test-only kill switch). If
    settings.USE_CHROMADB is True, tries chromadb_retrieval() first; on
    any exception, falls back to direct_file_retrieval() and reports
    status f"chromadb_failed_direct_file_fallback: {error}" (still
    rag_used=True if the fallback found chunks). Otherwise goes straight
    to direct_file_retrieval(). In both non-ChromaDB-first paths, an empty
    `loaded` list (no knowledge-base files found on disk) yields status
    "rag_enabled_no_knowledge_files_found"; a non-empty `loaded` but empty
    `docs` (files existed but nothing scored as relevant) yields
    rag_used=False, status "rag_enabled_no_relevant_context_found"; a
    successful hit yields rag_used=True, status "success_chromadb" or
    "success_direct_file_retrieval".
    [FYP-CALLS] _required_files_for_context(), chromadb_retrieval(),
    direct_file_retrieval(), _empty().
    [FYP-EVALUATOR] See the module-level [FYP-EVALUATOR] note: this
    function has no confirmed caller in the current pipeline wiring
    (context_builder.build_context() sets rag_used/rag_status from a
    different, non-retrieval source). Verify at evaluation time whether
    this is dead code, planned-but-unwired, or invoked through a path this
    search missed."""
    kb_dir = kb_dir or settings.KNOWLEDGE_BASE_DIR
    _required, excluded = _required_files_for_context(context)
    if not settings.USE_RAG:
        return _empty("disabled", excluded)
    if settings.FORCE_RAG_FAILURE:
        return _empty("forced_failure_for_test", excluded)
    if settings.USE_CHROMADB:
        try:
            docs, loaded, excluded = chromadb_retrieval(context, kb_dir)
            return {"rag_used": True, "rag_status": "success_chromadb", "retrieved_context": docs, "loaded_knowledge_files": loaded, "excluded_playbooks": excluded}
        except Exception as error:
            docs, loaded, excluded = direct_file_retrieval(context, kb_dir)
            if not loaded:
                return _empty("rag_enabled_no_knowledge_files_found", excluded)
            if not docs:
                return {"rag_used": False, "rag_status": "rag_enabled_no_relevant_context_found", "retrieved_context": [], "loaded_knowledge_files": loaded, "excluded_playbooks": excluded}
            return {"rag_used": True, "rag_status": f"chromadb_failed_direct_file_fallback: {error}", "retrieved_context": docs, "loaded_knowledge_files": loaded, "excluded_playbooks": excluded}
    docs, loaded, excluded = direct_file_retrieval(context, kb_dir)
    if not loaded:
        return _empty("rag_enabled_no_knowledge_files_found", excluded)
    if not docs:
        return {"rag_used": False, "rag_status": "rag_enabled_no_relevant_context_found", "retrieved_context": [], "loaded_knowledge_files": loaded, "excluded_playbooks": excluded}
    return {"rag_used": True, "rag_status": "success_direct_file_retrieval", "retrieved_context": docs, "loaded_knowledge_files": loaded, "excluded_playbooks": excluded}
