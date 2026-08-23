# ==========================================================================
# [FYP-FILE]
# Important dependencies: typing.
# File: soc_investigation_agent_revised/chroma_compat.py
# Purpose: Shared compatibility shim for safely opening persisted ChromaDB
#   collections — the low-level plumbing underneath every knowledge-base /
#   RAG (Retrieval-Augmented Generation) vector store used by this agent
#   (soc_alerts in vector_engine.py, soc_incidents in sync_engine.py,
#   soc_policies in orchestrator.py). Prevents accidental data loss when the
#   embedding function used to create a collection differs from the one the
#   current process wants to use.
# Main functionalities:
#   - is_embedding_function_conflict(): classifies a ChromaDB ValueError as
#     an embedding-function mismatch (vs. some other real error).
#   - open_persistent_collection(): tries to open/create a collection with
#     the caller's embedding function; on a mismatch, reopens it using
#     Chroma's persisted/default embedding function instead of deleting it,
#     preserving previously-ingested vectors used for RAG retrieval.
# Inputs: a ChromaDB PersistentClient, target collection name, an embedding
#   function object, and collection metadata (e.g. {"hnsw:space": "cosine"}).
# Outputs: a tuple (collection, used_persisted_embedding: bool).
# Workflow position: Investigation stage / RAG knowledge-base infrastructure
#   layer. Called at startup by every module that owns a persistent ChromaDB
#   collection, before any embedding/query/upsert happens.
# Called by: vector_engine.py is the only module that reimplements this
#   pattern inline (own _open_collection()); sync_engine.py
#   (ChromaIncidentVectorStore.__init__) and orchestrator.py
#   (PolicyVectorIndex.__init__) both import and call
#   open_persistent_collection() directly. Exercised directly by
#   tests/test_chroma_compat.py.
# Calls: only methods on the passed-in `client` object (chromadb
#   PersistentClient: get_or_create_collection / get_collection).
# Key evaluator search terms: RAG, ChromaDB, knowledge base, vector store,
#   embedding function conflict, persistent collection, ChromaIncidentVectorStore,
#   PolicyVectorIndex, evidence retrieval infrastructure.
# ==========================================================================

"""Compatibility helpers for opening persisted ChromaDB collections."""

from typing import Any, Dict, Tuple


# [FYP-RAG] [FYP-VALIDATION] Detects the specific ChromaDB error shape raised
# when a collection already exists with a different embedding function than
# the one the caller is trying to (re)open it with. Used to distinguish a
# recoverable "wrong embedding function" situation from any other genuine
# ChromaDB error, which should still propagate.
# =============================================================================
# [FYP-SECTION] INVESTIGATION EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================

# [FYP-FUNCTION] `is_embedding_function_conflict` — evaluates is embedding function conflict conditions so invalid or unsafe investigation processing is stopped early.
# [FYP-INPUT] Parameters: `exc`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/chroma_compat.py:open_persistent_collection; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `lower`, `str`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def is_embedding_function_conflict(exc: ValueError) -> bool:
    """Return whether Chroma rejected a different embedding function."""
    message = str(exc).lower()
    return (
        "embedding function" in message
        and ("conflict" in message or "already exists" in message)
    )


# [FYP-RAG] [FYP-KNOWLEDGE-BASE] [FYP-FALLBACK]
# Core helper shared by every persistent ChromaDB-backed knowledge store in
# this agent (alert index, incident index, policy index). Guarantees that a
# pre-existing vector collection (the RAG knowledge base) is never silently
# discarded just because the embedding function configuration changed
# between releases.
# [FYP-FUNCTION] `open_persistent_collection` — implements the open persistent collection operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: `client`, `name`, `embedding_function`, `metadata`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/orchestrator.py:__init__, soc_investigation_agent_revised/sync_engine.py:__init__, tests/test_chroma_compat.py:test_embedding_conflict_reopens_collection_without_override; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `get_collection`, `get_or_create_collection`, `is_embedding_function_conflict`.
# [FYP-ERROR] Contains local try/except handling; its fallback branches preserve a controlled result before unhandled failures propagate.

def open_persistent_collection(
    client: Any,
    *,
    name: str,
    embedding_function: Any,
    metadata: Dict[str, Any],
) -> Tuple[Any, bool]:
    """Open a collection without discarding vectors from an older provider.

    New collections use ``embedding_function``. If an existing collection was
    persisted with another provider, Chroma requires callers to reopen it with
    that persisted provider. Omitting the override lets Chroma reconstruct its
    stored/default embedding function and preserves all existing vectors.

    Returns ``(collection, used_persisted_embedding)``.
    """
    try:
        # [FYP-PROCESS] Happy path: create-or-open with the caller's requested
        # embedding function (used_persisted_embedding=False).
        collection = client.get_or_create_collection(
            name=name,
            embedding_function=embedding_function,
            metadata=metadata,
        )
        return collection, False
    except ValueError as exc:
        # [FYP-ERROR] Only handle the known embedding-function-conflict case;
        # any other ValueError is a real failure and must propagate.
        if not is_embedding_function_conflict(exc):
            raise

        # [FYP-FALLBACK] Reopen using whatever embedding function is already
        # persisted with the collection, instead of deleting/recreating it,
        # so existing RAG vectors are never lost.
        try:
            collection = client.get_collection(name=name)
        except Exception as fallback_exc:
            # Preserve the useful original Chroma error if even the compatible
            # reopen fails.
            raise exc from fallback_exc
        return collection, True
