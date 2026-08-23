"""
[FYP-FILE]
# Important dependencies: pytest, soc_investigation_agent_revised, unittest.
File: tests/test_chroma_compat.py
Purpose: Verifies soc_investigation_agent_revised/chroma_compat.py's
    open_persistent_collection() — the shared helper every persistent
    ChromaDB-backed knowledge store in the investigation agent (soc_alerts
    in vector_engine.py, soc_incidents in sync_engine.py, soc_policies in
    orchestrator.py) uses to avoid discarding an existing RAG vector index
    just because the embedding-function configuration changed.
Main functionalities: Calls open_persistent_collection() against a Mock
    ChromaDB client scripted to succeed, to raise an embedding-function
    conflict, or to raise an unrelated ValueError, and asserts which
    client methods were (or were not) invoked and what is returned.
Inputs: unittest.mock.Mock standing in for a chromadb PersistentClient;
    no real chromadb package, network, or on-disk vector store is used.
Outputs: assertions on the returned (collection, used_persisted_embedding)
    tuple and on the Mock's call history
    (get_or_create_collection/get_collection/delete_collection).
Workflow position: Investigation stage RAG/knowledge-base infrastructure —
    guards the same conflict-recovery contract that
    soc_investigation_agent_revised/vector_engine.py reimplements inline
    for its own scratch collection (see tests/test_vector_engine.py).
Called by: Executed by pytest, or by running
    `python -m pytest tests/test_chroma_compat.py`.
Calls: soc_investigation_agent_revised.chroma_compat.open_persistent_collection().
Key evaluator search terms: chroma_compat, open_persistent_collection,
    embedding function conflict, ChromaDB, RAG, knowledge base,
    persisted embedding, used_persisted_embedding.
[/FYP-FILE]
"""
from unittest.mock import Mock

import pytest

from agents.investigation.chroma_compat import (
    open_persistent_collection,
)


# [FYP-SECTION] Shared fixture — the exact ValueError message ChromaDB
# raises when an embedding function conflicts with a persisted collection's.
CONFLICT = (
    "An embedding function already exists in the collection configuration, "
    "and a new one is provided. Embedding function conflict: "
    "new: openai vs persisted: default"
)


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] open_persistent_collection() — happy path and conflict repair
# ══════════════════════════════════════════════════════════════════════════

def test_new_or_matching_collection_uses_requested_embedding():
    """[FYP-FUNCTION] Validates the happy path of open_persistent_collection().

    get_or_create_collection() succeeds on the first try (new collection,
    or an existing one already using the requested embedding function).
    Asserts the caller's requested collection is returned unchanged,
    used_persisted is False, and the fallback get_collection() path is
    never touched.
    """
    requested_collection = object()
    client = Mock()
    client.get_or_create_collection.return_value = requested_collection
    embedding_function = object()

    collection, used_persisted = open_persistent_collection(
        client,
        name="soc_incidents",
        embedding_function=embedding_function,
        metadata={"hnsw:space": "cosine"},
    )

    assert collection is requested_collection
    assert used_persisted is False
    client.get_collection.assert_not_called()


# [FYP-VALIDATION] [FYP-EVALUATOR]
def test_embedding_conflict_reopens_collection_without_override():
    """[FYP-FUNCTION] Validates open_persistent_collection()'s fallback repair.

    get_or_create_collection() raises the embedding-function-conflict
    ValueError; asserts the function falls back to
    client.get_collection(name=...) (no embedding_function override, so
    Chroma reconstructs the persisted one), returns that collection with
    used_persisted=True, and never calls delete_collection — existing RAG
    vectors are preserved rather than discarded.
    """
    persisted_collection = object()
    client = Mock()
    client.get_or_create_collection.side_effect = ValueError(CONFLICT)
    client.get_collection.return_value = persisted_collection

    collection, used_persisted = open_persistent_collection(
        client,
        name="soc_incidents",
        embedding_function=object(),
        metadata={"hnsw:space": "cosine"},
    )

    assert collection is persisted_collection
    assert used_persisted is True
    client.get_collection.assert_called_once_with(name="soc_incidents")
    client.delete_collection.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] Genuine ChromaDB errors must still propagate
# ══════════════════════════════════════════════════════════════════════════

def test_unrelated_value_error_is_not_hidden():
    """[FYP-FUNCTION] Validates open_persistent_collection() does not
    misclassify an unrelated ValueError ("invalid collection name") as an
    embedding-function conflict. Asserts the original error propagates and
    get_collection() (the conflict-repair path) is never attempted.
    """
    client = Mock()
    client.get_or_create_collection.side_effect = ValueError(
        "invalid collection name"
    )

    with pytest.raises(ValueError, match="invalid collection name"):
        open_persistent_collection(
            client,
            name="soc_incidents",
            embedding_function=object(),
            metadata={"hnsw:space": "cosine"},
        )

    client.get_collection.assert_not_called()


# [FYP-VALIDATION]
def test_failed_compatible_reopen_preserves_original_error():
    """[FYP-FUNCTION] Validates open_persistent_collection()'s error chaining
    when even the fallback repair fails: get_or_create_collection() raises
    the embedding-function-conflict ValueError, and the fallback
    get_collection() then raises a RuntimeError. Asserts the original,
    more informative "Embedding function conflict" ValueError is what
    propagates to the caller (via `raise exc from fallback_exc`), not the
    less useful RuntimeError.
    """
    client = Mock()
    client.get_or_create_collection.side_effect = ValueError(CONFLICT)
    client.get_collection.side_effect = RuntimeError("database unavailable")

    with pytest.raises(ValueError, match="Embedding function conflict"):
        open_persistent_collection(
            client,
            name="soc_incidents",
            embedding_function=object(),
            metadata={"hnsw:space": "cosine"},
        )
