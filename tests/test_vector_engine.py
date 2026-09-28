"""
[FYP-FILE]
# Important dependencies: __future__, importlib, pathlib, pytest, sys, types, unittest.
File: tests/test_vector_engine.py
Purpose: Verifies the module-load-time collection-repair logic in
    soc_investigation_agent_revised/vector_engine.py's _open_collection() —
    the "soc_alerts" scratch ChromaDB collection used to hold alerts for
    the current investigation run. vector_engine.py builds this collection
    as a side effect of import (module-level `collection = _open_collection()`),
    so these tests execute the file fresh via importlib for every case
    rather than `import vector_engine` (which would only run that code once
    per process and could not exercise both branches).
Main functionalities: Loads vector_engine.py with a fake `chromadb` module
    injected into sys.modules whose PersistentClient/get_or_create_collection
    are Mocks, then asserts what module-level code did in response to
    get_or_create_collection() raising (or not raising) a ValueError.
Inputs: A Mock ChromaDB client whose get_or_create_collection.side_effect is
    scripted per test (embedding-function-conflict ValueError, then a
    successful retry; or an unrelated ValueError). No real chromadb package,
    OpenAI key, or on-disk ChromaDatabase/ directory is touched.
Outputs: Assertions on the Mock client's call history
    (delete_collection/get_or_create_collection) and on the loaded module's
    `collection` attribute.
Workflow position: Investigation stage RAG/knowledge-base infrastructure —
    vector_engine.py owns the "soc_alerts" scratch index that
    soc_investigation_agent_revised/orchestrator.py queries during a run;
    this file guards the same embedding-function-conflict recovery pattern
    that soc_investigation_agent_revised/chroma_compat.py implements
    generically (see tests/test_chroma_compat.py for that shared helper).
Called by: Executed by pytest, or by running
    `python -m pytest tests/test_vector_engine.py`.
Calls: soc_investigation_agent_revised/vector_engine.py (loaded dynamically
    via importlib.util.spec_from_file_location, module-level _open_collection()).
Key evaluator search terms: vector_engine, soc_alerts, embedding function
    conflict, ChromaDB, scratch collection, RAG, knowledge base.
[/FYP-FILE]
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import Mock

import pytest


VECTOR_ENGINE_PATH = (
    Path(__file__).resolve().parent.parent
    / "agents"
    / "investigation"
    / "vector_engine.py"
)


def _load_vector_engine(monkeypatch, client):
    """[FYP-FUNCTION] Test helper (not itself a test).

    Injects a fake `chromadb` / `chromadb.utils` module pair into
    sys.modules (PersistentClient returns the given Mock `client`,
    OpenAIEmbeddingFunction returns a stub object), then imports
    vector_engine.py fresh under a throwaway module name so its
    module-level `collection = _open_collection()` line runs against the
    fake client. Returns the freshly executed module.
    """
    chromadb = types.ModuleType("chromadb")
    chromadb.PersistentClient = Mock(return_value=client)

    embedding_functions = types.SimpleNamespace(
        OpenAIEmbeddingFunction=Mock(return_value=object())
    )
    chromadb_utils = types.ModuleType("chromadb.utils")
    chromadb_utils.embedding_functions = embedding_functions
    chromadb.utils = chromadb_utils

    monkeypatch.setitem(sys.modules, "chromadb", chromadb)
    monkeypatch.setitem(sys.modules, "chromadb.utils", chromadb_utils)

    spec = importlib.util.spec_from_file_location(
        "_vector_engine_under_test", VECTOR_ENGINE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ══════════════════════════════════════════════════════════════════════════
# [FYP-SECTION] _open_collection() embedding-function-conflict recovery
# ══════════════════════════════════════════════════════════════════════════

# [FYP-VALIDATION] [FYP-EVALUATOR]
def test_legacy_embedding_function_conflict_recreates_scratch_collection(monkeypatch):
    """[FYP-FUNCTION] Validates vector_engine._open_collection()'s repair path.

    Sets up: get_or_create_collection.side_effect raises a ValueError whose
    message matches the "embedding function ... conflict/already exists"
    pattern on the first call, then returns a new collection object.
    Exercises: loading vector_engine.py, whose module-level _open_collection()
    call must catch that specific ValueError, call
    client.delete_collection("soc_alerts") to discard the disposable
    scratch collection, and retry get_or_create_collection() once.
    Asserts: delete_collection() was called exactly once with "soc_alerts",
    get_or_create_collection() was called twice, and module.collection is
    the object returned by the retry.
    """
    recreated_collection = object()
    client = Mock()
    client.get_or_create_collection.side_effect = [
        ValueError(
            "An embedding function already exists in the collection configuration. "
            "Embedding function conflict: new: openai vs persisted: default"
        ),
        recreated_collection,
    ]

    module = _load_vector_engine(monkeypatch, client)

    client.delete_collection.assert_called_once_with("soc_alerts")
    assert client.get_or_create_collection.call_count == 2
    assert module.collection is recreated_collection


# [FYP-VALIDATION]
def test_unrelated_chroma_value_error_is_not_destructively_repaired(monkeypatch):
    """[FYP-FUNCTION] Validates vector_engine._open_collection()'s error passthrough.

    Sets up: get_or_create_collection raises a ValueError with an unrelated
    message ("invalid collection name") that does not match the
    embedding-function-conflict pattern.
    Exercises: loading vector_engine.py.
    Asserts: the ValueError propagates unchanged out of module import (not
    swallowed/misclassified as a repairable conflict), and
    delete_collection() is never called — a genuine error must never
    trigger destructive deletion of the collection.
    """
    client = Mock()
    client.get_or_create_collection.side_effect = ValueError("invalid collection name")

    with pytest.raises(ValueError, match="invalid collection name"):
        _load_vector_engine(monkeypatch, client)

    client.delete_collection.assert_not_called()
