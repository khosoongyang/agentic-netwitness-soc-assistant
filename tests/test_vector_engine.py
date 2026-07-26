from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import Mock

import pytest


VECTOR_ENGINE_PATH = (
    Path(__file__).resolve().parent.parent
    / "soc_investigation_agent_revised"
    / "vector_engine.py"
)


def _load_vector_engine(monkeypatch, client):
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


def test_legacy_embedding_function_conflict_recreates_scratch_collection(monkeypatch):
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


def test_unrelated_chroma_value_error_is_not_destructively_repaired(monkeypatch):
    client = Mock()
    client.get_or_create_collection.side_effect = ValueError("invalid collection name")

    with pytest.raises(ValueError, match="invalid collection name"):
        _load_vector_engine(monkeypatch, client)

    client.delete_collection.assert_not_called()
