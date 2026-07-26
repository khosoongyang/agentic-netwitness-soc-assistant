from unittest.mock import Mock

import pytest

from soc_investigation_agent_revised.chroma_compat import (
    open_persistent_collection,
)


CONFLICT = (
    "An embedding function already exists in the collection configuration, "
    "and a new one is provided. Embedding function conflict: "
    "new: openai vs persisted: default"
)


def test_new_or_matching_collection_uses_requested_embedding():
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


def test_embedding_conflict_reopens_collection_without_override():
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


def test_unrelated_value_error_is_not_hidden():
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


def test_failed_compatible_reopen_preserves_original_error():
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
