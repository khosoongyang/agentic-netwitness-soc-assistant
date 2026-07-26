"""Compatibility helpers for opening persisted ChromaDB collections."""

from typing import Any, Dict, Tuple


def is_embedding_function_conflict(exc: ValueError) -> bool:
    """Return whether Chroma rejected a different embedding function."""
    message = str(exc).lower()
    return (
        "embedding function" in message
        and ("conflict" in message or "already exists" in message)
    )


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
        collection = client.get_or_create_collection(
            name=name,
            embedding_function=embedding_function,
            metadata=metadata,
        )
        return collection, False
    except ValueError as exc:
        if not is_embedding_function_conflict(exc):
            raise

        try:
            collection = client.get_collection(name=name)
        except Exception as fallback_exc:
            # Preserve the useful original Chroma error if even the compatible
            # reopen fails.
            raise exc from fallback_exc
        return collection, True
