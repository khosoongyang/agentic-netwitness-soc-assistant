"""Backend-owned Chroma status, semantic search, synchronization, and admin operations."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Callable

from .case_service import open_readonly_connection


class VectorStoreError(RuntimeError):
    def __init__(self, message: str, status_code: int = 503) -> None:
        self.message, self.status_code = message, status_code
        super().__init__(message)


class SearchService:
    def __init__(self, path: Path | None = None, collection_factory: Callable | None = None) -> None:
        project_root = Path(__file__).resolve().parents[2]
        self.path = Path(path or os.environ.get("AEGIS_CHROMA_DB_PATH", project_root / "runtime" / "chroma"))
        self.seed_path = project_root / "chroma_db"
        self.collection_factory = collection_factory
        self._client = None
        self._collections: dict[str, Any] = {}

    def _collection(self, name: str = "soc_incidents"):
        if name in self._collections:
            return self._collections[name]
        try:
            if self.collection_factory:
                collection = self.collection_factory(name)
            else:
                import chromadb
                from chromadb.utils import embedding_functions
                if not os.environ.get("OPENAI_API_KEY", "").strip():
                    raise VectorStoreError("Semantic search requires a configured OpenAI API key.")
                if self._client is None:
                    if not self.path.exists() and self.seed_path.is_dir():
                        self.path.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copytree(self.seed_path, self.path)
                    self._client = chromadb.PersistentClient(path=str(self.path))
                embedding = embedding_functions.OpenAIEmbeddingFunction(
                    api_key=os.environ["OPENAI_API_KEY"], model_name="text-embedding-3-small")
                collection = self._client.get_or_create_collection(
                    name=name, metadata={"hnsw:space": "cosine"}, embedding_function=embedding)
            self._collections[name] = collection
            return collection
        except VectorStoreError:
            raise
        except Exception as exc:
            raise VectorStoreError("The vector store is unavailable.") from exc

    def status(self) -> dict[str, Any]:
        try:
            collection = self._collection()
            return {"available": True, "collection": "soc_incidents", "vectors": int(collection.count())}
        except VectorStoreError as exc:
            return {"available": False, "collection": "soc_incidents", "vectors": 0, "message": exc.message}

    def search(self, query: str, *, limit: int = 5, collection_name: str = "soc_incidents") -> dict:
        query = str(query or "").strip()
        if not query or len(query) > 2000 or not 1 <= limit <= 20:
            raise VectorStoreError("Search query or result limit is invalid.", 400)
        collection = self._collection(collection_name)
        total = int(collection.count())
        if total == 0:
            return {"items": [], "total_vectors": 0, "collection": collection_name}
        result = collection.query(query_texts=[query], n_results=min(limit, total))
        items = []
        for index, document in enumerate((result.get("documents") or [[]])[0]):
            distance_rows = result.get("distances") or [[]]
            distance = distance_rows[0][index] if distance_rows and len(distance_rows[0]) > index else 1
            items.append({
                "id": result["ids"][0][index],
                "text": document,
                "score": round((1 - float(distance)) * 100, 1),
                "metadata": (result.get("metadatas") or [[{}]])[0][index] or {},
            })
        return {"items": items, "total_vectors": total, "collection": collection_name}

    def sync_incidents(self, *, database_path=None) -> dict:
        collection = self._collection()
        with open_readonly_connection(database_path) as connection:
            rows = connection.execute("SELECT id,title,severity,status,created,raw_json FROM incidents").fetchall()
        documents, ids, metadata = [], [], []
        for row in rows:
            raw = {}
            try:
                raw = json.loads(row["raw_json"] or "{}")
            except (TypeError, ValueError):
                pass
            documents.append(f"{row['title'] or ''}\n{raw.get('summary') or raw.get('description') or ''}".strip() or "no content")
            ids.append(str(row["id"]))
            metadata.append({"severity": row["severity"] or "", "status": row["status"] or "", "created": row["created"] or ""})
        if ids:
            collection.upsert(documents=documents, ids=ids, metadatas=metadata)
        return {"synchronized": len(ids), "collection": "soc_incidents"}

    def browse(self, *, limit: int = 100, collection_name: str = "soc_incidents") -> dict:
        if not 1 <= limit <= 300:
            raise VectorStoreError("Vector browse limit is invalid.", 400)
        collection = self._collection(collection_name)
        result = collection.get(include=["documents", "metadatas"], limit=limit)
        ids = result.get("ids") or []
        documents = result.get("documents") or []
        metadata = result.get("metadatas") or []
        return {"collection": collection_name, "items": [
            {"id": identity, "text": documents[index] if index < len(documents) else "",
             "metadata": metadata[index] if index < len(metadata) else {}}
            for index, identity in enumerate(ids)
        ]}

    def wipe(self, collection_name: str, confirmation: str) -> dict:
        if collection_name != "soc_incidents" and not collection_name.startswith("pipeline_"):
            raise VectorStoreError("Collection operation is forbidden.", 403)
        if confirmation != f"WIPE {collection_name}":
            raise VectorStoreError("Exact collection confirmation is required.", 400)
        try:
            if self.collection_factory:
                collection = self._collection(collection_name)
                ids = (collection.get(include=[]).get("ids") or [])
                if ids:
                    collection.delete(ids=ids)
            else:
                if self._client is None:
                    self._collection(collection_name)
                self._client.delete_collection(collection_name)
                self._collections.pop(collection_name, None)
                self._collection(collection_name)
        except VectorStoreError:
            raise
        except Exception as exc:
            raise VectorStoreError("The vector collection could not be cleared.") from exc
        return {"collection": collection_name, "vectors": 0}


search_service = SearchService()
