from __future__ import annotations

from pathlib import Path
from typing import Any

from config import settings


def _chunk_text(text: str, size: int = 1400) -> list[str]:
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
    terms = {term.lower() for term in query.replace("_", " ").split() if len(term) > 3}
    chunk_lower = chunk.lower()
    return sum(1 for term in terms if term in chunk_lower)


def _context_text(context: dict[str, Any]) -> str:
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
    text = _context_text(context)
    return any(term in text for term in ("wannacry", "wanna cry", "ransomware", "malware/ransomware", "ransomware-related"))


def _required_files_for_context(context: dict[str, Any]) -> tuple[list[str], list[str]]:
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
    return {"rag_used": False, "rag_status": status, "retrieved_context": [], "loaded_knowledge_files": [], "excluded_playbooks": excluded}


def retrieve_reporting_context(context: dict[str, Any], kb_dir: Path | None = None) -> dict[str, Any]:
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
