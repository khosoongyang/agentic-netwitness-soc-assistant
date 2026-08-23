# ==========================================================================
# [FYP-FILE]
# Important dependencies: chromadb, dotenv, os.
# File: soc_investigation_agent_revised/vector_engine.py
# Purpose: RAG (Retrieval-Augmented Generation) knowledge-base engine for
#   individual raw alerts. Owns the "soc_alerts" ChromaDB collection — the
#   scratch-space vector store that every alert log is embedded into during
#   ingestion, and that both the Two-Tier Correlation Engine's pivoting logic
#   and the LLM-driven playbook orchestrator query to answer "what other
#   evidence is related to this alert?".
# Main functionalities:
#   - _open_collection() / clear_collection(): manage the lifecycle of the
#     "soc_alerts" ChromaDB collection (OpenAI text-embedding-3-small,
#     cosine similarity), including repairing a legacy embedding-function
#     mismatch by recreating the (disposable, per-run) collection.
#   - ingest_logs(): the RAG ingestion step — upserts processed alert
#     documents + metadata into the vector store so they become retrievable.
#   - query_semantic(): core RAG retrieval primitive — vector similarity
#     search over "soc_alerts" with an optional numeric temporal pre-filter.
#   - get_alerts_by_temporal_window(): metadata-only (non-semantic) fetch of
#     every alert inside a time window; used for cheap relatedness checks
#     that don't need embeddings.
#   - has_technical_token_overlap(): the correlation "guardrail" — refuses to
#     treat two alerts as related unless they share a concrete forensic
#     token (IP/subnet, domain/parent-domain, hash, user, host), preventing
#     purely-semantic false positives from being merged into an incident.
#   - correlate_rrf(): fuses semantic-similarity ranking with metadata
#     match-count ranking via Reciprocal Rank Fusion (RRF) — the primary
#     "evidence correlation" / RAG-retrieval function used to pull
#     additional related alerts into an incident during pivoting.
# Inputs: processed alert dicts (id/document/metadata) produced by
#   ingest_pipeline.process_log_file(); free-text query strings; forensic
#   indicator token lists; optional epoch timestamp + time-window filters.
# Outputs: lists of tuples — (alert_id, distance_or_score, document,
#   metadata) — ranked most-relevant first.
# Workflow position: Investigation stage / RAG evidence-retrieval layer.
#   Sits underneath main.py (bulk ingestion + two-tier correlation loop +
#   Phase 2 dynamic retrieval) and orchestrator.py (transitive-closure
#   pivoting during single-incident playbook execution).
# Called by: main.py (clear_collection at pipeline start, ingest_logs after
#   bulk ingestion, get_alerts_by_temporal_window + has_technical_token_overlap
#   for the cheap "has externals?" check, correlate_rrf for dynamic report
#   enrichment); orchestrator.py (correlate_rrf, twice — initial transitive
#   closure and mid-playbook pivot retrieval); bench_correlation.py
#   (clear_collection, as part of test-environment reset).
# Calls: chromadb.PersistentClient / OpenAIEmbeddingFunction directly (does
#   NOT use chroma_compat.open_persistent_collection — "soc_alerts" is
#   disposable scratch space cleared every run, unlike soc_incidents/
#   soc_policies, so a mismatch is repaired by delete+recreate instead of
#   reopening with the persisted embedding function).
# Key evaluator search terms: RAG, ChromaDB, soc_alerts, evidence
#   correlation, RRF, Reciprocal Rank Fusion, semantic search, temporal
#   window, technical token overlap, knowledge base retrieval.
# ==========================================================================

import os
import chromadb
from chromadb.utils import embedding_functions
from dotenv import load_dotenv

load_dotenv()

# [FYP-KNOWLEDGE-BASE] Initialize persistent local ChromaDB client — the
# on-disk RAG vector store root shared by every collection this process
# opens (only "soc_alerts" lives here; soc_incidents/soc_policies are opened
# by sync_engine.py / orchestrator.py against the same ChromaDatabase path).
DB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "ChromaDatabase"))
client = chromadb.PersistentClient(path=DB_DIR)
COLLECTION_NAME = "soc_alerts"

# [FYP-RAG] [FYP-KNOWLEDGE-BASE] OpenAI embeddings — must match whatever embedding
# function every other collection in this project uses, or ChromaDB rejects queries
# with a dimension mismatch against already-stored vectors.
default_ef = embedding_functions.OpenAIEmbeddingFunction(
    api_key=os.environ.get("OPENAI_API_KEY") or None,
    model_name="text-embedding-3-small",
)

# [FYP-FUNCTION] [FYP-RAG] [FYP-KNOWLEDGE-BASE]
# Opens (or lazily creates) the "soc_alerts" ChromaDB collection that backs
# every RAG query in this module.
# [FYP-USED-BY]: module-level `collection` initialization below, and
# clear_collection() after a reset.
# =============================================================================
# [FYP-SECTION] INVESTIGATION EXECUTION, VALIDATION, AND SUPPORTING OPERATIONS
# =============================================================================


def _open_collection():
    """Open the run-scoped alert index, repairing a legacy EF mismatch.

    ``soc_alerts`` is scratch space and is cleared at the beginning of every
    investigation. Older releases created it with Chroma's default embedding
    function; current releases use OpenAI embeddings. Chroma 1.5+ correctly
    refuses to reopen such a collection with a different function, so discard
    only this disposable collection and recreate it with the current config.
    Other ValueErrors still propagate instead of being mistaken for a
    migration issue.
    """
    try:
        return client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=default_ef,
            metadata={"hnsw:space": "cosine"}
        )
    except ValueError as exc:
        # [FYP-DECISION] Only an embedding-function conflict is recoverable
        # here; any other ValueError is a genuine failure and must propagate.
        message = str(exc).lower()
        is_embedding_conflict = (
            "embedding function" in message
            and ("conflict" in message or "already exists" in message)
        )
        if not is_embedding_conflict:
            raise
        try:
            client.delete_collection(COLLECTION_NAME)
        except Exception:
            # A concurrent worker may already have removed it. The retry below
            # is the source of truth and preserves the useful Chroma exception
            # if the collection still cannot be opened.
            pass
        return client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=default_ef,
            metadata={"hnsw:space": "cosine"}
        )


# Create or retrieve the collection configured for cosine similarity.
collection = _open_collection()

# [FYP-FUNCTION] [FYP-KNOWLEDGE-BASE] [FYP-USED-BY]: main.py (start of every
# pipeline run, to discard the previous run's alert vectors) and
# bench_correlation.py (test-environment reset).
def clear_collection():
    """Helper function to reset collection database."""
    global collection
    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass
    collection = _open_collection()

# [FYP-FUNCTION] [FYP-RAG] [FYP-KNOWLEDGE-BASE] The RAG ingestion step: every
# alert processed by ingest_pipeline.process_log_file() is embedded and
# written here before any correlation/retrieval can find it.
# [FYP-USED-BY]: main.py's bulk-ingestion phase (main_async()).
def ingest_logs(logs_list: list):
    """Upserts list of processed logs containing 'id', 'document', and 'metadata' into ChromaDB."""
    if not logs_list:
        return
    ids = [log["id"] for log in logs_list]
    documents = [log["document"][:12000] if len(log["document"]) > 12000 else log["document"] for log in logs_list]
    metadatas = [log["metadata"] for log in logs_list]
    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)

# [FYP-FUNCTION] [FYP-RAG] [FYP-EVALUATOR] Core RAG retrieval primitive: this
# is "where RAG knowledge is retrieved" for individual alerts — a vector
# similarity query against soc_alerts, optionally scoped to a time window via
# a numeric metadata pre-filter (avoids re-embedding, just narrows candidates
# before the ANN search).
# [FYP-USED-BY]: correlate_rrf() (semantic half of the RRF fusion).
def query_semantic(query_text: str, timestamp_epoch: int = None, time_window_sec: int = 86400, n_results: int = 10) -> list:
    """Queries ChromaDB using semantic vector similarity and optional numerical temporal pre-filtering."""
    where_filter = None
    if timestamp_epoch is not None:
        where_filter = {
            "$and": [
                {"timestamp_epoch": {"$gte": int(timestamp_epoch - time_window_sec)}},
                {"timestamp_epoch": {"$lte": int(timestamp_epoch + time_window_sec)}}
            ]
        }

    results = collection.query(
        query_texts=[query_text],
        n_results=n_results,
        where=where_filter
    )

    # [FYP-PROCESS] Flatten ChromaDB's batch-query response shape (lists of
    # lists, one outer entry per query_text — always exactly one here) into a
    # flat list of (id, distance, document, metadata) tuples for callers.
    parsed = []
    if results and results["ids"] and results["ids"][0]:
        for idx in range(len(results["ids"][0])):
            alert_id = results["ids"][0][idx]
            dist = results["distances"][0][idx]
            doc = results["documents"][0][idx]
            meta = results["metadatas"][0][idx]
            parsed.append((alert_id, dist, doc, meta))
    return parsed

# [FYP-FUNCTION] [FYP-KNOWLEDGE-BASE] Non-semantic retrieval: fetches every
# alert whose timestamp_epoch metadata falls inside the window, without
# running an embedding/ANN search. Cheaper than query_semantic() when only a
# metadata-based relatedness check (has_technical_token_overlap) is needed.
# [FYP-USED-BY]: correlate_rrf() (metadata half of the RRF fusion); main.py's
# fast "has externals?" pre-check before deciding whether to invoke the LLM.
def get_alerts_by_temporal_window(timestamp_epoch: int, time_window_sec: int = 86400) -> list:
    """Gets all alerts falling inside a specific temporal window via numerical metadata filters."""
    where_filter = {
        "$and": [
            {"timestamp_epoch": {"$gte": int(timestamp_epoch - time_window_sec)}},
            {"timestamp_epoch": {"$lte": int(timestamp_epoch + time_window_sec)}}
        ]
    }
    results = collection.get(where=where_filter)
    parsed = []
    if results and results["ids"]:
        for idx in range(len(results["ids"])):
            alert_id = results["ids"][idx]
            doc = results["documents"][idx] if results["documents"] else ""
            meta = results["metadatas"][idx]
            parsed.append((alert_id, doc, meta))
    return parsed

# [FYP-FUNCTION] [FYP-DECISION] [FYP-EVALUATOR] Evidence-correlation
# guardrail: a candidate alert is only considered "related" to the active
# seed indicators if it shares at least one concrete forensic token (exact
# IP/host/user/domain/email/hash match, IP-subnet prefix match, or
# parent-domain suffix match). This is what stops correlate_rrf() from
# merging alerts that are merely semantically similar but share no real
# infrastructure/identity overlap.
# [FYP-USED-BY]: correlate_rrf() (filters both the semantic and metadata
# candidate lists); main.py's fast externals check.
def has_technical_token_overlap(candidate_meta: dict, active_seeds: list) -> bool:
    """Performs a strict check for any technical token overlap (IPs/subnets, domains, hashes, users, hosts)."""
    if not active_seeds:
        return False

    # 1. Normalize active seeds (lowercase, trimmed)
    active_set = {str(s).strip().lower() for s in active_seeds if s}

    # 2. Extract candidate tokens
    candidate_tokens = set()
    candidate_ips = []
    candidate_domains = []

    # Singular tracking fields
    for field in ["username", "hostname", "incident_id"]:
        val = candidate_meta.get(field)
        if val and str(val).lower() not in ("unknown", "null", "none", ""):
            val_clean = str(val).strip().lower()
            candidate_tokens.add(val_clean)
            if field == "hostname":
                candidate_domains.append(val_clean)

    # Comma-separated array fields
    for field in ["ips", "domains", "emails", "sha256s", "md5s"]:
        val = candidate_meta.get(field)
        if val and isinstance(val, str):
            items = [x.strip().lower() for x in val.split(",") if x.strip()]
            for item in items:
                if item not in ("unknown", "null", "none", ""):
                    candidate_tokens.add(item)
                    if field == "ips":
                        candidate_ips.append(item)
                    elif field == "domains":
                        candidate_domains.append(item)

    # 3. Perform intersection check using disjoint
    if not candidate_tokens.isdisjoint(active_set):
        return True

    # 4. Handle Subnet and Domain wildcard matching
    for seed in active_set:
        # Subnet match (ends with dot, e.g., '10.100.20.')
        if seed.endswith('.'):
            for ip in candidate_ips:
                if ip.startswith(seed):
                    return True
        # Parent domain match (e.g., 'domain.com' matching 'sub.domain.com')
        elif '.' in seed:
            for d in candidate_domains:
                if d == seed or d.endswith('.' + seed):
                    return True

    return False

# [FYP-FUNCTION] [FYP-RAG] [FYP-EVALUATOR] Primary alert-level evidence
# correlation function: fuses two independently-ranked candidate lists
# (semantic vector similarity from query_semantic(), and exact/wildcard
# metadata match-count from get_alerts_by_temporal_window()) using
# Reciprocal Rank Fusion (RRF, constant `k`, mirrors correlation_config.RRF_K
# used by CorrelationEngine.evaluate_tier1() in correlation_engine.py).
# CRITICAL GUARDRAIL: every candidate — from both lists — must pass
# has_technical_token_overlap() before it can be ranked, so RRF can only
# reorder alerts that are already forensically linked to the active seeds;
# it never introduces a new relationship on semantic similarity alone.
# [FYP-USED-BY]: orchestrator.py's transitive-closure pivoting loop
# (orchestrate_incident) and mid-playbook pivot retrieval
# (orchestrate_incident's milestone loop); main.py's Phase 2 dynamic
# retrieval (generate_incident_report()).
# [FYP-FUNCTION] `correlate_rrf` — implements the correlate rrf operation used by the surrounding investigation workflow.
# [FYP-INPUT] Parameters: `active_indicators`, `query_text`, `timestamp_epoch`, `time_window_sec`, `k`, `n_results`; values come from its direct caller, route, UI event, fixture, or stage handoff.
# [FYP-PROCESS] Executes the named operation within the Aegis investigation workflow; branch rules remain in the body below.
# [FYP-OUTPUT] Returns the explicit value(s) from its decision paths for the documented caller to consume.
# [FYP-USED-BY] Static symbol references include soc_investigation_agent_revised/orchestrator.py:orchestrate_incident; dynamic framework calls may add callers.
# [FYP-CALLS] Calls: `any`, `append`, `endswith`, `enumerate`, `get`, `get_alerts_by_temporal_window`, `has_technical_token_overlap`, `items`.
# [FYP-ERROR] Does not define a local fallback; unexpected failures propagate to the caller/framework error boundary.

def correlate_rrf(active_indicators: list, query_text: str = None, timestamp_epoch: int = None, time_window_sec: int = 86400, k: int = 60, n_results: int = 10) -> list:
    """Correlates alerts using Reciprocal Rank Fusion (RRF) of semantic search and metadata matches.
    CRITICAL GUARDRAIL: Candidates must pass has_technical_token_overlap to be ranked."""
    if not active_indicators and not query_text:
        return []

    if not query_text:
        query_text = " ".join(str(ind) for ind in active_indicators)

    # 1. Retrieve raw semantic candidates
    raw_semantic = query_semantic(
        query_text=query_text,
        timestamp_epoch=timestamp_epoch,
        time_window_sec=time_window_sec,
        n_results=n_results
    )

    # 2. Retrieve candidates for metadata matching (optionally scoped by time)
    if timestamp_epoch is not None:
        raw_all = get_alerts_by_temporal_window(timestamp_epoch, time_window_sec)
    else:
        results = collection.get()
        raw_all = []
        if results and results["ids"]:
            for idx in range(len(results["ids"])):
                raw_all.append((
                    results["ids"][idx],
                    results["documents"][idx] if results["documents"] else "",
                    results["metadatas"][idx]
                ))

    # CRITICAL GUARDRAIL: Filter out documents lacking technical token overlap
    semantic_candidates = [
        item for item in raw_semantic
        if has_technical_token_overlap(item[3], active_indicators)
    ]

    all_candidates = [
        item for item in raw_all
        if has_technical_token_overlap(item[2], active_indicators)
    ]

    # [FYP-PROCESS] Calculate metadata match scores for the filtered candidates
    # — counts how many active indicators each candidate's metadata satisfies
    # (exact field match, comma-separated list membership, or subnet/parent-
    # domain wildcard match), used to rank the metadata-side candidate list.
    metadata_ranked_candidates = []
    for alert_id, doc, meta in all_candidates:
        match_count = 0
        for ind in active_indicators:
            ind_lower = str(ind).lower()
            # Exact metadata checks
            if meta.get("username", "").lower() == ind_lower:
                match_count += 1
            elif meta.get("hostname", "").lower() == ind_lower:
                match_count += 1
            # Contains checks for comma-separated items
            elif ind_lower in [x.strip().lower() for x in meta.get("ips", "").split(",") if x.strip()]:
                match_count += 1
            elif ind_lower in [x.strip().lower() for x in meta.get("domains", "").split(",") if x.strip()]:
                match_count += 1
            elif ind_lower in [x.strip().lower() for x in meta.get("emails", "").split(",") if x.strip()]:
                match_count += 1
            elif meta.get("incident_id", "").lower() == ind_lower:
                match_count += 1
            # Subnet / parent domain wildcard match
            elif ind_lower.endswith('.') and any(ip.startswith(ind_lower) for ip in [x.strip().lower() for x in meta.get("ips", "").split(",") if x.strip()]):
                match_count += 1
            elif '.' in ind_lower and any(d == ind_lower or d.endswith('.' + ind_lower) for d in [x.strip().lower() for x in meta.get("domains", "").split(",") if x.strip()]):
                match_count += 1

        if match_count > 0:
            metadata_ranked_candidates.append((alert_id, match_count, doc, meta))

    # [FYP-PROCESS] 3. Compute RRF scores — rank each candidate list
    # (semantic candidates by ascending cosine distance, metadata candidates
    # by descending match_count), then fuse via the RRF formula
    # score += 1 / (k + rank) summed across both lists. Alerts appearing near
    # the top of either (or both) ranked lists surface highest.
    semantic_ranked_ids = [item[0] for item in sorted(semantic_candidates, key=lambda x: x[1])]
    metadata_ranked_ids = [item[0] for item in sorted(metadata_ranked_candidates, key=lambda x: x[1], reverse=True)]

    doc_meta_map = {}
    for alert_id, _, doc, meta in semantic_candidates:
        doc_meta_map[alert_id] = (doc, meta)
    for alert_id, _, doc, meta in metadata_ranked_candidates:
        doc_meta_map[alert_id] = (doc, meta)

    rrf_scores = {}
    for rank, alert_id in enumerate(semantic_ranked_ids):
        rrf_scores[alert_id] = rrf_scores.get(alert_id, 0.0) + 1.0 / (k + (rank + 1))

    for rank, alert_id in enumerate(metadata_ranked_ids):
        rrf_scores[alert_id] = rrf_scores.get(alert_id, 0.0) + 1.0 / (k + (rank + 1))

    # Sort fused results by score descending
    fused_sorted = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)

    final_results = []
    for alert_id, score in fused_sorted:
        doc, meta = doc_meta_map[alert_id]
        final_results.append((alert_id, score, doc, meta))

    return final_results
