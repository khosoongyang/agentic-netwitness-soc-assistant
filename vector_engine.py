import os
import chromadb
from chromadb.utils import embedding_functions

# Initialize persistent local ChromaDB client
DB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "ChromaDatabase"))
client = chromadb.PersistentClient(path=DB_DIR)

# Use default local embedding function (SentenceTransformers / ONNX MiniLM-L6-v2)
default_ef = embedding_functions.DefaultEmbeddingFunction()

# Create or retrieve the collection configured for cosine similarity
collection = client.get_or_create_collection(
    name="soc_alerts",
    embedding_function=default_ef,
    metadata={"hnsw:space": "cosine"}
)

def clear_collection():
    """Helper function to reset collection database."""
    global collection
    try:
        client.delete_collection("soc_alerts")
    except Exception:
        pass
    collection = client.get_or_create_collection(
        name="soc_alerts",
        embedding_function=default_ef,
        metadata={"hnsw:space": "cosine"}
    )

def ingest_logs(logs_list: list):
    """Upserts list of processed logs containing 'id', 'document', and 'metadata' into ChromaDB."""
    if not logs_list:
        return
    ids = [log["id"] for log in logs_list]
    documents = [log["document"] for log in logs_list]
    metadatas = [log["metadata"] for log in logs_list]
    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)

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
    
    parsed = []
    if results and results["ids"] and results["ids"][0]:
        for idx in range(len(results["ids"][0])):
            alert_id = results["ids"][0][idx]
            dist = results["distances"][0][idx]
            doc = results["documents"][0][idx]
            meta = results["metadatas"][0][idx]
            parsed.append((alert_id, dist, doc, meta))
    return parsed

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
    
    # Calculate metadata match scores for the filtered candidates
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
            
    # 3. Compute RRF scores
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
