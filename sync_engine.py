import os
import json
import time
import sqlite3
import logging
import asyncio
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, List, Dict, Set, Any
from pydantic import BaseModel, Field, model_validator

# Configure logger
logger = logging.getLogger("SyncEngine")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

# ==========================================
# STAGE 1: Data Schemas & Models
# ==========================================

class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

class IncidentMetadata(BaseModel):
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    status: IncidentStatus = IncidentStatus.NEW
    assigned_analyst: Optional[str] = None
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    source_type: str = "Default"
    similar_to_incident: Optional[str] = None

    @model_validator(mode='before')
    @classmethod
    def set_timestamps(cls, data: Any) -> Any:
        if isinstance(data, dict):
            now = time.time()
            if 'created_at' not in data:
                data['created_at'] = now
            if 'updated_at' not in data:
                data['updated_at'] = now
        return data

class Incident(BaseModel):
    id: str = Field(..., description="Unique incident identifier, e.g., Incident-001")
    metadata: IncidentMetadata = Field(default_factory=IncidentMetadata)
    raw_alerts: List[Dict[str, Any]] = Field(default_factory=list, description="Array of raw alert log dictionaries")
    summary_text: str = Field(..., description="Chronological technical summary text used for embeddings")
    indicators: List[str] = Field(default_factory=list, description="Extracted forensic indicators (IPs, hashes, domains)")

# ==========================================
# STAGE 2: Interface Abstractions
# ==========================================

class BaseIncidentRepository(ABC):
    """Abstract Base Class for primary incident relational data stores."""
    
    @abstractmethod
    async def begin(self) -> None:
        """Starts a session transaction."""
        pass

    @abstractmethod
    async def commit(self) -> None:
        """Commits all staged database operations."""
        pass

    @abstractmethod
    async def rollback(self) -> None:
        """Rolls back all staged database operations."""
        pass

    @abstractmethod
    async def save(self, incident: Incident) -> None:
        """Stages an incident creation or update in the transaction."""
        pass

    @abstractmethod
    async def delete(self, incident_id: str) -> None:
        """Stages an incident deletion in the transaction."""
        pass

    @abstractmethod
    async def get(self, incident_id: str) -> Optional[Incident]:
        """Fetches an incident by ID. Inside a transaction, should reflect staged writes/deletions."""
        pass


class BaseVectorIndex(ABC):
    """Abstract Base Class for vector/text-search indices."""

    @abstractmethod
    async def upsert(self, incident: Incident) -> None:
        """Upserts an incident document embedding and metadata to the search index."""
        pass

    @abstractmethod
    async def delete(self, incident_id: str) -> None:
        """Completely deletes an incident from the search index."""
        pass

    @abstractmethod
    async def query(self, query_text: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Queries the vector index for semantically similar incidents."""
        pass


# ==========================================
# STAGE 3: Concrete Implementations
# ==========================================

class FileIncidentRepository(BaseIncidentRepository):
    """
    Folder-based storage implementation storing incidents in 'incident_reports/Incident-XXX/incident_data.json'.
    Implements full transactional staging using in-memory caches to support rollback & commit.
    """
    def __init__(self, base_folder: str = "incident_reports"):
        self.base_folder = base_folder
        self._staged_saves: Dict[str, Incident] = {}
        self._staged_deletes: Set[str] = set()
        self._in_transaction = False

    def _get_file_paths(self, incident_id: str) -> tuple[str, str]:
        folder_path = os.path.join(self.base_folder, incident_id)
        file_path = os.path.join(folder_path, "incident_data.json")
        return folder_path, file_path

    async def begin(self) -> None:
        if self._in_transaction:
            raise RuntimeError("Transaction already active.")
        self._staged_saves.clear()
        self._staged_deletes.clear()
        self._in_transaction = True
        logger.debug("FileIncidentRepository: Transaction started.")

    async def commit(self) -> None:
        if not self._in_transaction:
            raise RuntimeError("No active transaction to commit.")

        # Run disk writes inside a thread pool to be asynchronous
        await asyncio.to_thread(self._commit_disk)
        self._in_transaction = False
        logger.debug("FileIncidentRepository: Transaction committed.")

    def _commit_disk(self):
        # 1. Process deletions
        for incident_id in self._staged_deletes:
            folder_path, file_path = self._get_file_paths(incident_id)
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"Deleted incident file: {file_path}")
            
            # If the directory is now empty, clean it up
            if os.path.exists(folder_path) and not os.listdir(folder_path):
                os.rmdir(folder_path)
                logger.info(f"Removed empty folder: {folder_path}")

        # 2. Process saves
        for incident_id, incident in self._staged_saves.items():
            folder_path, file_path = self._get_file_paths(incident_id)
            os.makedirs(folder_path, exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(incident.model_dump_json(indent=2))
            logger.info(f"Saved incident file: {file_path}")

        self._staged_saves.clear()
        self._staged_deletes.clear()

    async def rollback(self) -> None:
        if not self._in_transaction:
            raise RuntimeError("No active transaction to rollback.")
        self._staged_saves.clear()
        self._staged_deletes.clear()
        self._in_transaction = False
        logger.debug("FileIncidentRepository: Transaction rolled back.")

    async def save(self, incident: Incident) -> None:
        if not self._in_transaction:
            raise RuntimeError("Cannot save outside a transaction. Call begin() first.")
        self._staged_saves[incident.id] = incident
        self._staged_deletes.discard(incident.id)

    async def delete(self, incident_id: str) -> None:
        if not self._in_transaction:
            raise RuntimeError("Cannot delete outside a transaction. Call begin() first.")
        self._staged_deletes.add(incident_id)
        self._staged_saves.pop(incident_id, None)

    async def get(self, incident_id: str) -> Optional[Incident]:
        # Support Read-Your-Own-Writes within transaction
        if self._in_transaction:
            if incident_id in self._staged_deletes:
                return None
            if incident_id in self._staged_saves:
                return self._staged_saves[incident_id]

        _, file_path = self._get_file_paths(incident_id)
        if not await asyncio.to_thread(os.path.exists, file_path):
            return None

        def read_file():
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)

        try:
            data = await asyncio.to_thread(read_file)
            return Incident.model_validate(data)
        except Exception as e:
            logger.error(f"Failed to read incident {incident_id} from disk: {e}")
            return None


class SQLiteIncidentRepository(BaseIncidentRepository):
    """
    Relational database implementation using SQLite.
    Demonstrates transition path to relational DBs with ACID transaction rollback/commit.
    """
    def __init__(self, db_path: str = "soc_incidents.db"):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._in_transaction = False
        
        # Initialize schema synchronously
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                summary_text TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                raw_alerts_json TEXT NOT NULL,
                indicators_json TEXT NOT NULL
            );
        """)
        conn.commit()
        conn.close()

    async def begin(self) -> None:
        if self._in_transaction:
            raise RuntimeError("Transaction already active.")
        
        # Open connection and disable autocommit
        self._conn = await asyncio.to_thread(sqlite3.connect, self.db_path, isolation_level=None, check_same_thread=False)
        await asyncio.to_thread(self._conn.execute, "BEGIN TRANSACTION;")
        self._in_transaction = True
        logger.debug("SQLiteIncidentRepository: Transaction started.")

    async def commit(self) -> None:
        if not self._in_transaction or not self._conn:
            raise RuntimeError("No active transaction to commit.")
        try:
            await asyncio.to_thread(self._conn.execute, "COMMIT;")
            logger.debug("SQLiteIncidentRepository: Transaction committed.")
        finally:
            await asyncio.to_thread(self._conn.close)
            self._conn = None
            self._in_transaction = False

    async def rollback(self) -> None:
        if not self._in_transaction or not self._conn:
            raise RuntimeError("No active transaction to rollback.")
        try:
            await asyncio.to_thread(self._conn.execute, "ROLLBACK;")
            logger.debug("SQLiteIncidentRepository: Transaction rolled back.")
        finally:
            await asyncio.to_thread(self._conn.close)
            self._conn = None
            self._in_transaction = False

    async def save(self, incident: Incident) -> None:
        if not self._in_transaction or not self._conn:
            raise RuntimeError("Cannot save outside a transaction.")
        
        def execute_save():
            cursor = self._conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO incidents (id, summary_text, metadata_json, raw_alerts_json, indicators_json)
                VALUES (?, ?, ?, ?, ?);
                """,
                (
                    incident.id,
                    incident.summary_text,
                    incident.metadata.model_dump_json(),
                    json.dumps(incident.raw_alerts),
                    json.dumps(incident.indicators)
                )
            )

        await asyncio.to_thread(execute_save)

    async def delete(self, incident_id: str) -> None:
        if not self._in_transaction or not self._conn:
            raise RuntimeError("Cannot delete outside a transaction.")

        def execute_delete():
            cursor = self._conn.cursor()
            cursor.execute("DELETE FROM incidents WHERE id = ?;", (incident_id,))

        await asyncio.to_thread(execute_delete)

    async def get(self, incident_id: str) -> Optional[Incident]:
        def fetch_row():
            # If inside active transaction, use transaction's connection to see staged changes
            if self._in_transaction and self._conn:
                cursor = self._conn.cursor()
                cursor.execute("SELECT summary_text, metadata_json, raw_alerts_json, indicators_json FROM incidents WHERE id = ?;", (incident_id,))
                return cursor.fetchone()
            else:
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT summary_text, metadata_json, raw_alerts_json, indicators_json FROM incidents WHERE id = ?;", (incident_id,))
                    return cursor.fetchone()
                finally:
                    conn.close()

        row = await asyncio.to_thread(fetch_row)
        if not row:
            return None

        summary_text, meta_json, alerts_json, ind_json = row
        return Incident(
            id=incident_id,
            metadata=IncidentMetadata.model_validate_json(meta_json),
            raw_alerts=json.loads(alerts_json),
            summary_text=summary_text,
            indicators=json.loads(ind_json)
        )


class ChromaIncidentVectorStore(BaseVectorIndex):
    """
    ChromaDB vector index wrapper mapping Incident summaries into embeddings.
    Uses 'soc_incidents' collection.
    """
    def __init__(self, db_path: str = "ChromaDatabase"):
        import chromadb
        from chromadb.utils import embedding_functions
        self.client = chromadb.PersistentClient(path=db_path)
        self.default_ef = embedding_functions.DefaultEmbeddingFunction()
        self.collection = self.client.get_or_create_collection(
            name="soc_incidents",
            embedding_function=self.default_ef,
            metadata={"hnsw:space": "cosine"}
        )

    async def upsert(self, incident: Incident) -> None:
        metadata = {
            "incident_id": incident.id,
            "severity": incident.metadata.severity.value,
            "status": incident.metadata.status.value,
            "assigned_analyst": incident.metadata.assigned_analyst or "None",
            "created_at": incident.metadata.created_at,
            "updated_at": incident.metadata.updated_at,
            "source_type": incident.metadata.source_type,
            "indicators": ",".join(incident.indicators),
            "similar_to_incident": incident.metadata.similar_to_incident or "None"
        }
        
        def execute_upsert():
            self.collection.upsert(
                ids=[incident.id],
                documents=[incident.summary_text],
                metadatas=[metadata]
            )

        await asyncio.to_thread(execute_upsert)
        logger.info(f"ChromaIncidentVectorStore: Upserted incident {incident.id}")

    async def delete(self, incident_id: str) -> None:
        def execute_delete():
            self.collection.delete(ids=[incident_id])

        await asyncio.to_thread(execute_delete)
        logger.info(f"ChromaIncidentVectorStore: Deleted incident {incident_id}")

    async def query(self, query_text: str, limit: int = 5) -> List[Dict[str, Any]]:
        def execute_query():
            return self.collection.query(
                query_texts=[query_text],
                n_results=limit
            )

        results = await asyncio.to_thread(execute_query)
        parsed = []
        if results and results["ids"] and results["ids"][0]:
            for idx in range(len(results["ids"][0])):
                parsed.append({
                    "id": results["ids"][0][idx],
                    "score": results["distances"][0][idx] if "distances" in results and results["distances"] else 0.0,
                    "document": results["documents"][0][idx] if "documents" in results and results["documents"] else "",
                    "metadata": results["metadatas"][0][idx] if "metadatas" in results and results["metadatas"] else {}
                })
        return parsed


class InMemoryMockVectorIndex(BaseVectorIndex):
    """
    Mock in-memory vector/search index.
    Allows simulating failures on demand to verify transaction rollbacks and compensation logic.
    """
    def __init__(self):
        self.store: Dict[str, Incident] = {}
        self.should_fail_upsert = False
        self.should_fail_delete = False

    async def upsert(self, incident: Incident) -> None:
        if self.should_fail_upsert:
            raise RuntimeError("Simulated Vector Index Upsert Failure")
        self.store[incident.id] = incident
        logger.debug(f"MockVectorIndex: Upserted {incident.id}")

    async def delete(self, incident_id: str) -> None:
        if self.should_fail_delete:
            raise RuntimeError("Simulated Vector Index Delete Failure")
        self.store.pop(incident_id, None)
        logger.debug(f"MockVectorIndex: Deleted {incident_id}")

    async def query(self, query_text: str, limit: int = 5) -> List[Dict[str, Any]]:
        # Simple string containment mock query
        results = []
        for inc_id, inc in self.store.items():
            if query_text.lower() in inc.summary_text.lower():
                results.append({
                    "id": inc_id,
                    "score": 1.0,
                    "document": inc.summary_text,
                    "metadata": {"incident_id": inc_id}
                })
            if len(results) >= limit:
                break
        return results


# ==========================================
# STAGE 3: Coordinated Transaction Manager
# ==========================================

class IncidentSyncManager:
    """
    Orchestrates the synchronized life-cycle of Incidents between the primary database
    and the vector search index, preventing stale data through two-way rollbacks and compensation actions.
    """
    def __init__(self, repository: BaseIncidentRepository, vector_index: BaseVectorIndex):
        self.repo = repository
        self.vector_index = vector_index

    async def create_incident(self, incident: Incident) -> None:
        """
        Registers a new Incident.
        Rolls back the DB transaction if the vector index fails.
        Triggers compensation (deleting vector index entry) if the DB transaction commit fails.
        """
        logger.info(f"IncidentSyncManager: Initiating creation of incident {incident.id}")
        
        # 1. Open primary DB transaction
        await self.repo.begin()
        
        # 2. Stage DB save
        try:
            await self.repo.save(incident)
        except Exception as e:
            logger.error(f"IncidentSyncManager: Failed to stage DB write for {incident.id}. Aborting. Error: {e}")
            await self.repo.rollback()
            raise e

        # 3. Write to Vector Search Index
        try:
            await self.vector_index.upsert(incident)
        except Exception as e:
            logger.error(f"IncidentSyncManager: Failed to write to vector index for {incident.id}. Rolling back DB. Error: {e}")
            await self.repo.rollback()
            raise e

        # 4. Commit Primary DB Transaction
        try:
            await self.repo.commit()
        except Exception as e:
            logger.error(f"IncidentSyncManager: Failed to commit DB transaction for {incident.id}. Triggering rollback and vector compensation delete. Error: {e}")
            try:
                await self.repo.rollback()
            except Exception as re:
                logger.error(f"Failed to rollback DB transaction: {re}")
            # Compensation Action: Delete from vector index
            try:
                await self.vector_index.delete(incident.id)
            except Exception as ve:
                logger.critical(f"IncidentSyncManager: CRITICAL! Vector compensation delete failed for {incident.id}: {ve}")
            raise e

        logger.info(f"IncidentSyncManager: Successfully created and synced incident {incident.id}")

    async def update_incident(self, incident: Incident) -> None:
        """
        Updates an existing Incident.
        Rolls back the DB transaction if the vector index fails.
        Triggers compensation (restores original vector index entry) if the DB transaction commit fails.
        """
        logger.info(f"IncidentSyncManager: Initiating update of incident {incident.id}")
        
        # Fetch original incident to support rollback/compensation restore
        original_incident = await self.repo.get(incident.id)
        if not original_incident:
            logger.warning(f"IncidentSyncManager: Update target {incident.id} not found in DB. Reverting to creation sync.")
            await self.create_incident(incident)
            return

        # 1. Open primary DB transaction
        await self.repo.begin()
        
        # 2. Stage DB save (update)
        try:
            await self.repo.save(incident)
        except Exception as e:
            logger.error(f"IncidentSyncManager: Failed to stage DB update for {incident.id}. Aborting. Error: {e}")
            await self.repo.rollback()
            raise e

        # 3. Update Vector Search Index
        try:
            await self.vector_index.upsert(incident)
        except Exception as e:
            logger.error(f"IncidentSyncManager: Failed to update vector index for {incident.id}. Rolling back DB. Error: {e}")
            await self.repo.rollback()
            raise e

        # 4. Commit Primary DB Transaction
        try:
            await self.repo.commit()
        except Exception as e:
            logger.error(f"IncidentSyncManager: Failed to commit DB update transaction for {incident.id}. Triggering rollback and vector compensation restore. Error: {e}")
            try:
                await self.repo.rollback()
            except Exception as re:
                logger.error(f"Failed to rollback DB transaction: {re}")
            # Compensation Action: Restore original vector index entry
            try:
                await self.vector_index.upsert(original_incident)
            except Exception as ve:
                logger.critical(f"IncidentSyncManager: CRITICAL! Vector compensation restore failed for {incident.id}: {ve}")
            raise e

        logger.info(f"IncidentSyncManager: Successfully updated and synced incident {incident.id}")

    async def delete_incident(self, incident_id: str) -> None:
        """
        Completely invalidates and removes an Incident.
        Rolls back the DB transaction if the vector index delete fails.
        Triggers compensation (restores original vector index entry) if the DB transaction commit fails.
        """
        logger.info(f"IncidentSyncManager: Initiating deletion of incident {incident_id}")
        
        # Fetch original incident to support rollback/compensation restore
        original_incident = await self.repo.get(incident_id)
        if not original_incident:
            logger.warning(f"IncidentSyncManager: Deletion target {incident_id} not found in DB. Invalidation skipped.")
            return

        # 1. Open primary DB transaction
        await self.repo.begin()
        
        # 2. Stage DB deletion
        try:
            await self.repo.delete(incident_id)
        except Exception as e:
            logger.error(f"IncidentSyncManager: Failed to stage DB deletion for {incident_id}. Aborting. Error: {e}")
            await self.repo.rollback()
            raise e

        # 3. Delete from Vector Search Index
        try:
            await self.vector_index.delete(incident_id)
        except Exception as e:
            logger.error(f"IncidentSyncManager: Failed to delete from vector index for {incident_id}. Rolling back DB. Error: {e}")
            await self.repo.rollback()
            raise e

        # 4. Commit Primary DB Transaction
        try:
            await self.repo.commit()
        except Exception as e:
            logger.error(f"IncidentSyncManager: Failed to commit DB deletion transaction for {incident_id}. Triggering rollback and vector compensation restore. Error: {e}")
            try:
                await self.repo.rollback()
            except Exception as re:
                logger.error(f"Failed to rollback DB transaction: {re}")
            # Compensation Action: Restore original vector index entry
            try:
                await self.vector_index.upsert(original_incident)
            except Exception as ve:
                logger.critical(f"IncidentSyncManager: CRITICAL! Vector compensation restore failed for {incident_id}: {ve}")
            raise e

        logger.info(f"IncidentSyncManager: Successfully deleted and invalidated incident {incident_id}")

# ==========================================
# STAGE 4: Real-Time Sync Service
# ==========================================

class RealtimeSyncService:
    """
    Asynchronously monitors the incident_reports folder for changes to incident_data.json
    and synchronizes them with the vector index (soc_incidents).
    """
    def __init__(self, base_folder: str = "incident_reports", db_path: str = "ChromaDatabase", interval: float = 2.0):
        self.base_folder = base_folder
        self.db_path = db_path
        self.interval = interval
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._seen_mtimes: Dict[str, float] = {}  # incident_id -> mtime

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._sync_loop())
        logger.info(f"RealtimeSyncService: Monitoring folder '{self.base_folder}' every {self.interval}s.")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("RealtimeSyncService: Stopped monitoring.")

    async def _sync_loop(self) -> None:
        # Initialize the vector store inside the loop
        vector_store = ChromaIncidentVectorStore(db_path=self.db_path)
        
        while self._running:
            try:
                await self.sync_once(vector_store)
            except Exception as e:
                logger.error(f"RealtimeSyncService: Error in sync loop: {e}")
            await asyncio.sleep(self.interval)

    async def sync_once(self, vector_store: BaseVectorIndex) -> None:
        """Runs a single iteration of filesystem scanning and vector store updates."""
        if not os.path.exists(self.base_folder):
            return

        current_incidents: Dict[str, tuple[str, float]] = {}

        # 1. Scan filesystem for folder-based incidents containing incident_data.json
        try:
            items = os.listdir(self.base_folder)
        except OSError as e:
            logger.error(f"RealtimeSyncService: Failed to list directory {self.base_folder}: {e}")
            return

        for item in items:
            item_path = os.path.join(self.base_folder, item)
            if os.path.isdir(item_path):
                # Folders are typically named 'Incident-XXX' or similar
                json_path = os.path.join(item_path, "incident_data.json")
                if os.path.exists(json_path):
                    try:
                        mtime = os.path.getmtime(json_path)
                        current_incidents[item] = (json_path, mtime)
                    except OSError:
                        pass

        # 2. Identify and handle deleted incidents (present in seen registry but missing from disk)
        deleted_ids = [inc_id for inc_id in self._seen_mtimes if inc_id not in current_incidents]
        for inc_id in deleted_ids:
            logger.info(f"RealtimeSyncService: Detected deletion of incident {inc_id}. Invalidating from vector index.")
            try:
                await vector_store.delete(inc_id)
                self._seen_mtimes.pop(inc_id, None)
            except Exception as e:
                logger.error(f"RealtimeSyncService: Failed to delete incident {inc_id} from vector store: {e}")

        # 3. Identify and handle created or updated incidents
        for inc_id, (json_path, mtime) in current_incidents.items():
            last_mtime = self._seen_mtimes.get(inc_id)
            if last_mtime is None or mtime > last_mtime:
                action = "creation" if last_mtime is None else "modification"
                logger.info(f"RealtimeSyncService: Detected {action} of incident {inc_id}. Syncing to vector index.")
                
                try:
                    def read_json():
                        with open(json_path, "r", encoding="utf-8") as f:
                            return json.load(f)
                    
                    data = await asyncio.to_thread(read_json)
                    incident = Incident.model_validate(data)
                    
                    # Ensure the ID in the JSON matches the directory name
                    incident.id = inc_id
                    
                    # Upsert to vector index
                    await vector_store.upsert(incident)
                    self._seen_mtimes[inc_id] = mtime
                except Exception as e:
                    logger.error(f"RealtimeSyncService: Failed to sync incident {inc_id} from {json_path}: {e}")
