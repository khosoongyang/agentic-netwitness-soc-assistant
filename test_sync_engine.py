import os
import shutil
import unittest
import asyncio
import tempfile
from typing import Generator
from sync_engine import (
    Incident,
    IncidentMetadata,
    IncidentSeverity,
    IncidentStatus,
    FileIncidentRepository,
    SQLiteIncidentRepository,
    InMemoryMockVectorIndex,
    IncidentSyncManager
)

class TestSyncEngine(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for file-based repository tests
        self.test_dir = tempfile.mkdtemp()
        self.file_repo = FileIncidentRepository(base_folder=self.test_dir)
        
        # Create a temporary file for SQLite repository tests
        self.sqlite_db_path = os.path.join(self.test_dir, "test_incidents.db")
        self.sqlite_repo = SQLiteIncidentRepository(db_path=self.sqlite_db_path)
        
        # Create the mock vector index
        self.mock_vector = InMemoryMockVectorIndex()
        
        # Define a sample incident for testing
        self.sample_incident = Incident(
            id="Incident-001",
            metadata=IncidentMetadata(
                severity=IncidentSeverity.HIGH,
                status=IncidentStatus.TRIAGED,
                assigned_analyst="Analyst-123",
                source_type="Authentication"
            ),
            raw_alerts=[
                {"alert_id": "A1", "type": "Brute Force", "source_ip": "10.0.0.5"}
            ],
            summary_text="Incident-001 involves multiple failed authentication attempts from IP 10.0.0.5.",
            indicators=["10.0.0.5", "Analyst-123"]
        )

    def tearDown(self):
        # Clean up temporary directories and databases
        shutil.rmtree(self.test_dir, ignore_errors=True)
        # Ensure any active SQLite DB file is deleted
        if os.path.exists(self.sqlite_db_path):
            try:
                os.remove(self.sqlite_db_path)
            except OSError:
                pass

    def run_async(self, coro):
        """Helper to run async test cases in the event loop."""
        return asyncio.run(coro)

    # ==========================================
    # TESTS FOR FILE INCIDENT REPOSITORY
    # ==========================================

    def test_file_repo_creation_success(self):
        async def run():
            manager = IncidentSyncManager(self.file_repo, self.mock_vector)
            await manager.create_incident(self.sample_incident)
            
            # Verify database (file) has it
            db_incident = await self.file_repo.get("Incident-001")
            self.assertIsNotNone(db_incident)
            self.assertEqual(db_incident.summary_text, self.sample_incident.summary_text)
            
            # Verify vector store has it
            self.assertIn("Incident-001", self.mock_vector.store)
            self.assertEqual(self.mock_vector.store["Incident-001"].summary_text, self.sample_incident.summary_text)

        self.run_async(run())

    def test_file_repo_vector_failure_rollback(self):
        async def run():
            manager = IncidentSyncManager(self.file_repo, self.mock_vector)
            
            # Configure vector store to fail during creation
            self.mock_vector.should_fail_upsert = True
            
            with self.assertRaises(RuntimeError) as context:
                await manager.create_incident(self.sample_incident)
            
            self.assertIn("Simulated Vector Index Upsert Failure", str(context.exception))
            
            # Verify DB did NOT commit (file does not exist)
            db_incident = await self.file_repo.get("Incident-001")
            self.assertIsNone(db_incident)
            
            # Verify vector store does not have it
            self.assertNotIn("Incident-001", self.mock_vector.store)

        self.run_async(run())

    def test_file_repo_db_commit_failure_compensation(self):
        async def run():
            manager = IncidentSyncManager(self.file_repo, self.mock_vector)
            
            # Mock repo commit to fail
            original_commit = self.file_repo.commit
            async def failing_commit():
                raise RuntimeError("Simulated Database Commit Failure")
            self.file_repo.commit = failing_commit
            
            with self.assertRaises(RuntimeError) as context:
                await manager.create_incident(self.sample_incident)
                
            self.assertIn("Simulated Database Commit Failure", str(context.exception))
            
            # Restore commit
            self.file_repo.commit = original_commit
            
            # Verify DB does not have it (rolled back)
            db_incident = await self.file_repo.get("Incident-001")
            self.assertIsNone(db_incident)
            
            # Verify vector store compensation triggered (item deleted from vector index)
            self.assertNotIn("Incident-001", self.mock_vector.store)

        self.run_async(run())

    def test_file_repo_update_success(self):
        async def run():
            manager = IncidentSyncManager(self.file_repo, self.mock_vector)
            await manager.create_incident(self.sample_incident)
            
            # Update values
            updated_incident = self.sample_incident.model_copy(deep=True)
            updated_incident.summary_text = "Updated technical narrative."
            updated_incident.metadata.status = IncidentStatus.INVESTIGATING
            
            await manager.update_incident(updated_incident)
            
            # Verify DB has updated values
            db_incident = await self.file_repo.get("Incident-001")
            self.assertEqual(db_incident.summary_text, "Updated technical narrative.")
            self.assertEqual(db_incident.metadata.status, IncidentStatus.INVESTIGATING)
            
            # Verify vector store has updated values
            self.assertEqual(self.mock_vector.store["Incident-001"].summary_text, "Updated technical narrative.")

        self.run_async(run())

    def test_file_repo_update_vector_failure_rollback(self):
        async def run():
            manager = IncidentSyncManager(self.file_repo, self.mock_vector)
            await manager.create_incident(self.sample_incident)
            
            # Configure vector store to fail on next upsert
            self.mock_vector.should_fail_upsert = True
            
            updated_incident = self.sample_incident.model_copy(deep=True)
            updated_incident.summary_text = "Should not be saved."
            
            with self.assertRaises(RuntimeError):
                await manager.update_incident(updated_incident)
                
            # Verify DB rolled back (still has original narrative)
            db_incident = await self.file_repo.get("Incident-001")
            self.assertEqual(db_incident.summary_text, self.sample_incident.summary_text)
            
            # Verify Vector Store still has original narrative
            self.mock_vector.should_fail_upsert = False
            self.assertEqual(self.mock_vector.store["Incident-001"].summary_text, self.sample_incident.summary_text)

        self.run_async(run())

    def test_file_repo_update_commit_failure_compensation(self):
        async def run():
            manager = IncidentSyncManager(self.file_repo, self.mock_vector)
            await manager.create_incident(self.sample_incident)
            
            updated_incident = self.sample_incident.model_copy(deep=True)
            updated_incident.summary_text = "Staged update text."
            
            # Mock commit to fail
            original_commit = self.file_repo.commit
            async def failing_commit():
                raise RuntimeError("Simulated Database Commit Failure")
            self.file_repo.commit = failing_commit
            
            with self.assertRaises(RuntimeError):
                await manager.update_incident(updated_incident)
                
            self.file_repo.commit = original_commit
            
            # Verify DB still has original (not committed)
            db_incident = await self.file_repo.get("Incident-001")
            self.assertEqual(db_incident.summary_text, self.sample_incident.summary_text)
            
            # Verify Vector Store reverted/compensated to original summary
            self.assertEqual(self.mock_vector.store["Incident-001"].summary_text, self.sample_incident.summary_text)

        self.run_async(run())

    def test_file_repo_delete_success(self):
        async def run():
            manager = IncidentSyncManager(self.file_repo, self.mock_vector)
            await manager.create_incident(self.sample_incident)
            
            await manager.delete_incident("Incident-001")
            
            # Verify deleted from DB
            db_incident = await self.file_repo.get("Incident-001")
            self.assertIsNone(db_incident)
            
            # Verify deleted from Vector store
            self.assertNotIn("Incident-001", self.mock_vector.store)

        self.run_async(run())

    def test_file_repo_delete_vector_failure_rollback(self):
        async def run():
            manager = IncidentSyncManager(self.file_repo, self.mock_vector)
            await manager.create_incident(self.sample_incident)
            
            # Configure vector store to fail on delete
            self.mock_vector.should_fail_delete = True
            
            with self.assertRaises(RuntimeError):
                await manager.delete_incident("Incident-001")
                
            # Verify DB rolled back deletion (file still exists)
            db_incident = await self.file_repo.get("Incident-001")
            self.assertIsNotNone(db_incident)
            
            # Verify still in vector store
            self.mock_vector.should_fail_delete = False
            self.assertIn("Incident-001", self.mock_vector.store)

        self.run_async(run())

    def test_file_repo_delete_commit_failure_compensation(self):
        async def run():
            manager = IncidentSyncManager(self.file_repo, self.mock_vector)
            await manager.create_incident(self.sample_incident)
            
            # Mock commit to fail
            original_commit = self.file_repo.commit
            async def failing_commit():
                raise RuntimeError("Simulated Database Commit Failure")
            self.file_repo.commit = failing_commit
            
            with self.assertRaises(RuntimeError):
                await manager.delete_incident("Incident-001")
                
            self.file_repo.commit = original_commit
            
            # Verify DB has incident (rolled back delete)
            db_incident = await self.file_repo.get("Incident-001")
            self.assertIsNotNone(db_incident)
            
            # Verify Vector Store restored (compensation re-upserted)
            self.assertIn("Incident-001", self.mock_vector.store)
            self.assertEqual(self.mock_vector.store["Incident-001"].summary_text, self.sample_incident.summary_text)

        self.run_async(run())

    # ==========================================
    # TESTS FOR SQLITE INCIDENT REPOSITORY
    # ==========================================

    def test_sqlite_repo_creation_success(self):
        async def run():
            manager = IncidentSyncManager(self.sqlite_repo, self.mock_vector)
            await manager.create_incident(self.sample_incident)
            
            # Verify database has it
            db_incident = await self.sqlite_repo.get("Incident-001")
            self.assertIsNotNone(db_incident)
            self.assertEqual(db_incident.summary_text, self.sample_incident.summary_text)
            
            # Verify vector store has it
            self.assertIn("Incident-001", self.mock_vector.store)
            self.assertEqual(self.mock_vector.store["Incident-001"].summary_text, self.sample_incident.summary_text)

        self.run_async(run())

    def test_sqlite_repo_vector_failure_rollback(self):
        async def run():
            manager = IncidentSyncManager(self.sqlite_repo, self.mock_vector)
            
            # Configure vector store to fail during creation
            self.mock_vector.should_fail_upsert = True
            
            with self.assertRaises(RuntimeError) as context:
                await manager.create_incident(self.sample_incident)
            
            self.assertIn("Simulated Vector Index Upsert Failure", str(context.exception))
            
            # Verify DB did NOT commit (does not exist in SQLite DB)
            db_incident = await self.sqlite_repo.get("Incident-001")
            self.assertIsNone(db_incident)
            
            # Verify vector store does not have it
            self.assertNotIn("Incident-001", self.mock_vector.store)

        self.run_async(run())

    def test_sqlite_repo_db_commit_failure_compensation(self):
        async def run():
            manager = IncidentSyncManager(self.sqlite_repo, self.mock_vector)
            
            # Mock commit to fail
            original_commit = self.sqlite_repo.commit
            async def failing_commit():
                # We need to perform the rollback internally to clean up connections
                await self.sqlite_repo.rollback()
                raise RuntimeError("Simulated SQLite Commit Failure")
            self.sqlite_repo.commit = failing_commit
            
            with self.assertRaises(RuntimeError) as context:
                await manager.create_incident(self.sample_incident)
                
            self.assertIn("Simulated SQLite Commit Failure", str(context.exception))
            
            # Restore commit
            self.sqlite_repo.commit = original_commit
            
            # Verify DB does not have it (rolled back)
            db_incident = await self.sqlite_repo.get("Incident-001")
            self.assertIsNone(db_incident)
            
            # Verify vector store compensation triggered (item deleted from vector index)
            self.assertNotIn("Incident-001", self.mock_vector.store)

        self.run_async(run())

    def test_sqlite_repo_delete_success(self):
        async def run():
            manager = IncidentSyncManager(self.sqlite_repo, self.mock_vector)
            await manager.create_incident(self.sample_incident)
            
            await manager.delete_incident("Incident-001")
            
            # Verify deleted from DB
            db_incident = await self.sqlite_repo.get("Incident-001")
            self.assertIsNone(db_incident)
            
            # Verify deleted from Vector store
            self.assertNotIn("Incident-001", self.mock_vector.store)

        self.run_async(run())

    def test_realtime_sync_service_lifecycle(self):
        async def run():
            from sync_engine import RealtimeSyncService
            import time
            
            service = RealtimeSyncService(base_folder=self.test_dir, db_path=self.test_dir)
            
            # 1. Verify initially empty
            await service.sync_once(self.mock_vector)
            self.assertEqual(len(self.mock_vector.store), 0)
            
            # 2. Add an incident folder & file manually
            inc_dir = os.path.join(self.test_dir, "Incident-999")
            os.makedirs(inc_dir, exist_ok=True)
            
            incident_data = self.sample_incident.model_copy(deep=True)
            incident_data.id = "Incident-999"
            incident_data.summary_text = "Realtime watch test narrative."
            
            json_path = os.path.join(inc_dir, "incident_data.json")
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(incident_data.model_dump_json())
                
            # Trigger sync once
            await service.sync_once(self.mock_vector)
            
            # Verify synced to vector store
            self.assertIn("Incident-999", self.mock_vector.store)
            self.assertEqual(self.mock_vector.store["Incident-999"].summary_text, "Realtime watch test narrative.")
            
            # 3. Update the incident file manually
            # Sleep slightly to ensure timestamp resolution increases
            time.sleep(0.01)
            
            incident_data.summary_text = "Updated narrative in real-time."
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(incident_data.model_dump_json())
            
            # Force mtime forward to guarantee the watcher detects it
            os.utime(json_path, (time.time() + 10, time.time() + 10))
            
            # Trigger sync once
            await service.sync_once(self.mock_vector)
            
            # Verify update synced
            self.assertEqual(self.mock_vector.store["Incident-999"].summary_text, "Updated narrative in real-time.")
            
            # 4. Delete the incident file manually
            os.remove(json_path)
            
            # Trigger sync once
            await service.sync_once(self.mock_vector)
            
            # Verify deletion synced
            self.assertNotIn("Incident-999", self.mock_vector.store)
            
        self.run_async(run())

if __name__ == "__main__":
    unittest.main()
