import os
import time
import asyncio
import argparse
import logging
from sync_engine import RealtimeSyncService, logger

# Set logging level for daemon output
logging.getLogger("SyncEngine").setLevel(logging.INFO)

async def main():
    parser = argparse.ArgumentParser(description="Real-Time Incident Directory Watcher Sync Daemon")
    parser.add_argument("--folder", default="incident_reports", help="Path to incident reports directory")
    parser.add_argument("--db", default="ChromaDatabase", help="Path to ChromaDB persistent storage")
    parser.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds")
    args = parser.parse_args()

    # Create reports directory if it doesn't exist yet
    os.makedirs(args.folder, exist_ok=True)

    print("=" * 60)
    print("REAL-TIME INCIDENT SYNC DAEMON ACTIVE")
    print(f"Watching folder: {os.path.abspath(args.folder)}")
    print(f"Targeting DB:    {os.path.abspath(args.db)}")
    print(f"Interval:        {args.interval} seconds")
    print("=" * 60)
    
    service = RealtimeSyncService(base_folder=args.folder, db_path=args.db, interval=args.interval)
    await service.start()
    
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down Sync Daemon...")
    finally:
        await service.stop()
        print("Sync Daemon stopped successfully.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
