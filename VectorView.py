## Host the database on localhost:8000 using chroma and run this script to enumerate

import os
import chromadb
from chromadb.utils import embedding_functions

def enumerate_chroma_datastore():
    """
    Connects to a ChromaDB datastore and prints all collections, 
    document counts, IDs, text content, and metadata.
    """
    # -------------------------------------------------------------
    # 1. INITIALIZE CLIENT
    # Un-comment the line matching your environment setup:
    # -------------------------------------------------------------
    
    # Option A: Local persistent directory
    # client = chromadb.PersistentClient(path="./chroma_data")
    
    # Option B: Client/Server setup (Docker or hosted instance)
    client = chromadb.HttpClient(host="localhost", port=8000)
    
    print("=" * 60)
    print(" CHROMA DATASTORE ENUMERATION REPORT")
    print("=" * 60)

    # 2. FETCH ALL COLLECTIONS IN DATABASE
    try:
        collections = client.list_collections()
    except Exception as e:
        print(f"[-] Failed to connect or retrieve collections: {e}")
        return

    if not collections:
        print("[!] The datastore is empty. No collections found.")
        return

    print(f" Found {len(collections)} total collection(s).\n")

    # 3. ENUMERATE INSIDE EACH COLLECTION
    for index, col_obj in enumerate(collections, start=1):
        print(f"--- COLLECTION #{index}: {col_obj.name} ---")
        
        # Pull standard metadata attached to the collection configuration
        print(f" │ Metadata: {col_obj.metadata}")
        
        # Get actual document count inside this individual collection
        doc_count = col_obj.count()
        print(f" │ Document Count: {doc_count}")
        
        if doc_count == 0:
            print(" │ └── (Collection is empty)")
            print("-" * 60)
            continue
            
        # 4. EXTRACT CONTENT
        # .get() with no query arguments extracts all documents up to a default limit.
        # Note: We omit embeddings=['embeddings'] to avoid polluting terminal logs,
        # but you can include it if you want to inspect raw floats.
        contents = col_obj.get(
            include=['documents', 'metadatas']
        )
        
        ids = contents.get('ids', [])
        documents = contents.get('documents', []) or [None] * len(ids)
        metadatas = contents.get('metadatas', []) or [None] * len(ids)

        print(" │ Content Breakdown:")
        for idx, (doc_id, doc_text, doc_meta) in enumerate(zip(ids, documents, metadatas), start=1):
            print(f" │   ├── Item [{idx}] ID: {doc_id}")
            
            # Print preview snippet of text document content
            if doc_text:
                preview = doc_text.replace('\n', ' ')[:80]
                suffix = "..." if len(doc_text) > 80 else ""
                print(f" │   │   Document: \"{preview}{suffix}\"")
            else:
                print(" │   │   Document: [No associated text payload]")
                
            print(f" │   │   Metadata: {doc_meta}")
            
        print("-" * 60)

if __name__ == "__main__":
    enumerate_chroma_datastore()
