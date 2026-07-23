# 🛡️ SOC Platform v2

## Quick Start

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Features

### NetWitness Integration
- **Import token manually** — paste your access token, it's verified against `/rest/api/version`
- **Login with credentials** — username/password auth via `/rest/api/auth/userpass` to get a token automatically
- **Auto token refresh** — on every page render, the app checks if the token is within 5 min of expiry and re-authenticates using stored credentials
- **Force refresh button** — manual refresh on demand
- **Token lifetime bar** — visual countdown in the sidebar (turns yellow < 20%, red < 5%)

### Incidents
- Fetched from `/rest/api/incidents` with severity filtering
- Color-coded cards (CRITICAL / HIGH / MEDIUM / LOW)
- One-click **💬 Chat** to open chat with incident as context
- One-click **🔍 Detail** to inspect full JSON

### Chat (LangChain stub)
- Incident context banner when launched from an incident card
- Wire LangChain inside `chat_respond()` — all context is passed in
- ChromaDB collection accessible via `st.session_state.chroma_collection`

### ChromaDB
- Persistent local vector store at `./chroma_db` (configurable)
- **Sync Incidents** — upsert all fetched incidents as text embeddings
- **Semantic Search** — cosine similarity search across incident corpus
- **Wipe / Export** — collection management tools

## Wiring LangChain

Open `app.py` and replace the body of `chat_respond()`:

```python
from langchain_community.vectorstores import Chroma
from langchain_anthropic import ChatAnthropic
from langchain.chains import RetrievalQA

vectorstore = Chroma(
    client=st.session_state.chroma_client,
    collection_name="soc_incidents",
    embedding_function=your_embedder,
)
llm = ChatAnthropic(model="claude-sonnet-4-20250514")
chain = RetrievalQA.from_chain_type(llm=llm, retriever=vectorstore.as_retriever())
return chain.invoke(user_msg)["result"]
```

## NetWitness API Notes
- Token header: `NetWitness-Token`
- Auth endpoint: `POST /rest/api/auth/userpass`
- Incidents: `GET /rest/api/incidents?limit=100`
- Self-signed certs: SSL verification is disabled by default (`verify=False`)