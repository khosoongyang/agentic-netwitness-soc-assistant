# Deploying to Streamlit Community Cloud

This copy (`netwitness-agent_revised`) is prepped to run on **Streamlit
Community Cloud** — the free, purpose-built host for Streamlit apps.
Netlify was ruled out on purpose: it only serves static sites + short
serverless functions and cannot run a persistent Streamlit/Python server.

---

## ⚠️ Read first — two things the cloud can't do, and one decision

1. **NetWitness live-fetch will be dark.** NetWitness is on-prem / VPN-only;
   no cloud host can reach it. With no NW credentials set, the app stays in
   **offline/demo mode** and serves the incidents already stored in
   `soc_db/` + `chroma_db/`. Everything downstream (triage, investigation,
   reporting, all the skills) works against that stored data.

2. **Writes are ephemeral.** Streamlit Cloud containers reset on redeploy/
   sleep, so anything written back to the bundled SQLite/Chroma at runtime is
   lost on the next boot. Fine for a demo; not a system of record.

3. **DECISION — public vs private repo.** The committed demo databases may
   contain **internal hostnames, usernames, and IPs** from real incidents.
   - If that data is sensitive → deploy from a **PRIVATE** GitHub repo
     (Streamlit Cloud can deploy from private repos), **or** scrub/synthesize
     the DB before pushing.
   - Only use a public repo if you're certain the stored incidents are lab/
     synthetic data. `.env`, `*.pem`, and `certs/` are gitignored either way,
     so the LLM key and TLS material never get committed.

---

## One-time setup

### 1. Put this folder in a GitHub repo
This folder has no `.git` yet. From inside `netwitness-agent_revised`:

```bash
git init
git add .
git commit -m "SOC platform — Streamlit Cloud deployment snapshot"
git branch -M main
git remote add origin https://github.com/<you>/<repo>.git   # PRIVATE if data is sensitive
git push -u origin main
```

`.gitignore` keeps `.env`, `*.pem`, `certs/`, and `.streamlit/secrets.toml`
out of the push. The demo DBs **are** pushed (they're the app's data).
Note: `soc_db/soc_incidents.db` is ~74 MB — under GitHub's 100 MB hard
limit, so it pushes fine (you'll just see a >50 MB advisory).

### 2. Create the app on Streamlit Cloud
- Go to <https://share.streamlit.io> → **New app** → pick your repo/branch.
- **Main file path:** `app.py`
- Deploy.

### 3. Add secrets
In the app's **Settings → Secrets**, paste the block from
[`.streamlit/secrets.toml.example`](.streamlit/secrets.toml.example) with
real values — at minimum the LLM provider:

```toml
CISCO_LLM_URL   = "https://your-llm-endpoint/v1"
CISCO_LLM_KEY   = "sk-..."
CISCO_LLM_MODEL = "deepseek-chat"
```

`app.py` copies these into `os.environ` at startup, so no code changes are
needed. Leave the `NW_*` keys unset to stay in offline/demo mode.

> If the LLM endpoint is itself firewalled/VPN-only, the agents won't be able
> to reach it from the cloud either — the stored incidents still render, but
> re-running triage/investigation live would fail. Use a cloud-reachable LLM
> endpoint for a fully live demo.

---

## What was changed to make this deployable
All additive; nothing in the working pipeline was altered:

| Change | Why |
|---|---|
| `pysqlite3` swap at the top of `app.py` | Streamlit Cloud's Debian ships sqlite3 < 3.35; ChromaDB needs newer. No-op locally. |
| `st.secrets → os.environ` bridge in `app.py` | Lets the cloud Secrets manager feed the existing `os.environ.get(...)` call sites. No-op locally. |
| `pysqlite3-binary` in `requirements.txt` (Linux marker) | Supplies that newer sqlite on Cloud only; skipped on Windows/macOS. |
| `.streamlit/config.toml` | Aegis dark theme for native widgets. Cosmetic. |
| `.gitignore` rewrite | Secrets out, demo DBs in (the app's offline payload). |

Run locally exactly as before — the venv is the shared `.venv` one level up:
```bash
"C:\RP\AY26S1\C300 - Project\.venv\Scripts\streamlit.exe" run app.py
```

---

## Troubleshooting
- **`unsupported version of sqlite3` on Cloud** → the pysqlite3 swap or the
  `pysqlite3-binary` requirement didn't take. Confirm both are present and
  that the swap block is *above* the first `import chromadb`.
- **Agents error / empty reports on Cloud** → LLM secrets missing or the
  endpoint isn't reachable from the cloud. Check Settings → Secrets and that
  the endpoint is public.
- **App shows no incidents** → the DBs weren't committed (check they're not
  re-ignored) or the clone is on a branch without them.
