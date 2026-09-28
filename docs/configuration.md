# Configuration reference

Every variable below is read directly by the application - confirmed by
searching the codebase for `os.environ`/`os.getenv` calls, not copied from
an old `.env` file. If a variable isn't listed here, no code path reads it.

All variables are optional unless noted. Set them in `.env` (copy from
`.env.example`) or the real process environment - both work identically.

## OpenAI

| Variable | Purpose | Required | Default | Example |
|---|---|---|---|---|
| `OPENAI_API_KEY` | Enables all AI-assisted features (triage classification text, investigation reasoning, reporting narrative, Ask Aegis). Without it, those stages fall back to non-LLM/templated behavior rather than failing. | No (but most features degrade without it) | unset | `sk-...` |
| `OPENAI_MODEL` | Model name for chat/completions calls. | No | `gpt-4o-mini` | `gpt-4o-mini` |
| `OPENAI_SEED` | Fixed sampling seed, for more reproducible model output. | No | unset (non-deterministic) | `42` |

## Threat-intelligence providers

Each is independently optional; enrichment for a missing provider degrades
to "unavailable" for that provider only, not a stage failure.

| Variable | Purpose |
|---|---|
| `VT_API_KEY` | VirusTotal IOC lookups |
| `ABUSEIPDB_API_KEY` | AbuseIPDB reputation lookups |
| `OTX_API_KEY` | AlienVault OTX pulse lookups |

## NetWitness

Leave the whole section blank to run Aegis in offline/cached-case mode -
every case already imported or in `soc_db/` is still fully usable.

| Variable | Purpose | Default |
|---|---|---|
| `NW_HOST` (or `NETWITNESS_HOST` / `NETWITNESS_BASE_URL`) | NetWitness base URL, e.g. `https://your-nw-host` | unset |
| `NW_USERNAME` (or `NETWITNESS_USERNAME`) | Username for password-based login | unset |
| `NW_PASSWORD` (or `NETWITNESS_PASSWORD`) | Password (may be base64-encoded to preserve special characters; decoded automatically, never logged) | unset |
| `NW_TOKEN` (or `NETWITNESS_TOKEN`) | Use a session token directly instead of username/password | unset |
| `NW_AUTH_STYLE` | How the token is sent: `NetWitness-Token`, `Bearer`, `Cookie`, or `Both` | `NetWitness-Token` |
| `NETWITNESS_VERIFY_SSL` | TLS certificate verification. **Secure by default (`true`).** Set to `false` only for a trusted internal appliance with a self-signed certificate you can't add a CA bundle for - development/demo use only, never for a real deployment. | `true` |
| `NW_CERT_PATH` | Path to a CA bundle to verify NetWitness's certificate against, instead of disabling verification. Preferred over `NETWITNESS_VERIFY_SSL=false`. | unset |

The username/password and token fields can equivalently be set from the
running app's Integrations page instead of `.env` - both paths go through
the same `NetWitnessConfig` validation and never echo credentials back in
any API response.

## Vector store (Chroma)

| Variable | Purpose | Default |
|---|---|---|
| `AEGIS_CHROMA_DB_PATH` | Where the live Chroma vector store lives. Seeded from `chroma_db/` on first use if empty. | `runtime/chroma` |

Semantic search reports itself as `unavailable` (not an error) if no
OpenAI key is configured, since embeddings require one.

## Reporting agent

All optional; the reporting agent works with none of these set.

| Variable | Purpose | Default |
|---|---|---|
| `REPORTING_USE_LLM` | Generate narrative text with an LLM vs. deterministic templated sections | `true` (subprocess default; `false` in `.env.example` for a faster local smoke test) |
| `REPORTING_LLM_PROVIDER` | `openai`, `ollama` (local model), or `mock` (offline/CI) | `openai` |
| `REPORTING_LLM_MODEL` | Model name for the reporting narrative specifically (independent of `OPENAI_MODEL`) | `gpt-4o-mini` |
| `REPORTING_OLLAMA_BASE_URL` | Local Ollama server URL, used only when `REPORTING_LLM_PROVIDER=ollama` | `http://localhost:11434` |
| `REPORTING_OLLAMA_MODEL` | Ollama model name | `llama3.2:3b` |
| `REPORTING_USE_RAG` | Retrieve relevant `knowledge_base/reporting/` context into the narrative prompt | `true` |
| `REPORTING_USE_CHROMADB` | Use Chroma (vs. built-in text search) for that retrieval | `false` |
| `REPORTING_USE_POSTGRES` | Additionally mirror each finished report result to Postgres. An unreachable/misconfigured database is a logged warning, never a failure - report generation itself never depends on this. | `false` |
| `POSTGRES_DSN` | Postgres connection string, only read when `REPORTING_USE_POSTGRES=true` | `postgresql://postgres:postgres@localhost:5432/aegis_soc` |

A further ~15 low-level tuning variables (timeouts, retry counts,
temperature, narrative depth, prompt-cache behavior, mock-mode responses)
exist with working defaults - see `agents/reporting/config/settings.py` if
you need to tune them; they're not reproduced here to keep this reference
practical rather than exhaustive.

## Removing this application's local-only assumption

There is currently no environment variable that changes the
authentication posture, because there is no authentication layer (see
the README's **Security / deployment notes**). If you add one, document
it here.
