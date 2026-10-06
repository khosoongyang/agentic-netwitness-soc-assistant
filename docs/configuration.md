# Configuration reference

Every variable below is read directly by the application - confirmed by
searching the codebase for `os.environ`/`os.getenv` calls, not copied from
an old `.env` file. If a variable isn't listed here, no code path reads it.

All variables are optional unless noted. Set them in `.env` (copy from
`.env.example`) or the real process environment - both work identically.

## OpenAI

| Variable | Purpose | Required | Default | Example |
|---|---|---|---|---|
| `OPENAI_API_KEY` | Enables all AI-assisted features (triage classification text, investigation reasoning, reporting narrative, Ask Aegis). Triage requires it: without a key (or with a placeholder) the Triage stage fails fast with `LLM_NOT_CONFIGURED` and makes no network call; Ask Aegis reports itself unavailable. | Yes for Triage (offline: mock triage mode) | unset | `sk-...` |
| `OPENAI_MODEL` | Model name for chat/completions calls. | No | `gpt-4o-mini` | `gpt-4o-mini` |
| `OPENAI_SEED` | Fixed sampling seed, for more reproducible model output. | No | unset (non-deterministic) | `42` |
| `TRIAGE_JSON_MODE` | `always` / `never` overrides JSON-mode detection (on for OpenAI / Azure OpenAI hosts, off for other providers). | No | auto | `never` |
| `TRIAGE_JSON_SCHEMA` | `never` turns off the strict JSON schema used for the SOC Classification call on OpenAI / Azure OpenAI hosts (every citation is restricted to the evidence-packet paths that are present). Also off when `TRIAGE_JSON_MODE=never`. | No | auto | `never` |

## Triage evidence and review

See [`triage-review.md`](triage-review.md) and [`triage-evaluation.md`](triage-evaluation.md).

| Variable | Purpose | Required | Default | Example |
|---|---|---|---|---|
| `AEGIS_LOLBAS_PATH` | LOLBAS dataset cache used for abused-tool enrichment (`python scripts/update_lolbas.py` downloads it with a `.meta.json` sidecar). A cache whose bytes no longer match the sidecar sha256 is rejected, and enrichment is then reported as unknown, never as safe. | No | `runtime/threat_data/lolbas.json` | `/data/lolbas.json` |
| `AEGIS_CHANGE_WINDOWS` | JSON list of approved change windows, `[{"id", "entity" or "entities", "start", "end", "description", "approved_by"}]`. A window covering the incident's entity at the incident time becomes measured `context.change_context`, which Triage may cite for `benign_expected` (never past a strong rule signal). | No | `runtime/context/change_windows.json` | `/etc/aegis/changes.json` |
| `AEGIS_ASSET_INVENTORY` | JSON object `{entity: {"role", "tier", "owner", ...}}` (or a list with `entity`). A listed entity becomes measured `context.asset_context`; unlisted hostnames fall back to the naming-pattern tier (inferred). | No | `runtime/context/asset_inventory.json` | `/etc/aegis/assets.json` |
| `AEGIS_TICKET_DB` | Triage ticket / result-cache SQLite file (evaluation scripts point it at a temp copy). | No | `<AEGIS_DATA_DIR>/soc_tickets.db` | `/tmp/tickets.db` |
| `AEGIS_DATA_DIR` | Directory of the LIVE SQLite databases (incidents/workflow, pipeline, tickets). Each is seeded once by copying the tracked `soc_db/` demo file; the app never writes `soc_db/`. Relative paths are resolved from the repository root; `soc_db` restores the old in-place behaviour. | No | `runtime/db` (gitignored) | `/var/lib/aegis/db` |

Triage separates **severity** (`ticket.classification`) from **disposition**
(`true_positive` / `false_positive` / `benign_expected` / `needs_info`, set by
code guards over an evidence packet). An analyst's structured review
(`triage_reviews` table) is the canonical verdict downstream; suppressions are
only proposals until a second human approves them (`suppression_proposals`).

## Threat-intelligence providers

Each is independently optional; enrichment for a missing provider degrades
to "unavailable" for that provider only, not a stage failure.

| Variable | Purpose |
|---|---|
| `VT_API_KEY` | VirusTotal IOC lookups |
| `ABUSEIPDB_API_KEY` | AbuseIPDB reputation lookups |
| `OTX_API_KEY` | AlienVault OTX pulse lookups |

Internal / non-routable IP addresses (RFC 1918, loopback, link-local incl.
169.254.169.254, CGNAT 100.64/10, IPv6 ULA / link-local) are never sent to a
provider. File hashes are sent by default; set `AEGIS_TI_HASH_LOOKUPS=off` to
stop that (the result is then recorded as skipped, i.e. unknown, not clean).

| Variable | Purpose | Required | Default | Example |
|---|---|---|---|---|
| `AEGIS_TI_HASH_LOOKUPS` | `off` / `0` / `false` / `no` stops file hashes being sent to VirusTotal and OTX. | No | on | `off` |

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
