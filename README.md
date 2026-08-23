# Aegis SOC Investigation Platform

Aegis uses a Flask backend with an HTML, CSS and vanilla JavaScript frontend.
The canonical local entry point is the root `app.py`.

## Quick start

```bash
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. The health check is available at
<http://127.0.0.1:5000/api/health>.

Copy `.env.example` to `.env` when local credentials are required. Never
commit real API keys, passwords, tokens or certificate material.

## Application surfaces

- Overview and case archive with filtering, sorting and exports
- Case workspace for parsing, triage, threat intelligence, investigation and
  reporting workflow stages
- Durable analyst approvals, rejections, reruns and interrupted-run recovery
- NetWitness authentication, incident retrieval and synchronization
- JSON, CSV, text and log incident imports
- Global and case-scoped Ask Aegis
- Triage-ticket and report review, editing, confirmation and DOCX/PDF export
- Settings, semantic search and guarded pipeline administration

NetWitness can remain unconfigured for offline/cached-case use. Chroma data is
read from `runtime/chroma/` by default and can be configured with
`AEGIS_CHROMA_DB_PATH`.

## Tests

```bash
.venv/bin/python -m pytest -q
```

The test infrastructure redirects mutable databases, reporting artifacts and
vector data to temporary directories so a run does not modify tracked data.
