# Running and deploying Aegis

Aegis is currently a **single-operator, localhost-only application** - see
the README's "Security / deployment notes" section for the reasoning.
This document is honest about that: it is not a production deployment
guide, because Aegis is not currently production-ready as a multi-user or
internet-facing service. It covers local development use and what would
need to change before deploying it more broadly.

## Local development (the supported path)

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # then fill in whichever sections you need
python app.py
```

Open <http://127.0.0.1:5000>. Confirm the service:

```bash
curl http://127.0.0.1:5000/api/health
# {"application": "Aegis", "status": "ok"}
```

`app.py` binds to `127.0.0.1` and runs with `debug=False` - the Flask
interactive debugger is never exposed, and the server is not reachable
from other machines on your network by default.

## Configuration

Copy `.env.example` to `.env`, or set the same names in the process
environment - both are read identically. Full variable reference:
[`docs/configuration.md`](docs/configuration.md). Keep `.env`, API keys,
passwords, tokens and TLS certificate material out of version control -
`.gitignore` already excludes `.env`.

NetWitness is optional and normally reachable only from its trusted
network/VPN. When it's unavailable or unconfigured, Aegis continues to
serve every case already held in `soc_db/`. Runtime writes (uploads,
Chroma index, per-run reporting artifacts) should be placed on durable,
access-controlled storage if you deploy this anywhere persistent -
see [`docs/architecture.md`](docs/architecture.md#runtime) for exactly
which paths those are.

## If you need to deploy this beyond your own workstation

Before doing this, add an authentication layer - none exists today (see
the README). Once one exists:

- **WSGI server**: `app.py`'s dev server (`app.run(...)`) is not meant for
  concurrent/production traffic. Run the `app` object it exports (`from
  backend.app import create_app; app = create_app()`) under a real WSGI
  server (e.g. gunicorn or waitress) instead of calling `app.run()`.
- **Host/bind**: change the bind address only alongside the auth layer
  above - `0.0.0.0` or a real network interface without authentication
  means anyone on that network can run/approve/reject workflow stages,
  edit and confirm reports, and use the admin pipeline-deletion endpoints
  (which are gated by a `developer_mode` flag and a confirmation string,
  not by identity - see `docs/api.md`).
- **Reverse proxy / TLS termination**: put a reverse proxy (nginx, Caddy,
  a cloud load balancer) in front for TLS; Aegis itself serves plain HTTP.
- **Environment variables**: every value in `.env` needs to reach the WSGI
  process's environment the same way it reaches `python app.py` locally.
- **NetWitness TLS**: verification is on by default
  (`NETWITNESS_VERIFY_SSL=true`); only disable it for a trusted internal
  appliance you cannot obtain a CA bundle for, and never in a shared
  deployment.

This project does not currently ship a Dockerfile, process-supervisor
config, or reverse-proxy config - adding those is out of scope for the
current FYP/demo use case, and would be the next step if broader
deployment becomes a real requirement.

## Demo data / publishing this repository

`soc_db/` and `chroma_db/` are intentionally tracked in git (see
`.gitignore`'s header comment) so the app has something to show without a
live NetWitness connection. Before pushing this repository to any remote
you don't fully control - **especially a public one** - verify that this
data contains no real internal hostnames, usernames, IP addresses or
incident content, or replace it with sanitized/synthetic fixtures. This is
your call to make, not something this migration can verify on your behalf.
