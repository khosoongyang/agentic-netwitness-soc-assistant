# Running and deploying Aegis

The supported application is the root Flask launcher with its bundled HTML,
CSS and JavaScript frontend. A separate frontend server is not required.

## Local run

```bash
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. Confirm the service with:

```bash
curl http://127.0.0.1:5000/api/health
```

The expected response is:

```json
{"application": "Aegis", "status": "ok"}
```

## Configuration

Copy `.env.example` to `.env` for local configuration. The application also
accepts the same values from the process environment. Keep `.env`, API keys,
passwords, tokens and TLS certificate material out of version control.

NetWitness is normally reachable only from its trusted network or VPN. When it
is unavailable, Aegis continues to support the cases already held in its local
stores. Runtime writes are operational state and should be placed on durable,
access-controlled storage in a deployed environment.

## Existing server deployment

Any existing WSGI-compatible deployment can import `app` from the root
`app.py`. Phase 7 does not introduce a new production platform or persistence
stack; environment hardening, TLS termination and process supervision remain
deployment responsibilities.

Before publishing demo databases, verify that they contain no sensitive
hostnames, usernames, IP addresses or incident content. Prefer a private
repository or replace the data with sanitized fixtures.
