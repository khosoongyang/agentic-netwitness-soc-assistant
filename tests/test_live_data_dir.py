"""tests/test_live_data_dir.py -- audit T-24.

Running the app wrote workflow state, analyst reviews (names,
justifications), tickets and pipeline rows into the TRACKED soc_db/*.db demo
files, so they showed as modified in git. The live databases now live in a
git-ignored data directory (AEGIS_DATA_DIR, default runtime/db/), seeded
once from the tracked soc_db/ demo copies; the seeds are never written.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

import aegis_paths

ROOT = Path(__file__).resolve().parents[1]


def test_default_live_dir_is_git_ignored_runtime_db(monkeypatch):
    monkeypatch.delenv("AEGIS_DATA_DIR", raising=False)
    assert aegis_paths.data_dir() == ROOT / "runtime" / "db"
    r = subprocess.run(["git", "check-ignore", "-q", "runtime/db/soc_incidents.db"], cwd=ROOT)
    assert r.returncode == 0, "runtime/db/ must be git-ignored"


def test_env_override_and_relative_paths(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path / "live"))
    assert aegis_paths.data_dir() == tmp_path / "live"
    monkeypatch.setenv("AEGIS_DATA_DIR", "soc_db")
    assert aegis_paths.data_dir() == ROOT / "soc_db"     # opt back into the old behaviour


def test_live_db_is_seeded_once_and_seed_never_written(monkeypatch, tmp_path):
    seed_dir = tmp_path / "seed"
    seed_dir.mkdir()
    with sqlite3.connect(str(seed_dir / "soc_incidents.db")) as con:
        con.execute("CREATE TABLE incidents (id TEXT)")
        con.execute("INSERT INTO incidents VALUES ('INC-SEED')")
    seed_bytes = (seed_dir / "soc_incidents.db").read_bytes()
    monkeypatch.setattr(aegis_paths, "SEED_DIR", seed_dir)
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path / "live"))

    live = aegis_paths.live_db("soc_incidents.db")
    assert live == tmp_path / "live" / "soc_incidents.db" and not live.exists()   # pure
    aegis_paths.ensure_live(live)
    with sqlite3.connect(str(live)) as con:
        assert con.execute("SELECT id FROM incidents").fetchall() == [("INC-SEED",)]
        con.execute("INSERT INTO incidents VALUES ('INC-NEW')")
    # second resolve never re-copies over live data
    again = aegis_paths.ensure_live(aegis_paths.live_db("soc_incidents.db"))
    with sqlite3.connect(str(again)) as con:
        assert con.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 2
    assert (seed_dir / "soc_incidents.db").read_bytes() == seed_bytes


def test_missing_seed_yields_fresh_db_path(monkeypatch, tmp_path):
    monkeypatch.setattr(aegis_paths, "SEED_DIR", tmp_path / "noseed")
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path / "live"))
    p = aegis_paths.ensure_live(aegis_paths.live_db("soc_tickets.db"))
    assert p.parent.is_dir() and not p.exists()


def test_paths_outside_the_live_dir_are_never_seeded(monkeypatch, tmp_path):
    seed_dir = tmp_path / "seed"
    seed_dir.mkdir()
    (seed_dir / "soc_incidents.db").write_bytes(b"x" * 10)
    monkeypatch.setattr(aegis_paths, "SEED_DIR", seed_dir)
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path / "live"))
    other = tmp_path / "elsewhere" / "soc_incidents.db"
    aegis_paths.ensure_live(other)
    assert not other.exists()


def test_every_module_default_points_at_the_live_dir(tmp_path):
    """Fresh interpreter, AEGIS_DATA_DIR set: no module default may still
    name the tracked soc_db/ seed files."""
    live = tmp_path / "live"
    code = (
        "import sys, json; sys.path.insert(0, '.');"
        "from workflow import state_store as s, engine as e;"
        "from agents.triage import baseline as b, soc_triage_agent as t;"
        "from agents.investigation.tools import ioc_correlation as c;"
        "from backend.services import dashboard_service as d;"
        "print(json.dumps([str(s.DB_FILE), str(e.PIPELINE_DB_FILE), str(b.DEFAULT_BASELINE_DB),"
        " str(t._TICKET_DB), str(c._INCIDENTS_DB), str(c._PIPELINE_DB), str(c._TICKETS_DB),"
        " str(d.DEFAULT_PIPELINE_DB)]))"
    )
    env = dict(os.environ, AEGIS_DATA_DIR=str(live), OPENAI_API_KEY="sk-offline-dummy")
    env.pop("AEGIS_TICKET_DB", None)
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True,
                         text=True, timeout=180)
    assert out.returncode == 0, out.stderr[-2000:]
    import json
    paths = [Path(p) for p in json.loads(out.stdout.strip().splitlines()[-1])]
    for p in paths:
        assert p.parent == live, p
    # Importing the triage agent initialises its ticket DB (pre-existing
    # behaviour); it must land in the live dir, never in tracked soc_db/.
    assert {p.name for p in live.glob("*.db")} <= {"soc_tickets.db"}


def test_reconcile_writes_go_to_the_live_ticket_and_pipeline_dbs(monkeypatch, tmp_path):
    from workflow import engine as sw
    tickets, pipeline = tmp_path / "t.db", tmp_path / "p.db"
    with sqlite3.connect(str(tickets)) as con:
        con.execute("CREATE TABLE tickets (unc TEXT, incident_id TEXT, severity TEXT, created_at TEXT, payload TEXT)")
        con.execute("INSERT INTO tickets VALUES ('#1', 'I', 'Low', 't', '{}')")
    monkeypatch.setattr(sw, "_tickets_db_path", lambda: tickets)
    monkeypatch.setattr(sw, "PIPELINE_DB_FILE", pipeline)
    sw.reconcile_incident_severity("I", "#1", "high")
    with sqlite3.connect(str(tickets)) as con:
        payload = con.execute("SELECT payload FROM tickets").fetchone()[0]
    assert "High" in payload
