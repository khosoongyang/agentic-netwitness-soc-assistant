"""aegis_paths.py -- where the LIVE SQLite databases live (audit T-24).

The repository ships demo databases in ``soc_db/`` (tracked in git: the
offline demo payload). Running the app used to write workflow state,
analyst reviews (names, justifications), tickets and pipeline rows straight
into those tracked files, so every run left ``git status`` dirty and could
commit analyst data by accident.

Now:

* :func:`live_db` names a database inside the live directory
  ``AEGIS_DATA_DIR`` (absolute, or relative to the repository root),
  default ``runtime/db/`` (git-ignored). It has NO side effects, so module
  constants built from it never touch disk at import time;
* :func:`ensure_live` is called where a database is opened: the first time a
  live DB is needed it is seeded by COPYING the tracked ``soc_db/`` file of
  the same name (a fresh checkout still shows the demo cases). The seed is
  never opened for writing, an existing live file is never overwritten, and
  paths outside the live directory (tests' temp copies) are left alone;
* ``AEGIS_DATA_DIR=soc_db`` restores the old behaviour explicitly.

Stdlib only and import-safe from any layer (agents/, workflow/, backend/).
"""
from __future__ import annotations

import os
import shutil
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SEED_DIR = ROOT / "soc_db"
DEFAULT_DATA_DIR = ROOT / "runtime" / "db"
DATA_DIR_ENV = "AEGIS_DATA_DIR"
KNOWN_DBS = ("soc_incidents.db", "soc_pipeline.db", "soc_tickets.db")

_SEED_LOCK = threading.Lock()


def data_dir() -> Path:
    """The live database directory (not created here)."""
    raw = os.environ.get(DATA_DIR_ENV, "").strip()
    if not raw:
        return DEFAULT_DATA_DIR
    p = Path(raw)
    return p if p.is_absolute() else ROOT / p


def live_db(name: str) -> Path:
    """Path of live database ``name`` (e.g. "soc_incidents.db"). Pure."""
    return data_dir() / name


def _same(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return False


def ensure_live(path: str | os.PathLike | None) -> Path | None:
    """Seed ``path`` from ``soc_db/<name>`` if it is a not-yet-existing file
    in the live directory. No-op for any other path. Returns ``path``."""
    if path is None:
        return None
    p = Path(path)
    if p.exists() or not _same(p.parent, data_dir()):
        return p
    with _SEED_LOCK:
        p.parent.mkdir(parents=True, exist_ok=True)
        seed = SEED_DIR / p.name
        if (not p.exists() and seed.is_file() and not _same(seed, p)
                and seed.stat().st_size > 0):
            tmp = p.with_name(p.name + ".seeding")
            shutil.copyfile(seed, tmp)
            os.replace(tmp, p)
    return p


def seed_all() -> None:
    """Seed every known live DB (called once at app start-up)."""
    for name in KNOWN_DBS:
        ensure_live(live_db(name))


__all__ = ["ROOT", "SEED_DIR", "DEFAULT_DATA_DIR", "DATA_DIR_ENV", "KNOWN_DBS",
           "data_dir", "live_db", "ensure_live", "seed_all"]
