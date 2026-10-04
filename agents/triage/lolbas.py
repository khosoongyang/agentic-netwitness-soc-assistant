# =============================================================================
# [FYP-FILE] FILE OVERVIEW
# Important dependencies: __future__, hashlib, json, os, re, pathlib, typing,
#   agents.triage.raw_alerts.
# =============================================================================
# File: agents/triage/lolbas.py
# Purpose: Triage Step 2 (P12) -- abused-tool (LOLBAS) enrichment. Matches
#   the processes and command lines in the RAW alert events against the
#   LOLBAS project's catalogue of abusable Windows binaries, and flags
#   masquerading (a well-known binary name running from the wrong folder).
# Main functionality: load_lolbas_dataset(), match_lolbas(),
#   build_lolbas_signal(), build_masquerade_signal(),
#   signature_abused_tool_hits(), floor_labels().
# Inputs: the git-ignored runtime cache written by scripts/update_lolbas.py
#   (runtime/threat_data/lolbas.json + lolbas.meta.json; env override
#   AEGIS_LOLBAS_PATH), and the incident's raw alerts.
# Outputs: evidence leaves for rule_signals.lolbas / rule_signals.masquerade.
# Workflow position: Triage stage, Phase 0 (pure code, before the LLM).
# Called by: agents/triage/evidence_packet.py, agents/triage/guards.py,
#   agents/triage/soc_triage_agent.py (_prompt_signatures ranking).
# Important side effects: reads the cache file (no network, no writes).
# Error and fallback behaviour: a missing/corrupt cache gives a leaf with
#   status "missing" and a clear reason -- never a crash.
# Licence note: the LOLBAS dataset is GPL-3.0 and is NOT committed; only a
#   small self-authored test fixture lives in the repository.
# Key evaluator search terms: match_lolbas, path_mismatch, abused tool,
#   [FYP-TRIAGE-STEP2], adversarial mimicry.
# =============================================================================
"""
Abused-tool (LOLBAS) enrichment  --  lolbas.py
==============================================
[FYP-TRIAGE-STEP2] Adversarial mimicry: attackers "live off the land" with
built-in, Microsoft-SIGNED Windows tools (certutil, rundll32, schtasks,
regsvr32, mshta, bitsadmin ...) so their activity looks like normal IT work.
Two consequences are enforced here:

  * The binary NAME alone proves nothing (cmd.exe / powershell.exe are
    everywhere): name-only matches are "weak" and informational.
    A hit is "strong" only when an ABUSE ARGUMENT derived from the LOLBAS
    `Commands` is present (certutil -urlcache <url>, rundll32 javascript:,
    regsvr32 /i:<url>, schtasks /create, certutil -decode ...).
  * A valid signature (cert_thumbprint) is recorded but NEVER treated as
    evidence of benign -- every LOLBin is signed by Microsoft.

Masquerade check: a basename that matches a LOLBAS binary (or a well-known
Windows / security-tool binary) running from a directory that is not one of
its known locations is flagged `path_mismatch` -- a true-positive signal
(e.g. INC-53021: "splunkd.exe" running from C:\\Users\\Public\\).

Strong hits in categories Download / Execute / AWL Bypass / UAC Bypass /
Credentials, and every path_mismatch, join the Step-1 strong-signal floor in
agents/triage/guards.py (rule b): they block false_positive and
benign_expected unless a non-missing context.* field is validly cited.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

from .raw_alerts import alert_id, iter_alert_events

# =============================================================================
# [FYP-SECTION] CONFIGURATION
# =============================================================================

LOLBAS_SOURCE_URL = "https://lolbas-project.github.io/api/lolbas.json"
DEFAULT_LOLBAS_PATH = Path(__file__).resolve().parents[2] / "runtime" / "threat_data" / "lolbas.json"
LOLBAS_PATH_ENV = "AEGIS_LOLBAS_PATH"

# Strong hits in these categories join the guard floor (guards.py rule b).
FLOOR_CATEGORIES: frozenset[str] = frozenset({
    "Download", "Execute", "AWL Bypass", "UAC Bypass", "Credentials",
})
# Primary-category preference when one pattern serves several categories.
_CATEGORY_PRIORITY = ("Execute", "Download", "AWL Bypass", "UAC Bypass", "Credentials")

MAX_STRONG_HITS = 20
MAX_WEAK_HITS = 20
MAX_PATH_MISMATCHES = 20
MAX_EXPECTED_DIRS_SHOWN = 4
MAX_EVIDENCE_CMD_CHARS = 300

SIGNED_NOTE = ("signed status (cert_thumbprint) is recorded but never treated as evidence "
               "of benign: abused Windows tools are Microsoft-signed (adversarial mimicry)")

# Self-authored list of well-known Windows / security-tool binaries and the
# folders they legitimately run from (lower-case, trailing backslash). Used
# for the masquerade check in addition to LOLBAS Full_Path. Version folders
# are matched with a wildcard segment ("<v>").
WELL_KNOWN_BINARIES: dict[str, tuple[str, ...]] = {
    "svchost.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
    "lsass.exe": ("c:\\windows\\system32\\",),
    "csrss.exe": ("c:\\windows\\system32\\",),
    "smss.exe": ("c:\\windows\\system32\\",),
    "services.exe": ("c:\\windows\\system32\\",),
    "wininit.exe": ("c:\\windows\\system32\\",),
    "winlogon.exe": ("c:\\windows\\system32\\",),
    "taskhostw.exe": ("c:\\windows\\system32\\",),
    "spoolsv.exe": ("c:\\windows\\system32\\",),
    "lsaiso.exe": ("c:\\windows\\system32\\",),
    "dllhost.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
    "conhost.exe": ("c:\\windows\\system32\\",),
    "explorer.exe": ("c:\\windows\\", "c:\\windows\\syswow64\\"),
    "cmd.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
    "powershell.exe": ("c:\\windows\\system32\\windowspowershell\\v1.0\\",
                       "c:\\windows\\syswow64\\windowspowershell\\v1.0\\"),
    "rundll32.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
    "regsvr32.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
    "schtasks.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
    "certutil.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
    "mshta.exe": ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\"),
    "msmpeng.exe": ("c:\\programdata\\microsoft\\windows defender\\platform\\<v>\\",
                    "c:\\program files\\windows defender\\"),
    # Security/monitoring agents are favourite masquerade names because an
    # analyst expects to see them (INC-53021: splunkd.exe in C:\Users\Public).
    "splunkd.exe": ("c:\\program files\\splunk\\bin\\",
                    "c:\\program files\\splunkuniversalforwarder\\bin\\"),
    "splunk-winevtlog.exe": ("c:\\program files\\splunk\\bin\\",
                             "c:\\program files\\splunkuniversalforwarder\\bin\\"),
    "nweagent.exe": ("c:\\windows\\system32\\",),
}

# =============================================================================
# [FYP-SECTION] DATASET LOADING + PATTERN DERIVATION
# =============================================================================

_PLACEHOLDER_RE = re.compile(r"\{([A-Z_]+)(?::([^}]*))?\}", re.I)
_URL_RE = r"(?:https?|ftp)://"
_SMB_RE = r"\\\\[^\\\s]+\\"
# Typed placeholder extensions that are themselves strong (script payloads).
_SCRIPT_EXTS = {".hta", ".sct", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".xsl", ".inf",
                ".ps1", ".bat", ".cmd", ".msi", ".cpl", ".url"}


def _norm_dir(path: str | None) -> str | None:
    if not path:
        return None
    p = str(path).strip().strip('"').replace("/", "\\").lower()
    p = re.sub(r"\\+", r"\\", p)
    return p if p.endswith("\\") else p + "\\"


def _dir_regex(expected_dir: str) -> re.Pattern:
    """Expected directory -> regex; path segments containing digits (version
    folders such as 4.18.2008.4-0 or 138.0.3351.77) and placeholder segments
    (<username>, %USERNAME%) become wildcards."""
    parts = []
    for seg in expected_dir.rstrip("\\").split("\\"):
        if re.fullmatch(r"<[^>]*>|%[^%]*%", seg) or re.search(r"\d+\.\d+", seg):
            parts.append(r"[^\\]+")
        else:
            parts.append(re.escape(seg))
    return re.compile("^" + r"\\".join(parts) + r"\\$", re.I)


def _basename(value: str | None) -> str | None:
    if not value:
        return None
    b = re.split(r"[\\/]", str(value).strip().strip('"'))[-1].strip().lower()
    return b or None


def _exe_name(token: str) -> str | None:
    b = _basename(token)
    if not b:
        return None
    return b if "." in b else b + ".exe"


def _placeholder_requirement(kind: str, ext: str | None) -> tuple[str, str] | None:
    """(regex, display) a placeholder value must satisfy, or None (= free
    wildcard). {REMOTEURL} must be a URL, {PATH_SMB} a UNC path, a typed
    {PATH:.dll} an argument with that extension."""
    kind = kind.upper()
    if kind.startswith("REMOTEURL"):
        return _URL_RE, "<url>"
    if kind == "PATH_SMB":
        return _SMB_RE, "<\\\\unc>"
    if ext and ext.startswith("."):
        return r"\S*" + re.escape(ext.lower()) + r"(?![\w])", f"<*{ext.lower()}>"
    return None


def _tokens(command: str) -> list[str]:
    return [t for t in re.split(r"\s+", command.strip()) if t]


def derive_patterns(command: str, entry_name: str | None = None) -> list[dict]:
    """[FYP-FUNCTION] Turn one LOLBAS `Command` string into abuse-argument
    patterns. Returns a list of {binary, requirements:[regex], display}.
    Placeholder tokens such as {REMOTEURL} / {PATH} become wildcards (typed
    ones keep their constraint). Only ARGUMENT evidence is encoded -- the
    binary name alone never makes a pattern.

    entry_name: the LOLBAS entry the command belongs to. When the command
    invokes a DIFFERENT binary (powershell running CL_LoadAssembly.ps1,
    rundll32 loading advpack.dll, cmd.exe driving ftp.exe), the entry's own
    name must also appear -- otherwise a generic "powershell -command" would
    become a strong abuse pattern, which is exactly the name-only noise the
    weak/strong split exists to avoid."""
    toks = _tokens(command)
    if not toks:
        return []
    binary = _exe_name(toks[0])
    if not binary:
        return []
    anchors: list[tuple[str, str]] = []      # (regex, display)
    short_flags: list[tuple[str, str]] = []
    values: list[tuple[str, str]] = []
    for raw in toks[1:]:
        tok = raw.lower().replace("^", "").strip('"')
        ph = _PLACEHOLDER_RE.search(raw)
        literal = _PLACEHOLDER_RE.sub("", tok).strip('"')
        if tok.startswith(("-", "/")) and len(literal) > 1:
            name = re.match(r"[-/]([a-z][a-z0-9_]*)(:?)", literal)
            if not name:
                continue
            flag, colon = name.group(1), name.group(2)
            flag_re = r"(?<![^\s\"'])[-/]" + re.escape(flag)
            if colon:
                req = _placeholder_requirement(ph.group(1), ph.group(2)) if ph else None
                if req:
                    anchors.append((flag_re + r":\s*[\"']?" + req[0], f"/{flag}:{req[1]}"))
                elif not ph:
                    anchors.append((flag_re + ":", f"/{flag}:"))
                continue
            if len(flag) >= 3:
                anchors.append((flag_re + r"(?![\w])", f"-{flag}" if tok.startswith("-") else f"/{flag}"))
            else:
                short_flags.append((flag_re + r"(?![\w])", f"/{flag}"))
            continue
        proto = re.match(r"(javascript|vbscript|script|mshtml):", literal)
        if proto:
            anchors.append((r"(?<![\w])" + proto.group(1) + ":", proto.group(1) + ":"))
            continue
        dll_export = re.match(r"([a-z0-9_]+\.(?:dll|cpl|ocx)),\s*([#a-z0-9_]+)", literal)
        if dll_export and not ph:
            anchors.append((r"(?<![\w])" + re.escape(dll_export.group(1)) + r"\s*,\s*"
                            + re.escape(dll_export.group(2)) + r"(?![\w])",
                            f"{dll_export.group(1)},{dll_export.group(2)}"))
            continue
        if ph and _PLACEHOLDER_RE.fullmatch(raw.strip('"')):
            req = _placeholder_requirement(ph.group(1), ph.group(2))
            if req:
                values.append(req)
    patterns: list[dict] = []
    entry_req: list[tuple[str, str]] = []
    if entry_name:
        stem = _basename(entry_name) or ""
        stem_noext = stem.rsplit(".", 1)[0] if "." in stem else stem
        if stem and stem != binary and stem_noext:
            entry_req = [(r"(?<![\w])" + re.escape(stem_noext) + r"(?:\.\w+)?(?![\w])", stem)]
    if anchors:
        # The FIRST anchor is the command's verb (certutil -urlcache,
        # schtasks /create, rundll32 javascript:); a URL/UNC value in the same
        # command must also be present (certutil -urlcache needs a URL).
        first = anchors[0]
        typed = [v for v in values if v[1].startswith("<*.")]
        if "," in first[1] and typed:
            # dll,Export <typed payload>: the payload must FOLLOW the export
            # (otherwise "shell32.dll" itself satisfies "<*.dll>").
            first = (first[0] + r"\s*[\"']?\s*" + typed[0][0], f"{first[1]} {typed[0][1]}")
        reqs = [first]
        reqs += [v for v in values if v[1] in ("<url>", "<\\\\unc>")
                 and v[1] not in first[1]]
        reqs += [r for r in entry_req if r[1].rsplit(".", 1)[0] not in first[1]]
        patterns.append({"binary": binary, "requirements": [r for r, _ in reqs],
                         "display": " ".join([binary.replace(".exe", "")] + [d for _, d in reqs])})
    else:
        strong_value = any(d in ("<url>", "<\\\\unc>") or d[2:-1] in _SCRIPT_EXTS
                           for _, d in values)
        if strong_value or len(short_flags) >= 2:
            reqs = short_flags + values + entry_req
            if reqs:
                patterns.append({"binary": binary, "requirements": [r for r, _ in reqs],
                                 "display": " ".join([binary.replace(".exe", "")]
                                                     + [d for _, d in reqs])})
    return patterns


class LolbasDataset:
    """Indexed LOLBAS catalogue: entry names, Full_Path locations and the
    abuse-argument patterns of every Command, keyed by the invoked binary."""

    def __init__(self, entries: list[dict], meta: dict | None = None, path: str | None = None):
        self.meta = meta or {}
        self.path = path
        self.entries = [e for e in entries if isinstance(e, dict) and e.get("Name")]
        self.names: dict[str, dict] = {}
        self.paths: dict[str, set[str]] = {}
        self.patterns: dict[str, list[dict]] = {}
        for entry in self.entries:
            name = str(entry["Name"]).lower()
            self.names[name] = entry
            for fp in entry.get("Full_Path") or []:
                p = (fp or {}).get("Path") if isinstance(fp, dict) else None
                if p and re.match(r"^[a-z]:\\", p, re.I):
                    base = _basename(p)
                    d = _norm_dir(p.rsplit("\\", 1)[0])
                    if base and d:
                        self.paths.setdefault(base, set()).add(d)
            for cmd in entry.get("Commands") or []:
                if not isinstance(cmd, dict) or not cmd.get("Command"):
                    continue
                for pat in derive_patterns(str(cmd["Command"]), entry["Name"]):
                    pat = dict(pat, category=str(cmd.get("Category") or "Unknown"),
                               mitre_id=str(cmd.get("MitreID") or ""),
                               entry=entry["Name"], url=entry.get("url"),
                               lolbas_command=str(cmd["Command"])[:200])
                    pat["_compiled"] = [re.compile(r, re.I) for r in pat["requirements"]]
                    self.patterns.setdefault(pat["binary"], []).append(pat)
        self._embedded_re = (re.compile(
            r"(?<![\w.\\-])(?:[a-z]:\\[^\s\"']*\\)?(" + "|".join(
                re.escape(b[:-4]) for b in sorted(self.patterns, key=len, reverse=True)
                if b.endswith(".exe")) + r")(?:\.exe)?(?=[\s\"']|$)", re.I)
            if self.patterns else None)

    @property
    def source(self) -> str:
        retrieved = self.meta.get("retrieved_at") or "unknown date"
        sha = (self.meta.get("sha256") or "")[:12] or "unknown"
        # [AUDIT T-02 follow-up] file name only: the absolute cache path
        # (user profile / repo location) must not reach prompts, stored
        # review snapshots or the blind-review export.
        cache_name = Path(self.path).name if self.path else "?"
        return (f"LOLBAS {self.meta.get('source_url') or LOLBAS_SOURCE_URL} "
                f"(cache {cache_name}, retrieved {retrieved}, sha256 {sha}..., "
                f"{len(self.entries)} entries)")


_CACHE: dict[str, tuple[float, LolbasDataset]] = {}


def resolve_lolbas_path(path: str | Path | None = None) -> Path:
    if path:
        return Path(path)
    env = os.environ.get(LOLBAS_PATH_ENV, "").strip()
    return Path(env) if env else DEFAULT_LOLBAS_PATH


def load_lolbas_dataset(path: str | Path | None = None) -> tuple[LolbasDataset | None, str]:
    """[FYP-FUNCTION] Load (and memoise by mtime) the LOLBAS cache.
    Returns (dataset, "") or (None, reason). Never raises."""
    p = resolve_lolbas_path(path)
    # [AUDIT T-02 follow-up] reasons become the packet leaf `source`: name
    # the file, never its absolute location.
    shown = p.name or "lolbas.json"
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return None, (f"LOLBAS cache not found at {shown} -- run `python scripts/update_lolbas.py` "
                      "(abused-tool enrichment unavailable: unknown, not safe)")
    key = str(p.resolve())
    cached = _CACHE.get(key)
    if cached and cached[0] == mtime:
        return cached[1], ""
    try:
        raw = p.read_bytes()
        entries = json.loads(raw.decode("utf-8"))
        if not isinstance(entries, list) or not entries:
            return None, f"LOLBAS cache at {shown} is not a non-empty JSON list"
        meta_path = p.with_suffix(".meta.json")
        meta = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                meta = {}
        actual_sha = hashlib.sha256(raw).hexdigest()
        recorded_sha = str(meta.get("sha256") or "").strip().lower()
        # [AUDIT T-10] The sidecar's sha256 is verified, not just displayed:
        # a cache that no longer matches what update_lolbas.py fetched fails
        # closed (enrichment unknown, never a silently-trusted dataset).
        if recorded_sha and recorded_sha != actual_sha:
            return None, (f"LOLBAS cache at {shown} does not match its recorded sha256 "
                          f"({recorded_sha[:12]}... != {actual_sha[:12]}...) -- re-run "
                          "`python scripts/update_lolbas.py` (abused-tool enrichment "
                          "unavailable: unknown, not safe)")
        meta.setdefault("sha256", actual_sha)
        ds = LolbasDataset(entries, meta, str(p))
    except Exception as exc:  # corrupt cache must never crash triage
        return None, f"LOLBAS cache at {shown} could not be read ({type(exc).__name__}: {exc})"
    _CACHE[key] = (mtime, ds)
    return ds, ""


# =============================================================================
# [FYP-SECTION] MATCHING
# =============================================================================

def _as_proc(p: Any) -> dict:
    if isinstance(p, str):
        return {"name": p}
    return p if isinstance(p, dict) else {}


def _as_cmd(c: Any) -> dict:
    if isinstance(c, str):
        return {"command_line": c}
    return c if isinstance(c, dict) else {}


def expected_directories(binary: str, dataset: LolbasDataset | None) -> list[str]:
    dirs = set(WELL_KNOWN_BINARIES.get(binary, ()))
    if dataset is not None:
        dirs |= dataset.paths.get(binary, set())
    return sorted(dirs)


def _path_mismatch(binary: str, directory: str | None,
                   dataset: LolbasDataset | None) -> tuple[bool | None, list[str]]:
    expected = expected_directories(binary, dataset)
    obs = _norm_dir(directory)
    if not expected or not obs:
        return None, expected
    return (not any(_dir_regex(d).match(obs) for d in expected)), expected


def _primary(categories: list[str]) -> str:
    for c in _CATEGORY_PRIORITY:
        if c in categories:
            return c
    return categories[0] if categories else "Unknown"


def match_lolbas(processes: Iterable[Any], command_lines: Iterable[Any],
                 dataset: LolbasDataset | None = None) -> list[dict]:
    """[FYP-FUNCTION] [FYP-EVALUATOR] Match observed processes and command
    lines against LOLBAS.

    processes: [{name, directory?, alert_id?, signed?}] (or bare names)
    command_lines: [{command_line, alert_id?, process?}] (or bare strings)

    Returns hits {binary, strength: strong|weak, matched_command_pattern,
    category, categories, mitre_id, mitre_ids, path_mismatch, observed_directory,
    expected_directories, signed, evidence:{command_line|directory, alert_id},
    floor, lolbas_url}. strong = binary + abuse-argument match, or a
    path_mismatch; weak = binary name only (informational). `signed` is
    recorded, never used to downgrade a hit."""
    hits: dict[tuple, dict] = {}

    # 1) Abuse-argument matches on command lines (first token, or a LOLBAS
    #    binary embedded later, e.g. "cmd /c certutil -urlcache ...").
    if dataset is not None and dataset._embedded_re is not None:
        for c in command_lines or []:
            c = _as_cmd(c)
            text = str(c.get("command_line") or "")
            if not text.strip():
                continue
            low = text.lower()
            for m in dataset._embedded_re.finditer(low):
                binary = m.group(1).lower() + ".exe"
                tail = low[m.end():]
                for pat in dataset.patterns.get(binary, []):
                    if all(rx.search(tail) for rx in pat["_compiled"]):
                        key = ("arg", binary, pat["display"])
                        hit = hits.get(key)
                        if hit is None:
                            hit = hits[key] = {
                                "binary": binary, "strength": "strong",
                                "matched_command_pattern": pat["display"],
                                "categories": [], "mitre_ids": [],
                                "path_mismatch": False, "observed_directory": None,
                                "expected_directories": [], "signed": None,
                                "evidence": {"command_line": text[:MAX_EVIDENCE_CMD_CHARS],
                                             "alert_id": c.get("alert_id")},
                                "occurrences": 0, "lolbas_url": pat.get("url"),
                            }
                        if pat["category"] not in hit["categories"]:
                            hit["categories"].append(pat["category"])
                        if pat["mitre_id"] and pat["mitre_id"] not in hit["mitre_ids"]:
                            hit["mitre_ids"].append(pat["mitre_id"])
                        hit["occurrences"] += 1

    # 2) Process names: weak name-only hits + the masquerade (path) check.
    for p in processes or []:
        p = _as_proc(p)
        binary = _basename(p.get("name"))
        if not binary:
            continue
        entry = dataset.names.get(binary) if dataset is not None else None
        mismatch, expected = _path_mismatch(binary, p.get("directory"), dataset)
        signed = p.get("signed")
        if mismatch:
            key = ("path", binary, _norm_dir(p.get("directory")))
            hit = hits.setdefault(key, {
                "binary": binary, "strength": "strong",
                "matched_command_pattern": None,
                "categories": ["Masquerading"], "mitre_ids": ["T1036.005"],
                "path_mismatch": True, "observed_directory": p.get("directory"),
                "expected_directories": expected[:MAX_EXPECTED_DIRS_SHOWN],
                "signed": signed,
                "evidence": {"directory": p.get("directory"), "alert_id": p.get("alert_id")},
                "occurrences": 0, "lolbas_url": (entry or {}).get("url"),
            })
            hit["occurrences"] += 1
        if entry is not None:
            key = ("name", binary)
            hit = hits.setdefault(key, {
                "binary": binary, "strength": "weak",
                "matched_command_pattern": None,
                "categories": sorted({str(c.get("Category")) for c in entry.get("Commands") or []
                                      if isinstance(c, dict) and c.get("Category")}),
                "mitre_ids": [], "path_mismatch": False,
                "observed_directory": p.get("directory"),
                "expected_directories": expected[:MAX_EXPECTED_DIRS_SHOWN],
                "signed": signed,
                "evidence": {"directory": p.get("directory"), "alert_id": p.get("alert_id")},
                "occurrences": 0, "lolbas_url": entry.get("url"),
            })
            hit["occurrences"] += 1

    out = []
    for hit in hits.values():
        hit["category"] = _primary(hit["categories"])
        hit["mitre_id"] = hit["mitre_ids"][0] if hit["mitre_ids"] else None
        hit["floor"] = hit["strength"] == "strong" and (
            hit["path_mismatch"] or hit["category"] in FLOOR_CATEGORIES
            or any(c in FLOOR_CATEGORIES for c in hit["categories"]))
        out.append(hit)
    out.sort(key=lambda h: (h["strength"] != "strong", not h["floor"], h["binary"],
                            h.get("matched_command_pattern") or ""))
    return out


# =============================================================================
# [FYP-SECTION] INCIDENT -> INPUTS, LEAVES, RANKING HOOK
# =============================================================================

def incident_observables(incident: dict) -> tuple[list[dict], list[dict]]:
    """Processes (name + directory + signer) and command lines from EVERY
    raw alert event (deduplicated, first alert id kept as evidence)."""
    procs: dict[tuple, dict] = {}
    cmds: dict[str, dict] = {}
    alerts = incident.get("alerts") if isinstance(incident.get("alerts"), list) else []
    for i, alert in enumerate(alerts):
        if not isinstance(alert, dict):
            continue
        aid = alert_id(alert, i)
        for ev in iter_alert_events(alert):
            for side in ("src", "dst"):
                names = ev.get(f"filename_{side}")
                names = names if isinstance(names, list) else [names] if names else []
                dirs = ev.get(f"directory_{side}")
                dirs = dirs if isinstance(dirs, list) else [dirs] if dirs else []
                for j, name in enumerate(names):
                    if not isinstance(name, str) or not name.strip():
                        continue
                    # Only pair name<->directory when the lists align: a
                    # NetWitness event with filename_dst [script.bat, cmd.exe]
                    # and ONE directory_dst describes the script's folder,
                    # not cmd.exe's (pairing them would invent a masquerade).
                    directory = dirs[j] if len(dirs) == len(names) else None
                    key = (name.lower(), (directory or "").lower())
                    signed = None
                    if side == "src":
                        signed = bool(ev.get("cert_thumbprint"))
                    procs.setdefault(key, {"name": name, "directory": directory,
                                           "alert_id": aid, "signed": signed})
                params = ev.get(f"param_{side}")
                params = params if isinstance(params, list) else [params] if params else []
                for cmd in params:
                    if isinstance(cmd, str) and cmd.strip():
                        cmds.setdefault(cmd, {"command_line": cmd, "alert_id": aid})
    return list(procs.values()), list(cmds.values())


def _leaf(value: Any, status: str, source: str) -> dict:
    return {"value": value, "status": status, "source": source}


def _strip(hit: dict) -> dict:
    return {k: v for k, v in hit.items() if not k.startswith("_")}


def build_lolbas_signal(incident: dict, dataset_path: str | Path | None = None) -> dict:
    """[FYP-FUNCTION] The rule_signals.lolbas leaf."""
    ds, reason = load_lolbas_dataset(dataset_path)
    if ds is None:
        return _leaf(None, "missing", reason)
    procs, cmds = incident_observables(incident if isinstance(incident, dict) else {})
    if not procs and not cmds:
        return _leaf(None, "missing", "no raw process/command-line events to match "
                     f"(abused-tool check not possible) -- {ds.source}")
    hits = match_lolbas(procs, cmds, ds)
    strong = [_strip(h) for h in hits if h["strength"] == "strong"]
    weak = [_strip(h) for h in hits if h["strength"] == "weak"]
    floor = [h for h in strong if h["floor"]]
    value = {
        "floor_labels": sorted({floor_label(h) for h in floor}),
        "strong_hit_count": len(strong), "weak_hit_count": len(weak),
        "strong_hits": strong[:MAX_STRONG_HITS],
        "weak_hits": weak[:MAX_WEAK_HITS],
        "note": (f"showing {min(len(strong), MAX_STRONG_HITS)} of {len(strong)} strong and "
                 f"{min(len(weak), MAX_WEAK_HITS)} of {len(weak)} weak hits; weak = binary "
                 f"name only (informational); {SIGNED_NOTE}"),
        "checked": {"processes": len(procs), "command_lines": len(cmds)},
    }
    return _leaf(value, "measured", ds.source)


def build_masquerade_signal(incident: dict, dataset_path: str | Path | None = None) -> dict:
    """[FYP-FUNCTION] rule_signals.masquerade: well-known binary names running
    from an unexpected directory. Uses the self-authored WELL_KNOWN_BINARIES
    list (always available) plus LOLBAS Full_Path when the cache exists, so
    the masquerade check survives a missing LOLBAS cache."""
    ds, _reason = load_lolbas_dataset(dataset_path)
    procs, _cmds = incident_observables(incident if isinstance(incident, dict) else {})
    with_dir = [p for p in procs if p.get("directory")]
    src = ("agents/triage/lolbas.WELL_KNOWN_BINARIES"
           + (f" + {ds.source} Full_Path" if ds else " (LOLBAS cache absent: Full_Path not used)"))
    if not with_dir:
        return _leaf(None, "missing", "no process directories in the raw events "
                     "(masquerade check not possible)")
    mism = []
    for p in with_dir:
        binary = _basename(p["name"])
        bad, expected = _path_mismatch(binary, p["directory"], ds)
        if bad:
            mism.append({"binary": binary, "observed_directory": p["directory"],
                         "expected_directories": expected[:MAX_EXPECTED_DIRS_SHOWN],
                         "signed": p.get("signed"), "alert_id": p.get("alert_id"),
                         "mitre_id": "T1036.005"})
    value = {
        "floor_labels": sorted({f"masquerade:{m['binary']}" for m in mism}),
        "path_mismatches": mism[:MAX_PATH_MISMATCHES],
        "note": (f"{len(mism)} path mismatch(es) among {len(with_dir)} processes with a "
                 f"known directory; {SIGNED_NOTE}"),
    }
    return _leaf(value, "measured", src)


# Floor label used when the abused-tool check could NOT run (cache missing or
# corrupt) although the raw events contain command lines to check.
UNCHECKED_FLOOR_LABEL = "abused_tool_check_unavailable"
_CACHE_PROBLEM_PREFIX = "LOLBAS cache"


def floor_label(hit: dict) -> str:
    if hit.get("path_mismatch"):
        return f"masquerade:{hit['binary']}"
    return f"lolbas:{hit['binary']} {hit.get('category')}"


def floor_labels(packet: dict) -> list[str]:
    """[FYP-FUNCTION] Abused-tool labels that join the guard floor
    (agents/triage/guards.strong_rule_signals).

    "Missing evidence = unknown, not safe": when the LOLBAS cache is missing
    or unreadable but the raw events DO contain command lines, the abused-tool
    check is unknown rather than clean, so UNCHECKED_FLOOR_LABEL is returned
    and a benign close stays blocked (canaries must hold even on a machine
    where scripts/update_lolbas.py was never run)."""
    signals = (packet or {}).get("rule_signals") or {}
    labels: set[str] = set()
    for key in ("lolbas", "masquerade"):
        leaf = signals.get(key)
        if isinstance(leaf, dict) and leaf.get("status") != "missing" \
                and isinstance(leaf.get("value"), dict):
            labels.update(leaf["value"].get("floor_labels") or [])
    lol = signals.get("lolbas")
    if isinstance(lol, dict) and lol.get("status") == "missing" \
            and str(lol.get("source") or "").startswith(_CACHE_PROBLEM_PREFIX):
        cmd_leaf = ((packet or {}).get("raw_alerts") or {}).get("command_lines") or {}
        if cmd_leaf.get("status") != "missing" and \
                ((cmd_leaf.get("value") or {}).get("total_unique") or 0) > 0:
            labels.add(UNCHECKED_FLOOR_LABEL)
    return sorted(labels)


def signature_abused_tool_hits(signatures: list[dict],
                               dataset_path: str | Path | None = None) -> dict[str, list[str]]:
    """Ranking hook for agents/triage/raw_alerts.rank_signatures: strong
    abused-tool hits per signature id (masquerade works without the cache)."""
    ds, _ = load_lolbas_dataset(dataset_path)
    out: dict[str, list[str]] = {}
    for sig in signatures:
        procs = []
        if sig.get("process"):
            procs.append({"name": sig["process"], "directory": sig.get("directory")})
        cmds = [c for c in [sig.get("command_line")] + list(sig.get("child_command_lines") or []) if c]
        hits = match_lolbas(procs, cmds, ds) if ds is not None else []
        if ds is None and procs:
            bad, _exp = _path_mismatch(_basename(procs[0]["name"]) or "", procs[0]["directory"], None)
            if bad:
                hits = [{"strength": "strong", "path_mismatch": True, "binary": _basename(procs[0]["name"])}]
        labels = [floor_label(h) if h.get("path_mismatch")
                  else f"{h['binary']} {h.get('matched_command_pattern') or ''}".strip()
                  for h in hits if h.get("strength") == "strong"]
        if labels:
            out[sig["signature_id"]] = labels
    return out


__all__ = [
    "LOLBAS_SOURCE_URL", "DEFAULT_LOLBAS_PATH", "LOLBAS_PATH_ENV", "FLOOR_CATEGORIES",
    "WELL_KNOWN_BINARIES", "SIGNED_NOTE", "LolbasDataset", "derive_patterns",
    "resolve_lolbas_path", "load_lolbas_dataset", "expected_directories", "match_lolbas",
    "incident_observables", "build_lolbas_signal", "build_masquerade_signal",
    "floor_label", "floor_labels", "signature_abused_tool_hits", "UNCHECKED_FLOOR_LABEL",
]
