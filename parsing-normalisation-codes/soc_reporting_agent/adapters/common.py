from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INPUTS_DIR = PROJECT_ROOT / "inputs"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
LOGS_DIR = PROJECT_ROOT / "logs"
RUNTIME_DIR = PROJECT_ROOT / "runtime"

for d in (INPUTS_DIR, OUTPUTS_DIR, LOGS_DIR, RUNTIME_DIR):
    d.mkdir(parents=True, exist_ok=True)

load_dotenv(PROJECT_ROOT / ".env", override=False)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path, default: Any = None) -> Any:
    try:
        if not path.exists() or path.stat().st_size == 0:
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    # Run-specific mirroring for concurrent/re-run support. Legacy adapters still
    # write to the normal outputs/ paths so existing downstream code works. When
    # SOC_RUN_OUTPUT_DIR is provided by the dashboard backend, every output file
    # written under outputs/ is also mirrored under that run folder using the same
    # relative path. This preserves an immutable per-run copy even when the
    # compatibility output is overwritten by a later run.
    run_output_dir = os.getenv("SOC_RUN_OUTPUT_DIR") or os.getenv("SOC_OUTPUT_DIR")
    if run_output_dir:
        try:
            resolved = path.resolve()
            outputs_root = OUTPUTS_DIR.resolve()
            if resolved == outputs_root or outputs_root in resolved.parents:
                relative = resolved.relative_to(outputs_root)
                mirror_path = Path(run_output_dir) / relative
                mirror_path.parent.mkdir(parents=True, exist_ok=True)
                mirror_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass


def latest_file(pattern: str, base: Path = OUTPUTS_DIR) -> Path | None:
    files = [p for p in base.glob(pattern) if p.is_file()]
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def copy_if_exists(src: Path, dst: Path) -> bool:
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def severity_from_score(score: Any) -> str:
    try:
        s = float(score)
    except Exception:
        return str(score or "Unknown")
    if s >= 90:
        return "Critical"
    if s >= 70:
        return "High"
    if s >= 40:
        return "Medium"
    return "Low"


def _first_non_empty(*values: Any, default: Any = "") -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return default


def _ioc_risk_score(enriched: dict) -> int:
    score = 0
    raw_iocs = enriched.get("iocs") or enriched.get("indicators") or []
    if isinstance(raw_iocs, dict):
        raw_iocs = [raw_iocs]
    if not isinstance(raw_iocs, list):
        raw_iocs = []
    for ioc in raw_iocs:
        text = json.dumps(ioc, default=str).lower()
        if any(word in text for word in ["malicious", "critical", "high", "malware", "c2", "command and control"]):
            score += 50
        elif any(word in text for word in ["suspicious", "medium", "unknown"]):
            score += 25
        elif text.strip():
            score += 8
    return min(score, 95) if score else 0


def normalise_incident(enriched: dict | None = None) -> dict:
    enriched = enriched or read_json(INPUTS_DIR / "enriched_alert.json", {}) or read_json(OUTPUTS_DIR / "enriched_alert.json", {}) or {}
    # Support NetWitness style, processed-alert style, enriched-alert style, and simple sample JSON.
    ioc_score = _ioc_risk_score(enriched)
    risk_score = _first_non_empty(
        enriched.get("risk_score"),
        enriched.get("incident_risk_score"),
        enriched.get("enrichment_risk_score"),
        enriched.get("riskScore"),
        ioc_score if ioc_score else None,
        default=75,
    )
    title = _first_non_empty(
        enriched.get("incident_title"),
        enriched.get("alert_name"),
        enriched.get("alert_title"),
        enriched.get("title"),
        enriched.get("name"),
        default="High Risk Endpoint Malware Activity",
    )
    summary = _first_non_empty(
        enriched.get("incident_summary"),
        enriched.get("summary"),
        enriched.get("description"),
        enriched.get("alert_detail"),
        default=f"SOC alert requires triage: {title}",
    )
    return {
        "id": _first_non_empty(enriched.get("incident_id"), enriched.get("incidentId"), enriched.get("id"), enriched.get("case_id"), default="INC-0001"),
        "title": title,
        "summary": summary,
        "risk_score": risk_score,
        "severity": _first_non_empty(enriched.get("severity"), enriched.get("priority"), default=severity_from_score(risk_score)),
        "host": _first_non_empty(enriched.get("host"), enriched.get("event_domain"), enriched.get("destination_hostname"), enriched.get("hostname"), enriched.get("event_source"), default="unknown-host"),
        "ip": _first_non_empty(enriched.get("source_ip"), enriched.get("destination_ip"), enriched.get("ip"), default=""),
        "username": _first_non_empty(enriched.get("username"), enriched.get("user"), enriched.get("assignee"), default=""),
        "file_name": _first_non_empty(enriched.get("possible_file_name"), enriched.get("file_name"), enriched.get("filename"), default=""),
        "raw": enriched,
    }


def run_script(script: Path, timeout: int = 300, extra_env: dict[str, str] | None = None) -> dict:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    started = now_iso()
    try:
        result = subprocess.run(
            [sys.executable, str(script)],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=env,
        )
        return {
            "started_at": started,
            "finished_at": now_iso(),
            "returncode": result.returncode,
            "success": result.returncode == 0,
            "stdout": result.stdout[-20000:],
            "stderr": result.stderr[-20000:],
            "script": str(script.relative_to(PROJECT_ROOT)),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "started_at": started,
            "finished_at": now_iso(),
            "returncode": -1,
            "success": False,
            "status": "timeout",
            "stdout": (exc.stdout or "")[-20000:] if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "")[-20000:] if isinstance(exc.stderr, str) else "",
            "script": str(script.relative_to(PROJECT_ROOT)),
        }
    except Exception as exc:
        return {
            "started_at": started,
            "finished_at": now_iso(),
            "returncode": -1,
            "success": False,
            "status": "execution_error",
            "stdout": "",
            "stderr": str(exc),
            "script": str(script.relative_to(PROJECT_ROOT)),
        }


def openai_env_config(prefix: str = "") -> dict[str, str]:
    model = os.getenv(f"{prefix}OPENAI_MODEL") or os.getenv("OPENAI_MODEL") or os.getenv("REPORTING_LLM_MODEL") or "gpt-4o-mini"
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    return {
        "OPENAI_MODEL": model,
        "OPENAI_BASE_URL": base_url,
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", ""),
    }
