"""Pytest-only isolation for Aegis mutable runtime state.

The application intentionally keeps demo databases and reporting fixtures in
the repository.  Tests must not mutate those tracked files, so this module
creates an equivalent temporary runtime before test collection and redirects
the existing configuration seams to it.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent
_ENV_KEYS = (
    "REPORTING_INPUT_DIR",
    "REPORTING_OUTPUT_DIR",
    "REPORTING_TEMPLATE_DIR",
    "REPORTING_KB_DIR",
    "REPORTING_LLM_CACHE_DIR",
    "REPORTING_CHROMA_DB_PATH",
    "SOC_RUN_OUTPUT_DIR",
    "SOC_OUTPUT_DIR",
    "AEGIS_CHROMA_DB_PATH",
)


def _copy_directory(source: Path, destination: Path) -> None:
    """Copy a fixture tree when present, otherwise create an empty tree."""
    if source.exists():
        shutil.copytree(source, destination)
    else:
        destination.mkdir(parents=True)


def pytest_configure(config: pytest.Config) -> None:
    """Create and configure the isolated runtime before test collection."""
    temporary_directory = tempfile.TemporaryDirectory(prefix="aegis-pytest-")
    root = Path(temporary_directory.name)

    reporting_root = root / "reporting"
    reporting_inputs_target = reporting_root / "inputs"
    reporting_outputs_target = reporting_root / "outputs"
    reporting_root.mkdir(parents=True)

    # run_reporting.py records artifact paths relative to its package root.
    # Keep that lexical contract via a uniquely named ignored symlink while
    # all actual data remains in the system temporary directory.
    bridge_link = (
        PROJECT_ROOT
        / "agents" / "reporting"
        / "outputs"
        / f".pytest-{root.name}"
    )
    bridge_link.symlink_to(reporting_root, target_is_directory=True)
    reporting_inputs = bridge_link / "inputs"
    reporting_outputs = bridge_link / "outputs"
    merged_fixture = root / "merged_report_context"

    _copy_directory(
        PROJECT_ROOT / "agents" / "reporting" / "inputs",
        reporting_inputs_target,
    )
    reporting_outputs_target.mkdir(parents=True)
    _copy_directory(
        PROJECT_ROOT / "agents" / "reporting" / "testdata" / "merged_report_context",
        merged_fixture,
    )

    paths = {
        "REPORTING_INPUT_DIR": reporting_inputs,
        "REPORTING_OUTPUT_DIR": reporting_outputs,
        "REPORTING_TEMPLATE_DIR": PROJECT_ROOT / "agents" / "reporting" / "report_templates",
        "REPORTING_KB_DIR": PROJECT_ROOT / "knowledge_base" / "reporting",
        "REPORTING_LLM_CACHE_DIR": root / "reporting_cache",
        "REPORTING_CHROMA_DB_PATH": root / "reporting_chroma",
        "SOC_RUN_OUTPUT_DIR": root / "run_outputs",
        "SOC_OUTPUT_DIR": root / "run_outputs",
        "AEGIS_CHROMA_DB_PATH": root / "aegis_chroma",
    }
    for path in paths.values():
        if not path.exists() and PROJECT_ROOT not in path.parents:
            path.mkdir(parents=True)

    previous_environment = {key: os.environ.get(key) for key in _ENV_KEYS}
    os.environ.update({key: str(value) for key, value in paths.items()})

    config._aegis_test_isolation = SimpleNamespace(  # type: ignore[attr-defined]
        temporary_directory=temporary_directory,
        previous_environment=previous_environment,
        bridge_link=bridge_link,
        root=root,
        reporting_inputs=reporting_inputs,
        reporting_outputs=reporting_outputs,
        merged_fixture=merged_fixture,
        workflow_artifacts=root / "workflow_artifacts",
        adapter_logs=root / "adapter_logs",
        adapter_runtime=root / "adapter_runtime",
    )


@pytest.fixture(autouse=True)
def _isolate_mutable_test_state(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Redirect mutable module globals for every collected test."""
    isolation = request.config._aegis_test_isolation  # type: ignore[attr-defined]

    import soc_workflow
    import workflow_state_store

    monkeypatch.setattr(workflow_state_store, "DB_FILE", tmp_path / "workflow.db")
    monkeypatch.setattr(soc_workflow, "PIPELINE_DB_FILE", tmp_path / "pipeline.db")
    monkeypatch.setattr(soc_workflow, "_TRUSTED_OUTPUT_ROOT", isolation.workflow_artifacts)

    module = request.module
    module_path = Path(getattr(module, "__file__", "")).resolve()
    script_dir = PROJECT_ROOT / "agents" / "reporting" / "scripts"

    if module_path == script_dir / "test_evidence_gap_branch_and_reporting_wrapper.py":
        monkeypatch.setattr(module, "INPUTS_DIR", isolation.reporting_inputs)
        monkeypatch.setattr(module, "OUTPUTS_DIR", isolation.reporting_outputs)
    elif module_path == script_dir / "test_reporting_appendix_context.py":
        monkeypatch.setattr(module, "INPUTS", isolation.reporting_inputs)
        monkeypatch.setattr(module, "OUTPUTS", isolation.reporting_outputs)
    elif module_path == script_dir / "test_merged_report_context.py":
        monkeypatch.setattr(module, "BASE", isolation.merged_fixture)
        monkeypatch.setattr(module, "INPUTS", isolation.merged_fixture / "inputs")
        monkeypatch.setattr(module, "OUTPUTS", isolation.merged_fixture / "outputs")

    common = sys.modules.get("adapters.common")
    if common is not None:
        monkeypatch.setattr(common, "INPUTS_DIR", isolation.reporting_inputs)
        monkeypatch.setattr(common, "OUTPUTS_DIR", isolation.reporting_outputs)
        monkeypatch.setattr(common, "LOGS_DIR", isolation.adapter_logs)
        monkeypatch.setattr(common, "RUNTIME_DIR", isolation.adapter_runtime)

    run_reporting = sys.modules.get("adapters.run_reporting")
    if run_reporting is not None:
        monkeypatch.setattr(run_reporting, "INPUTS_DIR", isolation.reporting_inputs)
        monkeypatch.setattr(run_reporting, "OUTPUTS_DIR", isolation.reporting_outputs)


def pytest_unconfigure(config: pytest.Config) -> None:
    """Restore the process environment and remove the temporary runtime."""
    isolation = getattr(config, "_aegis_test_isolation", None)
    if isolation is None:
        return

    for key, previous_value in isolation.previous_environment.items():
        if previous_value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = previous_value
    isolation.bridge_link.unlink(missing_ok=True)
    isolation.temporary_directory.cleanup()
