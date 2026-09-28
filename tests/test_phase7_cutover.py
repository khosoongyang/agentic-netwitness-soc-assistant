"""Cutover guards for the canonical Flask application."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_active_python_has_no_streamlit_imports() -> None:
    excluded = {".git", ".venv", "runtime", "__pycache__"}
    for path in ROOT.rglob("*.py"):
        if any(part in excluded for part in path.parts):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name != "streamlit" for alias in node.names), path
            if isinstance(node, ast.ImportFrom):
                assert node.module != "streamlit" and not str(node.module).startswith("streamlit."), path


def test_streamlit_artifacts_and_dependency_are_removed() -> None:
    assert not (ROOT / ".streamlit").exists()
    assert not (ROOT / "scripts" / "legacy_streamlit_app.py").exists()
    assert not (ROOT / "chroma_viewer.py").exists()
    requirement_lines = {
        line.partition("#")[0].strip().lower()
        for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    }
    assert not any(line.startswith("streamlit") for line in requirement_lines)
    for active_document in ("README.md", "DEPLOY.md"):
        text = (ROOT / active_document).read_text(encoding="utf-8").lower()
        assert "python app.py" in text
        assert "streamlit run" not in text


def test_root_app_is_only_the_flask_launcher() -> None:
    path = ROOT / "app.py"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    assert not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in ast.walk(tree))
    assert "from backend.app import create_app" in source
    assert "app = create_app()" in source
    assert "soc_reporting_agent" not in source
    assert "app.run(" in source
