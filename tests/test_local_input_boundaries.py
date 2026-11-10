"""Ordinary collector boundaries, independent of Agent Mode snapshots."""

import os
import subprocess
import sys

import pytest

from ai_threat_lab.assessment import AssessmentService
from ai_threat_lab.code_review import read_python_source
from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.models import ValidationError


def test_python_link_rejection_keeps_scope_diagnostic(tmp_path, monkeypatch):
    import ai_threat_lab.dependency_paths as paths

    source = tmp_path / "source.py"
    source.write_text("eval(input())\n", encoding="utf-8")
    assert read_python_source(source).startswith("eval")
    monkeypatch.setattr(paths, "linked", lambda _: True)
    with pytest.raises(ValidationError, match="inside"):
        read_python_source(source)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics")
def test_ordinary_collectors_do_not_follow_directory_junction(tmp_path):
    import _winapi

    root, outside = tmp_path / "project", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "inside.py").write_text("eval(inside_input)\n", encoding="utf-8")
    (outside / "outside.py").write_text("eval(outside_input)\n", encoding="utf-8")
    (outside / ".env").write_text('PASSWORD="INERT_MARKER"\n', encoding="utf-8")
    _winapi.CreateJunction(str(outside), str(root / "junction"))
    for result in (AssessmentService().assess(str(root)), local_inventory(str(root))):
        evidence = "\n".join(f.evidence for f in result.findings)
        assert "inside.py" in evidence
        assert "outside.py" not in evidence
        assert "junction" not in evidence


@pytest.mark.skipif(os.name == "nt", reason="POSIX named pipes")
def test_text_fifo_does_not_block_inventory(tmp_path):
    (tmp_path / "inside.py").write_text("eval(input())\n", encoding="utf-8")
    os.mkfifo(tmp_path / "hostile.json")
    result = subprocess.run(
        [sys.executable, "-m", "ai_threat_lab", "scan", str(tmp_path),
         "--output-dir", str(tmp_path.parent / (tmp_path.name + "-run"))],
        capture_output=True, timeout=15,
    )
    assert result.returncode == 0
    assert b"unique_findings" in result.stdout
