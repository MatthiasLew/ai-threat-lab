import hashlib
import json
import os
import subprocess

import pytest

from ai_threat_lab.cli import main
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scanner_plan import plan_bandit


@pytest.fixture
def candidate(tmp_path):
    executable = tmp_path / "bandit.exe"
    raw = b"inert candidate, not executable"
    executable.write_bytes(raw)
    project = tmp_path / "project"
    project.mkdir()
    return project, {
        "executable": executable,
        "expected_sha256": hashlib.sha256(raw).hexdigest(),
        "declared_version": "1.7.8",
    }


def test_plan_and_blocked_execution_never_spawn(candidate, monkeypatch, capsys):
    project, options = candidate
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("unexpected process"))
    monkeypatch.setattr("ai_threat_lab.scanner_plan.shutil.which", lambda name: None)
    assert main(["scanner", "doctor"]) == 0
    assert not json.loads(capsys.readouterr().out)["candidate_present"]
    assert main(["scanner", "list"]) == 0
    assert json.loads(capsys.readouterr().out)["scanners"][0]["execution"] == "blocked"
    assert main([
        "scanner", "plan", "bandit", str(project), "--executable", str(options["executable"]),
        "--sha256", options["expected_sha256"], "--version", options["declared_version"],
    ]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["executable_sha256"] == options["expected_sha256"]
    assert not plan["version_verified"] and not plan["authorized_to_execute"]
    assert main(["scanner", "run", "bandit", str(project)]) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out)["execution"] == "blocked"
    assert "confinement" in captured.err


def test_candidate_changes_and_invalid_plan_are_rejected(candidate):
    project, options = candidate
    with pytest.raises(ValidationError, match="version"):
        plan_bandit(project, **{**options, "declared_version": "99.0"})
    with pytest.raises(ValidationError, match="64 hex"):
        plan_bandit(project, **{**options, "expected_sha256": "fake"})
    with pytest.raises(ValidationError, match="absolute"):
        plan_bandit(project, **{**options, "executable": "bandit"})
    with pytest.raises(ValidationError, match="Cannot open"):
        plan_bandit(project / "missing", **options)
    options["executable"].write_bytes(b"replacement")
    with pytest.raises(ValidationError, match="fingerprint"):
        plan_bandit(project, **options)


def test_linked_target_is_rejected(candidate, tmp_path):
    project, options = candidate
    link = tmp_path / "link"
    if os.name == "nt":
        from _winapi import CreateJunction

        CreateJunction(str(project), str(link))
    else:
        link.symlink_to(project, target_is_directory=True)
    with pytest.raises(ValidationError):
        plan_bandit(link, **options)
