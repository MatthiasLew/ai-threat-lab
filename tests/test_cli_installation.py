"""Release identity, exact CLI options and process stream regressions."""

import argparse
import json
import os
import subprocess
import sys
from importlib.metadata import PackageNotFoundError
from pathlib import Path

import pytest

from ai_threat_lab import __version__, installation
from ai_threat_lab.cli import build_parser

SOURCE = Path(__file__).resolve().parents[1] / "src"


def process(*args, input=None, encoding="utf-8"):
    env = dict(os.environ, PYTHONPATH=str(SOURCE), PYTHONIOENCODING=encoding, PYTHONUTF8="0")
    return subprocess.run(
        [sys.executable, "-m", "ai_threat_lab", *args],
        env=env, input=input, capture_output=True, timeout=15,
    )


def command_parsers():
    root = build_parser()
    action = next(a for a in root._actions if isinstance(a, argparse._SubParsersAction))
    return action.choices


@pytest.mark.parametrize("name", sorted(command_parsers()))
def test_each_command_rejects_abbreviated_help(name):
    # --hel previously worked everywhere, silently accepting a misspelled interface.
    result = process(name, "--hel")
    assert result.returncode == 2
    assert b"Traceback" not in result.stderr


@pytest.mark.parametrize("args", [("--ver", "doctor"), ("doctor", "--instal"),
                                  ("analyze", "ai_phishing", "--orga", "test")])
def test_root_and_child_options_require_full_names(args):
    result = process(*args)
    assert result.returncode == 2
    assert b"unrecognized arguments" in result.stderr


@pytest.mark.parametrize("args", [("--help",), ("--version",), ("scenarios",),
                                  ("controls",), ("doctor", "--installation")])
def test_closed_output_pipe_has_quiet_documented_exit(args):
    env = dict(os.environ, PYTHONPATH=str(SOURCE))
    child = subprocess.Popen(
        [sys.executable, "-m", "ai_threat_lab", *args],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert child.stdout is not None and child.stderr is not None
    child.stdout.close()
    try:
        errors = child.stderr.read()
        assert child.wait(timeout=15) == 141
        assert errors == b""
    finally:
        child.stderr.close()
        if child.poll() is None:
            child.kill()
            child.wait()


def test_utf8_output_does_not_depend_on_legacy_locale():
    # No UTF-8 env opt-in; the process boundary establishes the documented encoding.
    result = process("analyze", "ai_phishing", "--organization", "Łódź Żółw",
                     "--format", "json", encoding="ascii")
    assert result.returncode == 0, result.stderr
    assert "Łódź Żółw" in result.stdout.decode("utf-8")
    json.loads(result.stdout)
    assert result.stderr == b""


def test_release_identity_in_runtime_and_cli():
    result = process("--version")
    assert result.returncode == 0
    assert result.stdout.decode().strip() == f"AI Threat Lab {__version__}"
    report = json.loads(process("doctor", "--installation").stdout)
    assert report["runtime_version"] == __version__
    assert report["network_checked"] is False
    assert report["credentials_checked"] is False
    assert report["checks"]["bundled_catalog"] is True


def test_source_checkout_diagnosis_without_installed_metadata(monkeypatch):
    def absent(_):
        raise PackageNotFoundError
    monkeypatch.setattr(installation, "version", absent)
    report = installation.installation_report()
    assert report["status"] == "ready" and report["mode"] == "source_checkout"
    assert report["distribution_version"] is None


def test_stale_distribution_metadata_is_not_ready(monkeypatch):
    monkeypatch.setattr(installation, "version", lambda _: "0.0.0")
    report = installation.installation_report()
    assert report["status"] == "inconsistent_installation"
    assert report["checks"]["version_consistent"] is False


@pytest.mark.parametrize("raw", [b"not JSON", b"{}", b"[]", b"{\"scenarios\": []}",
                                 b"x" * (1024 * 1024 + 1), b"[" * 2000],
                         ids=["invalid-json", "empty", "array", "missing", "oversize", "deep"])
def test_broken_bundled_catalog_diagnosis(monkeypatch, tmp_path, raw):
    data = tmp_path / "data"
    data.mkdir()
    (data / "catalog.json").write_bytes(raw)
    monkeypatch.setattr(installation, "files", lambda _: tmp_path)
    report = installation.installation_report()
    assert report["status"] == "inconsistent_installation"
    assert report["checks"]["bundled_catalog"] is False


def test_missing_catalog_diagnosis(monkeypatch, tmp_path):
    monkeypatch.setattr(installation, "files", lambda _: tmp_path)
    assert installation.installation_report()["checks"]["bundled_catalog"] is False


def test_unsupported_python_diagnosis(monkeypatch):
    monkeypatch.setattr(installation.sys, "version_info", (3, 11))
    assert installation.installation_report()["checks"]["python_supported"] is False


def test_invalid_utf8_interactive_input_has_no_traceback():
    result = process("interactive", input=b"\xff\n")
    assert result.returncode == 2
    assert result.stderr == b"Error: text cannot be processed as UTF-8.\n"


def test_doctor_installation_failure_exit(monkeypatch, capsys):
    from ai_threat_lab import cli
    monkeypatch.setattr(cli, "installation_report", lambda: {"status": "inconsistent_installation"})
    assert cli.main(["doctor", "--installation"]) == 3
    assert json.loads(capsys.readouterr().out)["status"] == "inconsistent_installation"


def test_doctor_installation_success_exit(monkeypatch, capsys):
    from ai_threat_lab import cli
    monkeypatch.setattr(cli, "installation_report", lambda: {"status": "ready"})
    assert cli.main(["doctor", "--installation"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ready"
