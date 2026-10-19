"""Release identity, exact CLI options and process stream regressions."""

import argparse
import errno
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
        assert child.wait(timeout=15) == 141, errors.decode("utf-8", errors="replace")
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
    assert result.stderr.splitlines() == [b"Error: text cannot be processed as UTF-8."]


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


@pytest.mark.parametrize("method", ["write", "flush"])
def test_windows_invalid_argument_on_pipe_becomes_broken_pipe(method):
    from ai_threat_lab.cli import _WindowsPipeOutput

    read_fd, write_fd = os.pipe()
    class Stream:
        def fileno(self):
            return write_fd
        def write(self, *args):
            raise OSError(errno.EINVAL, "Windows CRT pipe failure")
        flush = write
    try:
        wrapped = _WindowsPipeOutput(Stream())
        with pytest.raises(BrokenPipeError):
            getattr(wrapped, method)(*(["text"] if method == "write" else []))
    finally:
        os.close(read_fd)
        os.close(write_fd)


@pytest.mark.parametrize("code", [errno.EINVAL, errno.ENOSPC, errno.EACCES])
def test_windows_output_wrapper_does_not_hide_file_errors(tmp_path, code):
    from ai_threat_lab.cli import _WindowsPipeOutput

    with (tmp_path / "regular file").open("w") as handle:
        class Stream:
            def fileno(self):
                return handle.fileno()
            def write(self, text):
                raise OSError(code, "file error")
        with pytest.raises(OSError) as caught:
            _WindowsPipeOutput(Stream()).write("text")
        assert not isinstance(caught.value, BrokenPipeError)
        assert caught.value.errno == code


def test_windows_output_wrapper_forwards_regular_stream_operations(tmp_path):
    from ai_threat_lab.cli import _WindowsPipeOutput

    path = tmp_path / "output"
    with path.open("w", encoding="utf-8") as handle:
        wrapped = _WindowsPipeOutput(handle)
        assert wrapped.encoding == "utf-8"
        assert wrapped.write("Łódź") == 4
        wrapped.flush()
    assert path.read_text(encoding="utf-8") == "Łódź"


def test_closed_error_pipe_has_quiet_documented_exit():
    env = dict(os.environ, PYTHONPATH=str(SOURCE))
    child = subprocess.Popen(
        [sys.executable, "-m", "ai_threat_lab", "unknown-command"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert child.stdout is not None and child.stderr is not None
    child.stderr.close()
    try:
        output = child.stdout.read()
        assert child.wait(timeout=15) == 141, output.decode("utf-8", errors="replace")
        assert output == b""
    finally:
        child.stdout.close()
        if child.poll() is None:
            child.kill()
            child.wait()


@pytest.mark.parametrize("change", ["schema", "invalid-record", "invalid-rule", "duplicate"])
def test_catalog_diagnosis_uses_full_runtime_validation(monkeypatch, tmp_path, change):
    raw = json.loads((SOURCE / "ai_threat_lab/data/catalog.json").read_text(encoding="utf-8"))
    if change == "schema":
        raw["schema_version"] = 2
    elif change == "invalid-record":
        raw["scenarios"] = [None]
    elif change == "invalid-rule":
        raw["scenarios"][0]["rules"][0]["control_id"] = "unknown-control"
    else:
        raw["controls"].append(raw["controls"][0])
    data = tmp_path / "data"
    data.mkdir()
    (data / "catalog.json").write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setattr(installation, "files", lambda _: tmp_path)
    report = installation.installation_report()
    assert report["status"] == "inconsistent_installation"
    assert report["checks"]["bundled_catalog"] is False
