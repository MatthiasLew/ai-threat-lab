"""Real CLI processes: argument parsing, streams, exit codes and file-based workflows."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src"


def run_cli(*args, input=None, cwd=None):
    env = dict(os.environ, PYTHONPATH=str(PACKAGE_ROOT), PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    return subprocess.run(
        [sys.executable, "-m", "ai_threat_lab", *map(str, args)],
        input=input,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
    )


COMMANDS = (
    "scenarios",
    "controls",
    "interactive",
    "analyze",
    "review-code",
    "review-headers",
    "review-html",
    "review-auth-log",
    "review-kubernetes",
    "campaigns",
    "campaign-demo",
    "campaign-report",
    "assess",
    "providers",
    "doctor",
    "campaign-example",
    "campaign-prepare",
    "campaign-approve",
    "campaign-simulate",
    "training-event-keygen",
    "training-events-register",
    "training-events-import",
    "training-events-report",
    "training-events-cancel",
    "training-events-receipt",
    "training-local-status",
    "training-local-cancel",
    "training-start",
    "training-step",
    "training-status",
    "training-run",
    "training-report",
    "training-cancel",
    "scan",
    "scan-batch",
    "batch-check",
    "scan-check",
    "scan-compare",
    "readiness",
    "exercise-export",
    "offline-demo",
)


@pytest.mark.parametrize("command", COMMANDS)
def test_each_command_has_working_help(command):
    result = run_cli(command, "--help")
    assert result.returncode == 0
    assert "usage:" in result.stdout
    assert not result.stderr


@pytest.mark.parametrize(
    "args",
    [
        (),
        ("unknown",),
        ("analyze",),
        ("review-code",),
        ("campaign-approve", "missing.json"),
        ("campaign-simulate", "missing.json"),
        ("analyze", "ai_phishing", "--format", "yaml"),
        ("analyze", "ai_phishing", "--access", "admin"),
    ],
)
def test_parser_rejects_invalid_invocations(args):
    result = run_cli(*args)
    assert result.returncode == 2
    assert "usage:" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "scenario",
    [
        "ai_phishing",
        "voice_deepfake",
        "video_deepfake",
        "brute_force",
        "credential_stuffing",
        "insecure_generated_code",
    ],
)
def test_risk_json_process_output_is_machine_readable(scenario):
    result = run_cli("analyze", scenario, "--format", "json", "--organization", "Żółć Sp. z o.o.")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["analysis"]["target"]["organization"] == "Żółć Sp. z o.o."
    assert report["analysis"]["scenario_id"] == scenario
    assert not result.stderr


@pytest.mark.parametrize("scenario", ["email_training", "voice_training"])
def test_full_offline_file_workflow_in_path_with_spaces(tmp_path, scenario):
    folder = tmp_path / "Projekt testowy Łódź"
    folder.mkdir()
    request, plan, approval, result = [
        folder / name for name in ("request.json", "plan.json", "approval.json", "result.json")
    ]
    commands = [
        ("campaign-example", scenario, "--output", request),
        ("campaign-prepare", request, "--output", plan),
        ("campaign-approve", plan, "--reviewer", "Reviewer", "--output", approval),
        (
            "campaign-simulate",
            plan,
            "--approval",
            approval,
            "--ledger",
            folder / "ledger.sqlite",
            "--output",
            result,
        ),
    ]
    for command in commands:
        completed = run_cli(*command, cwd=folder)
        assert completed.returncode == 0, completed.stderr
        assert not completed.stderr
    payload = json.loads(result.read_text(encoding="utf-8"))
    assert payload["mode"] == "offline_simulation"
    assert payload["receipts"][0]["status"] == "simulated"
    duplicate = run_cli(
        "campaign-simulate", plan, "--approval", approval, "--ledger", folder / "ledger.sqlite"
    )
    assert duplicate.returncode == 2
    assert "already attempted" in duplicate.stderr


def test_unicode_output_export_and_existing_file_preservation(tmp_path):
    path = tmp_path / "raport.json"
    first = run_cli("campaign-demo", "voice_training", "--output", path)
    assert first.returncode == 0
    original = path.read_bytes()
    second = run_cli("campaign-demo", "voice_training", "--output", path)
    assert second.returncode == 2
    assert path.read_bytes() == original
    assert "Traceback" not in second.stderr


def test_provider_diagnostics_and_missing_provider_exit_code(tmp_path):
    config = tmp_path / "providers.json"
    config.write_text('{"schema_version":1,"content":"not-installed"}')
    result = run_cli("--config", config, "doctor")
    assert result.returncode == 3
    assert json.loads(result.stdout)["status"] == "missing_provider"
    result = run_cli("--config", config, "providers")
    assert result.returncode == 0
    assert json.loads(result.stdout)["selected"]["content"] == "not-installed"


@pytest.mark.parametrize(
    "content",
    [
        "broken",
        "[]",
        '{"schema_version":true}',
        '{"schema_version":1,"api_key":"PRIVATE_EXAMPLE_VALUE"}',
    ],
)
def test_invalid_configuration_does_not_echo_contents_or_tracebacks(tmp_path, content):
    config = tmp_path / "bad.json"
    config.write_text(content)
    result = run_cli("--config", config, "doctor")
    assert result.returncode == 2
    assert "PRIVATE_EXAMPLE_VALUE" not in result.stderr
    assert "Traceback" not in result.stderr


def test_interactive_real_input_and_eof():
    complete = run_cli(
        "interactive", input="voice_deepfake\n\n\n\n\n\ncallback independent_approval\n"
    )
    assert complete.returncode == 0
    assert "10/25" in complete.stdout
    eof = run_cli("interactive", input="")
    assert eof.returncode == 2
    assert "Traceback" not in eof.stderr


def test_remote_target_stays_not_configured_without_adapter():
    result = run_cli("assess", "https://example.invalid")
    assert result.returncode == 0
    assert json.loads(result.stdout)["status"] == "not_configured"


def test_version_command():
    result = run_cli("--version")
    assert result.returncode == 0 and result.stdout.startswith("AI Threat Lab ")
