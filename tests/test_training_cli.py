import json
import os
import subprocess
import sys

import pytest

from ai_threat_lab.cli import main
from ai_threat_lab.contracts import approval_to_document, write_document
from ai_threat_lab.providers import ProviderConfig, ProviderRegistry
from ai_threat_lab.training_cli import interactive, terminal_text
from ai_threat_lab.training_lab import TrainingLab
from ai_threat_lab.workflows import approve_campaign, example_request, prepare_campaign


def saved_plan(tmp_path, channel="voice"):
    plan = prepare_campaign(
        example_request(channel + "_training"), ProviderRegistry(), ProviderConfig()
    )
    approval = approval_to_document(approve_campaign(plan, "fixture-reviewer"))
    write_document(plan, tmp_path / "plan.json")
    write_document(approval, tmp_path / "approval.json")
    return tmp_path / "plan.json", tmp_path / "approval.json"


def started(tmp_path, capsys, channel="voice"):
    plan, approval = saved_plan(tmp_path, channel)
    database = tmp_path / "training.sqlite"
    assert (
        main(
            [
                "training-start",
                str(plan),
                "--approval",
                str(approval),
                "--participant-id",
                "p1",
                "--ledger",
                str(database),
            ]
        )
        == 0
    )
    state = json.loads(capsys.readouterr().out)
    return state["session_id"], database


def test_cli_step_status_report_json_and_html(tmp_path, capsys):
    identifier, database = started(tmp_path, capsys)
    base = [identifier, "--ledger", str(database)]
    assert main(["training-status", *base]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "running"
    step = ["training-step", *base, "--action", "request_verification", "--action-id", "one"]
    assert main(step) == 0
    assert json.loads(capsys.readouterr().out)["session"]["outcome"] == "verification_selected"
    assert main(step) == 0
    assert json.loads(capsys.readouterr().out)["replayed"]
    assert main(["training-report", "--ledger", str(database), "--session-id", identifier]) == 0
    assert json.loads(capsys.readouterr().out)["counts"]["sessions"] == 1
    assert main(["training-report", "--ledger", str(database), "--format", "html"]) == 0
    assert "<!doctype html>" in capsys.readouterr().out
    html = tmp_path / "report.html"
    args = ["training-report", "--ledger", str(database), "--format", "html", "--output", str(html)]
    assert main(args) == 0 and "Local text rehearsal" in html.read_text(encoding="utf-8")
    assert main(args) == 2
    capsys.readouterr()


def test_interactive_invalid_numeric_then_stop_and_no_raw_storage(tmp_path, capsys, monkeypatch):
    identifier, database = started(tmp_path, capsys, "email")
    answers = iter(["SECRET_RAW_ENTRY", "999", "١", ""])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert main(["training-run", identifier, "--ledger", str(database)]) == 0
    output = capsys.readouterr().out
    assert "Invalid selection" in output and "SECRET_RAW_ENTRY" not in output
    assert "participant_stop" in output
    assert b"SECRET_RAW_ENTRY" not in database.read_bytes()
    assert TrainingLab(database).get(identifier)["turns"] == 1


def test_interactive_voice_numeric_selections_show_policy_response(tmp_path, capsys, monkeypatch):
    identifier, database = started(tmp_path, capsys)
    state = TrainingLab(database).get(identifier)
    unknown = str(state["allowed_actions"].index("unknown") + 1)
    answers = iter([unknown, unknown, unknown])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert main(["training-run", identifier, "--ledger", str(database)]) == 0
    output = capsys.readouterr().out
    assert "Only the invented TRAINING-ALPHA" in output and "unclassified" in output


@pytest.mark.parametrize("error", [EOFError(), KeyboardInterrupt()])
def test_interactive_eof_and_interrupt_stop_session(tmp_path, capsys, monkeypatch, error):
    identifier, database = started(tmp_path, capsys)

    def stop(prompt):
        raise error

    monkeypatch.setattr("builtins.input", stop)
    assert main(["training-run", identifier, "--ledger", str(database)]) == 0
    assert "Local interaction stopped" in capsys.readouterr().out
    assert TrainingLab(database).get(identifier)["status"] == "stopped"


def test_interactive_rechecks_expiry_at_prompt(tmp_path, capsys, monkeypatch):
    from datetime import timedelta

    from test_training_lab import NOW, approved

    times = iter([NOW, NOW, NOW + timedelta(hours=2)])
    lab = TrainingLab(tmp_path / "lab.sqlite", clock=lambda: next(times))
    state = lab.start(*approved(), "p1")
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("Expired session cannot prompt"))
    assert interactive(lab, state["session_id"]) == 0
    assert "expired" in capsys.readouterr().out


def test_terminal_controls_escaped():
    assert "\x1b" not in terminal_text("\x1b]0;malicious\x07\nnormal")
    assert "\\u001b" in terminal_text("\x1b")


def test_unknown_session_and_action_channel_errors_are_readable(tmp_path, capsys):
    identifier, database = started(tmp_path, capsys)
    assert main(["training-status", "unknown", "--ledger", str(database)]) == 2
    assert "does not exist" in capsys.readouterr().err
    assert (
        main(["training-step", identifier, "--action", "open_preview", "--ledger", str(database)])
        == 2
    )
    assert "channel" in capsys.readouterr().err


def test_report_empty_and_start_output_file(tmp_path, capsys):
    database = tmp_path / "training.sqlite"
    assert main(["training-report", "--ledger", str(database)]) == 0
    assert json.loads(capsys.readouterr().out)["counts"]["sessions"] == 0
    plan, approval = saved_plan(tmp_path)
    output = tmp_path / "session.json"
    assert (
        main(
            [
                "training-start",
                str(plan),
                "--approval",
                str(approval),
                "--participant-id",
                "p1",
                "--ledger",
                str(database),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(output.read_text())["mode"] == "local_text_rehearsal"
    capsys.readouterr()


def test_actual_training_cli_processes_and_help(tmp_path):
    plan, approval = saved_plan(tmp_path)
    database = tmp_path / "training.sqlite"

    def run(*args, input=None):
        result = subprocess.run(
            [sys.executable, "-m", "ai_threat_lab", *map(str, args)],
            input=input,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1"),
            timeout=20,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    for command in (
        "training-start",
        "training-step",
        "training-status",
        "training-run",
        "training-report",
    ):
        assert "usage:" in run(command, "--help")
    state = json.loads(
        run(
            "training-start",
            plan,
            "--approval",
            approval,
            "--participant-id",
            "p1",
            "--ledger",
            database,
        )
    )
    identifier = state["session_id"]
    assert "participant_stop" in run("training-run", identifier, "--ledger", database, input="\n")
    assert (
        json.loads(run("training-status", identifier, "--ledger", database))["status"] == "stopped"
    )
    assert json.loads(run("training-report", "--ledger", database))["counts"]["sessions"] == 1


def test_cli_plan_cancellation_and_completed_interaction(tmp_path, capsys, monkeypatch):
    identifier, database = started(tmp_path, capsys)
    digest = TrainingLab(database).get(identifier)["plan_digest"]
    assert main(["training-cancel", "--plan-digest", digest, "--ledger", str(database)]) == 0
    assert json.loads(capsys.readouterr().out)["cancelled_sessions"] == 1
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("Cancelled exercise cannot prompt"))
    assert main(["training-run", identifier, "--ledger", str(database)]) == 0
    output = capsys.readouterr().out
    assert "operator_cancelled" in output
    assert "Good morning, this is the fictional" not in output
