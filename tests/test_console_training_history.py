"""Real persisted workflows through the guided console, including approval refusal."""

import json

from ai_threat_lab.cli import main
from ai_threat_lab.contracts import write_document
from ai_threat_lab.workflows import example_request


def input_sequence(monkeypatch, items):
    iterator = iter(map(str, items))
    monkeypatch.setattr("builtins.input", lambda _: next(iterator))


def test_console_training_prepare_approve_start_stop_report_export(tmp_path, monkeypatch, capsys):
    request, plan = tmp_path / "request.json", tmp_path / "plan.json"
    approval, session = tmp_path / "approval.json", tmp_path / "session.json"
    ledger = tmp_path / "training.sqlite"
    report, assets = tmp_path / "report.html", tmp_path / "assets"
    input_sequence(monkeypatch, [
        "7", "1", "voice_training", request,
        "7", "2", request, plan,
        "7", "3", plan, "n",  # Refusal never creates an approval.
        "0",
    ])
    assert main(["console"]) == 0
    assert plan.exists() and not approval.exists()
    assert "No approval was recorded" in capsys.readouterr().out
    input_sequence(monkeypatch, [
        "7", "3", plan, "y", "fixture-reviewer", approval,
        "7", "4", plan, approval, "fixture-alias", ledger, session,
        "7", "8", plan, approval, assets, "0",
    ])
    assert main(["console"]) == 0
    assert approval.exists() and session.exists() and assets.is_dir()
    saved = json.loads(session.read_text(encoding="utf-8"))
    input_sequence(monkeypatch, [
        "7", "5", saved["session_id"], ledger, "",  # Local exercise stop action.
        "7", "6", ledger, report,
        "7", "7", saved["plan_digest"], ledger, "n",
        "7", "7", saved["plan_digest"], ledger, "y", "0",
    ])
    assert main(["console"]) == 0
    assert report.is_file()
    text = capsys.readouterr().out
    assert "Cancellation was not applied" in text
    assert "cancelled" in text.lower()


def test_console_history_batch_verification_and_export(tmp_path, monkeypatch):
    first, second = tmp_path / "a.py", tmp_path / "b.py"
    first.write_text("eval(input())")
    second.write_text("value = 1")
    root = tmp_path / "history"
    root.mkdir()
    batch, html = root / "batch", tmp_path / "report.html"
    input_sequence(monkeypatch, [
        "8", "4", first, second, "", batch, "y",
        "8", "5", batch,
        "8", "3", batch, html,
        "8", "1", root, "0",
    ])
    assert main(["console"]) == 0
    assert (batch / "batch.json").exists() and html.exists()


def test_console_workflow_errors_and_cancelled_batch_do_not_write(tmp_path, monkeypatch, capsys):
    target = tmp_path / "a.py"
    target.write_text("pass")
    output = tmp_path / "batch"
    input_sequence(monkeypatch, [
        "7", "0", "8", "0", "7", "9", "8", "9", "8", "4", "",
        "7", "3", tmp_path / "missing.json",
        "8", "4", target, "", output, "n", "0",
    ])
    assert main(["console"]) == 0
    assert not output.exists()
    text = capsys.readouterr().out
    assert "Input problem" in text and "Cannot read" in text and "Batch cancelled" in text


def test_console_preserves_explicit_provider_configuration(tmp_path, monkeypatch, capsys):
    request, plan = tmp_path / "request.json", tmp_path / "plan.json"
    settings = tmp_path / "providers.json"
    write_document(example_request("email_training"), request)
    write_document({"schema_version": 1, "content": "not-registered"}, settings)
    input_sequence(monkeypatch, ["7", "2", request, plan, "0"])
    assert main(["--config", str(settings), "console"]) == 0
    assert not plan.exists()  # The menu must not fall back to the default template provider.
    assert "Selected content provider is not installed" in capsys.readouterr().err
