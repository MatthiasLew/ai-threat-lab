"""Contract tests without GUI, live providers or target execution."""

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from ai_threat_lab import ScanCancelled, ScanControl, run_audit
from ai_threat_lab.assessment import AssessmentResult
from ai_threat_lab.cli import main
from ai_threat_lab.gui_api import get_capabilities
from ai_threat_lab.scan_bundle import read_bundle
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "źródła with spaces"
    root.mkdir()
    (root / "app.py").write_text("eval(input())\n", encoding="utf-8")
    return root


def test_gui_free_event_contract_and_existing_report_compatibility(project, tmp_path):
    events = []
    result = run_audit(project, tmp_path / "run", on_event=events.append)
    assert result["unique_findings"] == 1
    assert read_bundle(tmp_path / "run")["manifest"]["run_id"] == result["run_id"]
    assert [e.sequence for e in events] == list(range(1, len(events) + 1))
    assert {e.schema_version for e in events} == {1}
    assert len({e.operation_id for e in events}) == 1
    assert events[0].event == "scan_started"
    assert events[-1].event == "scan_completed"
    assert [(e.event, e.module) for e in events if e.module] == [
        ("module_started", "target_assessment"),
        ("module_completed", "target_assessment"),
        ("module_started", "dependency_inventory"),
        ("module_completed", "dependency_inventory"),
        ("module_skipped", "dependency_advisories"),
    ]
    assert "pdf" in get_capabilities()["export_formats"]


@pytest.mark.parametrize("checkpoint", ["scan_started", "module_completed", "scan_publishing"])
def test_cancel_before_publication_preserves_previous_run(project, tmp_path, checkpoint):
    previous = tmp_path / "previous"
    run_audit(project, previous)
    saved = (previous / "manifest.json").read_bytes()
    token, events = ScanControl(), []

    def event(item):
        events.append(item.event)
        if item.event == checkpoint:
            assert token.request_cancel()

    with pytest.raises(ScanCancelled):
        run_audit(project, tmp_path / "cancelled", control=token, on_event=event)
    assert events[-2:] == ["scan_cancel_requested", "scan_cancelled"]
    assert "scan_completed" not in events
    assert not (tmp_path / "cancelled").exists()
    assert (previous / "manifest.json").read_bytes() == saved
    assert not token.request_cancel()
    with pytest.raises(ValueError, match="single-use"):
        run_audit(project, tmp_path / "reuse", control=token)


def test_cross_thread_cancel_does_not_cancel_parallel_operation(project, tmp_path):
    entered, release = Event(), Event()
    token = ScanControl()

    def blocked(options):
        entered.set()
        assert release.wait(10)
        return AssessmentResult(options.target, "local_project", "partial", (), ("gap",))

    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(
            ScanService(blocked).run, ScanOptions(str(project)), tmp_path / "cancel",
            control=token,
        )
        try:
            assert entered.wait(10)
            assert token.request_cancel()
            result = run_audit(project, tmp_path / "other")
            assert result["unique_findings"] == 1
        finally:
            release.set()
        with pytest.raises(ScanCancelled):
            future.result(timeout=10)
    assert not (tmp_path / "cancel").exists()


def test_failures_skips_observer_failure_and_no_raw_exception(project, tmp_path):
    events = []

    def broken(_):
        raise RuntimeError("PRIVATE_EXCEPTION")

    result = ScanService(broken).run(
        ScanOptions(str(project / "app.py")), tmp_path / "failure", on_event=events.append,
    )
    assert result["failed_modules"] == ["target_assessment"]
    assert any(e.event == "module_failed" for e in events)
    assert sum(e.event == "module_skipped" for e in events) == 2
    assert "PRIVATE_EXCEPTION" not in json.dumps([e.to_dict() for e in events])

    def disconnected(_):
        raise RuntimeError("display gone")

    assert run_audit(project, tmp_path / "display", on_event=disconnected)["unique_findings"] == 1
    with pytest.raises(FileExistsError):
        run_audit(project, tmp_path / "display", on_event=events.append)
    assert events[-1].event == "scan_failed"


def test_ctrl_c_during_collector_and_cli_json_cancel(project, tmp_path, monkeypatch, capsys):
    import ai_threat_lab.scan_cli as scan_cli

    events = []

    def interrupted(_):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        ScanService(interrupted).run(
            ScanOptions(str(project)), tmp_path / "interrupted", on_event=events.append,
        )
    assert events[-1].event == "scan_cancelled"
    assert not (tmp_path / "interrupted").exists()
    monkeypatch.setattr(scan_cli, "assessor", interrupted)
    assert main(["scan", str(project), "--output-dir", str(tmp_path / "cli")]) == 130
    assert json.loads(capsys.readouterr().out)["status"] == "cancelled"


def test_real_cli_progress_keeps_stdout_json(project, tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "ai_threat_lab", "scan", str(project),
         "--output-dir", str(tmp_path / "process"), "--progress"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["unique_findings"] == 1
    rows = [json.loads(line) for line in result.stderr.splitlines()]
    assert rows[0]["event"] == "scan_started" and rows[-1]["event"] == "scan_completed"
    assert "\x1b" not in result.stdout + result.stderr


def test_closed_control_rejects_late_cancel(project, tmp_path):
    token = ScanControl()
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "done", control=token)
    assert token.request_cancel() is False


def test_interrupt_during_publication_is_not_claimed_uncommitted(
    project, tmp_path, monkeypatch, capsys,
):
    import ai_threat_lab.scan_engine as engine

    def interrupted(*args):
        raise KeyboardInterrupt

    monkeypatch.setattr(engine, "publish_bundle", interrupted)
    events, token = [], ScanControl()
    with pytest.raises(KeyboardInterrupt):
        run_audit(project, tmp_path / "run", control=token, on_event=events.append)
    assert events[-1].event == "scan_interrupted"
    assert events[-1].status == "verification_required"
    assert not token.request_cancel()
    assert main(["scan", str(project), "--output-dir", str(tmp_path / "cli")]) == 130
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "interrupted" and result["bundle_committed"] is None
