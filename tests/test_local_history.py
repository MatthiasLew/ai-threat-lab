"""Saved scan/batch history and exports never reopen source targets or contact providers."""

import json
import os
import socket

import pytest
from test_cli_process import run_cli
from test_report_consistency import reindex

import ai_threat_lab.local_history as history
from ai_threat_lab.assessment import AssessmentResult
from ai_threat_lab.batch_scan import run_batch
from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.models import ValidationError
from ai_threat_lab.report_io import ReportReadLimit, read_regular, report_read_budget
from ai_threat_lab.scan_engine import ScanOptions, ScanService


def collection(tmp_path):
    root = tmp_path / "history"
    root.mkdir()
    source = tmp_path / "source.py"
    source.write_text("eval(untrusted)\n")
    service = ScanService(lambda options: local_inventory(options.target))
    service.run(ScanOptions(str(source)), root / "one")
    source.write_text("safe = 1\n")
    service.run(ScanOptions(str(source)), root / "two", baseline=root / "one")
    run_batch([str(source)], root / "batch")
    return root, source


def test_catalog_single_batch_comparison_after_source_deleted_and_no_writes(tmp_path, monkeypatch):
    root, source = collection(tmp_path)
    source.unlink()
    snapshots = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}

    def deny(*a, **k):
        pytest.fail("History/export must not contact providers")

    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    value = history.history_list(root)
    assert value["verified_runs"] == 3 and value["invalid_runs"] == 0
    rows = {r["directory"]: r for r in value["runs"]}
    assert rows["one"]["unique_findings"] == 1
    assert rows["two"]["unique_findings"] == 0
    assert rows["two"]["comparison"]["counts"]["no_longer_observed"] == 1
    assert rows["batch"]["created_at"] is None and rows["batch"]["run_id"] is None
    assert rows["batch"]["target_count"] == 1
    assert snapshots == {
        p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()
    }
    for name in ("one", "batch"):
        for format in ("json", "html"):
            output = tmp_path / f"{name}.{format}"
            result = history.export_report(root / name, format=format, output=output)
            assert result == output.read_text(encoding="utf-8")
            assert "untrusted" not in result
            if os.name != "nt":
                assert output.stat().st_mode & 0o777 == 0o600
            with pytest.raises(FileExistsError):
                history.export_report(root / name, output=output)


def test_invalid_incomplete_unknown_and_ignored_entries_are_explicit(tmp_path):
    root, _ = collection(tmp_path)
    reindex(root / "one", "report.html", b"PRIVATE invalid HTML")
    (root / "two" / "manifest.json").unlink()
    (root / "notes").mkdir()
    (root / "note.txt").write_text("PRIVATE")
    value = history.history_list(root)
    assert value["verified_runs"] == 1 and value["invalid_runs"] == 2
    assert value["ignored_files"] == value["ignored_directories"] == 1
    invalid = [r for r in value["runs"] if r["verification"] == "invalid"]
    assert all("unique_findings" not in r and "targets" not in r for r in invalid)
    assert "PRIVATE" not in json.dumps(value)
    output = tmp_path / "bad.json"
    with pytest.raises(ValidationError):
        history.export_report(root / "one", output=output)
    assert not output.exists()


def test_failed_module_stays_visible_without_claiming_invalid_storage(tmp_path):
    root = tmp_path / "history"
    root.mkdir()
    source = tmp_path / "source.py"
    source.write_text("safe = 1")

    def fail(options):
        return AssessmentResult(options.target, "python_source", "not_configured", (), ("Absent",))

    ScanService(fail).run(ScanOptions(str(source)), root / "failed")
    value = history.history_list(root)
    assert value["verified_runs"] == 1
    assert value["runs"][0]["failed_components"] == ["target_assessment"]
    assert value["runs"][0]["unique_findings"] == 0


def test_html_escapes_untrusted_directory_names_without_clickable_paths(tmp_path):
    value = {
        "runs": [
            {
                "directory": "<script>PRIVATE</script>",
                "kind": "scan",
                "verification": "invalid",
                "reason": '"onclick=PRIVATE',
            }
        ],
        "notice": "<img src=PRIVATE>",
        "verified_runs": 0,
        "invalid_runs": 1,
        "ignored_files": 0,
        "ignored_directories": 0,
    }
    html = history.render_history(value)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "<img" not in html and "default-src 'none'" in html
    assert "href=" not in html and "<form" not in html


def test_root_and_output_guards_empty_history_and_marker_conflict(tmp_path):
    root, _ = collection(tmp_path)
    empty = tmp_path / "empty"
    empty.mkdir()
    assert history.history_list(empty)["runs"] == []
    for path in (tmp_path / "missing", root / "one", root / "one" / "report.json"):
        with pytest.raises(ValidationError):
            history.history_list(path)
    for path in (root / "one", root / "batch"):
        with pytest.raises(ValidationError):
            history.export_report(path, output=path / "new.json")
    with pytest.raises(ValidationError):
        history.export_report(root / "one", format="pdf")
    with pytest.raises(ValidationError):
        history.load_saved_run(empty)
    (root / "one" / "batch.json").write_text("{}")
    with pytest.raises(ValidationError):
        history.load_saved_run(root / "one")


def test_root_run_entry_limits_and_aggregate_budget_never_return_partial_catalog(
    tmp_path, monkeypatch
):
    root, _ = collection(tmp_path)
    monkeypatch.setattr(history, "MAX_ROOT_ENTRIES", 2)
    with pytest.raises(ValidationError):
        history.history_list(root)
    monkeypatch.setattr(history, "MAX_ROOT_ENTRIES", 100)
    monkeypatch.setattr(history, "MAX_RUNS", 2)
    with pytest.raises(ValidationError):
        history.history_list(root)
    monkeypatch.setattr(history, "MAX_RUNS", 20)
    monkeypatch.setattr(history, "MAX_READ_BYTES", 1)
    with pytest.raises(ReportReadLimit):
        history.history_list(root)
    monkeypatch.setattr(history, "MAX_READ_BYTES", 128 * 1024 * 1024)
    monkeypatch.setattr(history, "MAX_RUN_ENTRIES", 1)
    assert history.history_list(root)["invalid_runs"] == 3


def test_byte_budget_counts_repeated_reads_and_resets_after_failure(tmp_path):
    path = tmp_path / "report"
    path.write_bytes(b"1234")
    with report_read_budget(8):
        assert read_regular(path, 4) == b"1234"
        assert read_regular(path, 4) == b"1234"
        with pytest.raises(ReportReadLimit):
            read_regular(path, 4)
    assert read_regular(path, 4) == b"1234"
    with report_read_budget(8), report_read_budget(3):
        with pytest.raises(ReportReadLimit):
            read_regular(path, 4)
    with pytest.raises(ValidationError):
        read_regular(path, 3)


def test_links_roots_entries_and_manifests_are_rejected(tmp_path):
    root, _ = collection(tmp_path)
    link = tmp_path / "link"
    try:
        link.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("No symlink support")
    with pytest.raises(ValidationError):
        history.history_list(link)
    (root / "linked-run").symlink_to(root / "one", target_is_directory=True)
    value = history.history_list(root)
    assert value["invalid_runs"] == 1
    assert (
        next(r for r in value["runs"] if r["directory"] == "linked-run")["reason"]
        == "linked_entry_rejected"
    )
    manifest = root / "two" / "manifest.json"
    saved = tmp_path / "saved-marker.json"
    manifest.rename(saved)
    manifest.symlink_to(saved)
    assert history.history_list(root)["invalid_runs"] == 2


def test_real_cli_formats_no_overwrite_source_absence_and_partial_exit(tmp_path):
    root, source = collection(tmp_path)
    source.unlink()
    result = run_cli("history-list", root)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["verified_runs"] == 3
    catalog = root / "catalog.html"
    assert run_cli("history-list", root, "--format", "html", "--output", catalog).returncode == 0
    assert "Local report history" in catalog.read_text()
    assert run_cli("history-list", root, "--output", catalog).returncode == 2
    assert run_cli("history-list", root, "--output", root / "one" / "new.json").returncode == 2
    output = tmp_path / "export.json"
    assert run_cli("report-export", root / "batch", "--output", output).returncode == 0
    assert json.loads(output.read_text())["summary"]["input_reports"] == 1
    assert run_cli("report-export", root / "batch", "--output", output).returncode == 2
    assert run_cli("report-export", root / "one", "--format", "html").returncode == 0
    (root / "two" / "manifest.json").unlink()
    result = run_cli("history-list", root)
    assert result.returncode == 2 and json.loads(result.stdout)["invalid_runs"] == 1
    missing = tmp_path / "missing"
    assert run_cli("history-list", missing).returncode == 2 and not missing.exists()


def test_export_output_bound_and_write_failure_leave_no_completion(tmp_path, monkeypatch):
    root, _ = collection(tmp_path)
    output = tmp_path / "export.json"
    monkeypatch.setattr(history, "MAX_EXPORT_BYTES", 1)
    with pytest.raises(ValidationError):
        history.export_report(root / "one", output=output)
    assert not output.exists()
    monkeypatch.setattr(history, "MAX_EXPORT_BYTES", 8 * 1024 * 1024)
    original = history.os.fdopen

    def fail(*a, **k):
        raise OSError("Injected write failure")

    monkeypatch.setattr(history.os, "fdopen", fail)
    # Test writer directly so verification's fdopen is not intercepted first.
    with pytest.raises(OSError):
        history.write_new_report(output, b"{}")
    assert not output.exists()
    monkeypatch.setattr(history.os, "fdopen", original)


def test_undecodable_directory_names_are_a_readable_error(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX undecodable names only")
    root = tmp_path / "history"
    root.mkdir()
    os.mkdir(os.fsencode(root) + b"/invalid-\xff")
    with pytest.raises(ValidationError, match="UTF-8"):
        history.history_list(root)


@pytest.mark.parametrize("component", ["catalog", "export"])
def test_demo_incomplete_history_or_export_cannot_publish_completion(
    tmp_path, monkeypatch, component
):
    import ai_threat_lab.offline_cli as offline

    if component == "catalog":
        monkeypatch.setattr(
            offline,
            "history_list",
            lambda *a, **k: {"verified_runs": 0, "invalid_runs": 0, "runs": []},
        )
    else:
        monkeypatch.setattr(offline, "export_saved_report", lambda *a, **k: "{}")
    with pytest.raises(ValidationError, match="history acceptance|saved report export"):
        offline.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo" / "demo-result.json").exists()


def test_cli_catalog_output_limit_does_not_publish_a_partial_file(tmp_path, monkeypatch):
    import ai_threat_lab.scan_cli as cli
    from ai_threat_lab.cli import main

    root, _ = collection(tmp_path)
    output = tmp_path / "catalog.json"
    monkeypatch.setattr(cli, "MAX_CATALOG_BYTES", 1)
    assert main(["history-list", str(root), "--output", str(output)]) == 2
    assert not output.exists()
