"""Multi-target offline scans, verified derivation, publication and real CLI failures."""

import json
import socket
from pathlib import Path

import pytest
from test_cli_process import run_cli

from ai_threat_lab.acceptance_samples import synthetic_message
from ai_threat_lab.batch_scan import check_batch, run_batch
from ai_threat_lab.cli import main
from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scan_engine import ScanService


@pytest.fixture
def targets(tmp_path):
    source = tmp_path / "private source.py"
    source.write_text("eval(private_argument)")
    mail = tmp_path / "mail.eml"
    mail.write_bytes(synthetic_message())
    return [str(source), str(mail)]


def test_multiple_routes_source_free_reports_and_deleted_targets(targets, tmp_path, monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("Batch must remain offline")

    monkeypatch.setattr(socket, "create_connection", deny)
    root = tmp_path / "batch"
    summary = run_batch(targets, root)
    assert summary["target_count"] == 2 and summary["unique_findings"] == 6
    assert summary["failed_runs"] == [] and summary["ai_calls"] == 0
    assert not summary["network_called"]
    report = (root / "report.json").read_text()
    assert "private_argument" not in report and "fictional-report.pdf.exe" not in report
    assert len(json.loads(report)["findings"]) == 6
    assert check_batch(root)["assessment_summary"]["unique_findings"] == 6
    for source in targets:
        Path(source).unlink()
    assert check_batch(root)["status"] == "integrity_verified"


@pytest.mark.parametrize(
    "bad",
    [
        [],
        [""],
        [None],
        ["mailbox:owner@example.invalid"],
        ["https://example.invalid"],
        ["https://github.com/owner/repo"],
        ["mail-domain:example.invalid"],
        ["missing-file.py"],
        ["bad\npath"],
    ],
)
def test_invalid_targets_never_claim_output(tmp_path, bad):
    output = tmp_path / "absent"
    with pytest.raises(ValidationError):
        run_batch(bad, output)
    assert not output.exists()


def test_target_count_limit_and_exact_ten(tmp_path):
    targets = []
    for number in range(11):
        source = tmp_path / f"source-{number}.py"
        source.write_text("value=1")
        targets.append(str(source))
    with pytest.raises(ValidationError, match="10"):
        run_batch(targets, tmp_path / "over")
    result = run_batch(targets[:10], tmp_path / "ten")
    assert result["target_count"] == 10 and result["unique_findings"] == 0
    assert check_batch(tmp_path / "ten")["status"] == "integrity_verified"


def test_duplicate_overlap_output_inside_project_and_boolean_option(tmp_path, targets):
    for selected in (
        [targets[0], targets[0]],
        [str(tmp_path), targets[0]],
        [targets[0], str(tmp_path)],
    ):
        with pytest.raises(ValidationError, match="distinct"):
            run_batch(selected, tmp_path.parent / "unused-batch-destination")
    with pytest.raises(ValidationError, match="outside"):
        run_batch([str(tmp_path)], tmp_path / "inside")
    with pytest.raises(ValidationError, match="boolean"):
        run_batch(targets, tmp_path / "bad-option", recursive_dependencies=1)


def test_project_recursive_scope_applies_only_to_directories(tmp_path, targets):
    project = tmp_path / "project"
    (project / "nested").mkdir(parents=True)
    (project / "nested" / "requirements.txt").write_text("fixture==1.2.3")
    root = tmp_path / "recursive"
    run_batch([str(project), targets[1]], root, recursive_dependencies=True)
    inventory = json.loads((root / "run-01" / "dependency-inventory.json").read_text())
    assert inventory["packages"][0]["sources"] == ["nested/requirements.txt:1"]
    assert check_batch(root)["status"] == "integrity_verified"


def test_module_failure_keeps_other_targets_and_is_not_a_clean_result(tmp_path, targets):
    def selected(options):
        if options.target == str(Path(targets[0]).resolve()):
            raise RuntimeError("PRIVATE provider failure")
        return local_inventory(options.target)

    root = tmp_path / "partial"
    summary = run_batch(targets, root, service=ScanService(selected))
    assert summary["failed_runs"] == ["run-01"]
    assert summary["unique_findings"] == 5 and summary["status"] == "partial_with_module_failures"
    assert "PRIVATE" not in (root / "report.json").read_text()
    checked = check_batch(root)
    assert checked["assessment_summary"]["failed_runs"] == ["run-01"]


def test_existing_directory_is_never_overwritten(tmp_path, targets):
    root = tmp_path / "existing"
    root.mkdir()
    marker = root / "keep.txt"
    marker.write_text("original")
    with pytest.raises(FileExistsError):
        run_batch(targets, root)
    assert marker.read_text() == "original" and list(root.iterdir()) == [marker]


def test_interrupted_scan_leaves_no_completion_marker(tmp_path, targets):
    class Interrupted:
        def run(self, *args, **kwargs):
            raise KeyboardInterrupt

    root = tmp_path / "interrupted"
    with pytest.raises(KeyboardInterrupt):
        run_batch(targets, root, service=Interrupted())
    assert root.is_dir() and not (root / "batch.json").exists()
    with pytest.raises(ValidationError):
        check_batch(root)


@pytest.mark.parametrize(
    "name", ["report.json", "report.html", "run-01/report.json", "run-02/manifest.json"]
)
def test_artifact_tampering_is_rejected(tmp_path, targets, name):
    root = tmp_path / "tampered"
    run_batch(targets, root)
    (root / name).write_bytes(b"changed")
    with pytest.raises(ValidationError):
        check_batch(root)


@pytest.mark.parametrize(
    "change",
    [
        "schema",
        "mode",
        "options",
        "path",
        "target",
        "hash",
        "summary",
        "summary_type",
        "count",
        "extra",
        "missing",
    ],
)
def test_invalid_marker_and_unindexed_entries_are_rejected(tmp_path, targets, change):
    root = tmp_path / "bad-index"
    run_batch(targets, root)
    path = root / "batch.json"
    document = json.loads(path.read_text())
    if change == "schema":
        document["schema_version"] = True
    elif change == "mode":
        document["mode"] = "online"
    elif change == "options":
        document["recursive_dependencies"] = 1
    elif change == "path":
        document["runs"][0]["directory"] = "../outside"
    elif change == "target":
        document["runs"][0]["target"] = "https://example.invalid"
    elif change == "hash":
        document["runs"][0]["manifest_sha256"] = "a" * 64
    elif change == "summary":
        document["summary"]["unique_findings"] = 0
    elif change == "summary_type":
        document["summary"]["network_called"] = 0
    elif change == "count":
        document["runs"] = []
    elif change == "extra":
        (root / "unexpected.txt").write_text("extra")
    elif change == "missing":
        (root / "report.html").unlink()
    path.write_text(json.dumps(document))
    with pytest.raises((ValidationError, OSError)):
        check_batch(root)


def test_report_derivation_is_checked_even_if_hashes_are_recomputed(tmp_path, targets):
    import hashlib

    root = tmp_path / "forged-report"
    run_batch(targets, root)
    raw = b"{}\n"
    (root / "report.json").write_bytes(raw)
    marker = json.loads((root / "batch.json").read_text())
    marker["files"]["report.json"] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    (root / "batch.json").write_text(json.dumps(marker))
    with pytest.raises(ValidationError, match="derivation"):
        check_batch(root)


def test_byte_limits_stop_publication_and_checker_bounds_reads(tmp_path, targets, monkeypatch):
    import ai_threat_lab.batch_scan as module

    root = tmp_path / "report-limit"
    monkeypatch.setattr(module, "MAX_REPORT_BYTES", 1)
    with pytest.raises(ValidationError, match="8 MiB"):
        run_batch(targets, root)
    assert not (root / "batch.json").exists()
    monkeypatch.setattr(module, "MAX_REPORT_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(module, "MAX_CHILD_BYTES", 1)
    with pytest.raises(ValidationError, match="64 MiB"):
        run_batch(targets, tmp_path / "child-limit")
    monkeypatch.setattr(module, "MAX_CHILD_BYTES", 64 * 1024 * 1024)
    valid = tmp_path / "valid"
    run_batch(targets, valid)
    monkeypatch.setattr(module, "MAX_REPORT_BYTES", 1)
    with pytest.raises(ValidationError, match="byte limit"):
        check_batch(valid)


def test_symlink_roots_children_artifacts_and_targets_are_rejected(tmp_path, targets):
    source = Path(targets[0])
    link = tmp_path / "linked.py"
    try:
        link.symlink_to(source)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation unavailable")
    with pytest.raises(ValidationError, match="without links"):
        run_batch([str(link)], tmp_path / "bad-target")
    root = tmp_path / "batch"
    run_batch(targets, root)
    root_link = tmp_path / "batch-link"
    root_link.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValidationError, match="without links"):
        check_batch(root_link)
    report = root / "report.html"
    saved = tmp_path / "saved-report"
    report.rename(saved)
    report.symlink_to(saved)
    with pytest.raises(ValidationError, match="without links"):
        check_batch(root)


def test_real_cli_exit_codes_and_check_file_output(tmp_path, targets):
    root = tmp_path / "real batch"
    result = run_cli("scan-batch", *targets, "--output-dir", root, "--fail-on-findings")
    assert result.returncode == 1 and not result.stderr
    assert json.loads(result.stdout)["unique_findings"] == 6
    checked = run_cli("batch-check", root)
    assert checked.returncode == 0 and json.loads(checked.stdout)["status"] == "integrity_verified"
    saved = tmp_path / "checked.json"
    assert main(["batch-check", str(root), "--output", str(saved)]) == 0
    original = saved.read_bytes()
    assert main(["batch-check", str(root), "--output", str(saved)]) == 2
    assert saved.read_bytes() == original
    assert run_cli("scan-batch", *targets, "--output-dir", root).returncode == 2
    assert (
        run_cli("scan-batch", *targets, "--output-dir", tmp_path / "x", "--network").returncode == 2
    )


def test_failed_module_exit_three_takes_precedence_over_findings(
    tmp_path, targets, monkeypatch, capsys
):
    import ai_threat_lab.batch_scan as module

    original = module.local_inventory

    def fail_one(target):
        if target == str(Path(targets[0]).resolve()):
            raise RuntimeError("PRIVATE")
        return original(target)

    monkeypatch.setattr(module, "local_inventory", fail_one)
    assert (
        main(
            [
                "scan-batch",
                *targets,
                "--output-dir",
                str(tmp_path / "partial-cli"),
                "--fail-on-findings",
            ]
        )
        == 3
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["failed_runs"] == ["run-01"] and payload["unique_findings"] == 5


def test_reindexed_child_cannot_change_offline_scope(tmp_path, targets):
    import hashlib

    from ai_threat_lab.scan_bundle import scope_digest

    root = tmp_path / "scope-tamper"
    run_batch(targets, root)
    child_path = root / "run-01" / "manifest.json"
    child = json.loads(child_path.read_text())
    child["scope"]["network"] = True
    child["scope_digest"] = scope_digest(child["scope"])
    raw = (json.dumps(child) + "\n").encode()
    child_path.write_bytes(raw)
    marker_path = root / "batch.json"
    marker = json.loads(marker_path.read_text())
    marker["runs"][0]["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    marker_path.write_text(json.dumps(marker))
    with pytest.raises(ValidationError, match="scope mismatch"):
        check_batch(root)


def test_clean_real_batch_still_reports_partial_coverage(tmp_path):
    source = tmp_path / "clean.py"
    source.write_text("value=1")
    root = tmp_path / "clean-batch"
    result = run_cli("scan-batch", source, "--output-dir", root, "--fail-on-findings")
    assert result.returncode == 0 and not result.stderr
    summary = json.loads(result.stdout)
    assert summary["unique_findings"] == 0 and summary["status"] == "partial"
    report = json.loads((root / "report.json").read_text())
    assert report["not_checked"] and "complete security audit" in report["notice"]
