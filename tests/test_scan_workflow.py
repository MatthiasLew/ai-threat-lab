import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import ai_threat_lab.scan_cli as scan_cli
from ai_threat_lab.assessment import AssessmentResult
from ai_threat_lab.cli import main
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scan_bundle import compare_bundles, read_bundle
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService


def project(tmp_path):
    folder = tmp_path / "project"
    folder.mkdir()
    (folder / "code.py").write_text("eval(untrusted)\n")
    (folder / "requirements.txt").write_text("fixture==1.2.3\n")
    return folder


def service(**kwargs):
    return ScanService(assessor, **kwargs)


def test_offline_single_command_bundle_and_observation_comparison(tmp_path):
    root = project(tmp_path)
    options = ScanOptions(str(root))
    first = service().run(options, tmp_path / "first")
    assert first["unique_findings"] == 1 and first["ai_calls"] == 0
    before = read_bundle(tmp_path / "first")
    assert before["documents"]["modules.json"]["dependency_advisories"]["status"] == "not_requested"
    assert before["documents"]["dependencies.json"]["status"] == "not_configured"
    assert before["documents"]["dependency-inventory.json"]["packages"][0]["name"] == "fixture"
    assert "no osv query" in (tmp_path / "first" / "report.html").read_text().lower()
    (root / "code.py").write_text("value=1\n")
    service().run(options, tmp_path / "second", baseline=tmp_path / "first")
    after = read_bundle(tmp_path / "second")
    delta = after["documents"]["comparison.json"]
    assert delta["comparable"] and len(delta["no_longer_observed"]) == 1
    assert not delta["new_observations"] and "not proof" in delta["notice"]
    assert compare_bundles(before, after) == delta
    if os.name != "nt":
        assert (tmp_path / "first").stat().st_mode & 0o777 == 0o700


def test_persistent_new_and_same_observations(tmp_path):
    root = project(tmp_path)
    options = ScanOptions(str(root))
    for name in ("first", "same"):
        service().run(options, tmp_path / name)
    same = compare_bundles(read_bundle(tmp_path / "first"), read_bundle(tmp_path / "same"))
    assert len(same["still_observed"]) == 1
    (root / "new.py").write_text("eval(other)\n")
    service().run(options, tmp_path / "new")
    added = compare_bundles(read_bundle(tmp_path / "same"), read_bundle(tmp_path / "new"))
    assert len(added["new_observations"]) == 1 and not added["no_longer_observed"]


def test_inventory_error_preserves_source_and_redacts_exception(tmp_path):
    root = project(tmp_path)

    def broken(_):
        raise RuntimeError("SECRET_PROVIDER_PAYLOAD")

    result = service(inventory_loader=broken).run(ScanOptions(str(root)), tmp_path / "run")
    assert result["failed_modules"] == ["dependency_inventory"]
    bundle = read_bundle(tmp_path / "run")
    assert bundle["documents"]["report.json"]["summary"]["unique_findings"] == 1
    assert "SECRET" not in json.dumps(bundle)
    assert "dependency-inventory.json" not in bundle["documents"]


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError("SECRET"),
        None,
        AssessmentResult("different", "local_project", "partial", (), ("gap",)),
    ],
)
def test_source_failure_still_preserves_dependency_inventory(tmp_path, failure):
    root = project(tmp_path)

    def broken(_):
        if isinstance(failure, Exception):
            raise failure
        return failure

    result = ScanService(broken).run(ScanOptions(str(root)), tmp_path / "run")
    assert "target_assessment" in result["failed_modules"]
    bundle = read_bundle(tmp_path / "run")
    assert bundle["documents"]["assessment.json"]["status"] == "not_configured"
    assert bundle["documents"]["dependency-inventory.json"]["packages"]
    assert "SECRET" not in json.dumps(bundle)


def test_unavailable_result_is_not_a_successful_collector(tmp_path):
    root = project(tmp_path)
    options = ScanOptions(str(root))

    def unavailable(o):
        return AssessmentResult(o.target, "local_project", "not_configured", (), ("gap",))

    assert ScanService(unavailable).run(options, tmp_path / "run")["failed_modules"] == [
        "target_assessment"
    ]


def test_osv_lookup_wired_only_with_explicit_sharing(tmp_path):
    root = project(tmp_path)
    calls = []

    def lookup(collected, options):
        calls.append(collected)
        return {
            "target": options.target,
            "target_kind": "dependency_manifest",
            "status": "partial",
            "findings": [
                {
                    "check": "known_dependency_advisory",
                    "status": "candidate",
                    "evidence": "fixture@1.2.3: OSV-FIXTURE",
                    "recommendation": "Review applicability",
                }
            ],
            "not_checked": ["Version match only"],
        }

    engine = service(advisory_lookup=lookup)
    engine.run(ScanOptions(str(root)), tmp_path / "offline")
    assert not calls
    result = engine.run(
        ScanOptions(str(root), network=True, share_packages=True), tmp_path / "online"
    )
    assert len(calls) == 1 and result["unique_findings"] == 2
    assert result["modules"]["dependency_advisories"]["status"] == "partial"


@pytest.mark.parametrize(
    "result",
    [
        None,
        {},
        {"target": "wrong"},
        {
            "target": "different",
            "target_kind": "dependency_manifest",
            "status": "partial",
            "findings": [],
            "not_checked": [],
        },
    ],
)
def test_invalid_advisory_output_is_replaced_with_failed_placeholder(tmp_path, result):
    root = project(tmp_path)
    summary = service(advisory_lookup=lambda *a: result).run(
        ScanOptions(str(root), network=True, share_packages=True), tmp_path / "run"
    )
    assert summary["failed_modules"] == ["dependency_advisories"]
    bundle = read_bundle(tmp_path / "run")
    assert bundle["documents"]["dependencies.json"]["status"] == "not_configured"


def test_missing_advisory_or_provider_exception_is_not_a_clean_report(tmp_path):
    root = project(tmp_path)
    options = ScanOptions(str(root), network=True, share_packages=True)
    assert service().run(options, tmp_path / "none")["failed_modules"] == ["dependency_advisories"]

    def broken(*args):
        raise TimeoutError("SECRET")

    result = service(advisory_lookup=broken).run(options, tmp_path / "broken")
    assert result["failed_modules"] == ["dependency_advisories"]
    assert "SECRET" not in json.dumps(read_bundle(tmp_path / "broken"))


def test_empty_inventory_and_nonproject_targets(tmp_path):
    root = project(tmp_path)
    (root / "requirements.txt").unlink()
    summary = service(advisory_lookup=lambda *a: pytest.fail("No packages to share")).run(
        ScanOptions(str(root), network=True, share_packages=True), tmp_path / "empty"
    )
    assert summary["modules"]["dependency_inventory"]["status"] == "empty_inventory"
    service().run(ScanOptions(str(root / "code.py")), tmp_path / "file")
    bundle = read_bundle(tmp_path / "file")
    assert "dependencies.json" not in bundle["documents"]
    assert bundle["documents"]["modules.json"]["dependency_inventory"]["status"] == "not_applicable"


@pytest.mark.parametrize(
    "change",
    [
        {"network": 1},
        {"share_packages": 1},
        {"max_files": True},
        {"max_files": 10001},
        {"max_pages": 0},
        {"max_pages": 21},
        {"allowed_hosts": "example.com"},
        {"allowed_hosts": [None]},
        {"allowed_hosts": ["*.example.com"]},
        {"allowed_hosts": [" x "]},
        {"share_packages": True},
        {"advisory_cache": Path("cache.sqlite")},
        {"dkim_selector": "selector"},
    ],
)
def test_options_rejected_before_collection(tmp_path, change):
    root = project(tmp_path)
    with pytest.raises(ValidationError):
        ScanOptions(str(root), **change)


@pytest.mark.parametrize(
    "target,change",
    [
        ("https://example.com", {}),
        ("https://example.com", {"network": True}),
        ("http://example.com", {"network": True, "allowed_hosts": ("example.com",)}),
        ("https://example.com/#x", {"network": True, "allowed_hosts": ("example.com",)}),
        (
            "mail-domain:example.com",
            {"network": True, "allowed_hosts": ("example.com",), "dkim_selector": "bad.selector"},
        ),
        (
            "https://example.com",
            {"network": True, "allowed_hosts": ("example.com",), "share_packages": True},
        ),
    ],
)
def test_remote_scope_optin_and_unsupported_sharing(target, change):
    with pytest.raises(ValidationError):
        ScanOptions(target, **change)


def test_host_normalization_and_local_canonical_path(tmp_path, monkeypatch):
    root = project(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert ScanOptions("project").target == str(root.resolve())
    remote = ScanOptions(
        "https://example.com", network=True, allowed_hosts=("EXAMPLE.COM", "example.com")
    )
    assert remote.allowed_hosts == ("example.com",)


def test_existing_output_and_invalid_baseline_prevent_any_collector_call(tmp_path):
    root = project(tmp_path)
    options = ScanOptions(str(root))
    output = tmp_path / "existing"
    output.mkdir()
    engine = ScanService(lambda *a: pytest.fail("No collection allowed"))
    with pytest.raises(FileExistsError):
        engine.run(options, output)
    with pytest.raises(ValidationError):
        engine.run(options, tmp_path / "new", baseline=output)
    service().run(options, tmp_path / "baseline")
    with pytest.raises(ValidationError, match="inside"):
        engine.run(options, tmp_path / "baseline" / "nested", baseline=tmp_path / "baseline")
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(ValidationError, match="target differs"):
        engine.run(ScanOptions(str(other)), tmp_path / "new", baseline=tmp_path / "baseline")


def test_cache_must_stay_outside_bundle_paths(tmp_path):
    root = project(tmp_path)
    output = tmp_path / "run"
    options = ScanOptions(
        str(root), network=True, share_packages=True, advisory_cache=output / "cache.sqlite"
    )
    with pytest.raises(ValidationError, match="outside"):
        service().run(options, output)
    service().run(ScanOptions(str(root)), tmp_path / "baseline")
    options = replace(options, advisory_cache=tmp_path / "baseline" / "cache.sqlite")
    with pytest.raises(ValidationError):
        service().run(options, output, baseline=tmp_path / "baseline")


def test_scope_changes_and_failed_modules_disable_deltas(tmp_path):
    root = project(tmp_path)
    service().run(ScanOptions(str(root)), tmp_path / "first")
    service().run(ScanOptions(str(root), max_files=10), tmp_path / "changed")
    delta = compare_bundles(read_bundle(tmp_path / "first"), read_bundle(tmp_path / "changed"))
    assert not delta["comparable"] and delta["reason"] == "scope_or_options_changed"
    result = ScanService(lambda *a: None).run(ScanOptions(str(root)), tmp_path / "failed")
    assert result["failed_modules"]
    delta = compare_bundles(read_bundle(tmp_path / "first"), read_bundle(tmp_path / "failed"))
    assert delta["reason"] == "module_failure" and not delta["no_longer_observed"]
    (root / "requirements.txt").unlink()
    service().run(ScanOptions(str(root)), tmp_path / "empty")
    delta = compare_bundles(read_bundle(tmp_path / "first"), read_bundle(tmp_path / "empty"))
    assert delta["reason"] == "module_coverage_changed"


def test_naive_clock_does_not_publish(tmp_path):
    from datetime import datetime

    root = project(tmp_path)
    with pytest.raises(ValidationError):
        service(clock=lambda: datetime(2026, 1, 1)).run(ScanOptions(str(root)), tmp_path / "run")
    assert not (tmp_path / "run").exists()


def test_scan_cli_exit_codes_reports_and_osv_wire(tmp_path, capsys, monkeypatch):
    from test_dependencies import HTTP

    root = project(tmp_path)
    assert (
        main(["scan", str(root), "--output-dir", str(tmp_path / "first"), "--fail-on-findings"])
        == 1
    )
    assert json.loads(capsys.readouterr().out)["unique_findings"] == 1
    assert main(["scan-check", str(tmp_path / "first")]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "integrity_verified"
    client = HTTP({"results": [{}]})
    monkeypatch.setattr(scan_cli, "PublicHTTPS", lambda *a, **k: client)
    assert (
        main(
            [
                "scan",
                str(root),
                "--output-dir",
                str(tmp_path / "online"),
                "--network",
                "--share-packages",
                "--advisory-cache",
                str(tmp_path / "cache.sqlite"),
            ]
        )
        == 0
    )
    assert (
        json.loads(capsys.readouterr().out)["modules"]["dependency_advisories"]["status"]
        == "partial"
    )
    output = tmp_path / "comparison.json"
    assert (
        main(
            [
                "scan-compare",
                str(tmp_path / "first"),
                str(tmp_path / "online"),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert not json.loads(output.read_text())["comparable"]
    assert main(["scan-compare", str(tmp_path / "first"), str(tmp_path / "first")]) == 0
    assert json.loads(capsys.readouterr().out.split("\n", 1)[-1])["comparable"]


def test_cli_partial_failure_returns_integration_error_code_with_bundle(
    tmp_path, capsys, monkeypatch
):
    root = project(tmp_path)
    monkeypatch.setattr(
        scan_cli, "assessor", lambda *a: (_ for _ in ()).throw(RuntimeError("SECRET"))
    )
    output = tmp_path / "failed"
    assert main(["scan", str(root), "--output-dir", str(output)]) == 3
    assert json.loads(capsys.readouterr().out)["status"] == "partial_with_module_failures"
    assert "SECRET" not in json.dumps(read_bundle(output))


def test_actual_scan_cli_process_flow_and_help(tmp_path):
    root = project(tmp_path)
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")

    def run(*args):
        result = subprocess.run(
            [sys.executable, "-m", "ai_threat_lab", *map(str, args)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env,
            timeout=20,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    for command in ("scan", "scan-check", "scan-compare"):
        assert "usage:" in run(command, "--help")
    assert json.loads(run("scan", root, "--output-dir", tmp_path / "first"))["ai_calls"] == 0
    assert json.loads(run("scan-check", tmp_path / "first"))["assessment_status"] == "partial"
    assert json.loads(run("scan-compare", tmp_path / "first", tmp_path / "first"))["comparable"]


def test_root_symlink_and_nonstandard_https_port_rejected(tmp_path):
    root = project(tmp_path)
    link = tmp_path / "linked"
    try:
        link.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ValidationError):
        ScanOptions(str(link))
    with pytest.raises(ValidationError):
        ScanOptions("https://example.com:444", network=True, allowed_hosts=("example.com",))
