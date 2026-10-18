"""Opted-in nested manifest scope, bounded discovery, provenance and installed CLI paths."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_cli_process import run_cli
from test_remote_audit import QueueHTTP, blob, repository

import ai_threat_lab.dependencies as deps
import ai_threat_lab.dependency_paths as paths
import ai_threat_lab.remote_audit as remote
import ai_threat_lab.scan_cli as scan_cli
from ai_threat_lab.cli import main
from ai_threat_lab.dependencies import inventory, inventory_sources
from ai_threat_lab.models import ValidationError
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import (
    compare_bundles,
    publish_bundle,
    read_bundle,
    scope_digest,
    validate_manifest,
)
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService

TARGET = "https://github.com/owner/repo"


def write(root, name, text="fixture==1.0\n"):
    file = root / name
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(text, encoding="utf-8")
    return file


def remote_snapshot(*names, recursive=True, max_files=50):
    item, payload = blob("fixture==1.0\n")
    entries = [dict(item, path=name) for name in names]
    client = QueueHTTP(*repository(*entries), payload)
    result = GithubAudit(client, max_files=max_files).collect(
        TARGET, include_dependencies=True, recursive_dependencies=recursive
    )
    return result, client


def test_default_root_scope_and_recursive_provenance_merging(tmp_path):
    write(tmp_path, "requirements.txt")
    write(tmp_path, "services/api/requirements.txt")
    write(tmp_path, "services/worker/requirements-dev.txt", "fixture==2.0\n")
    root = inventory(tmp_path)
    assert len(root.packages) == 1 and root.packages[0].sources == ("requirements.txt:1",)
    nested = inventory(tmp_path, recursive=True)
    assert [(p.name, p.version) for p in nested.packages] == [
        ("fixture", "1.0"),
        ("fixture", "2.0"),
    ]
    assert nested.packages[0].sources == ("requirements.txt:1", "services/api/requirements.txt:1")
    assert nested.packages[1].sources == ("services/worker/requirements-dev.txt:1",)
    assert any("Recursive" in n for n in nested.not_checked)


@pytest.mark.parametrize("folder", sorted(paths.EXCLUDED))
def test_build_dependency_vcs_and_environment_dirs_excluded(tmp_path, folder):
    write(tmp_path, folder + "/requirements.txt", "excluded==1.0\n")
    write(tmp_path, "apps/api/requirements.txt")
    assert [p.name for p in inventory(tmp_path, recursive=True).packages] == ["fixture"]


@pytest.mark.parametrize(
    "filename,source,ecosystem",
    [
        ("requirements-dev.txt", "fixture==1.0\n", "PyPI"),
        ("poetry.lock", '[[package]]\nname="fixture"\nversion="1.0"\n', "PyPI"),
        ("uv.lock", '[[package]]\nname="fixture"\nversion="1.0"\n', "PyPI"),
        (
            "package-lock.json",
            '{"lockfileVersion":3,"packages":{"node_modules/fixture":{"version":"1.0"}}}',
            "npm",
        ),
    ],
)
def test_all_existing_formats_accept_relative_labels_without_disk_io(filename, source, ecosystem):
    result = inventory_sources(
        "monorepo", [("packages/app/" + filename, source.encode())], allow_paths=True
    )
    assert result.packages[0].ecosystem == ecosystem
    assert result.packages[0].sources[0].startswith("packages/app/" + filename)


@pytest.mark.parametrize(
    "name",
    [
        "../requirements.txt",
        "/requirements.txt",
        "a/../requirements.txt",
        "a//requirements.txt",
        "a/./requirements.txt",
        "C:/requirements.txt",
        "a\\requirements.txt",
        "requirements.txt/",
        "a\n/requirements.txt",
        "a\x7f/requirements.txt",
        "a/" + "x" * 256,
        "a/" * 513 + "requirements.txt",
    ],
)
def test_malformed_relative_origins_rejected_without_echoing_payload(name):
    with pytest.raises(ValidationError) as error:
        inventory_sources("fixture", [(name, b"SECRET==1.0")], allow_paths=True)
    assert "SECRET" not in str(error.value)


def test_relative_origins_require_optin_and_flags_are_boolean(tmp_path):
    with pytest.raises(ValidationError):
        inventory_sources("fixture", [("app/requirements.txt", b"fixture==1.0")])
    with pytest.raises(ValidationError):
        inventory_sources("fixture", [], allow_paths=1)
    with pytest.raises(ValidationError):
        inventory(tmp_path, recursive=1)
    file = write(tmp_path, "requirements.txt")
    with pytest.raises(ValidationError, match="directory"):
        inventory(file, recursive=True)


def test_discovery_manifest_budget_prioritizes_root_then_shallow_names(tmp_path):
    write(tmp_path, "requirements.txt", "root==1.0\n")
    for index in range(21):
        write(tmp_path, f"p{index:02}/requirements.txt", f"p{index}==1.0\n")
    result = inventory(tmp_path, recursive=True)
    assert len(result.packages) == 20
    assert "root" in {p.name for p in result.packages}
    assert "p19" not in {p.name for p in result.packages}
    assert any("manifest limit" in n for n in result.not_checked)


@pytest.mark.parametrize("bound", ["MAX_DIRECTORIES", "MAX_ENTRIES", "MAX_DEPTH"])
def test_discovery_bounds_record_incomplete_coverage(tmp_path, monkeypatch, bound):
    write(tmp_path, "requirements.txt", "root==1.0\n")
    write(tmp_path, "app/sub/requirements.txt", "nested==1.0\n")
    monkeypatch.setattr(paths, bound, 1 if bound != "MAX_DEPTH" else 0)
    result = inventory(tmp_path, recursive=True)
    assert not any(p.name == "nested" for p in result.packages)
    assert any("limit reached" in n for n in result.not_checked)


def test_symlink_file_directory_and_loop_are_never_followed(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    outside.mkdir()
    write(outside, "requirements.txt", "outside==1.0\n")
    write(root, "requirements.txt")
    try:
        (root / "external").symlink_to(outside, target_is_directory=True)
        (root / "requirements-linked.txt").symlink_to(outside / "requirements.txt")
        (root / "loop").symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("Symlinks unavailable")
    result = inventory(root, recursive=True)
    assert [p.name for p in result.packages] == ["fixture"]
    assert sum("symlink" in n for n in result.not_checked) == 3


def test_directory_enumeration_error_is_redacted_gap(tmp_path, monkeypatch):
    real_scandir = paths.os.scandir
    write(tmp_path, "requirements.txt")
    (tmp_path / "unreadable").mkdir()

    def denied(path):
        if Path(path).name == "unreadable":
            raise PermissionError("SECRET_PATH")
        return real_scandir(path)

    monkeypatch.setattr(paths.os, "scandir", denied)
    result = inventory(tmp_path, recursive=True)
    assert result.packages
    assert any("enumerate" in n for n in result.not_checked)
    assert "SECRET_PATH" not in str(result)


def test_local_and_memory_total_byte_budgets(tmp_path, monkeypatch):
    write(tmp_path, "requirements-a.txt")
    write(tmp_path, "requirements-b.txt")
    monkeypatch.setattr(deps, "MAX_TOTAL_BYTES", 20)
    result = inventory(tmp_path, recursive=True)
    assert len(result.packages[0].sources) == 1
    assert any("total-byte limit" in n for n in result.not_checked)
    with pytest.raises(ValidationError, match="total-byte"):
        inventory_sources(
            "fixture", [("requirements-a.txt", b"a" * 15), ("requirements-b.txt", b"b" * 15)]
        )


def test_recursive_github_pinned_shared_collection_and_scope(tmp_path):
    snapshot, client = remote_snapshot(
        "apps/api/requirements.txt", "requirements.txt", "apps/worker/requirements.txt"
    )
    assert len(client.calls) == 4  # one verified blob reused for three origins
    assert "a" * 40 in client.calls[2][0]
    result = snapshot.inventory()
    assert len(result.packages[0].sources) == 3
    options = ScanOptions(TARGET, True, ("github.com",), recursive_dependencies=True)
    summary = ScanService(lambda _: snapshot).run(options, tmp_path / "run")
    assert not summary["failed_modules"] and summary["ai_calls"] == 0
    bundle = read_bundle(tmp_path / "run")
    assert bundle["manifest"]["scope"]["recursive_dependencies"] is True
    assert len(bundle["documents"]["dependency-inventory.json"]["packages"][0]["sources"]) == 3
    # Do not mislabel root-only snapshot coverage as recursive.
    bad = ScanService(lambda _: replace(snapshot, recursive_dependencies=False)).run(
        options, tmp_path / "bad"
    )
    assert bad["failed_modules"] == ["dependency_inventory"]


def test_github_default_does_not_fetch_nested_requirements():
    item, _ = blob("fixture==1.0")
    client = QueueHTTP(*repository(dict(item, path="apps/api/requirements.txt")))
    snapshot = GithubAudit(client).collect(TARGET, include_dependencies=True)
    assert not snapshot.inventory().packages and len(client.calls) == 3


def test_github_depth_path_exclusions_and_tree_entry_limit(monkeypatch):
    item, data = blob("fixture==1.0\n")
    entries = [
        dict(item, path=name)
        for name in (
            "../requirements.txt",
            "a//requirements.txt",
            "node_modules/requirements.txt",
            "a/" * 9 + "requirements.txt",
            "apps/api/requirements.txt",
        )
    ]
    client = QueueHTTP(*repository(*entries), data)
    result = GithubAudit(client).collect(
        TARGET, include_dependencies=True, recursive_dependencies=True
    )
    assert result.inventory().packages[0].sources == ("apps/api/requirements.txt:1",)
    assert any("path/depth" in n for n in result.assessment.not_checked)
    monkeypatch.setattr(remote, "MAX_ENTRIES", 1)
    client = QueueHTTP(
        *repository(dict(item, path="requirements.txt"), dict(item, path="later/requirements.txt")),
        data,
    )
    result = GithubAudit(client).collect(
        TARGET, include_dependencies=True, recursive_dependencies=True
    )
    assert len(result.manifests) == 1
    assert any("entry inspection limit" in n for n in result.assessment.not_checked)


def test_github_small_shared_file_budget_prefers_root_manifests():
    snapshot, client = remote_snapshot("apps/a/requirements.txt", "requirements.txt", max_files=1)
    assert snapshot.manifests[0][0] == "requirements.txt" and len(client.calls) == 4
    assert any("limit" in n for n in snapshot.inventory().not_checked)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"recursive_dependencies": 1},
        {"recursive_dependencies": True},
    ],
)
def test_invalid_github_recursive_option_before_http(kwargs):
    with pytest.raises(ValidationError):
        GithubAudit(QueueHTTP()).collect(TARGET, **kwargs)


def test_combined_local_recursive_cli_and_scope_changes(tmp_path, capsys):
    root = tmp_path / "project"
    write(root, "apps/api/requirements.txt")
    normal = tmp_path / "normal"
    nested = tmp_path / "nested"
    assert main(["scan", str(root), "--output-dir", str(normal)]) == 0
    capsys.readouterr()
    assert main(["scan", str(root), "--recursive-dependencies", "--output-dir", str(nested)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["modules"]["dependency_inventory"]["status"] == "collected"
    assert result["modules"]["dependency_advisories"]["status"] == "not_requested"
    comparison = compare_bundles(read_bundle(normal), read_bundle(nested))
    assert not comparison["comparable"] and comparison["reason"] == "scope_or_options_changed"


def test_recursive_github_cli_to_osv_dedup_wire(tmp_path, capsys, monkeypatch):
    item, payload = blob("fixture==1.0\n")
    github = QueueHTTP(
        *repository(
            dict(item, path="requirements.txt"), dict(item, path="apps/api/requirements.txt")
        ),
        payload,
    )
    osv = QueueHTTP({"results": [{}]})
    monkeypatch.setattr(
        scan_cli, "PublicHTTPS", lambda hosts, **kw: github if hosts == ["api.github.com"] else osv
    )
    assert (
        main(
            [
                "scan",
                TARGET,
                "--network",
                "--allow-host",
                "github.com",
                "--recursive-dependencies",
                "--share-packages",
                "--output-dir",
                str(tmp_path / "run"),
            ]
        )
        == 0
    )
    assert not json.loads(capsys.readouterr().out)["failed_modules"]
    body = json.loads(osv.calls[0][1]["body"])
    assert len(body["queries"]) == 1  # same version across two subprojects = one advisory query
    assert body["queries"][0]["package"]["name"] == "fixture"


@pytest.mark.parametrize(
    "engine", ["read-only-pipeline-1", "read-only-pipeline-2", "read-only-pipeline-3"]
)
def test_legacy_engines_read_without_new_field_and_disable_comparison(tmp_path, engine):
    root = tmp_path / "project"
    root.mkdir()
    ScanService(assessor).run(ScanOptions(str(root)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": engine}
    metadata["scope"].pop("recursive_dependencies")
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "legacy", artifacts, metadata)
    old = read_bundle(tmp_path / "legacy")
    assert not compare_bundles(old, current)["comparable"]
    metadata["scope"]["recursive_dependencies"] = False
    with pytest.raises(ValidationError, match="Legacy"):
        validate_manifest(metadata)


@pytest.mark.parametrize("value", [None, 1, "yes"])
def test_new_bundle_recursive_flag_is_strict_bool(tmp_path, value):
    root = tmp_path / "project"
    root.mkdir()
    ScanService(assessor).run(ScanOptions(str(root)), tmp_path / "run")
    data = read_bundle(tmp_path / "run")["manifest"]
    data["scope"]["recursive_dependencies"] = value
    with pytest.raises(ValidationError):
        validate_manifest(data)


def test_recursive_scope_unsupported_target_rejected(tmp_path):
    file = write(tmp_path, "requirements.txt")
    with pytest.raises(ValidationError):
        ScanOptions(str(file), recursive_dependencies=True)
    with pytest.raises(ValidationError):
        ScanOptions(str(tmp_path), recursive_dependencies=1)
    with pytest.raises(ValidationError):
        ScanOptions("https://example.com", True, ("example.com",), recursive_dependencies=True)


def test_real_cli_nested_unicode_paths_and_no_network_optin(tmp_path):
    root = tmp_path / "project space"
    write(root, "usługi/api/requirements.txt")
    result = run_cli("audit-deps", root, "--recursive-dependencies")
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["packages"][0]["sources"] == ["usługi/api/requirements.txt:1"]
    result = run_cli("scan", root, "--recursive-dependencies", "--output-dir", tmp_path / "run")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["ai_calls"] == 0
    assert (
        run_cli(
            "audit-deps", root / "usługi/api/requirements.txt", "--recursive-dependencies"
        ).returncode
        == 2
    )
    assert (
        run_cli(
            "scan", TARGET, "--recursive-dependencies", "--output-dir", tmp_path / "remote"
        ).returncode
        == 2
    )


def test_junction_guard_and_post_discovery_nonfile_are_not_read(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.setattr(Path, "is_junction", lambda path: path == root, raising=False)
    with pytest.raises(ValidationError, match="junction"):
        inventory(root, recursive=True)
    with pytest.raises(ValidationError, match="junction"):
        ScanOptions(str(root), recursive_dependencies=True)
    monkeypatch.setattr(Path, "is_junction", lambda path: False, raising=False)
    missing = root / "requirements.txt"
    monkeypatch.setattr(deps, "discover_manifests", lambda *a, **k: ([(missing, missing.name)], []))
    result = inventory(root, recursive=True)
    assert not result.packages and any("non-file" in n for n in result.not_checked)


def test_stat_error_and_many_link_notices_are_bounded(tmp_path, monkeypatch):
    real_linked = paths.linked
    write(tmp_path, "requirements.txt")

    def fail_stat(path):
        if path.name == "requirements.txt":
            raise OSError("SECRET")
        return real_linked(path)

    monkeypatch.setattr(paths, "linked", fail_stat)
    result = inventory(tmp_path, recursive=True)
    assert not result.packages and "SECRET" not in str(result)
    assert any("inspect" in n for n in result.not_checked)
    for index in range(95):
        write(tmp_path, f"f{index:02}.txt", "not a manifest")
    monkeypatch.setattr(paths, "linked", lambda path: path != tmp_path)
    _, notices = paths.discover_manifests(tmp_path, recursive=True)
    assert len(notices) == 91 and "omitted discovery notices" in notices[-1]


def test_special_manifest_file_is_not_opened(tmp_path):
    import os

    if not hasattr(os, "mkfifo"):
        pytest.skip("No FIFO support")
    os.mkfifo(tmp_path / "requirements.txt")
    result = inventory(tmp_path, recursive=True)
    assert not result.packages
    assert any("non-regular" in n for n in result.not_checked)


def test_recursive_parse_failure_preserves_source_report_and_redacts_raw(tmp_path):
    root = tmp_path / "project"
    write(root, "app.py", "eval(value)\n")
    write(root, "nested/package-lock.json", '{"SECRET": malformed}')
    summary = ScanService(assessor).run(
        ScanOptions(str(root), recursive_dependencies=True), tmp_path / "run"
    )
    assert summary["failed_modules"] == ["dependency_inventory"]
    assert summary["unique_findings"] == 1
    assert "SECRET" not in json.dumps(read_bundle(tmp_path / "run"))


def test_missing_recursive_field_rejected_in_current_bundle(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    ScanService(assessor).run(ScanOptions(str(root)), tmp_path / "run")
    data = read_bundle(tmp_path / "run")["manifest"]
    data["scope"].pop("recursive_dependencies")
    with pytest.raises(ValidationError, match="recursive"):
        validate_manifest(data)
