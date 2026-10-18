"""Bounded Cargo inventories through local, immutable GitHub and installed CLI routes."""

import json

import pytest
from test_cli_process import run_cli
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.dependencies import MAX_PACKAGES, OSVAudit, inventory, inventory_sources
from ai_threat_lab.models import ValidationError
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import read_bundle
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def cargo(name="fixture-crate", version="1.2.3", source=REGISTRY, lock_version=4):
    entry = f"[[package]]\nname={json.dumps(name)}\nversion={json.dumps(version)}\n"
    if source is not None:
        entry += f"source={json.dumps(source)}\n"
    return f"version={lock_version}\n" + entry


def parse(source):
    return inventory_sources("fixture", [("Cargo.lock", source.encode())])


@pytest.mark.parametrize("version", [3, 4])
def test_registry_entries_exact_versions_origins_and_no_checksum_trust(version):
    result = parse(cargo(lock_version=version))
    assert len(result.packages) == 1
    assert result.packages[0].query() == {
        "package": {"ecosystem": "crates.io", "name": "fixture-crate"},
        "version": "1.2.3",
    }
    assert result.packages[0].sources == ("Cargo.lock",)
    assert any("checksum" in n and "unverified" in n for n in result.not_checked)


@pytest.mark.parametrize("version", ["0.0.0", "1.2.3-alpha.1", "1.2.3+build.01", "1.2.3-1a+ABC"])
def test_supported_exact_semver(version):
    assert parse(cargo(version=version)).packages[0].version == version


@pytest.mark.parametrize(
    "version",
    [
        "v1.2.3",
        "1.2",
        "01.2.3",
        "1.02.3",
        "1.2.03",
        "1.2.3-01",
        "1.2.3-a..b",
        "1.2.3+",
        "1.*",
        "^1.2.3",
        "1.2.3+build..x",
        "",
        True,
        123,
    ],
)
def test_invalid_versions_are_omitted_without_value_disclosure(version):
    result = parse(cargo(version=version))
    assert not result.packages
    assert any("version" in n and "omitted" in n for n in result.not_checked)


@pytest.mark.parametrize(
    "source",
    [
        None,
        "git+https://secret-token@private.invalid/repo#123",
        "registry+https://private.invalid/index",
        "registry+https://github.com/rust-lang/crates.io-index.evil.invalid",
        "sparse+https://index.crates.io/",
    ],
)
def test_unknown_or_non_registry_sources_are_not_mislabeled(source):
    result = parse(cargo(source=source))
    assert not result.packages and any("source" in n for n in result.not_checked)
    assert "secret-token" not in str(result) and "private.invalid" not in str(result)


@pytest.mark.parametrize(
    "source",
    [
        "version=2\npackage=[]",
        "version=true\npackage=[]",
        "version=5\npackage=[]",
        "version=4",
        "version=4\npackage=[1]",
        "version=4\n[[package]]\nsource=7",
        "[[broken",
        "version=4\nversion=4\npackage=[]",
    ],
)
def test_invalid_structure_is_rejected(source):
    with pytest.raises(ValidationError, match="manifest"):
        parse(source)


def test_duplicate_names_versions_and_monorepo_origins(tmp_path):
    (tmp_path / "Cargo.lock").write_text(cargo())
    sub = tmp_path / "member"
    sub.mkdir()
    (sub / "Cargo.lock").write_text(cargo())
    assert inventory(tmp_path).packages[0].sources == ("Cargo.lock",)
    result = inventory(tmp_path, recursive=True)
    assert len(result.packages) == 1
    assert result.packages[0].sources == ("Cargo.lock", "member/Cargo.lock")
    other = cargo(name="fixture_crate").split("\n", 1)[1]
    assert len(parse(cargo() + other).packages) == 2


def test_local_workspace_and_git_skips_do_not_hide_registry_packages():
    result = parse(cargo() + cargo(name="workspace", source=None).split("\n", 1)[1])
    assert [p.name for p in result.packages] == ["fixture-crate"]


def test_package_limit_applies_to_crates():
    source = "version=4\n" + "".join(
        cargo(name=f"fixture-{i}").split("\n", 1)[1] for i in range(MAX_PACKAGES + 1)
    )
    with pytest.raises(ValidationError, match="500"):
        parse(source)


def test_github_nested_shared_commit_and_scan_bundle(tmp_path):
    item, data = blob(cargo())
    item["path"] = "rust/Cargo.lock"
    client = QueueHTTP(*repository(item), data)
    snapshot = GithubAudit(client).collect(
        "https://github.com/owner/repo", include_dependencies=True, recursive_dependencies=True
    )
    assert len(client.calls) == 4
    assert snapshot.inventory().packages[0].sources == ("rust/Cargo.lock",)
    options = ScanOptions(
        "https://github.com/owner/repo",
        network=True,
        allowed_hosts=("github.com",),
        recursive_dependencies=True,
    )
    ScanService(lambda _: snapshot).run(options, tmp_path / "bundle")
    package = read_bundle(tmp_path / "bundle")["documents"]["dependency-inventory.json"][
        "packages"
    ][0]
    assert package["ecosystem"] == "crates.io" and package["sources"] == ["rust/Cargo.lock"]


def test_osv_wire_format_uses_crates_io_and_preserves_version():
    client = QueueHTTP({"results": [{"vulns": [{"id": "RUSTSEC-2026-0001"}]}]})
    result = OSVAudit(client).assess(parse(cargo()))
    assert result["findings"][0]["check"] == "known_dependency_advisory"
    sent = json.loads(client.calls[0][1]["body"])["queries"][0]
    assert sent == {
        "package": {"ecosystem": "crates.io", "name": "fixture-crate"},
        "version": "1.2.3",
    }


def test_real_cli_and_local_scan_are_offline_and_do_not_execute_cargo(tmp_path, monkeypatch):
    (tmp_path / "Cargo.lock").write_text(cargo())
    monkeypatch.setenv("CARGO_HOME", str(tmp_path / "absent-cargo-home"))
    process = run_cli("audit-deps", tmp_path)
    assert process.returncode == 0 and not process.stderr
    assert json.loads(process.stdout)["packages"][0]["ecosystem"] == "crates.io"
    summary = ScanService(assessor).run(ScanOptions(str(tmp_path)), tmp_path / "result")
    assert summary["ai_calls"] == 0 and not summary["failed_modules"]
    assert not (tmp_path / "absent-cargo-home").exists()
