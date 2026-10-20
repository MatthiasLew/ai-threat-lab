"""Composer/NuGet lockfile identity controls without either runtime or package restore."""

import json
import socket

import pytest
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.dependencies import Dependency, OSVAudit, inventory, inventory_sources
from ai_threat_lab.models import ValidationError
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import read_bundle
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService


def composer(version="v1.2.3"):
    return {"packages": [{"name": "fixture/library", "version": version}],
            "packages-dev": [{"name": "fixture/testing", "version": "2.0.0-rc.1"}]}


def nuget(version="1.2.3"):
    return {"version": 2, "dependencies": {"net8.0": {
        "Fixture.Library": {"type": "Direct", "requested": "[1.0.0, )", "resolved": version},
        "Fixture.Child": {"type": "Transitive", "resolved": "2.0.0"},
        "PRIVATE-PROJECT": {"type": "Project"},
    }}}


def parse(name, document):
    return inventory_sources("fixture", [(name, json.dumps(document).encode())])


def test_composer_production_development_and_preserved_tag():
    result = parse("composer.lock", composer())
    assert [(p.ecosystem, p.name, p.version) for p in result.packages] == [
        ("Packagist", "fixture/library", "v1.2.3"),
        ("Packagist", "fixture/testing", "2.0.0-rc.1"),
    ]
    assert result.packages[0].sources == ("composer.lock",)
    assert any("provenance" in note for note in result.not_checked)


def test_nuget_resolved_versions_and_framework_identity_merge():
    value = nuget()
    value["dependencies"]["net9.0"] = value["dependencies"]["net8.0"]
    result = parse("packages.lock.json", value)
    assert [(p.name, p.version) for p in result.packages] == [
        ("Fixture.Child", "2.0.0"), ("Fixture.Library", "1.2.3"),
    ]
    assert "PRIVATE-PROJECT" not in str(result)
    assert any("Requested ranges" in note for note in result.not_checked)


@pytest.mark.parametrize("version", ["dev-main", "v1.x-dev", "1.2.3-dev", "^1.2", "*", "1.*",
                                     "PRIVATE", "1.2.3\n", "1.2.3-rc..1"])
def test_non_exact_composer_versions_are_omitted(version):
    result = parse("composer.lock", {"packages": [{"name": "private/name", "version": version}]})
    assert not result.packages and "private/name" not in str(result)


@pytest.mark.parametrize("version", ["[1.0,2.0)", "1.*", "*", "v1.2.3", "1.2.3\n", None])
def test_nuget_ranges_not_used_as_resolved_versions(version):
    result = parse("packages.lock.json", nuget(version))
    assert [p.name for p in result.packages] == ["Fixture.Child"]


@pytest.mark.parametrize("name,value", [
    ("composer.lock", []), ("composer.lock", {}), ("composer.lock", {"packages": [None]}),
    ("composer.lock", {"packages": [], "packages-dev": {}}),
    ("composer.lock", {"packages": [{"dist": "PRIVATE"}]}),
    ("packages.lock.json", {"version": True, "dependencies": {}}),
    ("packages.lock.json", {"version": 3, "dependencies": {}}),
    ("packages.lock.json", {"version": 1, "dependencies": []}),
    ("packages.lock.json", {"version": 1, "dependencies": {"net": []}}),
    ("packages.lock.json", {"version": 1, "dependencies": {"net": {"x": None}}}),
])
def test_malformed_documents_fail_without_values(name, value):
    with pytest.raises(ValidationError) as error:
        parse(name, value)
    assert "PRIVATE" not in str(error.value)


def test_composer_local_path_and_long_notice_lists():
    value = {"packages": [{"name": "private/local", "version": "1.2.3",
                           "dist": {"type": "path"}}] * 1000}
    result = parse("composer.lock", value)
    assert not result.packages and "private/local" not in str(result)
    assert len(result.not_checked) <= 101
    assert any("provenance" in note for note in result.not_checked)
    value["packages"] *= 3
    with pytest.raises(ValidationError):
        parse("composer.lock", value)


def test_nuget_framework_and_row_bounds():
    with pytest.raises(ValidationError):
        parse("packages.lock.json", {"version": 1, "dependencies": {
            f"net{i}": {} for i in range(65)}})
    with pytest.raises(ValidationError):
        parse("packages.lock.json", {"version": 1, "dependencies": {
            "net": {f"private{i}": {"type": "Project"} for i in range(5001)}}})


@pytest.mark.parametrize("ecosystem,name,version", [
    ("Packagist", "missingvendor", "1.2.3"), ("Packagist", "Vendor/name", "1.2.3"),
    ("Packagist", "fixture/name", "dev-main"), ("NuGet", "../bad", "1.2.3"),
    ("NuGet", "Fixture.Library", "[1,2)"),
])
def test_dependency_contract_cannot_bypass_version_or_name_checks(ecosystem, name, version):
    with pytest.raises(ValidationError):
        Dependency(ecosystem, name, version, ())


def test_local_nested_and_standalone_inventory_without_network(tmp_path, monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("network"))
    root = tmp_path / "project"
    root.mkdir()
    (root / "composer.lock").write_text(json.dumps(composer()))
    nested = root / "service"
    nested.mkdir()
    (nested / "packages.lock.json").write_text(json.dumps(nuget()))
    assert len(inventory(root).packages) == 2
    assert len(inventory(root, recursive=True).packages) == 4
    assert len(inventory(nested / "packages.lock.json").packages) == 2
    summary = ScanService(assessor).run(
        ScanOptions(str(root), recursive_dependencies=True), tmp_path / "scan")
    assert not summary["failed_modules"]
    loaded = read_bundle(tmp_path / "scan")
    assert len(loaded["documents"]["dependency-inventory.json"]["packages"]) == 4


@pytest.mark.parametrize("name,value,ecosystem", [
    ("composer.lock", composer(), "Packagist"),
    ("packages.lock.json", nuget(), "NuGet"),
])
def test_shared_github_blob_and_osv_query(name, value, ecosystem):
    item, data = blob(json.dumps(value))
    item["path"] = f"service/{name}"
    client = QueueHTTP(*repository(item), data)
    snapshot = GithubAudit(client).collect(
        "https://github.com/owner/repo", include_dependencies=True, recursive_dependencies=True)
    result = snapshot.inventory()
    assert len(client.calls) == 4
    assert all(p.ecosystem == ecosystem for p in result.packages)
    assert all(p.sources == (f"service/{name}",) for p in result.packages)
    wire = QueueHTTP({"results": [{"vulns": [{"id": "GHSA-fixture"}]}, {}]})
    report = OSVAudit(wire).assess(result)
    assert report["findings"]
    payload = json.loads(wire.calls[0][1]["body"])
    assert payload["queries"] == [p.query() for p in result.packages]


def test_duplicate_json_keys_rejected():
    with pytest.raises(ValidationError):
        inventory_sources("fixture", [("composer.lock", b'{"packages":[],"packages":[]}')])


@pytest.mark.parametrize("old_engine", [26, 27])
def test_older_bundle_stays_readable_without_cross_engine_delta(tmp_path, old_engine):
    from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, scope_digest

    root = tmp_path / "source"
    root.mkdir()
    (root / "requirements.txt").write_text("fixture==1.0\n")
    ScanService(assessor).run(ScanOptions(str(root)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    assert current["manifest"]["scope"]["engine"] == "read-only-pipeline-28"
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": f"read-only-pipeline-{old_engine}"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    comparison = compare_bundles(read_bundle(tmp_path / "old"), current)
    assert not comparison["comparable"] and comparison["counts"] is None
