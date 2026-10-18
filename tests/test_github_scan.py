"""Shared immutable GitHub collection, dependency parsing and CLI wiring (no live HTTP)."""

import json

import pytest
from test_remote_audit import QueueHTTP, blob, repository

import ai_threat_lab.scan_cli as scan_cli
from ai_threat_lab.cli import main
from ai_threat_lab.dependencies import inventory_sources
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import compare_bundles, read_bundle
from ai_threat_lab.scan_engine import ScanOptions, ScanService

TARGET = "https://github.com/owner/repo"


def entry(name, source):
    item, data = blob(source)
    return dict(item, path=name), data


def options(**changes):
    return ScanOptions(TARGET, network=True, allowed_hosts=("github.com",), **changes)


def collector(client, **kwargs):
    return GithubAudit(client, **kwargs).collect(TARGET, include_dependencies=True)


def test_shared_commit_manifest_priority_dedup_and_no_raw_artifacts(tmp_path):
    code, code_blob = entry("code.py", "eval(untrusted)\n")
    req, req_blob = entry("requirements.txt", "fixture==1.2.3\n")
    duplicate = dict(req, path="requirements-dev.txt")
    client = QueueHTTP(*repository(code, req, duplicate), req_blob, code_blob)
    snapshot = collector(client)
    assert len(client.calls) == 5  # repo + commit + tree + two distinct blobs
    assert "/git/trees/" + "a" * 40 in client.calls[2][0]
    assert all("/git/blobs/" in url for url, _ in client.calls[3:])
    result = ScanService(lambda _: snapshot).run(options(), tmp_path / "run")
    assert result["failed_modules"] == [] and result["ai_calls"] == 0
    bundle = read_bundle(tmp_path / "run")
    inventory = bundle["documents"]["dependency-inventory.json"]
    assert inventory["target"] == TARGET
    assert inventory["packages"][0]["sources"] == ["requirements-dev.txt:1", "requirements.txt:1"]
    assert any("a" * 40 in note for note in inventory["not_checked"])
    assert "eval(untrusted)" not in json.dumps(bundle)
    assert result["modules"]["dependency_advisories"]["status"] == "not_requested"


@pytest.mark.parametrize(
    "name,source,ecosystem",
    [
        ("requirements.txt", "Flask==3.0.0\n", "PyPI"),
        ("uv.lock", '[[package]]\nname="flask"\nversion="3.0.0"\n', "PyPI"),
        ("poetry.lock", '[[package]]\nname="flask"\nversion="3.0.0"\n', "PyPI"),
        (
            "package-lock.json",
            json.dumps(
                {"lockfileVersion": 3, "packages": {"node_modules/fixture": {"version": "1.2.3"}}}
            ),
            "npm",
        ),
    ],
)
def test_root_manifest_formats(name, source, ecosystem):
    item, data = entry(name, source)
    snapshot = collector(QueueHTTP(*repository(item), data))
    assert snapshot.inventory().packages[0].ecosystem == ecosystem


def test_manifest_budget_has_priority_and_nested_manifests_are_not_inventoried():
    code, _ = entry("code.py", "eval(x)\n")
    root, data = entry("requirements.txt", "fixture==1.0\n")
    nested, _ = entry("nested/requirements.txt", "other==2.0\n")
    client = QueueHTTP(*repository(code, nested, root), data)
    snapshot = collector(client, max_files=1)
    assert len(client.calls) == 4
    assert [p.name for p in snapshot.inventory().packages] == ["fixture"]
    assert any("limit" in n for n in snapshot.inventory().not_checked)
    assert not snapshot.assessment.findings


def test_large_lockfile_and_file_total_byte_limits():
    source = "#" + "x" * (256 * 1024) + "\nfixture==1.0\n"
    item, data = entry("requirements.txt", source)
    snapshot = collector(QueueHTTP(*repository(item), data))
    assert snapshot.inventory().packages[0].name == "fixture"
    assert any("dependencies only" in n for n in snapshot.assessment.not_checked)
    # Three 1.5 MiB files exceed the shared 4 MiB budget, even for cached content.
    item, data = entry("requirements-a.txt", "#" + "x" * (1536 * 1024))
    client = QueueHTTP(
        *repository(
            item, dict(item, path="requirements-b.txt"), dict(item, path="requirements-c.txt")
        ),
        data,
    )
    snapshot = collector(client)
    assert len(snapshot.manifests) == 2 and len(client.calls) == 4
    assert any("total-byte limit" in n for n in snapshot.assessment.not_checked)


def test_manifest_count_truncated_tree_and_oversized_notice():
    item, data = entry("requirements-00.txt", "fixture==1.0\n")
    entries = [dict(item, path=f"requirements-{i:02}.txt") for i in range(21)]
    client = QueueHTTP(*repository(*entries, truncated=True), data)
    snapshot = collector(client)
    assert len(snapshot.manifests) == 20
    assert any("manifest limit" in n for n in snapshot.inventory().not_checked)
    assert any("truncated" in n for n in snapshot.inventory().not_checked)
    item["size"] = 2 * 1024 * 1024 + 1
    client = QueueHTTP(*repository(item))
    assert not collector(client).inventory().packages and len(client.calls) == 3


def test_symlink_submodule_and_nested_manifest_exclusions():
    item, _ = entry("requirements.txt", "fixture==1.0\n")
    entries = [
        dict(item, mode="120000"),
        dict(item, mode="160000", type="commit"),
        dict(item, path="nested/requirements.txt"),
        dict(item, path="../requirements.txt"),
    ]
    client = QueueHTTP(*repository(*entries))
    assert not collector(client).inventory().packages and len(client.calls) == 3


def test_bad_manifest_isolates_failure_and_preserves_code(tmp_path):
    item, data = entry("package-lock.json", '{"SECRET_VALUE": invalid}')
    code, code_data = entry("code.py", "eval(x)\n")
    snapshot = collector(QueueHTTP(*repository(item, code), data, code_data))
    result = ScanService(lambda _: snapshot).run(options(), tmp_path / "run")
    assert result["failed_modules"] == ["dependency_inventory"]
    assert result["unique_findings"] == 1
    assert "SECRET_VALUE" not in json.dumps(read_bundle(tmp_path / "run"))


def test_collection_failure_does_not_refetch_and_fails_both_modules(tmp_path):
    client = QueueHTTP(HttpResponse(403, {}, b"SECRET"))
    result = ScanService(lambda _: collector(client)).run(options(), tmp_path / "run")
    assert result["failed_modules"] == ["target_assessment", "dependency_inventory"]
    assert len(client.calls) == 1
    assert "SECRET" not in json.dumps(read_bundle(tmp_path / "run"))


def test_scan_cli_github_to_osv_explicit_wire_and_cache(tmp_path, monkeypatch, capsys):
    item, data = entry("requirements.txt", "fixture==1.0\n")
    github = QueueHTTP(*repository(item), data)
    osv = QueueHTTP({"results": [{"vulns": [{"id": "OSV-FIXTURE"}]}]})
    hosts = []

    def http(allowed, **kwargs):
        hosts.append(allowed)
        return github if allowed == ["api.github.com"] else osv

    monkeypatch.setattr(scan_cli, "PublicHTTPS", http)
    args = [
        "scan",
        TARGET,
        "--network",
        "--allow-host",
        "github.com",
        "--share-packages",
        "--output-dir",
        str(tmp_path / "run"),
        "--advisory-cache",
        str(tmp_path / "cache"),
    ]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["unique_findings"] == 1
    assert hosts == [["api.github.com"], ["api.osv.dev"]]
    url, request = osv.calls[0]
    assert url == "https://api.osv.dev/v1/querybatch"
    assert json.loads(request["body"]) == {
        "queries": [{"package": {"ecosystem": "PyPI", "name": "fixture"}, "version": "1.0"}]
    }
    assert "Authorization" not in request["headers"]
    bundle = read_bundle(tmp_path / "run")
    assert bundle["documents"]["dependencies.json"]["dependency_audit"]["network_requests"] == 1


def test_engine_change_preserves_old_bundle_reading_but_disables_delta(tmp_path):
    from ai_threat_lab.scan_bundle import encoded, publish_bundle, scope_digest

    snapshot = collector(QueueHTTP(*repository()))
    ScanService(lambda _: snapshot).run(options(), tmp_path / "new")
    new = read_bundle(tmp_path / "new")
    metadata = dict(new["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-1"}
    metadata["scope"].pop("recursive_dependencies", None)
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "new" / name).read_bytes() for name in metadata["files"]}
    # publish_bundle ignores the old file index and derives a fresh one.
    publish_bundle(tmp_path / "old", artifacts, metadata)
    delta = compare_bundles(read_bundle(tmp_path / "old"), new)
    assert not delta["comparable"] and delta["reason"] == "scope_or_options_changed"
    assert encoded(delta)


@pytest.mark.parametrize(
    "sources",
    [
        [("../requirements.txt", b"x")],
        [("a\\b", b"x")],
        [("", b"x")],
        [("requirements.txt", "not bytes")],
        [("requirements.txt", b"x")] * 2,
        [("requirements.txt", b"x")] * 21,
        [("requirements.txt", b"x" * (2 * 1024 * 1024 + 1))],
    ],
)
def test_memory_manifest_bounds(sources):
    with pytest.raises(ValidationError):
        inventory_sources(TARGET, sources)


def test_memory_target_validation():
    with pytest.raises(ValidationError):
        inventory_sources("", [])


@pytest.mark.parametrize("sources", [[None], [("only-name",)], "not-a-list"])
def test_memory_input_structure(sources):
    with pytest.raises(ValidationError):
        inventory_sources(TARGET, sources)


@pytest.mark.parametrize("items", [[None], [{"path": None}]])
def test_malformed_tree_fails_before_blob_request(items):
    from ai_threat_lab.providers import ProviderError

    client = QueueHTTP(*repository(*items))
    with pytest.raises(ProviderError):
        collector(client)
    assert len(client.calls) == 3


def test_duplicate_path_and_cached_size_disagreement():
    from ai_threat_lab.providers import ProviderError

    item, data = entry("requirements.txt", "fixture==1.0\n")
    for second in (item, dict(item, path="requirements-z.txt", size=1)):
        client = QueueHTTP(*repository(item, second), data)
        with pytest.raises(ProviderError):
            collector(client)
        assert len(client.calls) == 4


def test_cli_no_sharing_never_constructs_osv_client(tmp_path, monkeypatch, capsys):
    item, data = entry("requirements.txt", "fixture==1.0\n")
    github = QueueHTTP(*repository(item), data)

    def http(hosts, **kwargs):
        assert hosts == ["api.github.com"]
        return github

    monkeypatch.setattr(scan_cli, "PublicHTTPS", http)
    assert (
        main(
            [
                "scan",
                TARGET,
                "--network",
                "--allow-host",
                "github.com",
                "--output-dir",
                str(tmp_path / "run"),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["ai_calls"] == 0
    assert len(github.calls) == 4


def test_remote_advisory_failure_preserves_inventory(tmp_path):
    item, data = entry("requirements.txt", "fixture==1.0\n")
    snapshot = collector(QueueHTTP(*repository(item), data))

    def broken(*args):
        raise TimeoutError("SECRET")

    summary = ScanService(lambda _: snapshot, advisory_lookup=broken).run(
        options(share_packages=True), tmp_path / "run"
    )
    assert summary["failed_modules"] == ["dependency_advisories"]
    bundle = read_bundle(tmp_path / "run")
    assert bundle["documents"]["dependency-inventory.json"]["packages"]
    assert "SECRET" not in json.dumps(bundle)
