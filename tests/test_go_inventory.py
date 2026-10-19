"""Go checksum identities, conservative gaps and shared offline collection routes."""

import json
import socket

import pytest
from test_cli_process import run_cli
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.dependencies import Dependency, OSVAudit, inventory, inventory_sources
from ai_threat_lab.models import ValidationError
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import read_bundle
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService

HASH = "h1:" + "A" * 43 + "="


def record(name="example.invalid/Fixture", version="v1.2.3", checksum=HASH):
    return f"{name} {version} {checksum}\n"


def parse(source):
    return inventory_sources("fixture", [("go.sum", source.encode())])


@pytest.mark.parametrize(
    "version",
    [
        "v0.0.0",
        "v1.2.3",
        "v1.2.3-rc.1",
        "v2.3.4+incompatible",
        "v0.0.0-20260101000000-abcdefabcdef",
        "v1.2.4-0.20260101000000-abcdefabcdef",
    ],
)
def test_supported_versions_preserved_without_claiming_provenance(version):
    result = parse(record(version=version))
    assert result.packages[0].query() == {
        "package": {"ecosystem": "Go", "name": "example.invalid/Fixture"},
        "version": version,
    }
    assert result.packages[0].sources == ("go.sum",)
    assert any("provenance" in gap and "unchecked" in gap for gap in result.not_checked)
    assert any("checksums not verified" in gap for gap in result.not_checked)


@pytest.mark.parametrize(
    "version",
    [
        "1.2.3",
        "v1",
        "v1.2",
        "v01.2.3",
        "v1.02.3",
        "v1.2.03",
        "v1.2.3-01",
        "v1.2.3-a..b",
        "v1.2.3+build",
        "v1.2.3+dirty",
        "master",
        "v1.2.*",
        "v" + "1" * 128,
    ],
)
def test_bad_versions_omitted_with_redacted_notice(version):
    result = parse(record(version=version))
    assert not result.packages
    assert any("values omitted" in gap for gap in result.not_checked)
    assert "example.invalid/Fixture" not in str(result)


@pytest.mark.parametrize(
    "name",
    [
        "github.com/Owner/Module/v2",
        "golang.org/x/net",
        "gopkg.in/yaml.v3",
        "example.invalid/module_name",
        "example.invalid/sub/a~b",
        "example.invalid",
    ],
)
def test_supported_module_path_subset(name):
    assert parse(record(name=name)).packages[0].name == name


@pytest.mark.parametrize(
    "name",
    [
        "local",
        "../secret",
        "https://example.invalid/mod",
        "a.invalid//b",
        "a.invalid/../b",
        "a.invalid/.hidden",
        "a.invalid/trailing.",
        "a.invalid/",
        "a.invalid/!owner",
        "a.invalid/a@b",
        "a.invalid/a:b",
        "a.invalid/a\\b",
        "a.invalid/café",
        "UPPER.invalid/m",
        "a.invalid/" + "x" * 512,
    ],
)
def test_unsupported_paths_are_not_reinterpreted_or_disclosed(name):
    assert not parse(record(name=name)).packages
    with pytest.raises(ValidationError):
        Dependency("Go", name, "v1.2.3", ())


@pytest.mark.parametrize(
    "checksum",
    [
        "h2:" + "A" * 43 + "=",
        "h1:short",
        "h1:" + "A" * 44,
        "h1:" + "A" * 42 + "B=",
        "h1:" + "A" * 42 + "_=",
        "h1:" + "A" * 44 + "=",
    ],
)
def test_hash_shape_and_canonical_base64_checked_without_hash_trust(checksum):
    assert not parse(record(checksum=checksum)).packages


def test_metadata_only_entries_are_not_content_and_duplicates_merge():
    result = parse(record(version="v1.0.0/go.mod") + record() * 2 + record(version="v1.3.0"))
    assert [p.version for p in result.packages] == ["v1.2.3", "v1.3.0"]
    assert any("go.mod-only" in gap for gap in result.not_checked)


def test_bom_crlf_whitespace_empty_and_malformed_records():
    result = parse("\ufeff\r\n" + record().replace(" ", "\t").replace("\n", "\r\n"))
    assert len(result.packages) == 1
    assert not parse("").packages
    bad = parse("secret-token\nsecret-token v1.2.3 extra secret-token\n")
    assert not bad.packages and "secret-token" not in str(bad)


def test_global_package_and_line_bounds():
    with pytest.raises(ValidationError, match="500"):
        parse("".join(record(name=f"example.invalid/mod{i}") for i in range(501)))
    with pytest.raises(ValidationError, match="20000-line"):
        parse("\n" * 20001)
    assert parse("\n" * 20000).packages == ()


def test_notice_bound_retains_final_coverage_gap():
    result = parse("secret-token\n" * 1000 + record())
    assert len(result.packages) == 1
    assert len(result.not_checked) <= 101
    assert "secret-token" not in str(result)
    assert any("checksums not verified" in gap for gap in result.not_checked)
    assert any("Additional omitted" in gap for gap in result.not_checked)


def test_invalid_utf8_and_byte_bound():
    for source in (b"\xff", b"a" * (2 * 1024 * 1024 + 1)):
        with pytest.raises(ValidationError):
            inventory_sources("fixture", [("go.sum", source)])


def test_local_recursive_identity_merge_case_and_no_network(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("offline inventory attempted network access")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    (tmp_path / "go.sum").write_text(record())
    sub = tmp_path / "service"
    sub.mkdir()
    (sub / "go.sum").write_text(record() + record(name="example.invalid/fixture"))
    assert len(inventory(tmp_path).packages) == 1
    result = inventory(tmp_path, recursive=True)
    assert len(result.packages) == 2
    assert result.packages[0].sources == ("go.sum", "service/go.sum")
    assert inventory(tmp_path / "go.sum").packages[0].name == "example.invalid/Fixture"


def test_github_shared_commit_inventory_and_bundle(tmp_path):
    item, data = blob(record())
    item["path"] = "backend/go.sum"
    client = QueueHTTP(*repository(item), data)
    snapshot = GithubAudit(client).collect(
        "https://github.com/owner/repo", include_dependencies=True, recursive_dependencies=True
    )
    assert len(client.calls) == 4
    assert snapshot.inventory().packages[0].sources == ("backend/go.sum",)
    ScanService(lambda _: snapshot).run(
        ScanOptions(
            "https://github.com/owner/repo",
            network=True,
            allowed_hosts=("github.com",),
            recursive_dependencies=True,
        ),
        tmp_path / "bundle",
    )
    package = read_bundle(tmp_path / "bundle")["documents"]["dependency-inventory.json"][
        "packages"
    ][0]
    assert package["ecosystem"] == "Go" and package["version"] == "v1.2.3"


def test_osv_wire_payload_preserves_case_and_v_prefix_with_fake_transport():
    client = QueueHTTP({"results": [{"vulns": [{"id": "GO-2026-0001"}]}]})
    result = OSVAudit(client).assess(parse(record()))
    assert result["findings"][0]["check"] == "known_dependency_advisory"
    sent = json.loads(client.calls[0][1]["body"])["queries"][0]
    assert sent == parse(record()).packages[0].query()


def test_real_cli_scan_and_no_go_toolchain(tmp_path, monkeypatch):
    (tmp_path / "go.sum").write_text(record())
    monkeypatch.setenv("GOPATH", str(tmp_path / "absent-gopath"))
    process = run_cli("audit-deps", tmp_path)
    assert process.returncode == 0 and not process.stderr
    assert json.loads(process.stdout)["packages"][0]["ecosystem"] == "Go"
    summary = ScanService(assessor).run(ScanOptions(str(tmp_path)), tmp_path / "result")
    assert summary["ai_calls"] == 0 and not summary["failed_modules"]
    assert not (tmp_path / "absent-gopath").exists()


def test_engine_nine_remains_readable_but_not_comparable(tmp_path):
    from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, scope_digest

    (tmp_path / "go.sum").write_text(record())
    ScanService(assessor).run(ScanOptions(str(tmp_path)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    assert current["manifest"]["scope"]["engine"] == "read-only-pipeline-18"
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-9"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    comparison = compare_bundles(read_bundle(tmp_path / "old"), current)
    assert comparison["comparable"] is False and comparison["counts"] is None
