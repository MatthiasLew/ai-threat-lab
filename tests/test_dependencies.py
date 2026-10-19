import json
import sqlite3
from dataclasses import replace

import pytest

from ai_threat_lab.dependencies import AdvisoryCache, Dependency, Inventory, OSVAudit, inventory
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError


def test_requirements_exact_versions_markers_extras_normalization_and_redaction(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text(
        "# comment\n\nSome_Pkg[extra]==1.2.3; python_version < '3.14'\n"
        "some-pkg==1.2.3 # duplicate\nother>=1\n"
        "https://user:SECRET@private.example/pkg\n-r SECRET_FILE\n"
        "wildcard==1.*\n"
    )
    result = inventory(path)
    assert len(result.packages) == 1
    assert result.packages[0].name == "some-pkg" and result.packages[0].version == "1.2.3"
    assert len(result.packages[0].sources) == 2
    assert "SECRET" not in str(result)
    assert result.document()["schema_version"] == 1
    assert len(result.not_checked) >= 7


@pytest.mark.parametrize("version", [2, 3])
def test_npm_lock_scopes_transitives_duplicates_and_workspace(tmp_path, version):
    path = tmp_path / "package-lock.json"
    path.write_text(
        json.dumps(
            {
                "lockfileVersion": version,
                "packages": {
                    "": {"name": "root", "version": "0.1.0"},
                    "node_modules/@scope/name": {"version": "1.2.3"},
                    "node_modules/a/node_modules/@scope/name": {"version": "1.2.3"},
                    "node_modules/alias": {"name": "actual", "version": "2.0.0"},
                    "node_modules/local": {"link": True},
                    "packages/local": {"version": "1.0.0"},
                    "node_modules/missing": {},
                },
            }
        )
    )
    result = inventory(path)
    assert {(p.name, p.version) for p in result.packages} == {
        ("@scope/name", "1.2.3"),
        ("actual", "2.0.0"),
    }
    assert any("workspace" in n for n in result.not_checked)


@pytest.mark.parametrize("filename", ["uv.lock", "poetry.lock"])
def test_python_lockfile_registry_and_local_sources(tmp_path, filename):
    path = tmp_path / filename
    path.write_text("""[[package]]
name = "Some_Pkg"
version = "1.2.3"
[package.source]
registry = "https://pypi.org/simple"
[[package]]
name = "local"
version = "1.0"
[package.source]
editable = "."
""")
    result = inventory(path)
    assert len(result.packages) == 1 and result.packages[0].name == "some-pkg"
    assert any("non-registry" in n for n in result.not_checked)


def test_multiple_manifests_merge_and_nonrecursive_empty(tmp_path):
    (tmp_path / "requirements.txt").write_text("fixture==1.0\n")
    (tmp_path / "requirements-dev.txt").write_text("fixture==1.0\n")
    assert len(inventory(tmp_path).packages[0].sources) == 2
    (tmp_path / "requirements.txt").unlink()
    (tmp_path / "requirements-dev.txt").unlink()
    child = tmp_path / "nested"
    child.mkdir()
    (child / "requirements.txt").write_text("fixture==1.0")
    result = inventory(tmp_path)
    assert not result.packages and any("subdirectories" in n for n in result.not_checked)


@pytest.mark.parametrize(
    "filename,source",
    [
        ("other.txt", "x"),
        ("package-lock.json", "{"),
        ("package-lock.json", '{"lockfileVersion":1,"packages":{}}'),
        ("package-lock.json", '{"lockfileVersion":true,"packages":{}}'),
        ("package-lock.json", '{"lockfileVersion":2,"packages":[]}'),
        ("package-lock.json", '{"lockfileVersion":2,"packages":{"node_modules/a":null}}'),
        ("package-lock.json", '{"lockfileVersion":2,"packages":{},"packages":{}}'),
        ("package-lock.json", "[]"),
        ("poetry.lock", "[broken"),
        ("uv.lock", ""),
        ("uv.lock", "package=[1]"),
        ("uv.lock", '[[package]]\nname="fixture"\nversion="1.0"\nsource=2'),
    ],
)
def test_invalid_manifests_are_readable_and_source_free(tmp_path, filename, source):
    path = tmp_path / filename
    path.write_text(source)
    with pytest.raises(ValidationError, match="manifest"):
        inventory(path)


def test_inventory_limits(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(ValidationError, match="2 MiB"):
        inventory(path)
    path.write_text("\n".join(f"fixture{i}==1.0" for i in range(501)))
    with pytest.raises(ValidationError):
        inventory(path)
    path.write_text("unpinned>=1\n" * 200)
    assert any("Additional omitted" in s for s in inventory(path).not_checked)
    path.unlink()
    for index in range(21):
        (tmp_path / f"requirements{index}.txt").touch()
    with pytest.raises(ValidationError, match="20 manifests"):
        inventory(tmp_path)


def test_missing_symlink_and_nonfile_manifest(tmp_path):
    with pytest.raises(ValidationError):
        inventory(tmp_path / "missing")
    (tmp_path / "requirements.txt").mkdir()
    assert any("non-file" in n for n in inventory(tmp_path).not_checked)
    link = tmp_path / "requirements-dev.txt"
    try:
        link.symlink_to(tmp_path / "requirements.txt", target_is_directory=True)
    except OSError:
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ValidationError):
        inventory(link)
    assert any("symlink" in n for n in inventory(tmp_path).not_checked)


@pytest.mark.parametrize(
    "ecosystem,name,version",
    [
        ("other", "x", "1"),
        ("npm", "../x", "1"),
        ("PyPI", None, "1"),
        ("npm", "x", "latest"),
        ("PyPI", "x", None),
    ],
)
def test_invalid_package_identity(ecosystem, name, version):
    with pytest.raises(ValidationError):
        Dependency(ecosystem, name, version, ())


def test_invalid_lock_identity_is_skipped_without_disclosure(tmp_path):
    path = tmp_path / "package-lock.json"
    path.write_text(
        json.dumps(
            {"lockfileVersion": 3, "packages": {"node_modules/x": {"name": 123, "version": "1.0"}}}
        )
    )
    assert not inventory(path).packages


class HTTP:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        result = self.responses.pop(0)
        return (
            result
            if isinstance(result, HttpResponse)
            else HttpResponse(200, {}, json.dumps(result).encode())
        )


def collected(count=1):
    return Inventory(
        "requirements.txt",
        tuple(
            Dependency("PyPI", f"fixture{i}", "1.0", ("requirements.txt",)) for i in range(count)
        ),
        ("Not a full audit",),
    )


def test_osv_query_contract_pagination_and_cache(tmp_path):
    source = collected(2)
    cache = AdvisoryCache(tmp_path / "cache.sqlite", clock=lambda: 100)
    client = HTTP(
        {"results": [{"vulns": [{"id": "GHSA-fixture-1"}], "next_page_token": "page2"}, {}]},
        {"results": [{"vulns": [{"id": "CVE-2099-1234"}, {"id": "GHSA-fixture-1"}]}]},
    )
    report = OSVAudit(client, cache=cache).assess(source)
    assert len(report["findings"]) == 2 and all(
        f["status"] == "candidate" for f in report["findings"]
    )
    assert report["dependency_audit"]["network_requests"] == 2
    assert all(
        url == "https://api.osv.dev/v1/querybatch" and call["method"] == "POST"
        for url, call in client.calls
    )
    body = json.loads(client.calls[1][1]["body"])
    assert body["queries"][0]["page_token"] == "page2"
    assert "sources" not in str(body) and "requirements.txt" not in str(body)
    second = OSVAudit(HTTP(), cache=AdvisoryCache(cache.path, clock=lambda: 101)).assess(source)
    assert second["dependency_audit"]["network_requests"] == 0
    assert second["dependency_audit"]["cache_hits"] == 2
    assert second["findings"] == report["findings"]
    cache.path.unlink()  # Windows connection closure.


def test_batch_chunks_and_partial_page_limit_not_cached_as_clean(tmp_path):
    source = collected(101)
    client = HTTP({"results": [{}] * 100}, {"results": [{}]})
    result = OSVAudit(client).assess(source)
    assert result["dependency_audit"]["complete_queries"] == 101 and len(client.calls) == 2
    cache = AdvisoryCache(tmp_path / "cache.sqlite")
    result = OSVAudit(
        HTTP({"results": [{"next_page_token": "more"}]}), cache=cache, max_pages=1
    ).assess(collected())
    assert result["dependency_audit"]["complete_queries"] == 0
    assert cache.get(collected().packages[0]) is None
    assert any("incomplete" in n for n in result["not_checked"])
    assert not OSVAudit(HTTP()).assess(collected(0))["findings"]


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"results": []},
        {"results": [None]},
        {"results": [{"vulns": None}]},
        {"results": [{"vulns": [None]}]},
        {"results": [{"vulns": [{"id": "../../private"}]}]},
        {"results": [{"next_page_token": 1}]},
        {"results": [{"next_page_token": "x" * 4097}]},
        HttpResponse(429, {}, b"SECRET_PROVIDER_BODY"),
    ],
)
def test_osv_malformed_or_error_never_clean(response):
    with pytest.raises(ProviderError) as error:
        OSVAudit(HTTP(response)).assess(collected())
    assert "SECRET_PROVIDER_BODY" not in str(error.value)


def test_osv_pagination_loop_and_size_cap():
    page = {"results": [{"next_page_token": "same"}]}
    with pytest.raises(ProviderError, match="repeated"):
        OSVAudit(HTTP(page, page)).assess(collected())
    too_many = {"results": [{"vulns": [{"id": f"OSV-{i}"} for i in range(1001)]}]}
    with pytest.raises(ProviderError, match="limit"):
        OSVAudit(HTTP(too_many)).assess(collected())


@pytest.mark.parametrize("limit", [0, 21, True])
def test_page_limits(limit):
    with pytest.raises(ValidationError):
        OSVAudit(HTTP(), max_pages=limit)


@pytest.mark.parametrize("ttl", [0, 86401, True])
def test_cache_ttl_limits(tmp_path, ttl):
    with pytest.raises(ValidationError):
        AdvisoryCache(tmp_path / "cache.sqlite", ttl_seconds=ttl)


def test_cache_expiry_corruption_and_aggregate_size(tmp_path):
    package = collected().packages[0]
    cache = AdvisoryCache(tmp_path / "cache.sqlite", clock=lambda: 100, ttl_seconds=1)
    assert cache.get(package) is None
    cache.put(package, [])
    assert cache.get(package) == []
    assert AdvisoryCache(cache.path, clock=lambda: 101).get(package) is None
    with sqlite3.connect(cache.path) as db:
        db.execute("UPDATE advisories SET response='not json'")
    with pytest.raises(ValidationError):
        cache.get(package)
    with pytest.raises(ValidationError, match="limit"):
        cache.put(package, [f"OSV-{i}" for i in range(1001)])
    with pytest.raises(ValidationError):
        cache.put(package, [1])


def test_cache_symlinks_rejected(tmp_path):
    target = tmp_path / "target"
    target.touch()
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ValidationError):
        AdvisoryCache(link)


def test_cache_only_queries_misses(tmp_path):
    source = collected(2)
    cache = AdvisoryCache(tmp_path / "cache.sqlite")
    cache.put(source.packages[0], [])
    client = HTTP({"results": [{}]})
    result = OSVAudit(client, cache=cache).assess(source)
    assert len(json.loads(client.calls[0][1]["body"])["queries"]) == 1
    assert result["dependency_audit"]["cache_hits"] == 1


def test_legacy_registry_source_and_missing_version(tmp_path):
    path = tmp_path / "poetry.lock"
    path.write_text("""[[package]]
name="fixture"
version="1.0"
[package.source]
type="legacy"
url="https://private.example"
[[package]]
name="no-version"
""")
    assert len(inventory(path).packages) == 1


def test_different_versions_are_not_deduplicated(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("fixture==1.0\nfixture==2.0\n")
    assert len(inventory(path).packages) == 2
    assert replace(collected().packages[0], version="2.0").query()["version"] == "2.0"
