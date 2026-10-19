"""Malformed remote metadata must become explicit bounded provider failures."""

import json

import pytest
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.cli import main
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import read_bundle
from ai_threat_lab.scan_engine import ScanOptions, ScanService

TARGET = "https://github.com/owner/repo"
BAD_SHAS = (None, True, 12, [], {}, "", "a" * 39, "A" * 40, "z" * 40)


@pytest.fixture(autouse=True)
def anonymous_unit_environment(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)


@pytest.mark.parametrize("sha", BAD_SHAS)
@pytest.mark.parametrize("stage", ["commit", "blob"])
def test_invalid_sha_types_are_controlled_provider_errors(sha, stage):
    item, data = blob("eval(untrusted)\n")
    responses = repository(item)
    if stage == "commit":
        responses[1]["sha"] = sha
    else:
        item["sha"] = sha
    client = QueueHTTP(*responses, data)
    with pytest.raises(ProviderError, match="immutable commit|blob identity"):
        GithubAudit(client).collect(TARGET)
    assert len(client.calls) == (2 if stage == "commit" else 3)


@pytest.mark.parametrize("value", [None, 0, "false", [], {}])
def test_dependency_collection_option_requires_boolean_before_requests(value):
    client = QueueHTTP()
    with pytest.raises(ValidationError):
        GithubAudit(client).collect(TARGET, include_dependencies=value)
    assert client.calls == []


@pytest.mark.parametrize("value", [None, 0, "false", [], {}])
def test_invalid_tree_truncation_metadata_is_not_silently_trusted(value):
    client = QueueHTTP(*repository(truncated=value))
    with pytest.raises(ProviderError, match="tree"):
        GithubAudit(client).collect(TARGET)
    assert len(client.calls) == 3


@pytest.mark.parametrize("branch", ["\x00", "bad\nbranch", "\ud800", "x" * 1025])
def test_unusable_branch_metadata_is_rejected_without_request(branch):
    client = QueueHTTP({"default_branch": branch})
    with pytest.raises(ProviderError, match="default branch"):
        GithubAudit(client).collect(TARGET)
    assert len(client.calls) == 1


@pytest.mark.parametrize(
    "token", ["\r\nInjected: value", "with space", "\t", "Żółw", "x" * 4097],
    ids=["header-control", "space", "tab", "non-ascii", "oversize"],
)
def test_malformed_token_is_not_sent_or_echoed(monkeypatch, token):
    monkeypatch.setenv("GITHUB_TOKEN", token)
    client = QueueHTTP()
    with pytest.raises(ProviderError, match="GITHUB_TOKEN") as error:
        GithubAudit(client).collect(TARGET)
    assert token not in str(error.value)
    assert client.calls == []


def test_deep_provider_json_has_controlled_error():
    raw = b'{"x":' * 2000 + b'0' + b'}' * 2000
    with pytest.raises(ProviderError, match="invalid JSON"):
        HttpResponse(200, {}, raw).document()


@pytest.mark.parametrize("status", [301, 401, 403, 404, 429, 500, 503])
def test_http_failure_never_retries_or_discloses_body(status):
    client = QueueHTTP(HttpResponse(status, {}, b"PRIVATE_RESPONSE"))
    with pytest.raises(ProviderError) as error:
        GithubAudit(client).collect(TARGET)
    assert len(client.calls) == 1
    assert "PRIVATE_RESPONSE" not in str(error.value)


def test_metadata_failure_preserves_verified_failed_scan_without_retry(tmp_path):
    client = QueueHTTP({"default_branch": "main"}, {"sha": None})
    def collect(_):
        return GithubAudit(client).collect(TARGET, include_dependencies=True)
    summary = ScanService(collect).run(
        ScanOptions(TARGET, network=True, allowed_hosts=("github.com",)), tmp_path / "failed run"
    )
    assert summary["failed_modules"] == ["target_assessment", "dependency_inventory"]
    assert summary["ai_calls"] == 0
    saved = read_bundle(tmp_path / "failed run")
    assert len(client.calls) == 2
    assert "Traceback" not in json.dumps(saved)


def test_audit_cli_malformed_metadata_exit_is_integration_error(monkeypatch, capsys):
    import ai_threat_lab.integration_cli as integration
    client = QueueHTTP({"default_branch": "main"}, {"sha": None})
    monkeypatch.setattr(integration, "PublicHTTPS", lambda *a, **k: client)
    assert main(["audit", TARGET, "--network", "--allow-host", "github.com"]) == 3
    output = capsys.readouterr()
    assert output.out == "" and output.err.startswith("Integration error:")
    assert "Traceback" not in output.err and len(client.calls) == 2


@pytest.mark.parametrize("branch", ["main", "feature/name", "Łódź"])
def test_valid_default_branch_names_remain_supported(branch):
    from urllib.parse import quote
    client = QueueHTTP({"default_branch": branch}, {"sha": "a" * 40},
                       {"tree": [], "truncated": False})
    snapshot = GithubAudit(client).collect(TARGET)
    assert snapshot.commit_sha == "a" * 40
    assert client.calls[1][0].endswith("/commits/" + quote(branch, safe=""))
    assert client.calls[2][0].endswith("/git/trees/" + "a" * 40 + "?recursive=1")


@pytest.mark.parametrize("enabled", [False, True])
def test_boolean_dependency_selection_remains_supported(enabled):
    client = QueueHTTP(*repository())
    snapshot = GithubAudit(client).collect(TARGET, include_dependencies=enabled)
    assert snapshot.commit_sha == "a" * 40 and len(client.calls) == 3


@pytest.mark.parametrize("depth,accepted", [(63, True), (64, True), (65, False)])
def test_provider_json_container_depth_boundary(depth, accepted):
    raw = b'{"value":' * depth + b'0' + b'}' * depth
    response = HttpResponse(200, {}, raw)
    if accepted:
        assert isinstance(response.document(), dict)
    else:
        with pytest.raises(ProviderError):
            response.document()


def test_provider_json_mixed_array_object_depth_boundary():
    accepted = b'{"items":' + b'[' * 63 + b'0' + b']' * 63 + b'}'
    assert isinstance(HttpResponse(200, {}, accepted).document(), dict)
    rejected = b'{"items":' + b'[' * 64 + b'0' + b']' * 64 + b'}'
    with pytest.raises(ProviderError):
        HttpResponse(200, {}, rejected).document()
