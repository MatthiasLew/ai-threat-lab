"""Passive HTTPS preserves independently available headers, never partial HTML."""

import http.client
import io
import json
from dataclasses import asdict

import pytest

import ai_threat_lab.http_client as transport
from ai_threat_lab.http_client import HttpResponse, PublicHTTPS
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError
from ai_threat_lab.remote_audit import WebsiteAudit

TARGET = "https://website.example/"
LIMIT = 256 * 1024
HEADERS = [("Content-Type", "text/html"), ("Set-Cookie", "PRIVATE_COOKIE=PRIVATE_VALUE")]
HTML = b'<form action="http://other.example/"><input type="password" name="secret"></form>'


class Wire:
    status = 200
    length = 0

    def __init__(self, data=HTML, failure=None, stage="read"):
        self.data, self.failure, self.stage = data, failure, stage
        self.calls, self.reads, self.closed = [], [], False

    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.failure and self.stage == "request":
            raise self.failure

    def getresponse(self):
        if self.failure and self.stage == "response":
            raise self.failure
        return self

    def getheaders(self):
        return HEADERS

    def read(self, limit):
        self.reads.append(limit)
        if self.failure and self.stage == "read":
            raise self.failure
        return self.data[:limit]

    def close(self):
        self.closed = True


def client(monkeypatch, wire, *, partial=True):
    monkeypatch.setattr(transport, "public_address", lambda _: "8.8.8.8")
    monkeypatch.setattr(transport, "_PinnedHTTPS", lambda *a: wire)
    return PublicHTTPS(["website.example"], max_bytes=LIMIT, max_requests=1,
                       allow_partial_body=partial)


@pytest.mark.parametrize("failure", [OSError("PRIVATE_ERROR"), TimeoutError("PRIVATE_ERROR"),
                                    http.client.IncompleteRead(b"PRIVATE_PARTIAL")])
def test_body_read_failure_keeps_headers_and_discards_partial_html(monkeypatch, failure):
    wire = Wire(failure=failure)
    result = WebsiteAudit(client(monkeypatch, wire)).assess(TARGET)
    checks = {f.check for f in result.findings}
    assert "missing_strict-transport-security" in checks
    assert "cookie_missing_secure" in checks
    assert not any(c.startswith("html_") for c in checks)
    assert any("body" in n.lower() and "unchecked" in n for n in result.not_checked)
    assert "PRIVATE" not in json.dumps(asdict(result))
    assert len(wire.calls) == 1 and wire.reads == [LIMIT + 1] and wire.closed


def test_oversize_body_keeps_header_candidates(monkeypatch):
    wire = Wire(HTML + b"x" * LIMIT)
    result = WebsiteAudit(client(monkeypatch, wire)).assess(TARGET)
    assert any(f.check == "cookie_missing_secure" for f in result.findings)
    assert not any(f.check.startswith("html_") for f in result.findings)
    assert any("size" in n.lower() for n in result.not_checked)
    assert wire.reads == [LIMIT + 1] and wire.closed


def test_short_content_length_read_is_not_complete_html(monkeypatch):
    wire = Wire()
    wire.length = 500  # HTTPResponse.read(amt) can leave an outstanding body length.
    response = client(monkeypatch, wire).request(TARGET)
    assert response.body == b"" and response.body_status == "read_error"
    with pytest.raises(ProviderError):
        response.document()
    assert wire.closed


def test_complete_bounded_body_preserves_header_and_html_candidates(monkeypatch):
    wire = Wire()
    result = WebsiteAudit(client(monkeypatch, wire)).assess(TARGET)
    checks = {f.check for f in result.findings}
    assert {"cookie_missing_secure", "html_password_form_get", "html_password_form_http"} <= checks
    assert wire.closed and len(wire.calls) == 1


@pytest.mark.parametrize("stage", ["request", "response"])
def test_failures_before_headers_remain_errors_without_retry(monkeypatch, stage):
    wire = Wire(failure=OSError("PRIVATE_ERROR"), stage=stage)
    with pytest.raises(ProviderError) as error:
        WebsiteAudit(client(monkeypatch, wire)).assess(TARGET)
    assert "PRIVATE" not in str(error.value)
    assert wire.closed and len(wire.calls) == 1


@pytest.mark.parametrize("wire", [Wire(b"x" * (LIMIT + 1)), Wire(failure=OSError("PRIVATE"))],
                         ids=["size", "read"])
def test_default_json_client_stays_strict(monkeypatch, wire):
    with pytest.raises(ProviderError):
        client(monkeypatch, wire, partial=False).request(TARGET)
    assert wire.closed


@pytest.mark.parametrize("url", ["http://website.example/", "https://website.example:444/",
                                 "https://website.example/#fragment",
                                 "https://user:pass@website.example/",
                                 "https://website.example/a\nheader", "https://website.example/Łódź",
                                 "https://website.example/" + "x" * 4096,
                                 "https://website.example/a\\b"],
                         ids=["http", "port", "fragment", "credentials", "control",
                              "unicode", "length", "backslash"])
def test_website_preflight_happens_before_injected_client(url):
    class Never:
        def request(self, *a, **k):
            pytest.fail("Invalid target reached the client")
    with pytest.raises(ValidationError):
        WebsiteAudit(Never()).assess(url)


@pytest.mark.parametrize("kwargs", [{"allow_partial_body": 1}, {"allow_partial_body": "yes"},
                                    {"max_bytes": True}, {"max_bytes": 1.5},
                                    {"max_requests": True}, {"max_requests": 1.5},
                                    {"timeout": True}, {"timeout": "1"}])
def test_http_configuration_rejects_unsupported_types(kwargs):
    with pytest.raises(ValidationError):
        PublicHTTPS(["website.example"], **kwargs)


def test_partial_body_mode_is_read_only_before_dns(monkeypatch):
    monkeypatch.setattr(transport, "public_address", lambda _: pytest.fail("DNS called"))
    with pytest.raises(ValidationError):
        PublicHTTPS(["api.openai.com"], allow_partial_body=True).request(
            "https://api.openai.com/v1/responses", method="POST"
        )


@pytest.mark.parametrize("headers", [None, True, {"bad": 1}])
def test_malformed_adapter_headers_have_controlled_errors(headers):
    response = HttpResponse(200, headers, b"")
    class Client:
        def request(self, *a, **k):
            return response
    with pytest.raises(ProviderError):
        WebsiteAudit(Client()).assess(TARGET)


@pytest.mark.parametrize("partial", [False, True])
def test_native_http_short_read_never_becomes_complete_json(monkeypatch, partial):
    class Socket:
        def makefile(self, *args):
            return io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{"ok":true}')
    native = http.client.HTTPResponse(Socket())
    native.begin()
    wire = Wire()
    wire.getresponse = lambda: native
    original_close = wire.close
    def close():
        native.close()
        original_close()
    wire.close = close
    web_client = client(monkeypatch, wire, partial=partial)
    if partial:
        response = web_client.request(TARGET)
        assert response.body_status == "read_error" and response.body == b""
        with pytest.raises(ProviderError):
            response.document()
    else:
        with pytest.raises(ProviderError, match="incomplete"):
            web_client.request(TARGET)
    assert wire.closed and len(wire.calls) == 1


@pytest.mark.parametrize("state", ["size_limit", "read_error", "unsupported", None, []])
def test_incomplete_response_cannot_be_used_as_json(state):
    with pytest.raises(ProviderError):
        HttpResponse(200, {}, b'{"ok":true}', body_status=state).document()


@pytest.mark.parametrize("state", ["unsupported", None, []])
def test_website_rejects_invalid_body_metadata(state):
    class Client:
        def request(self, *a, **k):
            return HttpResponse(200, {}, b"", body_status=state)
    with pytest.raises(ProviderError):
        WebsiteAudit(Client()).assess(TARGET)



def test_declared_oversize_skips_body_read_entirely(monkeypatch):
    wire = Wire()
    wire.length = LIMIT + 1
    response = client(monkeypatch, wire).request(TARGET)
    assert response.body_status == "size_limit" and response.body == b""
    assert wire.reads == [] and wire.closed


def test_engine_22_bundle_is_readable_but_not_comparable(tmp_path):
    from ai_threat_lab.assessment import AssessmentResult
    from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, read_bundle, scope_digest
    from ai_threat_lab.scan_engine import ScanOptions, ScanService

    def assess(_):
        return AssessmentResult(TARGET, "website", "partial", (), ("Fixture only.",))
    ScanService(assess).run(
        ScanOptions(TARGET, network=True, allowed_hosts=("website.example",)), tmp_path / "current"
    )
    current = read_bundle(tmp_path / "current")
    assert current["manifest"]["scope"]["engine"] == "read-only-pipeline-27"
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-22"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    previous = read_bundle(tmp_path / "old")
    assert previous["manifest"]["scope"]["engine"] == "read-only-pipeline-22"
    comparison = compare_bundles(previous, current)
    assert comparison["comparable"] is False and comparison["counts"] is None



def test_http_agent_identifies_current_release(monkeypatch):
    from ai_threat_lab import __version__
    wire = Wire()
    client(monkeypatch, wire).request(TARGET)
    assert wire.calls[0][1]["headers"]["User-Agent"] == f"AI-Threat-Lab/{__version__}"
