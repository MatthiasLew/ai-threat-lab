import http.client
import socket

import pytest

import ai_threat_lab.http_client as module
from ai_threat_lab.http_client import HttpResponse, PublicHTTPS, get_document, public_address
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fc00::1",
        "192.0.2.1",
        "100.64.0.1",
    ],
)
def test_private_and_reserved_dns_rejected(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", (address, 443))])
    with pytest.raises(ProviderError):
        public_address("example.com")


def test_mixed_dns_empty_and_dns_failure(monkeypatch):
    for addresses in [[], [(0, 0, 0, "", ("8.8.8.8", 443)), (0, 0, 0, "", ("127.0.0.1", 443))]]:
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: addresses)
        with pytest.raises(ProviderError):
            public_address("example.com")

    def fail(*args, **kwargs):
        raise OSError("SECRET")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(ProviderError) as error:
        public_address("example.com")
    assert "SECRET" not in str(error.value)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://other.com",
        "https://example.com:444",
        "https://user:pass@example.com",
        "https://example.com/#fragment",
        "https://example.com/\r\nHeader:x",
        "https://example.com:bad",
        "https://[broken",
        "https://example.com/a b",
    ],
)
def test_https_scope_rejected_before_dns(monkeypatch, url):
    monkeypatch.setattr(module, "public_address", lambda *a: pytest.fail("DNS must not be called"))
    with pytest.raises(ValidationError):
        PublicHTTPS(["example.com"]).request(url)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_bytes": 0},
        {"max_bytes": 9000000},
        {"max_requests": 0},
        {"max_requests": 201},
        {"timeout": 0},
        {"timeout": 121},
    ],
)
def test_http_limits(kwargs):
    with pytest.raises(ValidationError):
        PublicHTTPS(["example.com"], **kwargs)


@pytest.mark.parametrize(
    "url,method",
    [
        ("https://example.com", "POST"),
        ("https://api.openai.com/v1/other", "POST"),
        ("https://example.com", "DELETE"),
    ],
)
def test_no_arbitrary_mutations(url, method):
    with pytest.raises(ValidationError):
        PublicHTTPS(["example.com", "api.openai.com"]).request(url, method=method)


@pytest.mark.parametrize("host,path,query", [
    ("example.com", "/avatar/batchsyntheses/" + "a" * 64, "api-version=2024-08-01"),
    ("fixture.cognitiveservices.azure.com", "/other", "api-version=2024-08-01"),
    ("fixture.cognitiveservices.azure.com", "/avatar/batchsyntheses/not-reviewed",
     "api-version=2024-08-01"),
    ("fixture.cognitiveservices.azure.com", "/avatar/batchsyntheses/" + "a" * 64,
     "api-version=2024-08-01&other=1"),
    ("fixture.cognitiveservices.azure.com.evil.invalid", "/avatar/batchsyntheses/" + "a" * 64,
     "api-version=2024-08-01"),
])
def test_avatar_put_scope_before_dns(monkeypatch, host, path, query):
    monkeypatch.setattr(module, "public_address", lambda *a: pytest.fail("Unexpected DNS"))
    with pytest.raises(ValidationError):
        PublicHTTPS([host]).request(f"https://{host}{path}?{query}", method="PUT")


class Connection:
    instances = []
    body = b"{}"
    failure = None

    def __init__(self, host, address, timeout):
        self.host, self.address, self.timeout = host, address, timeout
        self.closed = False
        self.instances.append(self)

    def request(self, *args, **kwargs):
        self.requested = args, kwargs
        if self.failure:
            raise self.failure

    def getresponse(self):
        return self

    status = 200

    def getheaders(self):
        return [("Content-Type", "application/json")]

    def read(self, count):
        return self.body[:count]

    def close(self):
        self.closed = True


def test_connection_pinning_bounds_cleanup_and_budget(monkeypatch):
    monkeypatch.setattr(module, "public_address", lambda host: "8.8.8.8")
    monkeypatch.setattr(module, "_PinnedHTTPS", Connection)
    client = PublicHTTPS(["example.com"], max_requests=1)
    assert get_document(client, "https://example.com/path?q=1") == {}
    connection = Connection.instances[-1]
    assert connection.host == "example.com" and connection.address == "8.8.8.8"
    assert connection.requested[0] == ("GET", "/path?q=1") and connection.closed
    with pytest.raises(ProviderError, match="budget"):
        client.request("https://example.com")
    monkeypatch.setattr(Connection, "body", b"12345")
    with pytest.raises(ProviderError, match="size"):
        PublicHTTPS(["example.com"], max_bytes=4).request("https://example.com")
    assert Connection.instances[-1].closed


def test_avatar_put_uses_fixed_path_and_request_budget(monkeypatch):
    host = "fixture.cognitiveservices.azure.com"
    path = "/avatar/batchsyntheses/" + "a" * 64 + "?api-version=2024-08-01"
    monkeypatch.setattr(module, "public_address", lambda value: "8.8.8.8")
    monkeypatch.setattr(module, "_PinnedHTTPS", Connection)
    client = PublicHTTPS([host], max_requests=1)
    client.request(f"https://{host}{path}", method="PUT", body=b"{}", headers={"X-Fixture": "1"})
    connection = Connection.instances[-1]
    assert connection.host == host and connection.requested[0] == ("PUT", path)
    assert connection.requested[1]["body"] == b"{}" and connection.closed
    with pytest.raises(ProviderError, match="budget"):
        client.request(f"https://{host}{path}", method="PUT")


@pytest.mark.parametrize("failure", [OSError("SECRET"), http.client.HTTPException("SECRET")])
def test_network_failure_redaction(monkeypatch, failure):
    monkeypatch.setattr(module, "public_address", lambda host: "8.8.8.8")
    monkeypatch.setattr(module, "_PinnedHTTPS", Connection)
    monkeypatch.setattr(Connection, "failure", failure)
    with pytest.raises(ProviderError) as error:
        PublicHTTPS(["example.com"]).request("https://example.com")
    assert "SECRET" not in str(error.value) and Connection.instances[-1].closed


@pytest.mark.parametrize("body", [b"[]", b"null", b"bad", b"\xff"])
def test_bad_json(body):
    with pytest.raises(ProviderError):
        HttpResponse(200, {}, body).document()


def test_get_document_http_error():
    class ErrorClient:
        def request(self, *args, **kwargs):
            return HttpResponse(401, {}, b"SECRET")

    with pytest.raises(ProviderError) as error:
        get_document(ErrorClient(), "url")
    assert "SECRET" not in str(error.value)


def test_dns_success_and_tls_original_hostname(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("8.8.8.8", 443))])
    assert public_address("example.com") == "8.8.8.8"
    calls = []

    class Raw:
        def close(self):
            calls.append("closed")

    class Context:
        def wrap_socket(self, raw, server_hostname):
            calls.append(server_hostname)
            return raw

    monkeypatch.setattr(
        socket, "create_connection", lambda address, timeout: calls.append(address) or Raw()
    )
    connection = module._PinnedHTTPS("example.com", "8.8.8.8", 3)
    connection._context = Context()
    connection.connect()
    assert calls == [("8.8.8.8", 443), "example.com"]

    class BadContext:
        def wrap_socket(self, *args, **kwargs):
            raise OSError("failed")

    connection._context = BadContext()
    with pytest.raises(OSError):
        connection.connect()
    assert calls[-1] == "closed"


@pytest.mark.parametrize("suffix", ["/Calls.json", "/Calls/CA" + "b" * 32 + ".json"])
def test_call_post_routes_preserve_exact_path(monkeypatch, suffix):
    path = "/2010-04-01/Accounts/AC" + "a" * 32 + suffix
    monkeypatch.setattr(module, "public_address", lambda value: "8.8.8.8")
    monkeypatch.setattr(module, "_PinnedHTTPS", Connection)
    client = PublicHTTPS(["api.twilio.com"], max_requests=1)
    client.request("https://api.twilio.com" + path, method="POST", body=b"Status=completed")
    connection = Connection.instances[-1]
    assert connection.host == "api.twilio.com" and connection.requested[0] == ("POST", path)
    assert connection.closed


@pytest.mark.parametrize("host,path", [
    ("api.twilio.com", "/2010-04-01/Accounts/AC" + "a" * 32 + "/Messages.json"),
    ("api.twilio.com", "/2010-04-01/Accounts/ACshort/Calls.json"),
    ("api.twilio.com", "/2010-04-01/Accounts/AC" + "a" * 32 + "/Calls/CAshort.json"),
    ("api.twilio.com", "/2010-04-01/Accounts/AC" + "a" * 32 + "/Calls.json?extra=1"),
    ("api.twilio.com.evil.invalid", "/2010-04-01/Accounts/AC" + "a" * 32 + "/Calls.json"),
])
def test_call_post_other_routes_fail_before_dns(monkeypatch, host, path):
    def forbidden(*args):
        raise AssertionError("Invalid route reached DNS")

    monkeypatch.setattr(module, "public_address", forbidden)
    with pytest.raises(ValidationError):
        PublicHTTPS([host]).request("https://" + host + path, method="POST")
