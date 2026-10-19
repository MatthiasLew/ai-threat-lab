"""Installed passive HTTPS acceptance with native HTTP parsing and blocked sockets."""

import http.client
import io
import json
import socket
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ai_threat_lab import __version__
from ai_threat_lab.cli import main as cli_main
from ai_threat_lab.scan_bundle import read_bundle

TARGET = "https://website.example/login"
LIMIT = 256 * 1024
UNSAFE = (b'<form action="http://other.example/">'
          b'<input type=password name=PRIVATE value=SECRET></form>')
SAFE = b'<form method=post action="/login"><input type=password name=PRIVATE></form>'


def blocked(*args, **kwargs):
    raise AssertionError("Offline website acceptance must not contact the network")


class MemorySocket:
    def __init__(self, raw):
        self.raw = raw

    def makefile(self, *args):
        return io.BytesIO(self.raw)


class Connection:
    def __init__(self, body, *, safe=False, short=False, status=200, failure=None):
        headers = [b"Content-Type: text/html", b"Content-Length: " + str(
            len(body) + (17 if short else 0)
        ).encode()]
        if safe:
            headers += [b"Strict-Transport-Security: max-age=31536000",
                        b"Content-Security-Policy: default-src 'self'",
                        b"X-Content-Type-Options: nosniff", b"Referrer-Policy: no-referrer"]
        for name in (b"PRIVATE_ONE", b"PRIVATE_TWO"):
            cookie = b"Set-Cookie: " + name + b"=SECRET_VALUE"
            headers.append(cookie + (b"; Secure; HttpOnly; SameSite=Strict" if safe else b""))
        if status == 302:
            headers.append(b"Location: https://127.0.0.1/private")
        raw = b"HTTP/1.1 " + str(status).encode() + b" Fixture\r\n"
        raw += b"\r\n".join(headers) + b"\r\n\r\n" + body
        self.response = http.client.HTTPResponse(MemorySocket(raw))
        self.response.begin()
        if failure:
            self.response.read = lambda limit: (_ for _ in ()).throw(failure)
        self.calls, self.closed = [], False

    def request(self, method, path, *, headers, body):
        assert method == "GET" and path == "/login" and body is None
        assert headers == {"User-Agent": f"AI-Threat-Lab/{__version__}"}
        self.calls.append(path)
        assert len(self.calls) == 1, "Retry or linked-resource request"

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True
        self.response.close()


def main():
    socket.create_connection = blocked
    socket.getaddrinfo = blocked
    cases = [
        ("before", Connection(UNSAFE), True, True),
        ("after", Connection(SAFE, safe=True), False, False),
        ("oversize", Connection(UNSAFE + b"x" * LIMIT), True, False),
        ("short", Connection(UNSAFE, short=True), True, False),
        ("read failure", Connection(UNSAFE, failure=TimeoutError("PRIVATE_ERROR")), True, False),
        ("redirect", Connection(UNSAFE, status=302), False, False),
    ]
    with tempfile.TemporaryDirectory(prefix="website acceptance ") as directory:
        for name, connection, expected_headers, expected_html in cases:
            destination = Path(directory) / name
            output = io.StringIO()
            with (
                patch("ai_threat_lab.http_client.public_address", return_value="8.8.8.8") as dns,
                patch("ai_threat_lab.http_client._PinnedHTTPS", return_value=connection) as wire,
                redirect_stdout(output),
            ):
                status = cli_main(["scan", TARGET, "--network", "--allow-host", "website.example",
                                   "--output-dir", str(destination)])
            assert status == 0
            dns.assert_called_once_with("website.example")
            wire.assert_called_once_with("website.example", "8.8.8.8", 15)
            summary = json.loads(output.getvalue())
            assert summary["failed_modules"] == [] and summary["ai_calls"] == 0
            saved = read_bundle(destination)
            assert saved["manifest"]["scope"]["engine"] == "read-only-pipeline-26"
            document = saved["documents"]["assessment.json"]
            checks = {f["check"] for f in document["findings"]}
            assert ("cookie_missing_secure" in checks) is expected_headers
            assert ("html_password_form_get" in checks) is expected_html
            if name in ("oversize", "short", "read failure"):
                assert any(
                    "body" in n.lower() and "unchecked" in n for n in document["not_checked"]
                )
            if name == "redirect":
                assert any("HTTP 302" in n for n in document["not_checked"])
            assert "PRIVATE" not in json.dumps(saved) and "SECRET" not in json.dumps(saved)
            assert connection.closed and len(connection.calls) == 1
        rejected = 0
        for flags in ([], ["--network"], ["--network", "--allow-host", "other.example"]):
            output = io.StringIO()
            with (
                patch("ai_threat_lab.http_client.public_address", side_effect=blocked),
                redirect_stdout(output), redirect_stderr(io.StringIO()),
            ):
                assert cli_main(["audit", TARGET, *flags]) == 2
            rejected += 1
    print(json.dumps({"status": "passed", "synthetic_requests": len(cases),
                      "scope_rejections": rejected, "live_requests": 0, "ai_calls": 0}))


if __name__ == "__main__":
    main()
