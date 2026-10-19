"""Installed GitHub collector acceptance using synthetic responses and blocked sockets."""

import base64
import hashlib
import io
import json
import os
import socket
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ai_threat_lab.cli import main as cli_main
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.providers import ProviderError
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import read_bundle

TARGET = "https://github.com/fixture-owner/fixture-repository"
BASE = "https://api.github.com/repos/fixture-owner/fixture-repository"
COMMIT = "a" * 40


def blocked(*args, **kwargs):
    raise AssertionError("Offline GitHub acceptance must not access the network")


def fixture_blob(path, content):
    raw = content.encode("utf-8")
    digest = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return {
        "path": path, "mode": "100644", "type": "blob", "size": len(raw), "sha": digest,
    }, {"encoding": "base64", "content": base64.b64encode(raw).decode("ascii")}


class SyntheticHTTP:
    def __init__(self, records):
        self.records = list(records)
        self.calls = []

    def request(self, url, **kwargs):
        assert kwargs.get("method", "GET") == "GET"
        assert kwargs.get("headers", {}).get("Authorization") == "Bearer offline-fixture-token"
        assert self.records, "Unexpected extra request or retry"
        expected_url, body = self.records.pop(0)
        assert url == expected_url
        self.calls.append(url)
        return body if isinstance(body, HttpResponse) else HttpResponse(
            200, {}, json.dumps(body).encode("utf-8")
        )


def main():
    socket.create_connection = blocked
    socket.getaddrinfo = blocked
    os.environ["GITHUB_TOKEN"] = "offline-fixture-token"
    requirement, requirement_blob = fixture_blob("requirements.txt", "fixture-package==1.2.3\n")
    code, code_blob = fixture_blob("z.py", "eval(untrusted)\n")
    client = SyntheticHTTP([
        (BASE, {"default_branch": "main"}),
        (BASE + "/commits/main", {"sha": COMMIT}),
        (BASE + f"/git/trees/{COMMIT}?recursive=1", {
            "truncated": False,
            "tree": [code, requirement, dict(requirement, path="requirements-dev.txt")],
        }),
        (BASE + "/git/blobs/" + requirement["sha"], requirement_blob),
        (BASE + "/git/blobs/" + code["sha"], code_blob),
    ])
    with tempfile.TemporaryDirectory(prefix="github acceptance ") as directory:
        destination = Path(directory) / "saved scan"
        output = io.StringIO()
        with (
            patch("ai_threat_lab.scan_cli.PublicHTTPS", return_value=client) as http,
            redirect_stdout(output),
        ):
            status = cli_main([
                "scan", TARGET, "--network", "--allow-host", "github.com",
                "--output-dir", str(destination),
            ])
        http.assert_called_once_with(["api.github.com"], max_bytes=8 * 1024 * 1024)
        assert status == 0
        summary = json.loads(output.getvalue())
        assert summary["ai_calls"] == 0 and summary["failed_modules"] == []
        saved = read_bundle(destination)
        inventory = saved["documents"]["dependency-inventory.json"]
        assert inventory["packages"][0]["sources"] == [
            "requirements-dev.txt:1", "requirements.txt:1",
        ]
        assert "eval(untrusted)" not in json.dumps(saved)
        assert len(client.calls) == 5 and not client.records
    negative_checks = 0
    for invalid in (None, True, 123, [], {}):
        broken = SyntheticHTTP([
            (BASE, {"default_branch": "main"}),
            (BASE + "/commits/main", {"sha": invalid}),
        ])
        try:
            GithubAudit(broken).collect(TARGET)
        except ProviderError:
            negative_checks += 1
        else:
            raise AssertionError("Malformed SHA was accepted")
        assert len(broken.calls) == 2 and not broken.records
    for status in (403, 429):
        denied = SyntheticHTTP([(BASE, HttpResponse(status, {}, b"PRIVATE_RESPONSE"))])
        try:
            GithubAudit(denied).collect(TARGET)
        except ProviderError as exc:
            assert "PRIVATE_RESPONSE" not in str(exc)
            negative_checks += 1
        else:
            raise AssertionError("Failed HTTP response was accepted")
        assert len(denied.calls) == 1 and not denied.records
    print(json.dumps({"status": "passed", "positive_requests": 5,
                      "negative_controls": negative_checks, "live_requests": 0, "ai_calls": 0}))


if __name__ == "__main__":
    main()
