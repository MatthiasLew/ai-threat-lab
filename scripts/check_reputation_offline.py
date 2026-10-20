"""Installed hash-reputation workflow with synthetic HTTP and blocked sockets."""

import io
import json
import os
import socket
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import ai_threat_lab.reputation_cli as adapter
from ai_threat_lab.cli import main
from ai_threat_lab.file_reputation import HOST, STATS
from ai_threat_lab.http_client import HttpResponse


def forbidden(*args, **kwargs):
    raise AssertionError("Reputation acceptance attempted live networking")


def run(*args, expected=0):
    output, errors = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        code = main(list(map(str, args)))
    assert code == expected, (args[0], code, errors.getvalue())
    return output.getvalue()


def main_check():
    socket.socket = socket.create_connection = socket.getaddrinfo = forbidden
    os.environ["VIRUSTOTAL_API_KEY"] = "synthetic-offline-key"
    with tempfile.TemporaryDirectory(prefix="reputation acceptance ") as folder:
        root = Path(folder)
        source, output = root / "PRIVATE.bin", root / "report.json"
        source.write_bytes(b"PRIVATE inert fixture")
        preview = json.loads(run("reputation-preview", source))
        digest, size = preview["sha256"], preview["bytes"]
        assert not preview["network_called"] and not preview["credentials_inspected"]
        assert "PRIVATE" not in json.dumps(preview)

        class Wire:
            calls = 0
            status = 200

            def request(self, url, **kwargs):
                assert url == f"https://{HOST}/api/v3/files/{digest}"
                assert kwargs == {"headers": {"x-apikey": "synthetic-offline-key"}}
                self.calls += 1
                document = {"data": {"type": "file", "id": digest, "attributes": {
                    "sha256": digest, "size": size, "last_analysis_date": 1700000000,
                    "last_analysis_stats": {key: int(key == "malicious") for key in STATS},
                    "names": ["PRIVATE"],
                }}}
                return HttpResponse(self.status, {}, json.dumps(document).encode())

        wire = Wire()
        adapter.PublicHTTPS = lambda *args, **kwargs: wire
        args = ["review-reputation", source, "--allow-host", HOST, "--sha256", digest]
        run(*args, expected=2)
        assert wire.calls == 0
        args += ["--network", "--share-hash"]
        run(*args, "--output", output)
        run(*args, "--output", output, expected=2)
        assert wire.calls == 1
        assert "PRIVATE" not in output.read_text(encoding="utf-8")
        wire.status = 429
        failure = root / "failed.json"
        run(*args, "--output", failure, expected=3)
        assert wire.calls == 2
        source.unlink()
        assert "file_reputation_counts" in run("brief", output)
        assert "lookup failed" in run("brief", failure)
        assert "binary_metadata" in run("brief", failure)
    print(json.dumps({"status": "passed", "synthetic_requests": 2, "live_requests": 0,
                      "source_independent_summary": True, "file_bytes_uploaded": False}))


if __name__ == "__main__":
    main_check()
