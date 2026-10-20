"""Installed-package console/interpretation acceptance; all sockets are blocked."""

import io
import json
import os
import socket
import tempfile
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

import ai_threat_lab.http_client as http
import ai_threat_lab.integration_cli as integration
from ai_threat_lab.cli import main
from ai_threat_lab.http_client import HttpResponse


def forbidden(*args, **kwargs):
    raise AssertionError("Offline console acceptance attempted network access")


class SyntheticResponses:
    calls = 0
    invalid = False

    def request(self, url, **kwargs):
        assert url == "https://api.openai.com/v1/responses"
        payload = json.loads(kwargs["body"])
        assert payload["tools"] == [] and payload["store"] is False
        assert payload["text"]["format"]["strict"] is True
        source = json.loads(payload["input"])
        assert source["not_checked"]
        observations = [{
            "evidence_id": "0" * 64 if self.invalid else row["evidence_id"],
            "explanation": "Synthetic explanation of the supplied observation.",
            "what_to_review": "Review the evidence in its original source.",
            "suggested_remediation": "Use the recommendation supplied by the prepared tool.",
        } for row in source["findings"]]
        answer = {"summary": "Synthetic partial review", "observations": observations,
                  "uncertainty": "No runtime or real-model validation occurred."}
        result = {"status": "completed", "output": [{"type": "message", "content": [
            {"type": "output_text", "text": json.dumps(answer)}]}],
            "usage": {"input_tokens": 100, "output_tokens": 200}}
        self.calls += 1
        return HttpResponse(200, {}, json.dumps(result).encode())


def run(*args, expected=0):
    output, errors = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        code = main(list(map(str, args)))
    assert code == expected, (args[0], code, errors.getvalue())
    return output.getvalue()


def main_check():
    socket.getaddrinfo = forbidden
    socket.create_connection = forbidden
    socket.socket = forbidden
    os.environ["OPENAI_API_KEY"] = "synthetic-offline-only"
    wire = SyntheticResponses()
    integration.PublicHTTPS = lambda *args, **kwargs: wire
    with tempfile.TemporaryDirectory(prefix="console acceptance ") as folder:
        root = Path(folder)
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("../PRIVATE", "PRIVATE")
        message = EmailMessage()
        message.set_content("PRIVATE")
        message.add_attachment(archive.getvalue(), maintype="application", subtype="zip",
                               filename="PRIVATE.zip")
        eml, attachments = root / "attachments.eml", root / "attachments.json"
        eml.write_bytes(message.as_bytes())
        run("review-attachments", eml, "--output", attachments)
        mail_bundle = root / "mail-scan"
        assert "zip_path_escape" in run("inspect", eml, "--output-dir", mail_bundle)
        eml.unlink()
        assert "zip_path_escape" in run("brief", mail_bundle)
        attachment_summary = run("brief", attachments)
        assert "zip_path_escape" in attachment_summary and "PRIVATE" not in attachment_summary
        class SiteWire:
            calls = []

            def request(self, url):
                self.calls.append(url)
                assert url in ("https://site.example/app/", "https://site.example/app/one")
                body = (b'<a href="one">one</a><a href="/outside">skip</a>'
                        if url.endswith("/") else
                        b'<form><input type="password" name="p"></form>')
                return HttpResponse(200, {"content-type": "text/html"}, body,
                                    (("content-type", "text/html"),))

        site_wire = SiteWire()
        http.PublicHTTPS = lambda *args, **kwargs: site_wire
        site_output = root / "site.json"
        run("review-site", "https://site.example/app/", "--network", "--allow-host",
            "site.example", "--path-prefix", "/app/", "--output", site_output)
        assert len(site_wire.calls) == 2
        assert "html_password_form_get" in run("brief", site_output)
        har = root / "browser.har"
        har.write_text(json.dumps({"log": {"version": "1.2", "entries": [{
            "request": {"url": "https://site.example/PRIVATE?key=PRIVATE",
                        "method": "POST", "postData": {"text": "PRIVATE"}},
            "response": {"status": 200, "headers": [
                {"name": "set-cookie", "value": "session=PRIVATE"},
            ], "content": {}},
        }]}}), encoding="utf-8")
        har_report = run("review-har", har)
        assert "cookie_missing_secure" in har_report
        assert "PRIVATE" not in har_report
        assert len(site_wire.calls) == 2  # HAR did not replay anything through any transport.
        class SessionWire:
            calls = 0
            def request(self, url, **kwargs):
                assert url == "https://site.example/app/"
                assert kwargs["headers"] == {"Cookie": "session=PRIVATE"}
                self.calls += 1
                return HttpResponse(200, {"content-type": "text/html"}, b"<p>fixture</p>")
        session_wire = SessionWire()
        http.PublicHTTPS = lambda *args, **kwargs: session_wire
        session = root / "private.session.json"
        session.write_text(json.dumps({
            "schema_version": 1, "host": "site.example", "path_prefix": "/app/",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "headers": {"Cookie": "session=PRIVATE"},
        }), encoding="utf-8")
        session_report = run(
            "review-site", "https://site.example/app/", "--network", "--allow-host",
            "site.example", "--path-prefix", "/app/", "--session-file", session,
            "--private-path-map", root / "pages.paths.private.json")
        assert session_wire.calls == 1 and "PRIVATE" not in session_report
        assert "Operator-supplied static session" in session_report
        assert json.loads((root / "pages.paths.private.json").read_text())["paths"] == {
            "Session page 0001": "https://site.example/app/",
        }
        run("brief", root / "pages.paths.private.json", expected=2)
        source, bundle = root / "source.py", root / "saved run"
        source.write_text("eval(input())\n", encoding="utf-8")
        external, imported = root / "external.sarif", root / "imported.json"
        run("review-code", source, "--format", "sarif", "--output", external)
        run("review-sarif", external, "--output", imported)
        external.unlink()
        assert "external_sarif_result" in run("brief", imported)
        plan = json.loads(run("plan", source))
        assert plan["tools"][0]["id"] == "python_review" and plan["ai_calls"] == 0
        assert "PY001" in run("inspect", source, "--output-dir", bundle)
        source.unlink()
        assert "PY001" in run("brief", bundle)
        config = root / "config.json"
        config.write_text(json.dumps({
            "schema_version": 1, "model": "fixture-model", "input_usd_per_million": "2",
            "output_usd_per_million": "8", "cache_ttl_seconds": 60,
        }), encoding="utf-8")
        external_preview = json.loads(run("ai-prepare", imported, "--ai-config", config,
                                          "--structured", "--split"))
        assert external_preview["total_finding_count"] == 1
        assert "unverified" in json.dumps(external_preview)
        assert json.loads(run("setup-check", "--ai-config", config))["live_ready"] is False
        smtp, speech = root / "smtp.json", root / "speech.json"
        smtp.write_text(json.dumps({
            "schema_version": 1, "host": "smtp.example.invalid",
            "sender": "PRIVATE@example.invalid", "mode": "starttls", "timeout": 15,
        }), encoding="utf-8")
        speech.write_text(json.dumps({
            "schema_version": 1, "region": "westeurope", "voice": "en-US-JennyNeural",
            "usd_per_million_characters": "20", "max_request_usd": "0.10",
        }), encoding="utf-8")
        setup = run("setup-check", "--smtp-config", smtp, "--speech-config", speech)
        assert "PRIVATE" not in setup
        profiles = json.loads(setup)["integrations"]
        assert [row["id"] for row in profiles] == ["smtp", "speech"]
        assert all(row["status"] == "local_configuration_valid" for row in profiles)
        assert all(row["live_ready"] is False for row in profiles)
        packets = json.loads(run("ai-prepare", bundle, "--ai-config", config,
                                 "--structured", "--split"))
        assert packets["packet_count"] == 1
        ledger, output = root / "cost.sqlite", root / "review.json"
        args = ["ai-review", bundle, "--ai-config", config, "--ledger", ledger]
        estimate = json.loads(run(*args, "--dry-run"))
        assert estimate["reserved_usd"] == packets["packets"][0]["reserved_usd"]
        assert not ledger.exists() and wire.calls == 0
        run(*args, expected=2)
        run(*args, "--send-evidence", "--output", output)
        response = json.loads(output.read_text(encoding="utf-8"))
        assert response["interpretation"]["observations"][0]["evidence_id"] == (
            packets["packets"][0]["input"]["findings"][0]["evidence_id"])
        assert json.loads(run(*args, "--send-evidence"))["status"] == "cached"
        run(*args, "--send-evidence", "--output", output, expected=2)
        assert wire.calls == 1
        run("api-cache-prune", "--ledger", ledger, "--all")
        wire.invalid = True
        run(*args, "--send-evidence", expected=3)
        assert wire.calls == 2
        costs = json.loads(run("api-costs", "--ledger", ledger))
        assert not costs["unconfirmed"]
        assert costs["days"][0]["calls"] == 2
        run("inspect", "https://example.invalid", "--output-dir", root / "forbidden", expected=2)
        assert not (root / "forbidden").exists()
    print(json.dumps({"status": "passed", "synthetic_ai_requests": 2, "live_requests": 0,
                      "source_independent_summary": True, "invalid_advice_rejected": True}))


if __name__ == "__main__":
    main_check()
