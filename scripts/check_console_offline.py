"""Installed-package console/interpretation acceptance; all sockets are blocked."""

import io
import json
import os
import socket
import tempfile
from contextlib import redirect_stderr, redirect_stdout
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
        source, bundle = root / "source.py", root / "saved run"
        source.write_text("eval(input())\n", encoding="utf-8")
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
        assert json.loads(run("setup-check", "--ai-config", config))["live_ready"] is False
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
