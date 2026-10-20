"""Installed fictional-call acceptance with synthetic provider responses and blocked sockets."""

import base64
import io
import json
import os
import socket
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from urllib.parse import parse_qs

import ai_threat_lab.call_cli as entry
from ai_threat_lab.cli import main
from ai_threat_lab.http_client import HttpResponse

ACCOUNT = "AC" + "a" * 32
CALL = "CA" + "b" * 32


def forbidden(*args, **kwargs):
    raise AssertionError("Call acceptance attempted a real network operation")


def run(*args, expected=0):
    output, errors = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        code = main(list(map(str, args)))
    assert code == expected, (args[0], code, errors.getvalue())
    return output.getvalue()


def check():
    socket.socket = socket.create_connection = socket.getaddrinfo = forbidden
    os.environ["TWILIO_AUTH_TOKEN"] = "c" * 32

    class Wire:
        creates = updates = gets = 0
        state = "queued"

        def request(self, url, **kwargs):
            base = f"https://api.twilio.com/2010-04-01/Accounts/{ACCOUNT}/Calls"
            assert url in (base + ".json", base + "/" + CALL + ".json")
            authorization = "Basic " + base64.b64encode(
                (ACCOUNT + ":" + "c" * 32).encode()).decode()
            assert kwargs["headers"]["Authorization"] == authorization
            form = parse_qs(kwargs.get("body", b"").decode())
            create = url == base + ".json"
            if create:
                self.creates += 1
                assert kwargs["method"] == "POST" and form["To"] == ["+12025550100"]
                assert form["From"] == ["+12025550101"]
                assert form["Record"] == form["Transcribe"] == ["false"]
                assert form["TimeLimit"] == ["60"] and form["Timeout"] == ["15"]
                assert "<Gather" not in form["Twiml"][0] and "<Hangup/>" in form["Twiml"][0]
                assert "fictional" in form["Twiml"][0] and "Hang up" in form["Twiml"][0]
            elif kwargs.get("method") == "POST":
                self.updates += 1
                assert form == {"Status": ["canceled"]}
                self.state = "canceled"
            else:
                self.gets += 1
            value = {"sid": CALL, "account_sid": ACCOUNT, "to": "+12025550100",
                     "from": "+12025550101", "direction": "outbound-api",
                     "duration": None, "status": self.state, "private": "PRIVATE"}
            return HttpResponse(201 if create else 200, {}, json.dumps(value).encode())

    wire = Wire()
    entry.PublicHTTPS = lambda *args, **kwargs: wire
    with tempfile.TemporaryDirectory(prefix="call acceptance ") as folder:
        root = Path(folder)
        request, plan, approval = (root / name for name in ("request.json", "plan.json",
                                                          "approval.json"))
        run("campaign-example", "voice_training", "--output", request)
        document = json.loads(request.read_text(encoding="utf-8"))
        document["approved_facts"] = []
        request.write_text(json.dumps(document), encoding="utf-8")
        run("campaign-prepare", request, "--output", plan)
        run("campaign-approve", plan, "--reviewer", "fixture-reviewer", "--output", approval)
        config = root / "call.json"
        config.write_text(json.dumps({"schema_version": 1, "account_sid": ACCOUNT,
                                     "caller": "+12025550101", "usd_per_minute": "0.10",
                                     "max_request_estimate_usd": "0.10"}), encoding="utf-8")
        common = [plan, "--approval", approval, "--call-config", config]
        preview = json.loads(run("call-preview", *common))
        assert wire.creates == wire.gets == wire.updates == 0
        ledger = root / "calls.sqlite"
        send = ["call-submit", *common, "--ledger", ledger,
                "--preview-sha256", preview["preview_sha256"],
                "--allow-call-host", "api.twilio.com"]
        run(*send, "--output-dir", root / "forbidden", expected=2)
        assert not ledger.exists()
        receipt = json.loads(run(*send, "--send-call", "--output-dir", root / "attempt"))
        assert receipt["status"] == "accepted" and "PRIVATE" not in json.dumps(receipt)
        assert "+1202555" not in json.dumps(receipt)
        run(*send, "--send-call", "--output-dir", root / "duplicate", expected=2)
        retrieve = [plan, "--call-config", config, "--ledger", ledger,
                    "--receipt", root / "attempt/result.json",
                    "--allow-call-host", "api.twilio.com"]
        run("call-status", *retrieve, expected=2)
        assert json.loads(run("call-status", *retrieve, "--network"))["provider_status"] == "queued"
        stopped = json.loads(run("call-stop", *retrieve, "--network",
                                 "--output-dir", root / "stop"))
        assert stopped["status"] == "provider_terminal" and stopped["local_cancelled"]
        again = json.loads(run("call-stop", *retrieve, "--network",
                               "--output-dir", root / "terminal"))
        assert again["status"] == "already_terminal"
        run("call-cancel", "--ledger", ledger, "--plan-digest", preview["plan_digest"])
        assert wire.creates == wire.updates == 1 and wire.gets == 3
    print(json.dumps({"status": "passed", "synthetic_calls": 1, "live_requests": 0,
                      "remote_stop_checked": True, "duplicate_blocked": True}))


if __name__ == "__main__":
    check()
