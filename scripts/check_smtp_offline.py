"""Installed SMTP lifecycle with sockets blocked and a synthetic protocol endpoint."""

import io
import json
import os
import socket
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import ai_threat_lab.smtp_training as smtp
from ai_threat_lab.cli import main


def blocked(*args, **kwargs):
    raise AssertionError("SMTP acceptance attempted a real connection")


def run(*args, expected=0):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        result = main(list(map(str, args)))
    assert result == expected, stderr.getvalue()
    return stdout.getvalue()


def main_check():
    socket.getaddrinfo = socket.create_connection = socket.socket = blocked
    os.environ["AI_THREAT_SMTP_USER"] = "synthetic-user"
    os.environ["AI_THREAT_SMTP_PASSWORD"] = "synthetic-password"

    class Endpoint:
        submissions = 0
        uncertain = False

        def login(self, username, password):
            assert username == "synthetic-user" and password == "synthetic-password"

        def sendmail(self, sender, recipients, raw):
            assert sender == "training@example.invalid"
            assert recipients == ["participant@example.invalid"]
            assert b"fictional" in raw and b"password" in raw
            self.submissions += 1
            if self.uncertain:
                raise OSError("PRIVATE synthetic response lost")
            return {}

        def close(self):
            pass

    endpoint = Endpoint()
    smtp._connection = lambda config: endpoint
    with tempfile.TemporaryDirectory(prefix="smtp acceptance ") as directory:
        root = Path(directory)
        settings, ledger = root / "smtp.json", root / "dispatch.sqlite"
        settings.write_text(json.dumps({
            "schema_version": 1, "host": "smtp.example.invalid",
            "sender": "training@example.invalid",
        }), encoding="utf-8")
        for index in range(2):
            request, plan, approval = (root / f"{name}-{index}.json"
                                       for name in ("request", "plan", "approval"))
            run("campaign-example", "email_training", "--output", request)
            document = json.loads(request.read_text(encoding="utf-8"))
            document["scope"]["campaign_id"] = f"fixture-{index}"
            request.write_text(json.dumps(document), encoding="utf-8")
            run("campaign-prepare", request, "--output", plan)
            run("campaign-approve", plan, "--reviewer", "fixture", "--output", approval)
            base = [plan, "--approval", approval, "--smtp-config", settings]
            preview = json.loads(run("smtp-preview", *base))
            args = ["smtp-send", *base, "--ledger", ledger,
                    "--preview-sha256", preview["preview_sha256"],
                    "--allow-smtp-host", "smtp.example.invalid", "--send-approved"]
            endpoint.uncertain = bool(index)
            result = json.loads(run(*args, expected=3 if index else 0))
            assert result["attempts"][0]["status"] == ("unknown" if index else "accepted")
            assert "PRIVATE" not in json.dumps(result)
            run(*args, expected=2)
            assert endpoint.submissions == index + 1
            run("smtp-cancel", "--ledger", ledger, "--plan-digest", preview["plan_digest"])
            status = json.loads(run("smtp-status", "--ledger", ledger,
                                    "--plan-digest", preview["plan_digest"]))
            assert status["cancelled"]
    print(json.dumps({"status": "passed", "synthetic_submissions": endpoint.submissions,
                      "live_submissions": 0, "duplicate_blocking": True,
                      "unknown_outcome_preserved": True}))


if __name__ == "__main__":
    main_check()
