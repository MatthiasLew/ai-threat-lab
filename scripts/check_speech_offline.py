"""Installed stock-speech integration acceptance with blocked sockets and synthetic audio."""

import io
import json
import os
import socket
import tempfile
import wave
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import ai_threat_lab.speech_cli as entry
from ai_threat_lab.cli import main
from ai_threat_lab.http_client import HttpResponse


def forbidden(*args, **kwargs):
    raise AssertionError("Speech acceptance attempted a real connection")


def run(*args, expected=0):
    output, errors = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        code = main(list(map(str, args)))
    assert code == expected, (args[0], code, errors.getvalue())
    return output.getvalue()


def check():
    socket.socket = socket.create_connection = socket.getaddrinfo = forbidden
    os.environ["AI_THREAT_SPEECH_KEY"] = "synthetic-offline-resource-key"
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as audio:
        audio.setparams((1, 2, 24000, 100, "NONE", "not compressed"))
        audio.writeframes(b"\x00" * 200)
    class Wire:
        calls = 0
        def request(self, url, **kwargs):
            assert url == "https://westeurope.tts.speech.microsoft.com/cognitiveservices/v1"
            assert kwargs["method"] == "POST"
            assert b"fictional" in kwargs["body"]
            self.calls += 1
            return HttpResponse(200, {}, buffer.getvalue())
    wire = Wire()
    entry.PublicHTTPS = lambda *a, **kw: wire
    with tempfile.TemporaryDirectory(prefix="speech acceptance ") as folder:
        root = Path(folder)
        request, plan, approval = (root / name for name in ("request.json", "plan.json",
                                                          "approval.json"))
        run("campaign-example", "voice_training", "--output", request)
        run("campaign-prepare", request, "--output", plan)
        run("campaign-approve", plan, "--reviewer", "fixture-reviewer", "--output", approval)
        configuration = root / "speech.json"
        configuration.write_text(json.dumps({
            "schema_version": 1, "region": "westeurope", "voice": "en-US-JennyNeural",
            "usd_per_million_characters": "20", "max_request_usd": "1",
        }), encoding="utf-8")
        common = [plan, "--approval", approval, "--speech-config", configuration]
        preview = json.loads(run("speech-preview", *common))
        assert wire.calls == 0
        journal, output = root / "journal.sqlite", root / "audio"
        generate = ["speech-generate", *common, "--ledger", journal,
                    "--preview-sha256", preview["preview_sha256"],
                    "--allow-speech-host", "westeurope.tts.speech.microsoft.com"]
        run(*generate, "--output-dir", output, expected=2)
        assert not output.exists() and not journal.exists()
        result = json.loads(run(*generate, "--output-dir", output, "--send-script"))
        assert result["status"] == "accepted"
        assert (output / "speech.wav").read_bytes() == buffer.getvalue()
        run(*generate, "--output-dir", root / "duplicate", "--send-script", expected=2)
        assert wire.calls == 1
        status = json.loads(run("speech-status", "--ledger", journal,
                                "--plan-digest", preview["plan_digest"]))
        assert status["attempts"][0]["status"] == "accepted"
        run("speech-cancel", "--ledger", journal, "--plan-digest", preview["plan_digest"])
    print(json.dumps({"status": "passed", "synthetic_generations": 1, "live_requests": 0,
                      "duplicate_blocking": True, "audio_validated": True}))


if __name__ == "__main__":
    check()
