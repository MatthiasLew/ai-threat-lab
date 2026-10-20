"""Installed fictional-avatar lifecycle with synthetic jobs/media and blocked sockets."""

import io
import json
import os
import socket
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import ai_threat_lab.avatar_cli as entry
from ai_threat_lab.cli import main
from ai_threat_lab.http_client import HttpResponse

HOST = "fixture.cognitiveservices.azure.com"
BLOB = "fixture.blob.core.windows.net"


def forbidden(*args, **kwargs):
    raise AssertionError("Avatar acceptance attempted live networking")


def run(*args, expected=0):
    output, errors = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        code = main(list(map(str, args)))
    assert code == expected, (args[0], code, errors.getvalue())
    return output.getvalue()


def box(kind, body=b""):
    return (len(body) + 8).to_bytes(4, "big") + kind + body


def check():
    socket.socket = socket.create_connection = socket.getaddrinfo = forbidden
    os.environ["AI_THREAT_AVATAR_KEY"] = "synthetic-offline-resource-key"
    media = box(b"ftyp", b"isom\x00\x00\x00\x00") + box(b"moov") + box(b"mdat", b"fixture")

    class Wire:
        puts = 0
        gets = 0
        assets = 0
        payload = None

        def request(self, url, **kwargs):
            if url.startswith(f"https://{BLOB}/"):
                assert kwargs == {}  # Resource key must not be sent to storage.
                self.assets += 1
                return HttpResponse(200, {}, media)
            assert url.startswith(f"https://{HOST}/avatar/batchsyntheses/")
            assert url.endswith("?api-version=2024-08-01")
            assert kwargs["headers"]["Ocp-Apim-Subscription-Key"] == (
                "synthetic-offline-resource-key")
            create = kwargs.get("method") == "PUT"
            if create:
                self.puts += 1
                self.payload = json.loads(kwargs["body"])
                assert self.payload["avatarConfig"]["customized"] is False
                assert "fictional" in self.payload["inputs"][0]["content"]
            else:
                self.gets += 1
            assert self.payload is not None
            result = {
                **self.payload, "id": url.split("?")[0].rsplit("/", 1)[-1],
                "status": "NotStarted" if create else "Succeeded", "customVoices": {},
                "properties": {"durationInMilliseconds": 3000, "succeededCount": 1,
                               "failedCount": 0},
                "outputs": {"result": f"https://{BLOB}/batchsynthesis-output/a/b/0001.mp4"
                           "?sig=PRIVATE"},
            }
            return HttpResponse(201 if create else 200, {}, json.dumps(result).encode())

    wire = Wire()
    entry.PublicHTTPS = lambda *args, **kwargs: wire
    with tempfile.TemporaryDirectory(prefix="avatar acceptance ") as folder:
        root = Path(folder)
        request, plan, approval = (root / name for name in ("request.json", "plan.json",
                                                          "approval.json"))
        run("campaign-example", "video_training", "--output", request)
        run("campaign-prepare", request, "--output", plan)
        run("campaign-approve", plan, "--reviewer", "fixture-reviewer", "--output", approval)
        config = root / "avatar.json"
        config.write_text(json.dumps({
            "schema_version": 1, "resource_host": HOST, "voice": "en-US-JennyNeural",
            "usd_per_video_minute": "0.50", "max_request_estimate_usd": "1.00",
        }), encoding="utf-8")
        common = [plan, "--approval", approval, "--avatar-config", config]
        preview = json.loads(run("avatar-preview", *common))
        assert wire.puts == wire.gets == wire.assets == 0
        ledger = root / "jobs.sqlite"
        submit = ["avatar-submit", *common, "--ledger", ledger,
                  "--preview-sha256", preview["preview_sha256"], "--allow-avatar-host", HOST]
        run(*submit, "--output-dir", root / "forbidden", expected=2)
        assert not ledger.exists()
        result = json.loads(run(*submit, "--send-script", "--output-dir", root / "attempt"))
        assert result["status"] == "accepted"
        run(*submit, "--send-script", "--output-dir", root / "duplicate", expected=2)
        assert wire.puts == 1
        retrieve = ["--avatar-config", config, "--ledger", ledger,
                    "--plan-digest", preview["plan_digest"], "--allow-avatar-host", HOST]
        run("avatar-status", *retrieve, expected=2)
        status = json.loads(run("avatar-status", *retrieve, "--network"))
        assert status["asset_host"] == BLOB and "PRIVATE" not in json.dumps(status)
        downloaded = json.loads(run(
            "avatar-download", *retrieve, "--network", "--allow-asset-host", BLOB,
            "--output-dir", root / "download"))
        assert downloaded["status"] == "downloaded" and "PRIVATE" not in json.dumps(downloaded)
        assert (root / "download/avatar.mp4").read_bytes() == media
        attached = root / "media-plan.json"
        run("avatar-attach", *common, "--download-dir", root / "download", "--output", attached)
        updated = json.loads(attached.read_text(encoding="utf-8"))
        assert updated["plan_digest"] != preview["plan_digest"]
        assert updated["plan"]["content"]["media_sha256"] == downloaded["video"]["sha256"]
        run("campaign-approve", attached, "--reviewer", "fixture-media-reviewer",
            "--output", root / "media-approval.json")
        run("avatar-cancel", "--ledger", ledger, "--plan-digest", preview["plan_digest"])
        assert wire.puts == 1 and wire.gets == 2 and wire.assets == 1
    print(json.dumps({"status": "passed", "synthetic_submissions": 1, "live_requests": 0,
                      "download_verified": True, "new_approval_required": True}))


if __name__ == "__main__":
    check()
