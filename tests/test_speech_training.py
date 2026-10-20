import io
import json
import wave
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from ai_threat_lab.contracts import plan_from_document
from ai_threat_lab.dispatch_journal import DispatchJournal
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderConfig, ProviderError, ProviderRegistry
from ai_threat_lab.speech_training import SpeechConfig, audio_metadata, generate, preview
from ai_threat_lab.workflows import approve_campaign, example_request, prepare_campaign

EXPIRES = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


def approved(facts=()):
    request = example_request("voice_training")
    request["scope"]["expires_at"] = EXPIRES
    request["approved_facts"] = list(facts)
    doc = prepare_campaign(request, ProviderRegistry(), ProviderConfig())
    return plan_from_document(doc), approve_campaign(doc, "reviewer")


def config(**changes):
    return SpeechConfig(**{"region": "westeurope", "voice": "en-US-JennyNeural",
                           "usd_per_million_characters": "20", "max_request_usd": "1",
                           **changes})


def wav(*, rate=24000, channels=1, width=2, frames=100):
    stream = io.BytesIO()
    with wave.open(stream, "wb") as audio:
        audio.setparams((channels, width, rate, frames, "NONE", "not compressed"))
        audio.writeframes(b"\x00" * frames * channels * width)
    return stream.getvalue()


class Wire:
    def __init__(self, response=None, error=None):
        self.response = response or HttpResponse(200, {}, wav())
        self.error = error
        self.calls = []

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return self.response


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setenv("AI_THREAT_SPEECH_KEY", "synthetic-key-for-offline-only")


def run(tmp_path, wire, *, settings=None, expected=None, host=None, journal=None):
    plan, approval = approved()
    settings = settings or config()
    prepared = preview(plan, approval, settings)
    journal = journal or DispatchJournal(tmp_path / "generation.sqlite", create=True)
    result = generate(plan, approval, settings, journal,
                      expected or prepared["preview_sha256"], allowed_host=host or settings.host,
                      output_dir=tmp_path / "audio", client=wire)
    return result, journal, plan


def test_preview_without_key_escapes_ssml_and_omits_destinations(monkeypatch):
    monkeypatch.delenv("AI_THREAT_SPEECH_KEY", raising=False)
    plan, approval = approved(("<audio src='https://PRIVATE'/> & text",))
    prepared = preview(plan, approval, config())
    assert "<audio" not in prepared["ssml"]
    assert "&lt;audio" in prepared["ssml"] and "&amp;" in prepared["ssml"]
    assert all(recipient not in json.dumps(prepared) for recipient in plan.recipients)
    assert not prepared["network_called"]
    assert prepared["estimated_usd"] != "0.000000000"
    with pytest.raises(ValidationError, match="estimate"):
        preview(plan, approval, config(max_request_usd="0.000001"))


@pytest.mark.parametrize("change", [
    {"region": "evil.example"}, {"voice": "clone:someone"}, {"max_request_usd": "NaN"},
    {"usd_per_million_characters": "0"},
])
def test_config_rejects_unbounded_or_unsupported_options(change):
    with pytest.raises(ValidationError):
        config(**change)


def test_exact_template_required():
    plan, approval = approved()
    changed = replace(plan, content=replace(plan.content, body="arbitrary"))
    with pytest.raises(ValidationError):
        preview(changed, replace(approval, plan_digest=changed.digest), config())


def test_generation_persists_valid_audio_and_blocks_duplicate(tmp_path, key):
    wire = Wire()
    result, journal, plan = run(tmp_path, wire)
    assert result["status"] == "accepted"
    assert (tmp_path / "audio" / "speech.wav").read_bytes() == wav()
    assert result["audio"] == audio_metadata(wav())
    assert journal.status(plan.digest)["attempts"][0]["status"] == "accepted"
    assert len(wire.calls) == 1
    endpoint, request = wire.calls[0]
    assert endpoint == "https://westeurope.tts.speech.microsoft.com/cognitiveservices/v1"
    assert request["headers"]["X-Microsoft-OutputFormat"] == "riff-24khz-16bit-mono-pcm"
    assert "synthetic-key" not in json.dumps(result)
    second = tmp_path / "second"
    second.mkdir()
    with pytest.raises(ValidationError):
        run(second, wire, journal=DispatchJournal(journal.path))
    assert len(wire.calls) == 1


@pytest.mark.parametrize("wire", [
    Wire(HttpResponse(429, {}, b"PRIVATE")),
    Wire(HttpResponse(200, {}, b"PRIVATE")),
    Wire(HttpResponse(200, {}, wav(), body_status="size_limit")),
    Wire(error=ProviderError("PRIVATE")),
])
def test_unconfirmed_cost_and_output_does_not_retry(tmp_path, key, wire):
    result, journal, plan = run(tmp_path, wire)
    assert result["status"] == "unknown"
    assert journal.status(plan.digest)["attempts"][0]["status"] == "unknown"
    assert not (tmp_path / "audio" / "speech.wav").exists()
    assert "PRIVATE" not in json.dumps(result)
    assert len(wire.calls) == 1


def test_wrong_preview_missing_key_and_existing_output_do_not_call(tmp_path, monkeypatch):
    monkeypatch.delenv("AI_THREAT_SPEECH_KEY", raising=False)
    wire = Wire()
    with pytest.raises(ValidationError):
        run(tmp_path, wire, expected="0" * 64)
    with pytest.raises(ProviderError):
        run(tmp_path, wire)
    monkeypatch.setenv("AI_THREAT_SPEECH_KEY", "synthetic-key-for-offline-only")
    (tmp_path / "audio").mkdir()
    with pytest.raises(FileExistsError):
        run(tmp_path, wire)
    assert not wire.calls


def test_cancel_and_interruption_are_durable(tmp_path, key):
    plan, approval = approved()
    journal = DispatchJournal(tmp_path / "generation.sqlite", create=True)
    journal.cancel(plan.digest)
    wire = Wire()
    with pytest.raises(ValidationError):
        run(tmp_path, wire, journal=journal)
    assert not wire.calls
    other = tmp_path / "other"
    other.mkdir()
    wire = Wire(error=KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        run(other, wire)
    status = DispatchJournal(other / "generation.sqlite").status(plan.digest)
    assert status["attempts"][0]["status"] == "pending"
    assert (other / "audio" / "attempt.json").exists()
    assert not (other / "audio" / "result.json").exists()


@pytest.mark.parametrize("raw", [
    b"", b"RIFF", wav(rate=8000), wav(channels=2), wav(width=1), wav(frames=0),
    wav()[:-2], wav() + b"trailer",
])
def test_audio_validation(raw):
    with pytest.raises(ProviderError):
        audio_metadata(raw)


def test_native_transport_allows_only_explicit_speech_endpoint(monkeypatch):
    import ai_threat_lab.http_client as http
    from ai_threat_lab.http_client import PublicHTTPS

    calls = []
    class Response:
        status, length = 200, 3
        def getheaders(self):
            return []
        def read(self, limit):
            self.length = 0
            return b"abc"
    class Connection:
        def request(self, method, path, **kwargs):
            calls.append((method, path, kwargs))
        def getresponse(self):
            return Response()
        def close(self):
            pass
    monkeypatch.setattr(http, "public_address", lambda _: "8.8.8.8")
    monkeypatch.setattr(http, "_PinnedHTTPS", lambda *a: Connection())
    allowed = "westeurope.tts.speech.microsoft.com"
    client = PublicHTTPS([allowed])
    assert client.request(f"https://{allowed}/cognitiveservices/v1", method="POST").status == 200
    for url in (f"https://{allowed}/other", f"https://{allowed}/cognitiveservices/v1?x=y"):
        with pytest.raises(ValidationError):
            client.request(url, method="POST")
    assert len(calls) == 1


def test_cli_preview_generation_status_and_cancel(tmp_path, monkeypatch, capsys, key):
    import ai_threat_lab.speech_cli as entry
    from ai_threat_lab.cli import main
    from ai_threat_lab.contracts import approval_to_document, plan_to_document

    plan, approval = approved()
    paths = {}
    for name, value in (
        ("plan", plan_to_document(plan)), ("approval", approval_to_document(approval)),
        ("config", {"schema_version": 1, "region": "westeurope", "voice": "en-US-JennyNeural",
                    "usd_per_million_characters": "20", "max_request_usd": "1"}),
    ):
        paths[name] = tmp_path / f"{name}.json"
        paths[name].write_text(json.dumps(value))
    common = [str(paths["plan"]), "--approval", str(paths["approval"]),
              "--speech-config", str(paths["config"])]
    prepared = tmp_path / "preview.json"
    assert main(["speech-preview", *common, "--output", str(prepared)]) == 0
    digest = json.loads(prepared.read_text())["preview_sha256"]
    wire = Wire()
    monkeypatch.setattr(entry, "PublicHTTPS", lambda *a, **kw: wire)
    journal, folder = tmp_path / "journal.sqlite", tmp_path / "audio"
    args = ["speech-generate", *common, "--output-dir", str(folder), "--ledger", str(journal),
            "--preview-sha256", digest,
            "--allow-speech-host", "westeurope.tts.speech.microsoft.com"]
    assert main(args) == 2
    assert not folder.exists() and not journal.exists()
    assert main([*args, "--send-script"]) == 0
    assert len(wire.calls) == 1 and (folder / "speech.wav").exists()
    assert main([*args, "--send-script"]) == 2
    assert main(["speech-status", "--ledger", str(journal), "--plan-digest", plan.digest]) == 0
    assert main(["speech-cancel", "--ledger", str(journal), "--plan-digest", plan.digest]) == 0
    assert "synthetic-key" not in capsys.readouterr().out


def test_expiry_before_submission_is_rejected_without_call(tmp_path, key):
    plan, approval = approved()
    settings = config()
    prepared = preview(plan, approval, settings)
    journal = DispatchJournal(tmp_path / "journal.sqlite", create=True)
    times = iter((datetime.now(timezone.utc), plan.scope.expires_at + timedelta(seconds=1)))
    wire = Wire()
    result = generate(plan, approval, settings, journal, prepared["preview_sha256"],
                      allowed_host=settings.host, output_dir=tmp_path / "audio",
                      client=wire, clock=lambda: next(times))
    assert result["status"] == "rejected" and not wire.calls
    assert journal.status(plan.digest)["attempts"][0]["status"] == "rejected"


def test_audio_write_failure_keeps_unknown_cost(tmp_path, key, monkeypatch):
    from pathlib import Path
    original = Path.open
    def guarded(path, *args, **kwargs):
        if path.name == "speech.wav":
            raise OSError("PRIVATE PATH")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", guarded)
    result, journal, plan = run(tmp_path, Wire())
    assert result["status"] == "unknown"
    assert "PRIVATE" not in json.dumps(result)
    assert journal.status(plan.digest)["attempts"][0]["status"] == "unknown"


def test_console_speech_generation_refusal(monkeypatch):
    from ai_threat_lab.cli import main
    answers = iter(["13", "2", "plan.json", "approval.json", "config.json",
                    "digest", "host", "journal", "audio", "n", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert main(["console"]) == 0
