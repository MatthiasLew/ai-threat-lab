"""Preview-bound stock-voice synthesis for fictional local training assets."""

import hashlib
import io
import json
import os
import re
import struct
import wave
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from .ai_costs import money, usd
from .campaigns import TemplateContentProvider, campaign_scenarios
from .models import ValidationError
from .providers import ProviderError
from .training_lab import validate_approval

REGIONS = ("eastus", "westeurope", "northeurope")
VOICES = ("en-US-JennyNeural", "en-US-ChristopherNeural")
MAX_AUDIO = 6 * 1024 * 1024
FORMAT = "riff-24khz-16bit-mono-pcm"
NOTICE = (
    "Stock synthetic voice for fictional training; no voice cloning, call placement, "
    "recording or recipient data collection. The generated audio must be reviewed before use. "
    "Local configured price estimates do not verify provider billing."
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class SpeechConfig:
    region: str
    voice: str
    usd_per_million_characters: str
    max_request_usd: str

    def __post_init__(self):
        if self.region not in REGIONS or self.voice not in VOICES:
            raise ValidationError("Choose a supported stock speech voice and region")
        money(self.usd_per_million_characters)
        money(self.max_request_usd)

    @property
    def host(self):
        return f"{self.region}.tts.speech.microsoft.com"

    @property
    def digest(self):
        return sha(json.dumps(asdict(self), sort_keys=True).encode())

    @classmethod
    def from_document(cls, value):
        keys = {
            "schema_version",
            "region",
            "voice",
            "usd_per_million_characters",
            "max_request_usd",
        }
        if (
            not isinstance(value, dict)
            or set(value) != keys
            or (type(value.get("schema_version")) is not int or value["schema_version"] != 1)
        ):
            raise ValidationError("Invalid speech configuration")
        return cls(**{key: item for key, item in value.items() if key != "schema_version"})


def preview(plan, approval, config, *, now=None):
    validate_approval(plan, approval, now or datetime.now(timezone.utc))
    if (
        plan.channel != "voice"
        or plan.scenario_id != "voice_training"
        or not plan.scope.identity_reference.startswith("fictional:")
        or len(plan.content.body) > 3000
    ):
        raise ValidationError("Speech synthesis requires a bounded fictional voice plan")
    scenario = next(s for s in campaign_scenarios() if s.id == "voice_training")
    expected = TemplateContentProvider().prepare(
        scenario, plan.approved_facts, plan.scope.identity_reference
    )
    if plan.content != expected or re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", plan.content.body):
        raise ValidationError("Speech requires the exact built-in fictional script")
    ssml = (
        f'<speak version="1.0" xmlns="http://www.w3.org/2001/10/synthesis" '
        f'xml:lang="en-US"><voice name="{config.voice}">'
        f"{escape(plan.content.body)}</voice></speak>"
    )
    raw = ssml.encode("utf-8")
    # UTF-8 bytes of the entire SSML are a conservative local character-count basis,
    # not provider usage. Markup is included to avoid understating that local estimate.
    estimate = (len(raw) * money(config.usd_per_million_characters) + 999999) // 1000000
    if estimate > money(config.max_request_usd):
        raise ValidationError("Speech preview exceeds the configured per-request estimate limit")
    result = {
        "schema_version": 1,
        "plan_digest": plan.digest,
        "configuration_sha256": config.digest,
        "endpoint": f"https://{config.host}/cognitiveservices/v1",
        "voice": config.voice,
        "output_format": FORMAT,
        "ssml": ssml,
        "request_sha256": sha(raw),
        "estimated_usd": usd(estimate),
        "estimate_basis_utf8_bytes": len(raw),
        "notice": NOTICE,
        "network_called": False,
    }
    result["preview_sha256"] = sha(json.dumps(result, sort_keys=True).encode())
    return result


def audio_metadata(raw):
    if not isinstance(raw, bytes) or not 44 <= len(raw) <= MAX_AUDIO:
        raise ProviderError("Speech output is missing or outside the audio size bound")
    if raw[:4] != b"RIFF" or int.from_bytes(raw[4:8], "little") + 8 != len(raw):
        raise ProviderError("Speech output has an invalid RIFF boundary")
    try:
        with wave.open(io.BytesIO(raw), "rb") as audio:
            if (
                audio.getnchannels(),
                audio.getsampwidth(),
                audio.getframerate(),
                audio.getcomptype(),
            ) != (1, 2, 24000, "NONE"):
                raise ProviderError("Speech output is not the requested mono PCM format")
            frames = audio.getnframes()
            if not 1 <= frames <= 24000 * 120 or len(audio.readframes(frames)) != frames * 2:
                raise ProviderError("Speech output is empty, truncated or longer than 120 seconds")
    except (wave.Error, EOFError, struct.error):
        raise ProviderError("Speech output has an invalid WAV structure") from None
    return {
        "sha256": sha(raw),
        "bytes": len(raw),
        "frames": frames,
        "sample_rate": 24000,
        "channels": 1,
        "sample_width": 2,
    }


def generate(
    plan,
    approval,
    config,
    journal,
    expected_preview,
    *,
    allowed_host,
    output_dir,
    client,
    clock=None,
):
    from pathlib import Path

    clock = clock or (lambda: datetime.now(timezone.utc))
    prepared = preview(plan, approval, config, now=clock())
    if prepared["preview_sha256"] != expected_preview or allowed_host != config.host:
        raise ValidationError("Confirm the exact speech preview and provider host")
    secret = os.environ.get("AI_THREAT_SPEECH_KEY", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", secret):
        raise ProviderError("Configure the speech resource key outside source control")
    destination = Path(output_dir)
    destination.mkdir(exist_ok=False)
    key = journal.claim(plan.digest, "stock_speech_asset", config.digest)
    receipt = {
        "schema_version": 1,
        "plan_digest": plan.digest,
        "preview_sha256": expected_preview,
        "configuration_sha256": config.digest,
        "status": "pending",
        "notice": NOTICE,
    }
    # This durable local marker remains if the process is interrupted before receiving audio.
    marker = destination / "attempt.json"
    with marker.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    outcome, submitted = "unknown", False
    try:
        validate_approval(plan, approval, clock())
        if journal.status(plan.digest)["cancelled"]:
            raise ValidationError("Speech generation cancelled before submission")
        submitted = True
        response = client.request(
            prepared["endpoint"],
            method="POST",
            headers={
                "Ocp-Apim-Subscription-Key": secret,
                "Content-Type": "application/ssml+xml",
                "X-Microsoft-OutputFormat": FORMAT,
            },
            body=prepared["ssml"].encode("utf-8"),
        )
        if response.status != 200:
            raise ProviderError("Speech provider did not return a successful audio response")
        if response.body_status != "complete":
            raise ProviderError("Speech provider returned incomplete audio")
        metadata = audio_metadata(response.body)
        with (destination / "speech.wav").open("xb") as stream:
            stream.write(response.body)
            stream.flush()
            os.fsync(stream.fileno())
        receipt["audio"] = metadata
        outcome = "accepted"
    except (ProviderError, OSError, ValidationError):
        # Billing may have occurred even for an error or locally unusable output.
        outcome = "unknown" if submitted else "rejected"
        receipt["diagnostic"] = (
            "Generation unconfirmed; inspect provider usage before retrying."
            if submitted
            else "Generation stopped before submission; no request was sent."
        )
    journal.outcome(key, outcome)
    receipt["status"] = outcome
    with (destination / "result.json").open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
    return receipt
