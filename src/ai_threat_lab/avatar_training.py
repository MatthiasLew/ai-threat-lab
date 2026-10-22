"""Fictional stock-avatar request preparation and bounded media response validation."""

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .ai_costs import money, usd
from .campaigns import TemplateContentProvider, campaign_scenarios
from .dispatch_journal import delivery_key
from .models import ValidationError
from .providers import ProviderError
from .speech_training import VOICES
from .training_lab import validate_approval

API_VERSION = "2024-08-01"
MAX_VIDEO = 8 * 1024 * 1024
ASSET = "stock_avatar_asset"
NOTICE = (
    "Stock avatar for a fictional training script. No likeness or voice cloning, calls or "
    "distribution. Review and approve the exact downloaded asset before use. "
    "The two-minute planning estimate is not a provider-enforced billing cap."
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class AvatarConfig:
    resource_host: str
    voice: str
    usd_per_video_minute: str
    max_request_estimate_usd: str

    def __post_init__(self):
        if not isinstance(self.resource_host, str) or not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cognitiveservices\.azure\.com",
            self.resource_host,
        ):
            raise ValidationError("Use the exact Azure resource hostname without a URL or key")
        if self.voice not in VOICES:
            raise ValidationError("Choose a supported stock English voice")
        money(self.usd_per_video_minute)
        money(self.max_request_estimate_usd)

    @classmethod
    def from_document(cls, value):
        fields = {
            "schema_version",
            "resource_host",
            "voice",
            "usd_per_video_minute",
            "max_request_estimate_usd",
        }
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1
        ):
            raise ValidationError("Invalid stock-avatar configuration")
        return cls(**{key: item for key, item in value.items() if key != "schema_version"})

    @property
    def digest(self):
        return sha(encoded(asdict(self)))

    def endpoint(self, plan_digest):
        job = delivery_key(plan_digest, ASSET)
        return f"https://{self.resource_host}/avatar/batchsyntheses/{job}?api-version={API_VERSION}"


def preview(plan, approval, config, *, now=None):
    validate_approval(plan, approval, now or datetime.now(timezone.utc))
    if (
        plan.channel != "video"
        or plan.scenario_id != "video_training"
        or not plan.scope.identity_reference.startswith("fictional:")
        or len(plan.content.body) > 600
    ):
        raise ValidationError("Avatar synthesis requires a short fictional video plan")
    scenario = next(row for row in campaign_scenarios() if row.id == "video_training")
    expected = TemplateContentProvider().prepare(
        scenario, plan.approved_facts, plan.scope.identity_reference
    )
    if plan.content != expected or re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", plan.content.body):
        raise ValidationError("Avatar synthesis requires the exact built-in fictional script")
    estimate = 2 * money(config.usd_per_video_minute)
    if estimate > money(config.max_request_estimate_usd):
        raise ValidationError("Avatar preview exceeds the configured planning estimate limit")
    request = {
        "inputKind": "PlainText",
        "inputs": [{"content": plan.content.body}],
        "synthesisConfig": {"voice": config.voice},
        "avatarConfig": {
            "talkingAvatarCharacter": "lisa",
            "talkingAvatarStyle": "casual-sitting",
            "videoFormat": "mp4",
            "videoCodec": "h264",
            "bitrateKbps": 1000,
            "customized": False,
        },
    }
    result = {
        "schema_version": 1,
        "plan_digest": plan.digest,
        "configuration_sha256": config.digest,
        "endpoint": config.endpoint(plan.digest),
        "job_id": delivery_key(plan.digest, ASSET),
        "method": "PUT",
        "request": request,
        "request_sha256": sha(encoded(request)),
        "planning_seconds": 120,
        "estimated_usd": usd(estimate),
        "network_called": False,
        "notice": NOTICE,
    }
    result["preview_sha256"] = sha(encoded(result))
    return result


def validate_job(document, job_id, config):
    """Never pass provider prose, URLs or echoed inputs to a public receipt."""
    try:
        status = document["status"]
        avatar = document["avatarConfig"]
        if (
            document["id"] != job_id
            or status not in ("NotStarted", "Running", "Succeeded", "Failed")
            or document["inputKind"] != "PlainText"
            or document.get("customVoices", {}) != {}
            or document["synthesisConfig"]["voice"] != config.voice
            or avatar["talkingAvatarCharacter"] != "lisa"
            or avatar["talkingAvatarStyle"] != "casual-sitting"
            or avatar["videoFormat"].lower() != "mp4"
            or avatar["videoCodec"].lower() != "h264"
            or avatar["customized"] is not False
        ):
            raise ValueError
        result = {"job_id": job_id, "provider_status": status}
        if status == "Succeeded":
            properties = document["properties"]
            duration = properties["durationInMilliseconds"]
            if (
                type(duration) is not int
                or not 0 < duration <= 120000
                or type(properties["succeededCount"]) is not int
                or properties["succeededCount"] != 1
                or type(properties["failedCount"]) is not int
                or properties["failedCount"] != 0
            ):
                raise ValueError
            result["provider_duration_ms"] = duration
        return result
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ProviderError(
            "Avatar job identity, configuration or output metadata is invalid"
        ) from None


def asset_url(document, *, allowed_host=None):
    try:
        value = document["outputs"]["result"]
        if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 33 for c in value):
            raise ValueError
        url = urlsplit(value)
        if (
            url.scheme != "https"
            or not url.hostname
            or not re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", url.hostname)
            or url.port not in (None, 443)
            or url.username
            or url.password
            or url.fragment
            or not url.path.startswith("/batchsynthesis-output/")
            or not url.path.endswith(".mp4")
            or not url.query
            or (allowed_host is not None and url.hostname != allowed_host)
        ):
            raise ValueError
        return value, url.hostname
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ProviderError("Avatar output is outside the approved storage destination") from None


def video_metadata(raw):
    """Structural inventory only; no media decoder, rendering or safety verdict."""
    if not isinstance(raw, bytes) or not 24 <= len(raw) <= MAX_VIDEO:
        raise ProviderError("Avatar output is missing or exceeds the 8 MiB limit")
    offset, kinds, boxes = 0, set(), 0
    while offset < len(raw):
        if offset + 8 > len(raw) or boxes >= 10000:
            raise ProviderError("Avatar output has an invalid MP4 box boundary")
        size, kind = int.from_bytes(raw[offset : offset + 4], "big"), raw[offset + 4 : offset + 8]
        header = 8
        if size == 1:
            if offset + 16 > len(raw):
                raise ProviderError("Avatar output has a truncated MP4 extended size")
            size, header = int.from_bytes(raw[offset + 8 : offset + 16], "big"), 16
        if size == 0:
            size = len(raw) - offset
        if size < header or offset + size > len(raw) or (offset == 0 and kind != b"ftyp"):
            raise ProviderError("Avatar output has an invalid MP4 structure")
        if kind == b"ftyp" and size < header + 8:
            raise ProviderError("Avatar output has an incomplete MP4 file type")
        if kind == b"mdat" and size == header:
            raise ProviderError("Avatar output has no media bytes")
        kinds.add(kind)
        boxes += 1
        offset += size
    if not {b"ftyp", b"moov", b"mdat"} <= kinds:
        raise ProviderError("Avatar output lacks required MP4 container boxes")
    return {
        "sha256": sha(raw),
        "bytes": len(raw),
        "format": "MP4",
        "notice": "Container boundaries checked; codec, quality and content need human review.",
    }
