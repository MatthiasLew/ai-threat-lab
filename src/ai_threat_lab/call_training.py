"""Exact fictional single-call preview and bounded provider status validation."""

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.parse import urlencode
from xml.sax.saxutils import escape

from .ai_costs import money, usd
from .campaigns import TemplateContentProvider, campaign_scenarios
from .models import ValidationError
from .providers import ProviderError
from .training_lab import validate_approval

HOST = "api.twilio.com"
ASSET = "fictional_training_call"
STATES = frozenset(
    ("queued", "ringing", "in-progress", "completed", "busy", "failed", "no-answer", "canceled")
)
TERMINAL = STATES - {"queued", "ringing", "in-progress"}
NOTICE = (
    "One explicitly approved fictional training announcement. Hang up to end playback. "
    "No recording, transcription, speech recognition or identity cloning is requested. "
    "No verbal-refusal detection or conversation occurs. Provider completion does not "
    "prove a person answered: voicemail or an IVR can answer. Configured cost estimates "
    "and requested duration limits require account/billing acceptance."
)
PREAMBLE = (
    "This is a disclosed, authorized training announcement. Do not speak or provide information. "
    "Hang up at any time to end this call. "
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def phone(value):
    if not isinstance(value, str) or not re.fullmatch(r"\+[1-9][0-9]{7,14}", value):
        raise ValidationError("Use one explicit E.164 phone number, without extensions")
    return value


def sid(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + r"[a-fA-F0-9]{32}", value):
        raise ValidationError("Unsupported provider resource identifier")
    return value


@dataclass(frozen=True)
class CallConfig:
    account_sid: str
    caller: str
    usd_per_minute: str
    max_request_estimate_usd: str

    def __post_init__(self):
        sid(self.account_sid, "AC")
        phone(self.caller)
        money(self.usd_per_minute)
        money(self.max_request_estimate_usd)

    @classmethod
    def from_document(cls, value):
        keys = {
            "schema_version",
            "account_sid",
            "caller",
            "usd_per_minute",
            "max_request_estimate_usd",
        }
        if (
            not isinstance(value, dict)
            or set(value) != keys
            or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1
        ):
            raise ValidationError("Invalid fictional-call configuration")
        return cls(**{key: item for key, item in value.items() if key != "schema_version"})

    @property
    def digest(self):
        return sha(encoded(asdict(self)))

    def endpoint(self, call_sid=None):
        suffix = "/" + sid(call_sid, "CA") if call_sid is not None else ""
        return f"https://{HOST}/2010-04-01/Accounts/{self.account_sid}/Calls{suffix}.json"


def preview(plan, approval, config, *, now=None):
    current = now or datetime.now(timezone.utc)
    validate_approval(plan, approval, current)
    if (
        plan.channel != "voice"
        or plan.scenario_id != "voice_training"
        or not plan.scope.identity_reference.startswith("fictional:")
        or len(plan.recipients) != 1
        or plan.approved_facts
        or len(plan.content.body) > 600
    ):
        raise ValidationError("Calls require one recipient and the fixed fictional voice script")
    scenario = next(row for row in campaign_scenarios() if row.id == "voice_training")
    expected = TemplateContentProvider().prepare(scenario, (), plan.scope.identity_reference)
    if plan.content != expected:
        raise ValidationError("Calls require the exact built-in fictional training template")
    target = phone(plan.recipients[0])
    if target == config.caller:
        raise ValidationError("Caller and approved recipient must be different")
    if (plan.scope.expires_at - current).total_seconds() < 120:
        raise ValidationError("Call approval must retain at least two minutes of scope")
    estimate = money(config.usd_per_minute)
    if estimate > money(config.max_request_estimate_usd):
        raise ValidationError("Call preview exceeds the configured planning estimate limit")
    twiml = (
        '<Response><Say voice="woman" language="en-US" loop="1">'
        + escape(PREAMBLE + plan.content.body)
        + "</Say><Hangup/></Response>"
    )
    form = {
        "To": target,
        "From": config.caller,
        "Twiml": twiml,
        "Record": "false",
        "Transcribe": "false",
        "Timeout": "15",
        "TimeLimit": "60",
    }
    result = {
        "schema_version": 1,
        "plan_digest": plan.digest,
        "configuration_sha256": config.digest,
        "endpoint": config.endpoint(),
        "method": "POST",
        "request": form,
        "request_sha256": sha(urlencode(form).encode("ascii")),
        "estimated_usd": usd(estimate),
        "network_called": False,
        "notice": NOTICE,
        "scope_expires_at": plan.scope.expires_at.isoformat(),
        "queue_notice": "Scope is checked before submission. Provider queuing and interrupted "
        "clients can delay or prevent remote cancellation; monitor the known call. "
        "The requested duration is not a guarantee of scope-expiry enforcement.",
    }
    result["preview_sha256"] = sha(encoded(result))
    return result


def validate_call(document, config, recipient_hash, *, expected_sid=None):
    try:
        call_sid = sid(document["sid"], "CA")
        if (
            document["account_sid"] != config.account_sid
            or document["from"] != config.caller
            or sha(phone(document["to"]).encode()) != recipient_hash
            or (expected_sid is not None and call_sid != expected_sid)
            or document["status"] not in STATES
            or document.get("direction") != "outbound-api"
        ):
            raise ValueError
        duration = document.get("duration")
        if duration not in (None, "") and (
            not isinstance(duration, str) or not re.fullmatch(r"[0-9]{1,7}", duration)
        ):
            raise ValueError
        return {
            "call_sid": call_sid,
            "provider_status": document["status"],
            "provider_duration_seconds": int(duration) if duration not in (None, "") else None,
        }
    except (KeyError, TypeError, ValueError, ValidationError):
        raise ProviderError("Call identity, destination or status mismatch") from None
