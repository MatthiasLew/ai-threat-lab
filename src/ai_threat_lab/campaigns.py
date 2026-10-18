"""Provider-independent training campaign orchestration with an offline demo transport."""

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Protocol

from .delivery_ledger import DeliveryLedger, MemoryLedger
from .models import ValidationError, require_text


@dataclass(frozen=True)
class CampaignScenario:
    id: str
    channel: str
    title: str
    objective: str
    steps: tuple[str, ...]
    expected_defenses: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    subject: str
    template: str


SCENARIOS = (
    CampaignScenario(
        "email_training",
        "email",
        "Controlled phishing awareness exercise",
        "Measure verification, reporting and interaction with a synthetic training request.",
        (
            "Use an approved fictional sender identity.",
            "Present the approved training message.",
            "Record only defined exercise events; never record passwords.",
        ),
        (
            "Verify the sender independently.",
            "Report unusual requests.",
            "Avoid following unexpected links.",
        ),
        (
            "Stop when scope expires or the participant requests an end.",
            "Never request passwords, MFA codes, personal records or production data.",
        ),
        "Example Company training appointment",
        "Hello, this is the fictional training coordinator. Please review the exercise "
        "appointment through your organization's approved training portal. Use your established "
        "verification and reporting procedures. No password or personal information is required.",
    ),
    CampaignScenario(
        "voice_training",
        "voice",
        "Controlled voice impersonation exercise",
        "Measure identity verification before sharing a synthetic exercise identifier.",
        (
            "Use a fictional speaker or a separately consented voice identity.",
            "Use only facts approved for this exercise; perform no automatic personal-data lookup.",
            "Ask about an invented training identifier, never actual internal information.",
            "End on refusal, verification request, scope expiry or stop request.",
        ),
        (
            "Call back using an established number.",
            "Verify authority through another channel.",
            "Decline requests for protected information.",
        ),
        (
            "Do not collect real secrets or personal/business records.",
            "Stop immediately on a request to end the exercise.",
            "Recording/transcription requires a separate approved policy.",
        ),
        "Voice exercise",
        "Good morning, this is the fictional office coordinator for Example Company. "
        "I am calling about the synthetic exercise identifier TRAINING-ALPHA. "
        "Please follow your usual caller-verification procedure before discussing it. "
        "Do not provide any real account, customer or authentication information.",
    ),
    CampaignScenario(
        "video_training",
        "video",
        "Controlled synthetic-video awareness exercise",
        "Measure independent verification of a synthetic video instruction.",
        (
            "Use an approved fictional/consented visual identity.",
            "Generate a preview asset and approve its exact content before distribution.",
            "Ask only about a synthetic exercise action.",
        ),
        ("Verify the source independently.", "Do not treat realistic video as proof of identity."),
        (
            "No unconsented likeness or real confidential data requests.",
            "No video distribution until an asset is explicitly approved.",
        ),
        "Synthetic-video training exercise",
        "This is a fictional Example Company training announcement. "
        "Verify the instruction through a trusted channel before acknowledging "
        "the synthetic exercise identifier TRAINING-ALPHA. No real data is requested.",
    ),
)


def campaign_scenarios() -> tuple[CampaignScenario, ...]:
    return SCENARIOS


def _utc(value: datetime, label: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"{label} must be a timezone-aware datetime")


@dataclass(frozen=True)
class CampaignScope:
    campaign_id: str
    authorized_by: str
    recipient_allowlist: tuple[str, ...]
    expires_at: datetime
    identity_reference: str = "fictional:example-company-coordinator"

    def __post_init__(self) -> None:
        for label in ("campaign_id", "authorized_by", "identity_reference"):
            require_text(getattr(self, label), label)
        _utc(self.expires_at, "expires_at")
        if not isinstance(self.recipient_allowlist, (tuple, list)) or not self.recipient_allowlist:
            raise ValidationError("recipient_allowlist must contain explicit destinations")
        for recipient in self.recipient_allowlist:
            require_text(recipient, "recipient")
            if any(char in recipient for char in ("*", "\r", "\n")):
                raise ValidationError("Wildcard and multiline recipients are not allowed")
        object.__setattr__(
            self, "recipient_allowlist", tuple(sorted(set(self.recipient_allowlist)))
        )
        if (
            not self.identity_reference.startswith(("fictional:", "consent:"))
            or not self.identity_reference.partition(":")[2].strip()
        ):
            raise ValidationError("identity_reference must identify fiction or a consent record")


@dataclass(frozen=True)
class TrainingContent:
    subject: str
    body: str
    media_reference: str | None = None
    media_sha256: str | None = None

    def __post_init__(self) -> None:
        require_text(self.subject, "subject")
        require_text(self.body, "body")
        if "\n" in self.subject or "\r" in self.subject:
            raise ValidationError("subject must be a single line")
        if self.media_reference is not None:
            require_text(self.media_reference, "media_reference")
            if not isinstance(self.media_sha256, str) or not re.fullmatch(
                r"[a-f0-9]{64}", self.media_sha256
            ):
                raise ValidationError("Media needs an immutable SHA-256 digest")
        elif self.media_sha256 is not None:
            raise ValidationError("Media digest requires a media reference")


class TrainingContentProvider(Protocol):
    def prepare(
        self, scenario: CampaignScenario, approved_facts: tuple[str, ...], identity_reference: str
    ) -> TrainingContent:
        """Return a preview only; do not send, call, scrape, or collect personal information."""
        ...


class TemplateContentProvider:
    def prepare(
        self, scenario: CampaignScenario, approved_facts: tuple[str, ...], identity_reference: str
    ) -> TrainingContent:
        facts = "\n".join(f"Approved exercise fact: {fact}" for fact in approved_facts)
        return TrainingContent(
            scenario.subject, scenario.template + ("\n" + facts if facts else "")
        )


@dataclass(frozen=True)
class CampaignPlan:
    scenario_id: str
    channel: str
    scope: CampaignScope
    recipients: tuple[str, ...]
    approved_facts: tuple[str, ...]
    content: TrainingContent

    def __post_init__(self) -> None:
        require_text(self.scenario_id, "scenario_id")
        if self.channel not in ("email", "voice", "video"):
            raise ValidationError("Invalid campaign channel")
        if not isinstance(self.scope, CampaignScope) or not isinstance(
            self.content, TrainingContent
        ):
            raise ValidationError("Campaign plan needs validated scope and content")
        for label in ("recipients", "approved_facts"):
            values = getattr(self, label)
            if not isinstance(values, (tuple, list)):
                raise ValidationError(f"{label} must be an array")
            for value in values:
                require_text(value, label)
            object.__setattr__(self, label, tuple(values))

    @property
    def digest(self) -> str:
        payload = asdict(self)
        payload["scope"]["expires_at"] = self.scope.expires_at.isoformat()
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


@dataclass(frozen=True)
class ContentApproval:
    plan_digest: str
    approved_by: str
    approved_at: datetime


@dataclass(frozen=True)
class DeliveryReceipt:
    recipient: str
    status: str
    reference: str

    def __post_init__(self) -> None:
        require_text(self.recipient, "recipient")
        require_text(self.reference, "reference")
        if self.status not in ("simulated", "accepted", "unknown"):
            raise ValidationError("Dispatch status must be simulated, accepted or unknown")


class TrainingTransport(Protocol):
    channel: str

    def deliver(self, plan: CampaignPlan, recipient: str) -> DeliveryReceipt:
        """Deliver approved training material; honor cancellation and provider idempotency."""
        ...


class DemoTransport:
    """Records simulated deliveries only. Never opens a connection or creates media."""

    def __init__(self, channel: str) -> None:
        self.channel = channel

    def deliver(self, plan: CampaignPlan, recipient: str) -> DeliveryReceipt:
        return DeliveryReceipt(recipient, "simulated", f"demo:{plan.digest[:16]}:{recipient}")


def _validate_plan(plan: CampaignPlan, now: datetime) -> CampaignScenario:
    _utc(now, "now")
    scenario = next((item for item in SCENARIOS if item.id == plan.scenario_id), None)
    if scenario is None or plan.channel != scenario.channel:
        raise ValidationError("Unknown scenario or mismatched campaign channel")
    if plan.scope.expires_at <= now:
        raise ValidationError("Campaign scope has expired")
    if not plan.recipients or len(set(plan.recipients)) != len(plan.recipients):
        raise ValidationError("Recipients must be non-empty and unique")
    if not set(plan.recipients) <= set(plan.scope.recipient_allowlist):
        raise ValidationError("A recipient is outside the approved scope")
    for recipient in plan.recipients:
        valid = (
            re.fullmatch(r"\+[1-9][0-9]{7,14}", recipient)
            if scenario.channel == "voice"
            else re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", recipient)
        )
        if not valid:
            raise ValidationError("Recipient format does not match the channel")
    return scenario


class CampaignService:
    def __init__(
        self,
        content_provider: TrainingContentProvider | None = None,
        ledger: DeliveryLedger | None = None,
    ) -> None:
        self.content_provider = content_provider or TemplateContentProvider()
        self.ledger = ledger or MemoryLedger()

    def prepare(
        self,
        scenario_id: str,
        scope: CampaignScope,
        recipients: tuple[str, ...],
        approved_facts: tuple[str, ...] = (),
        *,
        now: datetime | None = None,
    ) -> CampaignPlan:
        current = now or datetime.now(timezone.utc)
        if not isinstance(scope, CampaignScope):
            raise ValidationError("scope must be a CampaignScope")
        if not isinstance(recipients, (tuple, list)):
            raise ValidationError("recipients must be a list or tuple")
        for recipient in recipients:
            require_text(recipient, "recipient")
        scenario = next((item for item in SCENARIOS if item.id == scenario_id), None)
        if scenario is None:
            raise ValidationError(f"Unknown campaign scenario: {scenario_id}")
        if not isinstance(approved_facts, (tuple, list)):
            raise ValidationError("approved_facts must be a list or tuple")
        for fact in approved_facts:
            require_text(fact, "approved fact")
        # Validate scope and destinations before invoking any optional content provider.
        placeholder = CampaignPlan(
            scenario.id,
            scenario.channel,
            scope,
            tuple(recipients),
            tuple(approved_facts),
            TrainingContent("Preview", "Pending"),
        )
        _validate_plan(placeholder, current)
        content = self.content_provider.prepare(
            scenario, tuple(approved_facts), scope.identity_reference
        )
        if not isinstance(content, TrainingContent):
            raise ValidationError("Content provider must return TrainingContent")
        return CampaignPlan(
            scenario.id, scenario.channel, scope, tuple(recipients), tuple(approved_facts), content
        )

    def execute(
        self,
        plan: CampaignPlan,
        approval: ContentApproval,
        transport: TrainingTransport,
        *,
        now: datetime | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> tuple[DeliveryReceipt, ...]:
        current = now or datetime.now(timezone.utc)
        _validate_plan(plan, current)
        _utc(approval.approved_at, "approved_at")
        require_text(approval.approved_by, "approved_by")
        if approval.approved_at > current or approval.approved_at >= plan.scope.expires_at:
            raise ValidationError("Approval timestamp is outside the valid window")
        if approval.plan_digest != plan.digest:
            raise ValidationError("Approval does not match the exact preview and scope")
        if transport.channel != plan.channel:
            raise ValidationError("Transport channel does not match the plan")
        if plan.channel == "video" and not plan.content.media_reference:
            raise ValidationError("Video needs a generated asset in the approved preview")
        receipts = []
        for recipient in plan.recipients:
            _validate_plan(plan, now or datetime.now(timezone.utc))
            if should_stop and should_stop():
                raise ValidationError("Campaign cancelled before the next delivery")
            key = hashlib.sha256(f"{plan.digest}:{recipient}".encode()).hexdigest()
            if not self.ledger.claim(key):
                raise ValidationError(
                    "This campaign delivery was already attempted; review its status"
                )
            # Mark before calling: ambiguous provider timeouts must not trigger a duplicate send.
            receipt = transport.deliver(plan, recipient)
            if not isinstance(receipt, DeliveryReceipt) or receipt.recipient != recipient:
                raise ValidationError("Transport returned an invalid receipt")
            receipts.append(receipt)
        return tuple(receipts)


EVENT_TYPES = frozenset(
    (
        "delivered",
        "opened",
        "link_clicked",
        "reported",
        "identity_verified",
        "synthetic_info_shared",
        "declined",
    )
)


@dataclass(frozen=True)
class TrainingEvent:
    participant_id: str
    type: str
    automated: bool = False

    def __post_init__(self) -> None:
        require_text(self.participant_id, "participant_id")
        if self.type not in EVENT_TYPES or type(self.automated) is not bool:
            raise ValidationError("Invalid training event type or automated flag")


def summarize_events(events: tuple[TrainingEvent, ...]) -> dict:
    """Only aggregate exercise events; no transcripts, answers or passwords are accepted."""
    counts = {
        kind: len({e.participant_id for e in events if e.type == kind and not e.automated})
        for kind in sorted(EVENT_TYPES)
    }
    return {
        "unique_participants": len({e.participant_id for e in events if not e.automated}),
        "counts": counts,
        "automated_events_excluded": sum(e.automated for e in events),
        "interpretation": "Clicks and opens are observations, not proof of compromise. "
        "Events may overlap and depend on provider telemetry quality.",
    }
