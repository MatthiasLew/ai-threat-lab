"""Explicit approved fictional training email over authenticated, certificate-checked SMTP."""

import hashlib
import json
import os
import re
import smtplib
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime

from .campaigns import TemplateContentProvider, campaign_scenarios
from .contracts import fields, version
from .dispatch_journal import delivery_key
from .models import ValidationError
from .providers import ProviderError
from .training_lab import validate_approval


def sha(value):
    return hashlib.sha256(value).hexdigest()


def address(value):
    if (
        not isinstance(value, str) or not value.isascii() or len(value) > 254
        or not re.fullmatch(r"[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", value)
    ):
        raise ValidationError("SMTP requires a bounded plain ASCII email address")
    local, domain = value.split("@")
    if (
        local.startswith(".") or local.endswith(".") or ".." in local
        or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x)
               for x in domain.split("."))
    ):
        raise ValidationError("SMTP address contains an unsupported local part or domain")
    return value


@dataclass(frozen=True)
class SMTPConfig:
    host: str
    sender: str
    mode: str = "starttls"
    timeout: int = 15

    def __post_init__(self):
        if (
            not isinstance(self.host, str) or len(self.host) > 253
            or len(self.host.split(".")) < 2
            or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x)
                   for x in self.host.split("."))
        ):
            raise ValidationError("SMTP host must be an explicit ASCII DNS hostname")
        address(self.sender)
        if self.mode not in ("starttls", "tls"):
            raise ValidationError("SMTP supports STARTTLS/587 or implicit TLS/465 only")
        if type(self.timeout) is not int or not 1 <= self.timeout <= 60:
            raise ValidationError("SMTP timeout must be between 1 and 60 seconds")

    @classmethod
    def from_document(cls, value):
        fields(value, {"schema_version", "host", "sender"}, {"mode", "timeout"})
        version(value)
        return cls(**{k: v for k, v in value.items() if k != "schema_version"})

    @property
    def digest(self):
        return sha(json.dumps(asdict(self), sort_keys=True).encode())


def _validate(plan, approval, now):
    validate_approval(plan, approval, now)
    if (
        plan.channel != "email" or not plan.scope.identity_reference.startswith("fictional:")
        or len(plan.recipients) > 20 or len(plan.content.body.encode("utf-8")) > 16384
    ):
        raise ValidationError("SMTP supports at most 20 approved fictional email recipients")
    scenario = next(s for s in campaign_scenarios() if s.id == "email_training")
    expected = TemplateContentProvider().prepare(
        scenario, plan.approved_facts, plan.scope.identity_reference)
    if plan.content != expected:
        raise ValidationError("SMTP requires the exact built-in fictional training template")
    for recipient in plan.recipients:
        address(recipient)


def message_bytes(plan, approval, config, recipient):
    message = EmailMessage(policy=SMTP)
    message["From"], message["To"] = config.sender, recipient
    message["Subject"] = plan.content.subject
    message["Date"] = format_datetime(approval.approved_at)
    domain = config.sender.split("@")[1]
    message["Message-ID"] = f"<{delivery_key(plan.digest, recipient)}@{domain}>"
    message["X-AI-Threat-Lab-Training"] = "fictional-approved-exercise"
    message.set_content(plan.content.body, charset="utf-8", cte="quoted-printable")
    raw = message.as_bytes()
    raw.decode("ascii")  # This subset does not depend on SMTPUTF8 or 8BITMIME.
    return raw


def preview(plan, approval, config, *, now=None):
    _validate(plan, approval, now or datetime.now(timezone.utc))
    result = {
        "schema_version": 1, "plan_digest": plan.digest, "configuration_sha256": config.digest,
        "smtp_host": config.host, "smtp_mode": config.mode, "sender": config.sender,
        "subject": plan.content.subject, "body": plan.content.body,
        "messages": [{"recipient": to, "sha256": sha(message_bytes(plan, approval, config, to))}
                     for to in plan.recipients],
        "network_called": False,
    }
    result["preview_sha256"] = sha(json.dumps(result, sort_keys=True).encode())
    return result


def _connection(config):
    context = ssl.create_default_context()
    if config.mode == "tls":
        return smtplib.SMTP_SSL(config.host, 465, timeout=config.timeout,
                               local_hostname="training.invalid", context=context)
    client = smtplib.SMTP(config.host, 587, timeout=config.timeout,
                         local_hostname="training.invalid")
    try:
        client.ehlo()
        client.starttls(context=context)
        client.ehlo()
        return client
    except BaseException:
        client.close()
        raise


def send(plan, approval, config, journal, expected_preview, *, allowed_host,
         connection_factory=None, clock=None):
    clock = clock or (lambda: datetime.now(timezone.utc))
    prepared = preview(plan, approval, config, now=clock())
    if expected_preview != prepared["preview_sha256"] or allowed_host != config.host:
        raise ValidationError("Confirm the exact delivery preview and SMTP host before sending")
    username = os.environ.get("AI_THREAT_SMTP_USER")
    password = os.environ.get("AI_THREAT_SMTP_PASSWORD")
    if (
        not username or not password or max(len(username), len(password)) > 4096
        or not username.isascii() or not password.isascii()
    ):
        raise ProviderError("Configure SMTP credentials outside source control before sending")
    factory = connection_factory or _connection
    for recipient in plan.recipients:
        _validate(plan, approval, clock())
        raw = message_bytes(plan, approval, config, recipient)
        key = journal.claim(plan.digest, recipient, config.digest)
        submitted, client, outcome = False, None, "rejected"
        try:
            client = factory(config)
            client.login(username, password)
            _validate(plan, approval, clock())
            if journal.status(plan.digest)["cancelled"]:
                raise ValidationError("Dispatch plan cancelled before message submission")
            submitted = True
            refused = client.sendmail(config.sender, [recipient], raw)
            outcome = ("accepted" if not refused else "rejected"
                       ) if isinstance(refused, dict) else "unknown"
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPDataError):
            outcome = "rejected"
        except (OSError, ValidationError):
            outcome = "unknown" if submitted else "rejected"
        finally:
            if client is not None:
                try:
                    client.close()
                except OSError:
                    pass
        journal.outcome(key, outcome)
        if outcome != "accepted":
            break
    return journal.status(plan.digest)
