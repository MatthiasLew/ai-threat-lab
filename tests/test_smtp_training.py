"""No real dispatch: protocol fixtures exercise approval, TLS, ambiguity and persistence."""

import json
import smtplib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

import ai_threat_lab.smtp_training as smtp
from ai_threat_lab.contracts import plan_from_document
from ai_threat_lab.dispatch_journal import DispatchJournal
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderConfig, ProviderError, ProviderRegistry
from ai_threat_lab.workflows import approve_campaign, example_request, prepare_campaign


def approved():
    request = example_request("email_training")
    request["recipients"] = ["person@example.invalid", "second@example.invalid"]
    request["scope"]["recipient_allowlist"] = request["recipients"]
    doc = prepare_campaign(request, ProviderRegistry(), ProviderConfig())
    return plan_from_document(doc), approve_campaign(doc, "reviewer")


def configuration(**changes):
    return smtp.SMTPConfig(**{
        "host": "mail.example.invalid", "sender": "training@example.invalid", **changes,
    })


class Wire:
    def __init__(self, failure=None, during="send", refused=None, closing=False):
        self.failure, self.during, self.refused = failure, during, refused or {}
        self.closing, self.calls = closing, []

    def login(self, username, password):
        self.calls.append("login")
        if self.failure and self.during == "login":
            raise self.failure

    def sendmail(self, sender, recipients, raw):
        self.calls.append((sender, recipients, raw))
        if self.failure and self.during == "send":
            raise self.failure
        return self.refused

    def close(self):
        self.calls.append("close")
        if self.closing:
            raise OSError("PRIVATE")


@pytest.fixture
def credentials(monkeypatch):
    monkeypatch.setenv("AI_THREAT_SMTP_USER", "synthetic-user")
    monkeypatch.setenv("AI_THREAT_SMTP_PASSWORD", "synthetic-password")


def test_preview_no_credentials_or_transport_and_exact_mime(monkeypatch):
    plan, approval = approved()
    monkeypatch.delenv("AI_THREAT_SMTP_USER", raising=False)
    monkeypatch.setattr(smtp, "_connection", lambda _: pytest.fail("No preview connection"))
    config = configuration()
    preview = smtp.preview(plan, approval, config)
    assert not preview["network_called"]
    assert len(preview["messages"]) == 2
    from email import policy
    from email.parser import BytesParser

    raw = smtp.message_bytes(plan, approval, config, plan.recipients[0])
    message = BytesParser(policy=policy.default).parsebytes(raw)
    assert message["From"] == config.sender and message["To"] == plan.recipients[0]
    assert message.get_content().replace("\r\n", "\n").rstrip() == plan.content.body
    assert smtp.sha(raw) == preview["messages"][0]["sha256"]
    assert "Bcc" not in message


def test_accepted_is_durable_and_duplicate_blocked(tmp_path, credentials):
    plan, approval = approved()
    config = configuration()
    journal = DispatchJournal(tmp_path / "dispatch.sqlite", create=True)
    wire = Wire(closing=True)
    preview = smtp.preview(plan, approval, config)
    result = smtp.send(plan, approval, config, journal, preview["preview_sha256"],
                       allowed_host=config.host, connection_factory=lambda _: wire)
    assert {a["status"] for a in result["attempts"]} == {"accepted"}
    assert len(result["attempts"]) == 2
    assert "person@" not in json.dumps(result)
    journal = DispatchJournal(journal.path)
    with pytest.raises(ValidationError, match="already attempted"):
        smtp.send(plan, approval, config, journal, preview["preview_sha256"],
                  allowed_host=config.host, connection_factory=lambda _: pytest.fail("Repeat"))


@pytest.mark.parametrize("failure,during,expected", [
    (OSError("PRIVATE"), "send", "unknown"),
    (OSError("PRIVATE"), "login", "rejected"),
    (smtplib.SMTPRecipientsRefused({"PRIVATE": (550, b"PRIVATE")}), "send", "rejected"),
    (smtplib.SMTPDataError(550, b"PRIVATE"), "send", "rejected"),
])
def test_failures_stop_batch_without_retry(tmp_path, credentials, failure, during, expected):
    plan, approval = approved()
    config = configuration()
    journal = DispatchJournal(tmp_path / "dispatch.sqlite", create=True)
    wire = Wire(failure, during)
    result = smtp.send(plan, approval, config, journal,
                       smtp.preview(plan, approval, config)["preview_sha256"],
                       allowed_host=config.host, connection_factory=lambda _: wire)
    assert len(result["attempts"]) == 1
    assert result["attempts"][0]["status"] == expected
    assert "PRIVATE" not in json.dumps(result)
    assert wire.calls[-1] == "close"


def test_missing_credentials_and_bad_confirmation_never_claim(tmp_path, monkeypatch):
    plan, approval = approved()
    config = configuration()
    journal = DispatchJournal(tmp_path / "dispatch.sqlite", create=True)
    monkeypatch.delenv("AI_THREAT_SMTP_USER", raising=False)
    with pytest.raises(ValidationError):
        smtp.send(plan, approval, config, journal, "bad", allowed_host=config.host)
    with pytest.raises(ProviderError):
        smtp.send(plan, approval, config, journal,
                  smtp.preview(plan, approval, config)["preview_sha256"], allowed_host=config.host)
    assert not journal.status(plan.digest)["attempts"]


def test_cancellation_before_and_during_connection(tmp_path, credentials):
    plan, approval = approved()
    config = configuration()
    journal = DispatchJournal(tmp_path / "dispatch.sqlite", create=True)
    wire = Wire()

    def connect(_):
        journal.cancel(plan.digest)
        return wire

    result = smtp.send(plan, approval, config, journal,
                       smtp.preview(plan, approval, config)["preview_sha256"],
                       allowed_host=config.host, connection_factory=connect)
    assert result["cancelled"] and result["attempts"][0]["status"] == "rejected"
    assert wire.calls == ["login", "close"]
    with pytest.raises(ValidationError, match="cancelled"):
        journal.claim(plan.digest, "third@example.invalid", config.digest)


def test_interrupted_dispatch_remains_pending(tmp_path, credentials):
    plan, approval = approved()
    config = configuration()
    journal = DispatchJournal(tmp_path / "dispatch.sqlite", create=True)
    with pytest.raises(KeyboardInterrupt):
        smtp.send(plan, approval, config, journal,
                  smtp.preview(plan, approval, config)["preview_sha256"], allowed_host=config.host,
                  connection_factory=lambda _: Wire(KeyboardInterrupt()))
    assert DispatchJournal(journal.path).status(plan.digest)["attempts"][0]["status"] == "pending"


def test_atomic_claim_and_configuration_change_do_not_duplicate(tmp_path):
    path = tmp_path / "dispatch.sqlite"
    DispatchJournal(path, create=True)

    def claim(_):
        try:
            DispatchJournal(path).claim("a" * 64, "person@example.invalid", "b" * 64)
            return True
        except ValidationError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(claim, range(8))) == 1
    with pytest.raises(ValidationError):
        DispatchJournal(path).claim("a" * 64, "person@example.invalid", "c" * 64)


def test_changed_content_requires_supported_template():
    plan, approval = approved()
    altered = replace(plan, content=replace(plan.content, body="Other content"))
    approval = replace(approval, plan_digest=altered.digest)
    with pytest.raises(ValidationError, match="template"):
        smtp.preview(altered, approval, configuration())


@pytest.mark.parametrize("options", [
    {"host": "localhost"}, {"host": "mail.example:465"}, {"host": "mail\n.example"},
    {"mode": "plain"}, {"timeout": True}, {"timeout": 0},
    {"sender": "name <person@example.invalid>"}, {"sender": "a..b@example.invalid"},
])
def test_invalid_configuration(options):
    with pytest.raises(ValidationError):
        configuration(**options)


def test_tls_modes_check_certificates_and_never_fallback(monkeypatch):
    class Protocol:
        calls = []

        def ehlo(self):
            self.calls.append("ehlo")

        def starttls(self, *, context):
            assert context.check_hostname and context.verify_mode == smtp.ssl.CERT_REQUIRED
            self.calls.append("tls")

        def close(self):
            self.calls.append("close")

    protocol = Protocol()

    def factory(host, port, **options):
        assert host == configuration().host and port == 587
        assert options["local_hostname"] == "training.invalid"
        return protocol

    monkeypatch.setattr(smtp.smtplib, "SMTP", factory)
    assert smtp._connection(configuration()) is protocol
    assert protocol.calls == ["ehlo", "tls", "ehlo"]

    def implicit(host, port, **options):
        assert port == 465 and options["context"].check_hostname
        return protocol

    monkeypatch.setattr(smtp.smtplib, "SMTP_SSL", implicit)
    assert smtp._connection(configuration(mode="tls")) is protocol


def test_journal_identity_cancel_and_outcome_boundaries(tmp_path):
    path = tmp_path / "dispatch.sqlite"
    journal = DispatchJournal(path, create=True)
    key = journal.claim("a" * 64, "one@example.invalid", "b" * 64)
    journal.outcome(key, "unknown")
    with pytest.raises(ValidationError, match="pending"):
        journal.outcome(key, "accepted")
    journal.cancel("c" * 64)
    journal.cancel("c" * 64)
    assert DispatchJournal(path).status("c" * 64)["cancelled"]
    with pytest.raises(ValidationError):
        journal.outcome("bad", "accepted")
    with pytest.raises(ValidationError):
        journal.outcome(key, "delivered")
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=2")
    with pytest.raises(ValidationError, match="supported"):
        DispatchJournal(path)


def test_unrelated_database_is_not_modified(tmp_path):
    path = tmp_path / "other.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE important (data TEXT)")
        db.execute("INSERT INTO important VALUES ('keep')")
    before = path.read_bytes()
    with pytest.raises(ValidationError):
        DispatchJournal(path, create=True)
    assert path.read_bytes() == before


def test_corrupt_result_and_trigger_are_rejected(tmp_path):
    path = tmp_path / "dispatch.sqlite"
    journal = DispatchJournal(path, create=True)
    key = journal.claim("a" * 64, "one@example.invalid", "b" * 64)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE attempts SET updated='PRIVATE' WHERE key=?", (key,))
    with pytest.raises(ValidationError):
        journal.status("a" * 64)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TRIGGER unexpected AFTER INSERT ON cancelled BEGIN SELECT 1; END")
    with pytest.raises(ValidationError, match="triggers"):
        journal.cancel("a" * 64)


def test_cli_preview_send_and_status(tmp_path, monkeypatch, credentials, capsys):
    from ai_threat_lab.cli import main
    from ai_threat_lab.contracts import approval_to_document, plan_to_document, write_document

    plan, approval = approved()
    plan_path, approval_path = tmp_path / "plan.json", tmp_path / "approval.json"
    config_path, journal = tmp_path / "smtp.json", tmp_path / "dispatch.sqlite"
    write_document(plan_to_document(plan), plan_path)
    write_document(approval_to_document(approval), approval_path)
    write_document({"schema_version": 1, "host": "mail.example.invalid",
                    "sender": "training@example.invalid"}, config_path)
    base = [str(plan_path), "--approval", str(approval_path), "--smtp-config", str(config_path)]
    assert main(["smtp-preview", *base]) == 0
    preview = json.loads(capsys.readouterr().out)
    wire = Wire()
    monkeypatch.setattr(smtp, "_connection", lambda _: wire)
    args = ["smtp-send", *base, "--ledger", str(journal),
            "--preview-sha256", preview["preview_sha256"],
            "--allow-smtp-host", "mail.example.invalid"]
    assert main(args) == 2
    assert not journal.exists()
    output = tmp_path / "result.json"
    assert main([*args, "--send-approved", "--output", str(output)]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert {a["status"] for a in result["attempts"]} == {"accepted"}
    count = len(wire.calls)
    assert main([*args, "--send-approved", "--output", str(output)]) == 2
    assert len(wire.calls) == count
    assert main(["smtp-cancel", "--ledger", str(journal), "--plan-digest", plan.digest]) == 0
    capsys.readouterr()
    assert main(["smtp-status", "--ledger", str(journal), "--plan-digest", plan.digest]) == 0
    assert json.loads(capsys.readouterr().out)["cancelled"]


def test_cancel_output_cannot_alias_new_database(tmp_path):
    from ai_threat_lab.cli import main

    path = tmp_path / "new.sqlite"
    assert main(["smtp-cancel", "--ledger", str(path), "--plan-digest", "a" * 64,
                 "--output", str(path)]) == 2
    assert not path.exists()


def test_menu_preview_and_declined_send(monkeypatch):
    from ai_threat_lab.console import run_console

    answers = iter(["11", "1", "plan", "approval", "config", "output",
                    "11", "2", "plan", "approval", "config", "digest", "host", "journal", "n", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    calls = []
    assert run_console(lambda args: calls.append(args) or 0) == 0
    assert calls == [["smtp-preview", "plan", "--approval", "approval",
                      "--smtp-config", "config", "--output", "output"]]


def test_scope_expiring_during_connection_prevents_submission(tmp_path, credentials):
    from datetime import timedelta

    plan, approval = approved()
    config = configuration()
    journal = DispatchJournal(tmp_path / "dispatch.sqlite", create=True)
    wire = Wire()
    clock = iter([approval.approved_at, approval.approved_at,
                  plan.scope.expires_at + timedelta(seconds=1)])
    result = smtp.send(plan, approval, config, journal,
                       smtp.preview(plan, approval, config)["preview_sha256"],
                       allowed_host=config.host, connection_factory=lambda _: wire,
                       clock=lambda: next(clock))
    assert result["attempts"][0]["status"] == "rejected"
    assert wire.calls == ["login", "close"]


def test_failed_tls_closes_connection_without_authentication(monkeypatch):
    calls = []

    class FailedTLS:
        def ehlo(self):
            calls.append("ehlo")

        def starttls(self, **kwargs):
            calls.append("starttls")
            raise OSError("certificate rejected")

        def close(self):
            calls.append("close")

    monkeypatch.setattr(smtp.smtplib, "SMTP", lambda *a, **kw: FailedTLS())
    with pytest.raises(OSError):
        smtp._connection(configuration())
    assert calls == ["ehlo", "starttls", "close"]
