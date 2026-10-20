"""Fictional call contracts and lifecycle use synthetic responses only."""

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

import pytest

from ai_threat_lab.call_jobs import status, stop, submit
from ai_threat_lab.call_training import HOST, CallConfig, preview, validate_call
from ai_threat_lab.contracts import plan_from_document
from ai_threat_lab.dispatch_journal import DispatchJournal
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderConfig, ProviderError, ProviderRegistry
from ai_threat_lab.workflows import approve_campaign, example_request, prepare_campaign


def config(**changes):
    return CallConfig(**{"account_sid": "AC" + "a" * 32, "caller": "+12025550101",
                         "usd_per_minute": "0.10", "max_request_estimate_usd": "0.10",
                         **changes})


def approved():
    request = example_request("voice_training")
    request["approved_facts"] = []
    request["scope"]["expires_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    document = prepare_campaign(request, ProviderRegistry(), ProviderConfig())
    return plan_from_document(document), approve_campaign(document, "reviewer")


def response(state="queued"):
    return {"sid": "CA" + "b" * 32, "account_sid": "AC" + "a" * 32,
            "from": "+12025550101", "to": "+12025550100", "status": state,
            "direction": "outbound-api", "duration": None, "PRIVATE": "PRIVATE"}


class Wire:
    def __init__(self, *, state="queued", error=None):
        self.calls, self.state, self.error = [], state, error

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        form = parse_qs(kwargs.get("body", b"").decode())
        create = url.endswith("/Calls.json")
        if create:
            assert kwargs["method"] == "POST" and form["Record"] == ["false"]
            assert form["Transcribe"] == ["false"] and form["TimeLimit"] == ["60"]
            assert form["Timeout"] == ["15"]
            assert "<Gather" not in form["Twiml"][0] and "<Record" not in form["Twiml"][0]
            assert "Hang up" in form["Twiml"][0] and "<Hangup/>" in form["Twiml"][0]
        elif kwargs.get("method") == "POST":
            assert set(form) == {"Status"}
            self.state = form["Status"][0]
        return HttpResponse(201 if create else 200, {}, json.dumps(response(self.state)).encode())


def submitted(tmp_path, monkeypatch, wire=None):
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "c" * 32)
    plan, approval = approved()
    settings, wire = config(), wire or Wire()
    journal = DispatchJournal(tmp_path / "calls.sqlite", create=True)
    prepared = preview(plan, approval, settings)
    receipt = submit(plan, approval, settings, journal, prepared["preview_sha256"],
                     allowed_host=HOST, output_dir=tmp_path / "attempt", client=wire)
    return receipt, plan, approval, settings, journal, wire


def test_preview_exact_single_call_without_credentials(monkeypatch):
    monkeypatch.delenv("TWILIO_AUTH_TOKEN", raising=False)
    plan, approval = approved()
    result = preview(plan, approval, config())
    assert result["network_called"] is False and result["estimated_usd"] == "0.100000000"
    assert result["request"]["To"] == plan.recipients[0]
    assert result["request"]["From"] == config().caller
    assert "Authorization" not in json.dumps(result)
    assert preview(plan, approval, config()) == result


@pytest.mark.parametrize("changes", [{"caller": "sip:private"}, {"caller": "123"},
                                     {"account_sid": "ACwrong"}, {"usd_per_minute": "-1"}])
def test_config_rejects_unsupported_destinations(changes):
    with pytest.raises(ValidationError):
        config(**changes)


def test_preview_requires_fixed_approved_content_and_budget():
    plan, approval = approved()
    with pytest.raises(ValidationError):
        preview(plan, approval, config(max_request_estimate_usd="0.09"))
    with pytest.raises(ValidationError):
        preview(replace(plan, content=replace(plan.content, body="PRIVATE")), approval, config())
    with pytest.raises(ValidationError):
        preview(plan, approval, config(), now=plan.scope.expires_at - timedelta(seconds=30))


@pytest.mark.parametrize("field,value", [
    ("sid", "private"), ("account_sid", "AC" + "d" * 32), ("to", "+12025550102"),
    ("from", "+12025550102"), ("status", "unexpected"), ("direction", "inbound"),
    ("duration", -1), ("duration", "-1"), ("status", []),
])
def test_provider_identity_and_types_fail_closed(field, value):
    from ai_threat_lab.call_training import sha

    document = response()
    document[field] = value
    with pytest.raises(ProviderError):
        validate_call(document, config(), sha(b"+12025550100"))


def test_creation_status_and_duplicate_block(tmp_path, monkeypatch):
    receipt, plan, approval, settings, journal, wire = submitted(tmp_path, monkeypatch)
    assert receipt["status"] == "accepted" and receipt["provider_status"] == "queued"
    text = json.dumps(receipt)
    assert "+1202555" not in text and "c" * 32 not in text and "PRIVATE" not in text
    with pytest.raises(ValidationError, match="already attempted"):
        submit(plan, approval, settings, journal,
               preview(plan, approval, settings)["preview_sha256"],
               allowed_host=HOST, output_dir=tmp_path / "duplicate", client=wire)
    assert len(wire.calls) == 1
    result = status(plan, settings, journal, receipt, network=True, allowed_host=HOST, client=wire)
    assert result["provider_status"] == "queued" and len(wire.calls) == 2
    assert "method" not in wire.calls[-1][1]


def test_uncertain_creation_never_retries_or_guesses_call_id(tmp_path, monkeypatch):
    receipt, plan, _, settings, journal, wire = submitted(
        tmp_path, monkeypatch, Wire(error=ProviderError("PRIVATE")))
    assert receipt["status"] == "unknown" and "call_sid" not in receipt
    assert journal.status(plan.digest)["attempts"][0]["status"] == "unknown"
    with pytest.raises(ValidationError):
        status(plan, settings, journal, receipt, network=True, allowed_host=HOST, client=wire)
    assert len(wire.calls) == 1 and "PRIVATE" not in json.dumps(receipt)


@pytest.mark.parametrize("current,expected", [("queued", "canceled"), ("ringing", "canceled"),
                                             ("in-progress", "completed")])
def test_stop_only_updates_exact_known_call(tmp_path, monkeypatch, current, expected):
    receipt, plan, _, settings, journal, wire = submitted(tmp_path, monkeypatch)
    wire.state = current
    result = stop(plan, settings, journal, receipt, network=True, allowed_host=HOST,
                  output_dir=tmp_path / "stop", client=wire)
    assert result["status"] == "provider_terminal" and result["provider_status"] == expected
    assert journal.status(plan.digest)["cancelled"]
    assert len(wire.calls) == 3 and wire.calls[-1][0] == settings.endpoint(receipt["call_sid"])
    assert parse_qs(wire.calls[-1][1]["body"].decode()) == {"Status": [expected]}


def test_terminal_stop_needs_no_update_and_failed_stop_is_not_confirmed(tmp_path, monkeypatch):
    receipt, plan, _, settings, journal, wire = submitted(tmp_path, monkeypatch)
    wire.state = "completed"
    result = stop(plan, settings, journal, receipt, network=True, allowed_host=HOST,
                  output_dir=tmp_path / "stop", client=wire)
    assert result["status"] == "already_terminal" and len(wire.calls) == 2
    wire.error = ProviderError("PRIVATE")
    failed = stop(plan, settings, journal, receipt, network=True, allowed_host=HOST,
                  output_dir=tmp_path / "failed-stop", client=wire)
    assert failed["status"] == "stop_unknown" and failed["local_cancelled"]
    assert "PRIVATE" not in json.dumps(failed)


def test_interrupt_leaves_durable_pending_call(tmp_path, monkeypatch):
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "c" * 32)
    plan, approval = approved()
    settings, wire = config(), Wire(error=KeyboardInterrupt())
    journal = DispatchJournal(tmp_path / "calls.sqlite", create=True)
    with pytest.raises(KeyboardInterrupt):
        submit(plan, approval, settings, journal,
               preview(plan, approval, settings)["preview_sha256"], allowed_host=HOST,
               output_dir=tmp_path / "attempt", client=wire)
    assert journal.status(plan.digest)["attempts"][0]["status"] == "pending"
    assert json.loads((tmp_path / "attempt/attempt.json").read_text())["status"] == "pending"
    assert not (tmp_path / "attempt/result.json").exists()


@pytest.mark.parametrize("reason", ["expired", "cancelled"])
def test_changed_call_authorization_prevents_network(tmp_path, monkeypatch, reason):
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "c" * 32)
    plan, approval = approved()
    settings, wire = config(), Wire()
    journal = DispatchJournal(tmp_path / "calls.sqlite", create=True)
    tick = 0
    now = datetime.now(timezone.utc)

    def clock():
        nonlocal tick
        tick += 1
        if tick == 2:
            if reason == "expired":
                return plan.scope.expires_at - timedelta(seconds=30)
            journal.cancel(plan.digest)
        return now

    result = submit(plan, approval, settings, journal,
                    preview(plan, approval, settings)["preview_sha256"], allowed_host=HOST,
                    output_dir=tmp_path / "attempt", client=wire, clock=clock)
    assert result["status"] == "rejected" and not wire.calls


def test_wrong_scope_or_receipt_cannot_lookup_or_stop(tmp_path, monkeypatch):
    receipt, plan, _, settings, journal, wire = submitted(tmp_path, monkeypatch)
    with pytest.raises(ValidationError):
        stop(plan, settings, journal, receipt, network=False, allowed_host=HOST,
             output_dir=tmp_path / "stop", client=wire)
    assert not journal.status(plan.digest)["cancelled"]
    for changed in ({**receipt, "plan_digest": "d" * 64},
                    {**receipt, "recipient_sha256": "d" * 64},
                    {**receipt, "call_sid": "bad"}):
        with pytest.raises(ValidationError):
            status(plan, settings, journal, changed, network=True, allowed_host=HOST, client=wire)
    assert len(wire.calls) == 1


def test_call_profile_is_nonsecret_and_not_live_ready(tmp_path, monkeypatch):
    from dataclasses import asdict

    from ai_threat_lab.setup_check import setup_check

    path = tmp_path / "call.json"
    path.write_text(json.dumps({"schema_version": 1, **asdict(config())}))
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "PRIVATE")
    result = setup_check(call_path=path)
    call = next(row for row in result["integrations"] if row["id"] == "call")
    assert call["status"] == "local_configuration_valid"
    assert not call["live_ready"] and not call["credentials_inspected"]
    assert "PRIVATE" not in json.dumps(result) and "+1202555" not in json.dumps(result)


@pytest.mark.parametrize("choice,answers", [
    ("2", ["plan", "config", "approval", "ledger", HOST, "digest", "n"]),
    ("3", ["plan", "config", "ledger", "receipt", HOST, "n"]),
    ("4", ["plan", "config", "ledger", "receipt", HOST, "n"]),
])
def test_declined_call_menu_confirmation_does_not_dispatch(choice, answers):
    from ai_threat_lab.call_cli import call_menu

    replies, calls = iter([choice, *answers]), []
    assert call_menu(lambda args: calls.append(args),
                     lambda *args, **kwargs: next(replies)) == 0
    assert calls == []


def test_known_failed_created_call_has_failure_exit_without_retry(tmp_path, monkeypatch, capsys):
    from dataclasses import asdict

    import ai_threat_lab.call_cli as entry
    from ai_threat_lab.cli import main
    from ai_threat_lab.contracts import approval_to_document, plan_to_document

    plan, approval = approved()
    settings, wire = config(), Wire(state="failed")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "c" * 32)
    monkeypatch.setattr(entry, "PublicHTTPS", lambda *a, **k: wire)
    paths = [tmp_path / name for name in ("plan.json", "approval.json", "config.json")]
    values = [plan_to_document(plan), approval_to_document(approval),
              {"schema_version": 1, **asdict(settings)}]
    for path, value in zip(paths, values, strict=True):
        path.write_text(json.dumps(value))
    code = main(["call-submit", str(paths[0]), "--approval", str(paths[1]),
                 "--call-config", str(paths[2]), "--ledger", str(tmp_path / "calls.sqlite"),
                 "--preview-sha256", preview(plan, approval, settings)["preview_sha256"],
                 "--allow-call-host", HOST, "--send-call", "--output-dir", str(tmp_path / "out")])
    assert code == 3 and len(wire.calls) == 1
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["status"] == "accepted" and receipt["provider_status"] == "failed"
    assert DispatchJournal(tmp_path / "calls.sqlite").status(plan.digest)["attempts"][0][
        "status"] == "accepted"
