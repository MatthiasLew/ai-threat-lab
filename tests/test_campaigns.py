from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from ai_threat_lab.campaign_cli import demo_campaign, report_events
from ai_threat_lab.campaigns import (
    CampaignScope,
    CampaignService,
    ContentApproval,
    DemoTransport,
    TrainingContent,
    TrainingEvent,
    summarize_events,
)
from ai_threat_lab.models import ValidationError

NOW = datetime(2026, 10, 18, 10, 0, tzinfo=timezone.utc)
EMAIL = "participant@example.invalid"


def scope():
    return CampaignScope("exercise-1", "Training owner", (EMAIL,), NOW + timedelta(hours=1))


def plan(service):
    return service.prepare("email_training", scope(), (EMAIL,), now=NOW)


def approval(draft):
    return ContentApproval(draft.digest, "Exercise reviewer", NOW)


def test_prepare_is_repeatable_and_dispatch_requires_exact_approval():
    service = CampaignService()
    draft = plan(service)
    assert draft.digest == plan(service).digest
    receipts = service.execute(draft, approval(draft), DemoTransport("email"), now=NOW)
    assert receipts[0].status == "simulated"
    with pytest.raises(ValidationError, match="already attempted"):
        service.execute(draft, approval(draft), DemoTransport("email"), now=NOW)


@pytest.mark.parametrize("field", ["content", "recipient", "facts", "scope"])
def test_changes_invalidate_approval(field):
    service = CampaignService()
    draft = plan(service)
    old_approval = approval(draft)
    if field == "content":
        draft = replace(draft, content=TrainingContent("Changed", "Changed text"))
    elif field == "recipient":
        draft = replace(
            draft,
            recipients=("other@example.invalid",),
            scope=replace(draft.scope, recipient_allowlist=("other@example.invalid",)),
        )
    elif field == "facts":
        draft = replace(draft, approved_facts=("changed fact",))
    else:
        draft = replace(draft, scope=replace(draft.scope, authorized_by="Other owner"))
    with pytest.raises(ValidationError, match="exact preview"):
        service.execute(draft, old_approval, DemoTransport("email"), now=NOW)


def test_scope_is_checked_before_optional_provider_is_called():
    class NeverCalled:
        def prepare(self, *args):
            pytest.fail("Provider must not be called for an out-of-scope recipient")

    service = CampaignService(NeverCalled())
    with pytest.raises(ValidationError, match="outside"):
        service.prepare("email_training", scope(), ("outside@example.invalid",), now=NOW)
    with pytest.raises(ValidationError, match="expired"):
        service.prepare("email_training", scope(), (EMAIL,), now=NOW + timedelta(days=1))


def test_scope_channels_and_approval_times():
    service = CampaignService()
    draft = plan(service)
    with pytest.raises(ValidationError, match="channel"):
        service.execute(draft, approval(draft), DemoTransport("voice"), now=NOW)
    with pytest.raises(ValidationError, match="timestamp"):
        service.execute(
            draft,
            replace(approval(draft), approved_at=NOW + timedelta(minutes=1)),
            DemoTransport("email"),
            now=NOW,
        )
    with pytest.raises(ValidationError, match="expired"):
        service.execute(draft, approval(draft), DemoTransport("email"), now=NOW + timedelta(days=1))
    with pytest.raises(ValidationError, match="timezone"):
        replace(scope(), expires_at=datetime(2026, 10, 18))
    with pytest.raises(ValidationError, match="consent"):
        replace(scope(), identity_reference="actual boss")
    with pytest.raises(ValidationError, match="Wildcard"):
        replace(scope(), recipient_allowlist=("*@example.invalid",))


def test_transport_timeout_is_not_automatically_retried():
    class Timeout:
        channel = "email"

        def deliver(self, *args):
            raise TimeoutError("Unconfirmed provider delivery")

    service = CampaignService()
    draft = plan(service)
    with pytest.raises(TimeoutError):
        service.execute(draft, approval(draft), Timeout(), now=NOW)
    with pytest.raises(ValidationError, match="already attempted"):
        service.execute(draft, approval(draft), DemoTransport("email"), now=NOW)


def test_cancellation_prevents_dispatch():
    service = CampaignService()
    draft = plan(service)
    with pytest.raises(ValidationError, match="cancelled"):
        service.execute(
            draft, approval(draft), DemoTransport("email"), now=NOW, should_stop=lambda: True
        )


def test_video_preview_requires_content_addressed_asset():
    service = CampaignService()
    draft = service.prepare("video_training", scope(), (EMAIL,), now=NOW)
    with pytest.raises(ValidationError, match="asset"):
        service.execute(draft, approval(draft), DemoTransport("video"), now=NOW)
    with pytest.raises(ValidationError, match="SHA-256"):
        TrainingContent("Preview", "Video text", "asset:video")
    draft = replace(
        draft, content=TrainingContent("Preview", "Video text", "asset:video", "a" * 64)
    )
    assert (
        service.execute(draft, approval(draft), DemoTransport("video"), now=NOW)[0].status
        == "simulated"
    )


def test_custom_content_adapter_can_plug_into_same_contract():
    class TestProvider:
        def prepare(self, scenario, approved_facts, identity_reference):
            assert identity_reference.startswith("fictional:")
            assert scenario.channel == "email"
            return TrainingContent("Approved exercise", "Synthetic content: " + approved_facts[0])

    service = CampaignService(TestProvider())
    draft = service.prepare("email_training", scope(), (EMAIL,), ("fictional fact",), now=NOW)
    assert "fictional fact" in draft.content.body
    assert service.execute(draft, approval(draft), DemoTransport("email"), now=NOW)


def test_demo_never_uses_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Offline demo must not use the network")

    monkeypatch.setattr("socket.socket", forbidden)
    for scenario in ("email_training", "voice_training", "video_training"):
        result = demo_campaign(scenario)
        assert result["mode"] == "offline_demo"
    assert demo_campaign("video_training")["status"] == "preview_only_asset_missing"


def test_event_counts_deduplicate_and_exclude_automation():
    events = (
        TrainingEvent("a", "link_clicked"),
        TrainingEvent("a", "link_clicked"),
        TrainingEvent("a", "reported"),
        TrainingEvent("bot", "opened", True),
    )
    summary = summarize_events(events)
    assert summary["counts"]["link_clicked"] == 1
    assert summary["counts"]["reported"] == 1
    assert summary["counts"]["opened"] == 0
    assert summary["unique_participants"] == 1
    assert summary["automated_events_excluded"] == 1
    with pytest.raises(ValidationError):
        TrainingEvent("a", "password_collected")


def test_event_file_rejects_extra_raw_payloads(tmp_path):
    path = tmp_path / "events.json"
    path.write_text(
        '{"schema_version":1,"events":[{"participant_id":"a","type":"opened","password":"secret"}]}'
    )
    with pytest.raises(ValidationError):
        report_events(path)


def test_persistent_ledger_prevents_duplicate_after_service_restart(tmp_path):
    from ai_threat_lab.delivery_ledger import SQLiteLedger

    path = tmp_path / "delivery.sqlite"
    first = CampaignService(ledger=SQLiteLedger(path))
    draft = plan(first)
    first.execute(draft, approval(draft), DemoTransport("email"), now=NOW)
    second = CampaignService(ledger=SQLiteLedger(path))
    with pytest.raises(ValidationError, match="already attempted"):
        second.execute(draft, approval(draft), DemoTransport("email"), now=NOW)
    assert EMAIL.encode() not in path.read_bytes()


@pytest.mark.parametrize("signal", ["stop", "declined", "real_data_offered"])
def test_voice_policy_stops_without_requesting_real_data(signal):
    from ai_threat_lab.voice_exercise import VoiceExerciseSession, VoiceSignal

    session = VoiceExerciseSession("demo-001")
    turn = session.advance(VoiceSignal(signal))
    assert turn.finished
    with pytest.raises(ValidationError, match="already ended"):
        session.advance(VoiceSignal.UNKNOWN)


def test_voice_policy_bounds_unclassified_turns_and_verification():
    from ai_threat_lab.voice_exercise import VoiceExerciseSession, VoiceSignal

    session = VoiceExerciseSession("demo-001")
    assert not session.advance(VoiceSignal.UNKNOWN).finished
    assert not session.advance(VoiceSignal.UNKNOWN).finished
    assert session.advance(VoiceSignal.UNKNOWN).finished
    session = VoiceExerciseSession("demo-002")
    turn = session.advance(VoiceSignal.VERIFICATION_REQUESTED)
    assert turn.finished and turn.event is None  # A request is not verified identity.
    session = VoiceExerciseSession("demo-003")
    turn = session.advance(VoiceSignal.SYNTHETIC_INFO_SHARED)
    assert turn.event.type == "synthetic_info_shared"
