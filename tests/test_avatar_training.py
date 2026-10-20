"""Offline stock-avatar preparation; no credential or provider request."""

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from ai_threat_lab.avatar_training import (
    AvatarConfig,
    asset_url,
    preview,
    validate_job,
    video_metadata,
)
from ai_threat_lab.contracts import plan_from_document
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderConfig, ProviderError, ProviderRegistry
from ai_threat_lab.workflows import approve_campaign, example_request, prepare_campaign


def approved():
    request = example_request("video_training")
    request["scope"]["expires_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    doc = prepare_campaign(request, ProviderRegistry(), ProviderConfig())
    return plan_from_document(doc), approve_campaign(doc, "reviewer")


def config(**changes):
    return AvatarConfig(**{
        "resource_host": "fixture.cognitiveservices.azure.com",
        "voice": "en-US-JennyNeural", "usd_per_video_minute": "0.50",
        "max_request_estimate_usd": "1.00", **changes,
    })


def test_exact_fictional_request_and_cost_preview(monkeypatch):
    monkeypatch.delenv("AI_THREAT_AVATAR_KEY", raising=False)
    plan, approval = approved()
    prepared = preview(plan, approval, config())
    assert not prepared["network_called"] and prepared["estimated_usd"] == "1.000000000"
    assert prepared["request"]["inputs"] == [{"content": plan.content.body}]
    assert prepared["request"]["avatarConfig"]["customized"] is False
    assert len(prepared["job_id"]) == 64
    assert prepared == preview(plan, approval, config())
    assert "recipients" not in json.dumps(prepared)


@pytest.mark.parametrize("changes", [
    {"resource_host": "https://fixture.cognitiveservices.azure.com"},
    {"resource_host": "fixture.cognitiveservices.azure.com.evil.invalid"},
    {"resource_host": "127.0.0.1"}, {"resource_host": None},
    {"voice": "custom-voice"}, {"usd_per_video_minute": "-1"},
])
def test_bad_configuration(changes):
    with pytest.raises(ValidationError):
        config(**changes)


def test_estimate_and_modified_script_are_rejected():
    plan, approval = approved()
    with pytest.raises(ValidationError, match="estimate"):
        preview(plan, approval, config(max_request_estimate_usd="0.99"))
    changed = replace(plan, content=replace(plan.content, body="Unapproved"))
    with pytest.raises(ValidationError):
        preview(changed, approval, config())


def job(status="Succeeded"):
    return {
        "id": "a" * 64, "status": status, "inputKind": "PlainText", "customVoices": {},
        "synthesisConfig": {"voice": "en-US-JennyNeural"},
        "avatarConfig": {"talkingAvatarCharacter": "lisa", "talkingAvatarStyle": "casual-sitting",
                         "videoFormat": "Mp4", "videoCodec": "h264", "customized": False},
        "properties": {"durationInMilliseconds": 3000, "succeededCount": 1, "failedCount": 0},
        "outputs": {"result": "https://fixture.blob.core.windows.net/batchsynthesis-output/"
                              "account/job/0001.mp4?sig=PRIVATE"},
        "inputs": [{"content": "PRIVATE"}],
    }


@pytest.mark.parametrize("status", ["NotStarted", "Running", "Succeeded", "Failed"])
def test_typed_job_outcomes_omit_private_fields(status):
    result = validate_job(job(status), "a" * 64, config())
    assert result["provider_status"] == status and "PRIVATE" not in json.dumps(result)


@pytest.mark.parametrize("field,value", [
    ("id", "b" * 64), ("status", "Unexpected"), ("inputKind", "SSML"),
    ("customVoices", {"voice": "PRIVATE"}), ("avatarConfig", None),
    ("properties", {"durationInMilliseconds": True, "succeededCount": 1, "failedCount": 0}),
])
def test_bad_job_metadata(field, value):
    data = job()
    data[field] = value
    with pytest.raises(ProviderError):
        validate_job(data, "a" * 64, config())


@pytest.mark.parametrize("url", [
    "http://fixture.blob.core.windows.net/batchsynthesis-output/a.mp4?sig=x",
    "https://fixture.blob.core.windows.net.evil.invalid/batchsynthesis-output/a.mp4?sig=x",
    "https://fixture.blob.core.windows.net/other/a.mp4?sig=x",
    "https://fixture.blob.core.windows.net/batchsynthesis-output/a.mp4",
    "https://user:pass@fixture.blob.core.windows.net/batchsynthesis-output/a.mp4?sig=x",
])
def test_output_destination_rejected(url):
    data = job()
    data["outputs"]["result"] = url
    with pytest.raises(ProviderError):
        asset_url(data)


def test_exact_asset_host_confirmation():
    url, host = asset_url(job())
    assert host == "fixture.blob.core.windows.net" and "PRIVATE" in url
    assert asset_url(job(), allowed_host=host) == (url, host)
    with pytest.raises(ProviderError):
        asset_url(job(), allowed_host="other.blob.core.windows.net")


def box(kind, body=b""):
    return (len(body) + 8).to_bytes(4, "big") + kind + body


def test_bounded_container_metadata_only():
    raw = box(b"ftyp", b"isom\x00\x00\x00\x00") + box(b"moov") + box(b"mdat", b"fixture")
    metadata = video_metadata(raw)
    assert metadata["bytes"] == len(raw) and len(metadata["sha256"]) == 64
    assert "human review" in metadata["notice"]
    for invalid in (b"", raw[:-1], raw[16:], b"PRIVATE" * 100,
                    box(b"ftyp", b"isom\x00\x00\x00\x00") + box(b"mdat", b"x")):
        with pytest.raises(ProviderError):
            video_metadata(invalid)


class JobWire:
    def __init__(self, error=None, status="NotStarted"):
        self.calls, self.error, self.status = [], error, status

    def request(self, url, **kwargs):
        from ai_threat_lab.http_client import HttpResponse
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        data = job(self.status)
        data["id"] = url.split("?")[0].rsplit("/", 1)[-1]
        return HttpResponse(201 if kwargs.get("method") == "PUT" else 200, {},
                            json.dumps(data).encode())


def submit_fixture(tmp_path, monkeypatch, wire):
    from ai_threat_lab.avatar_jobs import submit
    from ai_threat_lab.dispatch_journal import DispatchJournal
    monkeypatch.setenv("AI_THREAT_AVATAR_KEY", "synthetic-avatar-key")
    plan, approval = approved()
    settings = config()
    prepared = preview(plan, approval, settings)
    journal = DispatchJournal(tmp_path / "jobs.sqlite", create=True)
    receipt = submit(plan, approval, settings, journal, prepared["preview_sha256"],
                     allowed_host=settings.resource_host, output_dir=tmp_path / "attempt",
                     client=wire)
    return receipt, plan, approval, settings, journal


def test_durable_submission_and_exact_duplicate_block(tmp_path, monkeypatch):
    from ai_threat_lab.avatar_jobs import status, submit
    wire = JobWire()
    receipt, plan, approval, settings, journal = submit_fixture(tmp_path, monkeypatch, wire)
    assert receipt["status"] == "accepted" and receipt["provider_status"] == "NotStarted"
    assert len(wire.calls) == 1 and wire.calls[0][1]["method"] == "PUT"
    assert "synthetic-avatar-key" not in json.dumps(receipt)
    assert json.loads((tmp_path / "attempt/attempt.json").read_text())["status"] == "pending"
    with pytest.raises(ValidationError, match="already attempted"):
        submit(plan, approval, settings, journal,
               preview(plan, approval, settings)["preview_sha256"],
               allowed_host=settings.resource_host, output_dir=tmp_path / "duplicate", client=wire)
    assert len(wire.calls) == 1
    wire.status = "Succeeded"
    read = status(journal, plan.digest, settings, network=True,
                  allowed_host=settings.resource_host, client=wire)
    assert read["asset_host"] == "fixture.blob.core.windows.net"
    assert "PRIVATE" not in json.dumps(read) and "outputs" not in read
    assert "method" not in wire.calls[-1][1]


def test_unknown_submission_is_not_retried(tmp_path, monkeypatch):
    receipt, plan, _, _, journal = submit_fixture(
        tmp_path, monkeypatch, JobWire(ProviderError("PRIVATE")))
    assert receipt["status"] == "unknown" and "PRIVATE" not in json.dumps(receipt)
    assert journal.status(plan.digest)["attempts"][0]["status"] == "unknown"


def test_interrupt_keeps_pending_marker_and_journal(tmp_path, monkeypatch):
    from ai_threat_lab.dispatch_journal import DispatchJournal
    with pytest.raises(KeyboardInterrupt):
        submit_fixture(tmp_path, monkeypatch, JobWire(KeyboardInterrupt()))
    marker = json.loads((tmp_path / "attempt/attempt.json").read_text())
    state = DispatchJournal(tmp_path / "jobs.sqlite").status(marker["plan_digest"])
    assert marker["status"] == state["attempts"][0]["status"] == "pending"


def test_status_checks_exact_binding_before_network(tmp_path, monkeypatch):
    from ai_threat_lab.avatar_jobs import status
    wire = JobWire()
    _, plan, _, settings, journal = submit_fixture(tmp_path, monkeypatch, wire)
    for network, host, chosen in (
        (False, settings.resource_host, settings),
        (True, "other.cognitiveservices.azure.com", settings),
        (True, settings.resource_host, config(usd_per_video_minute="0.49")),
    ):
        with pytest.raises(ValidationError):
            status(journal, plan.digest, chosen, network=network, allowed_host=host, client=wire)
    assert len(wire.calls) == 1


class AssetWire:
    def __init__(self, raw=None):
        self.calls = []
        self.raw = (box(b"ftyp", b"isom\x00\x00\x00\x00") + box(b"moov") +
                    box(b"mdat", b"fixture")) if raw is None else raw

    def request(self, url, **kwargs):
        from ai_threat_lab.http_client import HttpResponse
        self.calls.append((url, kwargs))
        return HttpResponse(200, {}, self.raw)


def test_download_and_new_approval_binding(tmp_path, monkeypatch):
    from ai_threat_lab.avatar_jobs import attach_asset, download
    from ai_threat_lab.training_lab import validate_approval

    wire, assets = JobWire(), AssetWire()
    _, plan, approval, settings, journal = submit_fixture(tmp_path, monkeypatch, wire)
    wire.status = "Succeeded"
    destination = tmp_path / "download"
    result = download(
        journal, plan.digest, settings, network=True, allowed_host=settings.resource_host,
        allowed_asset_host="fixture.blob.core.windows.net", output_dir=destination,
        client=wire, asset_client=assets,
    )
    assert result["status"] == "downloaded" and result["video"]["bytes"] == len(assets.raw)
    assert len(assets.calls) == 1 and assets.calls[0][1] == {}
    assert "PRIVATE" not in json.dumps(result) and "synthetic-avatar-key" not in json.dumps(result)
    updated = attach_asset(plan, approval, settings, destination)
    assert updated.digest != plan.digest
    assert updated.content.media_sha256 == result["video"]["sha256"]
    with pytest.raises(ValidationError):
        validate_approval(updated, approval, datetime.now(timezone.utc))
    assert plan.content.body == updated.content.body
    (destination / "avatar.mp4").write_bytes(assets.raw + b"tamper")
    with pytest.raises((ValidationError, ProviderError)):
        attach_asset(plan, approval, settings, destination)


@pytest.mark.parametrize("mode", ["pending", "bad_media", "wrong_host"])
def test_download_failure_never_claims_ready_media(tmp_path, monkeypatch, mode):
    from ai_threat_lab.avatar_jobs import attach_asset, download

    wire = JobWire()
    _, plan, approval, settings, journal = submit_fixture(tmp_path, monkeypatch, wire)
    wire.status = "Running" if mode == "pending" else "Succeeded"
    assets = AssetWire(b"PRIVATE" if mode == "bad_media" else None)
    result = download(
        journal, plan.digest, settings, network=True, allowed_host=settings.resource_host,
        allowed_asset_host=("other" if mode == "wrong_host" else "fixture") +
                           ".blob.core.windows.net",
        output_dir=tmp_path / "download", client=wire, asset_client=assets,
    )
    assert result["status"] in ("failed", "not_ready")
    assert len(assets.calls) == int(mode == "bad_media")
    assert not (tmp_path / "download/avatar.mp4").exists()
    with pytest.raises(ValidationError):
        attach_asset(plan, approval, settings, tmp_path / "download")
    assert len([call for call in wire.calls if call[1].get("method") == "PUT"]) == 1


def test_existing_download_and_wrong_scope_prevent_requests(tmp_path, monkeypatch):
    from ai_threat_lab.avatar_jobs import download

    wire, assets = JobWire(), AssetWire()
    _, plan, _, settings, journal = submit_fixture(tmp_path, monkeypatch, wire)
    destination = tmp_path / "existing"
    destination.mkdir()
    options = dict(network=True, allowed_host=settings.resource_host,
                   allowed_asset_host="fixture.blob.core.windows.net", output_dir=destination,
                   client=wire, asset_client=assets)
    with pytest.raises(FileExistsError):
        download(journal, plan.digest, settings, **options)
    options["network"] = False
    with pytest.raises(ValidationError):
        download(journal, plan.digest, settings, **options)
    assert len(wire.calls) == 1 and not assets.calls


def test_avatar_setup_profile_is_credential_free(tmp_path, monkeypatch):
    from dataclasses import asdict

    from ai_threat_lab.setup_check import setup_check

    path = tmp_path / "config.json"
    path.write_text(json.dumps({"schema_version": 1, **asdict(config())}))
    monkeypatch.setenv("AI_THREAT_AVATAR_KEY", "PRIVATE")
    result = setup_check(avatar_path=path)
    avatar = next(row for row in result["integrations"] if row["id"] == "avatar")
    assert avatar["status"] == "local_configuration_valid"
    assert not avatar["live_ready"] and "PRIVATE" not in json.dumps(result)

@pytest.mark.parametrize("reason", ["cancelled", "expired"])
def test_authorization_change_prevents_provider_call(tmp_path, monkeypatch, reason):
    from ai_threat_lab.avatar_jobs import submit
    from ai_threat_lab.dispatch_journal import DispatchJournal

    monkeypatch.setenv("AI_THREAT_AVATAR_KEY", "synthetic-avatar-key")
    plan, approval = approved()
    settings, wire = config(), JobWire()
    journal = DispatchJournal(tmp_path / "jobs.sqlite", create=True)
    prepared = preview(plan, approval, settings)
    now = datetime.now(timezone.utc)
    ticks = 0

    def clock():
        nonlocal ticks
        ticks += 1
        if ticks == 2:
            if reason == "cancelled":
                journal.cancel(plan.digest)
            else:
                return now + timedelta(days=2)
        return now

    receipt = submit(plan, approval, settings, journal, prepared["preview_sha256"],
                     allowed_host=settings.resource_host, output_dir=tmp_path / "attempt",
                     client=wire, clock=clock)
    assert receipt["status"] == "rejected" and not wire.calls
    assert journal.status(plan.digest)["attempts"][0]["status"] == "rejected"


def test_download_write_failure_preserves_failed_receipt(tmp_path, monkeypatch):
    from pathlib import Path

    from ai_threat_lab.avatar_jobs import attach_asset, download

    wire, assets = JobWire(), AssetWire()
    _, plan, approval, settings, journal = submit_fixture(tmp_path, monkeypatch, wire)
    wire.status = "Succeeded"
    original = Path.open

    def denied(path, *args, **kwargs):
        if path.name == "avatar.mp4":
            raise PermissionError("PRIVATE filesystem detail")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)
    destination = tmp_path / "download"
    result = download(journal, plan.digest, settings, network=True,
                      allowed_host=settings.resource_host,
                      allowed_asset_host="fixture.blob.core.windows.net",
                      output_dir=destination, client=wire, asset_client=assets)
    assert result["status"] == "failed" and "PRIVATE" not in json.dumps(result)
    assert json.loads((destination / "result.json").read_text())["status"] == "failed"
    with pytest.raises(ValidationError):
        attach_asset(plan, approval, settings, destination)
    assert len([call for call in wire.calls if call[1].get("method") == "PUT"]) == 1

@pytest.mark.parametrize("choice,answers", [
    ("2", ["plan", "approval", "config", "ledger", "host", "digest", "n"]),
    ("3", ["config", "ledger", "digest", "host", "n"]),
    ("4", ["config", "ledger", "digest", "host", "n"]),
])
def test_avatar_menu_declined_consent_never_dispatches(choice, answers):
    from ai_threat_lab.avatar_cli import avatar_menu

    replies, calls = iter([choice, *answers]), []
    assert avatar_menu(lambda args: calls.append(args),
                       lambda *args, **kwargs: next(replies)) == 0
    assert calls == []


def test_avatar_menu_download_requires_both_hosts_and_network():
    from ai_threat_lab.avatar_cli import avatar_menu

    replies = iter(["4", "config", "ledger", "digest", "provider", "y", "storage", "new"])
    calls = []
    avatar_menu(lambda args: calls.append(args), lambda *args, **kwargs: next(replies))
    assert calls == [["avatar-download", "--avatar-config", "config", "--ledger", "ledger",
                      "--plan-digest", "digest", "--allow-avatar-host", "provider",
                      "--network", "--allow-asset-host", "storage", "--output-dir", "new"]]
