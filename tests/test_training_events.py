"""Signed-claim boundaries, independent HMAC vector, transactional replay and CLI evidence."""

import json
import os
import socket
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from test_cli_process import run_cli
from test_training_lab import NOW, approved

from ai_threat_lab.contracts import approval_to_document, plan_to_document
from ai_threat_lab.models import ValidationError
from ai_threat_lab.training_events import (
    EventJournal,
    create_key,
    envelope_body,
    participant_bindings,
    read_envelope,
    read_key,
    render_event_report,
    sign_envelope,
    utc_text,
)

KEY = b"k" * 32  # Public, test-only material; not used by the demo or production keygen.


def bindings(count=1):
    return {
        "schema_version": 1,
        "participants": [
            {"participant_id": "alias-" + str(i), "recipient_index": i} for i in range(count)
        ],
    }


def setup(tmp_path, channel="email", *, count=1, clock=lambda: NOW):
    plan, approval = approved(channel, recipient_count=count)
    journal = EventJournal(tmp_path / "events.sqlite", clock=clock)
    result = journal.register(plan, approval, bindings(count), "fixture", KEY)
    assert result["registered"]
    return journal, plan, approval


def body(plan, **changes):
    result = {
        "schema_version": 1,
        "issuer": "fixture",
        "plan_digest": plan.digest,
        "channel": plan.channel,
        "provenance": "simulation",
        "event_id": "event-1",
        "participant_id": "alias-0",
        "type": "verification_requested",
        "automated": False,
        "occurred_at": NOW.isoformat(),
        "sent_at": NOW.isoformat(),
    }
    return {**result, **changes}


def total(journal, plan):
    report = journal.report(plan.digest)
    return sum(
        sum(group["nonautomated_events_by_type"].values()) + group["automated_events_excluded"]
        for group in report["groups"].values()
    )


def test_signing_matches_independent_openssl_vector():
    # Expected digest generated independently with openssl dgst -sha256 -mac HMAC.
    document = {
        "schema_version": 1,
        "issuer": "fixture",
        "plan_digest": "a" * 64,
        "channel": "email",
        "provenance": "simulation",
        "event_id": "event-1",
        "participant_id": "participant-1",
        "type": "opened",
        "automated": False,
        "occurred_at": "2026-01-01T00:00:00Z",
        "sent_at": "2026-01-01T00:00:00Z",
    }
    assert (
        sign_envelope(document, KEY)["signature"]
        == "45ee25f89fdda05e0cbbf2148426ad49ce7a8c00569b7269c23d350682c8f147"
    )


@pytest.mark.parametrize("channel", ["email", "voice", "video"])
def test_approved_signed_claims_and_replays_across_restart(tmp_path, channel):
    journal, plan, _ = setup(tmp_path, channel)
    envelope = sign_envelope(body(plan), KEY)
    assert journal.accept(envelope, KEY)["accepted"]
    journal = EventJournal(journal.path, clock=lambda: NOW)
    assert journal.accept(envelope, KEY)["duplicate"]
    assert total(journal, plan) == 1
    report = journal.report(plan.digest)
    assert report["groups"]["simulation"]["claimed_action_participants"] == 1
    assert (
        not report["participant_behavior_verified"] and not report["external_transport_validated"]
    )
    raw = journal.path.read_bytes()
    assert KEY not in raw and b"example.invalid" not in raw and b"TRAINING-ALPHA" not in raw
    assert "alias-0" not in json.dumps(report)
    if os.name != "nt":
        assert journal.path.stat().st_mode & 0o777 == 0o600


def test_automation_delivery_simulation_and_adapter_claims_stay_separate(tmp_path):
    journal, plan, _ = setup(tmp_path)
    events = [
        body(plan, event_id="delivered", type="delivered"),
        body(plan, event_id="auto", type="opened", automated=True),
        body(plan, event_id="simulated", type="opened"),
        body(plan, event_id="claim", type="opened", provenance="adapter_claim"),
        body(plan, event_id="again", type="opened", provenance="adapter_claim"),
    ]
    for event in events:
        journal.accept(sign_envelope(event, KEY), KEY)
    report = journal.report(plan.digest)
    sim, claim = report["groups"]["simulation"], report["groups"]["adapter_claim"]
    assert sim["automated_events_excluded"] == 1
    assert sim["nonautomated_events_by_type"] == {"delivered": 1, "opened": 1}
    assert sim["claimed_action_participants"] == 1
    assert claim["nonautomated_events_by_type"] == {"opened": 2}
    assert claim["nonautomated_participants_by_type"] == {"opened": 1}
    assert claim["claimed_action_participants"] == 1


def test_delivery_alone_is_not_participant_action(tmp_path):
    journal, plan, _ = setup(tmp_path)
    journal.accept(sign_envelope(body(plan, type="delivered"), KEY), KEY)
    assert journal.report(plan.digest)["groups"]["simulation"]["claimed_action_participants"] == 0


def test_registration_is_idempotent_but_conflicting_key_issuer_or_bindings_rejected(tmp_path):
    journal, plan, approval = setup(tmp_path)
    assert journal.register(plan, approval, bindings(), "fixture", KEY)["duplicate"]
    for issuer, key, selected in [
        ("other", KEY, bindings()),
        ("fixture", b"x" * 32, bindings()),
        (
            "fixture",
            KEY,
            {
                "schema_version": 1,
                "participants": [{"participant_id": "other", "recipient_index": 0}],
            },
        ),
    ]:
        with pytest.raises(ValidationError, match="conflict"):
            journal.register(plan, approval, selected, issuer, key)


@pytest.mark.parametrize(
    "change",
    [
        {"plan_digest": "a" * 64},
        {"approved_by": ""},
        {"approved_at": NOW + timedelta(seconds=1)},
        {"approved_at": NOW.replace(tzinfo=None)},
    ],
)
def test_invalid_approval_blocks_registration(tmp_path, change):
    plan, approval = approved("email")
    journal = EventJournal(tmp_path / "events.sqlite", clock=lambda: NOW)
    with pytest.raises(ValidationError):
        journal.register(plan, replace(approval, **change), bindings(), "fixture", KEY)
    with pytest.raises(ValidationError, match="not registered"):
        journal.report(plan.digest)


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"schema_version": True, "participants": []},
        {"schema_version": 1, "participants": []},
        {"schema_version": 1, "participants": [None]},
        {
            "schema_version": 1,
            "participants": [{"participant_id": "PRIVATE@example.invalid", "recipient_index": 0}],
        },
        {"schema_version": 1, "participants": [{"participant_id": "p", "recipient_index": True}]},
        {"schema_version": 1, "participants": [{"participant_id": "p", "recipient_index": -1}]},
        {"schema_version": 1, "participants": [{"participant_id": "p", "recipient_index": 1}]},
        {
            "schema_version": 1,
            "participants": [{"participant_id": "p", "recipient_index": 0, "raw": "PRIVATE"}],
        },
        {"schema_version": 1, "participants": [{"participant_id": "p", "recipient_index": 0}] * 2},
        {
            "schema_version": 1,
            "participants": [
                {"participant_id": "p", "recipient_index": 0},
                {"participant_id": "q", "recipient_index": 0},
            ],
        },
    ],
)
def test_strict_unique_alias_to_recipient_bindings(document):
    with pytest.raises(ValidationError) as caught:
        participant_bindings(document, 1)
    assert "PRIVATE" not in str(caught.value)


@pytest.mark.parametrize(
    "change",
    [
        {"issuer": "other"},
        {"plan_digest": "a" * 64},
        {"participant_id": "other"},
        {"type": "reported"},
        {"automated": True},
        {"provenance": "adapter_claim"},
        {"event_id": "different"},
        {"occurred_at": (NOW - timedelta(seconds=1)).isoformat()},
        {"sent_at": (NOW + timedelta(seconds=1)).isoformat()},
    ],
)
def test_every_changed_signed_field_is_detected(tmp_path, change):
    journal, plan, _ = setup(tmp_path)
    envelope = sign_envelope(body(plan), KEY)
    with pytest.raises(ValidationError, match="signature"):
        journal.accept({**envelope, **change}, KEY)
    assert total(journal, plan) == 0


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"issuer": "a@PRIVATE"},
        {"event_id": "x" * 65},
        {"channel": []},
        {"channel": "voice", "type": "opened"},
        {"type": []},
        {"type": "raw_reply"},
        {"provenance": []},
        {"provenance": "observed"},
        {"automated": 0},
        {"signature": "A" * 64},
        {"signature": "bad"},
        {"plan_digest": "bad"},
        {"occurred_at": "2026-01-01"},
        {"sent_at": "2026-01-01T00:00:00+01:00"},
        {"occurred_at": "0001-01-01T00:00:00Z"},
        {"occurred_at": "2026-02-30T00:00:00Z"},
        {"occurred_at": (NOW + timedelta(seconds=1)).isoformat()},
        {"raw": "PRIVATE"},
    ],
)
def test_invalid_envelope_fields_are_redacted(tmp_path, change):
    _, plan, _ = setup(tmp_path)
    with pytest.raises(ValidationError) as caught:
        envelope_body({**sign_envelope(body(plan), KEY), **change})
    assert "PRIVATE" not in str(caught.value)


@pytest.mark.parametrize("key", [None, "k" * 32, b"", b"k" * 31, b"k" * 33, bytearray(b"k" * 32)])
def test_signing_key_type_and_length(key):
    with pytest.raises(ValidationError):
        sign_envelope({}, key)


def test_valid_signature_under_wrong_bound_key_or_issuer_cannot_enter(tmp_path):
    journal, plan, _ = setup(tmp_path)
    for key, changes in [
        (b"x" * 32, {}),
        (KEY, {"issuer": "other"}),
        (KEY, {"participant_id": "other"}),
        (KEY, {"channel": "voice"}),
    ]:
        with pytest.raises(ValidationError):
            journal.accept(sign_envelope(body(plan, **changes), key), key)
    assert total(journal, plan) == 0


@pytest.mark.parametrize("offset,accept", [(-300, True), (-301, False), (30, True), (31, False)])
def test_signature_freshness_boundaries(tmp_path, offset, accept):
    journal, plan, _ = setup(tmp_path)
    journal.clock = lambda: NOW + timedelta(seconds=400)
    sent = NOW + timedelta(seconds=400 + offset)
    signed = sign_envelope(body(plan, sent_at=sent.isoformat()), KEY)
    if accept:
        assert journal.accept(signed, KEY)["accepted"]
    else:
        with pytest.raises(ValidationError, match="freshness"):
            journal.accept(signed, KEY)


def test_occurrence_age_bound_and_occurrence_before_registration(tmp_path):
    plan, approval = approved("email")
    start = NOW - timedelta(days=2)
    approval = replace(approval, approved_at=start)
    journal = EventJournal(tmp_path / "events.sqlite", clock=lambda: start)
    journal.register(plan, approval, bindings(), "fixture", KEY)
    journal.clock = lambda: NOW
    for delta, allowed in [(86400, True), (86401, False)]:
        envelope = sign_envelope(
            body(
                plan,
                event_id="old-" + str(delta),
                occurred_at=(NOW - timedelta(seconds=delta)).isoformat(),
            ),
            KEY,
        )
        if allowed:
            journal.accept(envelope, KEY)
        else:
            with pytest.raises(ValidationError, match="freshness"):
                journal.accept(envelope, KEY)
    # Test the separate registration boundary with a fresh journal instead of hitting age first.
    current = EventJournal(tmp_path / "current.sqlite", clock=lambda: NOW)
    current.register(plan, replace(approval, approved_at=NOW), bindings(), "fixture", KEY)
    before = sign_envelope(body(plan, occurred_at=(NOW - timedelta(seconds=1)).isoformat()), KEY)
    with pytest.raises(ValidationError, match="outside"):
        current.accept(before, KEY)


def test_expiry_and_send_at_expiry_rejected_including_replays(tmp_path):
    journal, plan, approval = setup(tmp_path)
    envelope = sign_envelope(body(plan), KEY)
    journal.accept(envelope, KEY)
    journal.clock = lambda: plan.scope.expires_at - timedelta(seconds=1)
    future = sign_envelope(
        body(
            plan,
            event_id="expiry",
            occurred_at=(plan.scope.expires_at - timedelta(seconds=1)).isoformat(),
            sent_at=plan.scope.expires_at.isoformat(),
        ),
        KEY,
    )
    with pytest.raises(ValidationError, match="outside"):
        journal.accept(future, KEY)
    journal.clock = lambda: plan.scope.expires_at
    assert journal.report(plan.digest)["status"] == "expired"
    fresh = sign_envelope(body(plan, sent_at=plan.scope.expires_at.isoformat()), KEY)
    with pytest.raises(ValidationError, match="inactive"):
        journal.accept(fresh, KEY)
    with pytest.raises(ValidationError):
        journal.register(plan, approval, bindings(), "fixture", KEY)


def test_event_id_conflict_does_not_change_original(tmp_path):
    journal, plan, _ = setup(tmp_path)
    journal.accept(sign_envelope(body(plan), KEY), KEY)
    with pytest.raises(ValidationError, match="different signed"):
        journal.accept(sign_envelope(body(plan, type="reported"), KEY), KEY)
    assert total(journal, plan) == 1


def test_cancel_is_permanent_and_idempotent(tmp_path):
    journal, plan, approval = setup(tmp_path)
    envelope = sign_envelope(body(plan), KEY)
    journal.accept(envelope, KEY)
    assert journal.cancel(plan.digest)["changed"]
    assert not journal.cancel(plan.digest)["changed"]
    assert journal.report(plan.digest)["status"] == "cancelled"
    with pytest.raises(ValidationError, match="inactive"):
        journal.accept(envelope, KEY)
    with pytest.raises(ValidationError, match="cancelled"):
        journal.register(plan, approval, bindings(), "fixture", KEY)
    assert total(journal, plan) == 1


def test_participant_stop_is_provenance_scoped_and_retries_are_idempotent(tmp_path):
    journal, plan, _ = setup(tmp_path)
    stop = sign_envelope(body(plan, type="stop_requested"), KEY)
    journal.accept(stop, KEY)
    assert journal.accept(stop, KEY)["duplicate"]
    with pytest.raises(ValidationError, match="stopped"):
        journal.accept(sign_envelope(body(plan, event_id="later"), KEY), KEY)
    assert journal.accept(
        sign_envelope(body(plan, event_id="other", provenance="adapter_claim"), KEY), KEY
    )["accepted"]
    assert total(journal, plan) == 2


def test_automated_stop_is_excluded_without_claiming_participant_stop(tmp_path):
    journal, plan, _ = setup(tmp_path)
    journal.accept(sign_envelope(body(plan, type="stop_requested", automated=True), KEY), KEY)
    journal.accept(sign_envelope(body(plan, event_id="later"), KEY), KEY)
    assert total(journal, plan) == 2


def test_concurrent_replays_accept_exactly_once(tmp_path):
    journal, plan, _ = setup(tmp_path)
    envelope = sign_envelope(body(plan), KEY)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: journal.accept(envelope, KEY), range(20)))
    assert sum(r["accepted"] for r in results) == 1
    assert sum(r["duplicate"] for r in results) == 19
    assert total(journal, plan) == 1


def test_scope_is_rechecked_after_writer_lock(tmp_path, monkeypatch):
    journal, plan, approval = setup(tmp_path)
    transaction = journal.transaction
    clock = [NOW]
    journal.clock = lambda: clock[0]

    @contextmanager
    def locked(**kwargs):
        with transaction(**kwargs) as db:
            clock[0] = plan.scope.expires_at
            yield db

    monkeypatch.setattr(journal, "transaction", locked)
    with pytest.raises(ValidationError, match="inactive"):
        journal.accept(
            sign_envelope(body(plan, sent_at=plan.scope.expires_at.isoformat()), KEY), KEY
        )
    clock[0] = NOW
    with pytest.raises(ValidationError, match="expired"):
        journal.register(plan, approval, bindings(), "fixture", KEY)


def test_insert_and_stop_marker_are_one_transaction(tmp_path):
    journal, plan, _ = setup(tmp_path)
    with sqlite3.connect(journal.path) as db:
        db.execute(
            "CREATE TRIGGER fail_stop BEFORE INSERT ON event_stops "
            "BEGIN SELECT RAISE(ABORT,'PRIVATE'); END"
        )
    with pytest.raises(ValidationError) as caught:
        journal.accept(sign_envelope(body(plan, type="stop_requested"), KEY), KEY)
    assert "PRIVATE" not in str(caught.value) and total(journal, plan) == 0


def test_resource_limits_reject_new_records_but_keep_idempotent_retries(tmp_path, monkeypatch):
    import ai_threat_lab.training_events as events

    journal, plan, _ = setup(tmp_path)
    monkeypatch.setattr(events, "MAX_EVENTS", 1)
    signed = sign_envelope(body(plan), KEY)
    journal.accept(signed, KEY)
    assert journal.accept(signed, KEY)["duplicate"]
    with pytest.raises(ValidationError, match="event limit"):
        journal.accept(sign_envelope(body(plan, event_id="new"), KEY), KEY)
    monkeypatch.setattr(events, "MAX_PLANS", 1)
    other, approval = approved("voice")
    with pytest.raises(ValidationError, match="plan limit"):
        journal.register(other, approval, bindings(), "fixture", KEY)
    monkeypatch.setattr(events, "MAX_PARTICIPANTS", 1)
    with pytest.raises(ValidationError):
        participant_bindings(bindings(2), 2)


def test_key_file_generation_privacy_and_no_overwrite(tmp_path):
    path = tmp_path / "signing.key"
    metadata = create_key(path)
    key = read_key(path)
    assert len(key) == 32 and key.hex() not in json.dumps(metadata)
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        create_key(path)
    path.write_bytes(b"k" * 33)
    with pytest.raises(ValidationError):
        read_key(path)


@pytest.mark.parametrize(
    "raw",
    [b"[]", b"null", b'{"signature":"a","signature":"b"}', b'{"x":NaN}', b"\xff", b"x" * 8193],
    ids=["array", "null", "duplicate", "nan", "encoding", "size"],
)
def test_invalid_event_files_rejected_without_values(tmp_path, raw):
    path = tmp_path / "event.json"
    path.write_bytes(raw)
    with pytest.raises(ValidationError):
        read_envelope(path)


def test_input_links_directories_and_unrelated_databases_rejected(tmp_path):
    with pytest.raises(ValidationError):
        read_key(tmp_path)
    unrelated = tmp_path / "unrelated.sqlite"
    with sqlite3.connect(unrelated) as db:
        db.execute("CREATE TABLE unrelated (value TEXT)")
    with pytest.raises(ValidationError):
        EventJournal(unrelated)
    wrong = tmp_path / "wrong.sqlite"
    with sqlite3.connect(wrong) as db:
        db.execute("PRAGMA user_version=2")
    with pytest.raises(ValidationError):
        EventJournal(wrong)
    raw = tmp_path / "bad.sqlite"
    raw.write_bytes(b"PRIVATE not SQLite")
    with pytest.raises(ValidationError) as caught:
        EventJournal(raw)
    assert "PRIVATE" not in str(caught.value)
    link = tmp_path / "link"
    try:
        link.symlink_to(unrelated)
    except OSError:
        pytest.skip("No symlink support")
    with pytest.raises(ValidationError):
        EventJournal(link)
    with pytest.raises(ValidationError):
        read_key(link)


def test_oversized_journal_rejected_without_opening_sqlite(tmp_path):
    path = tmp_path / "big.sqlite"
    with path.open("wb") as stream:
        stream.truncate(32 * 1024 * 1024 + 1)
    with pytest.raises(ValidationError):
        EventJournal(path)


def test_no_network_processes_or_raw_reply_collection(tmp_path, monkeypatch):
    import subprocess

    def forbidden(*a, **k):
        pytest.fail("local signed-event journal must not connect or dispatch")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    journal, plan, _ = setup(tmp_path)
    journal.accept(sign_envelope(body(plan), KEY), KEY)
    assert total(journal, plan) == 1
    report = render_event_report({"untrusted": "<script>alert(1)</script>"})
    assert "<script>" not in report and "&lt;script&gt;" in report


def test_extreme_utc_offset_and_bad_clock_rejected(tmp_path):
    with pytest.raises(ValidationError):
        utc_text(datetime(9999, 12, 31, 23, tzinfo=timezone(-timedelta(hours=23))))
    journal, plan, _ = setup(tmp_path)
    journal.clock = lambda: NOW.replace(tzinfo=None)
    with pytest.raises(ValidationError):
        journal.report(plan.digest)


def test_sign_helper_rejects_signed_or_nonobject_input():
    for value in (None, [], {"signature": "a"}):
        with pytest.raises(ValidationError):
            sign_envelope(value, KEY)


def test_cli_key_register_import_replay_report_cancel_and_preflight(tmp_path):
    from ai_threat_lab.campaigns import CampaignScope, CampaignService, ContentApproval

    current = datetime.now(timezone.utc)
    recipient = "fictional@example.invalid"
    scope = CampaignScope("local", "reviewer", (recipient,), current + timedelta(hours=1))
    plan = CampaignService().prepare("email_training", scope, (recipient,), (), now=current)
    approval = ContentApproval(plan.digest, "reviewer", current)
    for name, value in [
        ("plan.json", plan_to_document(plan)),
        ("approval.json", approval_to_document(approval)),
        ("bindings.json", bindings()),
    ]:
        (tmp_path / name).write_text(json.dumps(value), encoding="utf-8")
    keyfile, ledger = tmp_path / "local.key", tmp_path / "claims.sqlite"
    result = run_cli("training-event-keygen", "--key-file", keyfile)
    assert result.returncode == 0, result.stderr
    key = read_key(keyfile)
    assert key.hex() not in result.stdout
    result = run_cli(
        "training-events-register",
        tmp_path / "plan.json",
        "--approval",
        tmp_path / "approval.json",
        "--bindings",
        tmp_path / "bindings.json",
        "--issuer",
        "fixture",
        "--key-file",
        keyfile,
        "--ledger",
        ledger,
    )
    assert result.returncode == 0, result.stderr
    occurred = datetime.now(timezone.utc).isoformat()
    event = sign_envelope(body(plan, occurred_at=occurred, sent_at=occurred), key)
    incoming = tmp_path / "event.json"
    incoming.write_text(json.dumps(event))
    args = ["training-events-import", incoming, "--key-file", keyfile, "--ledger", ledger]
    result = run_cli(*args)
    assert result.returncode == 0 and json.loads(result.stdout)["accepted"], result.stderr
    result = run_cli(*args)
    assert result.returncode == 0 and json.loads(result.stdout)["duplicate"]
    report = tmp_path / "report.html"
    report_args = ["training-events-report", "--ledger", ledger, "--plan-digest", plan.digest]
    result = run_cli(*report_args, "--format", "html", "--output", report)
    assert result.returncode == 0 and "local_signed_event_claims" in report.read_text()
    assert run_cli(*report_args, "--output", report).returncode == 2
    assert "alias-0" not in report.read_text()
    result = run_cli("training-events-cancel", "--ledger", ledger, "--plan-digest", plan.digest)
    assert result.returncode == 0 and json.loads(result.stdout)["cancelled"]
    assert run_cli(*args).returncode == 2
    assert run_cli("training-event-keygen", "--key-file", keyfile).returncode == 2


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "issuer",
        "plan_digest",
        "channel",
        "provenance",
        "event_id",
        "participant_id",
        "type",
        "automated",
        "occurred_at",
        "sent_at",
        "signature",
    ],
)
def test_missing_required_fields_rejected(field):
    plan, _ = approved("email")
    event = sign_envelope(body(plan), KEY)
    del event[field]
    with pytest.raises(ValidationError):
        envelope_body(event)


def test_canonical_json_key_order_whitespace_and_domain_separation(tmp_path):
    import hmac

    journal, plan, _ = setup(tmp_path)
    signed = sign_envelope(body(plan), KEY)
    reordered = dict(reversed(list(signed.items())))
    path = tmp_path / "event.json"
    path.write_text(json.dumps(reordered, indent=4), encoding="utf-8")
    assert journal.accept(read_envelope(path), KEY)["accepted"]
    raw_body = {k: v for k, v in signed.items() if k != "signature"}
    wrong_domain = hmac.digest(
        KEY, json.dumps(raw_body, sort_keys=True, separators=(",", ":")).encode(), "sha256"
    ).hex()
    with pytest.raises(ValidationError, match="signature"):
        journal.accept({**signed, "signature": wrong_domain}, KEY)


def test_competing_contents_for_one_event_id_never_overwrite(tmp_path):
    journal, plan, _ = setup(tmp_path)
    events = [sign_envelope(body(plan, type=kind), KEY) for kind in ("reported", "declined")]

    def importing(event):
        try:
            return journal.accept(event, KEY)["accepted"]
        except ValidationError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(importing, events))
    assert results.count(True) == 1 and total(journal, plan) == 1


def test_private_input_descriptors_close_on_type_race_or_stream_error(tmp_path, monkeypatch):
    import stat
    from types import SimpleNamespace

    import ai_threat_lab.training_events as events

    path = tmp_path / "key"
    path.write_bytes(KEY)
    close, fstat = events.os.close, events.os.fstat
    closed = []

    def closing(fd):
        closed.append(fd)
        close(fd)

    monkeypatch.setattr(events.os, "close", closing)
    monkeypatch.setattr(events.os, "fstat", lambda _: SimpleNamespace(st_mode=stat.S_IFIFO))
    with pytest.raises(ValidationError):
        read_key(path)
    assert len(closed) == 1
    monkeypatch.setattr(events.os, "fstat", fstat)

    def unavailable(*a, **k):
        raise OSError("stream setup unavailable")

    monkeypatch.setattr(events.os, "fdopen", unavailable)
    with pytest.raises(OSError):
        read_key(path)
    assert len(closed) == 2
    with pytest.raises(OSError):
        create_key(tmp_path / "new-key")
    assert len(closed) == 3


def test_special_paths_and_clock_before_supported_year_rejected(tmp_path):
    with pytest.raises(ValidationError):
        EventJournal(tmp_path)
    with pytest.raises(ValidationError):
        utc_text(NOW.replace(year=1969))
    if hasattr(os, "mkfifo"):
        path = tmp_path / "pipe"
        os.mkfifo(path)
        with pytest.raises(ValidationError):
            EventJournal(path)
        with pytest.raises(ValidationError):
            read_key(path)


def test_registration_accepts_maximum_alias_count_and_failed_approval_is_atomic(tmp_path):
    journal, plan, approval = setup(tmp_path, count=1000)
    assert journal.register(plan, approval, bindings(1000), "fixture", KEY)["duplicate"]
    assert total(journal, plan) == 0


def test_demo_bad_signature_cannot_write_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as offline

    signing = offline.sign_envelope
    monkeypatch.setattr(
        offline, "sign_envelope", lambda body, key: {**signing(body, key), "signature": "0" * 64}
    )
    with pytest.raises(ValidationError, match="signature"):
        offline.offline_demo(tmp_path / "demo", now=NOW)
    assert not (tmp_path / "demo" / "demo-result.json").exists()


def test_demo_incorrect_provenance_counts_cannot_write_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as offline

    original = offline.EventJournal.report

    def wrong(self, digest):
        report = original(self, digest)
        report["participant_behavior_verified"] = True
        return report

    monkeypatch.setattr(offline.EventJournal, "report", wrong)
    with pytest.raises(ValidationError, match="provenance"):
        offline.offline_demo(tmp_path / "demo", now=NOW)
    assert not (tmp_path / "demo" / "demo-result.json").exists()


def test_unrelated_version_one_database_is_not_modified(tmp_path):
    path = tmp_path / "unrelated.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE unrelated (value TEXT)")
        db.execute("INSERT INTO unrelated VALUES ('PRIVATE')")
        db.execute("PRAGMA user_version=1")
    original = path.read_bytes()
    with pytest.raises(ValidationError, match="schema tables"):
        EventJournal(path)
    assert path.read_bytes() == original
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT value FROM unrelated").fetchone()[0] == "PRIVATE"


def test_incompatible_columns_are_rejected_at_open(tmp_path):
    path = tmp_path / "events.sqlite"
    EventJournal(path)
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE event_records ADD COLUMN unexpected TEXT")
    original = path.read_bytes()
    with pytest.raises(ValidationError, match="schema columns"):
        EventJournal(path)
    assert path.read_bytes() == original
