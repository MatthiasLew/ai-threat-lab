"""Read-only receipt recovery and single-transaction cancellation across existing local ledgers."""

import json
import os
import socket
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from test_cli_process import run_cli
from test_training_events import KEY, bindings, body, setup, total
from test_training_lab import NOW, approved

from ai_threat_lab.local_training_control import cancel_local_training, local_training_status
from ai_threat_lab.models import ValidationError
from ai_threat_lab.training_events import EventJournal, sign_envelope, validate_event_schema
from ai_threat_lab.training_lab import LabAction, TrainingLab


def exercise(tmp_path, *, count=1):
    journal, plan, approval = setup(tmp_path, count=count)
    lab = TrainingLab(tmp_path / "local.sqlite", clock=lambda: NOW)
    sessions = [
        lab.start(plan, approval, "local-" + str(i), recipient_index=i) for i in range(count)
    ]
    return lab, journal, plan, approval, sessions


def status(lab, journal, plan):
    return local_training_status(lab.path, journal.path, plan.digest, clock=lambda: NOW)


def cancel(lab, journal, plan):
    return cancel_local_training(lab.path, journal.path, plan.digest, clock=lambda: NOW)


def test_receipt_recovers_prior_acceptance_after_ttl_expiry_and_cancellation_without_writes(
    tmp_path,
):
    journal, plan, _ = setup(tmp_path)
    signed = sign_envelope(body(plan), KEY)
    journal.accept(signed, KEY)
    original = journal.path.read_bytes()
    historical = EventJournal(journal.path, create=False, clock=lambda: NOW + timedelta(days=2))
    receipt = historical.receipt(signed, KEY)
    assert receipt["state_in_this_journal"] == "recorded_matching"
    assert receipt["plan_status"] == "expired"
    assert not receipt["participant_behavior_verified"] and "alias-0" not in json.dumps(receipt)
    assert journal.path.read_bytes() == original
    journal.cancel(plan.digest)
    original = journal.path.read_bytes()
    assert historical.receipt(signed, KEY)["plan_status"] == "cancelled"
    assert journal.path.read_bytes() == original
    with pytest.raises(ValidationError):
        historical.accept(signed, KEY)
    assert total(journal, plan) == 1


def test_receipt_missing_and_conflicting_records_never_import_or_overwrite(tmp_path):
    journal, plan, _ = setup(tmp_path)
    signed = sign_envelope(body(plan), KEY)
    assert journal.receipt(signed, KEY)["state_in_this_journal"] == "not_recorded"
    assert total(journal, plan) == 0
    journal.accept(signed, KEY)
    changed = sign_envelope(body(plan, type="reported"), KEY)
    assert journal.receipt(changed, KEY)["state_in_this_journal"] == "event_id_conflict"
    assert total(journal, plan) == 1
    stopped = sign_envelope(body(plan, event_id="stop", type="stop_requested"), KEY)
    journal.accept(stopped, KEY)
    assert journal.receipt(signed, KEY)["stream_stopped"]
    assert (
        journal.receipt(sign_envelope(body(plan, event_id="future"), KEY), KEY)[
            "state_in_this_journal"
        ]
        == "not_recorded"
    )
    assert total(journal, plan) == 2


@pytest.mark.parametrize(
    "changes,key",
    [
        ({}, b"x" * 32),
        ({"issuer": "other"}, KEY),
        ({"channel": "voice"}, KEY),
        ({"participant_id": "other"}, KEY),
        ({"plan_digest": "a" * 64}, KEY),
    ],
)
def test_receipt_requires_original_scope_binding_even_with_a_valid_signature(
    tmp_path, changes, key
):
    journal, plan, _ = setup(tmp_path)
    with pytest.raises(ValidationError):
        journal.receipt(sign_envelope(body(plan, **changes), key), key)
    assert total(journal, plan) == 0


def test_receipt_rejects_tampering_and_never_renews_approval(tmp_path):
    journal, plan, _ = setup(tmp_path)
    signed = sign_envelope(body(plan), KEY)
    journal.accept(signed, KEY)
    with pytest.raises(ValidationError, match="signature"):
        journal.receipt({**signed, "type": "reported"}, KEY)
    journal.clock = lambda: NOW + timedelta(days=2)
    journal.receipt(signed, KEY)
    with pytest.raises(ValidationError):
        journal.accept(signed, KEY)


def test_existing_only_open_does_not_create_initialize_or_change_files(tmp_path):
    missing = tmp_path / "missing.sqlite"
    with pytest.raises(ValidationError, match="Existing"):
        EventJournal(missing, create=False)
    assert not missing.exists()
    missing.touch()
    with pytest.raises(ValidationError):
        EventJournal(missing, create=False)
    assert missing.read_bytes() == b""
    with pytest.raises(ValidationError):
        EventJournal(missing, create=1)
    db = sqlite3.connect(":memory:")
    try:
        with pytest.raises(ValidationError):
            validate_event_schema(db, schema="invalid")
    finally:
        db.close()


def test_combined_cancellation_stops_both_and_blocks_restart_and_new_events(tmp_path):
    lab, journal, plan, approval, sessions = exercise(tmp_path, count=2)
    signed = sign_envelope(body(plan), KEY)
    journal.accept(signed, KEY)
    before = status(lab, journal, plan)
    assert before["cancellation_state"] == "not_cancelled"
    assert before["stored_session_counts"] == {"running": 2}
    result = cancel(lab, journal, plan)
    assert result["changed"] and result["stopped_sessions"] == 2
    assert result["expired_sessions"] == 0
    assert result["cancellation_state"] == "both_cancelled"
    assert all(lab.get(s["session_id"])["status"] == "stopped" for s in sessions)
    assert journal.report(plan.digest)["status"] == "cancelled"
    with pytest.raises(ValidationError, match="cancelled"):
        lab.start(plan, approval, "new", recipient_index=0)
    assert not lab.record(sessions[0]["session_id"], LabAction.REPORT, "late")["applied"]
    with pytest.raises(ValidationError):
        journal.accept(sign_envelope(body(plan, event_id="late"), KEY), KEY)
    assert journal.receipt(signed, KEY)["state_in_this_journal"] == "recorded_matching"
    result = cancel(lab, journal, plan)
    assert not result["changed"] and result["stopped_sessions"] == 0
    assert total(journal, plan) == 1


@pytest.mark.parametrize("side", ["rehearsal", "event"])
def test_partial_individual_cancellation_is_visible_and_can_be_completed(tmp_path, side):
    lab, journal, plan, _, _ = exercise(tmp_path)
    (lab if side == "rehearsal" else journal).cancel(plan.digest)
    assert status(lab, journal, plan)["cancellation_state"] == "partially_cancelled"
    assert cancel(lab, journal, plan)["cancellation_state"] == "both_cancelled"


def test_status_does_not_expire_sessions_or_mutate_either_database(tmp_path):
    lab, journal, plan, _, _ = exercise(tmp_path)
    before = (lab.path.read_bytes(), journal.path.read_bytes())
    result = local_training_status(
        lab.path, journal.path, plan.digest, clock=lambda: NOW + timedelta(days=2)
    )
    assert result["event_plan_status"] == "expired"
    assert result["stored_session_counts"] == {"running": 1}
    assert before == (lab.path.read_bytes(), journal.path.read_bytes())
    result = cancel_local_training(
        lab.path, journal.path, plan.digest, clock=lambda: NOW + timedelta(days=2)
    )
    assert result["expired_sessions"] == 1 and result["stopped_sessions"] == 0
    assert result["stored_session_counts"] == {"expired": 1}


def test_completed_and_unrelated_sessions_and_claims_are_preserved(tmp_path):
    lab, journal, plan, _, sessions = exercise(tmp_path)
    lab.record(sessions[0]["session_id"], LabAction.REPORT, "complete")
    completed = lab.get(sessions[0]["session_id"])
    other, approval = approved("voice")
    second = lab.start(other, approval, "other")
    journal.register(other, approval, bindings(), "fixture", KEY)
    cancel(lab, journal, plan)
    assert lab.get(sessions[0]["session_id"]) == completed
    assert lab.get(second["session_id"])["status"] == "running"
    assert journal.accept(sign_envelope(body(other), KEY), KEY)["accepted"]


def test_event_only_registered_plan_still_blocks_future_rehearsals(tmp_path):
    journal, plan, approval = setup(tmp_path)
    lab = TrainingLab(tmp_path / "local.sqlite", clock=lambda: NOW)
    assert cancel(lab, journal, plan)["stopped_sessions"] == 0
    with pytest.raises(ValidationError, match="cancelled"):
        lab.start(plan, approval, "future")


@pytest.mark.parametrize("side", ["rehearsal", "event"])
def test_sql_failure_rolls_back_all_changes_in_both_files(tmp_path, side):
    lab, journal, plan, _, sessions = exercise(tmp_path)
    path = journal.path if side == "event" else lab.path
    trigger = (
        "CREATE TRIGGER failure BEFORE UPDATE OF cancelled ON event_plans "
        "BEGIN SELECT RAISE(ABORT,'PRIVATE'); END"
        if side == "event"
        else "CREATE TRIGGER failure BEFORE INSERT ON lab_revocations "
        "BEGIN SELECT RAISE(ABORT,'PRIVATE'); END"
    )
    with sqlite3.connect(path) as db:
        db.execute(trigger)
    before = (lab.path.read_bytes(), journal.path.read_bytes())
    with pytest.raises(ValidationError) as caught:
        cancel(lab, journal, plan)
    assert "PRIVATE" not in str(caught.value)
    assert before == (lab.path.read_bytes(), journal.path.read_bytes())
    assert status(lab, journal, plan)["cancellation_state"] == "not_cancelled"
    assert lab.get(sessions[0]["session_id"])["status"] == "running"


def test_concurrent_cancellation_is_idempotent_and_snapshots_do_not_show_half_commit(tmp_path):
    lab, journal, plan, _, _ = exercise(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(cancel, lab, journal, plan) for _ in range(6)]
        reads = [pool.submit(status, lab, journal, plan) for _ in range(12)]
        results = [f.result() for f in futures]
        snapshots = [f.result() for f in reads]
    assert sum(r["changed"] for r in results) == 1
    assert {r["cancellation_state"] for r in snapshots} <= {"not_cancelled", "both_cancelled"}


@pytest.mark.parametrize("side", ["rehearsal", "event"])
def test_wal_mode_rejected_without_conversion_or_state_changes(tmp_path, side):
    lab, journal, plan, _, _ = exercise(tmp_path)
    path = lab.path if side == "rehearsal" else journal.path
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
    with pytest.raises(ValidationError, match="DELETE"):
        cancel(lab, journal, plan)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert lab.get(next(iter(lab.report()["sessions"]))["id"])["status"] == "running"
    assert journal.report(plan.digest)["status"] == "active"


def test_missing_wrong_same_and_separate_directory_files_are_rejected_without_creation(tmp_path):
    lab, journal, plan, _, _ = exercise(tmp_path)
    missing = tmp_path / "missing.sqlite"
    for first, second in (
        (missing, journal.path),
        (lab.path, missing),
        (lab.path, lab.path),
        (tmp_path, journal.path),
        (journal.path, lab.path),
    ):
        with pytest.raises(ValidationError):
            cancel_local_training(first, second, plan.digest)
    assert not missing.exists()
    subdir = tmp_path / "other"
    subdir.mkdir()
    other = EventJournal(subdir / "event.sqlite")
    with pytest.raises(ValidationError):
        cancel_local_training(lab.path, other.path, plan.digest)
    with pytest.raises(ValidationError):
        cancel_local_training(lab.path, journal.path, "PRIVATE")
    with pytest.raises(ValidationError, match="registered"):
        cancel_local_training(lab.path, journal.path, "a" * 64)
    assert status(lab, journal, plan)["cancellation_state"] == "not_cancelled"


def test_incompatible_schemas_and_unknown_session_states_reject_without_updates(tmp_path):
    lab, journal, plan, _, _ = exercise(tmp_path)
    with sqlite3.connect(lab.path) as db:
        db.execute("ALTER TABLE lab_actions ADD COLUMN unexpected TEXT")
    before = (lab.path.read_bytes(), journal.path.read_bytes())
    with pytest.raises(ValidationError, match="columns"):
        cancel(lab, journal, plan)
    assert before == (lab.path.read_bytes(), journal.path.read_bytes())


def test_links_hardlinks_special_and_oversized_files_are_rejected(tmp_path):
    lab, journal, plan, _, _ = exercise(tmp_path)
    big = tmp_path / "big.sqlite"
    with big.open("wb") as stream:
        stream.truncate(128 * 1024 * 1024 + 1)
    with pytest.raises(ValidationError):
        cancel_local_training(big, journal.path, plan.digest)
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)
        with pytest.raises(ValidationError):
            cancel_local_training(fifo, journal.path, plan.digest)
    hard = tmp_path / "hard.sqlite"
    try:
        os.link(lab.path, hard)
    except OSError:
        pass
    else:
        with pytest.raises(ValidationError):
            cancel_local_training(lab.path, hard, plan.digest)
    link = tmp_path / "link.sqlite"
    try:
        link.symlink_to(lab.path)
    except OSError:
        pytest.skip("No symlink support")
    with pytest.raises(ValidationError):
        cancel_local_training(link, journal.path, plan.digest)


def test_no_network_or_subprocess_and_clock_validation(tmp_path, monkeypatch):
    import subprocess

    lab, journal, plan, _, _ = exercise(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("Local control must not execute or contact providers")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    with pytest.raises(ValidationError):
        cancel_local_training(
            lab.path, journal.path, plan.digest, clock=lambda: NOW.replace(tzinfo=None)
        )
    assert status(lab, journal, plan)["cancellation_state"] == "not_cancelled"
    assert cancel(lab, journal, plan)["cancellation_state"] == "both_cancelled"


def test_cli_receipts_after_expiry_cancel_status_no_overwrite_and_missing_ledger(tmp_path):
    lab, journal, plan, _, _ = exercise(tmp_path)
    signed = sign_envelope(body(plan), KEY)
    journal.accept(signed, KEY)
    key, event = tmp_path / "key.key", tmp_path / "event.json"
    key.write_bytes(KEY)
    event.write_text(json.dumps(signed))
    args = ["training-events-receipt", event, "--key-file", key, "--ledger", journal.path]
    result = run_cli(*args)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["state_in_this_journal"] == "recorded_matching"
    common = [
        "--training-ledger",
        lab.path,
        "--event-ledger",
        journal.path,
        "--plan-digest",
        plan.digest,
    ]
    result = run_cli("training-local-status", *common)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["cancellation_state"] == "not_cancelled"
    result = run_cli("training-local-cancel", *common)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["cancellation_state"] == "both_cancelled"
    result = run_cli(*args)
    assert result.returncode == 0 and json.loads(result.stdout)["plan_status"] == "cancelled"
    output = tmp_path / "receipt.json"
    assert run_cli(*args, "--output", output).returncode == 0
    assert run_cli(*args, "--output", output).returncode == 2
    missing = tmp_path / "missing.sqlite"
    result = run_cli("training-events-receipt", event, "--key-file", key, "--ledger", missing)
    assert result.returncode == 2 and not missing.exists()
    result = run_cli("training-events-report", "--ledger", missing, "--plan-digest", plan.digest)
    assert result.returncode == 2 and not missing.exists()


@pytest.mark.parametrize("kind", ["revision", "tables", "state"])
def test_invalid_lab_revision_table_or_state_rejects_without_mutating_either_file(tmp_path, kind):
    lab, journal, plan, _, _ = exercise(tmp_path)
    with sqlite3.connect(lab.path) as db:
        if kind == "revision":
            db.execute("PRAGMA user_version=1")
        elif kind == "tables":
            db.execute("CREATE TABLE unrelated (value TEXT)")
        else:
            db.execute("UPDATE lab_sessions SET status='PRIVATE'")
    original = (lab.path.read_bytes(), journal.path.read_bytes())
    with pytest.raises(ValidationError) as caught:
        cancel(lab, journal, plan)
    assert "PRIVATE" not in str(caught.value)
    assert original == (lab.path.read_bytes(), journal.path.read_bytes())


def test_uri_escaping_for_spaces_percent_hash_and_unicode_paths(tmp_path):
    directory = tmp_path / "workspace # % próbne"
    directory.mkdir()
    lab, journal, plan, _, _ = exercise(directory)
    signed = sign_envelope(body(plan), KEY)
    journal.accept(signed, KEY)
    assert (
        EventJournal(journal.path, create=False, clock=lambda: NOW).receipt(signed, KEY)[
            "state_in_this_journal"
        ]
        == "recorded_matching"
    )
    assert cancel(lab, journal, plan)["cancellation_state"] == "both_cancelled"


def test_other_journal_schema_and_invalid_sqlite_do_not_modify_training_database(tmp_path):
    lab, journal, plan, _, _ = exercise(tmp_path)
    with sqlite3.connect(journal.path) as db:
        db.execute("PRAGMA user_version=2")
    original = lab.path.read_bytes()
    with pytest.raises(ValidationError):
        cancel(lab, journal, plan)
    assert lab.path.read_bytes() == original
    invalid = tmp_path / "invalid.sqlite"
    invalid.write_bytes(b"PRIVATE not SQLite")
    with pytest.raises(ValidationError) as caught:
        cancel_local_training(lab.path, invalid, plan.digest)
    assert "PRIVATE" not in str(caught.value)
    assert lab.path.read_bytes() == original


def test_existing_journal_constructor_no_longer_rewrites_schema_header(tmp_path):
    journal, plan, _ = setup(tmp_path)
    original = journal.path.read_bytes()
    EventJournal(journal.path)
    assert journal.path.read_bytes() == original


def test_demo_fake_combined_cancellation_cannot_write_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as offline

    monkeypatch.setattr(
        offline,
        "cancel_local_training",
        lambda *a, **k: {
            "cancellation_state": "both_cancelled",
            "stopped_sessions": 1,
        },
    )
    with pytest.raises(ValidationError, match="combined local cancellation"):
        offline.offline_demo(tmp_path / "demo", now=NOW)
    assert not (tmp_path / "demo" / "demo-result.json").exists()


def test_demo_missing_receipt_cannot_write_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as offline

    monkeypatch.setattr(
        offline.EventJournal,
        "receipt",
        lambda *a, **k: {
            "state_in_this_journal": "not_recorded",
        },
    )
    with pytest.raises(ValidationError, match="historical receipt"):
        offline.offline_demo(tmp_path / "demo", now=NOW)
    assert not (tmp_path / "demo" / "demo-result.json").exists()
