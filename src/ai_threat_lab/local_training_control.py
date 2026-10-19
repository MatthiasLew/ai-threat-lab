"""Bounded attached-SQLite local cancellation; no external transport or provider control."""

import os
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .dependency_paths import linked
from .models import ValidationError
from .training_events import MAX_DATABASE, digest, event_time, utc_text, validate_event_schema

MAX_LAB_BYTES = 128 * 1024 * 1024
LAB_COLUMNS = {
    "lab_sessions": (
        "id",
        "plan_digest",
        "participant",
        "recipient_hash",
        "scenario",
        "channel",
        "created",
        "expires",
        "preview",
        "status",
        "outcome",
        "turns",
    ),
    "lab_actions": ("session_id", "request_id", "action", "selected_at"),
    "lab_revocations": ("plan_digest", "revoked_at"),
}
NOTICE = (
    "Local rehearsal and event acceptance only; no external delivery, calls, media or provider "
    "queues are controlled. Attached rollback-journal transaction relies on SQLite/VFS, "
    "filesystem locking and disk-flush guarantees; this is not a tamper-proof journal."
)


def paths(training_ledger, event_ledger):
    result = []
    for value, limit in ((training_ledger, MAX_LAB_BYTES), (event_ledger, MAX_DATABASE)):
        path = Path(value)
        if linked(path) or not path.is_file() or path.stat().st_size > limit:
            raise ValidationError(
                "Local control needs bounded existing regular databases without links"
            )
        result.append(path.resolve(strict=True))
    if result[0].parent != result[1].parent or os.path.samefile(*result):
        raise ValidationError(
            "Local control needs distinct databases in the same private directory"
        )
    return result


def validate_lab(db):
    tables = {r[0] for r in db.execute("SELECT name FROM main.sqlite_master WHERE type='table'")}
    if db.execute("PRAGMA main.user_version").fetchone()[0] != 0 or tables != set(LAB_COLUMNS):
        raise ValidationError("Local rehearsal schema is incompatible")
    for table, columns in LAB_COLUMNS.items():
        actual = tuple(r[1] for r in db.execute(f"PRAGMA main.table_info({table})"))
        if actual != columns:
            raise ValidationError("Local rehearsal schema columns are incompatible")


@contextmanager
def connected(training_ledger, event_ledger, *, write):
    lab, events = paths(training_ledger, event_ledger)
    try:
        # Explicit mode=rw prevents accidental creation if an input disappears.
        with closing(sqlite3.connect(lab.as_uri() + "?mode=rw", uri=True, timeout=15)) as db:
            db.row_factory = sqlite3.Row
            db.execute("ATTACH DATABASE ? AS events", (events.as_uri() + "?mode=rw",))
            db.execute("PRAGMA main.synchronous=FULL")
            db.execute("PRAGMA events.synchronous=FULL")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                for schema in ("main", "events"):
                    if (
                        db.execute(f"PRAGMA {schema}.journal_mode").fetchone()[0].lower()
                        != "delete"
                    ):
                        raise ValidationError("Local combined control requires DELETE journal mode")
                validate_lab(db)
                validate_event_schema(db, schema="events")
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise
    except sqlite3.Error:
        raise ValidationError(
            "Combined local operation failed; cancellation was not confirmed"
        ) from None


def snapshot(db, plan_digest, now):
    row = db.execute(
        "SELECT cancelled,expires FROM events.event_plans WHERE digest=?", (plan_digest,)
    ).fetchone()
    if row is None:
        raise ValidationError("Plan must already be registered in the event journal")
    revoked = (
        db.execute(
            "SELECT 1 FROM main.lab_revocations WHERE plan_digest=?", (plan_digest,)
        ).fetchone()
        is not None
    )
    counts = {
        r[0]: r[1]
        for r in db.execute(
            "SELECT status,count(*) FROM main.lab_sessions WHERE plan_digest=? GROUP BY status",
            (plan_digest,),
        )
    }
    if set(counts) - {"running", "stopped", "expired", "completed"}:
        raise ValidationError("Local rehearsal state is invalid")
    event_cancelled = bool(row["cancelled"])
    state = (
        "both_cancelled"
        if revoked and event_cancelled
        else "partially_cancelled"
        if revoked or event_cancelled
        else "not_cancelled"
    )
    return {
        "schema_version": 1,
        "mode": "combined_local_training_control",
        "plan_digest": plan_digest,
        "cancellation_state": state,
        "rehearsal_plan_revoked": revoked,
        "event_plan_status": "cancelled"
        if event_cancelled
        else "expired"
        if event_time(row["expires"]) <= now
        else "active",
        "stored_session_counts": counts,
        "notice": NOTICE,
    }


def local_training_status(training_ledger, event_ledger, plan_digest, *, clock=None):
    digest(plan_digest)
    with connected(training_ledger, event_ledger, write=False) as db:
        now = (clock or (lambda: datetime.now(timezone.utc)))()
        utc_text(now)
        return snapshot(db, plan_digest, now)


def cancel_local_training(training_ledger, event_ledger, plan_digest, *, clock=None):
    digest(plan_digest)
    with connected(training_ledger, event_ledger, write=True) as db:
        now = (clock or (lambda: datetime.now(timezone.utc)))()
        text = utc_text(now)
        before = snapshot(db, plan_digest, now)
        expired = db.execute(
            "UPDATE main.lab_sessions SET status='expired',outcome='scope_expired' "
            "WHERE plan_digest=? AND status='running' AND expires<=?",
            (plan_digest, now.timestamp()),
        ).rowcount
        stopped = db.execute(
            "UPDATE main.lab_sessions SET status='stopped',outcome='operator_cancelled' "
            "WHERE plan_digest=? AND status='running'",
            (plan_digest,),
        ).rowcount
        db.execute("INSERT OR IGNORE INTO main.lab_revocations VALUES(?,?)", (plan_digest, text))
        changed = db.execute(
            "UPDATE events.event_plans SET cancelled=1 WHERE digest=? AND cancelled=0",
            (plan_digest,),
        ).rowcount
        after = snapshot(db, plan_digest, now)
        after.update(
            changed=bool(stopped or expired or changed or not before["rehearsal_plan_revoked"]),
            stopped_sessions=stopped,
            expired_sessions=expired,
        )
        return after
