"""Durable at-most-one local dispatch attempt, outcomes and per-plan cancellation."""

import hashlib
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .dependency_paths import linked
from .models import ValidationError

APPLICATION_ID = 0x41544C44
MAX_BYTES = 8 * 1024 * 1024


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValidationError("Dispatch identifier must be SHA-256")
    return value


def delivery_key(plan_digest, recipient):
    identifier(plan_digest)
    return hashlib.sha256(f"{plan_digest}:{recipient}".encode("utf-8")).hexdigest()


class DispatchJournal:
    def __init__(self, path, *, create=False):
        self.path = Path(path)
        if linked(self.path) or (self.path.exists() and not self.path.is_file()):
            raise ValidationError("Dispatch journal must be a regular file without links")
        created = False
        if create and not self.path.exists():
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            created = True
        if not self.path.is_file() or self.path.stat().st_size > MAX_BYTES:
            raise ValidationError("Dispatch journal is missing or exceeds 8 MiB")
        with self.connection(write=created, initializing=created) as db:
            if created:
                db.execute(f"PRAGMA application_id={APPLICATION_ID}")
                db.execute("PRAGMA user_version=1")
                db.execute(
                    "CREATE TABLE attempts (key TEXT PRIMARY KEY, plan TEXT NOT NULL, "
                    "recipient TEXT NOT NULL, configuration TEXT NOT NULL, status TEXT NOT NULL "
                    "CHECK(status IN ('pending','accepted','unknown','rejected')), "
                    "updated TEXT NOT NULL)"
                )
                db.execute("CREATE TABLE cancelled (plan TEXT PRIMARY KEY)")

    @contextmanager
    def connection(self, *, write=False, initializing=False):
        if linked(self.path) or not self.path.is_file() or self.path.stat().st_size > MAX_BYTES:
            raise ValidationError("Dispatch journal is unavailable or exceeds its bound")
        # Existing-only URI prevents a deletion race from silently creating an empty journal.
        uri = self.path.resolve().as_uri() + ("?mode=rw" if write else "?mode=ro")
        db = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            db.execute("PRAGMA trusted_schema=OFF")
            if not initializing:
                if (
                    db.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
                    or db.execute("PRAGMA user_version").fetchone()[0] != 1
                ):
                    raise ValidationError("Not a supported dispatch journal")
                expected = {
                    "attempts": ["key", "plan", "recipient", "configuration", "status", "updated"],
                    "cancelled": ["plan"],
                }
                tables = {
                    row[0]
                    for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                if tables != set(expected):
                    raise ValidationError("Unexpected dispatch journal schema")
                for table, columns in expected.items():
                    if [row[1] for row in db.execute(f"PRAGMA table_info({table})")] != columns:
                        raise ValidationError("Unexpected dispatch journal columns")
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='trigger'").fetchone():
                    raise ValidationError("Dispatch journal triggers are unsupported")
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            if write:
                db.commit()
        except BaseException:
            if write:
                db.rollback()
            raise
        finally:
            db.close()

    def claim(self, plan, recipient, configuration):
        identifier(plan)
        identifier(configuration)
        key = delivery_key(plan, recipient)
        recipient_hash = hashlib.sha256(recipient.encode("utf-8")).hexdigest()
        with self.connection(write=True) as db:
            if db.execute("SELECT 1 FROM cancelled WHERE plan=?", (plan,)).fetchone():
                raise ValidationError("Dispatch plan has been cancelled")
            if db.execute("SELECT 1 FROM attempts WHERE key=?", (key,)).fetchone():
                raise ValidationError("Delivery was already attempted; inspect the journal")
            if db.execute("SELECT count(*) FROM attempts").fetchone()[0] >= 10000:
                raise ValidationError("Dispatch journal attempt limit reached")
            db.execute(
                "INSERT INTO attempts VALUES (?, ?, ?, ?, 'pending', ?)",
                (key, plan, recipient_hash, configuration, datetime.now(timezone.utc).isoformat()),
            )
        return key

    def outcome(self, key, status):
        identifier(key)
        if status not in ("accepted", "unknown", "rejected"):
            raise ValidationError("Invalid dispatch outcome")
        with self.connection(write=True) as db:
            changed = db.execute(
                "UPDATE attempts SET status=?,updated=? WHERE key=? AND status='pending'",
                (status, datetime.now(timezone.utc).isoformat(), key),
            ).rowcount
            if changed != 1:
                raise ValidationError("Only a pending dispatch outcome can be recorded")

    def cancel(self, plan):
        identifier(plan)
        with self.connection(write=True) as db:
            if db.execute("SELECT 1 FROM cancelled WHERE plan=?", (plan,)).fetchone():
                return
            if db.execute("SELECT count(*) FROM cancelled").fetchone()[0] >= 1000:
                raise ValidationError("Dispatch cancellation limit reached")
            db.execute("INSERT OR IGNORE INTO cancelled VALUES (?)", (plan,))

    def status(self, plan):
        identifier(plan)
        with self.connection() as db:
            cancelled = bool(db.execute("SELECT 1 FROM cancelled WHERE plan=?", (plan,)).fetchone())
            rows = db.execute(
                "SELECT key,recipient,configuration,status,updated FROM attempts "
                "WHERE plan=? ORDER BY key LIMIT 10001",
                (plan,),
            ).fetchall()
        if len(rows) > 10000:
            raise ValidationError("Dispatch result limit exceeded")
        from .contracts import timestamp

        for row in rows:
            for value in row[:3]:
                identifier(value)
            if row[3] not in ("pending", "accepted", "unknown", "rejected"):
                raise ValidationError("Dispatch journal contains an invalid outcome")
            timestamp(row[4], "dispatch update time")
        return {
            "schema_version": 1,
            "plan_digest": plan,
            "cancelled": cancelled,
            "attempts": [
                dict(
                    zip(
                        ("key", "recipient_sha256", "configuration_sha256", "status", "updated_at"),
                        row,
                        strict=True,
                    )
                )
                for row in rows
            ],
            "notice": "Accepted means server acceptance, not delivery or participant action. "
            "Pending/unknown attempts must not be retried automatically. "
            "Cancellation blocks later claims; it cannot recall an in-flight message. "
            "Hashes minimize stored data but do not anonymize known addresses.",
        }
