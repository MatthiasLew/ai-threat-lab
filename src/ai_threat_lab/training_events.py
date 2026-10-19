"""Local signed training-event journal; no transport, tracking server or behavior verification."""

import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import stat
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .campaigns import _utc
from .contracts import _nonfinite, _pairs, fields, version
from .models import ValidationError
from .training_lab import opaque, validate_approval

MAX_ENVELOPE = 8192
MAX_EVENTS = 10000
MAX_PLANS = 100
MAX_PARTICIPANTS = 1000
MAX_DATABASE = 32 * 1024 * 1024
MAX_AGE_SECONDS = 300
MAX_OCCURRENCE_AGE = 86400
FUTURE_SKEW = 30
DOMAIN = b"ai-threat-lab:training-event:v1\x00"
COMMON = frozenset(
    {"delivered", "reported", "verification_requested", "declined", "stop_requested"}
)
CHANNEL_EVENTS = {
    "email": COMMON | {"opened", "link_clicked"},
    "voice": COMMON | {"synthetic_info_shared"},
    "video": COMMON | {"opened", "synthetic_action_acknowledged"},
}
PROVENANCE = ("simulation", "adapter_claim")
TABLE_COLUMNS = {
    "event_plans": (
        "digest",
        "channel",
        "issuer",
        "key_hash",
        "created",
        "expires",
        "bindings",
        "cancelled",
    ),
    "event_records": (
        "plan",
        "event_id",
        "payload_hash",
        "participant",
        "type",
        "automated",
        "provenance",
        "occurred",
        "sent",
        "received",
    ),
    "event_stops": ("plan", "participant", "provenance"),
}
EVENT_FIELDS = {
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
}
NOTICE = (
    "Local shared-key signature validation only, not trusted provider-native telemetry or "
    "proof of participant identity/actions, delivery or compromise. "
    "Simulation, adapter claims and automated events remain separate. "
    "No messages sent, links tracked, calls placed, media generated or API credentials accessed."
)


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValidationError("Expected a lowercase SHA-256 digest")
    return value


def utc_text(value):
    _utc(value, "clock")
    if value.year < 1970:
        raise ValidationError("Event time must be in year 1970 or later")
    try:
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        raise ValidationError("Event UTC conversion exceeds supported dates") from None


def event_time(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]{1,6})?(?:Z|\+00:00)",
        value,
    ):
        raise ValidationError("Event timestamps require bounded UTC date/time strings")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        utc_text(result)
        return result
    except (ValueError, OverflowError):
        raise ValidationError("Invalid event timestamp; values omitted") from None


def key_bytes(key):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValidationError("Signing key must contain exactly 32 raw bytes")
    return key


def key_id(key):
    return hashlib.sha256(key_bytes(key)).hexdigest()


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def envelope_body(envelope):
    try:
        fields(envelope, EVENT_FIELDS)
        version(envelope)
        for field in ("issuer", "event_id", "participant_id"):
            opaque(envelope[field], "Event identifier")
        digest(envelope["plan_digest"])
        digest(envelope["signature"])
        channel = envelope["channel"]
        if (
            not isinstance(channel, str)
            or channel not in CHANNEL_EVENTS
            or not isinstance(envelope["type"], str)
            or envelope["type"] not in CHANNEL_EVENTS[channel]
            or envelope["provenance"] not in PROVENANCE
            or type(envelope["automated"]) is not bool
        ):
            raise ValidationError("Unsupported event channel/type/provenance or automated flag")
        occurred, sent = event_time(envelope["occurred_at"]), event_time(envelope["sent_at"])
        if occurred > sent:
            raise ValidationError("Event occurrence cannot be after signing time")
        body = {k: v for k, v in envelope.items() if k != "signature"}
        if len(canonical(envelope)) > MAX_ENVELOPE:
            raise ValidationError("Event envelope exceeds the 8 KiB limit")
        return body
    except (TypeError, RecursionError, UnicodeError):
        raise ValidationError("Invalid signed event envelope; values omitted") from None


def sign_envelope(body, key):
    """Adapter/test helper. A signed assertion is not participant-behavior proof."""
    key_bytes(key)
    if not isinstance(body, dict) or "signature" in body:
        raise ValidationError("Sign an event body without a signature field")
    validated = envelope_body({**body, "signature": "0" * 64})
    signature = hmac.new(key, DOMAIN + canonical(validated), hashlib.sha256).hexdigest()
    return {**validated, "signature": signature}


def read_regular(path, limit):
    path = Path(path)
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)() or not path.is_file():
        raise ValidationError("Event input must be a regular file without links")
    fd = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValidationError("Event input must be a regular file")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(limit + 1)
    finally:
        if fd is not None:
            os.close(fd)
    if len(raw) > limit:
        raise ValidationError("Event input exceeds its byte limit")
    return raw


def read_envelope(path):
    raw = read_regular(path, MAX_ENVELOPE)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
        envelope_body(value)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValidationError("Invalid signed event file; values omitted") from None


def read_key(path):
    return key_bytes(read_regular(path, 32))


def create_key(path):
    path = Path(path)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = None
            key = secrets.token_bytes(32)
            stream.write(key)
    finally:
        if fd is not None:
            os.close(fd)
    return {
        "schema_version": 1,
        "created": True,
        "key_id": key_id(key),
        "notice": "Local event-signing key created; plaintext was not printed. Not an API key.",
    }


def participant_bindings(document, recipient_count):
    fields(document, {"schema_version", "participants"})
    version(document)
    entries = document["participants"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_PARTICIPANTS:
        raise ValidationError("Bind between 1 and 1000 explicit participant aliases")
    result, indexes = {}, set()
    for entry in entries:
        fields(entry, {"participant_id", "recipient_index"})
        name = opaque(entry["participant_id"], "Participant alias")
        index = entry["recipient_index"]
        if (
            type(index) is not int
            or not 0 <= index < recipient_count
            or name in result
            or index in indexes
        ):
            raise ValidationError(
                "Participant aliases and approved recipient indexes must be unique"
            )
        result[name] = index
        indexes.add(index)
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def validate_event_schema(db, *, schema="main", allow_empty=False):
    if schema not in ("main", "events"):
        raise ValidationError("Unsupported event database schema name")
    revision = db.execute(f"PRAGMA {schema}.user_version").fetchone()[0]
    tables = {
        row[0] for row in db.execute(f"SELECT name FROM {schema}.sqlite_master WHERE type='table'")
    }
    if revision == 0 and not tables and allow_empty:
        return False
    if revision != 1:
        raise ValidationError("Event journal needs a new empty database or schema version 1")
    if tables != set(TABLE_COLUMNS):
        raise ValidationError("Event journal schema tables are incompatible")
    for table, columns in TABLE_COLUMNS.items():
        actual = tuple(row[1] for row in db.execute(f"PRAGMA {schema}.table_info({table})"))
        if actual != columns:
            raise ValidationError("Event journal schema columns are incompatible")
    return True


def verified_envelope(envelope, key):
    body = envelope_body(envelope)
    fingerprint = key_id(key)
    signature = hmac.new(key, DOMAIN + canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, envelope["signature"]):
        raise ValidationError("Event signature invalid")
    return body, fingerprint


class EventJournal:
    def __init__(self, path, *, clock=None, create=True):
        if type(create) is not bool:
            raise ValidationError("Event journal create option must be Boolean")
        self.path = Path(path)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        if self.path.is_symlink() or getattr(self.path, "is_junction", lambda: False)():
            raise ValidationError("Event journal must not be a link/junction")
        if self.path.exists() and not self.path.is_file():
            raise ValidationError("Event journal path must be a regular file")
        if create:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        elif not self.path.is_file():
            raise ValidationError("Existing event journal required; no file was created")
        with self.transaction(write=create) as db:
            if validate_event_schema(db, allow_empty=create):
                return
            db.execute(
                "CREATE TABLE IF NOT EXISTS event_plans (digest TEXT PRIMARY KEY, "
                "channel TEXT,issuer TEXT,key_hash TEXT,created TEXT,expires TEXT,"
                "bindings TEXT,cancelled INTEGER NOT NULL DEFAULT 0)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS event_records (plan TEXT,event_id TEXT,"
                "payload_hash TEXT,participant TEXT,type TEXT,automated INTEGER,provenance TEXT,"
                "occurred TEXT,sent TEXT,received TEXT,PRIMARY KEY(plan,event_id),"
                "FOREIGN KEY(plan) REFERENCES event_plans(digest))"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS event_stops (plan TEXT,participant TEXT,"
                "provenance TEXT,PRIMARY KEY(plan,participant,provenance),"
                "FOREIGN KEY(plan) REFERENCES event_plans(digest))"
            )
            db.execute("PRAGMA user_version=1")

    @contextmanager
    def transaction(self, *, write=True):
        if (
            self.path.is_symlink()
            or getattr(self.path, "is_junction", lambda: False)()
            or not self.path.is_file()
            or self.path.stat().st_size > MAX_DATABASE
        ):
            raise ValidationError("Event journal file type/size unsupported")
        try:
            uri = self.path.resolve().as_uri() + ("?mode=rw" if write else "?mode=ro")
            with closing(sqlite3.connect(uri, timeout=15, uri=True)) as db:
                db.row_factory = sqlite3.Row
                db.execute("PRAGMA foreign_keys=ON")
                db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 256 * 1024)
                db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                try:
                    yield db
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
        except sqlite3.Error:
            raise ValidationError(
                "Event journal operation failed; no new acceptance confirmed"
            ) from None

    def now(self):
        current = self.clock()
        utc_text(current)
        return current.astimezone(timezone.utc)

    @staticmethod
    def plan(db, plan_digest):
        digest(plan_digest)
        row = db.execute("SELECT * FROM event_plans WHERE digest=?", (plan_digest,)).fetchone()
        if row is None:
            raise ValidationError("Approved event plan is not registered")
        return row

    def register(self, plan, approval, bindings, issuer, key):
        now = self.now()
        validate_approval(plan, approval, now)
        opaque(issuer, "Issuer alias")
        fingerprint = key_id(key)
        selected = participant_bindings(bindings, len(plan.recipients))
        expiry = utc_text(plan.scope.expires_at)
        with self.transaction() as db:
            now = self.now()
            validate_approval(plan, approval, now)
            prior = db.execute(
                "SELECT * FROM event_plans WHERE digest=?", (plan.digest,)
            ).fetchone()
            if prior is not None:
                if (
                    prior["cancelled"]
                    or prior["channel"] != plan.channel
                    or prior["issuer"] != issuer
                    or prior["key_hash"] != fingerprint
                    or prior["bindings"] != selected
                ):
                    raise ValidationError(
                        "Plan registration conflicts or was permanently cancelled"
                    )
                return {"registered": False, "duplicate": True, "plan_digest": plan.digest}
            if db.execute("SELECT count(*) FROM event_plans").fetchone()[0] >= MAX_PLANS:
                raise ValidationError("Event journal plan limit reached")
            db.execute(
                "INSERT INTO event_plans VALUES (?,?,?,?,?,?,?,0)",
                (plan.digest, plan.channel, issuer, fingerprint, utc_text(now), expiry, selected),
            )
        return {
            "registered": True,
            "duplicate": False,
            "plan_digest": plan.digest,
            "channel": plan.channel,
            "participant_bindings": len(json.loads(selected)),
            "notice": "Caller-supplied exact-plan approval; not reviewer identity verification.",
        }

    def accept(self, envelope, key):
        body, fingerprint = verified_envelope(envelope, key)
        sent, occurred = event_time(body["sent_at"]), event_time(body["occurred_at"])
        payload_hash = hashlib.sha256(canonical(body)).hexdigest()
        with self.transaction() as db:
            now = self.now()  # Recheck freshness/scope after acquiring the writer lock.
            if (
                (now - sent).total_seconds() > MAX_AGE_SECONDS
                or (sent - now).total_seconds() > FUTURE_SKEW
                or (now - occurred).total_seconds() > MAX_OCCURRENCE_AGE
            ):
                raise ValidationError("Event freshness window exceeded")
            plan = self.plan(db, body["plan_digest"])
            if (
                plan["cancelled"]
                or event_time(plan["expires"]) <= now
                or body["channel"] != plan["channel"]
                or body["issuer"] != plan["issuer"]
                or fingerprint != plan["key_hash"]
            ):
                raise ValidationError(
                    "Event plan is inactive or issuer/channel/key binding differs"
                )
            if (
                occurred < event_time(plan["created"])
                or sent >= event_time(plan["expires"])
                or body["participant_id"] not in json.loads(plan["bindings"])
            ):
                raise ValidationError("Event participant/time is outside the registered scope")
            prior = db.execute(
                "SELECT payload_hash FROM event_records WHERE plan=? AND event_id=?",
                (body["plan_digest"], body["event_id"]),
            ).fetchone()
            if prior is not None:
                if prior[0] != payload_hash:
                    raise ValidationError("Event ID reused with different signed contents")
                return {"accepted": False, "duplicate": True, "plan_digest": body["plan_digest"]}
            identity = (body["plan_digest"], body["participant_id"], body["provenance"])
            if db.execute(
                "SELECT 1 FROM event_stops WHERE plan=? AND participant=? AND provenance=?",
                identity,
            ).fetchone():
                raise ValidationError("Participant stopped this event provenance stream")
            if db.execute("SELECT count(*) FROM event_records").fetchone()[0] >= MAX_EVENTS:
                raise ValidationError("Event journal event limit reached")
            db.execute(
                "INSERT INTO event_records VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    body["plan_digest"],
                    body["event_id"],
                    payload_hash,
                    body["participant_id"],
                    body["type"],
                    int(body["automated"]),
                    body["provenance"],
                    utc_text(occurred),
                    utc_text(sent),
                    utc_text(now),
                ),
            )
            if body["type"] == "stop_requested" and not body["automated"]:
                db.execute("INSERT INTO event_stops VALUES (?,?,?)", identity)
        return {
            "accepted": True,
            "duplicate": False,
            "plan_digest": body["plan_digest"],
            "provenance": body["provenance"],
            "notice": NOTICE,
        }

    def receipt(self, envelope, key):
        """Reconcile local acceptance even after TTL/expiry/cancellation; never import again."""
        body, fingerprint = verified_envelope(envelope, key)
        payload_hash = hashlib.sha256(canonical(body)).hexdigest()
        with self.transaction(write=False) as db:
            plan = self.plan(db, body["plan_digest"])
            if (
                body["channel"] != plan["channel"]
                or body["issuer"] != plan["issuer"]
                or fingerprint != plan["key_hash"]
                or body["participant_id"] not in json.loads(plan["bindings"])
            ):
                raise ValidationError("Receipt key/issuer/channel/participant binding differs")
            prior = db.execute(
                "SELECT payload_hash FROM event_records WHERE plan=? AND event_id=?",
                (body["plan_digest"], body["event_id"]),
            ).fetchone()
            state = (
                "not_recorded"
                if prior is None
                else "recorded_matching"
                if prior[0] == payload_hash
                else "event_id_conflict"
            )
            stopped = (
                db.execute(
                    "SELECT 1 FROM event_stops WHERE plan=? AND participant=? AND provenance=?",
                    (body["plan_digest"], body["participant_id"], body["provenance"]),
                ).fetchone()
                is not None
            )
            current = self.now()
            status = (
                "cancelled"
                if plan["cancelled"]
                else "expired"
                if event_time(plan["expires"]) <= current
                else "active"
            )
        return {
            "schema_version": 1,
            "mode": "local_event_receipt",
            "plan_digest": body["plan_digest"],
            "event_id": body["event_id"],
            "state_in_this_journal": state,
            "plan_status": status,
            "stream_stopped": stopped,
            "participant_behavior_verified": False,
            "notice": "Read-only local record check; does not accept, renew or resend anything. "
            "Not evidence of external delivery, participant behavior or missing history "
            "in a different/restored journal.",
        }

    def cancel(self, plan_digest):
        with self.transaction() as db:
            self.plan(db, plan_digest)
            changed = db.execute(
                "UPDATE event_plans SET cancelled=1 WHERE digest=? AND cancelled=0", (plan_digest,)
            ).rowcount
        return {
            "plan_digest": plan_digest,
            "cancelled": True,
            "changed": bool(changed),
            "notice": "Local event acceptance cancelled; external delivery is not controlled.",
        }

    def report(self, plan_digest):
        with self.transaction(write=False) as db:
            now = self.now()
            plan = self.plan(db, plan_digest)
            groups = {}
            for provenance in PROVENANCE:
                rows = db.execute(
                    "SELECT type,automated,count(*) AS n,count(DISTINCT participant) "
                    "AS people FROM event_records WHERE plan=? AND provenance=? "
                    "GROUP BY type,automated",
                    (plan_digest, provenance),
                ).fetchall()
                counts, people, automated = {}, {}, 0
                for row in rows:
                    if row["automated"]:
                        automated += row["n"]
                    else:
                        counts[row["type"]], people[row["type"]] = row["n"], row["people"]
                active_people = db.execute(
                    "SELECT count(DISTINCT participant) FROM event_records "
                    "WHERE plan=? AND provenance=? AND automated=0 "
                    "AND type!='delivered'",
                    (plan_digest, provenance),
                ).fetchone()[0]
                groups[provenance] = {
                    "automated_events_excluded": automated,
                    "nonautomated_events_by_type": counts,
                    "nonautomated_participants_by_type": people,
                    "claimed_action_participants": active_people,
                }
            status = (
                "cancelled"
                if plan["cancelled"]
                else "expired"
                if event_time(plan["expires"]) <= now
                else "active"
            )
            return {
                "schema_version": 1,
                "mode": "local_signed_event_claims",
                "plan_digest": plan_digest,
                "channel": plan["channel"],
                "status": status,
                "groups": groups,
                "participant_behavior_verified": False,
                "external_transport_validated": False,
                "notice": NOTICE,
            }


def render_event_report(report):
    encoded = html.escape(json.dumps(report, indent=2, ensure_ascii=True))
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'">'
        "<title>Signed training event claims</title><h1>Signed training event claims</h1>"
        f"<p>{html.escape(NOTICE)}</p><pre>{encoded}</pre></html>"
    )
