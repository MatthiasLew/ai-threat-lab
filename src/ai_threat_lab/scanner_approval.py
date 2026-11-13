"""Owner approval and durable redemption for offline scanner review."""

import hmac
import secrets
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path

from .models import ValidationError
from .scan_bundle import encoded
from .scanner_objects import ScannerRuntime, ScannerSnapshot, digest
from .scanner_sandbox import ScannerExecutionPlan

MAX_APPROVAL_SECONDS = 300


@dataclass(frozen=True, slots=True)
class ScannerReview:
    plan: ScannerExecutionPlan
    snapshot: ScannerSnapshot
    runtime: ScannerRuntime

    def fingerprint(self):
        runtime = self.runtime.manifest()
        if (
            self.plan.target != self.snapshot.root
            or self.plan.snapshot_sha256 != self.snapshot.fingerprint()
            or self.plan.executable_sha256 != runtime["executable"]
            or self.plan.interpreter_sha256 != runtime["interpreter"]
            or self.plan.configuration_sha256 != runtime["configuration"]
            or self.plan.dependencies_sha256 != digest(runtime)
        ):
            raise ValidationError("Scanner plan does not match captured objects")
        return self.plan.fingerprint()


@dataclass(frozen=True, slots=True)
class OwnerApproval:
    ledger_id: str
    plan_sha256: str
    nonce: str
    issued_at: int
    expires_at: int
    signature: str

    def message(self):
        return encoded({
            "purpose": "ai-threat-lab-scanner-review-v1", "plan_sha256": self.plan_sha256,
            "ledger_id": self.ledger_id,
            "nonce": self.nonce, "issued_at": self.issued_at, "expires_at": self.expires_at,
        })


def _signature(key, approval):
    if type(key) is not bytes or len(key) != 32:
        raise ValidationError("Owner approval requires a 256-bit key")
    return hmac.new(key, approval.message(), sha256).hexdigest()


def issue_owner_approval(review, *, owner_key, ledger_id, confirmed_fingerprint, ttl=120):
    """Use only inside a trusted owner application after its independent confirmation."""
    fingerprint = review.fingerprint()
    if confirmed_fingerprint != fingerprint:
        raise ValidationError("Owner confirmation must match the reviewed plan")
    if type(ttl) is not int or not 1 <= ttl <= MAX_APPROVAL_SECONDS:
        raise ValidationError("Invalid owner approval lifetime")
    now = int(time.time())
    approval = OwnerApproval(ledger_id, fingerprint, secrets.token_hex(32), now, now + ttl, "")
    return replace(approval, signature=_signature(owner_key, approval))


class ScannerReviewBroker:
    """An offline broker for a trusted local caller and an owner-controlled ledger."""

    def __init__(self, ledger, *, owner_key):
        self._ledger = Path(ledger).absolute()
        self._owner_key = owner_key
        with closing(sqlite3.connect(self._ledger)) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS redeemed_approval "
                "(nonce TEXT PRIMARY KEY, plan_sha256 TEXT NOT NULL, redeemed_at INTEGER NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS approval_ledger "
                "(slot INTEGER PRIMARY KEY CHECK (slot = 1), id TEXT NOT NULL)"
            )
            db.execute("INSERT OR IGNORE INTO approval_ledger VALUES (1, ?)",
                       (secrets.token_hex(32),))
            self.ledger_id = db.execute(
                "SELECT id FROM approval_ledger WHERE slot = 1"
            ).fetchone()[0]

    def redeem(self, review, approval):
        """Commit redemption before returning. A committed approval is never restored."""
        if not isinstance(approval, OwnerApproval):
            raise ValidationError("Owner approval is required")
        fingerprint = review.fingerprint()
        if approval.plan_sha256 != fingerprint or approval.ledger_id != self.ledger_id:
            raise ValidationError("Owner approval covers a different scanner plan")
        if not hmac.compare_digest(_signature(self._owner_key, approval), approval.signature):
            raise ValidationError("Owner approval signature is invalid")
        try:
            uri = self._ledger.as_uri() + "?mode=rw"
            with closing(sqlite3.connect(uri, uri=True)) as db, db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT id FROM approval_ledger WHERE slot = 1").fetchone() != (
                    self.ledger_id,
                ):
                    raise ValidationError("Owner approval ledger identity changed")
                now = int(time.time())
                if not (
                    approval.issued_at <= now < approval.expires_at
                    <= approval.issued_at + MAX_APPROVAL_SECONDS
                ):
                    raise ValidationError("Owner approval is expired or not yet valid")
                db.execute(
                    "INSERT INTO redeemed_approval VALUES (?, ?, ?) ON CONFLICT(nonce) DO NOTHING",
                    (approval.nonce, fingerprint, now),
                )
                if db.execute("SELECT changes()").fetchone() != (1,):
                    raise ValidationError("Owner approval was already used")
        except sqlite3.Error:
            raise ValidationError("Owner approval could not be durably consumed") from None
        return fingerprint
