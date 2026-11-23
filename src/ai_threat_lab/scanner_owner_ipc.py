"""Linux test-only approval broker. No scanner dispatch or public endpoint."""

import json
import os
import secrets
import socket
import stat
import struct
import sys
import time
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path

from .models import ValidationError
from .scan_bundle import encoded
from .scanner_approval import MAX_APPROVAL_SECONDS, ScannerReviewBroker, issue_owner_approval

PROTOCOL = 1
MAX_PACKET = 65536
DENIED = {"status": "denied"}
ALLOWED = {"status": "allowed"}


def _peer_uid(channel):
    size = struct.calcsize("3i")
    return struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size))[1]


def _receive(channel):
    raw, _, flags, _ = channel.recvmsg(MAX_PACKET)
    if not raw or flags & socket.MSG_TRUNC:
        raise ValidationError("Missing or oversized owner IPC message")
    return json.loads(raw)


def _send(channel, message):
    data = encoded(message)
    if len(data) > MAX_PACKET or channel.send(data) != len(data):
        raise ValidationError("Owner IPC message was not sent")


def _boot_seconds():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def _ledger_identity(path):
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        or info.st_uid != os.geteuid() or info.st_mode & 0o077
    ):
        raise ValidationError("Owner broker requires a private ledger")
    return info.st_dev, info.st_ino


class TestOwnerBroker:
    """One review per process generation, serialized decisions and redemption."""

    __test__ = False

    def __init__(self, review, policy, directory, *, owner_uid, launcher_uid, ttl=120):
        if sys.platform != "linux":
            raise ValidationError("Owner IPC is Linux-only")
        uid = os.geteuid()
        if len({uid, owner_uid, launcher_uid}) != 3 or min(uid, owner_uid, launcher_uid) <= 0:
            raise ValidationError("Owner, broker and launcher require separate unprivileged UIDs")
        if type(ttl) is not int or not 1 <= ttl <= MAX_APPROVAL_SECONDS:
            raise ValidationError("Invalid owner IPC lifetime")
        directory = Path(directory)
        info = directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or info.st_mode & 0o022 or directory.resolve() != directory.absolute()
        ):
            raise ValidationError("Owner broker requires a trusted socket directory")
        # The installation owns the ancestors. The ledger is kept below a
        # private directory separate from the socket.
        state = directory / "private"
        state.mkdir(mode=0o700, exist_ok=True)
        info = state.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
            raise ValidationError("Owner broker requires private state")
        self.path = directory / "owner.sock"
        self._ledger = state / "approval.sqlite"
        fd = os.open(self._ledger, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        self._identity = _ledger_identity(self._ledger)
        self._review = review
        self._key = secrets.token_bytes(32)
        self._broker = ScannerReviewBroker(self._ledger, owner_key=self._key)
        self._owner_uid = owner_uid
        self._launcher_uid = launcher_uid
        self._ttl = ttl
        self._deadline = _boot_seconds() + ttl
        self._approval = None
        self._decision_made = False
        fingerprint = review.fingerprint()
        if sha256(encoded(policy)).hexdigest() != review.plan.backend_policy_sha256:
            raise ValidationError("Owner IPC policy does not match reviewed plan")
        self._record = encoded({
            "protocol": PROTOCOL,
            "broker_uid": uid,
            "broker_generation": self._broker.ledger_id,
            "owner_uid": owner_uid,
            "launcher_uid": launcher_uid,
            "key_id": sha256(self._key).hexdigest(),
            "fingerprint": fingerprint,
            "plan": asdict(review.plan),
            "policy": policy,
            "runtime": review.runtime.manifest(),
            "snapshot": review.snapshot.manifest(),
            "valid_for_seconds_at_most": ttl,
        })
        if len(self._record) > MAX_PACKET // 2:
            raise ValidationError("Owner IPC review exceeds the display limit")
        self.operation = sha256(self._record).hexdigest()

    def listen(self, listener):
        listener.bind(str(self.path))
        # Kernel peer credentials authorize operations. This mode lets an
        # unrelated account reach the protocol denial path.
        self.path.chmod(0o666)
        listener.listen(4)

    def serve_one(self, listener):
        channel, _ = listener.accept()
        with channel:
            try:
                uid = _peer_uid(channel)
                if uid not in (self._owner_uid, self._launcher_uid):
                    return
                channel.settimeout(1)
                reply = self._handle(channel, uid, _receive(channel))
                _send(channel, reply)
            except (OSError, ValueError, ValidationError):
                # A lost redemption reply is a denial to the client. The
                # committed nonce stays spent.
                return

    def _handle(self, channel, uid, request):
        if _boot_seconds() >= self._deadline:
            return DENIED
        if uid == self._owner_uid:
            if request == ["review", PROTOCOL] and not self._decision_made:
                _send(channel, {"record": json.loads(self._record), "operation": self.operation})
                channel.settimeout(max(0.1, self._deadline - _boot_seconds()))
                decision = _receive(channel)
                if decision in (["approve", self.operation], ["deny", self.operation]):
                    self._decision_made = True
                    if decision[0] == "approve" and _boot_seconds() < self._deadline:
                        self._approval = issue_owner_approval(
                            self._review, owner_key=self._key, ledger_id=self._broker.ledger_id,
                            confirmed_fingerprint=self._review.fingerprint(), ttl=self._ttl,
                            authorization_context=self.operation,
                        )
                        return ALLOWED
            if request == ["revoke", self.operation] and self._approval is not None:
                self._decision_made = True
                self._approval = None
                return ALLOWED
        if (
            uid == self._launcher_uid and self._approval is not None
            and request == ["redeem", self.operation, self._review.fingerprint()]
        ):
            # Clear first so an uncertain commit or intact-inode rollback
            # cannot resurrect this generation's grant.
            approval, self._approval = self._approval, None
            if _ledger_identity(self._ledger) == self._identity:
                self._broker.redeem(self._review, approval)
                if _boot_seconds() < self._deadline:
                    return ALLOWED
        return DENIED


def owner_ipc_request(path, broker_uid, request, *, confirm=None, timeout=5):
    """Use from a trusted owner or launcher process. Transport failures deny."""
    if sys.platform != "linux":
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
            channel.settimeout(timeout)
            channel.connect(str(path))
            if _peer_uid(channel) != broker_uid:
                return False
            _send(channel, request)
            reply = _receive(channel)
            if confirm is not None:
                record, operation = reply["record"], reply["operation"]
                if (
                    record["protocol"] != PROTOCOL
                    or record["owner_uid"] != os.geteuid()
                    or sha256(encoded(record)).hexdigest() != operation
                ):
                    return False
                decision = "approve" if confirm(record, operation) is True else "deny"
                _send(channel, [decision, operation])
                reply = _receive(channel)
            return reply == ALLOWED
    except (OSError, ValueError, ValidationError, KeyError, TypeError):
        return False


def confirm_at_owner_terminal(record, operation):
    """Call only in the independently controlled owner login session."""
    with (
        open("/dev/tty", "w", encoding="utf-8") as terminal,
        open("/dev/tty", encoding="utf-8") as response,
    ):
        terminal.write(json.dumps(record, ensure_ascii=True, sort_keys=True, indent=2))
        terminal.write(f"\nType approve {operation} to allow this test operation: ")
        terminal.flush()
        return response.readline(128).rstrip("\n") == f"approve {operation}"
