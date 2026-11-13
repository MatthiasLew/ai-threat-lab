"""Kernel-backed tests require a privileged test coordinator on Linux."""

import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from ai_threat_lab import scanner_owner_ipc as ipc_module
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scan_bundle import encoded
from ai_threat_lab.scanner_objects import digest

BROKER, OWNER, LAUNCHER, AGENT = 62001, 62002, 62003, 62004


@pytest.fixture
def ipc():
    if sys.platform != "linux" or os.geteuid() != 0:
        pytest.skip("Linux owner IPC integration requires a privileged test coordinator")
    with tempfile.TemporaryDirectory(prefix="atl-ipc-", dir="/tmp") as location:
        root = Path(location)
        root.chmod(0o755)
        source = Path(__file__).resolve().parents[1] / "src"
        shutil.copytree(source / "ai_threat_lab", root / "ai_threat_lab")
        script = root / "fixture.py"
        shutil.copyfile(Path(__file__).with_name("owner_ipc_fixture.py"), script)
        state = root / "state"
        state.mkdir(mode=0o755)
        os.chown(state, BROKER, BROKER)
        (root / "input").mkdir()
        (root / "clock").write_text("0")
        (root / "input" / "sample.py").write_text("pass\n")
        (root / "runtime").mkdir()
        for name in ("tool", "python", "config"):
            (root / "runtime" / name).write_text(name)

        # Use the system interpreter so test accounts never traverse a user's home.
        def launch(uid, *args, **options):
            return subprocess.Popen(
                ["/usr/bin/python3", "-B", str(script), args[0], str(root), *args[1:]],
                user=uid, group=uid, extra_groups=[], cwd=root, env={}, **options,
            )

        yield root, launch


def start(launch, ttl=10):
    process = launch(BROKER, "broker", str(ttl), stdout=subprocess.PIPE)
    try:
        assert select.select([process.stdout], [], [], 5)[0]
        operation, fingerprint = json.loads(process.stdout.readline())
    except BaseException:
        process.kill()
        process.communicate(timeout=5)
        raise
    return process, operation, fingerprint


def stop(process):
    process.kill()
    process.communicate(timeout=5)


def request(launch, uid, *args):
    with launch(uid, *args) as process:
        return process.wait(timeout=5) == 0


def decide(launch, operation, *, approval):
    import pty

    # setsid + a real controlling terminal exercises the actual review UI.
    master, slave = pty.openpty()
    os.fchown(slave, OWNER, OWNER)
    with launch(
        OWNER, "terminal", stdin=slave, stdout=slave, stderr=slave,
        start_new_session=True,
    ) as process:
        try:
            transcript = b""
            while b"to allow this test operation" not in transcript:
                assert select.select([master], [], [], 5)[0], transcript
                transcript += os.read(master, 65536)
            assert b'"snapshot"' in transcript and b'"block_io"' in transcript
            os.write(master, (f"approve {operation}\n" if approval else "decline\n").encode())
            assert process.wait(timeout=5) == (0 if approval else 1)
        finally:
            if process.poll() is None:
                process.kill()
            os.close(slave)
            os.close(master)


def test_owner_ipc_single_use_and_custody(ipc):
    _, launch = ipc
    process, operation, fingerprint = start(launch)
    try:
        assert request(launch, AGENT, "custody", str(process.pid))
        assert not request(launch, AGENT, "redeem", operation, fingerprint)
        assert not request(launch, LAUNCHER, "approve", operation)
        assert not request(launch, LAUNCHER, "redeem", operation, fingerprint)
        decide(launch, operation, approval=True)
        assert not request(launch, OWNER, "redeem", operation, fingerprint)
        assert not request(launch, LAUNCHER, "redeem", operation, "other-fingerprint")
        with (
            launch(LAUNCHER, "redeem", operation, fingerprint) as first,
            launch(LAUNCHER, "redeem", operation, fingerprint) as second,
        ):
            assert sorted([first.wait(timeout=5), second.wait(timeout=5)]) == [0, 1]
        assert not request(launch, LAUNCHER, "redeem", operation, fingerprint)
    finally:
        stop(process)


@pytest.mark.parametrize("action", [
    "decline", "revoke", "expire", "replace", "rollback", "crash", "disconnect",
    "snapshot", "runtime",
    "clock-backward", "clock-forward",
])
def test_owner_ipc_refusals(ipc, action):
    root, launch = ipc
    process, operation, fingerprint = start(launch, ttl=3 if action == "expire" else 10)
    ledger = root / "state" / "private" / "approval.sqlite"
    original = ledger.read_bytes()
    try:
        if action == "disconnect":
            assert request(launch, OWNER, "disconnect")
        else:
            decide(launch, operation, approval=action != "decline")
        if action == "revoke":
            assert request(launch, OWNER, "revoke", operation)
        if action == "expire":
            time.sleep(3)
        if action in {"clock-backward", "clock-forward"}:
            (root / "clock").write_text("-3600" if action == "clock-backward" else "3600")
        if action == "replace":
            ledger.rename(ledger.with_suffix(".old"))
            ledger.write_bytes(original)
            ledger.chmod(0o600)
            os.chown(ledger, BROKER, BROKER)
        if action == "rollback":
            assert request(launch, LAUNCHER, "redeem", operation, fingerprint)
            ledger.write_bytes(original)
        if action == "crash":
            stop(process)
        if action in {"snapshot", "runtime"}:
            assert not request(launch, LAUNCHER, "changed", operation, action)
            assert request(launch, LAUNCHER, "redeem", operation, fingerprint)
        else:
            assert not request(launch, LAUNCHER, "redeem", operation, fingerprint)
    finally:
        stop(process)
    (root / "state" / "owner.sock").unlink()
    (root / "clock").write_text("0")
    ledger.unlink()
    restarted, new_operation, new_fingerprint = start(launch)
    try:
        assert new_operation != operation
        assert new_fingerprint == fingerprint
        decide(launch, new_operation, approval=True)
        assert not request(launch, LAUNCHER, "redeem", operation, fingerprint)
        assert request(launch, LAUNCHER, "redeem", new_operation, new_fingerprint)
    finally:
        stop(restarted)


@pytest.mark.parametrize("case", [
    "wrong-platform", "shared-uid", "zero-uid", "ttl", "directory", "private",
    "policy", "oversize",
])
def test_broker_refuses_invalid_configuration(tmp_path, monkeypatch, case):
    from owner_ipc_fixture import review_fixture

    platform = "win32" if case == "wrong-platform" else "linux"
    monkeypatch.setattr(ipc_module, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(ipc_module.os, "geteuid", lambda: 1, raising=False)
    monkeypatch.setattr(ipc_module, "_boot_seconds", lambda: 1)
    (tmp_path / "input").mkdir()
    (tmp_path / "runtime").mkdir()
    for name in ("tool", "python", "config"):
        (tmp_path / "runtime" / name).touch()
    # Capture with native path validation before simulating Linux ownership.
    review, policy = review_fixture(tmp_path)
    directory = tmp_path / "ipc"
    directory.mkdir()
    real_path = Path.lstat

    def lstat(path):
        result = real_path(path)
        mode = result.st_mode & ~0o777
        permissions = 0o755 if path == directory else 0o700 if path.name == "private" else 0o600
        unsafe_directory = case == "directory" and path == directory
        unsafe_state = case == "private" and path.name == "private"
        if unsafe_directory or unsafe_state:
            permissions = 0o777
        if path in {directory, directory / "private", directory / "private" / "approval.sqlite"}:
            return SimpleNamespace(
                st_uid=1, st_mode=mode | permissions, st_nlink=1,
                st_dev=result.st_dev, st_ino=result.st_ino,
                st_file_attributes=getattr(result, "st_file_attributes", 0),
            )
        return result

    if case == "oversize":
        policy = {"large": "x" * ipc_module.MAX_PACKET}
        review = replace(review, plan=replace(review.plan, backend_policy_sha256=digest(policy)))
    if case == "policy":
        policy = {}
    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(ValidationError):
        ipc_module.TestOwnerBroker(
            review, policy, directory, owner_uid=1 if case == "shared-uid" else 2,
            launcher_uid=0 if case == "zero-uid" else 3, ttl=0 if case == "ttl" else 10,
        )


@pytest.mark.parametrize("case", [
    "expired", "owner", "decline", "late-decision", "wrong-decision", "revoke", "agent",
    "launcher", "stale-ledger", "late-commit",
])
def test_request_dispatch(case, monkeypatch):
    broker = object.__new__(ipc_module.TestOwnerBroker)
    broker._deadline = 2
    readings = {
        "late-decision": (1, 1, 3), "late-commit": (1, 3), "expired": (3,),
    }.get(case, (1, 1, 1))
    monkeypatch.setattr(ipc_module, "_boot_seconds", iter(readings).__next__)
    broker._owner_uid, broker._launcher_uid = OWNER, LAUNCHER
    broker._decision_made = False
    broker.operation = "operation"
    broker._record = b"{}"
    broker._review = SimpleNamespace(fingerprint=lambda: "fingerprint")
    broker._key, broker._ttl = b"test fixture", 5
    broker._broker = Mock(ledger_id="ledger")
    broker._ledger = "ledger"
    broker._identity = 1
    broker._approval = object()
    issued = object()
    monkeypatch.setattr(ipc_module, "_ledger_identity", lambda path: int(case != "stale-ledger"))
    monkeypatch.setattr(ipc_module, "issue_owner_approval", lambda *args, **kwargs: issued)
    channel = Mock()
    channel.send.side_effect = len
    decision = {"decline": "deny", "wrong-decision": "bad"}.get(case, "approve")
    channel.recvmsg.return_value = (encoded([decision, broker.operation]), [], 0, None)
    if case in {"owner", "decline", "late-decision", "wrong-decision"}:
        uid, request_data = OWNER, ["review", ipc_module.PROTOCOL]
        broker._approval = None
    elif case == "revoke":
        uid, request_data = OWNER, ["revoke", broker.operation]
    else:
        uid = AGENT if case == "agent" else LAUNCHER
        request_data = ["redeem", broker.operation, "fingerprint"]
    expected = case in {"owner", "revoke", "launcher"}
    assert (broker._handle(channel, uid, request_data) == ipc_module.ALLOWED) is expected
    if case == "owner":
        assert broker._approval is issued
    if case in {"launcher", "late-commit", "stale-ledger", "revoke"}:
        assert broker._approval is None


def test_ipc_response_validation(monkeypatch):
    record = {"protocol": ipc_module.PROTOCOL, "owner_uid": OWNER}
    channel = Mock()
    channel.__enter__ = Mock(return_value=channel)
    channel.__exit__ = Mock(return_value=False)
    channel.send.side_effect = len
    monkeypatch.setattr(ipc_module, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(ipc_module.os, "geteuid", lambda: OWNER, raising=False)
    monkeypatch.setattr(ipc_module.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(ipc_module.socket, "SOCK_SEQPACKET", 5, raising=False)
    monkeypatch.setattr(ipc_module.socket, "MSG_TRUNC", 32, raising=False)
    monkeypatch.setattr(ipc_module.socket, "socket", lambda *args: channel)
    monkeypatch.setattr(ipc_module, "_peer_uid", lambda stream: BROKER)
    request_data = ["review", ipc_module.PROTOCOL]
    for reply in (
        {"record": record, "operation": "tampered"},
        {"record": record | {"protocol": 0}, "operation": digest(record)},
        {"record": record | {"owner_uid": AGENT}, "operation": digest(record)},
    ):
        channel.recvmsg.return_value = (encoded(reply), [], 0, None)
        assert not ipc_module.owner_ipc_request("socket", BROKER, request_data, confirm=Mock())
    for confirmed in (False, True):
        channel.recvmsg.side_effect = [
            (encoded({"record": record, "operation": digest(record)}), [], 0, None),
            (encoded(ipc_module.ALLOWED if confirmed else ipc_module.DENIED), [], 0, None),
        ]
        assert ipc_module.owner_ipc_request(
            "socket", BROKER, request_data, confirm=lambda *_: confirmed,
        ) is confirmed
    channel.recvmsg.side_effect = None
    channel.recvmsg.return_value = (b"", [], 0, None)
    assert not ipc_module.owner_ipc_request("socket", BROKER, request_data)
    assert not ipc_module.owner_ipc_request("socket", AGENT, request_data)
    monkeypatch.setattr(ipc_module, "sys", SimpleNamespace(platform="win32"))
    assert not ipc_module.owner_ipc_request("socket", BROKER, request_data)


@pytest.mark.parametrize("packet", [b"", b"malformed", b"[]", b"truncated"])
def test_broker_packet_handling(monkeypatch, packet):
    broker = object.__new__(ipc_module.TestOwnerBroker)
    broker._owner_uid, broker._launcher_uid = OWNER, LAUNCHER
    broker._deadline = 0
    broker.path = Mock()
    channel = MagicMock()
    listener = Mock()
    listener.accept.return_value = channel, None
    channel.send.side_effect = len
    monkeypatch.setattr(ipc_module.socket, "MSG_TRUNC", 32, raising=False)
    monkeypatch.setattr(ipc_module, "_boot_seconds", lambda: 1)
    monkeypatch.setattr(ipc_module, "_peer_uid", lambda stream: LAUNCHER)
    flags = ipc_module.socket.MSG_TRUNC if packet == b"truncated" else 0
    channel.recvmsg.return_value = packet, [], flags, None
    broker.listen(listener)
    broker.serve_one(listener)
    if packet == b"[]":
        channel.send.assert_called_once_with(encoded(ipc_module.DENIED))
    else:
        channel.send.assert_not_called()


def test_socket_peer_and_boot_clock(monkeypatch):
    import struct

    channel = Mock()
    channel.getsockopt.return_value = struct.pack("3i", 111, OWNER, OWNER)
    monkeypatch.setattr(ipc_module.socket, "SO_PEERCRED", 17, raising=False)
    assert ipc_module._peer_uid(channel) == OWNER
    monkeypatch.setattr(ipc_module.time, "CLOCK_BOOTTIME", 7, raising=False)
    monkeypatch.setattr(ipc_module.time, "clock_gettime", lambda clock: clock, raising=False)
    assert ipc_module._boot_seconds() == 7


@pytest.mark.parametrize("mode", [0o100644, 0o120600, 0o100600])
def test_ledger_requires_private_regular_file(monkeypatch, mode):
    monkeypatch.setattr(ipc_module.os, "geteuid", lambda: BROKER, raising=False)
    path = Mock()
    path.lstat.return_value = SimpleNamespace(
        st_mode=mode, st_nlink=1, st_uid=AGENT, st_dev=1, st_ino=2,
    )
    with pytest.raises(ValidationError, match="private ledger"):
        ipc_module._ledger_identity(path)


@pytest.mark.parametrize("case", ["large", "short"])
def test_ipc_requires_complete_send(case):
    channel = Mock()
    channel.send.return_value = 0
    message = "x" * ipc_module.MAX_PACKET if case == "large" else []
    with pytest.raises(ValidationError, match="was not sent"):
        ipc_module._send(channel, message)


@pytest.mark.parametrize("decision", ["approve operation\n", "decline\n"])
def test_terminal_displays_escaped_record(monkeypatch, decision):
    from io import StringIO

    stream = StringIO()
    transcript = []
    stream.close = lambda: transcript.append(stream.getvalue())
    def open_terminal(path, mode="r", **kwargs):
        return stream if mode == "w" else StringIO(decision)

    monkeypatch.setattr("builtins.open", open_terminal)
    assert ipc_module.confirm_at_owner_terminal({"path": "\x1b"}, "operation") is (
        decision.startswith("approve")
    )
    assert "\\u001b" in transcript[0]
