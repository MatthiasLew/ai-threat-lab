"""Fixed subprocess entry points for the Linux owner IPC acceptance suite."""

import json
import socket
import sys
from dataclasses import replace
from pathlib import Path

from ai_threat_lab import scanner_owner_ipc
from ai_threat_lab.scanner_approval import ScannerReview
from ai_threat_lab.scanner_objects import ScannerRuntime, capture_scanner_tree, digest
from ai_threat_lab.scanner_owner_ipc import (
    PROTOCOL,
    TestOwnerBroker,
    confirm_at_owner_terminal,
    owner_ipc_request,
)
from ai_threat_lab.scanner_sandbox import ScannerExecutionPlan


def review_fixture(directory):
    snapshot = capture_scanner_tree(directory / "input")
    runtime = ScannerRuntime(
        capture_scanner_tree(directory / "runtime"), "tool", "python", "config", (), (), (), (),
    )
    manifest = runtime.manifest()
    policy = {
        "test_only": True, "filesystem": "fixed readonly fixtures and private tmpfs",
        "network": "denied", "cpu_max": "20000 100000",
        "block_io": "unverified; production blocked",
        "publication": "exclusive SARIF import into the fixed result path",
    }
    plan = ScannerExecutionPlan(
        "bandit", snapshot.root, snapshot.fingerprint(), manifest["executable"],
        manifest["interpreter"], digest(manifest), manifest["configuration"],
        str(directory / "result.json"), 10, 128 * 1024**2, 8, 1024**2, 65536,
        "linux", "bubblewrap", digest(policy),
    )
    return ScannerReview(plan, snapshot, runtime), policy


def main():
    role, root, *arguments = sys.argv[1:]
    directory = Path(root)
    path = directory / "state" / "owner.sock"
    broker_uid, owner_uid, launcher_uid = 62001, 62002, 62003
    if role == "broker":
        review, policy = review_fixture(directory)
        wall_clock = scanner_owner_ipc.time.time
        offset_path = directory / "clock"
        scanner_owner_ipc.time.time = lambda: wall_clock() + int(offset_path.read_text())
        broker = TestOwnerBroker(
            review, policy, path.parent, owner_uid=owner_uid,
            launcher_uid=launcher_uid, ttl=int(arguments[0]),
        )
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            broker.listen(listener)
            print(json.dumps([broker.operation, review.fingerprint()]), flush=True)
            while True:
                broker.serve_one(listener)
    if role == "terminal":
        import fcntl
        import termios

        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        return not owner_ipc_request(
            path, broker_uid, ["review", PROTOCOL], confirm=confirm_at_owner_terminal,
        )
    if role == "custody":
        for target in ("state/private/approval.sqlite", f"/proc/{arguments[0]}/mem"):
            try:
                with (directory / target if not target.startswith("/") else Path(target)).open(
                    "rb",
                ):
                    return 1
            except PermissionError:
                pass
        return 0
    if role == "disconnect":
        def abandon(record, operation):
            sys.exit(0)

        return not owner_ipc_request(path, broker_uid, ["review", PROTOCOL], confirm=abandon)
    if role == "changed":
        operation, change = arguments
        review, _ = review_fixture(directory)
        field = "snapshot_sha256" if change == "snapshot" else "dependencies_sha256"
        changed = replace(review.plan, **{field: "0" * 64})
        return not owner_ipc_request(path, broker_uid, ["redeem", operation, changed.fingerprint()])
    return not owner_ipc_request(path, broker_uid, [role, *arguments])


if __name__ == "__main__":
    sys.exit(main())
