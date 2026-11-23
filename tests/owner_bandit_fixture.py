"""Fixed subprocess entry points for the combined owner/Bandit acceptance."""

import json
import os
import socket
import sys
from pathlib import Path

from owner_bandit_handoff import LAUNCHER, OWNER, execute_approved, load_review
from owner_ipc_fixture import main as owner_client

from ai_threat_lab.scanner_owner_ipc import TestOwnerBroker


def main():
    role, root, *arguments = sys.argv[1:]
    directory = Path(root)
    if role == "custody":
        for path in (
            directory / "owner_bandit_handoff.py",
            directory / "ai_threat_lab" / "scanner_owner_ipc.py",
        ):
            try:
                descriptor = os.open(path, os.O_WRONLY)
            except PermissionError:
                continue
            os.close(descriptor)
            return 1
        return owner_client()
    if role in {"terminal", "approve", "redeem"}:
        return owner_client()
    if role == "recover":
        from linux_probe_supervision import recover_groups

        print(json.dumps(recover_groups(Path(arguments[0]), directory / "output" / "registry")))
        return 0
    review, policy, descriptors = load_review(int(arguments[0]))
    if role == "broker":
        for fd in {int(arguments[0]), *descriptors.values()}:
            os.close(fd)
        broker = TestOwnerBroker(
            review, policy, directory / "state", owner_uid=OWNER, launcher_uid=LAUNCHER,
        )
        if len(arguments) > 1 and arguments[1] == "drop-reply":
            from ai_threat_lab import scanner_owner_ipc

            send = scanner_owner_ipc._send

            def drop_after_commit(channel, message):
                if message == scanner_owner_ipc.ALLOWED and broker._approval is None:
                    channel.shutdown(socket.SHUT_RDWR)
                    raise OSError("Injected lost redemption response")
                send(channel, message)

            scanner_owner_ipc._send = drop_after_commit
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            broker.listen(listener)
            print(json.dumps([broker.operation, review.fingerprint()]), flush=True)
            while True:
                broker.serve_one(listener)
    if role == "launcher":
        os.close(int(arguments[0]))
        print("CAPTURED", flush=True)
        operation = sys.stdin.readline().strip()
        result = execute_approved(
            review, policy, descriptors, directory / "state" / "owner.sock", operation,
            fault=arguments[1],
        )
        print(json.dumps(result), flush=True)
        return 0
    raise ValueError("Unsupported test role")


if __name__ == "__main__":
    sys.exit(main())
