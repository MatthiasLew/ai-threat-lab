"""Local file-hash preview and explicitly consented reputation lookup."""

import os
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from .contracts import write_document
from .file_reputation import HOST, capture, preview, review
from .http_client import PublicHTTPS
from .models import ValidationError

COMMANDS = {"reputation-preview", "review-reputation"}


def add_commands(commands):
    for name in sorted(COMMANDS):
        parser = commands.add_parser(name, help="Preview or query existing file-hash reputation")
        parser.add_argument("path", type=Path)
        parser.add_argument("--output", type=Path)
        if name == "review-reputation":
            parser.add_argument("--network", action="store_true")
            parser.add_argument("--share-hash", action="store_true")
            parser.add_argument("--allow-host", required=True)
            parser.add_argument("--sha256", required=True)


@contextmanager
def claimed_output(path):
    if path is None:
        yield None
        return
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    identity, success = os.fstat(descriptor), False
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            yield stream
        success = True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if not success:
            try:
                if os.path.samestat(identity, Path(path).stat(follow_symlinks=False)):
                    Path(path).unlink()
            except FileNotFoundError:
                pass


def run_command(args):
    if args.command == "review-reputation" and (
        not args.network or not args.share_hash or args.allow_host != HOST
    ):
        raise ValidationError("Review reputation-preview, then authorize network, hash and host")
    raw = capture(args.path)
    with claimed_output(args.output) as stream:
        failed = False
        if args.command == "reputation-preview":
            value = preview(raw)
        else:
            result, failed = review(
                raw,
                expected_sha256=args.sha256,
                network=args.network,
                share_hash=args.share_hash,
                allowed_host=args.allow_host,
                client=PublicHTTPS([HOST], max_bytes=1024 * 1024, max_requests=1),
            )
            value = asdict(result)
        text = write_document(value)
        if stream is not None:
            stream.write(text)
            print(f"Report saved: {args.output}")
        else:
            print(text, end="")
    return 3 if failed else 0


def reputation_menu(run, ask):
    print(
        "1. Preview the local file hash and disclosure\n"
        "2. Query existing reputation for a reviewed hash\n0. Return"
    )
    choice = ask("Choose 0–2: ")
    if choice == "0":
        return 0
    if choice not in ("1", "2"):
        print("Choose a number from 0 to 2.")
        return 0
    source, output = ask("Local file: "), ask("New preview/report JSON: ")
    if choice == "1":
        return run(["reputation-preview", source, "--output", output])
    digest = ask("Reviewed SHA-256: ")
    print(
        "This sends the hash and API credential to www.virustotal.com. "
        "A hash can identify a private file; account quota and terms apply. "
        "File bytes are not uploaded."
    )
    if ask("Share this exact hash? [y/N]: ", required=False).lower() != "y":
        return 0
    return run(
        [
            "review-reputation",
            source,
            "--output",
            output,
            "--sha256",
            digest,
            "--network",
            "--share-hash",
            "--allow-host",
            HOST,
        ]
    )
