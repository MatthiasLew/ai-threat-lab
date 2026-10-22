"""Explicit delivery preview, send, status and cancellation; no implicit network operation."""

from pathlib import Path

from .contracts import (
    approval_from_document,
    plan_from_document,
    read_document,
    write_document,
)
from .dispatch_journal import DispatchJournal
from .integration_cli import exclusive_ai_output
from .models import ValidationError
from .smtp_training import SMTPConfig, preview, send

COMMANDS = {"smtp-preview", "smtp-send", "smtp-status", "smtp-cancel"}


def add_commands(commands):
    for name in ("smtp-preview", "smtp-send"):
        parser = commands.add_parser(
            name,
            help=(
                "Preview exact fictional email delivery without credentials"
                if name == "smtp-preview"
                else "Send explicitly approved fictional training email"
            ),
        )
        parser.add_argument("plan", type=Path)
        parser.add_argument("--approval", type=Path, required=True)
        parser.add_argument("--smtp-config", type=Path, required=True)
        parser.add_argument("--output", type=Path)
        if name == "smtp-send":
            parser.add_argument("--ledger", type=Path, required=True)
            parser.add_argument("--preview-sha256", required=True)
            parser.add_argument("--allow-smtp-host", required=True)
            parser.add_argument("--send-approved", action="store_true")
    for name in ("smtp-status", "smtp-cancel"):
        parser = commands.add_parser(
            name,
            help=(
                "Read local delivery outcomes"
                if name == "smtp-status"
                else "Permanently block new dispatch claims for this exact plan"
            ),
        )
        parser.add_argument("--ledger", type=Path, required=True)
        parser.add_argument("--plan-digest", required=True)
        parser.add_argument("--output", type=Path)


def run_command(args):
    if args.command in ("smtp-status", "smtp-cancel"):
        with exclusive_ai_output(args.output, args.ledger) as stream:
            journal = DispatchJournal(args.ledger, create=args.command == "smtp-cancel")
            if args.command == "smtp-cancel":
                journal.cancel(args.plan_digest)
            value = journal.status(args.plan_digest)
            text = write_document(value)
            if stream is not None:
                stream.write(text)
                print(f"Report saved: {args.output}")
            else:
                print(text, end="")
        return 0
    else:
        if args.command == "smtp-send" and not args.send_approved:
            raise ValidationError("Use smtp-preview first, then explicitly --send-approved")
        plan = plan_from_document(read_document(args.plan))
        approval = approval_from_document(read_document(args.approval))
        config = SMTPConfig.from_document(read_document(args.smtp_config))
        value = preview(plan, approval, config)
        if args.command == "smtp-send":
            if (
                args.preview_sha256 != value["preview_sha256"]
                or args.allow_smtp_host != config.host
            ):
                raise ValidationError("Delivery preview or SMTP host does not match")
            with exclusive_ai_output(args.output, args.ledger) as stream:
                journal = DispatchJournal(args.ledger, create=True)
                result = send(
                    plan,
                    approval,
                    config,
                    journal,
                    args.preview_sha256,
                    allowed_host=args.allow_smtp_host,
                )
                text = write_document(result)
                if stream is not None:
                    stream.write(text)
                    print(f"Report saved: {args.output}")
                else:
                    print(text, end="")
            return 0 if all(row["status"] == "accepted" for row in result["attempts"]) else 3
    text = write_document(value, args.output)
    print(f"Report saved: {args.output}" if args.output else text, end="\n" if args.output else "")
    return 0


def delivery_menu(run, ask):
    print("""
Fictional email delivery — account configuration required only for sending
1. Prepare exact SMTP delivery preview without connecting
2. Send using a reviewed preview fingerprint
3. Read the local delivery journal
4. Cancel future sends for an exact plan
0. Return
""")
    choice = ask("Choose 0–4: ")
    if choice == "0":
        return 0
    if choice in ("1", "2"):
        command = [
            "smtp-preview" if choice == "1" else "smtp-send",
            ask("Approved plan JSON: "),
            "--approval",
            ask("Approval JSON: "),
            "--smtp-config",
            ask("SMTP settings JSON (no secrets): "),
        ]
        if choice == "1":
            return run([*command, "--output", ask("New exact delivery preview JSON: ")])
        digest = ask("Exact preview_sha256 from the reviewed delivery preview: ")
        host = ask("Exact SMTP host from the reviewed delivery preview: ")
        journal = ask("Delivery journal SQLite path: ")
        print(
            "This sends the approved fictional email to every scoped recipient. "
            "Pending/unknown attempts are never automatically retried."
        )
        if ask("Send these approved messages now? [y/N]: ", required=False).lower() != "y":
            return 0
        return run(
            [
                *command,
                "--preview-sha256",
                digest,
                "--allow-smtp-host",
                host,
                "--ledger",
                journal,
                "--send-approved",
            ]
        )
    if choice in ("3", "4"):
        journal, digest = ask("Delivery journal SQLite path: "), ask("Exact plan digest: ")
        if (
            choice == "4"
            and ask("Permanently block later sends for this plan? [y/N]: ", required=False).lower()
            != "y"
        ):
            return 0
        return run(
            [
                "smtp-status" if choice == "3" else "smtp-cancel",
                "--ledger",
                journal,
                "--plan-digest",
                digest,
            ]
        )
    raise ValidationError("Choose a delivery operation from 0 to 4")
