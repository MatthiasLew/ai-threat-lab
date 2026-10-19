"""File-based signed event CLI; no webhook listener or live dispatch."""

from pathlib import Path

from .contracts import approval_from_document, plan_from_document, read_document, write_document
from .training_events import (
    EventJournal,
    create_key,
    read_envelope,
    read_key,
    render_event_report,
)

COMMANDS = {
    "training-event-keygen",
    "training-events-register",
    "training-events-import",
    "training-events-report",
    "training-events-cancel",
}


def add_commands(commands):
    key = commands.add_parser(
        "training-event-keygen", help="Create a local signing key, not an API key"
    )
    key.add_argument("--key-file", type=Path, required=True)
    register = commands.add_parser(
        "training-events-register", help="Bind an approved plan to event aliases/key"
    )
    register.add_argument("plan", type=Path)
    register.add_argument("--approval", type=Path, required=True)
    register.add_argument("--bindings", type=Path, required=True)
    register.add_argument("--issuer", required=True)
    register.add_argument("--key-file", type=Path, required=True)
    incoming = commands.add_parser(
        "training-events-import", help="Validate one signed saved event locally"
    )
    incoming.add_argument("envelope", type=Path)
    incoming.add_argument("--key-file", type=Path, required=True)
    report = commands.add_parser(
        "training-events-report", help="Aggregate signed claims by provenance"
    )
    report.add_argument("--plan-digest", required=True)
    report.add_argument("--format", choices=("json", "html"), default="json")
    cancel = commands.add_parser(
        "training-events-cancel", help="Permanently revoke local event acceptance"
    )
    cancel.add_argument("--plan-digest", required=True)
    for command in (register, incoming, report, cancel):
        command.add_argument(
            "--ledger", type=Path, required=True, help="Separate private event SQLite journal"
        )
    for command in (key, register, incoming, report, cancel):
        command.add_argument("--output", type=Path, help="New output file; never overwrite")


def run_command(args):
    if args.command == "training-event-keygen":
        payload = create_key(args.key_file)
    elif args.command == "training-events-register":
        plan = plan_from_document(read_document(args.plan))
        approval = approval_from_document(read_document(args.approval))
        bindings = read_document(args.bindings)
        key = read_key(args.key_file)
        payload = EventJournal(args.ledger).register(plan, approval, bindings, args.issuer, key)
    elif args.command == "training-events-import":
        event, key = read_envelope(args.envelope), read_key(args.key_file)
        payload = EventJournal(args.ledger).accept(event, key)
    elif args.command == "training-events-cancel":
        payload = EventJournal(args.ledger).cancel(args.plan_digest)
    else:
        payload = EventJournal(args.ledger).report(args.plan_digest)
        if args.format == "html":
            content = render_event_report(payload)
            if args.output:
                with args.output.open("x", encoding="utf-8") as stream:
                    stream.write(content)
                print(f"Report saved: {args.output}")
            else:
                print(content)
            return 0
    text = write_document(payload, args.output)
    print(f"Report saved: {args.output}" if args.output else text, end="\n" if args.output else "")
    return 0
