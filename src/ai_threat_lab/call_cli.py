"""Explicit approved fictional-call preview, submission, lookup and stop commands."""

from pathlib import Path

from .call_jobs import status, stop, submit
from .call_training import HOST, CallConfig, preview
from .contracts import approval_from_document, plan_from_document, read_document, write_document
from .dispatch_journal import DispatchJournal
from .http_client import PublicHTTPS
from .integration_cli import exclusive_ai_output
from .models import ValidationError

COMMANDS = {"call-preview", "call-submit", "call-status", "call-stop", "call-cancel"}


def add_commands(commands):
    for name in sorted(COMMANDS):
        parser = commands.add_parser(name, help="Manage one approved fictional training call")
        if name != "call-cancel":
            parser.add_argument("plan", type=Path)
            parser.add_argument("--call-config", type=Path, required=True)
        if name in ("call-preview", "call-submit"):
            parser.add_argument("--approval", type=Path, required=True)
        if name != "call-preview":
            parser.add_argument("--ledger", type=Path, required=True)
        if name in ("call-status", "call-stop"):
            parser.add_argument("--receipt", type=Path, required=True)
            parser.add_argument("--network", action="store_true")
        if name in ("call-submit", "call-status", "call-stop"):
            parser.add_argument("--allow-call-host", required=True)
        if name in ("call-submit", "call-stop"):
            parser.add_argument("--output-dir", type=Path, required=True)
        else:
            parser.add_argument("--output", type=Path)
        if name == "call-submit":
            parser.add_argument("--preview-sha256", required=True)
            parser.add_argument("--send-call", action="store_true")
        if name == "call-cancel":
            parser.add_argument("--plan-digest", required=True)


def run_command(args):
    if args.command == "call-cancel":
        with exclusive_ai_output(args.output, args.ledger) as stream:
            journal = DispatchJournal(args.ledger, create=True)
            journal.cancel(args.plan_digest)
            value = journal.status(args.plan_digest)
            value["notice"] += " This command does not stop a remote call; use call-stop."
            text = write_document(value)
            if stream is not None:
                stream.write(text)
                print(f"Report saved: {args.output}")
            else:
                print(text, end="")
        return 0
    config = CallConfig.from_document(read_document(args.call_config))
    plan = plan_from_document(read_document(args.plan))
    if args.command == "call-submit" and not args.send_call:
        raise ValidationError("Review call-preview first, then explicitly --send-call")
    if args.command in ("call-status", "call-stop") and (
        not args.network or args.allow_call_host != HOST
    ):
        raise ValidationError("Call lookup/stop requires explicit network and exact provider host")
    if args.command in ("call-preview", "call-submit"):
        approval = approval_from_document(read_document(args.approval))
        prepared = preview(plan, approval, config)
        if args.command == "call-preview":
            text = write_document(prepared, args.output)
            print(f"Saved: {args.output}" if args.output else text, end="\n" if args.output else "")
            return 0
        if args.preview_sha256 != prepared["preview_sha256"] or args.allow_call_host != HOST:
            raise ValidationError("Call preview or provider host does not match")
    else:
        receipt = read_document(args.receipt)
    if args.command in ("call-submit", "call-stop"):
        destination = args.output_dir.resolve()
        if (args.output_dir.exists() or args.output_dir.is_symlink()
                or args.ledger.resolve().is_relative_to(destination)):
            raise ValidationError("Use a new output directory with the journal outside it")
    journal = DispatchJournal(args.ledger, create=args.command == "call-submit")
    client = PublicHTTPS([HOST], max_bytes=1024 * 1024,
                         max_requests=2 if args.command == "call-stop" else 1, timeout=15)
    if args.command == "call-submit":
        result = submit(plan, approval, config, journal, args.preview_sha256,
                        allowed_host=args.allow_call_host,
                        output_dir=args.output_dir, client=client)
        code = 0 if (result["status"] == "accepted"
                     and result["provider_status"] not in ("failed", "busy", "no-answer")) else 3
    elif args.command == "call-stop":
        result = stop(plan, config, journal, receipt, network=args.network,
                      allowed_host=args.allow_call_host, output_dir=args.output_dir, client=client)
        code = 0 if result["status"] in ("already_terminal", "provider_terminal") else 3
    else:
        with exclusive_ai_output(args.output, args.ledger) as stream:
            result = status(plan, config, journal, receipt, network=args.network,
                            allowed_host=args.allow_call_host, client=client)
            text = write_document(result)
            if stream is not None:
                stream.write(text)
                print(f"Report saved: {args.output}")
            else:
                print(text, end="")
        return 3 if result["provider_status"] in ("failed", "busy", "no-answer") else 0
    print(write_document(result), end="")
    return code


def call_menu(run, ask):
    print("1. Preview one fictional training call\n2. Submit the approved call\n"
          "3. Check a known call\n4. Stop a known call remotely\n"
          "5. Block future submissions locally (does not stop a remote call)\n0. Return")
    choice = ask("Choose 0–5: ")
    if choice == "0":
        return 0
    if choice not in ("1", "2", "3", "4", "5"):
        print("Choose a number from 0 to 5.")
        return 0
    commands = {"1": "call-preview", "2": "call-submit", "3": "call-status",
                "4": "call-stop", "5": "call-cancel"}
    arguments = [commands[choice]]
    if choice != "5":
        arguments += [ask("Original approved voice plan JSON: "),
                      "--call-config", ask("Call configuration JSON (no token): ")]
    if choice in ("1", "2"):
        arguments += ["--approval", ask("Approval JSON: ")]
    if choice != "1":
        arguments += ["--ledger", ask("Call attempt journal SQLite: ")]
    if choice == "5":
        arguments += ["--plan-digest", ask("Original plan digest: ")]
    if choice in ("3", "4"):
        arguments += ["--receipt", ask("Accepted call submission result JSON: ")]
    if choice in ("2", "3", "4"):
        arguments += ["--allow-call-host", ask("Exact provider host (api.twilio.com): ")]
    if choice == "2":
        arguments += ["--preview-sha256", ask("Reviewed preview SHA-256: ")]
        print("This calls the exact approved recipient and can incur provider charges.")
        if ask("Place this one call? [y/N]: ", required=False).lower() != "y":
            return 0
        arguments += ["--send-call"]
    if choice in ("3", "4"):
        operation = "Look up this call" if choice == "3" else "Request remote stop of this call"
        if ask(f"{operation}? [y/N]: ", required=False).lower() != "y":
            return 0
        arguments += ["--network"]
    if choice in ("2", "4"):
        arguments += ["--output-dir", ask("New operation output directory: ")]
    elif choice == "1":
        arguments += ["--output", ask("New private preview JSON (includes phone numbers): ")]
    return run(arguments)
