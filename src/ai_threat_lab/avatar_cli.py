"""Explicit fictional stock-avatar preview, job, download and approval handoff."""

from pathlib import Path

from .avatar_jobs import attach_asset, download, status, submit
from .avatar_training import MAX_VIDEO, AvatarConfig, preview
from .contracts import (
    approval_from_document,
    plan_from_document,
    plan_to_document,
    read_document,
    write_document,
)
from .dispatch_journal import DispatchJournal
from .http_client import PublicHTTPS
from .integration_cli import exclusive_ai_output
from .models import ValidationError

COMMANDS = {"avatar-preview", "avatar-submit", "avatar-status", "avatar-download",
            "avatar-cancel", "avatar-attach"}


def add_commands(commands):
    for name in sorted(COMMANDS):
        parser = commands.add_parser(name, help="Prepare or manage a fictional stock-avatar asset")
        if name != "avatar-cancel":
            parser.add_argument("--avatar-config", type=Path, required=True)
        if name in ("avatar-preview", "avatar-submit", "avatar-attach"):
            parser.add_argument("plan", type=Path)
            parser.add_argument("--approval", type=Path, required=True)
        if name in ("avatar-submit", "avatar-status", "avatar-download", "avatar-cancel"):
            parser.add_argument("--ledger", type=Path, required=True)
        if name in ("avatar-status", "avatar-download", "avatar-cancel"):
            parser.add_argument("--plan-digest", required=True)
        if name in ("avatar-submit", "avatar-status", "avatar-download"):
            parser.add_argument("--allow-avatar-host", required=True)
        if name in ("avatar-status", "avatar-download"):
            parser.add_argument("--network", action="store_true")
        if name in ("avatar-submit", "avatar-download"):
            parser.add_argument("--output-dir", type=Path, required=True)
        else:
            parser.add_argument("--output", type=Path, required=name == "avatar-attach")
        if name == "avatar-submit":
            parser.add_argument("--preview-sha256", required=True)
            parser.add_argument("--send-script", action="store_true")
        if name == "avatar-download":
            parser.add_argument("--allow-asset-host", required=True)
        if name == "avatar-attach":
            parser.add_argument("--download-dir", type=Path, required=True)


def run_command(args):
    if args.command == "avatar-cancel":
        with exclusive_ai_output(args.output, args.ledger) as stream:
            journal = DispatchJournal(args.ledger, create=True)
            journal.cancel(args.plan_digest)
            text = write_document(journal.status(args.plan_digest))
            if stream is not None:
                stream.write(text)
                print(f"Report saved: {args.output}")
            else:
                print(text, end="")
        return 0
    config = AvatarConfig.from_document(read_document(args.avatar_config))
    if args.command == "avatar-submit" and not args.send_script:
        raise ValidationError("Review avatar-preview first, then explicitly --send-script")
    if args.command in ("avatar-status", "avatar-download") and (
        not args.network or args.allow_avatar_host != config.resource_host
    ):
        raise ValidationError("Avatar retrieval requires explicit network and exact provider host")
    if args.command in ("avatar-preview", "avatar-submit", "avatar-attach"):
        plan = plan_from_document(read_document(args.plan))
        approval = approval_from_document(read_document(args.approval))
        prepared = preview(plan, approval, config)
        if args.command in ("avatar-preview", "avatar-attach"):
            value = prepared if args.command == "avatar-preview" else plan_to_document(
                attach_asset(plan, approval, config, args.download_dir))
            text = write_document(value, args.output)
            print(f"Saved: {args.output}" if args.output else text,
                  end="\n" if args.output else "")
            if args.command == "avatar-attach":
                print("Review the actual video, then approve this new plan digest before use.")
            return 0
        if (prepared["preview_sha256"] != args.preview_sha256
                or args.allow_avatar_host != config.resource_host):
            raise ValidationError("Avatar preview or provider host does not match")
    if args.command in ("avatar-submit", "avatar-download"):
        destination = args.output_dir.resolve()
        if (args.output_dir.exists() or args.output_dir.is_symlink()
                or args.ledger.resolve().is_relative_to(destination)):
            raise ValidationError("Use a new output directory and a journal outside it")
    journal = DispatchJournal(args.ledger, create=args.command == "avatar-submit")
    client = PublicHTTPS([config.resource_host], max_bytes=1024 * 1024, max_requests=1, timeout=60)
    if args.command == "avatar-submit":
        result = submit(plan, approval, config, journal, args.preview_sha256,
                        allowed_host=args.allow_avatar_host,
                        output_dir=args.output_dir, client=client)
        code = 0 if result["status"] == "accepted" else 3
    elif args.command == "avatar-download":
        result = download(
            journal, args.plan_digest, config, network=args.network,
            allowed_host=args.allow_avatar_host, allowed_asset_host=args.allow_asset_host,
            output_dir=args.output_dir, client=client,
            asset_client=PublicHTTPS([args.allow_asset_host], max_bytes=MAX_VIDEO,
                                     max_requests=1, timeout=60),
        )
        code = 0 if result["status"] == "downloaded" else 3
    else:
        with exclusive_ai_output(args.output, args.ledger) as stream:
            result = status(journal, args.plan_digest, config, network=args.network,
                            allowed_host=args.allow_avatar_host, client=client)
            text = write_document(result)
            if stream is not None:
                stream.write(text)
                print(f"Report saved: {args.output}")
            else:
                print(text, end="")
        return 3 if result["provider_status"] in ("Failed", "not_found") else 0
    print(write_document(result), end="")
    return code


def avatar_menu(run, ask):
    print("1. Prepare an exact stock-avatar preview\n2. Submit the approved script\n"
          "3. Check an existing job\n4. Download a completed asset\n"
          "5. Attach downloaded media to a new plan for approval\n"
          "6. Block future submissions locally\n0. Return")
    choice = ask("Choose 0–6: ")
    if choice == "0":
        return 0
    if choice not in ("1", "2", "3", "4", "5", "6"):
        print("Choose a number from 0 to 6.")
        return 0
    names = {"1": "avatar-preview", "2": "avatar-submit", "3": "avatar-status",
             "4": "avatar-download", "5": "avatar-attach", "6": "avatar-cancel"}
    arguments = [names[choice]]
    if choice in ("1", "2", "5"):
        arguments += [ask("Original approved video plan JSON: "),
                      "--approval", ask("Approval JSON: ")]
    if choice != "6":
        arguments += ["--avatar-config", ask("Avatar configuration JSON (no key): ")]
    if choice in ("2", "3", "4", "6"):
        arguments += ["--ledger", ask("Avatar attempt journal SQLite: ")]
    if choice in ("3", "4", "6"):
        arguments += ["--plan-digest", ask("Original plan digest: ")]
    if choice in ("2", "3", "4"):
        arguments += ["--allow-avatar-host", ask("Exact configured avatar resource host: ")]
    if choice == "2":
        arguments += ["--preview-sha256", ask("Reviewed preview SHA-256: ")]
        print("This submits the exact fictional script and can incur provider charges.")
        if ask("Submit this job once? [y/N]: ", required=False).lower() != "y":
            return 0
        arguments += ["--send-script"]
    if choice in ("3", "4"):
        if ask("Allow this existing job lookup? [y/N]: ", required=False).lower() != "y":
            return 0
        arguments += ["--network"]
    if choice == "4":
        arguments += ["--allow-asset-host", ask("Exact asset_host from job status: ")]
    if choice == "5":
        arguments += ["--download-dir", ask("Completed download directory: ")]
    if choice in ("2", "4"):
        arguments += ["--output-dir", ask("New output directory: ")]
    elif choice in ("1", "5"):
        arguments += ["--output", ask("New preview/plan JSON: ")]
    return run(arguments)
