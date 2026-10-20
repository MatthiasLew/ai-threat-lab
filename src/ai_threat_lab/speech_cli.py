"""Speech asset generation: offline exact preview and explicit optional paid request."""

from pathlib import Path

from .contracts import approval_from_document, plan_from_document, read_document, write_document
from .dispatch_journal import DispatchJournal
from .http_client import PublicHTTPS
from .integration_cli import exclusive_ai_output
from .models import ValidationError
from .speech_training import MAX_AUDIO, SpeechConfig, generate, preview

COMMANDS = {"speech-preview", "speech-generate", "speech-status", "speech-cancel"}


def add_commands(commands):
    for name in ("speech-preview", "speech-generate"):
        parser = commands.add_parser(name, help="Prepare or generate a fictional stock-voice asset")
        parser.add_argument("plan", type=Path)
        parser.add_argument("--approval", type=Path, required=True)
        parser.add_argument("--speech-config", type=Path, required=True)
        if name == "speech-preview":
            parser.add_argument("--output", type=Path)
        else:
            parser.add_argument("--output-dir", type=Path, required=True)
            parser.add_argument("--ledger", type=Path, required=True)
            parser.add_argument("--preview-sha256", required=True)
            parser.add_argument("--allow-speech-host", required=True)
            parser.add_argument("--send-script", action="store_true")
    for name in ("speech-status", "speech-cancel"):
        parser = commands.add_parser(name, help="Read or cancel local speech generation attempts")
        parser.add_argument("--ledger", type=Path, required=True)
        parser.add_argument("--plan-digest", required=True)
        parser.add_argument("--output", type=Path)


def run_command(args):
    if args.command in ("speech-status", "speech-cancel"):
        with exclusive_ai_output(args.output, args.ledger) as stream:
            journal = DispatchJournal(args.ledger, create=args.command == "speech-cancel")
            if args.command == "speech-cancel":
                journal.cancel(args.plan_digest)
            text = write_document(journal.status(args.plan_digest))
            if stream is not None:
                stream.write(text)
                print(f"Report saved: {args.output}")
            else:
                print(text, end="")
        return 0
    if args.command == "speech-generate" and not args.send_script:
        raise ValidationError("Review speech-preview first, then explicitly --send-script")
    plan = plan_from_document(read_document(args.plan))
    approval = approval_from_document(read_document(args.approval))
    config = SpeechConfig.from_document(read_document(args.speech_config))
    value = preview(plan, approval, config)
    if args.command == "speech-preview":
        text = write_document(value, args.output)
        print(f"Preview saved: {args.output}" if args.output else text,
              end="\n" if args.output else "")
        return 0
    if (value["preview_sha256"] != args.preview_sha256
            or args.allow_speech_host != config.host):
        raise ValidationError("Speech preview or provider host does not match")
    destination = args.output_dir.resolve()
    if (args.output_dir.exists() or args.output_dir.is_symlink()
            or args.ledger.resolve().is_relative_to(destination)):
        raise ValidationError("Use a new output directory and a journal outside that directory")
    journal = DispatchJournal(args.ledger, create=True)
    result = generate(
        plan, approval, config, journal, args.preview_sha256, allowed_host=config.host,
        output_dir=args.output_dir,
        client=PublicHTTPS([config.host], max_bytes=MAX_AUDIO, max_requests=1, timeout=60),
    )
    print(write_document(result), end="")
    return 0 if result["status"] == "accepted" else 3


def speech_menu(run, ask):
    print("""
Fictional stock-voice asset preparation
1. Prepare an exact local preview and configured price estimate
2. Generate audio through the configured provider
3. Read generation status
4. Cancel future generation for an exact plan
0. Return
""")
    choice = ask("Choose 0–4: ")
    if choice == "0":
        return 0
    if choice in ("1", "2"):
        command = ["speech-preview" if choice == "1" else "speech-generate",
                   ask("Approved voice plan JSON: "), "--approval", ask("Approval JSON: "),
                   "--speech-config", ask("Speech configuration JSON (no secrets): ")]
        if choice == "1":
            return run([*command, "--output", ask("New speech preview JSON: ")])
        digest, host = ask("Reviewed preview_sha256: "), ask("Reviewed speech provider host: ")
        journal, output = ask("Generation journal SQLite path: "), ask("New audio directory: ")
        print("This sends the approved script to the speech provider and may incur a charge. "
              "It creates local audio only; it does not place calls or send audio.")
        if ask("Generate this exact stock-voice asset? [y/N]: ", required=False).lower() != "y":
            return 0
        return run([*command, "--preview-sha256", digest, "--allow-speech-host", host,
                    "--ledger", journal, "--output-dir", output, "--send-script"])
    if choice in ("3", "4"):
        journal, digest = ask("Generation journal SQLite path: "), ask("Exact plan digest: ")
        if choice == "4" and ask(
            "Block later generation for this plan? [y/N]: ", required=False
        ).lower() != "y":
            return 0
        return run(["speech-status" if choice == "3" else "speech-cancel",
                    "--ledger", journal, "--plan-digest", digest])
    raise ValidationError("Choose a speech operation from 0 to 4")
