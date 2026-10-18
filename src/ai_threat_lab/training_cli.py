"""Local text-only training CLI; cannot select network, speech or media providers."""

import uuid
from pathlib import Path

from .contracts import approval_from_document, plan_from_document, read_document, write_document
from .training_lab import LabAction, TrainingLab, render_training_html

COMMANDS = {
    "training-start",
    "training-step",
    "training-status",
    "training-run",
    "training-report",
    "training-cancel",
}
LABELS = {
    "open_preview": "Read the local text preview",
    "follow_synthetic_link": "Select following the synthetic link (nothing is opened)",
    "acknowledge_synthetic_request": "Select acknowledging the synthetic video request",
    "request_verification": "Select independent verification (not proof of verification)",
    "report": "Select reporting through the approved process",
    "share_synthetic_identifier": "Select sharing only the invented TRAINING-ALPHA identifier",
    "decline": "Decline the exercise request",
    "stop": "Stop this exercise",
    "real_data_offered": "Stop: real information would be involved (do not enter it)",
    "unknown": "No classified response in this voice rehearsal turn",
}


def add_commands(commands):
    start = commands.add_parser(
        "training-start", help="Start a local text rehearsal from an approved plan"
    )
    start.add_argument("plan", type=Path)
    start.add_argument("--approval", type=Path, required=True)
    start.add_argument(
        "--participant-id", required=True, help="Opaque training alias; no name/address needed"
    )
    start.add_argument(
        "--recipient-index", type=int, default=0, help="Zero-based approved recipient index"
    )
    step = commands.add_parser(
        "training-step", help="Record one structured local exercise selection"
    )
    step.add_argument("session_id")
    step.add_argument("--action", choices=[str(a) for a in LabAction], required=True)
    step.add_argument("--action-id", help="Opaque idempotency token; generated if omitted")
    status = commands.add_parser("training-status", help="Read a session and apply scope expiry")
    status.add_argument("session_id")
    run = commands.add_parser(
        "training-run", help="Interactive numbered local rehearsal; no raw replies"
    )
    run.add_argument("session_id")
    report = commands.add_parser(
        "training-report", help="Aggregate local selected outcomes and follow-up guidance"
    )
    report.add_argument("--session-id", help="Optional single-session report")
    report.add_argument("--format", choices=("json", "html"), default="json")
    cancel = commands.add_parser("training-cancel", help="Permanently cancel a local approved plan")
    cancel.add_argument("--plan-digest", required=True)
    for command in (start, step, status, run, report, cancel):
        command.add_argument(
            "--ledger", required=True, type=Path, help="Local private training SQLite database"
        )
        if command is not run:
            command.add_argument("--output", type=Path, help="New JSON path; never overwrite")


def terminal_text(value):
    return "".join(
        char if char.isprintable() or char in "\n\t" else f"\\u{ord(char):04x}" for char in value
    )


def interactive(lab, session_id):
    state = lab.get(session_id)
    print("LOCAL TEXT REHEARSAL — enter only menu numbers, never real information.")
    if state["status"] == "running":
        print(terminal_text(state["preview"]["subject"]))
        print(terminal_text(state["preview"]["body"]))
    try:
        while state["status"] == "running":
            # Recheck expiry before each prompt and again during the transactional action.
            state = lab.get(session_id)
            if state["status"] != "running":
                break
            if state["channel"] == "voice" and state["turns"]:
                print(terminal_text(state["next_prompt"]))
            actions = state["allowed_actions"]
            for index, action in enumerate(actions, 1):
                print(f"{index}. {LABELS[action]}")
            choice = input("Selection number (empty ends the exercise): ").strip()
            if not choice:
                action = LabAction.STOP
            elif (
                choice.isascii()
                and choice.isdecimal()
                and len(choice) <= 3
                and 1 <= int(choice) <= len(actions)
            ):
                action = LabAction(actions[int(choice) - 1])
            else:
                print("Invalid selection. Use a displayed number; no response text is saved.")
                continue
            result = lab.record(session_id, action, uuid.uuid4().hex)
            state = result["session"]
    except (EOFError, KeyboardInterrupt):
        # Close local interaction; no external caller/session exists to disconnect.
        state = lab.record(session_id, LabAction.STOP, uuid.uuid4().hex)["session"]
        print("Local interaction stopped.")
    print(f"Status: {state['status']}; selected outcome: {state['outcome']}")
    print(state["guidance"])
    print(state["notice"])
    return 0


def run_command(args):
    lab = TrainingLab(args.ledger)
    if args.command == "training-start":
        payload = lab.start(
            plan_from_document(read_document(args.plan)),
            approval_from_document(read_document(args.approval)),
            args.participant_id,
            recipient_index=args.recipient_index,
        )
    elif args.command == "training-step":
        payload = lab.record(
            args.session_id, LabAction(args.action), args.action_id or uuid.uuid4().hex
        )
    elif args.command == "training-status":
        payload = lab.get(args.session_id)
    elif args.command == "training-run":
        return interactive(lab, args.session_id)
    elif args.command == "training-cancel":
        payload = lab.cancel(args.plan_digest)
    else:
        payload = lab.report(session_id=args.session_id)
        if args.format == "html":
            content = render_training_html(payload)
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
