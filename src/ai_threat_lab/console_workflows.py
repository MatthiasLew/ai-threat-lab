"""Guided local training and saved-result operations, without separate domain logic."""

from pathlib import Path

from .contracts import plan_from_document, read_document
from .models import ValidationError
from .training_cli import terminal_text


def training_menu(run, ask):
    print("""
Local training — fictional text only, no delivery, calls or generated media
1. Create an example request
2. Prepare a request as an exact preview
3. Review the exact preview and record approval
4. Start an approved local rehearsal
5. Continue a saved rehearsal
6. Export local selected-outcome report
7. Permanently cancel a local plan
8. Export approved inert email/script/storyboard assets
0. Return
""")
    choice = ask("Choose 0–8: ")
    if choice == "0":
        return 0
    if choice == "1":
        scenario = ask("Scenario (email_training/voice_training/video_training): ")
        return run(["campaign-example", scenario, "--output", ask("New request JSON file: ")])
    if choice == "2":
        return run(
            [
                "campaign-prepare",
                ask("Request JSON file: "),
                "--output",
                ask("New preview JSON file: "),
            ]
        )
    if choice == "3":
        path = ask("Preview JSON file: ")
        plan = plan_from_document(read_document(Path(path)))
        preview = (
            f"Channel: {plan.channel}\nScope: {plan.scope.campaign_id}\n"
            f"Expires: {plan.scope.expires_at.isoformat()}\n"
            f"Recipients: {', '.join(plan.recipients)}\n"
            f"Subject: {plan.content.subject}\n\n{plan.content.body}\n"
            f"Media reference: {plan.content.media_reference or '(none)'}\n"
            f"Media hash: {plan.content.media_sha256 or '(none)'}\n"
            f"Approved facts: {', '.join(plan.approved_facts) or '(none)'}\n"
            f"Plan digest: {plan.digest}"
        )
        print(terminal_text(preview))
        approval = ask("Approve this exact local preview and scope? [y/N]: ", required=False)
        if approval.lower() != "y":
            print("No approval was recorded.")
            return 0
        return run(
            [
                "campaign-approve",
                path,
                "--reviewer",
                ask("Reviewer identifier: "),
                "--output",
                ask("New approval JSON file: "),
            ]
        )
    if choice == "4":
        return run(
            [
                "training-start",
                ask("Preview JSON file: "),
                "--approval",
                ask("Approval JSON file: "),
                "--participant-id",
                ask("Opaque participant alias (no personal data): "),
                "--ledger",
                ask("Training SQLite file: "),
                "--output",
                ask("New session JSON file: "),
            ]
        )
    if choice == "5":
        return run(
            [
                "training-run",
                ask("Session ID from the saved session: "),
                "--ledger",
                ask("Training SQLite file: "),
            ]
        )
    if choice == "6":
        return run(
            [
                "training-report",
                "--ledger",
                ask("Training SQLite file: "),
                "--format",
                "html",
                "--output",
                ask("New HTML report: "),
            ]
        )
    if choice == "7":
        digest, ledger = ask("Exact plan digest to cancel: "), ask("Training SQLite file: ")
        if ask("Permanently cancel this local plan? [y/N]: ", required=False).lower() != "y":
            print("Cancellation was not applied.")
            return 0
        return run(["training-cancel", "--plan-digest", digest, "--ledger", ledger])
    if choice == "8":
        return run(
            [
                "exercise-export",
                ask("Preview JSON file: "),
                "--approval",
                ask("Approval JSON file: "),
                "--output-dir",
                ask("New inert asset directory: "),
            ]
        )
    raise ValidationError("Choose a training operation from 0 to 8")


def history_menu(run, ask):
    print("""
Saved results and batches — local operations only
1. List and verify saved history
2. Compare two saved single-target scans
3. Export a saved single/batch report as HTML
4. Scan a batch of local targets
5. Verify a saved batch
6. Verify a saved single-target scan
0. Return
""")
    choice = ask("Choose 0–6: ")
    if choice == "0":
        return 0
    if choice == "1":
        return run(["history-list", ask("History root directory: ")])
    if choice == "2":
        return run(
            ["scan-compare", ask("Previous scan directory: "), ask("Current scan directory: ")]
        )
    if choice == "3":
        return run(
            [
                "report-export",
                ask("Saved single/batch directory: "),
                "--format",
                "html",
                "--output",
                ask("New HTML report: "),
            ]
        )
    if choice == "4":
        targets = []
        for index in range(1, 11):
            target = ask(f"Local target {index}/10 (Enter finishes the list): ", required=False)
            if not target:
                break
            targets.append(target)
        if not targets:
            raise ValidationError("Choose at least one local target")
        output = ask("New batch directory: ")
        if ask("Scan these local targets? [y/N]: ", required=False).lower() != "y":
            print("Batch cancelled.")
            return 0
        return run(["scan-batch", *targets, "--output-dir", output])
    if choice in ("5", "6"):
        return run(["batch-check" if choice == "5" else "scan-check", ask("Saved run directory: ")])
    raise ValidationError("Choose a history operation from 0 to 6")
