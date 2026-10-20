"""Thin console adapter around the reusable analysis service."""

import argparse
import errno
import json
import os
import sqlite3
import stat
import sys
from dataclasses import asdict
from pathlib import Path

from ._version import __version__
from .analyzer import ThreatAnalyzer
from .campaign_cli import demo_campaign, report_events
from .campaigns import campaign_scenarios
from .code_review import render_code_review, review_file
from .console import run_console
from .contracts import approval_to_document, config_from_document, read_document, write_document
from .delivery_cli import COMMANDS as DELIVERY_COMMANDS
from .delivery_cli import add_commands as add_delivery_commands
from .delivery_cli import run_command as run_delivery_command
from .installation import installation_report
from .integration_cli import COMMANDS, add_commands, run_command
from .models import AnalysisRequest, TargetProfile, ValidationError
from .offline_cli import COMMANDS as OFFLINE_COMMANDS
from .offline_cli import add_commands as add_offline_commands
from .offline_cli import run_command as run_offline_command
from .providers import ProviderConfig, ProviderError, ProviderRegistry
from .reports import export_report, render_json, render_text
from .reputation_cli import COMMANDS as REPUTATION_COMMANDS
from .reputation_cli import add_commands as add_reputation_commands
from .reputation_cli import run_command as run_reputation_command
from .scan_cli import COMMANDS as SCAN_COMMANDS
from .scan_cli import add_commands as add_scan_commands
from .scan_cli import run_command as run_scan_command
from .speech_cli import COMMANDS as SPEECH_COMMANDS
from .speech_cli import add_commands as add_speech_commands
from .speech_cli import run_command as run_speech_command
from .training_cli import COMMANDS as TRAINING_COMMANDS
from .training_cli import add_commands as add_training_commands
from .training_cli import run_command as run_training_command
from .training_events_cli import COMMANDS as EVENT_COMMANDS
from .training_events_cli import add_commands as add_event_commands
from .training_events_cli import run_command as run_event_command
from .workbench_cli import COMMANDS as WORKBENCH_COMMANDS
from .workbench_cli import add_commands as add_workbench_commands
from .workbench_cli import run_command as run_workbench_command
from .workflows import approve_campaign, example_request, prepare_campaign, simulate_campaign


class ExactArgumentParser(argparse.ArgumentParser):
    """Require complete option names, including in every child parser."""

    def __init__(self, *args, **kwargs):
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)

    def _print_message(self, message, file=None):
        # argparse suppresses OSError, including immediate large-help pipe failures.
        # Let the process boundary handle a broken pipe consistently with final flush.
        if message:
            try:
                (file or sys.stderr).write(message)
            except BrokenPipeError:
                raise
            except (AttributeError, OSError):
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = ExactArgumentParser(
        description="AI Threat Lab — read-only audits, budgeted AI and training workflows"
    )
    parser.add_argument("--version", action="version", version=f"AI Threat Lab {__version__}")
    parser.add_argument("--config", type=Path, help="Provider selection JSON; no credentials")
    commands = parser.add_subparsers(dest="command", required=True)
    add_delivery_commands(commands)
    add_speech_commands(commands)
    add_reputation_commands(commands)
    commands.add_parser("scenarios", help="List available scenarios")
    commands.add_parser("controls", help="List defense IDs and descriptions")
    commands.add_parser("interactive", help="Guided analysis with console prompts")
    commands.add_parser(
        "console", help="Guided target, saved report, AI preview and setup workflow"
    )
    analyze = commands.add_parser("analyze", help="Analyze a fictional scenario")
    analyze.add_argument("scenario", help="Scenario ID; see scenarios command")
    analyze.add_argument("--organization", default="Example Company")
    analyze.add_argument("--role", help="Defaults to the selected scenario's fictional target role")
    analyze.add_argument("--access", choices=("low", "medium", "high"), default="medium")
    analyze.add_argument("--urgency", choices=("low", "normal", "high"), default="normal")
    analyze.add_argument("--existing", action="append", default=[], metavar="CONTROL_ID")
    analyze.add_argument("--proposed", action="append", default=[], metavar="CONTROL_ID")
    analyze.add_argument("--format", choices=("txt", "json"), default="txt")
    analyze.add_argument(
        "--output", type=Path, help="New file path; existing files are not overwritten"
    )
    review = commands.add_parser("review-code", help="Review a local Python file without execution")
    review.add_argument("path", type=Path)
    review.add_argument("--format", choices=("txt", "json", "sarif"), default="txt")
    review.add_argument(
        "--source-root",
        type=Path,
        help="SARIF only: export a path relative to this directory instead of a basename",
    )
    review.add_argument("--output", type=Path, help="New report path; no overwriting")
    review.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Return exit code 1 when candidate findings exist",
    )
    commands.add_parser("campaigns", help="List prepared training scenarios")
    demo = commands.add_parser("campaign-demo", help="Offline campaign preview/simulated dispatch")
    demo.add_argument("scenario")
    events = commands.add_parser("campaign-report", help="Aggregate exported exercise events")
    events.add_argument("path", type=Path)
    assess = commands.add_parser("assess", help="Route a target to available assessment modules")
    assess.add_argument("target")
    commands.add_parser("providers", help="List registered adapters and configuration")
    doctor = commands.add_parser(
        "doctor", help="Check adapter registrations or installation without network access"
    )
    doctor.add_argument(
        "--installation", action="store_true",
        help="Check Python, distribution identity and bundled catalog; no credential access",
    )
    example = commands.add_parser("campaign-example", help="Create a fictional exercise request")
    example.add_argument("scenario")
    prepare = commands.add_parser(
        "campaign-prepare", help="Prepare an exact preview from a request"
    )
    prepare.add_argument("request", type=Path)
    approve = commands.add_parser("campaign-approve", help="Record reviewer approval of a preview")
    approve.add_argument("plan", type=Path)
    approve.add_argument("--reviewer", required=True)
    simulate = commands.add_parser("campaign-simulate", help="Simulate an approved saved plan")
    simulate.add_argument("plan", type=Path)
    simulate.add_argument("--approval", type=Path, required=True)
    simulate.add_argument(
        "--ledger", type=Path, help="Optional persistent simulated-attempt ledger"
    )
    for command in (example, prepare, approve, simulate, demo, events, assess):
        command.add_argument("--output", type=Path, help="New JSON file path; never overwrite")
    add_commands(commands)
    add_training_commands(commands)
    add_event_commands(commands)
    add_scan_commands(commands)
    add_offline_commands(commands)
    add_workbench_commands(commands)
    return parser


def _interactive(analyzer: ThreatAnalyzer) -> AnalysisRequest:
    for scenario in analyzer.list_scenarios():
        print(f"{scenario.id}: {scenario.title}")
    scenario_id = input("Scenario ID: ").strip()
    scenario = next((s for s in analyzer.list_scenarios() if s.id == scenario_id), None)
    if scenario is None:
        raise ValidationError(f"Unknown scenario: {scenario_id}")
    organization = input("Fictional organization [Example Company]: ").strip() or "Example Company"
    role = input(f"Role [{scenario.default_role}]: ").strip() or scenario.default_role
    access = input("Access low/medium/high [medium]: ").strip() or "medium"
    urgency = input("Urgency low/normal/high [normal]: ").strip() or "normal"
    print("Available defenses:")
    for control in analyzer.list_controls():
        print(f"  {control.id}: {control.title}")
    existing = tuple(input("Existing defense IDs (space-separated, or empty): ").split())
    proposed = tuple(input("Proposed defense IDs (space-separated, or empty): ").split())
    return AnalysisRequest(
        scenario_id, TargetProfile(organization, role, access, urgency), existing, proposed
    )


def main(argv: list[str] | None = None, *, registry: ProviderRegistry | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        registry = registry or ProviderRegistry()
        config = (
            config_from_document(read_document(args.config)) if args.config else ProviderConfig()
        )
        if getattr(args, "output", None) is not None and args.output.exists():
            raise FileExistsError("Output path already exists; choose a new file")
        if args.command in OFFLINE_COMMANDS:
            return run_offline_command(args)
        if args.command in DELIVERY_COMMANDS:
            return run_delivery_command(args)
        if args.command in SPEECH_COMMANDS:
            return run_speech_command(args)
        if args.command in REPUTATION_COMMANDS:
            return run_reputation_command(args)
        if args.command == "console":
            prefix = ["--config", str(args.config)] if args.config else []
            return run_console(lambda argv: main([*prefix, *argv], registry=registry))
        if args.command in WORKBENCH_COMMANDS:
            return run_workbench_command(args)
        if args.command in SCAN_COMMANDS:
            return run_scan_command(args)
        if args.command in EVENT_COMMANDS:
            return run_event_command(args)
        if args.command in TRAINING_COMMANDS:
            return run_training_command(args)
        if args.command in COMMANDS:
            return run_command(args)
        if args.command == "doctor" and args.installation:
            payload = installation_report()
            print(write_document(payload), end="")
            return 0 if payload["status"] == "ready" else 3
        if args.command in ("providers", "doctor"):
            payload = (
                registry.describe(config)
                if args.command == "providers"
                else registry.diagnose(config)
            )
            print(write_document(payload), end="")
            return 3 if args.command == "doctor" and payload["missing"] else 0
        if args.command.startswith("campaign-") and args.command not in (
            "campaign-demo",
            "campaign-report",
        ):
            if args.command == "campaign-example":
                payload = example_request(args.scenario)
            elif args.command == "campaign-prepare":
                payload = prepare_campaign(read_document(args.request), registry, config)
            elif args.command == "campaign-approve":
                payload = approval_to_document(
                    approve_campaign(read_document(args.plan), args.reviewer)
                )
            else:
                payload = simulate_campaign(
                    read_document(args.plan), read_document(args.approval), args.ledger
                )
            text = write_document(payload, args.output)
            print(
                f"Report saved: {args.output}" if args.output else text,
                end="\n" if args.output else "",
            )
            return 0
        if args.command == "campaigns":
            print(json.dumps([asdict(s) for s in campaign_scenarios()], indent=2))
            return 0
        if args.command in ("campaign-demo", "campaign-report", "assess"):
            if args.command == "campaign-demo":
                payload = demo_campaign(args.scenario)
            elif args.command == "campaign-report":
                payload = report_events(args.path)
            else:
                payload = asdict(registry.assessment_service(config).assess(args.target))
            text = write_document(payload, args.output)
            print(
                f"Report saved: {args.output}" if args.output else text,
                end="\n" if args.output else "",
            )
            return 0
        if args.command == "review-code":
            if args.source_root is not None and args.format != "sarif":
                raise ValidationError("Source root is only supported for SARIF export")
            result = review_file(args.path)
            content = render_code_review(result, args.format, source_root=args.source_root)
            if args.output:
                with args.output.open("x", encoding="utf-8") as output:
                    output.write(content)
                print(f"Report saved: {args.output}")
            else:
                print(content, end="")
            return 1 if args.fail_on_findings and result.findings else 0
        analyzer = ThreatAnalyzer()
        if args.command == "scenarios":
            for scenario in analyzer.list_scenarios():
                print(f"{scenario.id}: {scenario.title}\n  {scenario.description}")
            return 0
        if args.command == "controls":
            for control in analyzer.list_controls():
                print(f"{control.id}: {control.title}\n  {control.description}")
            return 0
        if args.command == "interactive":
            print(render_text(analyzer.analyze(_interactive(analyzer))), end="")
            return 0
        scenario = next((s for s in analyzer.list_scenarios() if s.id == args.scenario), None)
        if scenario is None:
            raise ValidationError(f"Unknown scenario: {args.scenario}")
        request = AnalysisRequest(
            args.scenario,
            TargetProfile(
                args.organization, args.role or scenario.default_role, args.access, args.urgency
            ),
            args.existing,
            args.proposed,
        )
        result = analyzer.analyze(request)
        if args.output:
            export_report(result, args.output, args.format)
            print(f"Report saved: {args.output}")
        else:
            print(render_json(result) if args.format == "json" else render_text(result), end="")
        return 0
    except sqlite3.Error:
        print("Storage error; inspect any pending API outcome before retrying.", file=sys.stderr)
        return 3
    except ProviderError as exc:
        print(f"Integration error: {exc}", file=sys.stderr)
        return 3
    except BrokenPipeError:
        raise
    except UnicodeError:
        print("Error: text cannot be processed as UTF-8.", file=sys.stderr)
        return 2
    except (ValidationError, OSError, EOFError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130


class _WindowsPipeOutput:
    """Normalize Windows CRT EINVAL only when writing/flushing an actual pipe."""

    def __init__(self, stream):
        self.stream = stream

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def _call(self, method, *args):
        try:
            return getattr(self.stream, method)(*args)
        except OSError as exc:
            if exc.errno == errno.EINVAL:
                try:
                    pipe = stat.S_ISFIFO(os.fstat(self.stream.fileno()).st_mode)
                except (AttributeError, OSError, ValueError):
                    pipe = False
                if pipe:
                    raise BrokenPipeError(errno.EPIPE, "Output pipe closed") from None
            raise

    def write(self, text):
        return self._call("write", text)

    def flush(self):
        return self._call("flush")


def entrypoint() -> int:
    """Process boundary: UTF-8 streams and quiet, deterministic closed-pipe exit."""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="strict")
    if os.name == "nt":
        sys.stdout = _WindowsPipeOutput(sys.stdout)
        sys.stderr = _WindowsPipeOutput(sys.stderr)
    try:
        try:
            result = main()
        except SystemExit:
            # Help/version/parse errors also need a flush before interpreter shutdown.
            sys.stdout.flush()
            sys.stderr.flush()
            raise
        sys.stdout.flush()
        sys.stderr.flush()
        return result
    except BrokenPipeError:
        # Close the original buffered streams, including cached Windows handles.
        # Rebinding alone leaves their destructors able to retry the failed flush.
        streams = (sys.stdout, sys.stderr)
        sys.stdout = sys.stderr = open(os.devnull, "w", encoding="utf-8")
        for stream in streams:
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        return 141
