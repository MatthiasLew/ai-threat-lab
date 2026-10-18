"""Thin console adapter around the reusable analysis service."""

import argparse
import json
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path

from .analyzer import ThreatAnalyzer
from .campaign_cli import demo_campaign, report_events
from .campaigns import campaign_scenarios
from .code_review import render_code_review, review_file
from .contracts import approval_to_document, config_from_document, read_document, write_document
from .integration_cli import COMMANDS, add_commands, run_command
from .models import AnalysisRequest, TargetProfile, ValidationError
from .providers import ProviderConfig, ProviderError, ProviderRegistry
from .reports import export_report, render_json, render_text
from .workflows import approve_campaign, example_request, prepare_campaign, simulate_campaign


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AI Threat Lab — read-only audits, budgeted AI and training workflows"
    )
    parser.add_argument("--version", action="version", version="AI Threat Lab 0.5.0")
    parser.add_argument("--config", type=Path, help="Provider selection JSON; no credentials")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("scenarios", help="List available scenarios")
    commands.add_parser("controls", help="List defense IDs and descriptions")
    commands.add_parser("interactive", help="Guided analysis with console prompts")
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
    review.add_argument("--format", choices=("txt", "json"), default="txt")
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
    commands.add_parser(
        "doctor", help="Check selected adapter registrations without network access"
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
        if args.command in COMMANDS:
            return run_command(args)
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
            result = review_file(args.path)
            content = render_code_review(result, args.format)
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
    except (ValidationError, OSError, EOFError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
