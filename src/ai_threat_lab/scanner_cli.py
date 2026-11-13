"""CLI for optional scanner planning."""

import json
import sys
from dataclasses import asdict
from pathlib import Path

from .scanner_plan import EXECUTION_BLOCKER, bandit_availability, plan_bandit
from .scanner_report import save_bandit_report
from .scanner_sandbox import sandbox_diagnostic


def add_scanner_commands(commands):
    parser = commands.add_parser("scanner", help="Inspect and plan optional local scanners")
    actions = parser.add_subparsers(dest="scanner_action", required=True)
    actions.add_parser("list", help="List supported scanner adapters")
    actions.add_parser("doctor", help="Check Bandit presence without starting it")
    plan = actions.add_parser("plan", help="Validate a local Bandit plan without executing it")
    plan.add_argument("scanner", choices=["bandit"])
    plan.add_argument("target", type=Path)
    plan.add_argument("--executable", type=Path, required=True)
    plan.add_argument("--sha256", required=True, help="Expected SHA-256 from trusted provenance")
    plan.add_argument("--version", required=True, help="Declared version from trusted provenance")
    run = actions.add_parser("run", help="Report the current execution restriction")
    run.add_argument("scanner", choices=["bandit"])
    run.add_argument("target", type=Path)
    report = actions.add_parser("import", help="Publish an existing Bandit report")
    report.add_argument("scanner", choices=["bandit"])
    report.add_argument("source", type=Path)
    report.add_argument("--output", type=Path, required=True)


def run_scanner_command(args):
    action = args.scanner_action
    if action == "run":
        print(EXECUTION_BLOCKER, file=sys.stderr)
        print(json.dumps({"scanner": args.scanner, "execution": "blocked"}))
        return 2
    if action == "import":
        report = save_bandit_report(args.source, args.output)
        result = {"scanner": args.scanner, "reported_results": report["total_results"]}
    elif action == "plan":
        result = plan_bandit(
            args.target, executable=args.executable,
            expected_sha256=args.sha256, declared_version=args.version,
        )
    else:
        result = bandit_availability()
        if action == "list":
            result = {"scanners": [result]}
        else:
            diagnostic = asdict(sandbox_diagnostic())
            diagnostic["prerequisites"] = dict(diagnostic["prerequisites"])
            result["sandbox"] = diagnostic
    print(json.dumps(result))
    return 0
