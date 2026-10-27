"""Noninteractive agent CLI; stdout contains one compact versioned JSON result."""

import argparse
import json
from pathlib import Path

from .agent_protocol import execute, exit_code, input_schema
from .agent_service import OPERATIONS, error_result


class AgentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("Invalid agent arguments")


def build_parser():
    parser = AgentParser(prog="ai-threat-lab agent", allow_abbrev=False)
    commands = parser.add_subparsers(dest="operation", required=True)
    for operation in OPERATIONS:
        cmd = commands.add_parser(operation, allow_abbrev=False)
        cmd.add_argument(
            "--root", type=Path, default=Path.cwd(), help="Approved local project root"
        )
        cmd.add_argument("--format", choices=("json",), default="json")
        schema = input_schema(operation)
        for key, rule in schema["properties"].items():
            cmd.add_argument(
                "--" + key.replace("_", "-"),
                dest=key,
                required=key in schema["required"],
                type=int if rule["type"] == "integer" else str,
                default=argparse.SUPPRESS,
            )
    mcp = commands.add_parser("mcp", allow_abbrev=False)
    serve = mcp.add_subparsers(dest="mcp_command", required=True).add_parser("serve")
    serve.add_argument("--root", type=Path, required=True)
    return parser


def main(argv):
    try:
        args = vars(build_parser().parse_args(argv))
    except ValueError:
        result = error_result("unknown", "invalid_request", "Invalid agent arguments; use --help")
    else:
        operation, root = args.pop("operation"), args.pop("root")
        if operation == "mcp":
            from .agent_mcp import serve

            return serve(root)
        args.pop("format")
        result = execute(root, operation, args)
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return exit_code(result)
