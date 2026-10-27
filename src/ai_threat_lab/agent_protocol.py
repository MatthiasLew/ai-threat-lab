"""Shared strict input schemas, process limits and safe errors for CLI and MCP."""

import json
import subprocess
import sys

from .agent_service import MAX_RESPONSE, OPERATIONS, AgentError, AgentService, error_result
from .models import ValidationError
from .scan_bundle import document

MAX_REQUEST = 8192
TIMEOUT = 60
PATH = {"type": "string", "minLength": 1, "maxLength": 1024}
PAGE = {
    "limit": {"type": "integer", "minimum": 1, "maximum": 20},
    "offset": {"type": "integer", "minimum": 0, "maximum": 40000},
}


def input_schema(operation):
    properties, required = {}, []
    if operation in ("plan", "scan"):
        properties = {
            "target": PATH,
            "max_files": {"type": "integer", "minimum": 1, "maximum": 1000},
        }
    elif operation == "compare":
        properties, required = {"base": PATH, "head": PATH}, ["base", "head"]
    elif operation not in ("capabilities", "doctor"):
        properties, required = {"run": PATH}, ["run"]
        if operation == "finding":
            properties["id"] = {
                "type": "string",
                "pattern": "^[a-f0-9]{64}$",
                "minLength": 64,
                "maxLength": 64,
            }
            required.append("id")
        if operation in ("findings", "limitations"):
            properties.update(PAGE)
        if operation == "findings":
            properties.update(
                {
                    "priority": {"type": "string", "enum": ["P1", "P2", "P3"]},
                    "rule": {"type": "string", "minLength": 1, "maxLength": 100},
                    "status": {"type": "string", "enum": ["candidate", "unverified"]},
                }
            )
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def validate_args(operation, args):
    import re

    if operation not in OPERATIONS or not isinstance(args, dict):
        raise ValidationError("Invalid operation")
    schema = input_schema(operation)
    if set(args) - schema["properties"].keys() or set(schema["required"]) - args.keys():
        raise ValidationError("Invalid arguments")
    for key, value in args.items():
        rule = schema["properties"][key]
        if rule["type"] == "integer":
            if type(value) is not int or not rule["minimum"] <= value <= rule["maximum"]:
                raise ValidationError("Invalid integer")
        elif (
            not isinstance(value, str)
            or not rule.get("minLength", 0) <= len(value) <= rule.get("maxLength", 1024)
            or any(ord(c) < 32 for c in value)
        ):
            raise ValidationError("Invalid text")
        if "enum" in rule and value not in rule["enum"]:
            raise ValidationError("Invalid selection")
        if "pattern" in rule and not re.fullmatch(rule["pattern"], value):
            raise ValidationError("Invalid reference")


def perform(root, operation, args):
    try:
        validate_args(operation, args)
        return AgentService(root).call(operation, args)
    except AgentError as exc:
        return error_result(operation, exc.code, str(exc))
    except ValidationError:
        return error_result(operation, "invalid_request", "Arguments or approved scope are invalid")
    except OSError:
        return error_result(operation, "infrastructure_error", "Local filesystem operation failed")
    except Exception:
        return error_result(
            operation, "internal_error", "Operation failed; no sensitive details shown"
        )


def execute(root, operation, args):
    """Bound each operation in a trusted worker; never invoke project code or shell commands."""
    raw = json.dumps({"root": str(root), "operation": operation, "arguments": args}).encode()
    if len(raw) > MAX_REQUEST:
        return error_result(operation, "request_limit", "Request exceeds byte limit")
    try:
        completed = subprocess.run(
            [sys.executable, "-P", "-m", "ai_threat_lab.agent_worker"],
            input=raw,
            capture_output=True,
            timeout=TIMEOUT,
        )
        if completed.returncode or len(completed.stdout) > MAX_RESPONSE:
            return error_result(operation, "worker_error", "Worker failed or exceeded output limit")
        return document(completed.stdout)
    except subprocess.TimeoutExpired:
        return error_result(operation, "timeout", "Operation exceeded deadline; inspect saved runs")
    except (OSError, ValidationError):
        return error_result(operation, "infrastructure_error", "Worker could not complete")


def exit_code(result):
    if result["status"] != "error":
        return 0
    return (
        2
        if result["error"]["code"]
        in (
            "invalid_request",
            "request_limit",
            "finding_not_found",
            "invalid_bundle",
            "response_limit",
        )
        else 3
    )
