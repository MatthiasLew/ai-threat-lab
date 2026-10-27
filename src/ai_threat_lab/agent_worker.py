"""Private bounded worker entry point for the agent transport adapters."""

import json
import sys

from .agent_protocol import MAX_REQUEST, perform
from .agent_service import error_result
from .scan_bundle import document


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            raise ValueError
        value = document(raw)
        result = perform(value["root"], value["operation"], value["arguments"])
    except (ValueError, KeyError, TypeError):
        result = error_result("unknown", "invalid_request", "Invalid worker request")
    sys.stdout.buffer.write(json.dumps(result, ensure_ascii=False).encode() + b"\n")


if __name__ == "__main__":
    main()
