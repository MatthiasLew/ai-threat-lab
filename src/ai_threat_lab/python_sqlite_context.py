"""Recognize selected default-factory connection calls, without opening SQLite."""

import ast

# Positional options and custom factories remain outside context-manager selection.
OPTIONS = {
    "database",
    "timeout",
    "detect_types",
    "isolation_level",
    "check_same_thread",
    "cached_statements",
    "uri",
    "autocommit",
}
MAX_CONTEXT_ITEMS = 8


def connection_context_call(call):
    """Syntactic subset only: argument types and connection success are unverified."""
    names = [keyword.arg for keyword in call.keywords]
    return (
        len(call.args) <= 1
        and not any(isinstance(arg, ast.Starred) for arg in call.args)
        and all(name in OPTIONS for name in names)
        and len(set(names)) == len(names)
        and bool(call.args or "database" in names)
        and not (call.args and "database" in names)
    )
