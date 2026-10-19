"""Literal-only importlib call decoding, without importing the named target."""

import ast
import re

from .python_module_index import IDENTIFIER


def dotted_name(value):
    return (
        isinstance(value, str)
        and 0 < len(value) <= 1024
        and all(len(part) <= 255 and re.fullmatch(IDENTIFIER, part) for part in value.split("."))
    )


def literal_import_target(call):
    """Return an absolute label, or None for unsupported/invalid call arguments."""
    if len(call.args) > 2 or any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    arguments = dict(zip(("name", "package"), call.args, strict=False))
    for keyword in call.keywords:
        if keyword.arg not in ("name", "package") or keyword.arg in arguments:
            return None
        arguments[keyword.arg] = keyword.value
    name = arguments.get("name")
    package = arguments.get("package")
    if not isinstance(name, ast.Constant) or not isinstance(name.value, str):
        return None
    name = name.value
    if not name or len(name) > 1024:
        return None
    if package is not None:
        if not isinstance(package, ast.Constant):
            return None
        package = package.value
        if package is not None and not dotted_name(package):
            return None
    if not name.startswith("."):
        return name if dotted_name(name) else None
    if not dotted_name(package):
        return None
    remainder = name.lstrip(".")
    level = len(name) - len(remainder)
    parts = package.split(".")
    if level > len(parts) or (remainder and not dotted_name(remainder)):
        return None
    target = ".".join(parts[: len(parts) - level + 1])
    target += "." + remainder if remainder else ""
    return target if dotted_name(target) else None
