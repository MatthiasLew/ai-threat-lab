"""Bounded regular-package/source-root metadata from labels; no filesystem or imports."""

import re
from dataclasses import dataclass

MAX_PACKAGE_DEPTH = 8
IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"


@dataclass(frozen=True)
class ModuleSpec:
    path: str
    name: str
    package: bool


def module_index(labels):
    labels = set(labels)
    candidates, local_names, notices = {}, set(), set()
    for path in sorted(labels):
        parts = path.split("/")
        if (
            len(path) > 1024
            or any(not part or len(part) > 255 for part in parts)
            or not parts[-1].endswith(".py")
            or not re.fullmatch(IDENTIFIER, parts[-1][:-3])
            or any(not re.fullmatch(IDENTIFIER, part) for part in parts[:-1])
        ):
            notices.add("Project flow: unsupported module paths/layouts remain unchecked.")
            continue
        prefix = ""
        if len(parts) > 1 and parts[0] == "src" and "src/__init__.py" not in labels:
            parts = parts[1:]
            prefix = "src/"
        directories = parts[:-1]
        package = parts[-1] == "__init__.py"
        qualified = directories if package else [*directories, parts[-1][:-3]]
        if not qualified:
            notices.add("Project flow: unsupported module paths/layouts remain unchecked.")
            continue
        for size in range(1, len(qualified) + 1):
            local_names.add(".".join(qualified[:size]))
        if len(directories) > MAX_PACKAGE_DEPTH:
            notices.add("Project flow: package-depth limit reached; deeper modules unchecked.")
            continue
        if any(
            prefix + "/".join(directories[:size]) + "/__init__.py" not in labels
            for size in range(1, len(directories) + 1)
        ):
            notices.add("Project flow: namespace/missing-marker layout unchecked.")
            continue
        name = ".".join(qualified)
        candidates.setdefault(name, []).append(ModuleSpec(path, name, package))
    specs = {}
    for name, entries in candidates.items():
        if len(entries) == 1:
            specs[name] = entries[0]
        else:
            notices.add("Project flow: ambiguous module/root/package mapping; binding unchecked.")
    return specs, local_names, tuple(sorted(notices))
