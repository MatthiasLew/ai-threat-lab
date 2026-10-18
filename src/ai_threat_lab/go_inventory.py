"""Conservative Go checksum-record parsing, without resolving or fetching modules."""

import base64
import re

from .models import ValidationError

MAX_LINES = 20000


def module_path(value):
    """Accept a documented ASCII subset of unescaped, domain-prefixed module paths."""
    if not isinstance(value, str) or not 1 <= len(value) <= 512:
        return False
    parts = value.split("/")
    if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)+", parts[0]):
        return False
    return all(
        part not in ("", ".", "..")
        and not part.startswith(".")
        and not part.endswith(".")
        and re.fullmatch(r"[A-Za-z0-9._~-]+", part)
        for part in parts[1:]
    )


def module_version(value):
    if not isinstance(value, str) or len(value) > 128:
        return False
    match = re.fullmatch(
        r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
        r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+incompatible)?",
        value,
    )
    return bool(match) and all(
        not (part.isdigit() and len(part) > 1 and part.startswith("0"))
        for part in (match[1] or "").split(".")
    )


def parse_go_sum(source, origin, add, note):
    """Keep module-content records; metadata-only records do not imply downloaded code."""
    note(
        f"{origin}: recorded Go module-content identities only; checksums not verified. "
        "Selected build list, replacements, exclusions, workspace, toolchain, "
        "pseudo-version provenance and runtime reachability remain unchecked. "
        "Historical/unused module versions may be included; go.mod-only records omitted."
    )

    lines = source.splitlines()
    if len(lines) > MAX_LINES:
        raise ValidationError("Go checksum manifest exceeds the 20000-line limit")
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 3:
            note(f"{origin}:{number}: skipped unsupported Go record (values omitted).")
            continue
        name, version, checksum = fields
        metadata = version.endswith("/go.mod")
        if metadata:
            version = version[:-7]
        valid_hash = False
        if re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", checksum):
            digest = base64.b64decode(checksum[3:], validate=True)
            valid_hash = (
                len(digest) == 32 and base64.b64encode(digest).decode("ascii") == checksum[3:]
            )
        if not module_path(name) or not module_version(version) or not valid_hash:
            note(f"{origin}:{number}: skipped unsupported Go identity/hash (values omitted).")
        elif metadata:
            note(f"{origin}:{number}: skipped go.mod-only checksum record.")
        else:
            add("Go", name, version, origin)
