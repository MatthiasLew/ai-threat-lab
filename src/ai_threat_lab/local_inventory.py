"""Bounded static source/configuration inventory. Never executes target code."""

import hashlib
import json
import re
from pathlib import Path

from .assessment import AssessmentFinding, AssessmentResult, AssessmentService, identify_target
from .models import ValidationError

EXCLUDED = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
TEXT_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".json", ".toml", ".yaml", ".yml", ".env"}
SECRET_PATTERNS = (
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
    r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b",
)


def inspect_text(name: str, source: str) -> tuple[AssessmentFinding, ...]:
    findings = []
    for index, line in enumerate(source.splitlines(), 1):
        if any(re.search(pattern, line) for pattern in SECRET_PATTERNS):
            findings.append(
                AssessmentFinding(
                    "possible_secret",
                    "candidate",
                    f"{name}:{index}: credential pattern (value redacted)",
                    "Verify without sharing the value; rotate exposed credentials "
                    "and remove from history.",
                )
            )
    if Path(name).name == "package.json":
        try:
            manifest = json.loads(source)
            for section in ("dependencies", "devDependencies"):
                for package, version in manifest.get(section, {}).items():
                    if version in ("*", "latest"):
                        findings.append(
                            AssessmentFinding(
                                "floating_dependency",
                                "candidate",
                                f"{name}: {package} uses {version}",
                                "Review and lock dependency versions; audit the resolved lockfile.",
                            )
                        )
        except (ValueError, AttributeError, TypeError):
            findings.append(
                AssessmentFinding(
                    "invalid_manifest",
                    "candidate",
                    f"{name}: invalid package manifest",
                    "Validate the package manifest before dependency analysis.",
                )
            )
    return tuple(findings)


def local_inventory(target: str) -> AssessmentResult:
    kind = identify_target(target)
    path = Path(target)
    if path.is_symlink():
        raise ValidationError("Root symlinks are not accepted for inventory")
    if kind == "program_file":
        with path.open("rb") as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValidationError("Program metadata inventory is limited to 16 MiB")
        form = "PE" if raw.startswith(b"MZ") else "ELF" if raw.startswith(b"\x7fELF") else "unknown"
        finding = AssessmentFinding(
            "binary_metadata",
            "unverified",
            f"Format={form}; bytes={len(raw)}; sha256={hashlib.sha256(raw).hexdigest()}",
            "Use platform signature verification and a specialized binary analyzer.",
        )
        return AssessmentResult(
            target,
            kind,
            "partial",
            (finding,),
            ("No disassembly, malware detection, signature verification or execution.",),
        )
    if kind not in ("local_project", "python_source"):
        return AssessmentService().assess(target)
    baseline = AssessmentService().assess(target)
    findings, missing = list(baseline.findings), list(baseline.not_checked)
    candidates = [path]
    if path.is_dir():
        import os

        candidates = []
        stopped = False
        visited = 0
        for directory, dirs, files in os.walk(path, followlinks=False):
            dirs[:] = sorted(
                d for d in dirs if d not in EXCLUDED and not (Path(directory) / d).is_symlink()
            )
            visited += 1
            for name in sorted(files):
                item = Path(directory) / name
                if not item.is_symlink() and (item.suffix in TEXT_SUFFIXES or name == ".env"):
                    candidates.append(item)
                if len(candidates) >= 100 or visited >= 1000:
                    stopped = True
                    break
            if stopped or visited >= 1000:
                missing.append("Inventory traversal stopped at the file/directory limit.")
                break
    for item in candidates:
        try:
            with item.open("rb") as stream:
                data = stream.read(256 * 1024 + 1)
            if len(data) > 256 * 1024:
                missing.append(f"Skipped oversized file: {item.name}")
                continue
            findings.extend(
                inspect_text(
                    str(item.relative_to(path) if path.is_dir() else item.name),
                    data.decode("utf-8"),
                )
            )
        except (OSError, UnicodeError):
            missing.append(f"Could not read text file: {item.name}")
    missing.append("Secret patterns are incomplete; no dependency advisory database was queried.")
    return AssessmentResult(target, kind, "partial", tuple(findings), tuple(missing))
