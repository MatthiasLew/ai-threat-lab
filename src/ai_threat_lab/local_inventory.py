"""Bounded static source/configuration inventory. Never executes target code."""

import json
import re
from pathlib import Path

from .assessment import AssessmentFinding, AssessmentResult, AssessmentService, identify_target
from .binary_audit import audit_binary
from .config_review import NOTICE, configuration_file, inspect_configuration
from .html_review import inspect_html
from .kubernetes_review import NOTICE as KUBERNETES_NOTICE
from .kubernetes_review import review_kubernetes_source
from .models import ValidationError

EXCLUDED = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    "site-packages",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".env",
    ".html",
    ".htm",
}
SECRET_PATTERNS = (
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
    r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b",
)
_COMBINED_SECRET_RE = re.compile("|".join(f"(?:{pattern})" for pattern in SECRET_PATTERNS))


def is_excluded_dirname(name: str) -> bool:
    return name in EXCLUDED or name.startswith(".venv") or name.endswith("-venv")


def inspect_text(name: str, source: str) -> tuple[AssessmentFinding, ...]:
    findings = []
    if _COMBINED_SECRET_RE.search(source):
        for index, line in enumerate(source.splitlines(), 1):
            if _COMBINED_SECRET_RE.search(line):
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
    findings.extend(inspect_configuration(name, source))
    return tuple(findings)


def local_inventory(target: str) -> AssessmentResult:
    kind = identify_target(target)
    path = Path(target)
    if path.is_symlink():
        raise ValidationError("Root symlinks are not accepted for inventory")
    if kind == "program_file":
        return audit_binary(target)
    if kind not in ("local_project", "python_source"):
        return AssessmentService().assess(target)
    raw_cache: dict[Path, bytes] = {}
    service = AssessmentService()
    service._raw_cache = raw_cache
    baseline = service.assess(target)
    findings, missing = list(baseline.findings), list(baseline.not_checked)
    candidates = [path]
    if path.is_dir():
        import os

        candidates = []
        stopped = False
        visited = 0
        walk_errors = []
        for directory, dirs, files in os.walk(
            path, followlinks=False, onerror=walk_errors.append
        ):
            if "pyvenv.cfg" in files and Path(directory) != path:
                dirs[:] = []
                continue
            dirs[:] = sorted(
                d
                for d in dirs
                if not is_excluded_dirname(d) and not (Path(directory) / d).is_symlink()
            )
            visited += 1
            for name in sorted(files):
                item = Path(directory) / name
                if not item.is_symlink() and (
                    item.suffix in TEXT_SUFFIXES
                    or item.suffix.lower() in (".html", ".htm")
                    or name == ".env"
                    or configuration_file(name)
                ):
                    candidates.append(item)
                if len(candidates) >= 100 or visited >= 1000:
                    stopped = True
                    break
            if stopped or visited >= 1000:
                missing.append("Inventory traversal stopped at the file/directory limit.")
                break
        for err in walk_errors:
            err_name = Path(getattr(err, "filename", None) or target).name
            missing.append(f"Could not enumerate directory: {err_name}")
    for item in candidates:
        try:
            cached_bytes = raw_cache.get(item)
            if cached_bytes is not None:
                data = cached_bytes
            else:
                with item.open("rb") as stream:
                    data = stream.read(256 * 1024 + 1)
            if len(data) > 256 * 1024:
                missing.append(f"Skipped oversized file: {item.name}")
                continue
            source = data.decode("utf-8")
            findings.extend(
                inspect_text(
                    str(item.relative_to(path) if path.is_dir() else item.name),
                    source,
                )
            )
            if item.suffix.lower() in (".html", ".htm"):
                observed, gaps = inspect_html(source)
                name = str(item.relative_to(path) if path.is_dir() else item.name)
                findings.extend(
                    AssessmentFinding(f.check, f.status, name + ": " + f.evidence, f.recommendation)
                    for f in observed
                )
                missing.extend(gaps)
            if item.suffix.lower() == ".json":
                name = str(item.relative_to(path) if path.is_dir() else item.name)
                review = review_kubernetes_source(source, name)
                if review is not None:
                    findings.extend(review.findings)
                    missing.extend(n for n in review.not_checked if n != KUBERNETES_NOTICE)
        except (OSError, UnicodeError):
            missing.append(f"Could not read text file: {item.name}")
    missing.append(NOTICE)
    missing.append(KUBERNETES_NOTICE)
    missing.append("Secret patterns are incomplete; no dependency advisory database was queried.")
    return AssessmentResult(target, kind, "partial", tuple(findings), tuple(missing))
