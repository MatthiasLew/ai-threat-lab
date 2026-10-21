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

EXCLUDED = frozenset(
    {
        # Version control
        ".git",
        ".svn",
        ".hg",
        # Virtual environments & package managers
        ".venv",
        "venv",
        "env",
        ".virtualenv",
        "node_modules",
        "site-packages",
        ".cargo",
        ".rustup",
        # Build & test caches
        "__pycache__",
        "dist",
        "build",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".hypothesis",
        ".coverage",
        "htmlcov",
        # Temporary directories, caches, and AI/IDE workspaces
        ".ai",
        ".gemini",
        ".antigravity",
        ".cursor",
        ".vscode",
        ".idea",
        "tmp",
        "temp",
        ".tmp",
        ".temp",
        ".cache",
        "cache",
    }
)

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
    ".go",
    ".rs",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".cs",
    ".php",
    ".rb",
    ".sh",
    ".bash",
    ".sql",
    ".xml",
    ".properties",
    ".ini",
    ".cfg",
    ".conf",
}

SECRET_PATTERNS = (
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
    r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b",
)
_COMBINED_SECRET_RE = re.compile("|".join(f"(?:{pattern})" for pattern in SECRET_PATTERNS))


def is_excluded_dirname(name: str) -> bool:
    """Return True if directory represents a temporary, cache, build, or virtualenv directory."""
    low = name.lower()
    if low in EXCLUDED:
        return True
    if low.startswith((".venv", "venv-", "env-")) or low.endswith(("-venv", ".venv", "-env")):
        return True
    if low.endswith((".egg-info", ".dist-info")):
        return True
    return False


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


def local_inventory(
    target: str, max_files: int = 100, max_bytes: int = 64 * 1024 * 1024
) -> AssessmentResult:
    kind = identify_target(target)
    path = Path(target)
    if path.is_symlink():
        raise ValidationError("Root symlinks are not accepted for inventory")
    if kind == "program_file":
        return audit_binary(target)
    if kind not in ("local_project", "python_source"):
        return AssessmentService().assess(target)
    raw_cache: dict[Path, bytes] = {}
    service = AssessmentService(max_files=max_files)
    service._raw_cache = raw_cache
    baseline = service.assess(target)
    findings, missing = list(baseline.findings), list(baseline.not_checked)
    candidates = [path]
    excluded_dirs: set[str] = set()
    dir_limit = max(1000, min(50000, max_files * 10))
    recognized_tech: set[str] = set()
    if path.is_dir():
        import os

        def file_priority(item_name: str) -> int:
            low = item_name.lower()
            if low == ".env" or low.endswith(
                (
                    ".py",
                    ".go",
                    ".rs",
                    ".js",
                    ".ts",
                    ".java",
                    ".c",
                    ".cpp",
                    ".cs",
                    ".php",
                    ".rb",
                    ".sh",
                    ".bash",
                )
            ):
                return 0
            if configuration_file(low) or low.endswith(
                (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".sql")
            ):
                return 1
            return 2

        candidates = []
        stopped = False
        visited = 0
        walk_errors = []
        for directory, dirs, files in os.walk(path, followlinks=False, onerror=walk_errors.append):
            if "pyvenv.cfg" in files and Path(directory) != path:
                dirs[:] = []
                continue
            pruned_dirs = [d for d in dirs if is_excluded_dirname(d)]
            excluded_dirs.update(pruned_dirs)
            dirs[:] = sorted(
                d
                for d in dirs
                if not is_excluded_dirname(d) and not (Path(directory) / d).is_symlink()
            )
            visited += 1
            sorted_files = sorted(files, key=lambda f: (file_priority(f), f))
            for name in sorted_files:
                item = Path(directory) / name
                if not item.is_symlink() and (
                    item.suffix in TEXT_SUFFIXES
                    or item.suffix.lower() in (".html", ".htm")
                    or name == ".env"
                    or configuration_file(name)
                ):
                    candidates.append(item)
                    ext = item.suffix.lower()
                    if ext == ".py":
                        recognized_tech.add("Python")
                    elif ext == ".go":
                        recognized_tech.add("Go")
                    elif ext == ".rs":
                        recognized_tech.add("Rust")
                    elif ext == ".java":
                        recognized_tech.add("Java")
                    elif ext in (".c", ".cpp", ".h"):
                        recognized_tech.add("C/C++")
                    elif ext in (".js", ".ts"):
                        recognized_tech.add("JavaScript/TypeScript")
                    elif ext in (".sh", ".bash"):
                        recognized_tech.add("Shell/Bash")
                    elif ext in (".html", ".htm"):
                        recognized_tech.add("HTML")
                    elif ext == ".sql":
                        recognized_tech.add("SQL")
                    elif (
                        name == ".env"
                        or configuration_file(name)
                        or ext in (".json", ".yaml", ".yml", ".toml")
                    ):
                        recognized_tech.add("Config")
                if len(candidates) >= max_files or visited >= dir_limit:
                    stopped = True
                    break
            if stopped or visited >= dir_limit:
                missing.append(
                    f"Inventory traversal stopped at the file/directory limit "
                    f"({max_files} files / {dir_limit} directories). Scope is incomplete."
                )
                break
        if excluded_dirs:
            sample_dirs = ", ".join(sorted(excluded_dirs)[:8])
            more = f" (+{len(excluded_dirs) - 8} more)" if len(excluded_dirs) > 8 else ""
            missing.append(
                f"Excluded {len(excluded_dirs)} temporary/cache/environment directories: "
                f"{sample_dirs}{more}."
            )
        for err in walk_errors:
            err_name = Path(getattr(err, "filename", None) or target).name
            missing.append(f"Could not enumerate directory: {err_name}")
    total_bytes_read = 0
    scanned_files_count = 0
    byte_budget_exceeded = False
    for item in candidates:
        if total_bytes_read >= max_bytes:
            byte_budget_exceeded = True
            break
        try:
            cached_bytes = raw_cache.get(item)
            if cached_bytes is not None:
                data = cached_bytes
            else:
                with item.open("rb") as stream:
                    data = stream.read(256 * 1024 + 1)
            total_bytes_read += len(data)
            if len(data) > 256 * 1024:
                missing.append(f"Skipped oversized file: {item.name}")
                continue
            source = data.decode("utf-8")
            scanned_files_count += 1
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
    if byte_budget_exceeded:
        missing.append(
            f"Inventory read byte budget limit reached ({max_bytes // (1024 * 1024)} MiB). "
            f"Remaining files omitted to protect memory."
        )
    if recognized_tech:
        missing.append(
            f"Scope technologies: {', '.join(sorted(recognized_tech))}. "
            f"Files inspected: {scanned_files_count} / {len(candidates)}."
        )
    missing.append(NOTICE)
    missing.append(KUBERNETES_NOTICE)
    missing.append("Secret patterns are incomplete; no dependency advisory database was queried.")
    return AssessmentResult(target, kind, "partial", tuple(findings), tuple(missing))
