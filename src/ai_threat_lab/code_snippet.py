"""Safe source code snippet extraction and line highlighting.

Provides bounded, read-only extraction of code snippets around detected findings with
context lines, visual highlighting of the suspicious line, secret redaction, and
divergence checks. Never executes code and never reads unbounded file data.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .dependency_paths import linked
from .local_inventory import SECRET_PATTERNS
from .models import ValidationError
from .report_io import read_regular

MAX_SNIPPET_FILE_BYTES = 512 * 1024  # 512 KiB per-file read limit
MAX_SNIPPET_LINE_LENGTH = 160
DEFAULT_CONTEXT_LINES = 2

# High-entropy credential or token patterns for safe redaction in snippets
_SECRET_PATTERNS = [
    re.compile(
        r"""(?i)(api[_-]?key|secret|token|password|passwd|auth)\s*[:=]\s*['"][A-Za-z0-9_\-.~+/=]{8,}['"]"""
    ),
    re.compile(r"""AIza[0-9A-Za-z-_]{35}"""),
    re.compile(r"""sk-[A-Za-z0-9_-]{20,}"""),
    re.compile(r"""bearer\s+[A-Za-z0-9_\-.~+/=]{16,}""", re.IGNORECASE),
]


@dataclass(frozen=True)
class SnippetLine:
    line_number: int
    text: str
    is_target: bool


@dataclass(frozen=True)
class CodeSnippet:
    file_path: str
    target_line: int
    lines: tuple[SnippetLine, ...]
    status: str  # "exact", "diverged", "unavailable"
    language_hint: str = "python"

    def format_text(self) -> str:
        """Render snippet text with line numbers and target marker."""
        out = []
        for line in self.lines:
            marker = ">" if line.is_target else " "
            out.append(f"{marker} {line.line_number:4d} | {line.text}")
        return "\n".join(out)


def redact_snippet_secrets(text: str) -> str:
    """Scrub raw API keys and passwords from code snippet text."""
    result = re.sub(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?"
        r"(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\Z)",
        lambda match: "[REDACTED_SECRET]" + "\n" * match.group().count("\n"), text,
    )
    result = re.sub(
        r'''(?i)\b\w*(?:key|secret|token|password|passwd|auth|credential)\w*\s*[:=]\s*(["'])(?:\\.|(?!\1)[^\r\n])*\1''',
        "[REDACTED_SECRET]", result,
    )
    for pattern in SECRET_PATTERNS:
        result = re.sub(pattern, "[REDACTED_SECRET]", result)
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("[REDACTED_SECRET]", result)
    return result


def extract_code_snippet(
    target_path: str | Path,
    line_number: int | None,
    *,
    context_lines: int = DEFAULT_CONTEXT_LINES,
    max_bytes: int = MAX_SNIPPET_FILE_BYTES,
    expected_hash: str | None = None,
    source_root: Path | str | None = None,
) -> CodeSnippet | None:
    """Safely extract source code context around a given line number.

    Returns None if line_number is None or file cannot be resolved.
    """
    if line_number is None:
        return None
    if (type(line_number) is not int or line_number < 1
            or type(context_lines) is not int or not 0 <= context_lines <= 10
            or type(max_bytes) is not int or not 1 <= max_bytes <= MAX_SNIPPET_FILE_BYTES):
        raise ValidationError("Invalid source context bounds")
    if expected_hash is not None and (
        not isinstance(expected_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_hash)
    ):
        raise ValidationError("Source hash must be SHA-256")

    path_candidate = Path(target_path)
    if source_root is not None:
        root = Path(source_root).absolute()
        if not path_candidate.is_absolute():
            path_candidate = root / path_candidate
        if (linked(root) or not root.is_dir()
                or not path_candidate.resolve().is_relative_to(root.resolve())
                or any(linked(p) for p in (path_candidate, *path_candidate.parents))):
            return CodeSnippet(str(target_path), line_number, (), "unavailable")

    if not path_candidate.is_file():
        return CodeSnippet(
            file_path=str(target_path),
            target_line=line_number,
            lines=(),
            status="unavailable",
        )

    try:
        stat = path_candidate.stat()
        if stat.st_size > max_bytes:
            return CodeSnippet(
                file_path=str(target_path),
                target_line=line_number,
                lines=(),
                status="file_too_large",
            )

        raw_bytes = read_regular(path_candidate, max_bytes)
        actual_hash = hashlib.sha256(raw_bytes).hexdigest()

        diverged = bool(expected_hash and actual_hash != expected_hash)
        if diverged:
            return CodeSnippet(str(target_path), line_number, (), "diverged")

        raw_text = raw_bytes.decode("utf-8", errors="replace")
        all_lines = redact_snippet_secrets(raw_text).splitlines()

        total = len(all_lines)
        if total == 0:
            return None

        # 1-based indexing for line_number
        idx = line_number - 1
        if idx >= total:
            # File might have shrunk or line number was outside scope
            return CodeSnippet(
                file_path=str(target_path),
                target_line=line_number,
                lines=(),
                status="diverged" if diverged else "line_out_of_range",
            )

        start_idx = max(0, idx - context_lines)
        end_idx = min(total, idx + context_lines + 1)

        snippet_lines = []
        for i in range(start_idx, end_idx):
            num = i + 1
            line_str = all_lines[i]
            if len(line_str) > MAX_SNIPPET_LINE_LENGTH:
                line_str = line_str[:MAX_SNIPPET_LINE_LENGTH] + "..."
            clean_line = redact_snippet_secrets(line_str)
            snippet_lines.append(
                SnippetLine(
                    line_number=num,
                    text=clean_line,
                    is_target=(num == line_number),
                )
            )

        suffix = path_candidate.suffix.lower()
        hint = {
            ".py": "python",
            ".json": "json",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".html": "html",
            ".js": "javascript",
            ".sh": "bash",
        }.get(suffix, "text")

        return CodeSnippet(
            file_path=str(target_path),
            target_line=line_number,
            lines=tuple(snippet_lines),
            status="exact" if expected_hash else "unverified_current",
            language_hint=hint,
        )
    except (OSError, ValidationError):
        return CodeSnippet(
            file_path=str(target_path),
            target_line=line_number,
            lines=(),
            status="unavailable",
        )
