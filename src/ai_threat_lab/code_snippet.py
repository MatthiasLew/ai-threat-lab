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
    result = text
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
    if line_number is None or line_number < 1:
        return None

    path_candidate = Path(target_path)
    if source_root is not None and not path_candidate.is_file():
        candidate = Path(source_root) / path_candidate
        if candidate.is_file():
            path_candidate = candidate

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

        raw_bytes = path_candidate.read_bytes()
        actual_hash = hashlib.sha256(raw_bytes).hexdigest()

        diverged = False
        if expected_hash and actual_hash != expected_hash:
            diverged = True

        raw_text = raw_bytes.decode("utf-8", errors="replace")
        all_lines = raw_text.splitlines()

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
            status="diverged" if diverged else "exact",
            language_hint=hint,
        )
    except (OSError, PermissionError):
        return CodeSnippet(
            file_path=str(target_path),
            target_line=line_number,
            lines=(),
            status="unavailable",
        )
