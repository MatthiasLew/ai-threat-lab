"""Path normalization and validation utilities for AI Threat Lab.

Provides safe handling of user-supplied filesystem paths across Windows, macOS,
and Linux. Specifically resolves issues with paths copied with quotes from file
managers (e.g., Windows Explorer "Copy as path"), PowerShell copy strings, and
terminal drag-and-drops without shell injection or unintentional path corruption.
"""

from __future__ import annotations

from pathlib import Path


def clean_user_path(raw: str | None) -> str:
    """Normalize and sanitize user-supplied filesystem path strings.

    Safe for Windows, Linux, and macOS. Specifically addresses paths copied from
    file managers (like Windows Explorer "Copy as path"), terminal shells, or drag-and-drop
    that include surrounding double or single quotes.

    Rules:
    - Returns empty string for None or empty inputs.
    - Strips leading and trailing whitespace.
    - Strips common shell copy prefixes (e.g. PowerShell '& ' or '@"..."').
    - Removes matching outermost double quotes or single quotes.
    - Strips any remaining whitespace inside stripped quotes.
    - Removes dangerous control characters (such as NUL bytes).
    - Preserves internal quotes, directory separators (forward and backslashes),
      spaces in path components, and UNC path prefixes (\\\\server\\share).
    - Never invokes shell expansion, environment variable substitution, or network calls.
    """
    if raw is None:
        return ""
    val = str(raw).strip()
    if not val:
        return ""

    # Remove NUL bytes immediately
    val = val.replace("\0", "")

    # Handle PowerShell copy-as-path or command paste prefixes
    if val.startswith("& "):
        val = val[2:].strip()
    if val.startswith('@"') and val.endswith('"') and len(val) >= 3:
        val = val[2:-1].strip()

    # Repeatedly strip outermost matching quotes if user wrapped multiple times
    # e.g., '" "path" "' or '""path""'
    changed = True
    while changed and len(val) >= 2:
        changed = False
        is_quoted = (val.startswith('"') and val.endswith('"')) or (
            val.startswith("'") and val.endswith("'")
        )
        if is_quoted:
            val = val[1:-1].strip()
            changed = True

    return val


def suggest_output_dir(safe_name: str, base_dir: str = "reports") -> str:
    """Find the next available non-existing output directory path.

    Returns normalized path string with forward slashes for clean display.
    """
    clean_name = safe_name.strip().replace(" ", "_") or "audit_target"
    base = Path(base_dir) / clean_name
    if not base.exists():
        return str(base).replace("\\", "/")
    idx = 1
    while True:
        candidate = Path(base_dir) / f"{clean_name}_{idx}"
        if not candidate.exists():
            return str(candidate).replace("\\", "/")
        idx += 1
