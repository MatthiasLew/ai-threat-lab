"""Deterministic bounded manifest discovery; never follow links or execute files."""

import os
from collections import deque
from pathlib import Path

from .local_inventory import EXCLUDED
from .models import ValidationError

SUPPORTED = {"package-lock.json", "poetry.lock", "uv.lock", "Cargo.lock", "go.sum",
             "composer.lock", "packages.lock.json"}
MAX_MANIFESTS = 20
MAX_DIRECTORIES = 1000
MAX_ENTRIES = 10000
MAX_DEPTH = 8
MAX_TOTAL_BYTES = 4 * 1024 * 1024


def is_manifest(name):
    return name in SUPPORTED or (name.startswith("requirements") and name.endswith(".txt"))


def valid_source_path(name, *, allow_paths=False):
    if not isinstance(name, str) or not name or len(name) > 1024:
        return False
    if "\\" in name or ":" in name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        return False
    parts = name.split("/")
    return (allow_paths or len(parts) == 1) and all(
        p not in ("", ".", "..") and len(p) <= 255 for p in parts
    )


def linked(path):
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def discover_manifests(root, *, recursive=False):
    """Root-first breadth-first selection with global directory/entry/manifest bounds."""
    root = Path(root)
    queue = deque([(root, 0)])
    files, notices = [], []
    visited, inspected = 0, 0
    skipped_notices = 0

    def note(message):
        nonlocal skipped_notices
        if len(notices) < 90:
            notices.append(message)
        else:
            skipped_notices += 1

    stop = False
    while queue and not stop:
        if visited >= MAX_DIRECTORIES:
            note("Dependency discovery directory limit reached; remaining directories unchecked.")
            break
        folder, depth = queue.popleft()
        visited += 1
        entries = []
        try:
            with os.scandir(folder) as stream:
                for entry in stream:
                    if inspected >= MAX_ENTRIES:
                        note(
                            "Dependency discovery entry limit reached; remaining entries unchecked."
                        )
                        stop = True
                        break
                    inspected += 1
                    entries.append(entry)
        except OSError:
            note("Could not enumerate a dependency directory; some manifests remain unchecked.")
            continue
        for entry in sorted(entries, key=lambda e: e.name):
            path = Path(entry.path)
            origin = path.relative_to(root).as_posix()
            try:
                if linked(path):
                    if is_manifest(entry.name) or recursive:
                        note(f"{origin}: skipped symlink or junction.")
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if is_manifest(entry.name):
                        note(f"{origin}: skipped non-file manifest path.")
                    if recursive and entry.name not in EXCLUDED:
                        if depth < MAX_DEPTH:
                            queue.append((path, depth + 1))
                        else:
                            note(
                                "Dependency discovery depth limit reached; deeper paths unchecked."
                            )
                    continue
                if not is_manifest(entry.name):
                    continue
                if not entry.is_file(follow_symlinks=False):
                    note(f"{origin}: skipped non-regular manifest.")
                    continue
                if not valid_source_path(origin, allow_paths=recursive):
                    note("Skipped a non-portable manifest path; values omitted.")
                    continue
                if len(files) >= MAX_MANIFESTS:
                    if not recursive:
                        raise ValidationError(
                            "At most 20 manifests per directory; narrow the scope"
                        )
                    note("Dependency manifest limit reached; additional paths unchecked.")
                    queue.clear()
                    stop = True
                    break
                files.append((path, origin))
            except OSError:
                note("Could not inspect a dependency path; some manifests remain unchecked.")
    if skipped_notices:
        notices.append(f"Additional omitted discovery notices: {skipped_notices}.")
    return files, notices
