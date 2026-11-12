"""Read-only sandbox diagnostics and the plan fields reserved for owner approval."""

import ctypes
import hashlib
import json
import os
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from .scanner_plan import EXECUTION_BLOCKER


@dataclass(frozen=True)
class SandboxDiagnostic:
    platform: str
    backend: str | None
    prerequisites: tuple[tuple[str, bool], ...]
    verified_controls: tuple[str, ...] = ()
    validation: str = "not_validated"
    execution: str = "blocked"
    reason: str = EXECUTION_BLOCKER


@dataclass(frozen=True)
class ScannerExecutionPlan:
    """Canonical review record. A matching fingerprint grants no authority."""

    scanner: str
    target: str
    snapshot_sha256: str
    executable_sha256: str
    interpreter_sha256: str
    dependencies_sha256: str
    configuration_sha256: str
    output_directory: str
    timeout_seconds: int
    memory_bytes: int
    max_processes: int
    scratch_bytes: int
    max_output_bytes: int
    platform: str
    backend: str
    backend_policy_sha256: str
    network: str = "denied"

    def fingerprint(self) -> str:
        record = {"schema_version": 1, "plan": asdict(self)}
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")
        return hashlib.sha256(canonical).hexdigest()


def system_bubblewrap() -> Path | None:
    """Discover a candidate at a system path without consulting PATH or launching it."""
    for candidate in (Path("/usr/bin/bwrap"), Path("/bin/bwrap")):
        try:
            info = candidate.stat()
        except OSError:
            continue
        if (
            stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and not info.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022)
            and os.access(candidate, os.X_OK)
        ):
            return candidate
    return None


def _windows_api(library: str, entry: str) -> bool:
    try:
        # LOAD_LIBRARY_SEARCH_SYSTEM32 avoids loading DLLs from the project.
        getattr(ctypes.WinDLL(library, winmode=0x800), entry)
    except (AttributeError, OSError):
        return False
    return True


def sandbox_diagnostic() -> SandboxDiagnostic:
    """Report prerequisites. Presence does not establish effective isolation."""
    if sys.platform == "linux":
        return SandboxDiagnostic("linux", "bubblewrap", (
            ("system_bubblewrap_candidate", system_bubblewrap() is not None),
            ("cgroup_v2_hierarchy", Path("/sys/fs/cgroup/cgroup.controllers").is_file()),
        ))
    if sys.platform == "win32":
        return SandboxDiagnostic("win32", "appcontainer", (
            ("appcontainer_profile_api", _windows_api("userenv.dll", "CreateAppContainerProfile")),
            ("job_object_api", _windows_api("kernel32.dll", "CreateJobObjectW")),
        ))
    return SandboxDiagnostic(sys.platform, None, ())
