"""Read-only discovery and plan validation for optional Bandit integration."""

import hashlib
import hmac
import os
import re
import shutil
from pathlib import Path

from .agent_fs import pinned_directory
from .models import ValidationError
from .report_io import read_regular

SUPPORTED_VERSION = "1.7.8"
MAX_EXECUTABLE_BYTES = 32 * 1024 * 1024
EXECUTION_BLOCKER = "Filesystem and network confinement have not been verified."


def network_syntax(path):
    return str(path).startswith(("//", "\\\\"))


def bandit_availability():
    """Probe PATH presence without launching or trusting a candidate."""
    directories = [
        item for item in os.get_exec_path()
        if Path(item).is_absolute() and not network_syntax(item)
    ]
    return {
        "scanner": "bandit",
        "candidate_present": bool(directories and shutil.which(
            "bandit", path=os.pathsep.join(directories),
        )),
        "supported_declaration": SUPPORTED_VERSION,
        "execution": "blocked",
        "reason": EXECUTION_BLOCKER,
    }


def plan_bandit(target, *, executable, expected_sha256, declared_version):
    """Validate an explicit candidate fingerprint and local directory without execution."""
    if declared_version != SUPPORTED_VERSION:
        raise ValidationError("Unsupported declared Bandit version")
    if not isinstance(expected_sha256, str) or not re.fullmatch(
        r"[0-9a-fA-F]{64}", expected_sha256,
    ):
        raise ValidationError("Expected executable SHA-256 must contain 64 hex digits")
    program = Path(executable)
    if any(network_syntax(path) for path in (program, target)):
        raise ValidationError("Network and device paths are not supported for Bandit planning")
    if not program.is_absolute():
        raise ValidationError("An explicit absolute Bandit executable path is required")
    root = Path(os.path.abspath(target))
    if network_syntax(root):
        raise ValidationError("Network and device paths are not supported for Bandit planning")
    try:
        with pinned_directory(root) as descriptor:
            identity = os.fstat(descriptor) if descriptor is not None else root.stat()
            raw = read_regular(
                program, MAX_EXECUTABLE_BYTES, limit_message="Bandit executable exceeds byte limit",
            )
    except OSError:
        raise ValidationError("Cannot open the selected executable or project directory") from None
    fingerprint = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(fingerprint, expected_sha256.lower()):
        raise ValidationError("Bandit executable fingerprint does not match the expected SHA-256")
    return {
        "schema_version": 1,
        "scanner": "bandit",
        "target": str(root),
        "target_identity": {"device": identity.st_dev, "inode": identity.st_ino},
        "executable": str(program),
        "executable_sha256": fingerprint,
        "declared_version": declared_version,
        "version_verified": False,
        "authorized_to_execute": False,
        "execution": "blocked",
        "reason": EXECUTION_BLOCKER,
    }
