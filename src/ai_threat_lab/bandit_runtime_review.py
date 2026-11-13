"""Offline artifact and runtime inventory checks. No package code is loaded."""

import hmac
import io
from email.parser import BytesParser
from hashlib import sha256
from zipfile import ZipFile

from .models import ValidationError
from .scanner_objects import digest
from .scanner_plan import SUPPORTED_VERSION

BANDIT_WHEEL_SHA256 = "509f7af645bc0cd8fd4587abc1a038fc795636671ee8204d502b933aee44f381"


def inspect_bandit_wheel(raw: bytes):
    """Authenticate the pinned PyPI artifact before reading its distribution metadata."""
    if not hmac.compare_digest(sha256(raw).hexdigest(), BANDIT_WHEEL_SHA256):
        raise ValidationError("Bandit wheel does not match the pinned PyPI artifact")
    metadata_path = f"bandit-{SUPPORTED_VERSION}.dist-info/METADATA"
    with ZipFile(io.BytesIO(raw)) as wheel:
        metadata = BytesParser().parsebytes(wheel.read(metadata_path))
    if metadata["Name"] != "bandit" or metadata["Version"] != SUPPORTED_VERSION:
        raise ValidationError("Unexpected Bandit distribution identity")
    return {
        "version": SUPPORTED_VERSION, "sha256": BANDIT_WHEEL_SHA256,
        "declared_dependencies": tuple(metadata.get_all("Requires-Dist", [])),
    }


def runtime_inventory(review, *, platform, architecture, python_version):
    """Build a candidate inventory for independent review and pinning."""
    plan = review.plan
    if plan.scanner != "bandit" or plan.platform != platform:
        raise ValidationError("Runtime review requires Bandit and the expected platform")
    return {
        "version": 1, "bandit_version": SUPPORTED_VERSION,
        "platform": platform, "architecture": architecture, "python_version": python_version,
        "plan": review.fingerprint(), "runtime": review.runtime.manifest(),
        "files": review.runtime.tree.manifest()["entries"],
    }


def review_runtime_inventory(review, *, pinned_digest, platform, architecture, python_version):
    """Match captured objects to an external pin, without attesting loader closure."""
    inventory = runtime_inventory(
        review, platform=platform, architecture=architecture, python_version=python_version,
    )
    fingerprint = digest(inventory)
    if not hmac.compare_digest(fingerprint, pinned_digest):
        raise ValidationError("Captured runtime does not match the pinned inventory")
    hazards = []
    for row in inventory["files"]:
        path = row["path"].lower()
        leaf = path.rsplit("/", 1)[-1]
        if leaf in {"sitecustomize.py", "usercustomize.py"} or path.endswith(
            (".pth", ".zip", ".pyz", ".egg"),
        ):
            hazards.append(row["path"])
    return {
        "inventory_sha256": fingerprint, "runtime_resolution": "unverified",
        "startup_artifacts": tuple(hazards),
        "unresolved": (
            "stdlib and distribution installation provenance",
            "dynamic imports, namespace packages and import hooks",
            "native loader, shared libraries and host resources",
            "environment-dependent resolution and immutable backend handoff",
        ),
    }
