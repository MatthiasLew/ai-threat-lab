"""Literal configuration observations; no YAML interpreter or container execution."""

import re
from pathlib import PurePosixPath

from .assessment import AssessmentFinding

NOTICE = (
    "Dockerfile/workflow checks inspect selected literal lines only; no YAML evaluation, "
    "build, expression expansion, inherited-image or effective-permission analysis."
)

_DOCKER_USER_ROOT_RE = re.compile(r"(?i)USER\s+(root|0)(?::[^\s#]+)?\s*(?:#.*)?")
_DOCKER_FROM_RE = re.compile(r"(?i)FROM\s+([^\s]+)(?:\s+AS\s+(\S+))?\s*(?:#.*)?")
_DOCKER_SHA256_RE = re.compile(r"@sha256:[a-fA-F0-9]{64}$")
_DOCKER_REMOTE_ADD_RE = re.compile(r"(?i)ADD\s+(?:--\S+\s+)*https?://")
_WORKFLOW_WRITE_ALL_RE = re.compile(r"permissions:\s*['\"]?write-all['\"]?\s*(?:#.*)?")
_WORKFLOW_USES_RE = re.compile(
    r"(?:-\s*)?uses:\s*['\"]?([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)"
    r"@([A-Za-z0-9_.+-]+)['\"]?\s*(?:#.*)?"
)
_SHA40_RE = re.compile(r"[a-fA-F0-9]{40}")


def configuration_file(name):
    path = PurePosixPath(name.replace("\\", "/"))
    return (
        path.name == "Dockerfile"
        or path.name.startswith("Dockerfile.")
        or (path.name.endswith(".Dockerfile"))
    )


def inspect_configuration(name, source):
    path = PurePosixPath(name.replace("\\", "/"))
    docker = configuration_file(name)
    workflow = path.suffix in (".yml", ".yaml") and path.parts[-3:-1] == (".github", "workflows")
    if not docker and not workflow:
        return ()
    findings, stages = [], set()

    def add(check, line, title, recommendation):
        findings.append(
            AssessmentFinding(check, "candidate", f"{name}:{line}: {title}", recommendation)
        )

    for number, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if docker:
            # Only simple single-line instructions; never reproduce their arguments.
            match = _DOCKER_USER_ROOT_RE.fullmatch(stripped)
            if match:
                add(
                    "container_explicit_root",
                    number,
                    "Explicit root USER instruction",
                    "Review every build stage and use a suitable non-root runtime user.",
                )
            match = _DOCKER_FROM_RE.fullmatch(stripped)
            if match and not match[1].startswith("$") and match[1].lower() != "scratch":
                image = match[1]
                if (
                    image.lower() not in stages
                    and not image.isdecimal()
                    and not _DOCKER_SHA256_RE.search(image)
                ):
                    add(
                        "container_mutable_base",
                        number,
                        "Base image lacks a SHA-256 digest",
                        "Review provenance and pin the reviewed image digest; plan updates.",
                    )
            if match and match[2]:
                stages.add(match[2].lower())
            if _DOCKER_REMOTE_ADD_RE.match(stripped):
                add(
                    "container_remote_add",
                    number,
                    "Remote ADD instruction",
                    "Review source integrity and use verified, reproducible build inputs.",
                )
        if workflow:
            if _WORKFLOW_WRITE_ALL_RE.fullmatch(stripped):
                add(
                    "workflow_write_all",
                    number,
                    "Explicit write-all token permissions",
                    "Set minimal job-specific permissions and review untrusted event inputs.",
                )
            match = _WORKFLOW_USES_RE.fullmatch(stripped)
            if match and not _SHA40_RE.fullmatch(match[2]):
                add(
                    "workflow_mutable_action",
                    number,
                    "External action uses a mutable reference",
                    "Pin a reviewed full commit SHA and maintain an update process.",
                )
    return tuple(findings)
