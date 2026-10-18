"""Literal configuration observations; no YAML interpreter or container execution."""

import re
from pathlib import PurePosixPath

from .assessment import AssessmentFinding

NOTICE = (
    "Dockerfile/workflow checks inspect selected literal lines only; no YAML evaluation, "
    "build, expression expansion, inherited-image or effective-permission analysis."
)


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
            match = re.fullmatch(r"(?i)USER\s+(root|0)(?::[^\s#]+)?\s*(?:#.*)?", stripped)
            if match:
                add(
                    "container_explicit_root",
                    number,
                    "Explicit root USER instruction",
                    "Review every build stage and use a suitable non-root runtime user.",
                )
            match = re.fullmatch(r"(?i)FROM\s+([^\s]+)(?:\s+AS\s+(\S+))?\s*(?:#.*)?", stripped)
            if match and not match[1].startswith("$") and match[1].lower() != "scratch":
                image = match[1]
                if (
                    image.lower() not in stages
                    and not image.isdecimal()
                    and not re.search(r"@sha256:[a-fA-F0-9]{64}$", image)
                ):
                    add(
                        "container_mutable_base",
                        number,
                        "Base image lacks a SHA-256 digest",
                        "Review provenance and pin the reviewed image digest; plan updates.",
                    )
            if match and match[2]:
                stages.add(match[2].lower())
            if re.match(r"(?i)ADD\s+(?:--\S+\s+)*https?://", stripped):
                add(
                    "container_remote_add",
                    number,
                    "Remote ADD instruction",
                    "Review source integrity and use verified, reproducible build inputs.",
                )
        if workflow:
            if re.fullmatch(r"permissions:\s*['\"]?write-all['\"]?\s*(?:#.*)?", stripped):
                add(
                    "workflow_write_all",
                    number,
                    "Explicit write-all token permissions",
                    "Set minimal job-specific permissions and review untrusted event inputs.",
                )
            match = re.fullmatch(
                r"(?:-\s*)?uses:\s*['\"]?([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)"
                r"@([A-Za-z0-9_.+-]+)['\"]?\s*(?:#.*)?",
                stripped,
            )
            if match and not re.fullmatch(r"[a-fA-F0-9]{40}", match[2]):
                add(
                    "workflow_mutable_action",
                    number,
                    "External action uses a mutable reference",
                    "Pin a reviewed full commit SHA and maintain an update process.",
                )
    return tuple(findings)
