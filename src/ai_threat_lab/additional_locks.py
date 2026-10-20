"""Recorded Composer/NuGet identities; no package manager execution or restore."""

import re

from .models import ValidationError


def release_version(value, *, composer=False):
    if not isinstance(value, str) or len(value) > 128:
        return False
    prefix = "v?" if composer else ""
    return bool(re.fullmatch(
        prefix + r"[0-9]+(?:\.[0-9]+){1,3}"
        r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
        r"(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?", value
    )) and not (composer and re.search(r"(?:^|[.-])dev(?:$|[.+-])", value, re.I))


def parse_composer(document, origin, add, note):
    if not isinstance(document, dict) or not isinstance(document.get("packages"), list):
        raise ValidationError("Composer lock requires its recorded package array")
    groups = (document["packages"], document.get("packages-dev", []))
    if any(not isinstance(group, list) for group in groups) or sum(map(len, groups)) > 2000:
        raise ValidationError("Composer package groups exceed their type or entry bounds")
    note(
        f"{origin}: recorded production and development package identities included; "
        "Packagist provenance, custom registries, source commits, hashes, platform "
        "requirements, plugins, install state and reachability are unverified."
    )
    for group in groups:
        for package in group:
            if not isinstance(package, dict):
                raise ValidationError("Malformed Composer package row")
            dist = package.get("dist")
            if dist is not None and not isinstance(dist, dict):
                raise ValidationError("Malformed Composer distribution metadata")
            if isinstance(dist, dict) and dist.get("type") == "path":
                note(f"{origin}: skipped local path package; value omitted.")
                continue
            version = package.get("version")
            if not release_version(version, composer=True):
                note(f"{origin}: skipped unsupported or development version; value omitted.")
                continue
            add("Packagist", package.get("name"), version, origin)


def parse_nuget(document, origin, add, note):
    if not isinstance(document, dict) or type(document.get("version")) is not int or (
        document["version"] not in (1, 2)
    ):
        raise ValidationError("Only NuGet lock versions 1 and 2 are supported")
    frameworks = document.get("dependencies")
    if not isinstance(frameworks, dict) or len(frameworks) > 64:
        raise ValidationError("NuGet framework map is missing or exceeds 64 entries")
    note(
        f"{origin}: all recorded target frameworks included; feed provenance, content hashes, "
        "project references, selected framework/runtime, restore state and reachability "
        "are unverified. Requested ranges are not substituted for resolved versions."
    )
    total = 0
    for packages in frameworks.values():
        if not isinstance(packages, dict):
            raise ValidationError("Malformed NuGet framework package map")
        total += len(packages)
        if total > 5000:
            raise ValidationError("NuGet recorded package-row limit exceeded")
        for name, package in packages.items():
            if not isinstance(package, dict):
                raise ValidationError("Malformed NuGet package row")
            if package.get("type") not in ("Direct", "Transitive"):
                note(f"{origin}: skipped project or unsupported dependency kind; value omitted.")
                continue
            version = package.get("resolved")
            if not release_version(version):
                note(f"{origin}: skipped unresolved or unsupported version; value omitted.")
                continue
            add("NuGet", name, version, origin)
