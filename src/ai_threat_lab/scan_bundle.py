"""Private, no-overwrite report bundles; manifest-last publication and bounded reads."""

import hashlib
import json
import re
import tempfile
from pathlib import Path

from .contracts import _nonfinite, _pairs, fields
from .models import ValidationError

FILES = frozenset(
    (
        "assessment.json",
        "dependency-inventory.json",
        "dependencies.json",
        "report.json",
        "report.html",
        "modules.json",
        "comparison.json",
    )
)
REQUIRED = frozenset(("assessment.json", "report.json", "report.html", "modules.json"))
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
SCOPE_FIELDS = {
    "target",
    "target_kind",
    "engine",
    "network",
    "allowed_hosts",
    "max_files",
    "dkim_selector",
    "share_packages",
    "max_pages",
    "advisory_cache",
}
MODULES = {"target_assessment", "dependency_inventory", "dependency_advisories"}
STATUSES = {"partial", "failed", "collected", "empty_inventory", "not_requested", "not_applicable"}


def encoded(document):
    return (json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def scope_digest(scope):
    return digest(json.dumps(scope, sort_keys=True, separators=(",", ":")).encode())


def document(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise ValidationError("Bundle contains an invalid JSON document") from None


def validate_manifest(value):
    fields(value, {"schema_version", "run_id", "created_at", "scope", "scope_digest", "files"})
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValidationError("Unsupported scan bundle schema")
    if not isinstance(value["run_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", value["run_id"]):
        raise ValidationError("Invalid scan run ID")
    from .contracts import timestamp

    timestamp(value["created_at"], "created_at")
    scope = value["scope"]
    fields(scope, SCOPE_FIELDS, {"recursive_dependencies"})
    current = scope["engine"] in (
        "read-only-pipeline-4",
        "read-only-pipeline-5",
        "read-only-pipeline-6",
        "read-only-pipeline-7",
        "read-only-pipeline-8",
    )
    if current:
        if type(scope.get("recursive_dependencies")) is not bool:
            raise ValidationError("Invalid recursive dependency scan scope")
    elif "recursive_dependencies" in scope:
        raise ValidationError("Legacy scan scope cannot declare recursive dependencies")
    if (
        not isinstance(scope["target"], str)
        or not scope["target"]
        or not isinstance(scope["target_kind"], str)
        or not scope["target_kind"]
        or scope["engine"]
        not in (
            "read-only-pipeline-1",
            "read-only-pipeline-2",
            "read-only-pipeline-3",
            "read-only-pipeline-4",
            "read-only-pipeline-5",
            "read-only-pipeline-6",
            "read-only-pipeline-7",
            "read-only-pipeline-8",
        )
        or type(scope["network"]) is not bool
        or type(scope["share_packages"]) is not bool
        or type(scope["advisory_cache"]) is not bool
        or not isinstance(scope["allowed_hosts"], list)
        or any(not isinstance(h, str) or not h for h in scope["allowed_hosts"])
        or type(scope["max_files"]) is not int
        or not 1 <= scope["max_files"] <= 100
        or type(scope["max_pages"]) is not int
        or not 1 <= scope["max_pages"] <= 20
        or (scope["dkim_selector"] is not None and not isinstance(scope["dkim_selector"], str))
    ):
        raise ValidationError("Invalid scan scope")
    if value["scope_digest"] != scope_digest(scope):
        raise ValidationError("Scan scope digest does not match")
    index = value["files"]
    if not isinstance(index, dict) or not REQUIRED <= index.keys() or index.keys() - FILES:
        raise ValidationError("Invalid bundle artifact index")
    total = 0
    for metadata in index.values():
        fields(metadata, {"bytes", "sha256"})
        if (
            type(metadata["bytes"]) is not int
            or not 0 <= metadata["bytes"] <= MAX_FILE_BYTES
            or not isinstance(metadata["sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", metadata["sha256"])
        ):
            raise ValidationError("Invalid bundle artifact bounds or digest")
        total += metadata["bytes"]
    if total > MAX_TOTAL_BYTES:
        raise ValidationError("Bundle exceeds the total-byte limit")


def validate_modules(value):
    fields(value, MODULES)
    for item in value.values():
        fields(item, {"status", "notice"})
        if (
            not isinstance(item["status"], str)
            or item["status"] not in STATUSES
            or not isinstance(item["notice"], str)
            or not item["notice"]
        ):
            raise ValidationError("Invalid module status")


def publish_bundle(destination: Path, artifacts: dict[str, bytes], metadata: dict) -> dict:
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Scan output directory already exists")
    if not REQUIRED <= artifacts.keys() or artifacts.keys() - FILES:
        raise ValidationError("Unsupported scan artifacts")
    manifest = {
        **metadata,
        "schema_version": 1,
        "files": {
            name: {"bytes": len(raw), "sha256": digest(raw)}
            for name, raw in sorted(artifacts.items())
        },
    }
    validate_manifest(manifest)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Stage complete bytes before claiming the final path. The manifest is the commit marker.
    with tempfile.TemporaryDirectory(prefix=".ai-threat-scan-", dir=destination.parent) as staging:
        stage = Path(staging)
        for name, raw in {**artifacts, "manifest.json": encoded(manifest)}.items():
            (stage / name).write_bytes(raw)
        destination.mkdir(
            mode=0o700
        )  # Atomic no-overwrite claim, including existing empty folders.
        created = []
        try:
            for name in [*sorted(artifacts), "manifest.json"]:
                path = destination / name
                with path.open("xb") as stream:
                    created.append(path)
                    stream.write((stage / name).read_bytes())
        except BaseException:
            for path in reversed(created):
                path.unlink(missing_ok=True)
            try:
                destination.rmdir()
            except OSError:
                pass  # Never delete unrelated files placed in the folder by another actor.
            raise
    return manifest


def read_bundle(folder: Path) -> dict:
    folder = Path(folder)
    if folder.is_symlink() or not folder.is_dir():
        raise ValidationError("Bundle must be an existing non-symlink directory")
    manifest_path = folder / "manifest.json"
    if manifest_path.is_symlink():
        raise ValidationError("Bundle manifest must not be a symlink")
    try:
        with manifest_path.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
    except FileNotFoundError:
        raise ValidationError("Bundle is incomplete: no committed manifest") from None
    if len(raw) > 1024 * 1024:
        raise ValidationError("Bundle manifest exceeds 1 MiB")
    manifest = document(raw)
    validate_manifest(manifest)
    if {p.name for p in folder.iterdir()} != {*manifest["files"], "manifest.json"}:
        raise ValidationError("Bundle has missing or unindexed artifacts")
    payloads = {}
    for name, metadata in manifest["files"].items():
        path = folder / name
        if path.is_symlink() or not path.is_file():
            raise ValidationError("Bundle artifacts must be regular non-symlink files")
        with path.open("rb") as stream:
            data = stream.read(metadata["bytes"] + 1)
        if len(data) != metadata["bytes"] or digest(data) != metadata["sha256"]:
            raise ValidationError("Bundle artifact integrity check failed")
        if name.endswith(".json"):
            payloads[name] = document(data)
    validate_modules(payloads["modules.json"])
    # Regenerate the derived report: indexed assessment documents must agree with its content.
    from .audit_report import merge_reports

    inputs = [payloads["assessment.json"]]
    if "dependencies.json" in payloads:
        inputs.append(payloads["dependencies.json"])
    if merge_reports(inputs) != payloads["report.json"]:
        raise ValidationError("Bundle report does not match its assessment artifacts")
    if payloads["assessment.json"]["target"] != manifest["scope"]["target"]:
        raise ValidationError("Bundle assessment does not match target scope")
    return {"manifest": manifest, "documents": payloads}


def compare_bundles(previous: dict, current: dict) -> dict:
    old_manifest, new_manifest = previous["manifest"], current["manifest"]
    old, new = previous["documents"], current["documents"]
    reason = None
    if old_manifest["scope_digest"] != new_manifest["scope_digest"]:
        reason = "scope_or_options_changed"
    if any(
        m["status"] == "failed" for bundle in (old, new) for m in bundle["modules.json"].values()
    ):
        reason = "module_failure"
    if old["modules.json"] != new["modules.json"]:
        reason = reason or "module_coverage_changed"
    result = {
        "schema_version": 1,
        "previous_run_id": old_manifest["run_id"],
        "current_run_id": new_manifest["run_id"],
        "comparable": reason is None,
        "reason": reason,
        "new_observations": [],
        "no_longer_observed": [],
        "still_observed": [],
        "counts": None,
        "coverage_notices_changed": old["report.json"]["not_checked"]
        != new["report.json"]["not_checked"],
        "notice": "Exact observation comparison only. Disappearance is not proof of a fix; "
        "line changes, file limits, cache age and partial coverage can change results.",
    }
    if reason:
        return result
    before = {f["id"]: f for f in old["report.json"]["findings"]}
    after = {f["id"]: f for f in new["report.json"]["findings"]}
    result.update(
        new_observations=[after[k] for k in sorted(after.keys() - before.keys())],
        no_longer_observed=[before[k] for k in sorted(before.keys() - after.keys())],
        still_observed=[after[k] for k in sorted(before.keys() & after.keys())],
    )
    result["counts"] = {
        "new_observations": len(result["new_observations"]),
        "no_longer_observed": len(result["no_longer_observed"]),
        "still_observed": len(result["still_observed"]),
    }
    return result
