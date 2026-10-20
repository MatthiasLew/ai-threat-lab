"""Private, no-overwrite report bundles; manifest-last publication and bounded reads."""

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from .contracts import _nonfinite, _pairs, fields
from .dependency_paths import linked
from .models import ValidationError
from .report_io import read_regular

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
    try:
        return (json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
    except UnicodeError:
        raise ValidationError("Report JSON requires valid UTF-8 text") from None


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
        "read-only-pipeline-9",
        "read-only-pipeline-10",
        "read-only-pipeline-11",
        "read-only-pipeline-12",
        "read-only-pipeline-13",
        "read-only-pipeline-14",
        "read-only-pipeline-15",
        "read-only-pipeline-16",
        "read-only-pipeline-17",
        "read-only-pipeline-18",
        "read-only-pipeline-19",
        "read-only-pipeline-20",
        "read-only-pipeline-21",
        "read-only-pipeline-22",
        "read-only-pipeline-23",
        "read-only-pipeline-24",
        "read-only-pipeline-25",
        "read-only-pipeline-26",
        "read-only-pipeline-27",
        "read-only-pipeline-28",
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
            "read-only-pipeline-9",
            "read-only-pipeline-10",
            "read-only-pipeline-11",
            "read-only-pipeline-12",
            "read-only-pipeline-13",
            "read-only-pipeline-14",
            "read-only-pipeline-15",
            "read-only-pipeline-16",
            "read-only-pipeline-17",
            "read-only-pipeline-18",
            "read-only-pipeline-19",
            "read-only-pipeline-20",
            "read-only-pipeline-21",
            "read-only-pipeline-22",
            "read-only-pipeline-23",
            "read-only-pipeline-24",
            "read-only-pipeline-25",
            "read-only-pipeline-26",
            "read-only-pipeline-27",
            "read-only-pipeline-28",
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
                    created.append((path, os.fstat(stream.fileno())))
                    stream.write((stage / name).read_bytes())
        except BaseException:
            for path, identity in reversed(created):
                try:
                    if os.path.samestat(identity, path.stat(follow_symlinks=False)):
                        path.unlink()
                except FileNotFoundError:
                    pass
            try:
                destination.rmdir()
            except OSError:
                pass  # Never delete unrelated files placed in the folder by another actor.
            raise
    return manifest


def read_bundle(folder: Path) -> dict:
    folder = Path(folder)
    if linked(folder) or not folder.is_dir():
        raise ValidationError("Bundle must be an existing non-symlink directory")
    manifest_path = folder / "manifest.json"
    try:
        raw = read_regular(
            manifest_path, 1024 * 1024, limit_message="Bundle manifest exceeds 1 MiB"
        )
    except FileNotFoundError:
        raise ValidationError("Bundle is incomplete: no committed manifest") from None
    manifest = document(raw)
    validate_manifest(manifest)
    expected = {*manifest["files"], "manifest.json"}
    found = set()
    with os.scandir(folder) as entries:
        for entry in entries:
            if entry.name not in expected:
                raise ValidationError("Bundle has missing or unindexed artifacts")
            found.add(entry.name)
    if found != expected:
        raise ValidationError("Bundle has missing or unindexed artifacts")
    payloads, html_bytes = {}, None
    for name, metadata in manifest["files"].items():
        path = folder / name
        data = read_regular(path, metadata["bytes"])
        if name == "report.html":
            html_bytes = data
        if len(data) != metadata["bytes"] or digest(data) != metadata["sha256"]:
            raise ValidationError("Bundle artifact integrity check failed")
        if name.endswith(".json"):
            payloads[name] = document(data)
    validate_modules(payloads["modules.json"])
    # Regenerate the derived report: indexed assessment documents must agree with its content.
    from .audit_report import merge_reports, render_html

    inputs = [payloads["assessment.json"]]
    if "dependencies.json" in payloads:
        inputs.append(payloads["dependencies.json"])
    if json.dumps(merge_reports(inputs), sort_keys=True) != json.dumps(
        payloads["report.json"], sort_keys=True
    ):
        raise ValidationError("Bundle report does not match its assessment artifacts")
    try:
        expected_html = render_html(payloads["report.json"]).encode("utf-8")
    except UnicodeError:
        raise ValidationError("Report HTML requires valid UTF-8 text") from None
    if html_bytes != expected_html:
        raise ValidationError("Bundle HTML does not match its derived report")
    if (
        payloads["assessment.json"]["target"] != manifest["scope"]["target"]
        or payloads["assessment.json"]["target_kind"] != manifest["scope"]["target_kind"]
    ):
        raise ValidationError("Bundle assessment does not match target scope")
    if "dependencies.json" in payloads:
        dependencies = payloads["dependencies.json"]
        if (
            dependencies["target"] != manifest["scope"]["target"]
            or dependencies["target_kind"] != "dependency_manifest"
        ):
            raise ValidationError("Bundle dependency report does not match target scope")
    if "comparison.json" in payloads:
        validate_comparison(payloads["comparison.json"], manifest, payloads["report.json"])
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


def validate_comparison(value, manifest, report):
    """Validate current-side derivation; the previous bundle is not embedded here."""
    from .assessment import AssessmentFinding
    from .audit_report import PRIORITIES

    groups = ("new_observations", "no_longer_observed", "still_observed")
    fields(
        value,
        {
            "schema_version",
            "previous_run_id",
            "current_run_id",
            "comparable",
            "reason",
            *groups,
            "counts",
            "coverage_notices_changed",
            "notice",
        },
    )
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or type(value["comparable"]) is not bool
        or type(value["coverage_notices_changed"]) is not bool
        or value["current_run_id"] != manifest["run_id"]
        or not isinstance(value["previous_run_id"], str)
        or not re.fullmatch(r"[a-f0-9]{32}", value["previous_run_id"])
        or not isinstance(value["notice"], str)
        or not value["notice"]
    ):
        raise ValidationError("Invalid saved observation comparison")
    for key in groups:
        if not isinstance(value[key], list) or len(value[key]) > 40000:
            raise ValidationError("Invalid saved comparison observations")
    if not value["comparable"]:
        if (
            value["reason"]
            not in ("scope_or_options_changed", "module_failure", "module_coverage_changed")
            or value["counts"] is not None
            or any(value[key] for key in groups)
        ):
            raise ValidationError("Unavailable comparison cannot declare observation changes")
        return
    if value["reason"] is not None:
        raise ValidationError("Comparable observations cannot declare an unavailable reason")
    fields(value["counts"], set(groups))
    all_ids, current = set(), {item["id"]: item for item in report["findings"]}
    selected = {}
    for key in groups:
        if type(value["counts"][key]) is not int or value["counts"][key] != len(value[key]):
            raise ValidationError("Saved comparison counts do not match observations")
        selected[key] = set()
        for item in value[key]:
            fields(
                item,
                {
                    "id",
                    "target",
                    "check",
                    "status",
                    "evidence",
                    "recommendation",
                    "triage_priority",
                    "sources",
                },
            )
            finding = AssessmentFinding(
                **{k: item[k] for k in ("check", "status", "evidence", "recommendation")}
            )
            canonical = json.dumps(
                {
                    "target": item["target"],
                    **{
                        k: getattr(finding, k)
                        for k in ("check", "status", "evidence", "recommendation")
                    },
                },
                sort_keys=True,
            )
            if (
                not isinstance(item["target"], str)
                or not item["target"].strip()
                or item["id"] != hashlib.sha256(canonical.encode()).hexdigest()
                or item["id"] in all_ids
                or item["triage_priority"] != PRIORITIES.get(finding.check, "P3")
                or not isinstance(item["sources"], list)
                or not item["sources"]
                or any(type(n) is not int or not 1 <= n <= 20 for n in item["sources"])
                or len(set(item["sources"])) != len(item["sources"])
            ):
                raise ValidationError("Invalid saved comparison finding/provenance")
            all_ids.add(item["id"])
            selected[key].add(item["id"])
            if key != "no_longer_observed" and current.get(item["id"]) != item:
                raise ValidationError("Saved comparison differs from current observations")
    if selected["new_observations"] | selected["still_observed"] != set(current) or selected[
        "no_longer_observed"
    ] & set(current):
        raise ValidationError("Saved comparison does not cover current observations")
