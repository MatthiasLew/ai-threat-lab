"""Sequential offline local batches with verified child bundles and a final index."""

import hashlib
import os
import re
from pathlib import Path

from .assessment import identify_target
from .audit_report import merge_reports, render_html
from .contracts import fields, version
from .dependency_paths import linked
from .exercise_export import claim_directory
from .local_inventory import local_inventory
from .models import ValidationError
from .scan_bundle import document, encoded, read_bundle
from .scan_engine import ScanOptions, ScanService

MAX_TARGETS = 10
MAX_CHILD_BYTES = 64 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
LOCAL_KINDS = {"local_project", "python_source", "mail_message", "program_file", "html_document"}
NOTICE = (
    "Bounded local checks only; no network, account access or model calls. "
    "Hashes verify consistency, not authenticity or security completeness."
)


def _read(path, limit):
    if linked(path) or not path.is_file():
        raise ValidationError("Batch artifact must be a regular file without links")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValidationError("Batch artifact exceeds its byte limit")
    return raw


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _preflight(targets, output, recursive):
    if type(recursive) is not bool:
        raise ValidationError("Recursive dependency selection must be boolean")
    if not isinstance(targets, (list, tuple)) or not 1 <= len(targets) <= MAX_TARGETS:
        raise ValidationError("Select between 1 and 10 local batch targets")
    selected = []
    destination = Path(output).resolve()
    for target in targets:
        if (
            not isinstance(target, str)
            or not target.strip()
            or any(ord(c) < 32 or ord(c) == 127 for c in target)
        ):
            raise ValidationError("Batch targets must be non-empty local path strings")
        kind = identify_target(target)
        if kind not in LOCAL_KINDS:
            raise ValidationError(
                "Batch scanning accepts local paths only; remote targets rejected"
            )
        source = Path(target)
        if linked(source) or (not source.is_file() and not source.is_dir()):
            raise ValidationError("Batch target must be a regular file or directory without links")
        source = source.resolve(strict=True)
        if source in selected or any(
            (prior.is_dir() and source.is_relative_to(prior))
            or (source.is_dir() and prior.is_relative_to(source))
            for prior in selected
        ):
            raise ValidationError("Batch targets must be distinct and must not overlap")
        if source.is_dir() and destination.is_relative_to(source):
            raise ValidationError("Batch output must stay outside every scanned project")
        selected.append(source)
    return selected


def _derive(root, entries, recursive):
    reports, failed, total = [], [], 0
    for entry in entries:
        folder = root / entry["directory"]
        child = read_bundle(folder)
        raw_manifest = _read(folder / "manifest.json", 1024 * 1024)
        if _hash(raw_manifest) != entry["manifest_sha256"]:
            raise ValidationError("Batch child manifest digest mismatch")
        manifest = child["manifest"]
        total += len(raw_manifest) + sum(item["bytes"] for item in manifest["files"].values())
        if total > MAX_CHILD_BYTES:
            raise ValidationError("Batch child artifacts exceed the 64 MiB aggregate limit")
        scope = manifest["scope"]
        if (
            scope["target"] != entry["target"]
            or scope["target_kind"] not in LOCAL_KINDS
            or scope["network"]
            or scope["share_packages"]
            or scope["allowed_hosts"]
            or scope.get("recursive_dependencies")
            != (recursive if scope["target_kind"] == "local_project" else False)
        ):
            raise ValidationError(
                "Batch child scope mismatch; only local offline scope is accepted"
            )
        docs = child["documents"]
        reports.append(docs["assessment.json"])
        if "dependencies.json" in docs:
            reports.append(docs["dependencies.json"])
        if any(row["status"] == "failed" for row in docs["modules.json"].values()):
            failed.append(entry["directory"])
    report = merge_reports(reports)
    summary = {
        "mode": "offline_local_batch",
        "target_count": len(entries),
        "status": "partial_with_module_failures" if failed else "partial",
        "failed_runs": failed,
        "unique_findings": report["summary"]["unique_findings"],
        "network_called": False,
        "ai_calls": 0,
        "notice": NOTICE,
    }
    return report, summary


def run_batch(targets, output, *, recursive_dependencies=False, service=None):
    selected = _preflight(targets, output, recursive_dependencies)
    root = claim_directory(output)
    service = service or ScanService(lambda options: local_inventory(options.target))
    entries, total_bytes = [], 0
    for index, target in enumerate(selected, 1):
        directory = f"run-{index:02}"
        service.run(
            ScanOptions(
                str(target),
                recursive_dependencies=(recursive_dependencies if target.is_dir() else False),
            ),
            root / directory,
        )
        entries.append(
            {
                "directory": directory,
                "target": str(target),
                "manifest_sha256": _hash(_read(root / directory / "manifest.json", 1024 * 1024)),
            }
        )
        # Bound already-published child bytes before starting another target.
        raw_manifest = _read(root / directory / "manifest.json", 1024 * 1024)
        total_bytes += len(raw_manifest) + sum(
            item["bytes"] for item in document(raw_manifest)["files"].values()
        )
        if total_bytes > MAX_CHILD_BYTES:
            raise ValidationError("Batch child artifacts exceed the 64 MiB aggregate limit")
    report, summary = _derive(root, entries, recursive_dependencies)
    artifacts = {"report.json": encoded(report), "report.html": render_html(report).encode()}
    if any(len(raw) > MAX_REPORT_BYTES for raw in artifacts.values()):
        raise ValidationError("Combined batch report exceeds the 8 MiB artifact limit")
    for name, raw in artifacts.items():
        with (root / name).open("xb") as stream:
            stream.write(raw)
    marker = {
        "schema_version": 1,
        "mode": "offline_local_batch",
        "recursive_dependencies": recursive_dependencies,
        "runs": entries,
        "summary": summary,
        "files": {
            name: {"bytes": len(raw), "sha256": _hash(raw)} for name, raw in artifacts.items()
        },
    }
    with (root / "batch.json").open("xb") as stream:
        stream.write(encoded(marker))
    return {**summary, "output_directory": str(root.resolve())}


def check_batch(path):
    root = Path(path)
    if linked(root) or not root.is_dir():
        raise ValidationError("Batch must be a directory without links")
    marker = document(_read(root / "batch.json", 1024 * 1024))
    fields(marker, {"schema_version", "mode", "recursive_dependencies", "runs", "summary", "files"})
    version(marker)
    if (
        marker["mode"] != "offline_local_batch"
        or type(marker["recursive_dependencies"]) is not bool
    ):
        raise ValidationError("Invalid batch mode/options")
    entries = marker["runs"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_TARGETS:
        raise ValidationError("Invalid batch target count")
    targets = set()
    for index, entry in enumerate(entries, 1):
        fields(entry, {"directory", "target", "manifest_sha256"})
        if (
            entry["directory"] != f"run-{index:02}"
            or not isinstance(entry["target"], str)
            or not entry["target"]
            or entry["target"] in targets
            or not isinstance(entry["manifest_sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", entry["manifest_sha256"])
        ):
            raise ValidationError("Invalid batch child index")
        targets.add(entry["target"])
    fields(marker["files"], {"report.json", "report.html"})
    expected = {"batch.json", *marker["files"], *(e["directory"] for e in entries)}
    with os.scandir(root) as stream:
        for item in stream:
            if item.name not in expected:
                raise ValidationError("Batch contains an unindexed entry")
    report, summary = _derive(root, entries, marker["recursive_dependencies"])
    expected_content = {"report.json": encoded(report), "report.html": render_html(report).encode()}
    for name, metadata in marker["files"].items():
        fields(metadata, {"bytes", "sha256"})
        raw = _read(root / name, MAX_REPORT_BYTES)
        if (
            type(metadata["bytes"]) is not int
            or metadata["bytes"] != len(raw)
            or metadata["sha256"] != _hash(raw)
            or raw != expected_content[name]
        ):
            raise ValidationError("Batch report integrity or derivation mismatch")
    if marker["summary"] != summary or any(
        type(marker["summary"][key]) is not type(value) for key, value in summary.items()
    ):
        raise ValidationError("Batch summary does not match child evidence")
    return {"status": "integrity_verified", "assessment_summary": summary}
