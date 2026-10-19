"""Read-only bounded catalogs and regenerated exports of saved scan/batch results."""

import html
import os
from pathlib import Path

from .audit_report import render_html
from .batch_scan import check_batch
from .dependency_paths import linked
from .models import ValidationError
from .report_io import ReportReadLimit, report_read_budget
from .scan_bundle import read_bundle

MAX_ROOT_ENTRIES = 100
MAX_RUN_ENTRIES = 32
MAX_RUNS = 20
MAX_READ_BYTES = 128 * 1024 * 1024
MAX_EXPORT_BYTES = 8 * 1024 * 1024
MAX_CATALOG_BYTES = 4 * 1024 * 1024
ARTIFACT_NAMES = {
    "manifest.json",
    "batch.json",
    "assessment.json",
    "report.json",
    "report.html",
    "modules.json",
    "comparison.json",
    "dependency-inventory.json",
    "dependencies.json",
}
NOTICE = (
    "Read-only saved-result inventory; hashes establish local consistency, not authenticity, "
    "security completeness or verified fixes. No original targets, network or models are accessed. "
    "Directory-name order is not chronology; timestamps and targets are saved claims. "
    "Filesystem reads are not an atomic snapshot. Protect history/exports as sensitive data."
)


def bounded_entries(root, maximum):
    entries = []
    with os.scandir(root) as stream:
        for entry in stream:
            if len(entries) >= maximum:
                raise ValidationError("Local history directory entry limit exceeded")
            try:
                entry.name.encode("utf-8")
            except UnicodeError:
                raise ValidationError("History directory names require valid UTF-8 text") from None
            entries.append(entry)
    return sorted(entries, key=lambda item: item.name)


def load_saved_run(path):
    root = Path(path)
    if linked(root) or not root.is_dir():
        raise ValidationError("Saved run must be an existing directory without links/junctions")
    batch, scan = (root / "batch.json").exists(), (root / "manifest.json").exists()
    if batch and scan:
        raise ValidationError("Saved run cannot declare both scan and batch markers")
    if batch:
        verified = check_batch(root, include_report=True)
        summary = verified["assessment_summary"]
        return {
            "kind": "batch",
            "report": verified["report"],
            "run_id": None,
            "created_at": None,
            "target_count": summary["target_count"],
            "failed_components": summary["failed_runs"],
            "comparison": None,
        }
    bundle = read_bundle(root)
    documents, manifest = bundle["documents"], bundle["manifest"]
    comparison = documents.get("comparison.json")
    return {
        "kind": "scan",
        "report": documents["report.json"],
        "run_id": manifest["run_id"],
        "created_at": manifest["created_at"],
        "target_count": 1,
        "failed_components": sorted(
            k for k, v in documents["modules.json"].items() if v["status"] == "failed"
        ),
        "comparison": {
            k: comparison[k] for k in ("previous_run_id", "comparable", "reason", "counts")
        }
        if comparison is not None
        else None,
    }


def history_list(path):
    root = Path(path)
    if linked(root) or not root.is_dir():
        raise ValidationError("History root must be an existing directory without links/junctions")
    try:
        str(root).encode("utf-8")
    except UnicodeError:
        raise ValidationError("History root requires valid UTF-8 text") from None
    entries = bounded_entries(root, MAX_ROOT_ENTRIES)
    if {entry.name for entry in entries} & {"manifest.json", "batch.json"}:
        raise ValidationError("Select a parent history directory, not an individual saved run")
    rows, ignored_files, ignored_directories = [], 0, 0
    with report_read_budget(MAX_READ_BYTES):
        for entry in entries:
            folder = Path(entry.path)
            if linked(folder):
                row = {
                    "directory": entry.name,
                    "kind": "unknown",
                    "verification": "invalid",
                    "reason": "linked_entry_rejected",
                }
            elif not entry.is_dir(follow_symlinks=False):
                ignored_files += 1
                continue
            else:
                try:
                    names = {item.name for item in bounded_entries(folder, MAX_RUN_ENTRIES)}
                    if not names & ARTIFACT_NAMES:
                        ignored_directories += 1
                        continue
                    saved = load_saved_run(folder)
                    report = saved.pop("report")
                    row = {
                        "directory": entry.name,
                        "verification": "verified",
                        **saved,
                        "unique_findings": report["summary"]["unique_findings"],
                        "targets": list(dict.fromkeys(s["target"] for s in report["assessments"])),
                    }
                except ReportReadLimit:
                    raise
                except (ValidationError, OSError):
                    row = {
                        "directory": entry.name,
                        "kind": "unknown",
                        "verification": "invalid",
                        "reason": "saved_result_invalid_or_unreadable",
                    }
            if len(rows) >= MAX_RUNS:
                raise ValidationError("History run limit exceeded; select a narrower directory")
            rows.append(row)
    return {
        "schema_version": 1,
        "mode": "local_report_history",
        "root": str(root.resolve()),
        "runs": rows,
        "verified_runs": sum(r["verification"] == "verified" for r in rows),
        "invalid_runs": sum(r["verification"] == "invalid" for r in rows),
        "ignored_files": ignored_files,
        "ignored_directories": ignored_directories,
        "network_called": False,
        "ai_calls": 0,
        "notice": NOTICE,
    }


def render_history(value):
    def escape(item):
        return html.escape(str(item), quote=True)

    rows = []
    for run in value["runs"]:
        rows.append(
            "<tr>"
            + "".join(
                f"<td>{escape(cell)}</td>"
                for cell in (
                    run["directory"],
                    run["verification"],
                    run["kind"],
                    run.get("created_at") or "Not recorded",
                    "; ".join(run.get("targets", [])),
                    run.get("unique_findings", "Not established"),
                    ", ".join(run.get("failed_components", [])),
                    run.get("reason", ""),
                )
            )
            + "</tr>"
        )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        "<title>AI Threat Lab — local history</title>"
        "<style>body{font:16px system-ui;margin:2rem}table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #cad4dc;padding:.6rem;text-align:left;overflow-wrap:anywhere}"
        ".scroll{overflow-x:auto}</style><h1>Local report history</h1><p>"
        + escape(value["notice"])
        + "</p><p>Verified: "
        + escape(value["verified_runs"])
        + "; invalid: "
        + escape(value["invalid_runs"])
        + "; ignored files: "
        + escape(value["ignored_files"])
        + "; ignored directories: "
        + escape(value["ignored_directories"])
        + '</p><div class="scroll"><table><thead><tr><th>Directory</th><th>Verification</th>'
        "<th>Kind</th><th>Saved time</th><th>Targets</th><th>Observations</th>"
        "<th>Failed components</th><th>Reason</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div></html>"
    )


def export_report(path, *, format="json", output=None):
    root = Path(path)
    if format not in ("json", "html"):
        raise ValidationError("Saved report export supports JSON or HTML")
    if output is not None and Path(output).resolve().is_relative_to(root.resolve()):
        raise ValidationError("Export must stay outside the saved run")
    saved = load_saved_run(root)
    from .scan_bundle import encoded

    raw = encoded(saved["report"]) if format == "json" else render_html(saved["report"]).encode()
    if len(raw) > MAX_EXPORT_BYTES:
        raise ValidationError("Saved report export exceeds its 8 MiB byte limit")
    if output is not None:
        write_new_report(output, raw)
    return raw.decode("utf-8")


def write_new_report(output, raw):
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    identity = os.fstat(descriptor)
    success = False
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(raw)
        success = True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if not success:
            try:
                if os.path.samestat(identity, Path(output).stat(follow_symlinks=False)):
                    Path(output).unlink()
            except FileNotFoundError:
                pass
