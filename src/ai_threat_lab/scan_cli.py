"""CLI workflows for read-only scans, committed artifacts and observation comparison."""

from pathlib import Path
from types import SimpleNamespace

from .assessment import identify_target
from .batch_scan import check_batch, run_batch
from .contracts import write_document
from .dependencies import AdvisoryCache, OSVAudit
from .http_client import PublicHTTPS
from .integration_cli import audit_target
from .local_history import (
    MAX_CATALOG_BYTES,
    export_report,
    history_list,
    render_history,
    write_new_report,
)
from .models import ValidationError
from .remote_audit import GithubAudit
from .scan_bundle import compare_bundles, read_bundle
from .scan_engine import ScanOptions, ScanService

COMMANDS = {
    "scan",
    "scan-check",
    "scan-compare",
    "scan-batch",
    "batch-check",
    "history-list",
    "report-export",
}


def add_commands(commands):
    history = commands.add_parser("history-list", help="Verify a bounded local saved-run catalog")
    history.add_argument("root", type=Path)
    history.add_argument("--format", choices=("json", "html"), default="json")
    history.add_argument("--output", type=Path)
    export = commands.add_parser(
        "report-export", help="Export a verified saved report without scanning"
    )
    export.add_argument("run", type=Path)
    export.add_argument("--format", choices=("json", "html"), default="json")
    export.add_argument("--output", type=Path)

    batch = commands.add_parser("scan-batch", help="Scan 1..10 distinct local targets offline")
    batch.add_argument("targets", nargs="+")
    batch.add_argument("--output-dir", type=Path, required=True)
    batch.add_argument("--recursive-dependencies", action="store_true")
    batch.add_argument("--fail-on-findings", action="store_true")
    batch_check = commands.add_parser(
        "batch-check", help="Verify an offline batch and child bundles"
    )
    batch_check.add_argument("batch", type=Path)
    batch_check.add_argument("--output", type=Path)
    scan = commands.add_parser(
        "scan", help="Run applicable read-only collectors and publish a report bundle"
    )
    scan.add_argument("target")
    scan.add_argument(
        "--output-dir", type=Path, required=True, help="New directory; never overwrite"
    )
    scan.add_argument(
        "--baseline", type=Path, help="Integrity-checked prior bundle of the same target"
    )
    scan.add_argument("--network", action="store_true")
    scan.add_argument("--allow-host", action="append", default=[])
    scan.add_argument("--max-files", type=int, default=50)
    scan.add_argument(
        "--recursive-dependencies",
        action="store_true",
        help="Discover supported nested manifests within fixed bounds",
    )
    scan.add_argument("--dkim-selector")
    scan.add_argument(
        "--share-packages",
        action="store_true",
        help="Share exact local/GitHub package versions with OSV",
    )
    scan.add_argument("--advisory-cache", type=Path)
    scan.add_argument("--max-pages", type=int, default=10)
    scan.add_argument("--fail-on-findings", action="store_true")
    check = commands.add_parser(
        "scan-check", help="Verify bundle integrity and derived report consistency"
    )
    check.add_argument("bundle", type=Path)
    compare = commands.add_parser(
        "scan-compare", help="Compare observations from two verified bundles"
    )
    compare.add_argument("previous", type=Path)
    compare.add_argument("current", type=Path)
    for command in (check, compare):
        command.add_argument("--output", type=Path, help="New JSON file; never overwrite")


def assessor(options):
    if identify_target(options.target) == "github_repository":
        client = PublicHTTPS(["api.github.com"], max_bytes=8 * 1024 * 1024)
        return GithubAudit(client, max_files=options.max_files).collect(
            options.target,
            include_dependencies=True,
            recursive_dependencies=options.recursive_dependencies,
        )
    return audit_target(
        SimpleNamespace(
            target=options.target,
            network=options.network,
            allow_host=options.allowed_hosts,
            max_files=options.max_files,
            dkim_selector=options.dkim_selector,
        )
    )


def advisory_lookup(collected, options):
    client = PublicHTTPS(["api.osv.dev"], max_requests=20, max_bytes=2 * 1024 * 1024)
    cache = AdvisoryCache(options.advisory_cache) if options.advisory_cache else None
    return OSVAudit(client, cache=cache, max_pages=options.max_pages).assess(collected)


def run_command(args):
    code = 0
    if args.command == "report-export":
        content = export_report(args.run, format=args.format, output=args.output)
        print(
            f"Report saved: {args.output}" if args.output else content,
            end="\n" if args.output else "",
        )
        return 0
    if args.command == "history-list":
        # A catalog may be saved at its root, but never inside one of its saved runs.
        if args.output is not None:
            relative = (
                args.output.resolve().relative_to(args.root.resolve())
                if (args.output.resolve().is_relative_to(args.root.resolve()))
                else None
            )
            if relative is not None and len(relative.parts) > 1:
                raise ValidationError("History output must stay outside saved run directories")
        payload = history_list(args.root)
        content = render_history(payload) if args.format == "html" else write_document(payload)
        if len(content.encode("utf-8")) > MAX_CATALOG_BYTES:
            raise ValidationError("History catalog exceeds its 4 MiB output limit")
        if args.output:
            write_new_report(args.output, content.encode("utf-8"))
            print(f"Report saved: {args.output}")
        else:
            print(content, end="")
        return 2 if payload["invalid_runs"] else 0
    if args.command == "scan-batch":
        payload = run_batch(
            args.targets, args.output_dir, recursive_dependencies=args.recursive_dependencies
        )
        print(write_document(payload), end="")
        return (
            3
            if payload["failed_runs"]
            else (1 if args.fail_on_findings and payload["unique_findings"] else 0)
        )
    if args.command == "batch-check":
        print(write_document(check_batch(args.batch), args.output), end="")
        return 0
    if args.command == "scan":
        options = ScanOptions(
            args.target,
            args.network,
            tuple(args.allow_host),
            args.max_files,
            args.dkim_selector,
            args.share_packages,
            args.max_pages,
            args.advisory_cache,
            args.recursive_dependencies,
        )
        payload = ScanService(assessor, advisory_lookup=advisory_lookup).run(
            options, args.output_dir, baseline=args.baseline
        )
        code = (
            3
            if payload["failed_modules"]
            else (1 if args.fail_on_findings and payload["unique_findings"] else 0)
        )
        print(write_document(payload), end="")
        return code
    if args.command == "scan-check":
        bundle = read_bundle(args.bundle)
        payload = {
            "status": "integrity_verified",
            "run_id": bundle["manifest"]["run_id"],
            "assessment_status": "partial",
            "modules": bundle["documents"]["modules.json"],
            "notice": "Hashes check local consistency, not authenticity or security completeness.",
        }
    else:
        payload = compare_bundles(read_bundle(args.previous), read_bundle(args.current))
        code = 0 if payload["comparable"] else 2
    text = write_document(payload, args.output)
    print(f"Report saved: {args.output}" if args.output else text, end="\n" if args.output else "")
    return code
