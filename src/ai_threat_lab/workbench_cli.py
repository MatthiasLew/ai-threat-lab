"""Console entry points joining prepared tools, saved evidence and AI previews."""

import json
import os
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path

from .ai_costs import INSTRUCTIONS, AIConfig, compact_evidence, usd
from .ai_review import REVIEW_INSTRUCTIONS, TEXT_FORMAT
from .attachment_review import review_attachments
from .contracts import read_document, write_document
from .evidence import brief, evidence_digest, load_evidence
from .har_review import review_har
from .local_history import write_new_report
from .models import ValidationError
from .office_review import review_office
from .review_packets import review_packets, select_packet
from .sarif_review import review_sarif
from .scan_cli import advisory_lookup, assessor
from .scan_engine import ScanOptions, ScanService
from .setup_check import setup_check
from .site_review import SiteReview, canonical_url
from .tool_plan import plan_target

COMMANDS = {"brief", "ai-prepare", "plan", "inspect", "setup-check", "review-site", "review-har",
            "review-attachments", "review-sarif", "review-office"}


def add_commands(commands):
    office = commands.add_parser(
        "review-office", help="Inspect saved Office package declarations without opening content")
    office.add_argument("path", type=Path)
    office.add_argument("--output", type=Path)
    office.add_argument("--fail-on-findings", action="store_true")
    sarif = commands.add_parser(
        "review-sarif", help="Import saved external static-analysis claims without executing tools")
    sarif.add_argument("path", type=Path)
    sarif.add_argument("--start", type=int, default=1)
    sarif.add_argument("--max-entries", type=int, default=200)
    sarif.add_argument("--output", type=Path)
    sarif.add_argument("--fail-on-findings", action="store_true")
    attachments = commands.add_parser(
        "review-attachments", help="Review decoded saved-email attachment structures in memory")
    attachments.add_argument("path", type=Path)
    attachments.add_argument("--start", type=int, default=1)
    attachments.add_argument("--max-entries", type=int, default=20)
    attachments.add_argument("--output", type=Path)
    attachments.add_argument("--fail-on-findings", action="store_true")
    har = commands.add_parser("review-har", help="Review saved browser responses without replay")
    har.add_argument("path", type=Path)
    har.add_argument("--start", type=int, default=1)
    har.add_argument("--max-entries", type=int, default=20)
    har.add_argument("--output", type=Path)
    har.add_argument("--fail-on-findings", action="store_true")
    site = commands.add_parser("review-site", help="Bounded passive same-host page navigation")
    site.add_argument("target")
    site.add_argument("--network", action="store_true")
    site.add_argument("--allow-host", action="append", default=[])
    site.add_argument("--path-prefix", default="/")
    site.add_argument("--session-file", type=Path,
                      help="Explicit host/path/expiry-bound Authorization/Cookie JSON")
    site.add_argument("--private-path-map", type=Path,
                      help="Separate private session-page URL index; never sent as AI evidence")
    site.add_argument("--max-pages", type=int, default=10)
    site.add_argument("--max-depth", type=int, default=2)
    site.add_argument("--output", type=Path)
    site.add_argument("--fail-on-findings", action="store_true")
    setup = commands.add_parser("setup-check", help="Validate local setup without inspecting keys")
    setup.add_argument("--ai-config", type=Path)
    setup.add_argument("--smtp-config", type=Path)
    setup.add_argument("--speech-config", type=Path)
    setup.add_argument("--avatar-config", type=Path)
    setup.add_argument("--output", type=Path)
    plan = commands.add_parser("plan", help="Preview prepared tools, scope and data disclosures")
    inspect = commands.add_parser(
        "inspect", help="Scan with prepared tools and read a local summary"
    )
    for parser in (plan, inspect):
        parser.add_argument("target")
        parser.add_argument("--network", action="store_true")
        parser.add_argument("--allow-host", action="append", default=[])
        parser.add_argument("--max-files", type=int, default=50)
        parser.add_argument("--recursive-dependencies", action="store_true")
        parser.add_argument("--share-packages", action="store_true")
        parser.add_argument("--dkim-selector")
        parser.add_argument("--max-pages", type=int, default=10)
    plan.add_argument("--output", type=Path)
    inspect.add_argument("--output-dir", type=Path, required=True)
    inspect.add_argument("--baseline", type=Path)
    inspect.add_argument("--advisory-cache", type=Path)
    inspect.add_argument("--format", choices=("txt", "json"), default="txt")
    inspect.add_argument("--fail-on-findings", action="store_true")
    summary = commands.add_parser("brief", help="Explain saved observations locally without AI")
    summary.add_argument(
        "evidence", type=Path, help="Assessment/report JSON or scan/batch directory"
    )
    summary.add_argument("--format", choices=("txt", "json"), default="txt")
    summary.add_argument("--output", type=Path)
    prepare = commands.add_parser(
        "ai-prepare", help="Preview exact minimized evidence and cost without API or ledger writes"
    )
    prepare.add_argument("evidence", type=Path)
    prepare.add_argument("--ai-config", type=Path, required=True)
    prepare.add_argument("--structured", action="store_true", help="Preview the ai-review request")
    prepare.add_argument("--split", action="store_true", help="Preview every structured packet")
    prepare.add_argument("--packet-index", type=int)
    prepare.add_argument("--group-size", type=int, default=3)
    prepare.add_argument("--output", type=Path)


def prepare_evidence(path, config, *, structured=False, split=False,
                     packet_index=None, group_size=3):
    value = load_evidence(path)
    if (split or packet_index is not None or group_size != 3) and not structured:
        raise ValidationError("Packet options require --structured")
    if split and packet_index is not None:
        raise ValidationError("Choose --split or --packet-index, not both")
    if structured and split:
        groups = review_packets(value["report"], config.max_input_bytes, group_size=group_size)
        previews = [_preview(value, config, evidence, structured=True) for evidence in groups]
        for index, item in enumerate(previews, 1):
            item.update(packet_index=index, packet_count=len(previews))
        reserved = sum(int(item["reserved_usd"].replace(".", "")) for item in previews)
        return {
            "schema_version": 1, "mode": "structured_review_packets", "network_called": False,
            "packet_count": len(previews), "total_finding_count": len(value["report"]["findings"]),
            "maximum_reserved_usd": usd(reserved), "packets": previews,
            "notice": "No requests were sent. Each packet preserves all limitations. "
                      "Review packets and request one explicitly with ai-review --packet-index. "
                      "Daily budget/request limits and current ledger state apply to each call.",
        }
    if structured:
        evidence, index, count = select_packet(value["report"], config.max_input_bytes,
                                              packet_index=packet_index, group_size=group_size)
        return {**_preview(value, config, evidence, structured=True),
                "packet_index": index, "packet_count": count}
    return _preview(value, config, value["ai_document"], structured=False)


def _preview(value, config, evidence, *, structured):
    instructions = REVIEW_INSTRUCTIONS if structured else INSTRUCTIONS
    overhead = len(json.dumps({"text": {"format": TEXT_FORMAT}}).encode()) if structured else 0
    prompt = compact_evidence(evidence, config.max_input_bytes)
    bound = len((instructions + prompt).encode("utf-8")) + overhead + 1024
    count = len(json.loads(prompt)["findings"])
    return {
        "schema_version": 1, "status": "prepared" if count else "skipped_no_findings",
        "origin": value["origin"], "failed_components": value["failed_components"],
        "network_called": False, "credentials_inspected": False, "ledger_written": False,
        "model": config.model, "evidence_sha256": evidence_digest(json.loads(prompt)),
        "finding_count": count, "input_bytes": len(prompt.encode("utf-8")),
        "input_token_planning_bound": bound if count else 0,
        "max_output_tokens": config.max_output_tokens if count else 0,
        "reserved_usd": usd(config.charge(bound, config.max_output_tokens)) if count else usd(0),
        "instructions": instructions, "input": json.loads(prompt), "input_text": prompt,
        "text_format": TEXT_FORMAT if structured else None,
        "notice": "Preview only. Review every evidence string before sharing. Target fields are "
                  "omitted, but evidence may contain sensitive data. Prices are configured claims; "
                  "the estimate is not provider billing. "
                  "AI cannot execute tools or change evidence.",
    }


def run_command(args):
    if args.command == "review-office":
        result, failures = review_office(args.path)
        text = write_document(asdict(result))
        if args.output:
            write_new_report(args.output, text.encode("utf-8"))
            print(f"Report saved: {args.output}")
        else:
            print(text, end="")
        candidates = any(item.status == "candidate" for item in result.findings)
        return 2 if failures else 1 if args.fail_on_findings and candidates else 0
    if args.command in ("review-har", "review-attachments", "review-sarif"):
        review = {"review-har": review_har, "review-attachments": review_attachments,
                  "review-sarif": review_sarif}[args.command]
        report, failures = review(args.path, start=args.start, max_entries=args.max_entries)
        text = write_document(report)
        if args.output:
            write_new_report(args.output, text.encode("utf-8"))
            print(f"Report saved: {args.output}")
        else:
            print(text, end="")
        return 2 if failures else 1 if args.fail_on_findings and report["findings"] else 0
    if args.command == "review-site":
        from urllib.parse import urlsplit

        from .http_client import PublicHTTPS

        target = canonical_url(args.target)
        host = urlsplit(target).hostname
        if not args.network or host not in [h.lower() for h in args.allow_host]:
            raise ValidationError("Site navigation requires --network and exact --allow-host")
        if args.output and (args.output.exists() or args.output.is_symlink()):
            raise ValidationError("Output already exists")
        client = PublicHTTPS([host], max_bytes=256 * 1024, max_requests=20,
                             allow_partial_body=True)
        session_file = getattr(args, "session_file", None)
        private_map = getattr(args, "private_path_map", None)
        if private_map is not None and (
            session_file is None or (args.output and private_map.resolve() == args.output.resolve())
        ):
            raise ValidationError("Private path map requires a session and a separate output file")
        if session_file is not None:
            from .session_http import ScopedSession

            client = ScopedSession.from_file(session_file, client, target=target,
                                             path_prefix=args.path_prefix)
        review = SiteReview(
            client, session_supplied=session_file is not None,
            max_pages=args.max_pages, max_depth=args.max_depth,
        )
        with ExitStack() as stack:
            mapping = None
            if private_map is not None:
                descriptor = os.open(private_map, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                mapping = stack.enter_context(os.fdopen(descriptor, "w", encoding="utf-8"))
            report, failures = review.run(target, path_prefix=args.path_prefix)
            if mapping is not None:
                mapping.write(write_document({
                    "schema_version": 1, "mode": "private_session_path_map",
                    "paths": review.private_paths,
                    "notice": "Private local URL index; paths can contain sensitive data. "
                              "Not an assessment and not accepted as AI evidence.",
                }))
        text = write_document(report)
        if args.output:
            write_new_report(args.output, text.encode("utf-8"))
            print(f"Report saved: {args.output}")
        else:
            print(text, end="")
        if private_map is not None and args.output:
            print(f"Private page map saved separately: {private_map}")
        return 2 if failures else 1 if args.fail_on_findings and report["findings"] else 0
    if args.command == "setup-check":
        text = write_document(setup_check(
            args.ai_config, smtp_path=args.smtp_config, speech_path=args.speech_config,
            avatar_path=args.avatar_config))
    elif args.command in ("plan", "inspect"):
        options = dict(
            network=args.network, allowed_hosts=args.allow_host, max_files=args.max_files,
            recursive_dependencies=args.recursive_dependencies, share_packages=args.share_packages,
            dkim_selector=args.dkim_selector, max_pages=args.max_pages,
        )
        if args.command == "plan":
            text = write_document(plan_target(args.target, **options))
        else:
            result = ScanService(assessor, advisory_lookup=advisory_lookup).run(
                ScanOptions(args.target, **options, advisory_cache=args.advisory_cache),
                args.output_dir, baseline=args.baseline,
            )
            text = (write_document(result) if args.format == "json" else
                    brief(load_evidence(args.output_dir)) + f"\nSaved run: {args.output_dir}\n")
            print(text, end="")
            return (2 if result["failed_modules"] else
                    1 if args.fail_on_findings and result["unique_findings"] else 0)
    elif args.command == "brief":
        value = load_evidence(args.evidence)
        # ai_document is an internal projection, not another user-visible source of truth.
        value.pop("ai_document")
        text = brief(value) if args.format == "txt" else write_document(value)
    else:
        config = AIConfig.from_document(read_document(args.ai_config))
        text = write_document(prepare_evidence(
            args.evidence, config, structured=args.structured, split=args.split,
            packet_index=args.packet_index, group_size=args.group_size,
        ))
        if len(text.encode("utf-8")) > 32 * 1024 * 1024:
            raise ValidationError("Preview exceeds 32 MiB; narrow the assessment scope")
    if args.output:
        write_new_report(args.output, text.encode("utf-8"))
        print(f"Report saved: {args.output}")
    else:
        print(text, end="")
    return 0
