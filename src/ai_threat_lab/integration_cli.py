"""Explicit opt-in network assessment and AI cost workflow commands."""

import os
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

from .ai_costs import AIConfig, BudgetedAI, CostLedger, OpenAIResponses, compact_evidence
from .ai_review import review_result
from .assessment import identify_target
from .audit_report import merge_reports, render_html
from .auth_log_review import AuthPolicy, review_auth_log_file
from .contracts import read_document, write_document
from .dependencies import AdvisoryCache, OSVAudit, inventory
from .evidence import load_evidence
from .header_review import audit_header_capture
from .html_review import review_html_file
from .http_client import PublicHTTPS
from .kubernetes_review import review_kubernetes_file
from .local_inventory import local_inventory
from .models import ValidationError
from .providers import ProviderError
from .remote_audit import GithubAudit, GmailAudit, MailDomainAudit, WebsiteAudit
from .ssh_journal_review import review_ssh_journal_file

COMMANDS = {
    "audit",
    "audit-deps",
    "audit-report",
    "review-headers",
    "review-html",
    "review-auth-log",
    "review-ssh-journal",
    "review-kubernetes",
    "ai-explain",
    "ai-review",
    "api-costs",
    "api-reconcile",
    "api-cache-prune",
}


def add_commands(commands):
    headers = commands.add_parser(
        "review-headers", help="Review a saved HTTPS header capture offline"
    )
    kubernetes = commands.add_parser(
        "review-kubernetes", help="Review selected Kubernetes JSON fields without a cluster"
    )
    html = commands.add_parser(
        "review-html", help="Review saved HTML without rendering or requests"
    )
    html.add_argument("--document-url", help="Declared HTTP(S) context; never fetched")
    auth = commands.add_parser(
        "review-auth-log", help="Review normalized saved login events without login attempts"
    )
    ssh = commands.add_parser(
        "review-ssh-journal", help="Review a saved single-host OpenSSH journal JSONL export"
    )
    for auth_review in (auth, ssh):
        auth_review.add_argument("--window-seconds", type=int, default=300)
        auth_review.add_argument("--min-failures", type=int, default=5)
        auth_review.add_argument("--min-accounts", type=int, default=5)
        auth_review.add_argument("--min-sources", type=int, default=3)
    for review in (headers, kubernetes, html, auth, ssh):
        review.add_argument("path", type=Path)
        review.add_argument("--format", choices=("json", "html"), default="json")
        review.add_argument("--fail-on-findings", action="store_true")
    audit = commands.add_parser(
        "audit", help="Bounded local inventory or opted-in read-only remote audit"
    )
    audit.add_argument("target")
    audit.add_argument(
        "--network", action="store_true", help="Explicitly permit remote read-only requests"
    )
    audit.add_argument(
        "--allow-host", action="append", default=[], help="Exact hostname approved for this audit"
    )
    audit.add_argument("--dkim-selector", help="Actual selector from outgoing mail")
    audit.add_argument("--max-files", type=int, default=50)
    explain = commands.add_parser(
        "ai-explain", help="Explain audit findings with explicit AI budget controls"
    )
    explain.add_argument("assessment", type=Path)
    explain.add_argument("--ai-config", type=Path, required=True)
    explain.add_argument("--ledger", type=Path, required=True)
    explain.add_argument(
        "--dry-run", action="store_true", help="Estimate only; no credential or network needed"
    )
    explain.add_argument(
        "--send-evidence", action="store_true", help="Permit sending reviewed evidence to OpenAI"
    )
    review = commands.add_parser(
        "ai-review", help="Interpret saved evidence with validated observation references"
    )
    review.add_argument(
        "assessment", type=Path, help="Assessment/report JSON or scan/batch directory"
    )
    review.add_argument("--ai-config", type=Path, required=True)
    review.add_argument("--ledger", type=Path, required=True)
    review.add_argument("--dry-run", action="store_true")
    review.add_argument("--send-evidence", action="store_true")
    review.add_argument("--packet-index", type=int, help="1-based packet from the prepared preview")
    review.add_argument("--group-size", type=int, default=3, help="1..20 observations per packet")
    costs = commands.add_parser(
        "api-costs", help="Show local estimated charges and unresolved reservations"
    )
    costs.add_argument("--ledger", type=Path, required=True)
    reconcile = commands.add_parser(
        "api-reconcile", help="Reconcile a pending request using provider billing"
    )
    reconcile.add_argument("request_id")
    reconcile.add_argument(
        "--actual-usd", required=True, help="Observed charge; use 0 only for confirmed no-charge"
    )
    reconcile.add_argument("--ledger", type=Path, required=True)
    prune = commands.add_parser(
        "api-cache-prune", help="Clear expired cached AI text without deleting accounting"
    )
    prune.add_argument("--ledger", type=Path, required=True)
    prune.add_argument("--all", action="store_true", help="Clear unexpired cached responses too")
    dependencies = commands.add_parser(
        "audit-deps", help="Inventory pinned dependencies; optionally query OSV"
    )
    dependencies.add_argument("path", type=Path)
    dependencies.add_argument(
        "--recursive-dependencies",
        action="store_true",
        help="Discover supported nested manifests within fixed bounds",
    )
    dependencies.add_argument("--network", action="store_true")
    dependencies.add_argument(
        "--share-packages", action="store_true", help="Permit sharing names/versions with OSV"
    )
    dependencies.add_argument(
        "--advisory-cache", type=Path, help="Optional local advisory cache, TTL one hour"
    )
    dependencies.add_argument("--max-pages", type=int, default=10)
    report = commands.add_parser(
        "audit-report", help="Merge assessment reports into a remediation queue"
    )
    report.add_argument("reports", nargs="+", type=Path)
    report.add_argument("--format", choices=("json", "html"), default="json")
    for command in (
        audit,
        explain,
        review,
        costs,
        reconcile,
        prune,
        dependencies,
        report,
        headers,
        kubernetes,
        html,
        auth,
        ssh,
    ):
        command.add_argument("--output", type=Path, help="New JSON file; never overwrite")


def audit_target(args):
    kind = identify_target(args.target)
    if kind in (
        "local_project",
        "python_source",
        "program_file",
        "mail_message",
        "html_document",
        "authentication_log",
        "ssh_journal",
    ):
        return local_inventory(args.target)
    if not args.network:
        raise ValidationError(
            "Remote audit requires --network and --allow-host for an approved target"
        )
    expected = {
        "website": urlsplit(args.target).hostname,
        "github_repository": "github.com",
        "mail_domain": args.target.removeprefix("mail-domain:").lower(),
        "mailbox_account": "gmail.googleapis.com",
    }[kind]
    if expected not in [h.lower() for h in args.allow_host]:
        raise ValidationError("Target is not in --allow-host scope")
    if kind == "website":
        adapter = WebsiteAudit(PublicHTTPS(
            [expected], max_requests=1, max_bytes=256 * 1024, allow_partial_body=True,
        ))
    elif kind == "github_repository":
        adapter = GithubAudit(
            PublicHTTPS(["api.github.com"], max_bytes=8 * 1024 * 1024), max_files=args.max_files
        )
    elif kind == "mail_domain":
        adapter = MailDomainAudit(
            PublicHTTPS(["cloudflare-dns.com"], max_requests=3), selector=args.dkim_selector
        )
    else:
        adapter = GmailAudit(PublicHTTPS(["gmail.googleapis.com"], max_requests=3))
    try:
        return adapter.assess(args.target)
    except (KeyError, TypeError, AttributeError):
        raise ProviderError("Remote provider returned an invalid document") from None


def run_command(args):
    code = 0
    if args.command in (
        "review-headers",
        "review-kubernetes",
        "review-html",
        "review-auth-log",
        "review-ssh-journal",
    ):
        result = (
            (
                review_ssh_journal_file
                if args.command == "review-ssh-journal"
                else review_auth_log_file
            )(
                args.path,
                policy=AuthPolicy(
                    args.window_seconds, args.min_failures, args.min_accounts, args.min_sources
                ),
            )
            if args.command in ("review-auth-log", "review-ssh-journal")
            else audit_header_capture(args.path)
            if args.command == "review-headers"
            else review_html_file(args.path, document_url=args.document_url)
            if args.command == "review-html"
            else review_kubernetes_file(args.path)
        )
        payload = asdict(result)
        payload["findings"] = list(payload["findings"])
        code = 1 if args.fail_on_findings and result.findings else 0
        if args.format == "html":
            content = render_html(merge_reports([payload]))
            if args.output:
                with args.output.open("x", encoding="utf-8") as stream:
                    stream.write(content)
                print(f"Report saved: {args.output}")
            else:
                print(content)
            return code
    elif args.command == "audit":
        payload = asdict(audit_target(args))
    elif args.command == "audit-deps":
        collected = inventory(args.path, recursive=args.recursive_dependencies)
        if args.network:
            if not args.share_packages:
                raise ValidationError("OSV lookup requires --share-packages as well as --network")
            client = PublicHTTPS(["api.osv.dev"], max_requests=20, max_bytes=2 * 1024 * 1024)
            cache = AdvisoryCache(args.advisory_cache) if args.advisory_cache else None
            payload = OSVAudit(client, cache=cache, max_pages=args.max_pages).assess(collected)
        else:
            if args.share_packages or args.advisory_cache:
                raise ValidationError("Sharing/cache options require explicit --network")
            payload = collected.document()
    elif args.command == "audit-report":
        payload = merge_reports([read_document(p) for p in args.reports])
        if args.format == "html":
            content = render_html(payload)
            if args.output:
                with args.output.open("x", encoding="utf-8") as stream:
                    stream.write(content)
                print(f"Report saved: {args.output}")
            else:
                print(content)
            return 0
    elif args.command in ("ai-explain", "ai-review"):
        with exclusive_ai_output(args.output, args.ledger) as stream:
            payload = review_payload(args) if args.command == "ai-review" else explain_payload(args)
            text = write_document(payload, None)
            if stream is not None:
                stream.write(text)
            else:
                print(text, end="")
        if args.output:
            print(f"Report saved: {args.output}")
        return 0
    else:
        ledger = CostLedger(args.ledger, create=False)
        if args.command == "api-reconcile":
            ledger.reconcile(args.request_id, args.actual_usd)
        payload = (
            ledger.prune_cache(all_entries=args.all)
            if args.command == "api-cache-prune"
            else ledger.report()
        )
    text = write_document(payload, args.output)
    print(f"Report saved: {args.output}" if args.output else text, end="\n" if args.output else "")
    return code


@contextmanager
def exclusive_ai_output(path, ledger):
    """Claim before dispatch; never spend a call on an already occupied output path."""
    if path is None:
        yield None
        return
    target, database = Path(path).resolve(), Path(ledger).resolve()
    if target == database or (
        target.parent == database.parent
        and target.name in {database.name + suffix for suffix in ("-journal", "-wal", "-shm")}
    ):
        raise ValidationError("AI output must not alias its cost database or SQLite sidecars")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    identity, success = os.fstat(descriptor), False
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            yield stream
        success = True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if not success:
            try:
                if os.path.samestat(identity, Path(path).stat(follow_symlinks=False)):
                    Path(path).unlink()
            except FileNotFoundError:
                pass


def explain_payload(args):
    if not args.dry_run and not args.send_evidence:
        raise ValidationError("Review the report and use --send-evidence, or choose --dry-run")
    config = AIConfig.from_document(read_document(args.ai_config))
    document = load_evidence(args.assessment)["ai_document"]
    if not isinstance(document.get("findings"), list):
        raise ValidationError("Assessment document must contain a findings array")
    compact_evidence(document, config.max_input_bytes)
    if not document["findings"]:
        return {
            "status": "skipped_no_findings",
            "network_called": False,
            "not_checked": document.get("not_checked", []),
            "notice": "No AI call is needed; the audit limitations still apply.",
        }
    if not args.dry_run and not os.environ.get("OPENAI_API_KEY"):
        raise ProviderError("OPENAI_API_KEY is missing; no request was reserved or sent")
    ai = BudgetedAI(
        config,
        CostLedger(args.ledger),
        OpenAIResponses(PublicHTTPS(["api.openai.com"], max_requests=1)),
    )
    return ai.explain(document, dry_run=args.dry_run)


def review_payload(args):
    if not args.dry_run and not args.send_evidence:
        raise ValidationError("Review the evidence and use --send-evidence, or choose --dry-run")
    config = AIConfig.from_document(read_document(args.ai_config))
    saved = load_evidence(args.assessment)
    # Complete offline preflight before credential inspection or ledger creation.
    packet_options = {"packet_index": args.packet_index, "group_size": args.group_size}
    estimate = review_result(config, None, None, saved["report"], dry_run=True, **packet_options)
    if args.dry_run or estimate["status"] == "skipped_no_findings":
        return estimate
    if not os.environ.get("OPENAI_API_KEY"):
        raise ProviderError("OPENAI_API_KEY is missing; no request was reserved or sent")
    return review_result(
        config, CostLedger(args.ledger), PublicHTTPS(["api.openai.com"], max_requests=1),
        saved["report"], **packet_options,
    )
