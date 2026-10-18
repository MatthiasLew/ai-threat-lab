"""Explicit opt-in network assessment and AI cost workflow commands."""

import os
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

from .ai_costs import AIConfig, BudgetedAI, CostLedger, OpenAIResponses
from .assessment import identify_target
from .audit_report import merge_reports, render_html
from .contracts import read_document, write_document
from .dependencies import AdvisoryCache, OSVAudit, inventory
from .header_review import audit_header_capture
from .http_client import PublicHTTPS
from .local_inventory import local_inventory
from .models import ValidationError
from .providers import ProviderError
from .remote_audit import GithubAudit, GmailAudit, MailDomainAudit, WebsiteAudit

COMMANDS = {
    "audit",
    "audit-deps",
    "audit-report",
    "review-headers",
    "ai-explain",
    "api-costs",
    "api-reconcile",
}


def add_commands(commands):
    headers = commands.add_parser(
        "review-headers", help="Review a saved HTTPS header capture offline"
    )
    headers.add_argument("path", type=Path)
    headers.add_argument("--format", choices=("json", "html"), default="json")
    headers.add_argument("--fail-on-findings", action="store_true")
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
    for command in (audit, explain, costs, reconcile, dependencies, report, headers):
        command.add_argument("--output", type=Path, help="New JSON file; never overwrite")


def audit_target(args):
    kind = identify_target(args.target)
    if kind in ("local_project", "python_source", "program_file", "mail_message"):
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
        adapter = WebsiteAudit(PublicHTTPS([expected], max_requests=1))
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
    if args.command == "review-headers":
        result = audit_header_capture(args.path)
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
    elif args.command == "ai-explain":
        if not args.dry_run and not args.send_evidence:
            raise ValidationError("Review the report and use --send-evidence, or choose --dry-run")
        config = AIConfig.from_document(read_document(args.ai_config))
        document = read_document(args.assessment)
        if not isinstance(document.get("findings"), list):
            raise ValidationError("Assessment document must contain a findings array")
        if not document["findings"]:
            payload = {
                "status": "skipped_no_findings",
                "network_called": False,
                "notice": "No AI call is needed; the audit limitations still apply.",
            }
        else:
            if not args.dry_run and not os.environ.get("OPENAI_API_KEY"):
                raise ProviderError("OPENAI_API_KEY is missing; no request was reserved or sent")
            ai = BudgetedAI(
                config,
                CostLedger(args.ledger),
                OpenAIResponses(PublicHTTPS(["api.openai.com"], max_requests=1)),
            )
            payload = ai.explain(document, dry_run=args.dry_run)
    else:
        ledger = CostLedger(args.ledger)
        if args.command == "api-reconcile":
            ledger.reconcile(args.request_id, args.actual_usd)
        payload = ledger.report()
    text = write_document(payload, args.output)
    print(f"Report saved: {args.output}" if args.output else text, end="\n" if args.output else "")
    return code
