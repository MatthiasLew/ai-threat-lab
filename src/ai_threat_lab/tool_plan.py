"""Deterministic prepared-tool selection. Planning never invokes a collector or model."""

from urllib.parse import urlsplit

from .assessment import identify_target
from .models import ValidationError
from .scan_engine import ScanOptions

TOOLS = {
    "local_project": (
        "local_inventory",
        "Selected Python source/flows, secret patterns and configuration",
        "Other language semantics, runtime behavior and complete project coverage are unchecked.",
    ),
    "python_source": (
        "python_review",
        "Selected Python syntax and bounded data-flow candidates",
        "The source is parsed, never executed; applicability needs human review.",
    ),
    "program_file": (
        "binary_archive_review",
        "Bounded PE/ELF structures and ZIP metadata",
        "No malware execution, decompression, signature trust or disassembly.",
    ),
    "mail_message": (
        "saved_mail_review",
        "Saved EML headers, links, forms and attachment metadata",
        "No mailbox access, message delivery, attachment execution or authenticity proof.",
    ),
    "html_document": (
        "saved_html_review",
        "Saved HTML form and resource observations",
        "No browser, JavaScript execution, navigation or form submission.",
    ),
    "authentication_log": (
        "authentication_patterns",
        "Normalized saved login-event patterns",
        "No login attempts or proof that an account was compromised.",
    ),
    "ssh_journal": (
        "openssh_journal_review",
        "Selected saved single-host OpenSSH journal events",
        "Unsupported native messages and missing events remain explicit gaps.",
    ),
    "github_repository": (
        "github_snapshot",
        "Pinned source and dependency manifests from one repository commit",
        "Bounded files and supported source patterns only; account access needs live validation.",
    ),
    "website": (
        "passive_https",
        "One HTTPS response: headers and eligible complete HTML",
        "No crawling, authenticated testing, form submission or business-logic assessment.",
    ),
    "mail_domain": (
        "mail_dns",
        "Basic SPF/DMARC and explicitly selected DKIM TXT observations",
        "Not full DNSSEC, policy, message authentication or delivery validation.",
    ),
    "mailbox_account": (
        "gmail_settings",
        "Identity-bound Gmail forwarding and filter settings",
        "Gmail settings token/account setup required; not a complete mailbox assessment.",
    ),
}


def plan_target(
    target,
    *,
    network=False,
    allowed_hosts=(),
    max_files=50,
    recursive_dependencies=False,
    share_packages=False,
    dkim_selector=None,
    max_pages=10,
):
    if type(network) is not bool or not isinstance(allowed_hosts, (tuple, list)):
        raise ValidationError("Network must be boolean and approved hosts must be an array")
    kind = identify_target(target)
    remote_host = {
        "github_repository": "github.com",
        "website": urlsplit(target).hostname,
        "mail_domain": target.removeprefix("mail-domain:").lower(),
        "mailbox_account": "gmail.googleapis.com",
    }.get(kind)
    # Validate the same executable options even when planning lacks consent.
    # The projected opt-in is never used to construct a collector or execute work.
    projected_hosts = (*allowed_hosts, remote_host) if remote_host else allowed_hosts
    options = ScanOptions(
        target,
        network=network or bool(remote_host) or share_packages,
        allowed_hosts=projected_hosts,
        max_files=max_files,
        recursive_dependencies=recursive_dependencies,
        share_packages=share_packages,
        dkim_selector=dkim_selector,
        max_pages=max_pages,
    )
    # Validate original booleans too: Python's `or` must not hide malformed API input.
    original_hosts = tuple(h.lower() for h in allowed_hosts)
    requirements = []
    if (remote_host or share_packages) and not network:
        requirements.append("Explicit --network permission is required before collection.")
    if remote_host and remote_host not in original_hosts:
        requirements.append(f"Explicit --allow-host {remote_host} is required before collection.")
    tool, title, limit = TOOLS[kind]
    selected = [{"id": tool, "purpose": title, "limit": limit}]
    if kind == "mail_message":
        selected.append(
            {
                "id": "mail_attachment_structures",
                "purpose": "Decoded attachment size/hash and selected PE/ELF/ZIP structures",
                "limit": "First 20 discovered attachments within byte/part bounds; "
                "no extraction, execution, signature trust or malware detection.",
            }
        )
    destinations, disclosure, setup = [], [], []
    if kind == "github_repository":
        destinations = ["api.github.com"]
        disclosure = ["Repository owner/name and bounded GitHub API resource requests."]
    elif kind == "website":
        destinations = [remote_host]
        disclosure = ["The exact HTTPS URL/path/query is sent to the selected website."]
    elif kind == "mail_domain":
        destinations = ["cloudflare-dns.com"]
        disclosure = ["Domain and selected DNS names are sent to the DNS-over-HTTPS resolver."]
    elif kind == "mailbox_account":
        destinations = ["gmail.googleapis.com"]
        disclosure = ["The token is sent only to Gmail; returned settings are locally reviewed."]
        setup = ["Provide the documented read-only Gmail settings token for the selected account."]
    if kind in ("local_project", "github_repository"):
        selected.append(
            {
                "id": "dependency_inventory",
                "purpose": "Exact versions in supported root/opt-in nested manifests",
                "limit": "No package installation, resolution or reachability analysis.",
            }
        )
        if share_packages:
            selected.append(
                {
                    "id": "osv_advisories",
                    "purpose": "Known package/version advisories",
                    "limit": "Version matches do not establish exploitability.",
                }
            )
            destinations.append("api.osv.dev")
            disclosure.append("Package ecosystems, names and exact versions are sent to OSV.")
    selected.append(
        {
            "id": "verified_report_bundle",
            "purpose": "Preserve evidence, module failures, limitations and readable reports",
            "limit": "Local integrity is not authenticity or proof of security.",
        }
    )
    return {
        "schema_version": 1,
        "mode": "prepared_tool_plan",
        "target": options.target,
        "target_kind": kind,
        "tools": selected,
        "network_destinations": destinations,
        "approval_host": remote_host,
        "data_disclosure": disclosure,
        "permission_requirements": requirements,
        "setup_requirements": setup,
        "collection_permitted": not requirements,
        "bounds": {
            "max_files": max_files,
            "max_advisory_pages": max_pages,
            "recursive_dependencies": recursive_dependencies,
        },
        "network_called": False,
        "credentials_inspected": False,
        "ai_calls": 0,
        "notice": "Deterministic plan only; no tool or model ran. Execution revalidates scope. "
        "Optional AI interprets saved evidence; it does not generate or execute attacks. "
        "Permission readiness does not establish account access or target availability.",
    }
