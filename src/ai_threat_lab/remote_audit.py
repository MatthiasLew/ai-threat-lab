"""Concrete, bounded, read-only adapters; never exploit, send mail or execute downloads."""

import base64
import hashlib
import os
import re
import shlex
from pathlib import PurePosixPath
from urllib.parse import quote, urlencode, urlsplit

from .assessment import AssessmentFinding, AssessmentResult, identify_target
from .code_review import review_source
from .http_client import get_document
from .local_inventory import EXCLUDED, TEXT_SUFFIXES, inspect_text
from .models import ValidationError
from .providers import ProviderError


def finding(check, evidence, recommendation):
    return AssessmentFinding(check, "candidate", evidence, recommendation)


class WebsiteAudit:
    def __init__(self, client):
        self.client = client

    def assess(self, target):
        if identify_target(target) != "website" or urlsplit(target).scheme != "https":
            raise ValidationError("Passive website auditing requires an HTTPS website URL")
        response = self.client.request(target)
        missing = [
            "Only one HTTPS response was checked; redirects are not followed.",
            "No exploitation, authentication, crawling, injection or business-logic testing.",
            "Header presence alone does not establish secure configuration.",
        ]
        findings = []
        if response.status != 200:
            missing.append(f"HTTP {response.status}; response security checks were not performed.")
        else:
            for header, action in (
                ("strict-transport-security", "Review and enable an appropriate HSTS policy."),
                (
                    "content-security-policy",
                    "Define and test a restrictive content security policy.",
                ),
                ("x-content-type-options", "Set X-Content-Type-Options: nosniff."),
                ("referrer-policy", "Define a privacy-appropriate referrer policy."),
            ):
                if not response.headers.get(header, "").strip():
                    findings.append(
                        finding("missing_" + header, f"{header} absent in this response", action)
                    )
            if response.headers.get("x-content-type-options", "nosniff").lower() != "nosniff":
                findings.append(
                    finding(
                        "invalid_nosniff",
                        "Unexpected MIME-sniffing header value",
                        "Set X-Content-Type-Options to nosniff.",
                    )
                )
            hsts = response.headers.get("strict-transport-security", "")
            if hsts and not re.search(
                r"(?:^|;)\s*max-age\s*=\s*[1-9][0-9]*(?:\s*;|\s*$)", hsts, re.I
            ):
                findings.append(
                    finding(
                        "weak_hsts",
                        "HSTS has no positive max-age",
                        "Review the effective HSTS policy.",
                    )
                )
        return AssessmentResult(target, "website", "partial", tuple(findings), tuple(missing))


class GithubAudit:
    def __init__(self, client, *, max_files=50):
        if not 1 <= max_files <= 100:
            raise ValidationError("Repository review limit must be between 1 and 100 files")
        self.client, self.max_files = client, max_files

    def assess(self, target):
        if identify_target(target) != "github_repository":
            raise ValidationError("Expected a GitHub repository root URL")
        owner, repository = urlsplit(target).path.strip("/").split("/")
        repository = repository.removesuffix(".git")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", owner) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,100}", repository
        ):
            raise ValidationError("Invalid GitHub repository name")
        if repository in (".", ".."):
            raise ValidationError("Invalid GitHub repository name")
        base = f"https://api.github.com/repos/{owner}/{repository}"
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = "Bearer " + token
        repository_data = get_document(self.client, base, headers)
        branch = repository_data.get("default_branch")
        if not isinstance(branch, str) or not branch:
            raise ProviderError("Repository response lacks a default branch")
        commit = get_document(self.client, base + "/commits/" + quote(branch, safe=""), headers)
        sha = commit.get("sha", "")
        if not re.fullmatch(r"[a-f0-9]{40}", sha):
            raise ProviderError("Repository response lacks an immutable commit")
        tree = get_document(self.client, base + f"/git/trees/{sha}?recursive=1", headers)
        if not isinstance(tree.get("tree"), list):
            raise ProviderError("Repository tree is invalid")
        findings = []
        missing = [
            f"Reviewed immutable commit {sha}; at most {self.max_files} selected text files.",
            "Python AST and secret/manifest patterns only; no full semantic or dependency audit.",
            "No installation, execution, submodule retrieval or archive extraction.",
        ]
        if tree.get("truncated"):
            missing.append("GitHub truncated the repository tree; unlisted paths were not checked.")
        count, total = 0, 0
        for item in tree["tree"]:
            name = item.get("path", "")
            path = PurePosixPath(name)
            if (
                item.get("type") != "blob"
                or item.get("mode") not in ("100644", "100755")
                or path.is_absolute()
                or ".." in path.parts
                or EXCLUDED.intersection(path.parts)
                or (path.suffix not in TEXT_SUFFIXES and path.name != ".env")
            ):
                continue
            size = item.get("size")
            if type(size) is not int or not 0 <= size <= 256 * 1024:
                missing.append(f"Skipped oversized or unknown-sized file: {name}")
                continue
            if count >= self.max_files or total + size > 4 * 1024 * 1024:
                missing.append("Repository review stopped at the file or total-byte limit.")
                break
            blob_sha = item.get("sha", "")
            if not re.fullmatch(r"[a-f0-9]{40}", blob_sha):
                raise ProviderError("Invalid Git blob identity")
            blob = get_document(self.client, base + "/git/blobs/" + blob_sha, headers)
            try:
                if blob.get("encoding") != "base64" or not isinstance(blob.get("content"), str):
                    raise ValueError
                raw = base64.b64decode("".join(blob["content"].split()), validate=True)
                digest = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                if len(raw) != size or digest != blob_sha:
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                raise ProviderError("Invalid repository blob content or digest") from None
            count += 1
            total += len(raw)
            try:
                source = raw.decode("utf-8")
            except UnicodeError:
                missing.append(f"Skipped non-UTF-8 file: {name}")
                continue
            findings.extend(inspect_text(name, source))
            if path.suffix == ".py":
                try:
                    result = review_source(source, name)
                    findings.extend(
                        finding(f.rule_id, f"{name}:{f.line}: {f.title}", f.recommendation)
                        for f in result.findings
                    )
                except ValidationError:
                    missing.append(f"Could not parse Python file: {name}")
        missing.append(f"Inspected {count} selected files ({total} bytes).")
        return AssessmentResult(
            target, "github_repository", "partial", tuple(findings), tuple(missing)
        )


class MailDomainAudit:
    def __init__(self, client, *, selector=None):
        if selector is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", selector):
            raise ValidationError("DKIM selector must be one DNS label")
        self.client, self.selector = client, selector

    def _txt(self, name):
        url = "https://cloudflare-dns.com/dns-query?" + urlencode({"name": name, "type": "TXT"})
        data = get_document(self.client, url, {"Accept": "application/dns-json"})
        if data.get("Status") not in (0, 3):
            raise ProviderError("DNS query failed; policy presence cannot be determined")
        records = []
        for answer in data.get("Answer", []):
            if (
                answer.get("type") == 16
                and answer.get("name", "").rstrip(".").lower() == name.lower()
            ):
                try:
                    records.append("".join(shlex.split(answer["data"])))
                except (ValueError, KeyError, TypeError):
                    raise ProviderError("Invalid DNS TXT response") from None
        return records

    def assess(self, target):
        if identify_target(target) != "mail_domain":
            raise ValidationError("Expected mail-domain:example.com")
        domain = target.removeprefix("mail-domain:").lower()
        spf = [x for x in self._txt(domain) if x.lower().startswith("v=spf1")]
        dmarc = [x for x in self._txt("_dmarc." + domain) if x.lower().startswith("v=dmarc1;")]
        findings = []
        for label, records in (("spf", spf), ("dmarc", dmarc)):
            if len(records) != 1:
                findings.append(
                    finding(
                        label + "_record_count",
                        f"Found {len(records)} {label.upper()} records",
                        "Review effective DNS policy and publish one valid record.",
                    )
                )
        if len(spf) == 1 and (
            "+all" in spf[0].split()
            or not any(term.lower() in ("-all", "~all") for term in spf[0].split())
        ):
            findings.append(
                finding(
                    "weak_spf",
                    "SPF lacks a restrictive terminal all mechanism",
                    "Review legitimate senders and SPF evaluation before tightening policy.",
                )
            )
        if len(dmarc) == 1:
            policy = dict(re.findall(r"(?:^|;)\s*([A-Za-z]+)\s*=\s*([^;\s]+)", dmarc[0]))
            if policy.get("p", "").lower() not in ("quarantine", "reject"):
                findings.append(
                    finding(
                        "monitoring_dmarc",
                        "DMARC policy is not quarantine/reject",
                        "Review alignment reports before moving toward enforcement.",
                    )
                )
        missing = [
            "No SPF include/redirect traversal, DMARC inheritance or full policy validation.",
            "DNS observations are not proof of message authentication or delivery behavior.",
        ]
        if self.selector:
            records = self._txt(self.selector + "._domainkey." + domain)
            if not records:
                findings.append(
                    finding(
                        "dkim_selector_missing",
                        "No TXT record for supplied DKIM selector",
                        "Verify the selector in actual outgoing messages and provider settings.",
                    )
                )
            missing.append("DKIM TXT presence only; no cryptographic signature/key validation.")
        else:
            missing.append("DKIM was not checked: specify the actual selector.")
        return AssessmentResult(target, "mail_domain", "partial", tuple(findings), tuple(missing))


class GmailAudit:
    """Access-token adapter for the authenticated owner's settings, not message content."""

    def __init__(self, client):
        self.client = client

    def assess(self, target):
        if identify_target(target) != "mailbox_account":
            raise ValidationError("Expected mailbox:user@example.com")
        token = os.environ.get("GMAIL_ACCESS_TOKEN")
        if not token:
            raise ProviderError("GMAIL_ACCESS_TOKEN is missing; OAuth consent is required")
        base = "https://gmail.googleapis.com/gmail/v1/users/me"
        headers = {"Authorization": "Bearer " + token}
        profile = get_document(self.client, base + "/profile", headers)
        if profile.get("emailAddress", "").casefold() != target.removeprefix("mailbox:").casefold():
            raise ProviderError("Authenticated Gmail account does not match the requested mailbox")
        forwarding = get_document(self.client, base + "/settings/autoForwarding", headers)
        filters = get_document(self.client, base + "/settings/filters", headers)
        if type(forwarding.get("enabled")) is not bool or not isinstance(
            filters.get("filter", []), list
        ):
            raise ProviderError("Gmail settings response is incomplete")
        findings = []
        if forwarding["enabled"]:
            findings.append(
                finding(
                    "mailbox_auto_forwarding",
                    "Automatic forwarding is enabled (destination omitted)",
                    "Verify the forwarding destination and whether forwarding is necessary.",
                )
            )
        rules = filters.get("filter", [])
        if any(rule.get("action", {}).get("forward") for rule in rules):
            findings.append(
                finding(
                    "mailbox_filter_forwarding",
                    "One or more filters forward messages",
                    "Review forwarding filters against approved account configuration.",
                )
            )
        return AssessmentResult(
            target,
            "mailbox_account",
            "partial",
            tuple(findings),
            (
                "Gmail profile/forwarding/filter settings only; no messages were downloaded.",
                "MFA, account sessions, delegated access, malicious links "
                "and attachments were not checked.",
                "Access-token refresh and interactive OAuth consent are handled outside this CLI.",
            ),
        )
