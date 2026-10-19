"""Concrete, bounded, read-only adapters; never exploit, send mail or execute downloads."""

import base64
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import quote, urlencode, urlsplit

from .assessment import AssessmentFinding, AssessmentResult, identify_target
from .code_review import review_source
from .config_review import NOTICE, configuration_file
from .dependencies import MAX_BYTES, inventory_sources
from .dependency_paths import MAX_DEPTH, MAX_ENTRIES, is_manifest, valid_source_path
from .header_review import inspect_response_headers
from .http_client import get_document
from .kubernetes_review import NOTICE as KUBERNETES_NOTICE
from .kubernetes_review import review_kubernetes_source
from .local_inventory import EXCLUDED, TEXT_SUFFIXES, inspect_text
from .models import ValidationError
from .providers import ProviderError
from .python_flow import NOTICE as FLOW_NOTICE


def finding(check, evidence, recommendation):
    return AssessmentFinding(check, "candidate", evidence, recommendation)


class WebsiteAudit:
    def __init__(self, client):
        self.client = client

    def assess(self, target):
        kind = identify_target(target)
        parsed = urlsplit(target)
        if (
            kind != "website" or parsed.scheme != "https" or parsed.port not in (None, 443)
            or parsed.fragment or not target.isascii() or len(target) > 4096
            or "\\" in target or any(ord(c) <= 32 or ord(c) == 127 for c in target)
        ):
            raise ValidationError(
                "Use bounded ASCII HTTPS on port 443 without fragments or ambiguous characters"
            )
        response = self.client.request(target)
        try:
            headers = response.header_items or tuple(response.headers.items())
            findings, missing = inspect_response_headers(response.status, headers)
            body_status = getattr(response, "body_status", "complete")
            if body_status not in ("complete", "size_limit", "read_error"):
                raise ValidationError("Unsupported response body state")
        except (ValidationError, AttributeError, TypeError):
            raise ProviderError(
                "Response headers/state exceed supported structure or limits"
            ) from None
        from .html_review import inspect_html_response

        if response.status != 200:
            html_findings, html_missing = (), ("Non-200 response body unchecked.",)
        elif body_status != "complete":
            reason = (
                "HTML body exceeded the size limit; body unchecked."
                if body_status == "size_limit"
                else "HTML body read incomplete or failed; body unchecked."
            )
            html_findings, html_missing = (), (reason,)
        else:
            html_findings, html_missing = inspect_html_response(
                response.body, headers, document_url=target
            )
        return AssessmentResult(
            target,
            "website",
            "partial",
            (*findings, *html_findings),
            (
                "Only one HTTPS response was checked; redirects are not followed.",
                *missing,
                *html_missing,
                *(
                    ("Adapter supplied only a header mapping; duplicate fields may be missing.",)
                    if not response.header_items
                    else ()
                ),
            ),
        )


@dataclass(frozen=True)
class GithubSnapshot:
    assessment: AssessmentResult
    commit_sha: str
    manifests: tuple[tuple[str, bytes], ...]
    recursive_dependencies: bool = False

    def inventory(self):
        return inventory_sources(
            self.assessment.target,
            self.manifests,
            not_checked=(
                f"Inventory from immutable GitHub commit {self.commit_sha}.",
                "Selected recursive manifests; bounded/excluded/unsupported paths remain unchecked."
                if self.recursive_dependencies
                else "Only root manifests; subdirectory and unsupported manifests unchecked.",
                *self.assessment.not_checked,
            ),
            allow_paths=self.recursive_dependencies,
        )


class GithubAudit:
    def __init__(self, client, *, max_files=50):
        if type(max_files) is not int or not 1 <= max_files <= 100:
            raise ValidationError("Repository review limit must be between 1 and 100 files")
        self.client, self.max_files = client, max_files

    def assess(self, target):
        return self.collect(target).assessment

    def collect(self, target, *, include_dependencies=False, recursive_dependencies=False):
        if type(include_dependencies) is not bool:
            raise ValidationError("GitHub dependency selection must be boolean")
        if type(recursive_dependencies) is not bool or (
            recursive_dependencies and not include_dependencies
        ):
            raise ValidationError("Recursive GitHub manifests require dependency collection")
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
            if len(token) > 4096 or any(not 33 <= ord(char) <= 126 for char in token):
                raise ProviderError("GITHUB_TOKEN has unsupported length or characters")
            headers["Authorization"] = "Bearer " + token
        repository_data = get_document(self.client, base, headers)
        branch = repository_data.get("default_branch")
        if (
            not isinstance(branch, str)
            or not 1 <= len(branch) <= 1024
            or any(ord(c) <= 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in branch)
        ):
            raise ProviderError("Repository response lacks a usable default branch")
        commit = get_document(self.client, base + "/commits/" + quote(branch, safe=""), headers)
        sha = commit.get("sha", "")
        if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{40}", sha):
            raise ProviderError("Repository response lacks an immutable commit")
        tree = get_document(self.client, base + f"/git/trees/{sha}?recursive=1", headers)
        if not isinstance(tree.get("tree"), list) or type(tree.get("truncated", False)) is not bool:
            raise ProviderError("Repository tree is invalid")
        findings = []
        missing = [
            f"Reviewed immutable commit {sha}; at most {self.max_files} selected text files.",
            "Python AST and secret/manifest patterns only; no full semantic or dependency audit.",
            "No installation, execution, submodule retrieval or archive extraction.",
            NOTICE,
        ]
        if tree.get("truncated"):
            missing.append("GitHub truncated the repository tree; unlisted paths were not checked.")
        count, total = 0, 0
        manifests, cache, seen = [], {}, set()
        project_sources, unavailable_sources = [], []
        entries = tree["tree"]
        if recursive_dependencies and len(entries) > MAX_ENTRIES:
            missing.append("GitHub tree entry inspection limit reached; unlisted paths unchecked.")
            entries = entries[:MAX_ENTRIES]

        def selected_manifest(name):
            path = PurePosixPath(name)
            return (
                include_dependencies
                and is_manifest(path.name)
                and (recursive_dependencies or "/" not in name)
            )

        if any(
            not isinstance(item, dict) or not isinstance(item.get("path"), str) for item in entries
        ):
            raise ProviderError("Invalid repository tree entry")
        if include_dependencies:
            # Selected manifests share the same file/byte budget and immutable tree.
            entries = sorted(
                entries,
                key=lambda item: (
                    not selected_manifest(item["path"]),
                    item["path"].count("/") if recursive_dependencies else 0,
                    item["path"],
                ),
            )
        for item in entries:
            name = item.get("path", "")
            path = PurePosixPath(name)
            manifest = selected_manifest(name)
            if (
                manifest
                and recursive_dependencies
                and (
                    not valid_source_path(name, allow_paths=True) or len(path.parts) - 1 > MAX_DEPTH
                )
            ):
                missing.append("Skipped a manifest outside portable path/depth bounds.")
                continue
            if (
                item.get("type") != "blob"
                or item.get("mode") not in ("100644", "100755")
                or path.is_absolute()
                or ".." in path.parts
                or EXCLUDED.intersection(path.parts)
                or (
                    not manifest
                    and path.suffix not in TEXT_SUFFIXES
                    and path.suffix.lower() not in (".html", ".htm")
                    and path.name != ".env"
                    and not configuration_file(name)
                )
            ):
                continue
            if name in seen:
                raise ProviderError("Duplicate repository tree path")
            seen.add(name)
            if manifest and len(manifests) >= 20:
                missing.append("Repository manifest limit reached; additional manifests unchecked.")
                continue
            size = item.get("size")
            if type(size) is not int or not 0 <= size <= (MAX_BYTES if manifest else 256 * 1024):
                missing.append(f"Skipped oversized or unknown-sized file: {name}")
                continue
            if count >= self.max_files or total + size > 4 * 1024 * 1024:
                missing.append("Repository review stopped at the file or total-byte limit.")
                break
            blob_sha = item.get("sha", "")
            if not isinstance(blob_sha, str) or not re.fullmatch(r"[a-f0-9]{40}", blob_sha):
                raise ProviderError("Invalid Git blob identity")
            if blob_sha not in cache:
                blob = get_document(self.client, base + "/git/blobs/" + blob_sha, headers)
                try:
                    if blob.get("encoding") != "base64" or not isinstance(blob.get("content"), str):
                        raise ValueError
                    raw = base64.b64decode("".join(blob["content"].split()), validate=True)
                    digest = hashlib.sha1(
                        b"blob " + str(len(raw)).encode() + b"\0" + raw
                    ).hexdigest()
                    if len(raw) != size or digest != blob_sha:
                        raise ValueError
                except (ValueError, KeyError, TypeError):
                    raise ProviderError("Invalid repository blob content or digest") from None
                cache[blob_sha] = raw
            raw = cache[blob_sha]
            if len(raw) != size:
                raise ProviderError("Repository tree/blob size mismatch")
            if manifest:
                manifests.append((name, raw))
            count += 1
            total += len(raw)
            try:
                source = raw.decode("utf-8")
            except UnicodeError:
                if path.suffix == ".py":
                    unavailable_sources.append(name)
                missing.append(f"Skipped non-UTF-8 file: {name}")
                continue
            if len(raw) > 256 * 1024:
                missing.append(f"Large manifest parsed for dependencies only: {name}")
                continue
            findings.extend(inspect_text(name, source))
            if path.suffix.lower() in (".html", ".htm"):
                from .html_review import inspect_html

                observed, gaps = inspect_html(source)
                findings.extend(
                    AssessmentFinding(f.check, f.status, name + ": " + f.evidence, f.recommendation)
                    for f in observed
                )
                missing.extend(gaps)
            if path.suffix.lower() == ".json":
                review = review_kubernetes_source(source, name)
                if review is not None:
                    findings.extend(review.findings)
                    missing.extend(n for n in review.not_checked if n != KUBERNETES_NOTICE)
            if path.suffix == ".py":
                project_sources.append((name, source))
                try:
                    result = review_source(source, name)
                    missing.extend(
                        f"{name}: {notice}"
                        for notice in result.limitations
                        if notice.startswith("Flow coverage:") and notice != FLOW_NOTICE
                    )
                    findings.extend(
                        finding(
                            f.rule_id,
                            f"{name}:{f.line}: {f.title}"
                            + (f". {f.rationale}" if f.rule_id in ("PY013", "PY014") else ""),
                            f.recommendation,
                        )
                        for f in result.findings
                    )
                except ValidationError:
                    missing.append(f"Could not parse Python file: {name}")
        from .python_project_flow import project_flows

        extra, notices = project_flows(project_sources, unavailable=unavailable_sources)
        findings.extend(extra)
        missing.extend(notices)
        missing.append(FLOW_NOTICE)
        missing.append(KUBERNETES_NOTICE)
        missing.append(f"Inspected {count} selected files ({total} bytes).")
        return GithubSnapshot(
            AssessmentResult(
                target, "github_repository", "partial", tuple(findings), tuple(missing)
            ),
            sha,
            tuple(manifests),
            recursive_dependencies,
        )


def dns_txt(value):
    """Decode the bounded quoted-string subset of DNS TXT presentation syntax.

    Unsupported presentations fail closed; shell quoting is not DNS quoting.
    """
    if not isinstance(value, str) or not value or len(value) > 262144:
        raise ProviderError("Invalid or unsupported DNS TXT response")
    position, chunks = 0, []
    while position < len(value):
        if value[position] in " \t":
            position += 1
            continue
        if value[position] != '"':
            raise ProviderError("Invalid or unsupported DNS TXT response")
        position += 1
        chunk = []
        while position < len(value) and value[position] != '"':
            char = value[position]
            position += 1
            if char == "\\":
                if position == len(value):
                    raise ProviderError("Invalid or unsupported DNS TXT response")
                char = value[position]
                if char in "0123456789":
                    digits = value[position:position + 3]
                    if len(digits) != 3 or any(d not in "0123456789" for d in digits):
                        raise ProviderError("Invalid or unsupported DNS TXT response")
                    number = int(digits)
                    if number > 255:
                        raise ProviderError("Invalid or unsupported DNS TXT response")
                    char = chr(number)
                    position += 3
                else:
                    position += 1
            if not 32 <= ord(char) <= 126:
                raise ProviderError("Invalid or unsupported DNS TXT response")
            chunk.append(char)
            if len(chunk) > 255:
                raise ProviderError("Invalid or unsupported DNS TXT response")
        if position == len(value):
            raise ProviderError("Invalid or unsupported DNS TXT response")
        chunks.append("".join(chunk))
        position += 1
        if position < len(value) and value[position] not in " \t":
            raise ProviderError("Invalid or unsupported DNS TXT response")
    result = "".join(chunks)
    if not chunks or len(result) > 65535:
        raise ProviderError("Invalid or unsupported DNS TXT response")
    return result


class MailDomainAudit:
    def __init__(self, client, *, selector=None):
        if selector is not None and (
            not isinstance(selector, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", selector)
        ):
            raise ValidationError("DKIM selector must be one DNS label")
        self.client, self.selector = client, selector

    def _txt(self, name):
        url = "https://cloudflare-dns.com/dns-query?" + urlencode({"name": name, "type": "TXT"})
        data = get_document(self.client, url, {"Accept": "application/dns-json"})
        status = data.get("Status")
        if type(status) is not int or status not in (0, 3):
            raise ProviderError("DNS query failed; policy presence cannot be determined")
        if type(data.get("TC", False)) is not bool or data.get("TC", False):
            raise ProviderError("Truncated or invalid DNS response; policy presence is unknown")
        if "Question" in data:
            question = data["Question"]
            if (
                not isinstance(question, list) or len(question) != 1
                or not isinstance(question[0], dict)
                or type(question[0].get("type")) is not int or question[0]["type"] != 16
                or not isinstance(question[0].get("name"), str)
                or question[0]["name"].removesuffix(".").lower() != name.lower()
            ):
                raise ProviderError("DNS response does not match the requested question")
        answers = data.get("Answer", [])
        if not isinstance(answers, list) or len(answers) > 256 or (status == 3 and answers):
            raise ProviderError("Invalid or contradictory DNS answer section")
        records = []
        for answer in answers:
            if (
                not isinstance(answer, dict)
                or type(answer.get("type")) is not int or not 1 <= answer["type"] <= 65535
                or not isinstance(answer.get("name"), str)
                or len(answer["name"].removesuffix(".")) > 253
                or not re.fullmatch(
                    r"(?:[A-Za-z0-9_-]{1,63}\.)*[A-Za-z0-9_-]{1,63}\.?", answer["name"]
                )
                or not isinstance(answer.get("data"), str)
            ):
                raise ProviderError("Invalid DNS answer metadata")
            if answer["name"].removesuffix(".").lower() != name.lower():
                continue
            if answer["type"] in (5, 39):
                raise ProviderError("DNS alias resolution is outside this audit; policy is unknown")
            if answer["type"] == 16:
                records.append(dns_txt(answer["data"]))
        return records

    def assess(self, target):
        if identify_target(target) != "mail_domain":
            raise ValidationError("Expected mail-domain:example.com")
        domain = target.removeprefix("mail-domain:").lower()
        names = [domain, "_dmarc." + domain]
        if self.selector:
            names.append(self.selector + "._domainkey." + domain)
        if any(len(name) > 253 for name in names):
            raise ValidationError("Mail DNS query name exceeds 253 characters")
        spf = [x for x in self._txt(domain) if re.match(r"(?i)^v=spf1(?: |$)", x)]
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
            "+all" in spf[0].lower().split()
            or not any(term.lower() in ("-all", "~all") for term in spf[0].split())
        ):
            findings.append(
                finding(
                    "weak_spf",
                    "SPF has permissive +all or lacks an explicit -all/~all mechanism",
                    "Review legitimate senders and SPF evaluation before tightening policy.",
                )
            )
        if len(dmarc) == 1:
            tags = [part.strip() for part in dmarc[0].split(";")]
            if tags[-1] == "":
                tags.pop()
            policy = {}
            invalid = False
            for tag in tags:
                match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.+)", tag)
                if not match or match[1] in policy:
                    invalid = True
                    break
                policy[match[1]] = match[2].strip()
            if invalid or policy.get("p") not in ("none", "quarantine", "reject"):
                findings.append(finding(
                    "invalid_dmarc", "DMARC has ambiguous or unsupported policy tags",
                    "Validate the complete DMARC record before relying on enforcement.",
                ))
            elif policy["p"] == "none":
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
        if len(token) > 4096 or any(not 33 <= ord(char) <= 126 for char in token):
            raise ProviderError("GMAIL_ACCESS_TOKEN has unsupported length or characters")
        base = "https://gmail.googleapis.com/gmail/v1/users/me"
        headers = {"Authorization": "Bearer " + token}
        profile = get_document(self.client, base + "/profile", headers)
        identity = profile.get("emailAddress")
        if not isinstance(identity, str) or identity.casefold() != target.removeprefix(
            "mailbox:"
        ).casefold():
            raise ProviderError("Authenticated Gmail account does not match the requested mailbox")
        forwarding = get_document(self.client, base + "/settings/autoForwarding", headers)
        if type(forwarding.get("enabled")) is not bool:
            raise ProviderError("Gmail forwarding settings response is incomplete")
        filters = get_document(self.client, base + "/settings/filters", headers)
        rules = filters.get("filter", [])
        if (
            not isinstance(rules, list) or len(rules) > 1000
            or filters.get("nextPageToken") not in (None, "")
        ):
            raise ProviderError("Gmail filter response is incomplete or exceeds the audit limit")
        forwards = False
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("action", {}), dict):
                raise ProviderError("Invalid Gmail filter action metadata")
            destination = rule.get("action", {}).get("forward", "")
            if (
                not isinstance(destination, str) or len(destination) > 1024
                or any(not 33 <= ord(char) <= 126 for char in destination)
            ):
                raise ProviderError("Invalid Gmail filter forwarding metadata")
            forwards = forwards or bool(destination)
        findings = []
        if forwarding["enabled"]:
            findings.append(
                finding(
                    "mailbox_auto_forwarding",
                    "Automatic forwarding is enabled (destination omitted)",
                    "Verify the forwarding destination and whether forwarding is necessary.",
                )
            )
        if forwards:
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
