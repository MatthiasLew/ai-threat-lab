"""Bounded same-origin navigation with prepared passive checks, never form submission."""

import re
from collections import deque
from dataclasses import asdict
from urllib.parse import urljoin, urlsplit, urlunsplit

from .assessment import AssessmentResult
from .audit_report import merge_reports
from .html_review import MAX_BYTES, HTMLLimit, Page, inspect_html_response
from .html_review import NOTICE as HTML_NOTICE
from .models import ValidationError
from .providers import ProviderError
from .remote_audit import WebsiteAudit

NOTICE = (
    "Bounded passive navigation only: no login, cookies, JavaScript, forms, redirects, "
    "query URLs, application logic, robots policy interpretation or active tests. "
    "GET requests can still have effects on incorrectly designed applications."
)


def canonical_url(value):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or not value.isascii()
        or re.search(r"[\x00-\x20\x7f\\%]", value)
    ):
        raise ValidationError("Use an ASCII HTTPS URL without encoded or ambiguous characters")
    try:
        url = urlsplit(value)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.port not in (None, 443)
            or url.query
            or any(part in (".", "..") for part in url.path.split("/"))
            or "//" in url.path
            or not re.fullmatch(r"[A-Za-z0-9.-]+", url.hostname)
        ):
            raise ValueError
    except ValueError:
        raise ValidationError("Use an HTTPS hostname on port 443 without query or credentials")
    return urlunsplit(("https", url.hostname.lower(), url.path or "/", "", ""))


class Links(Page):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attributes):
        super().handle_starttag(tag, attributes)
        if self.plaintext or self.ignored or tag != "a":
            return
        attrs = dict(attributes)
        if len(attrs) != len(attributes) or "download" in attrs:
            return
        if attrs.get("href") and len(self.links) < 500:
            self.links.append(attrs["href"])


def page_links(response, target):
    """Use exactly the HTML eligibility rules used by the passive finding collector."""
    headers = response.header_items or tuple(response.headers.items())
    if response.status != 200 or response.body_status != "complete":
        return (), ("Navigation skipped for a non-200 or incomplete response.",)
    _, notices = inspect_html_response(response.body, headers, document_url=target)
    if HTML_NOTICE not in notices:
        return (), notices
    page = Links()
    try:
        page.feed(response.body.decode("utf-8-sig"))
        page.close()
    except (UnicodeError, HTMLLimit, ValueError):
        return (), ("Navigation HTML exceeded parser bounds or was invalid.",)
    if page.base_seen:
        return (), ("Navigation with a base element is not followed.",)
    return page.links, (
        *sorted(page.notices),
        *(("Link enumeration reached its 500-element bound.",) if len(page.links) == 500 else ()),
    )


class SiteReview:
    def __init__(self, client, *, max_pages=10, max_depth=2, session_supplied=False):
        if type(max_pages) is not int or not 1 <= max_pages <= 20:
            raise ValidationError("Site page limit must be between 1 and 20")
        if type(max_depth) is not int or not 0 <= max_depth <= 5:
            raise ValidationError("Site navigation depth must be between 0 and 5")
        if type(session_supplied) is not bool:
            raise ValidationError("Session selection must be boolean")
        self.client, self.max_pages, self.max_depth = client, max_pages, max_depth
        self.session_supplied = session_supplied
        self.private_paths = {}
        self.notice = NOTICE
        self.session_failures = {}
        if session_supplied:
            from .session_http import FAILURES
            from .session_http import NOTICE as SESSION_NOTICE

            self.notice = SESSION_NOTICE
            self.session_failures = FAILURES

    def run(self, target, *, path_prefix="/"):
        start = canonical_url(target)
        host = urlsplit(start).hostname
        if not isinstance(path_prefix, str) or not path_prefix.startswith("/"):
            raise ValidationError("Path scope must be an absolute URL path")
        scope = canonical_url(f"https://{host}{path_prefix}")
        prefix = urlsplit(scope).path
        if path_prefix != prefix or not prefix.endswith("/"):
            raise ValidationError("Path scope must end with / and contain no URL suffixes")
        if not urlsplit(start).path.startswith(prefix):
            raise ValidationError("Start URL is outside the approved path scope")
        queue, seen = deque([(start, 0)]), {start}
        documents, failures = [], 0
        self.private_paths = {}
        while queue and len(documents) < self.max_pages:
            url, depth = queue.popleft()
            label = f"Session page {len(documents) + 1:04d}" if self.session_supplied else url
            if self.session_supplied:
                self.private_paths[label] = url
            try:
                # Capture exactly one response, reused by the existing analyzer and navigation.
                response = self.client.request(url)
                if not isinstance(response.body, bytes) or len(response.body) > MAX_BYTES:
                    raise ProviderError("Response exceeds page byte bound")

                class Captured:
                    def request(self, requested):
                        assert requested == url
                        return response

                assessment = WebsiteAudit(Captured()).assess(url)
                links, gaps = page_links(response, url)
                candidates = []
                for link in links:
                    try:
                        if re.search(r"[\x00-\x20\x7f\\]", link):
                            continue
                        candidate = canonical_url(urljoin(url, link))
                    except (ValidationError, ValueError):
                        continue
                    parsed = urlsplit(candidate)
                    if parsed.hostname == host and parsed.path.startswith(prefix):
                        if candidate not in seen and candidate not in candidates:
                            candidates.append(candidate)
                limits = list(gaps)
                if candidates and depth >= self.max_depth:
                    limits.append("Navigation depth limit reached; linked pages unchecked.")
                elif candidates:
                    room = self.max_pages - len(seen)
                    if len(candidates) > room:
                        limits.append("Page limit reached; additional linked pages unchecked.")
                    for candidate in candidates[:room]:
                        seen.add(candidate)
                        queue.append((candidate, depth + 1))
                documents.append(
                    asdict(
                        AssessmentResult(
                            label,
                            "website",
                            "partial",
                            assessment.findings,
                            (*assessment.not_checked, *limits, self.notice),
                        )
                    )
                )
            except (ProviderError, ValidationError):
                failures += 1
                code = getattr(self.client, "failure_code", None)
                reason = self.session_failures.get(code) if isinstance(code, str) else None
                documents.append(
                    asdict(
                        AssessmentResult(
                            label,
                            "website",
                            "not_configured",
                            (),
                            (
                                "Page collection failed; no security conclusion for this page.",
                                *((reason,) if reason else ()),
                                self.notice,
                            ),
                        )
                    )
                )
        # Normalize tuples through the existing contract's JSON representation.
        import json

        report = merge_reports(json.loads(json.dumps(documents)))
        return report, failures
