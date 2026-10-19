"""Bounded offline MIME metadata and link candidates; never visit or open content."""

import ipaddress
import re
from collections import Counter
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from .assessment import AssessmentFinding

MAX_PARTS = 100
MAX_DEPTH = 8
MAX_TEXT_PARTS = 20
MAX_TEXT_BYTES = 256 * 1024
MAX_LINKS = 200
MAX_LINK_LENGTH = 4096
MAX_HTML_FINDINGS = 200
ACTIVE_EXTENSIONS = {
    ".exe",
    ".com",
    ".scr",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".lnk",
    ".jar",
    ".docm",
    ".xlsm",
    ".pptm",
}
DISPLAY_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}
ACTIVE_TYPES = {"application/x-msdownload", "application/x-dosexec", "application/x-sh"}
LINK = re.compile(r"https?://[^\s<>\"']+", re.I)
DESCRIPTIONS = {
    "message_link_cleartext": (
        "selected link occurrences use HTTP",
        "Review the destination and prefer authenticated HTTPS; "
        "HTTP alone does not establish phishing.",
    ),
    "message_link_ip_address": (
        "selected link occurrences use an IP-literal host",
        "Verify the intended destination independently; "
        "internal tools may legitimately use IP hosts.",
    ),
    "message_link_credentials": (
        "selected link occurrences contain URL user information",
        "Review the real destination independently; user information can obscure the host.",
    ),
    "message_link_active_scheme": (
        "selected HTML links use data/javascript/vbscript schemes",
        "Review the original in a controlled viewer; no active link content was executed.",
    ),
    "message_link_display_mismatch": (
        "selected HTML anchors display a different HTTP(S) hostname",
        "Review the destination independently; tracking and redirect links can be legitimate.",
    ),
    "message_attachment_active_type": (
        "parts declare executable/script/macro-capable attachment metadata",
        "Review through the organization's attachment policy; "
        "an extension/type is not malware evidence.",
    ),
    "message_attachment_double_extension": (
        "parts combine a document/image extension with an active final extension",
        "Verify the file type in a controlled workflow; "
        "names alone do not establish malicious content.",
    ),
}


def _host(value):
    if any(character.isspace() for character in value):
        return None
    try:
        url = urlsplit("https:" + value if value.startswith("//") else value)
        if url.scheme.lower() not in ("http", "https") or not url.hostname:
            return None
        _ = url.port
        return url
    except ValueError:
        return None


class _Anchors(HTMLParser):
    def __init__(self, observe):
        super().__init__(convert_charrefs=True)
        self.observe = observe
        self.current = None
        self.text = ""

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            if self.current is not None:
                self.observe(self.current, self.text)
            self.current = dict(attrs).get("href")
            self.text = ""

    def handle_data(self, data):
        if self.current is not None:
            self.text = (self.text + data)[:MAX_LINK_LENGTH]

    def handle_endtag(self, tag):
        if tag == "a" and self.current is not None:
            self.observe(self.current, self.text)
            self.current = None

    def finish(self):
        self.close()
        if self.current is not None:
            self.observe(self.current, self.text)
            self.current = None


def inspect_message_content(message):
    """Return redacted aggregate candidates and explicit selection/decoding gaps."""
    counts = Counter()
    notices = set()
    links = text_parts = decoded_bytes = visited = 0
    html_findings = []

    def observe(value, label=""):
        nonlocal links
        if links >= MAX_LINKS:
            notices.add("Message link limit reached; additional links unchecked.")
            return
        links += 1
        if len(value) > MAX_LINK_LENGTH:
            notices.add("Oversized message link skipped; destination omitted.")
            return
        value = value.strip()
        if value.lower().startswith(("javascript:", "data:", "vbscript:")):
            counts["message_link_active_scheme"] += 1
            return
        url = _host(value)
        if url is None:
            return
        if url.scheme.lower() == "http":
            counts["message_link_cleartext"] += 1
        if url.username is not None or url.password is not None:
            counts["message_link_credentials"] += 1
        try:
            ipaddress.ip_address(url.hostname)
            counts["message_link_ip_address"] += 1
        except ValueError:
            pass
        visible = _host(label.strip())
        if visible and visible.hostname.casefold().rstrip(".") != url.hostname.casefold().rstrip(
            "."
        ):
            counts["message_link_display_mismatch"] += 1

    stack = [(message, 0)]
    while stack:
        if visited >= MAX_PARTS:
            notices.add("Message MIME part limit reached; remaining parts unchecked.")
            break
        part, depth = stack.pop()
        visited += 1
        if part.defects:
            notices.add(
                "A selected MIME part has parser defects; interpretation may be incomplete."
            )
        try:
            filename = part.get_filename()
            attachment = filename is not None or part.get_content_disposition() == "attachment"
            kind = part.get_content_type()
            if attachment:
                # Filename/type only: attachment payloads and nested messages are not decoded.
                suffixes = PurePosixPath((filename or "").replace("\\", "/").lower()).suffixes
                active = bool(suffixes and suffixes[-1] in ACTIVE_EXTENSIONS)
                if active or kind in ACTIVE_TYPES:
                    counts["message_attachment_active_type"] += 1
                if active and len(suffixes) > 1 and suffixes[-2] in DISPLAY_EXTENSIONS:
                    counts["message_attachment_double_extension"] += 1
                notices.add(
                    "Attachment contents, archives and embedded messages "
                    "were not opened or scanned."
                )
                continue
            if part.get_content_maintype() == "message":
                notices.add("Embedded message bodies were not analyzed.")
                continue
            if part.is_multipart():
                if depth >= MAX_DEPTH:
                    notices.add("Message MIME depth limit reached; deeper parts unchecked.")
                else:
                    children = part.get_payload()
                    if len(children) > MAX_PARTS - visited - len(stack):
                        notices.add("Message MIME part limit reached; remaining parts unchecked.")
                    capacity = max(0, MAX_PARTS - visited - len(stack))
                    stack.extend((child, depth + 1) for child in reversed(children[:capacity]))
                continue
            if kind not in ("text/plain", "text/html"):
                notices.add("Non-text message body part skipped.")
                continue
            if text_parts >= MAX_TEXT_PARTS:
                notices.add("Message text-part limit reached; remaining text unchecked.")
                continue
            text_parts += 1
            raw = part.get_payload(decode=True)
            if part.defects:
                notices.add(
                    "A selected MIME part has parser defects; interpretation may be incomplete."
                )
            if not isinstance(raw, bytes):
                notices.add("Could not decode a selected message text part.")
                continue
            if decoded_bytes + len(raw) > MAX_TEXT_BYTES:
                notices.add("Message decoded-text byte limit reached; oversized text unchecked.")
                continue
            decoded_bytes += len(raw)
            text = raw.decode(part.get_content_charset() or "ascii", errors="strict")
            if kind == "text/html":
                from .html_review import inspect_html

                observed, gaps = inspect_html(text)
                remaining = MAX_HTML_FINDINGS - len(html_findings)
                if len(observed) > remaining:
                    notices.add("Message HTML finding limit reached; extra candidates omitted.")
                html_findings.extend(
                    AssessmentFinding(
                        "message_" + f.check,
                        f.status,
                        f"MIME text part {text_parts}; " + f.evidence,
                        f.recommendation,
                    )
                    for f in observed[:remaining]
                )
                notices.update(gaps)
                parser = _Anchors(observe)
                parser.feed(text)
                parser.finish()
            else:
                for match in LINK.finditer(text):
                    observe(match[0].rstrip(".,;!)}"))
                    if links >= MAX_LINKS:
                        notices.add(
                            "Message link limit reached; additional links may be unchecked."
                        )
                        break
        except (ValueError, UnicodeError, LookupError, TypeError, AttributeError, RecursionError):
            notices.add("Could not interpret a selected MIME part; values omitted.")
    findings = tuple(
        AssessmentFinding(
            check,
            "candidate",
            f"{counts[check]} {DESCRIPTIONS[check][0]}; values omitted.",
            DESCRIPTIONS[check][1],
        )
        for check in sorted(counts)
    )
    return (*findings, *html_findings), tuple(sorted(notices))
