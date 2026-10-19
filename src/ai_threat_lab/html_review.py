"""Bounded HTML authoring observations; never render, fetch, submit or execute content."""

import ipaddress
import os
import re
import stat
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .assessment import AssessmentFinding, AssessmentResult
from .models import ValidationError

MAX_BYTES = 256 * 1024
MAX_ELEMENTS = 5000
MAX_FORMS = 100
MAX_ATTRIBUTES = 100
MAX_URL = 4096
MAX_FINDINGS = 200
NOTICE = (
    "Static HTML subset only; no rendering, JavaScript, requests, form submission, CSP/browser "
    "enforcement, authentication, CSRF, reachability or exploitability validation."
)
ACTIONS = {
    "html_password_form_get": "Review credential submission method and URL logging; prefer POST.",
    "html_password_form_http": "Protect credential submission with authenticated HTTPS.",
    "html_password_form_cross_origin": "Verify the credential recipient.",
    "html_mixed_active_content": "Use HTTPS resources and test effective browser/CSP policy.",
    "html_external_script_without_integrity": "Review external script trust and integrity.",
}


def http_url(value):
    if not isinstance(value, str) or not value or len(value) > MAX_URL:
        return None
    if "\\" in value or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        return None
    try:
        url = urlsplit(value)
        if url.scheme.lower() not in ("http", "https") or not url.hostname:
            return None
        _ = url.port
        host = url.hostname
        if not host.isascii() or "%" in host:
            return None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or any(
                not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in host.rstrip(".").split(".")
            ):
                return None
        return url
    except ValueError:
        return None


def origin(url):
    host = url.hostname.lower()
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    return (
        url.scheme.lower(),
        host,
        url.port if url.port is not None else (443 if url.scheme.lower() == "https" else 80),
    )


@dataclass
class Form:
    line: int
    action: str
    method: str
    password: bool = False
    uncertain: bool = False


class HTMLLimit(ValueError):
    pass


class Page(HTMLParser):
    CDATA_CONTENT_ELEMENTS = (
        "script",
        "style",
        "textarea",
        "title",
        "xmp",
        "iframe",
        "noembed",
        "noframes",
    )

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.plaintext = False
        self.elements = 0
        self.forms = []
        self.form_stack = []
        self.resources = []
        self.base = None
        self.base_seen = False
        self.base_invalid = False
        self.ignored = []
        self.external_owners = False
        self.notices = set()

    def handle_starttag(self, tag, attributes):
        if self.plaintext:
            return
        if tag == "plaintext":
            self.plaintext = True
            self.notices.add("Plaintext remainder unchecked as markup.")
            return
        self.elements += 1
        if self.elements > MAX_ELEMENTS or len(attributes) > MAX_ATTRIBUTES:
            raise HTMLLimit
        if self.ignored:
            if tag in ("template", "svg", "math", "noscript"):
                self.ignored.append(tag)
            return
        if tag in ("template", "svg", "math", "noscript"):
            self.ignored.append(tag)
            self.notices.add("Template, foreign and noscript subtrees unchecked.")
            return
        if tag in ("table", "select"):
            self.external_owners = True
            self.notices.add("Table/select tree-repair contexts leave form checks unresolved.")
        attrs = dict(attributes)
        duplicate = len(attrs) != len(attributes)
        if duplicate:
            self.notices.add("Duplicate attributes leave the affected element unchecked.")
            if self.form_stack:
                self.forms[self.form_stack[-1]].uncertain = True
            if tag == "base" and not self.base_seen and "href" in attrs:
                self.base_seen, self.base_invalid = True, True
            if tag != "form":
                return
        line = self.getpos()[0]
        if tag == "base" and "href" in attrs and not self.base_seen:
            self.base_seen = True
            self.base = attrs["href"]
        if tag == "form":
            if len(self.forms) >= MAX_FORMS:
                raise HTMLLimit
            nested = bool(self.form_stack)
            for index in self.form_stack:
                self.forms[index].uncertain = True
            form = Form(
                line,
                attrs.get("action") or "",
                (attrs.get("method") or "get").lower(),
                uncertain=nested or duplicate,
            )
            self.forms.append(form)
            self.form_stack.append(len(self.forms) - 1)
            if nested:
                self.notices.add("Nested forms unchecked; HTML tree repair was not simulated.")
        if "form" in attrs:
            self.external_owners = True
            self.notices.add(
                "Explicit form-owner associations unchecked; form-dependent candidates omitted."
            )
        if self.form_stack:
            form = self.forms[self.form_stack[-1]]
            if tag == "fieldset" or "formaction" in attrs or "formmethod" in attrs:
                form.uncertain = True
                self.notices.add("Fieldset and submitter-override form effects unchecked.")
            if (
                tag == "input"
                and (attrs.get("type") or "").lower() == "password"
                and attrs.get("name")
                and "disabled" not in attrs
            ):
                form.password = True
        if tag == "script" and attrs.get("src"):
            if (attrs.get("type") or "").lower() in (
                "",
                "module",
                "text/javascript",
                "application/javascript",
                "text/ecmascript",
                "application/ecmascript",
            ):
                self.resources.append(
                    (line, attrs["src"], bool((attrs.get("integrity") or "").strip()), True)
                )
            else:
                self.notices.add("Non-JavaScript script types unchecked.")
        elif tag == "iframe" and attrs.get("src") and "srcdoc" not in attrs:
            self.resources.append((line, attrs["src"], False, False))
        elif (
            tag == "link"
            and "stylesheet" in (attrs.get("rel") or "").lower().split()
            and attrs.get("href")
        ):
            self.resources.append((line, attrs["href"], False, False))
        if "srcset" in attrs or "srcdoc" in attrs:
            self.notices.add("Srcset and srcdoc contents unchecked.")

    def handle_endtag(self, tag):
        if self.plaintext:
            return
        if self.ignored:
            if tag == self.ignored[-1]:
                self.ignored.pop()
            return
        if tag == "form":
            if self.form_stack:
                self.form_stack.pop()
            else:
                self.notices.add("Unmatched form end tag; tree repair unchecked.")

    def handle_startendtag(self, tag, attrs):
        if len(attrs) > MAX_ATTRIBUTES:
            raise HTMLLimit
        if tag in ("form", "template", "svg", "math", "noscript", "table", "select"):
            # A browser does not necessarily close these elements at '/>'. Do not
            # let a different parser tree create candidates from inert/fallback text.
            raise HTMLLimit
        self.handle_starttag(tag, attrs)
        if tag in self.CDATA_CONTENT_ELEMENTS:
            self.set_cdata_mode(tag)


def inspect_html(source, *, document_url=None):
    if not isinstance(source, str):
        raise ValidationError("HTML input must be text")
    try:
        if len(source.encode("utf-8")) > MAX_BYTES:
            raise ValidationError("HTML input exceeds the 256 KiB limit")
    except UnicodeError:
        raise ValidationError("Invalid HTML text encoding; values omitted") from None
    document = None
    if document_url is not None:
        document = http_url(document_url)
        if document is None or document.username is not None or document.password is not None:
            raise ValidationError(
                "Document URL requires bounded ASCII-host HTTP(S) without credentials"
            )
    page = Page()
    try:
        page.feed(source)
        page.close()
    except (HTMLLimit, RecursionError, ValueError):
        return (), (
            NOTICE,
            "HTML structural/attribute/form limit, unsupported self-closing container "
            "or parser failure; candidates omitted.",
        )
    notices = page.notices
    if page.form_stack:
        for index in page.form_stack:
            page.forms[index].uncertain = True
        notices.add("Unclosed form bodies unchecked.")
    if document is None:
        notices.add(
            "Document URL absent; relative destinations, secure-page context "
            "and origin comparisons unchecked."
        )
    base = document_url
    if page.base_seen:
        if page.base_invalid or not isinstance(page.base, str) or len(page.base) > MAX_URL:
            base = None
        else:
            try:
                base = urljoin(document_url or "", page.base)
            except ValueError:
                base = None
            if http_url(base) is None:
                base = None
        if base is None:
            notices.add("First base URL unsupported; relative destinations unchecked.")

    def resolve(value):
        value = value.strip()
        if (
            len(value) > MAX_URL
            or "\\" in value
            or any(ord(c) <= 32 or ord(c) == 127 for c in value)
        ):
            notices.add("Unsupported URL syntax/length; destination omitted.")
            return None
        try:
            result = http_url(urljoin(base or "", value))
        except ValueError:
            result = None
        if result is None:
            notices.add("Non-HTTP or unresolved destination unchecked; values omitted.")
        return result

    findings = []
    seen = set()

    def add(check, line):
        if (check, line) in seen:
            return
        seen.add((check, line))
        if len(findings) >= MAX_FINDINGS:
            notices.add("HTML finding limit reached; additional candidates omitted.")
            return
        findings.append(
            AssessmentFinding(
                check,
                "candidate",
                f"HTML line {line}: selected authoring pattern; values omitted. "
                "Runtime behavior and applicability unverified.",
                ACTIONS[check],
            )
        )

    for form in page.forms:
        if form.uncertain or page.external_owners or not form.password:
            continue
        if form.method == "dialog":
            continue
        if form.method not in ("get", "post"):
            notices.add("Unsupported form method unchecked; values omitted.")
            continue
        # Empty/missing action uses the document URL, not the base href.
        action = resolve(form.action) if form.action.strip() else document
        if action is None:
            notices.add("Form destination unavailable; dependent candidates omitted.")
            continue
        if form.method == "get":
            add("html_password_form_get", form.line)
        if action.scheme.lower() == "http":
            add("html_password_form_http", form.line)
        if document is not None and origin(action) != origin(document):
            add("html_password_form_cross_origin", form.line)
    for line, value, integrity, script in page.resources:
        url = resolve(value)
        if url is None or document is None:
            continue
        if document.scheme.lower() == "https" and url.scheme.lower() == "http":
            add("html_mixed_active_content", line)
        if script and origin(document) != origin(url) and not integrity:
            add("html_external_script_without_integrity", line)
    return tuple(findings), (
        NOTICE,
        *sorted(notices),
        "Declared integrity values, CSS URLs, DOM mutations "
        "and browser URL normalization are unverified.",
    )


def inspect_html_response(body, headers, *, document_url):
    types = [v for k, v in headers if k.lower() == "content-type"]
    encodings = [v for k, v in headers if k.lower() == "content-encoding"]
    if len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != "text/html":
        return (), ("Response is not unambiguously declared text/html; body unchecked.",)
    parts = types[0].split(";")
    if (
        len(parts) > 2
        or (
            len(parts) == 2
            and not re.fullmatch(r'charset\s*=\s*(?:utf-8|"utf-8")', parts[1].strip(), re.I)
        )
        or len(encodings) > 1
        or any(value.strip().lower() != "identity" for value in encodings)
    ):
        return (), ("HTML body encoding/charset unsupported; body unchecked.",)
    if not isinstance(body, bytes) or len(body) > MAX_BYTES:
        return (), ("HTML body size/encoding unsupported; body unchecked.",)
    try:
        return inspect_html(body.decode("utf-8-sig"), document_url=document_url)
    except (UnicodeError, ValidationError):
        return (), ("HTML body size/encoding unsupported; body unchecked.",)


def review_html_file(path, *, document_url=None):
    path = Path(path)
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)() or not path.is_file():
        raise ValidationError("HTML target must be a regular file without links")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValidationError("HTML target must be a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(MAX_BYTES + 1)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > MAX_BYTES:
        raise ValidationError("HTML input exceeds the 256 KiB limit")
    try:
        source = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ValidationError("HTML requires UTF-8 text; values omitted") from None
    findings, missing = inspect_html(source, document_url=document_url)
    return AssessmentResult(str(path), "html_document", "partial", findings, missing)
