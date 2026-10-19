"""Selected response-header candidates shared by passive HTTPS and offline captures."""

import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

from .assessment import AssessmentFinding, AssessmentResult
from .contracts import fields, read_document, version
from .models import ValidationError

MAX_HEADERS = 100
MAX_VALUE_BYTES = 16 * 1024
MAX_TOTAL_BYTES = 64 * 1024
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
COOKIE_VALUE = re.compile(r"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*")
NONCE_HASH = re.compile(r"'(?:nonce-|sha256-|sha384-|sha512-)[A-Za-z0-9+/_-]+=*'", re.I)
ACTIONS = {
    "cookie_missing_secure": (
        "Review which cookies carry sensitive state and add Secure where appropriate."
    ),
    "cookie_missing_httponly": (
        "Use HttpOnly for sensitive cookies that do not require JavaScript access."
    ),
    "cookie_missing_samesite": (
        "Choose an explicit SameSite policy that matches the application flow."
    ),
    "cookie_invalid_samesite": (
        "Review the unsupported SameSite value; browser fallback was not simulated."
    ),
    "cookie_none_without_secure": (
        "Review SameSite=None and Secure together; test the intended browser flow."
    ),
    "cookie_prefix_constraints": (
        "Review the Secure/Host prefix contract, including Path and Domain."
    ),
    "cookie_unparsed": (
        "Inspect the original Set-Cookie in a controlled workflow; this entry was not assessed."
    ),
    "cookie_ambiguous_attributes": (
        "Review duplicate/malformed cookie attributes; this entry was not assessed."
    ),
}


def _normalize(status, headers):
    if type(status) is not int or not 100 <= status <= 599:
        raise ValidationError("HTTP status must be an integer between 100 and 599")
    if not isinstance(headers, (list, tuple)) or len(headers) > MAX_HEADERS:
        raise ValidationError("At most 100 response header fields are supported")
    values, total = defaultdict(list), 0
    for item in headers:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ValidationError("Response headers must be name/value pairs")
        name, value = item
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 128
            or not TOKEN.fullmatch(name)
            or not isinstance(value, str)
            or any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in value)
        ):
            raise ValidationError("Invalid response header field; values omitted")
        try:
            size = len(value.encode("utf-8"))
        except UnicodeError:
            raise ValidationError("Invalid response header encoding; values omitted") from None
        total += len(name) + size
        if size > MAX_VALUE_BYTES or total > MAX_TOTAL_BYTES:
            raise ValidationError("Response headers exceed the 16 KiB field or 64 KiB total limit")
        values[name.lower()].append(value.strip())
    return values


def _cookie_observations(cookies):
    counts = Counter()
    for value in cookies:
        parts = value.split(";")
        name, separator, raw = parts[0].strip().partition("=")
        unquoted = raw[1:-1] if raw.startswith('"') and raw.endswith('"') else raw
        if not separator or not TOKEN.fullmatch(name) or not COOKIE_VALUE.fullmatch(unquoted):
            counts["cookie_unparsed"] += 1
            continue
        attributes, ambiguous = {}, False
        for part in parts[1:]:
            if not part.strip():
                continue
            key, _, item = part.strip().partition("=")
            key = key.lower()
            if not key or not TOKEN.fullmatch(key) or key in attributes:
                ambiguous = True
                break
            attributes[key] = item.strip()
        if ambiguous:
            counts["cookie_ambiguous_attributes"] += 1
            continue
        if "secure" not in attributes:
            counts["cookie_missing_secure"] += 1
        if "httponly" not in attributes:
            counts["cookie_missing_httponly"] += 1
        same_site = attributes.get("samesite", "").lower()
        if "samesite" not in attributes:
            counts["cookie_missing_samesite"] += 1
        elif same_site not in ("none", "lax", "strict"):
            counts["cookie_invalid_samesite"] += 1
        if same_site == "none" and "secure" not in attributes:
            counts["cookie_none_without_secure"] += 1
        if (name.startswith("__Secure-") and "secure" not in attributes) or (
            name.startswith("__Host-")
            and (
                "secure" not in attributes
                or "domain" in attributes
                or attributes.get("path") != "/"
            )
        ):
            counts["cookie_prefix_constraints"] += 1
    return [
        AssessmentFinding(
            check,
            "candidate",
            f"{count} selected Set-Cookie fields match this "
            "metadata pattern; names and values omitted.",
            ACTIONS[check],
        )
        for check, count in sorted(counts.items())
    ]


def inspect_response_headers(status, headers):
    values = _normalize(status, headers)
    missing = [
        "Header checks cover one supplied response; redirects and bodies "
        "are outside header-only checks.",
        "No exploitation, authentication, crawling, injection or business-logic testing.",
        "Header observations do not establish effective browser behavior or secure configuration.",
        "Cookie purpose, expiry/session state and browser defaults were not inferred. "
        "Preference and deletion cookies can legitimately need different policies.",
        "CSP intersection, meta policies, nonces/hashes, redirects and browser execution "
        "were not validated; selected literal patterns only.",
    ]
    findings = []

    def add(check, evidence, action):
        findings.append(AssessmentFinding(check, "candidate", evidence, action))

    if status != 200:
        missing.append(f"HTTP {status}; response security checks were not performed.")
        return (), tuple(missing)
    for header, action in (
        ("strict-transport-security", "Review and enable an appropriate HSTS policy."),
        ("content-security-policy", "Define and test a restrictive content security policy."),
        ("x-content-type-options", "Set X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Define a privacy-appropriate referrer policy."),
    ):
        if not any(values[header]):
            add("missing_" + header, f"{header} absent in this response", action)
        if len(values[header]) > 1 and header != "content-security-policy":
            add(
                "duplicate_security_header",
                f"Repeated {header} fields; values omitted.",
                "Review the exact response and browser/header-specific duplicate handling.",
            )
    if (
        values["x-content-type-options"]
        and values["x-content-type-options"][0].lower() != "nosniff"
    ):
        add(
            "invalid_nosniff",
            "Unexpected MIME-sniffing header value",
            "Set X-Content-Type-Options to nosniff.",
        )
    hsts = values["strict-transport-security"][0] if values["strict-transport-security"] else ""
    if hsts and not re.search(r"(?:^|;)\s*max-age\s*=\s*[1-9][0-9]*(?:\s*;|\s*$)", hsts, re.I):
        add("weak_hsts", "HSTS has no positive max-age", "Review the effective HSTS policy.")
    csp_patterns = set()
    policies = values["content-security-policy"]
    if len(policies) > 1:
        missing.append(
            "Multiple enforcing CSP fields were inspected separately; intersection unverified."
        )
    for policy in policies:
        if "," in policy:
            missing.append(
                "Comma-combined CSP policy was not semantically inspected; values omitted."
            )
            continue
        directives = {}
        for declaration in policy.split(";"):
            tokens = declaration.split()
            if tokens:
                key = tokens[0].lower()
                if key in directives:
                    missing.append("Duplicate CSP directives detected; first occurrence selected.")
                else:
                    directives[key] = tokens[1:]
        script = directives.get("script-src", directives.get("default-src", []))
        lowered = {token.lower() for token in script}
        has_nonce_hash = any(NONCE_HASH.fullmatch(token) for token in script)
        if "'unsafe-eval'" in lowered:
            csp_patterns.add("csp_script_unsafe_eval")
        if "'unsafe-inline'" in lowered and not has_nonce_hash:
            if "script-src-elem" in directives or "script-src-attr" in directives:
                missing.append(
                    "Split CSP script directives were not evaluated for inline behavior."
                )
            else:
                csp_patterns.add("csp_script_unsafe_inline")
        if "*" in lowered and not (has_nonce_hash and "'strict-dynamic'" in lowered):
            csp_patterns.add("csp_script_wildcard")
    for check in sorted(csp_patterns):
        add(
            check,
            "An inspected enforcing CSP declares this selected script-source pattern; "
            "policy values omitted. Other policies may restrict it.",
            "Review effective policies, nonce/hash handling and browser compatibility; "
            "test a restrictive script policy against the application.",
        )
    findings.extend(_cookie_observations(values["set-cookie"]))
    return tuple(findings), tuple(dict.fromkeys(missing))


def audit_header_capture(path):
    path = Path(path)
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)() or not path.is_file():
        raise ValidationError("Header capture must be a regular file without links")
    capture = read_document(path)
    fields(capture, {"schema_version", "url", "status", "headers"})
    version(capture)
    try:
        url = urlsplit(capture["url"]) if isinstance(capture["url"], str) else None
        if (
            url is None
            or url.scheme != "https"
            or not url.hostname
            or url.port not in (None, 443)
            or url.username is not None
            or url.password is not None
            or url.fragment
            or re.search(r"[\x00-\x20\x7f]", capture["url"])
        ):
            raise ValueError
    except ValueError:
        raise ValidationError(
            "Capture requires an HTTPS URL without credentials or fragment"
        ) from None
    findings, missing = inspect_response_headers(capture["status"], capture["headers"])
    return AssessmentResult(
        str(path),
        "http_response_headers",
        "partial",
        findings,
        (
            "Offline capture is caller supplied; origin, freshness and authenticity "
            "are unverified. "
            "The declared URL was not fetched and is omitted from the report.",
            *missing,
        ),
    )
