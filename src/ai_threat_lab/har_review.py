"""Offline HAR response review without replaying requests or exposing captured secrets."""

import base64
import binascii
import json
from dataclasses import asdict

from .assessment import AssessmentResult
from .audit_report import merge_reports
from .header_review import inspect_response_headers
from .html_review import MAX_BYTES, http_url, inspect_html_response
from .models import ValidationError
from .report_io import read_regular
from .scan_bundle import document

NOTICE = (
    "Offline HAR claims only: origin, completeness, freshness, authentication and "
    "browser behavior are unverified. No requests are replayed. Request headers, "
    "cookies, bodies, URL values and response body/header values are not exported."
)


def response_body(content):
    if not isinstance(content, dict) or not isinstance(content.get("text"), str):
        return None, "HAR response body was not captured."
    text = content["text"]
    if len(text) > MAX_BYTES * 2:
        return None, "HAR response body exceeds the review bound."
    try:
        encoding = content.get("encoding")
        if encoding == "base64":
            body = base64.b64decode(text, validate=True)
        elif encoding is None:
            body = text.encode("utf-8")
        else:
            return None, "HAR response body encoding is unsupported."
    except (UnicodeError, binascii.Error, ValueError):
        return None, "HAR response body encoding is invalid."
    if len(body) > MAX_BYTES:
        return None, "HAR response body exceeds the review bound."
    size = content.get("size")
    if type(size) is not int or size != len(body):
        return None, "HAR declared body size differs from captured UTF-8 bytes; body unchecked."
    return body, None


def review_entry(entry, index):
    target = f"HAR entry {index:04d}"
    try:
        if not isinstance(entry, dict):
            raise ValidationError("Invalid HAR entry")
        request, response = entry.get("request"), entry.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            raise ValidationError("Invalid HAR request/response")
        url = http_url(request.get("url"))
        if url is None or url.scheme.lower() != "https" or url.username or url.password:
            raise ValidationError("Unsupported HAR URL")
        rows = response.get("headers")
        if not isinstance(rows, list) or len(rows) > 100:
            raise ValidationError("Invalid HAR response headers")
        headers = []
        for row in rows:
            if not isinstance(row, dict):
                raise ValidationError("Invalid HAR header")
            headers.append((row.get("name"), row.get("value")))
        findings, missing = inspect_response_headers(response.get("status"), headers)
        body, gap = response_body(response.get("content"))
        html_findings, html_missing = (), ()
        if response["status"] != 200:
            html_missing = ("Non-200 HAR response body unchecked.",)
        elif gap:
            html_missing = (gap,)
        else:
            # HAR text is already decoded by the exporter. Do not decompress any data.
            # A compressed Content-Encoding conservatively suppresses HTML checks.
            html_findings, html_missing = inspect_html_response(
                body, headers, document_url=request["url"])
        return AssessmentResult(target, "har_response", "partial",
                                (*findings, *html_findings),
                                (NOTICE, *missing, *html_missing)), False
    except (ValidationError, UnicodeError, ValueError):
        return AssessmentResult(target, "har_response", "not_configured", (), (
            NOTICE, "Malformed or unsupported HAR entry; values omitted.",
        )), True


def review_har(path, *, start=1, max_entries=20):
    if type(start) is not int or start < 1:
        raise ValidationError("HAR entry start must be a positive integer")
    if type(max_entries) is not int or not 1 <= max_entries <= 20:
        raise ValidationError("Review between 1 and 20 HAR entries at a time")
    capture = document(read_regular(path, 8 * 1024 * 1024))
    log = capture.get("log")
    if not isinstance(log, dict) or log.get("version") != "1.2":
        raise ValidationError("Expected a HAR 1.2 log")
    entries = log.get("entries")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 200:
        raise ValidationError("HAR requires between 1 and 200 entries")
    if start > len(entries):
        raise ValidationError("HAR entry start is beyond the saved capture")
    results, failures = [], 0
    stop = min(start + max_entries - 1, len(entries))
    for index in range(start, stop + 1):
        result, failed = review_entry(entries[index - 1], index)
        failures += failed
        result = AssessmentResult(
            result.target, result.target_kind, result.status, result.findings,
            (*result.not_checked,
             f"Selected HAR entries {start}..{stop} of {len(entries)}; other entries unchecked."),
        )
        results.append(asdict(result))
    return merge_reports(json.loads(json.dumps(results))), failures
