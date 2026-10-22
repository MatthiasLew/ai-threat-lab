"""Review decoded MIME attachment bytes in memory, without extracting or opening files."""

import json
import re
from dataclasses import asdict
from email import policy
from email.parser import BytesParser

from .assessment import AssessmentFinding, AssessmentResult
from .audit_report import merge_reports
from .binary_audit import inspect_binary
from .models import ValidationError
from .report_io import read_regular

MAX_MESSAGE = 8 * 1024 * 1024
MAX_ATTACHMENT = 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024
NOTICE = (
    "Offline attachment bytes only; sender, MIME claims, authenticity and malware status "
    "are unverified. No attachment is written, opened, executed or decompressed. "
    "Filenames, addresses, message text and attachment contents are omitted."
)


def selected_parts(message):
    """Bound the traversal independently of MIME filenames and recursive walk()."""
    pending = [(message, 0)]
    selected, gaps, visited = [], [], 0
    while pending:
        part, depth = pending.pop()
        visited += 1
        if visited > 100:
            gaps.append("MIME part limit reached; remaining parts unchecked.")
            break
        if depth > 8:
            gaps.append("MIME depth limit reached; nested parts unchecked.")
            continue
        if part.get_content_maintype() == "message":
            gaps.append("Encapsulated message parts are not traversed.")
            continue
        if part.is_multipart():
            if part.defects:
                gaps.append("Multipart parsing defects; attachment completeness is unverified.")
            children = part.get_payload()
            if not isinstance(children, list):
                gaps.append("Malformed multipart container unchecked.")
                continue
            pending.extend((child, depth + 1) for child in reversed(children[:101]))
            if len(children) > 101:
                gaps.append("Multipart child limit reached; remaining children unchecked.")
            continue
        if part.get_content_disposition() == "attachment" or part.get_filename() is not None:
            selected.append((visited, part))
    return selected, tuple(dict.fromkeys(gaps))


def decoded_attachment(part):
    if part.defects:
        raise ValidationError("MIME attachment has parsing defects; bytes unchecked.")
    encodings = part.get_all("Content-Transfer-Encoding", [])
    if len(encodings) > 1:
        raise ValidationError("Duplicate attachment transfer encoding; bytes unchecked.")
    encoding = str(encodings[0]).strip().lower() if encodings else "7bit"
    if encoding not in ("base64", "quoted-printable", "7bit", "8bit", "binary"):
        raise ValidationError("Unsupported attachment transfer encoding; bytes unchecked.")
    payload = part.get_payload()
    if not isinstance(payload, str) or len(payload) > 2 * MAX_ATTACHMENT:
        raise ValidationError("Encoded attachment exceeds the review bound.")
    if encoding == "quoted-printable" and re.search(r"=(?![0-9A-Fa-f]{2}|\r?\n)", payload):
        raise ValidationError("Malformed quoted-printable attachment; bytes unchecked.")
    # The parser records malformed base64 defects during decoding.
    raw = part.get_payload(decode=True)
    if part.defects or not isinstance(raw, bytes):
        raise ValidationError("Malformed attachment encoding; bytes unchecked.")
    if len(raw) > MAX_ATTACHMENT:
        raise ValidationError("Decoded attachment exceeds the 1 MiB review bound.")
    if encoding == "7bit" and any(byte > 127 for byte in raw):
        raise ValidationError("Attachment contradicts its 7bit encoding; bytes unchecked.")
    return raw


def _selection(start, max_entries):
    if type(start) is not int or start < 1:
        raise ValidationError("Attachment start must be a positive integer")
    if type(max_entries) is not int or not 1 <= max_entries <= 20:
        raise ValidationError("Review between 1 and 20 attachments at a time")


def review_message_attachments(message, *, start=1, max_entries=20):
    """Reuse an already parsed MIME message so a normal scan needs no second file read."""
    _selection(start, max_entries)
    try:
        parts, gaps = selected_parts(message)
    except (RecursionError, ValueError, UnicodeError):
        raise ValidationError("Malformed or unsupported MIME structure") from None
    if message.defects:
        gaps = (*gaps, "Top-level MIME parsing defects; capture completeness is unverified.")
    if not parts:
        if start != 1:
            raise ValidationError("Attachment start is beyond the saved message")
        result = AssessmentResult(
            "Saved message attachments",
            "mail_attachments",
            "partial",
            (),
            (NOTICE, *gaps, "No eligible attachment parts selected."),
        )
        return [result], 0
    if start > len(parts):
        raise ValidationError("Attachment start is beyond the saved message")
    stop = min(start + max_entries - 1, len(parts))
    results, failures, total = [], 0, 0
    for index in range(start, stop + 1):
        part_index, part = parts[index - 1]
        target = f"Attachment {index:04d} (MIME part {part_index:04d})"
        limits = (
            NOTICE,
            *gaps,
            f"Selected attachments {start}..{stop} of {len(parts)} discovered; "
            "other attachments unchecked.",
        )
        try:
            raw = decoded_attachment(part)
            if total + len(raw) > MAX_TOTAL:
                raise ValidationError("Total decoded attachment review exceeds 4 MiB.")
            total += len(raw)
            inspected = inspect_binary(raw, target)
            result = AssessmentResult(
                target,
                "mail_attachment",
                "partial",
                inspected.findings,
                (*limits, *inspected.not_checked),
            )
        except ValidationError as error:
            failures += 1
            result = AssessmentResult(
                target, "mail_attachment", "not_configured", (), (*limits, str(error))
            )
        results.append(result)
    return results, failures


def inspect_message_attachments(message):
    results, failures = review_message_attachments(message)
    findings, missing = [], []
    for result in results:
        findings.extend(
            AssessmentFinding(
                finding.check,
                finding.status,
                f"{result.target}: {finding.evidence}",
                finding.recommendation,
            )
            for finding in result.findings
        )
        missing.extend(result.not_checked)
    if failures:
        missing.append(f"Attachment sub-review failures: {failures}; other evidence retained.")
    return tuple(findings), tuple(dict.fromkeys(missing))


def review_attachments(path, *, start=1, max_entries=20):
    _selection(start, max_entries)
    try:
        message = BytesParser(policy=policy.default).parsebytes(read_regular(path, MAX_MESSAGE))
    except (RecursionError, ValueError, UnicodeError, IndexError):
        raise ValidationError("Malformed or unsupported MIME structure") from None
    results, failures = review_message_attachments(message, start=start, max_entries=max_entries)
    return merge_reports(json.loads(json.dumps([asdict(result) for result in results]))), failures
