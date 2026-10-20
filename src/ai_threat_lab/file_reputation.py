"""Explicit SHA-256 reputation lookup; no upload, rescan or execution."""

import hashlib
import os
import re
from datetime import datetime, timezone

from .assessment import AssessmentFinding, AssessmentResult
from .binary_audit import MAX_BINARY_BYTES, inspect_binary
from .models import ValidationError
from .providers import ProviderError
from .report_io import read_regular

HOST = "www.virustotal.com"
STATS = frozenset({
    "confirmed-timeout", "failure", "harmless", "malicious", "suspicious",
    "timeout", "type-unsupported", "undetected",
})
NOTICE = (
    "Provider counts are historical third-party claims, not verified malware conclusions. "
    "No detections or no record does not establish safety. No file upload, execution or "
    "rescan occurs. A hash can identify a private file and is not anonymization."
)


def capture(path):
    return read_regular(path, MAX_BINARY_BYTES,
                        limit_message="Reputation file exceeds the 16 MiB limit")


def preview(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_BINARY_BYTES:
        raise ValidationError("Reputation input must be bytes within the 16 MiB limit")
    digest = hashlib.sha256(raw).hexdigest()
    return {
        "schema_version": 1, "mode": "file_reputation_preview", "sha256": digest,
        "bytes": len(raw), "host": HOST, "method": "GET",
        "url": f"https://{HOST}/api/v3/files/{digest}",
        "network_called": False, "credentials_inspected": False,
        "data_disclosure": "Only the SHA-256 is sent as the resource identifier, "
                           "with the account API key in the x-apikey header.",
        "remaining_setup": "Configure VIRUSTOTAL_API_KEY outside source control; "
                           "verify account permissions, terms and request quota.",
        "notice": NOTICE,
    }


def _statistics(document, digest, size, current):
    try:
        data = document["data"]
        attrs = data["attributes"]
        stats, stamp = attrs["last_analysis_stats"], attrs["last_analysis_date"]
        if (data["type"] != "file" or data["id"] != digest or attrs["sha256"] != digest
                or type(attrs["size"]) is not int or attrs["size"] != size
                or type(stamp) is not int or not 0 < stamp <= current.timestamp() + 300
                or not isinstance(stats, dict) or set(stats) != STATS
                or any(type(v) is not int or not 0 <= v <= 10000 for v in stats.values())
                or not 0 < sum(stats.values()) <= 10000):
            raise ValueError
        analyzed = datetime.fromtimestamp(stamp, timezone.utc).isoformat()
    except (KeyError, TypeError, ValueError, OverflowError, OSError, AttributeError):
        raise ProviderError("Reputation response identity or statistics are unavailable") from None
    return stats, analyzed


def review(raw, *, expected_sha256, network, share_hash, allowed_host, client, now=None):
    prepared = preview(raw)
    if network is not True or share_hash is not True or allowed_host != HOST:
        raise ValidationError("Reputation requires explicit network, hash sharing and exact host")
    digest = prepared["sha256"]
    if (not isinstance(expected_sha256, str)
            or not re.fullmatch("[0-9a-f]{64}", expected_sha256)
            or expected_sha256 != digest):
        raise ValidationError("File bytes no longer match the reviewed SHA-256")
    current = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise ValidationError("Reputation time must be timezone-aware")
    credential = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not credential or len(credential) > 512 or any(
        not 33 <= ord(char) <= 126 for char in credential
    ):
        raise ProviderError("VIRUSTOTAL_API_KEY is missing or invalid; no request was sent")
    local = inspect_binary(raw, "Selected file")
    findings, gaps = list(local.findings), [*local.not_checked, NOTICE]
    failed = False
    try:
        response = client.request(prepared["url"], headers={"x-apikey": credential})
        if response.status == 404:
            gaps.append("Provider returned no file record for this SHA-256; reputation unknown.")
        elif response.status != 200:
            raise ProviderError("Reputation service did not return a usable response")
        else:
            stats, analyzed = _statistics(response.document(), digest, len(raw), current)
            counts = "; ".join(f"{key}={stats[key]}" for key in sorted(stats))
            findings.append(AssessmentFinding(
                "file_reputation_counts", "unverified",
                f"VirusTotal SHA-256={digest}; last_analysis_utc={analyzed}; {counts}",
                "Review the dated provider result and independent evidence; engine counts "
                "are not a probability of malware or proof that the file is safe.",
            ))
    except (ProviderError, OSError):
        failed = True
        gaps.append("Reputation lookup failed or returned unsupported evidence. "
                    "Local file observations retained; no automatic retry.")
    return AssessmentResult("Selected file", "program_file", "partial",
                            tuple(findings), tuple(gaps)), failed
