"""Bounded ZIP directory/local-header metadata; no member extraction or decompression."""

import io
import re
import stat
import struct
import unicodedata
import zipfile
from collections import defaultdict

from .assessment import AssessmentFinding

MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 1000
MAX_DIRECTORY_BYTES = 512 * 1024
MAX_NAME = 4096
MAX_DECLARED_BYTES = 100 * 1024 * 1024
NOTICE = (
    "ZIP metadata only; no extraction, decompression, CRC/password verification, signature trust, "
    "payload/malware analysis, nested archive or extractor-specific behavior validation."
)
ACTIONS = {
    "zip_path_escape": "Reject unsafe extraction paths and enforce destination containment.",
    "zip_duplicate_entries": "Reject duplicate names before processing or extracting members.",
    "zip_portability_collision": "Review case/normalization collisions for the chosen platform.",
    "zip_platform_ambiguous_path": "Review reserved names, streams and trailing dots/spaces.",
    "zip_control_filename": "Reject control characters in archive member names.",
    "zip_symlink_entry": "Apply an explicit symbolic-link policy before extraction.",
    "zip_declared_expansion": "Set extraction byte/ratio limits; declared sizes are not verified.",
}


class ArchiveFormatError(ValueError):
    pass


def central_bounds(raw):
    end = raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557))
    if end < 0 or end + 22 > len(raw):
        raise ArchiveFormatError("ZIP end record unavailable")
    _, disk, directory_disk, local_count, count, size, offset, comment = struct.unpack_from(
        "<4s4H2IH", raw, end
    )
    if end + 22 + comment != len(raw):
        raise ArchiveFormatError("ZIP end/comment range unsupported")
    if disk or directory_disk or local_count != count:
        raise ArchiveFormatError("Split ZIP archives unsupported")
    if (
        count == 0xFFFF
        or size == 0xFFFFFFFF
        or offset == 0xFFFFFFFF
        or (end >= 20 and raw[end - 20 : end - 16] == b"PK\x06\x07")
    ):
        raise ArchiveFormatError("ZIP64 archives unsupported")
    if count > MAX_ENTRIES or size > MAX_DIRECTORY_BYTES:
        raise ArchiveFormatError("ZIP directory entry/byte limit reached")
    if offset + size != end or offset < 0:
        raise ArchiveFormatError("ZIP directory range unsupported")
    return offset, count


def zip_metadata(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_ARCHIVE_BYTES:
        raise ArchiveFormatError("ZIP input must be bytes within the 16 MiB limit")
    directory, count = central_bounds(raw)
    observations = defaultdict(list)
    exact, portable, ranges = set(), {}, []
    total = encrypted = 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw), mode="r") as archive:
            entries = archive.infolist()
            if len(entries) != count:
                raise ArchiveFormatError("ZIP directory count mismatch")
            for index, entry in enumerate(entries):
                name = entry.orig_filename
                if len(name) > MAX_NAME:
                    raise ArchiveFormatError("ZIP member-name limit reached")
                offset = entry.header_offset
                if (
                    offset < 0
                    or offset + 30 > directory
                    or raw[offset : offset + 4] != b"PK\x03\x04"
                ):
                    raise ArchiveFormatError("ZIP local-header range unsupported")
                flags, method = struct.unpack_from("<HH", raw, offset + 6)
                name_size, extra_size = struct.unpack_from("<HH", raw, offset + 26)
                start = offset + 30 + name_size + extra_size
                stop = start + entry.compress_size
                if start > directory or stop > directory or stop < start:
                    raise ArchiveFormatError("ZIP member-data range unsupported")
                local_name = raw[offset + 30 : offset + 30 + name_size].decode(
                    "utf-8" if flags & 0x800 else "cp437"
                )
                if (
                    name != local_name
                    or method != entry.compress_type
                    or (flags ^ entry.flag_bits) & 0x809
                ):
                    raise ArchiveFormatError("ZIP local/directory metadata mismatch")
                if not flags & 8:
                    crc, compressed, expanded = struct.unpack_from("<III", raw, offset + 14)
                    if (crc, compressed, expanded) != (
                        entry.CRC,
                        entry.compress_size,
                        entry.file_size,
                    ):
                        raise ArchiveFormatError("ZIP size/CRC metadata mismatch or ZIP64 layout")
                ranges.append((offset, stop))
                total += entry.file_size
                encrypted += bool(entry.flag_bits & 1)
                if any(ord(c) < 32 or ord(c) == 127 for c in name):
                    observations["zip_control_filename"].append(index)
                normalized = name.replace("\\", "/")
                parts = normalized.split("/")
                if (
                    normalized.startswith("/")
                    or re.match(r"^[A-Za-z]:", normalized)
                    or ".." in parts
                ):
                    observations["zip_path_escape"].append(index)
                if any(
                    ":" in part
                    or part.endswith((".", " "))
                    or re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part, re.I)
                    for part in parts
                    if part
                ):
                    observations["zip_platform_ambiguous_path"].append(index)
                if name in exact:
                    observations["zip_duplicate_entries"].append(index)
                exact.add(name)
                key = "/".join(
                    unicodedata.normalize("NFC", part).casefold().rstrip(". ")
                    for part in parts
                    if part not in ("", ".")
                )
                if key in portable and portable[key] != name:
                    observations["zip_portability_collision"].append(index)
                portable[key] = name
                if entry.create_system == 3 and stat.S_ISLNK(entry.external_attr >> 16):
                    observations["zip_symlink_entry"].append(index)
                if entry.file_size > 1024 * 1024 and entry.file_size > 100 * max(
                    1, entry.compress_size
                ):
                    observations["zip_declared_expansion"].append(index)
    except (zipfile.BadZipFile, UnicodeError, struct.error, NotImplementedError, OverflowError):
        raise ArchiveFormatError("ZIP metadata is malformed or unsupported") from None
    ranges.sort()
    if (ranges and ranges[0][0] != 0) or (not ranges and directory != 0):
        raise ArchiveFormatError("ZIP prefixed layouts unsupported")
    if any(first[1] > second[0] for first, second in zip(ranges, ranges[1:])):
        raise ArchiveFormatError("ZIP local/member ranges overlap")
    if total > MAX_DECLARED_BYTES:
        observations["zip_declared_expansion"].append(-1)
    findings = [
        AssessmentFinding(
            "zip_metadata",
            "unverified",
            f"ZIP directory entries={count}; declared expanded bytes={total}; "
            f"encrypted entries={encrypted}. Payloads were not opened.",
            "Use a bounded, platform-aware inspection/extraction workflow if needed.",
        )
    ]
    for check, indexes in sorted(observations.items()):
        shown = ", ".join("aggregate" if i < 0 else str(i) for i in indexes[:8])
        findings.append(
            AssessmentFinding(
                check,
                "candidate",
                f"{len(indexes)} selected metadata occurrence(s); entry index(es): {shown}. "
                "Names and payloads omitted; extraction behavior unverified.",
                ACTIONS[check],
            )
        )
    return findings, (
        NOTICE,
        "ZIP64, split, self-extracting and trailing-data layouts unsupported; "
        "extra fields, data descriptors and payload consistency are not fully validated.",
    )
