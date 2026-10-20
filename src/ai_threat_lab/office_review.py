"""Bounded local Office package declarations; never open active document content."""

import io
import re
import zipfile
import zlib
from collections import Counter
from xml.etree import ElementTree as ET

from .archive_review import ArchiveFormatError, zip_metadata
from .assessment import AssessmentFinding, AssessmentResult
from .models import ValidationError
from .report_io import read_regular

MAX_INPUT = 16 * 1024 * 1024
MAX_XML = 128 * 1024
MAX_TOTAL_XML = 1024 * 1024
MAX_PARTS = 64
CONTENT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
NOTICE = (
    "Selected Office package declarations only; not malware detection, signature trust or "
    "a complete Office validator. No document rendering, macro execution, external requests, "
    "embedded payload analysis or files extracted to disk. Document text and URLs omitted."
)


def xml_part(archive, entry, remaining):
    if (
        entry.flag_bits & 1
        or entry.compress_type not in (0, 8)
        or not 0 < entry.file_size <= min(MAX_XML, remaining)
        or entry.file_size > 100 * max(1, entry.compress_size)
    ):
        raise ValidationError("XML member exceeds size/ratio bounds or uses unsupported encoding")
    with archive.open(entry) as stream:
        raw = stream.read(MAX_XML + 1)
    if len(raw) != entry.file_size:
        raise ValidationError("XML member length differs from its declaration")
    try:
        text = raw.decode("utf-8-sig")
        if "\x00" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.I):
            raise ValueError
        declaration = re.match(r"\s*<\?xml\s+[^?]*encoding\s*=\s*['\"]([^'\"]+)", text, re.I)
        if declaration and declaration[1].lower() not in ("utf-8", "utf8"):
            raise ValueError
        root = ET.fromstring(text)
        if sum(1 for _ in root.iter()) > 4096:
            raise ValueError
    except (UnicodeError, ET.ParseError, ValueError):
        raise ValidationError(
            "XML is malformed or outside the supported UTF-8/no-DTD subset"
        ) from None
    return root, len(raw)


def _inspect_office(raw):
    try:
        zip_findings, zip_limits = zip_metadata(raw)
    except ArchiveFormatError as error:
        raise ValidationError(str(error)) from None
    findings = [AssessmentFinding(item.check, item.status, "ZIP header pass: " + item.evidence,
                                  item.recommendation) for item in zip_findings]
    gaps = [NOTICE, *("ZIP header pass: " + item for item in zip_limits)]
    failures = 0
    # Existing metadata evidence remains accurate for its pass; the explicit XML pass below
    # has separate byte limits and does not read document bodies or embedded objects.
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            names = [entry.orig_filename for entry in entries]
            if len(set(names)) != len(names) or any(
                "\\" in name
                or name.startswith("/")
                or "\x00" in name
                or any(part in (".", "..") for part in name.split("/"))
                for name in names
            ):
                raise ValidationError("Ambiguous package member names prevent XML review")
            mapping = {entry.orig_filename: entry for entry in entries}
            if "[Content_Types].xml" not in mapping:
                raise ValidationError("No package content-type manifest; Office review unavailable")
            selected = [
                mapping["[Content_Types].xml"],
                *[entry for entry in entries if entry.orig_filename.endswith(".rels")],
            ]
            counts, used, reviewed = Counter(), 0, 0
            for index, entry in enumerate(selected[:MAX_PARTS], 1):
                try:
                    remaining = MAX_TOTAL_XML - used
                    if 0 < entry.file_size <= min(MAX_XML, remaining):
                        used += entry.file_size  # Charge malformed XML too; no budget reset.
                    root, _ = xml_part(archive, entry, remaining)
                    part_counts = Counter()
                    if index == 1:
                        if root.tag != f"{{{CONTENT_NS}}}Types":
                            raise ValidationError("Unsupported content-type manifest namespace")
                        for child in root:
                            if child.tag not in (
                                f"{{{CONTENT_NS}}}Override",
                                f"{{{CONTENT_NS}}}Default",
                            ):
                                raise ValidationError("Unexpected content-type manifest element")
                            content = child.get("ContentType", "").lower()
                            if not content:
                                raise ValidationError("Missing package content-type declaration")
                            part_counts["macro_declarations"] += (
                                "macroenabled" in content or "vbaproject" in content
                            )
                            part_counts["activex_declarations"] += "activex" in content
                            part_counts["embedded_declarations"] += "oleobject" in content
                    else:
                        if root.tag != f"{{{REL_NS}}}Relationships":
                            raise ValidationError("Unsupported relationship namespace")
                        seen = set()
                        for child in root:
                            if (
                                child.tag != f"{{{REL_NS}}}Relationship"
                                or not child.get("Id")
                                or child.get("Id") in seen
                                or not child.get("Type")
                                or not child.get("Target")
                                or child.get("TargetMode", "Internal")
                                not in ("Internal", "External")
                            ):
                                raise ValidationError(
                                    "Malformed or ambiguous relationship declaration"
                                )
                            seen.add(child.get("Id"))
                            if child.get("TargetMode") == "External":
                                part_counts["external_relationships"] += 1
                                part_counts["external_hyperlinks"] += child.get(
                                    "Type", ""
                                ).endswith("/hyperlink")
                    counts.update(part_counts)
                    reviewed += 1
                except (
                    ValidationError,
                    zipfile.BadZipFile,
                    RuntimeError,
                    NotImplementedError,
                    zlib.error,
                ):
                    failures += 1
                    gaps.append(
                        f"XML metadata part {index:04d} could not be fully reviewed; "
                        "malformed, unsupported or over bound. Other evidence retained."
                    )
            if len(selected) > MAX_PARTS:
                gaps.append("XML metadata selection capped at 64 parts; remaining parts unchecked.")
            findings.append(
                AssessmentFinding(
                    "office_package_inventory",
                    "unverified",
                    f"Selected XML parts={min(len(selected), MAX_PARTS)}; "
                    f"fully reviewed={reviewed}; "
                    f"reserved XML bytes={used}. Only declarations were inspected.",
                    "Review the actual document using controlled, format-aware tooling.",
                )
            )
            for name, count in sorted(counts.items()):
                if count:
                    findings.append(
                        AssessmentFinding(
                            "office_" + name,
                            "candidate",
                            f"Declared occurrences={count}; "
                            "content, destinations and execution behavior unverified.",
                            "Review whether declared capabilities are expected before opening.",
                        )
                    )
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
        raise ValidationError("Office package metadata could not be read") from None
    return AssessmentResult(
        "Saved Office package", "office_package", "partial", tuple(findings), tuple(gaps)
    ), failures


def inspect_office(raw):
    return _inspect_office(raw)[0]


def review_office(path):
    return _inspect_office(read_regular(path, MAX_INPUT))
