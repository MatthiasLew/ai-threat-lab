"""Bounded PE/ELF header observations. Never load, disassemble or execute a target."""

import hashlib
import os
import stat
import struct
from pathlib import Path

from .assessment import AssessmentFinding, AssessmentResult
from .models import ValidationError

MAX_BINARY_BYTES = 16 * 1024 * 1024
MAX_PE_SECTIONS = 96
MAX_ELF_SEGMENTS = 512
LIMITATIONS = (
    "Selected static PE/ELF headers only; not a complete loader or format validator.",
    "No execution, disassembly, unpacking, malware detection, imports or dependency analysis.",
    "Header flags do not prove effective runtime mitigation, exploitability or overall security.",
    "No cryptographic signature, trust-chain, external catalog or provenance verification.",
)


class BinaryFormatError(ValueError):
    """Malformed or unsupported structure; diagnostic strings never contain target bytes."""


def span(raw, offset, size):
    if offset < 0 or size < 0 or offset + size > len(raw):
        raise BinaryFormatError("Header/table/file range exceeds the available bytes")


def unpack(raw, format, offset):
    span(raw, offset, struct.calcsize(format))
    return struct.unpack_from(format, raw, offset)


def observation(check, evidence, *, candidate=False, recommendation=None):
    return AssessmentFinding(
        check,
        "candidate" if candidate else "unverified",
        evidence,
        recommendation
        or "Review the recorded header with platform-specific tooling; "
        "do not infer runtime protection or trust from these fields alone.",
    )


def pe_headers(raw):
    span(raw, 0, 64)
    pe = unpack(raw, "<I", 0x3C)[0]
    if pe < 64:
        raise BinaryFormatError("Unsupported PE header offset")
    span(raw, pe, 24)
    if raw[pe : pe + 4] != b"PE\0\0":
        raise BinaryFormatError("Invalid PE signature")
    machine, count = unpack(raw, "<HH", pe + 4)
    optional_size, characteristics = unpack(raw, "<HH", pe + 20)
    if not 1 <= count <= MAX_PE_SECTIONS or not characteristics & 2:
        raise BinaryFormatError("Unsupported PE section count or executable-image marker")
    optional = pe + 24
    span(raw, optional, optional_size)
    magic = unpack(raw, "<H", optional)[0]
    if magic not in (0x10B, 0x20B):
        raise BinaryFormatError("Unsupported PE optional-header format")
    bits = 32 if magic == 0x10B else 64
    directory_base = 96 if bits == 32 else 112
    if optional_size < directory_base:
        raise BinaryFormatError("Truncated PE optional header")
    dll_flags = unpack(raw, "<H", optional + 70)[0]
    directories = unpack(raw, "<I", optional + directory_base - 4)[0]
    if directories > 16 or directory_base + directories * 8 > optional_size:
        raise BinaryFormatError("Unsupported PE data-directory layout")
    sections = optional + optional_size
    span(raw, sections, count * 40)
    certificate = False
    if directories > 4:
        offset, size = unpack(raw, "<II", optional + directory_base + 4 * 8)
        if offset or size:
            if not offset or size < 8 or offset % 8 or offset < sections + count * 40:
                raise BinaryFormatError("Invalid PE certificate-table range")
            span(raw, offset, size)  # Certificate directory uses a file offset, not an RVA.
            certificate = True
    writable_executable = []
    for index in range(count):
        section = sections + index * 40
        size, offset = unpack(raw, "<II", section + 16)
        flags = unpack(raw, "<I", section + 36)[0]
        if size:
            if offset < sections + count * 40:
                raise BinaryFormatError("PE section raw data overlaps headers")
            span(raw, offset, size)
        if flags & 0x20000000 and flags & 0x80000000:
            writable_executable.append(index)
    # Emit no mitigation candidates until all selected structural checks have succeeded.
    findings = [
        observation(
            "pe_header",
            f"PE{bits}; machine=0x{machine:04x}; sections={count}; "
            f"dynamic_base={bool(dll_flags & 0x40)}; nx_compat={bool(dll_flags & 0x100)}; "
            f"guard_cf={bool(dll_flags & 0x4000)}; "
            f"relocations_stripped={bool(characteristics & 1)}; certificate_table={certificate}",
        )
    ]
    for flag, check, label in (
        (0x40, "pe_dynamic_base_unset", "DYNAMIC_BASE flag is unset"),
        (0x100, "pe_nx_compat_unset", "NX_COMPAT flag is unset"),
    ):
        if not dll_flags & flag:
            findings.append(
                observation(
                    check,
                    label,
                    candidate=True,
                    recommendation="Review platform requirements and linker hardening settings; "
                    "a missing bit alone does not establish absent runtime protection.",
                )
            )
    if characteristics & 1:
        findings.append(
            observation(
                "pe_relocations_stripped",
                "COFF base-relocations-stripped flag is set",
                candidate=True,
                recommendation="Review relocation availability and ASLR/linker configuration.",
            )
        )
    findings.extend(
        observation(
            "pe_writable_executable_section",
            f"Section index {index} records write and execute flags",
            candidate=True,
            recommendation="Review section permissions and separate writable data "
            "from executable code where supported; loader behavior was not measured.",
        )
        for index in writable_executable
    )
    return findings, (
        "PE optional-header bits and section flags only; no effective ASLR/DEP/CFG validation.",
        "Certificate-table presence/absence is not signature validity or unsigned-status proof.",
    )


def elf_headers(raw):
    span(raw, 0, 16)
    elf_class, data, version = raw[4:7]
    if elf_class not in (1, 2) or data not in (1, 2) or version != 1:
        raise BinaryFormatError("Unsupported ELF class, byte order or identification version")
    endian = "<" if data == 1 else ">"
    bits = 32 if elf_class == 1 else 64
    header_size, segment_size = (52, 32) if bits == 32 else (64, 56)
    span(raw, 0, header_size)
    kind, machine, file_version = unpack(raw, endian + "HHI", 16)
    if file_version != 1:
        raise BinaryFormatError("Unsupported ELF file version")
    table = unpack(raw, endian + ("I" if bits == 32 else "Q"), 28 if bits == 32 else 32)[0]
    size, entry_size, count = unpack(raw, endian + "HHH", 40 if bits == 32 else 52)
    if size != header_size or count > MAX_ELF_SEGMENTS:
        raise BinaryFormatError("Unsupported ELF header size or program-header count")
    if count and (entry_size != segment_size or table < header_size):
        raise BinaryFormatError("Unsupported ELF program-header layout")
    if count:
        span(raw, table, entry_size * count)
    loads, wx, stack, relro = 0, [], [], False
    for index in range(count):
        position = table + index * entry_size
        if bits == 32:
            type_, offset, address, _, file_size, memory_size, flags, alignment = unpack(
                raw, endian + "IIIIIIII", position
            )
        else:
            type_, flags, offset, address, _, file_size, memory_size, alignment = unpack(
                raw, endian + "IIQQQQQQ", position
            )
        if type_ == 0:
            continue  # PT_NULL fields have no defined segment semantics.
        if file_size:
            span(raw, offset, file_size)
        if type_ == 1:
            if file_size > memory_size or (
                alignment > 1
                and (alignment & (alignment - 1) or offset % alignment != address % alignment)
            ):
                raise BinaryFormatError("Invalid ELF load-segment size or alignment")
            loads += 1
            if memory_size and flags & 1 and flags & 2:
                wx.append(index)
        elif type_ == 0x6474E551:
            stack.append(bool(flags & 1))
        elif type_ == 0x6474E552:
            relro = True
    if len(stack) > 1:
        raise BinaryFormatError("Multiple GNU_STACK headers are not interpreted")
    stack_label = ("execute" if stack[0] else "no_execute") if stack else "absent"
    findings = [
        observation(
            "elf_header",
            f"ELF{bits}; byte_order={'little' if data == 1 else 'big'}; "
            f"machine={machine}; type={kind}; program_headers={count}; load_segments={loads}; "
            f"gnu_stack={stack_label}; gnu_relro={relro}",
        )
    ]
    if kind in (2, 3):
        findings.extend(
            observation(
                "elf_writable_executable_load",
                f"PT_LOAD index {index} records write and execute flags",
                candidate=True,
                recommendation="Review segment permissions and linker layout; "
                "effective runtime mappings were not inspected.",
            )
            for index in wx
        )
        if stack and stack[0]:
            findings.append(
                observation(
                    "elf_executable_stack",
                    "PT_GNU_STACK records the execute flag",
                    candidate=True,
                    recommendation="Review executable-stack requirements and rebuild without them "
                    "where supported; actual runtime stack permissions were not measured.",
                )
            )
        if kind == 2 and loads:
            findings.append(
                observation(
                    "elf_exec_type",
                    "ET_EXEC with load segments recorded",
                    candidate=True,
                    recommendation="Review position-independent executable/linker configuration; "
                    "platform loader and ASLR behavior were not validated.",
                )
            )
    return findings, (
        "ELF program headers only; no section/symbol/dynamic-table or runtime mapping analysis.",
        "ET_DYN alone does not distinguish a shared library from PIE; runtime ASLR is unverified.",
        "GNU_STACK absence does not establish executable/non-executable stack behavior.",
        "GNU_RELRO marker alone does not establish full RELRO or eager binding.",
    )


def inspect_binary(raw, target="<bytes>"):
    if not isinstance(raw, bytes) or len(raw) > MAX_BINARY_BYTES:
        raise ValidationError("Binary input must be bytes within the 16 MiB limit")
    form = "PE" if raw.startswith(b"MZ") else "ELF" if raw.startswith(b"\x7fELF") else "unknown"
    findings = [
        observation(
            "binary_metadata",
            f"Format={form}; bytes={len(raw)}; sha256={hashlib.sha256(raw).hexdigest()}",
        )
    ]
    missing = list(LIMITATIONS)
    if form == "unknown":
        missing.append("Unrecognized format; only size and digest were inventoried.")
    else:
        try:
            observed, unchecked = pe_headers(raw) if form == "PE" else elf_headers(raw)
            findings.extend(observed)
            missing.extend(unchecked)
        except BinaryFormatError as error:
            findings.append(
                observation(
                    "binary_structure_unavailable",
                    f"{form} structure is malformed or unsupported",
                )
            )
            missing.append(f"Structural checks unavailable: {error}; no mitigation conclusion.")
    return AssessmentResult(target, "program_file", "partial", tuple(findings), tuple(missing))


def audit_binary(target):
    path = Path(target)
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        raise ValidationError("Binary target must not be a symlink/junction")
    if not path.is_file():
        raise ValidationError("Binary target must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValidationError("Binary target must be a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None  # Stream now owns the descriptor, including on read failure.
            raw = stream.read(MAX_BINARY_BYTES + 1)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return inspect_binary(raw, str(target))
