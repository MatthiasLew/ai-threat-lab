"""Independent synthetic headers, boundary failures and no-execution CLI integration."""

import hashlib
import json
import os
import random
import struct
import sys
from pathlib import Path

import pytest
from test_cli_process import run_cli

from ai_threat_lab.binary_audit import MAX_BINARY_BYTES, audit_binary, inspect_binary
from ai_threat_lab.cli import main
from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, read_bundle, scope_digest
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService


def pe_fixture(bits=32, *, flags=0x4140, characteristics=2, wx=False, certificate=False):
    raw = bytearray(544 if certificate else 528)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 60, 64)
    raw[64:68] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        raw,
        68,
        0x14C if bits == 32 else 0x8664,
        1,
        0,
        0,
        0,
        224 if bits == 32 else 240,
        characteristics,
    )
    optional = 88
    struct.pack_into("<H", raw, optional, 0x10B if bits == 32 else 0x20B)
    struct.pack_into("<H", raw, optional + 70, flags)
    base = 96 if bits == 32 else 112
    struct.pack_into("<I", raw, optional + base - 4, 16)
    if certificate:
        struct.pack_into("<II", raw, optional + base + 32, 536, 8)
    section = optional + (224 if bits == 32 else 240)
    raw[section : section + 8] = b"SECRET!!"
    struct.pack_into("<II", raw, section + 16, 16, 512)
    struct.pack_into("<I", raw, section + 36, 0xE0000020 if wx else 0x60000020)
    return bytes(raw)


def elf_fixture(bits=64, endian="<", *, kind=3, flags=5, stack=6, relro=True):
    size, entry = (52, 32) if bits == 32 else (64, 56)
    count = 1 + (stack is not None) + relro
    data = size + entry * count
    raw = bytearray(data + 16)
    raw[:16] = (
        b"\x7fELF" + bytes([1 if bits == 32 else 2, 1 if endian == "<" else 2, 1]) + b"\0" * 9
    )
    format = "HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"
    struct.pack_into(
        endian + format,
        raw,
        16,
        kind,
        3 if bits == 32 else 62,
        1,
        0,
        size,
        0,
        0,
        size,
        entry,
        count,
        0,
        0,
        0,
    )

    def segment(position, type_, permission, offset=0, length=0):
        values = (
            (type_, offset, offset, 0, length, length, permission, 1)
            if bits == 32
            else (type_, permission, offset, offset, 0, length, length, 1)
        )
        struct.pack_into(
            endian + ("IIIIIIII" if bits == 32 else "IIQQQQQQ"), raw, position, *values
        )

    segment(size, 1, flags, data, 16)
    if stack is not None:
        segment(size + entry, 0x6474E551, stack)
    if relro:
        segment(size + entry * (count - 1), 0x6474E552, 4)
    return bytes(raw)


def checks(result):
    return {f.check for f in result.findings if f.status == "candidate"}


def mutate(raw, offset, format, value):
    data = bytearray(raw)
    struct.pack_into(format, data, offset, value)
    return bytes(data)


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("certificate", [False, True])
def test_pe_supported_headers_are_unverified_observations(bits, certificate):
    result = inspect_binary(pe_fixture(bits, certificate=certificate))
    assert not checks(result)
    header = next(f for f in result.findings if f.check == "pe_header")
    assert header.status == "unverified" and f"PE{bits}" in header.evidence
    assert "dynamic_base=True" in header.evidence and "nx_compat=True" in header.evidence
    assert f"certificate_table={certificate}" in header.evidence
    assert "SECRET" not in str(result)
    assert any("signature validity" in n for n in result.not_checked)


@pytest.mark.parametrize(
    "flags,characteristics,wx,expected",
    [
        (0, 2, False, {"pe_dynamic_base_unset", "pe_nx_compat_unset"}),
        (0x40, 2, False, {"pe_nx_compat_unset"}),
        (0x100, 2, False, {"pe_dynamic_base_unset"}),
        (0x4140, 3, False, {"pe_relocations_stripped"}),
        (0x4140, 2, True, {"pe_writable_executable_section"}),
    ],
)
def test_pe_candidate_flags_are_specific(flags, characteristics, wx, expected):
    assert (
        checks(inspect_binary(pe_fixture(flags=flags, characteristics=characteristics, wx=wx)))
        == expected
    )


@pytest.mark.parametrize(
    "offset,format,value",
    [
        (60, "<I", 0),
        (60, "<I", 0xFFFFFFFF),
        (64, "<I", 0),
        (70, "<H", 0),
        (70, "<H", 97),
        (86, "<H", 0),
        (84, "<H", 1),
        (88, "<H", 0x107),
        (84, "<H", 70),
        (180, "<I", 17),
        (84, "<H", 100),
        (328, "<I", 1000),
        (332, "<I", 0),
        (332, "<I", 0xFFFFFFF0),
        (216, "<I", 1),
        (220, "<I", 1),
        (216, "<I", 0xFFFFFFF0),
    ],
)
def test_pe_invalid_structures_never_emit_partial_mitigation_candidates(offset, format, value):
    result = inspect_binary(mutate(pe_fixture(flags=0), offset, format, value))
    assert not checks(result)
    assert {f.check for f in result.findings} == {"binary_metadata", "binary_structure_unavailable"}
    assert any("no mitigation conclusion" in n for n in result.not_checked)


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("endian", ["<", ">"])
def test_elf_class_and_byte_order(bits, endian):
    result = inspect_binary(elf_fixture(bits, endian))
    assert not checks(result)
    evidence = result.findings[1].evidence
    assert f"ELF{bits}" in evidence
    assert "gnu_stack=no_execute" in evidence and "gnu_relro=True" in evidence
    assert any("does not distinguish" in n for n in result.not_checked)


@pytest.mark.parametrize(
    "kind,flags,stack,expected",
    [
        (3, 7, 6, {"elf_writable_executable_load"}),
        (3, 5, 7, {"elf_executable_stack"}),
        (2, 5, 6, {"elf_exec_type"}),
        (2, 7, 7, {"elf_exec_type", "elf_writable_executable_load", "elf_executable_stack"}),
        (1, 7, 7, set()),
        (3, 5, None, set()),
    ],
)
def test_elf_candidate_flags_and_missing_stack_are_not_runtime_claims(kind, flags, stack, expected):
    result = inspect_binary(elf_fixture(kind=kind, flags=flags, stack=stack, relro=False))
    assert checks(result) == expected
    assert any("absence does not establish" in n for n in result.not_checked)
    assert any("full RELRO" in n for n in result.not_checked)


@pytest.mark.parametrize(
    "offset,format,value",
    [
        (4, "B", 0),
        (5, "B", 0),
        (6, "B", 0),
        (20, "<I", 2),
        (52, "<H", 63),
        (56, "<H", 513),
        (56, "<H", 0xFFFF),
        (54, "<H", 55),
        (32, "<Q", 0),
        (32, "<Q", 2**64 - 1),
        (96, "<Q", 99999),
        (104, "<Q", 0),
        (72, "<Q", 2**64 - 1),
        (112, "<Q", 3),
        (176, "<I", 0x6474E551),
    ],
)
def test_invalid_elf_structures_suppress_otherwise_risky_flags(offset, format, value):
    raw = elf_fixture(flags=7, stack=7)
    result = inspect_binary(mutate(raw, offset, format, value))
    assert not checks(result)
    assert result.findings[-1].check == "binary_structure_unavailable"


@pytest.mark.parametrize("raw", [b"", b"other", b"MZ", b"\x7fELF", b"MZSECRET", b"\x7fELFSECRET"])
def test_short_unknown_and_recognized_markers_preserve_digest_without_leaking_bytes(raw):
    result = inspect_binary(raw)
    assert "sha256=" + hashlib.sha256(raw).hexdigest() in result.findings[0].evidence
    assert not checks(result) and "SECRET" not in str(result)
    assert result.status == "partial"


@pytest.mark.parametrize(
    "raw", ["not bytes", None, bytearray(b"MZ"), b"x" * (MAX_BINARY_BYTES + 1)]
)
def test_binary_input_limits(raw):
    with pytest.raises(ValidationError):
        inspect_binary(raw)


def test_no_program_headers_or_empty_segments_do_not_imply_a_stack_policy():
    raw = mutate(elf_fixture(), 56, "<H", 0)
    result = inspect_binary(raw)
    assert not checks(result) and "program_headers=0" in result.findings[1].evidence
    raw = elf_fixture(flags=7)
    raw = mutate(mutate(raw, 96, "<Q", 0), 104, "<Q", 0)
    assert "elf_writable_executable_load" not in checks(inspect_binary(raw))
    raw = mutate(elf_fixture(flags=7), 64, "<I", 0)
    assert "elf_writable_executable_load" not in checks(inspect_binary(raw))


def test_fuzzed_short_headers_are_bounded_and_never_raise_low_level_errors():
    randomizer = random.Random(11)
    for index in range(250):
        prefix = b"MZ" if index % 2 else b"\x7fELF"
        raw = prefix + randomizer.randbytes(randomizer.randrange(0, 512))
        result = inspect_binary(raw)
        assert result.status == "partial"
        assert all(f.status != "confirmed" for f in result.findings)


def test_audit_binary_rejects_links_non_regular_and_oversized_files(tmp_path):
    path = tmp_path / "program.bin"
    path.write_bytes(pe_fixture())
    assert audit_binary(path).target_kind == "program_file"
    with pytest.raises(ValidationError, match="regular"):
        audit_binary(tmp_path)
    with path.open("wb") as stream:
        stream.truncate(MAX_BINARY_BYTES + 1)
    with pytest.raises(ValidationError):
        audit_binary(path)
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ValidationError, match="symlink"):
        audit_binary(link)


def test_special_file_does_not_block(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("No FIFO support")
    fifo = tmp_path / "program.bin"
    os.mkfifo(fifo)
    with pytest.raises(ValidationError, match="regular"):
        audit_binary(fifo)


def test_no_network_execution_or_tool_subprocess_used(tmp_path, monkeypatch):
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        pytest.fail("Static inspection must not execute or connect")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    path = tmp_path / "program.bin"
    path.write_bytes(elf_fixture(flags=7, stack=7))
    assert checks(local_inventory(str(path))) == {
        "elf_writable_executable_load",
        "elf_executable_stack",
    }


def test_real_interpreter_headers_are_read_without_running_target():
    # Cross-platform independent evidence alongside the synthetic format fixtures.
    path = Path(sys.executable).resolve()
    if path.stat().st_size > MAX_BINARY_BYTES:
        path = Path("/bin/true").resolve()
        if not path.is_file() or path.stat().st_size > MAX_BINARY_BYTES:
            pytest.skip("No small native runtime fixture available")
    result = audit_binary(path)
    assert result.findings[0].check == "binary_metadata"
    assert result.findings[1].check in {"pe_header", "elf_header"}
    assert all(f.status != "confirmed" for f in result.findings)


def test_cli_audit_scan_report_integrity_and_partial_findings(tmp_path, capsys):
    path = tmp_path / "program.bin"
    path.write_bytes(pe_fixture(wx=True))
    assert main(["audit", str(path)]) == 0
    assert any(
        f["check"] == "pe_writable_executable_section"
        for f in json.loads(capsys.readouterr().out)["findings"]
    )
    output = tmp_path / "run"
    assert main(["scan", str(path), "--output-dir", str(output), "--fail-on-findings"]) == 1
    capsys.readouterr()
    bundle = read_bundle(output)
    assert bundle["documents"]["modules.json"]["dependency_inventory"]["status"] == "not_applicable"
    assert "pe_writable_executable_section" in (output / "report.html").read_text(encoding="utf-8")


def test_real_binary_cli_process_unicode_path_and_json_contract(tmp_path):
    path = tmp_path / "program próbny.bin"
    path.write_bytes(elf_fixture(flags=7))
    result = run_cli("audit", path)
    assert result.returncode == 0, result.stderr
    assert "elf_writable_executable_load" in {
        f["check"] for f in json.loads(result.stdout)["findings"]
    }
    result = run_cli("scan", path, "--output-dir", tmp_path / "bundle")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["ai_calls"] == 0


def test_engine_four_remains_readable_but_not_comparable(tmp_path):
    path = tmp_path / "program.bin"
    path.write_bytes(pe_fixture())
    ScanService(assessor).run(ScanOptions(str(path)), tmp_path / "new")
    current = read_bundle(tmp_path / "new")
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-4"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "new" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    assert not compare_bundles(read_bundle(tmp_path / "old"), current)["comparable"]


def test_elf_load_alignment_mismatch_is_unavailable():
    raw = mutate(mutate(elf_fixture(), 112, "<Q", 16), 80, "<Q", 0)
    assert inspect_binary(raw).findings[-1].check == "binary_structure_unavailable"


@pytest.mark.parametrize(
    "family,bits,endian",
    [
        ("PE", 32, "<"),
        ("PE", 64, "<"),
        ("ELF", 32, "<"),
        ("ELF", 32, ">"),
        ("ELF", 64, "<"),
        ("ELF", 64, ">"),
    ],
)
def test_every_truncated_prefix_suppresses_candidate_flags(family, bits, endian):
    raw = (
        pe_fixture(bits, flags=0, wx=True) if family == "PE" else elf_fixture(bits, endian, flags=7)
    )
    for length in range(len(raw)):
        assert not checks(inspect_binary(raw[:length]))


@pytest.mark.parametrize("offset,size", [(0, 8), (536, 4), (336, 8), (537, 8), (536, 99999)])
def test_pe_certificate_table_bounds_not_signature_claims(offset, size):
    raw = bytearray(pe_fixture(certificate=True))
    struct.pack_into("<II", raw, 88 + 96 + 32, offset, size)
    result = inspect_binary(bytes(raw))
    assert result.findings[-1].check == "binary_structure_unavailable"
    assert not checks(result)


def test_maximum_table_counts_are_bounded_but_supported():
    raw = bytearray(pe_fixture())
    raw.extend(b"\0" * 4000)
    struct.pack_into("<H", raw, 70, 96)
    struct.pack_into("<II", raw, 312 + 16, 0, 0)
    assert "sections=96" in inspect_binary(bytes(raw)).findings[1].evidence
    raw = bytearray(elf_fixture())
    raw.extend(b"\0" * (64 + 512 * 56 - len(raw)))
    struct.pack_into("<H", raw, 56, 512)
    assert "program_headers=512" in inspect_binary(bytes(raw)).findings[1].evidence


def test_file_descriptor_closed_if_type_changes_or_stream_setup_fails(tmp_path, monkeypatch):
    import stat
    from types import SimpleNamespace

    import ai_threat_lab.binary_audit as binary

    path = tmp_path / "sample.bin"
    path.write_bytes(b"fixture")
    close, fstat = binary.os.close, binary.os.fstat
    closed = []

    def closing(descriptor):
        closed.append(descriptor)
        close(descriptor)

    monkeypatch.setattr(binary.os, "close", closing)
    monkeypatch.setattr(binary.os, "fstat", lambda _: SimpleNamespace(st_mode=stat.S_IFIFO))
    with pytest.raises(ValidationError, match="regular"):
        audit_binary(path)
    assert len(closed) == 1
    monkeypatch.setattr(binary.os, "fstat", fstat)

    def fail_open(*args, **kwargs):
        raise OSError("stream unavailable")

    monkeypatch.setattr(binary.os, "fdopen", fail_open)
    with pytest.raises(OSError):
        audit_binary(path)
    assert len(closed) == 2


def test_exact_maximum_input_size_preserves_metadata():
    raw = b"x" * MAX_BINARY_BYTES
    result = inspect_binary(raw)
    assert "bytes=" + str(MAX_BINARY_BYTES) in result.findings[0].evidence
    assert not checks(result)


def test_demo_malformed_binary_is_not_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as offline

    monkeypatch.setattr(offline, "synthetic_binary_samples", lambda: {"synthetic-pe.bin": b"MZ"})
    with pytest.raises(ValidationError, match="binary structure"):
        offline.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo" / "demo-result.json").exists()


def test_demo_binary_module_failure_is_not_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as offline

    actual = offline.assessor

    def unavailable(options):
        if options.target.endswith(".bin"):
            raise OSError("unavailable")
        return actual(options)

    monkeypatch.setattr(offline, "assessor", unavailable)
    with pytest.raises(ValidationError, match="binary acceptance"):
        offline.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo" / "demo-result.json").exists()
