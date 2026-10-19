"""ZIP metadata controls, bounded corrupt inputs and CLI without member reads."""

import io
import json
import random
import stat
import struct
import warnings
import zipfile

import pytest
from test_cli_process import run_cli

from ai_threat_lab.archive_review import ArchiveFormatError, zip_metadata
from ai_threat_lab.binary_audit import inspect_binary
from ai_threat_lab.scan_bundle import read_bundle


def fixture(*names, payload=b"example", compression=zipfile.ZIP_STORED, symlink=False):
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w", compression=compression) as archive:
            for name in names:
                if symlink:
                    entry = zipfile.ZipInfo(name)
                    entry.create_system = 3
                    entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(entry, payload)
                else:
                    archive.writestr(name, payload)
    return stream.getvalue()


def checks(raw):
    result = inspect_binary(raw)
    assert all(f.status != "confirmed" for f in result.findings)
    return {f.check for f in result.findings if f.status == "candidate"}


def mutated(raw, offset, fmt, value):
    raw = bytearray(raw)
    struct.pack_into(fmt, raw, offset, value)
    return bytes(raw)


@pytest.mark.parametrize(
    "name", ["../PRIVATE", "/PRIVATE", "C:/PRIVATE", "a/../PRIVATE", "..\\PRIVATE"]
)
def test_path_escape_is_candidate_and_does_not_expose_name(name):
    raw = fixture(name)
    assert "zip_path_escape" in checks(raw)
    assert "PRIVATE" not in str(inspect_binary(raw))


@pytest.mark.parametrize("name", ["CON", "nul.txt", "a/LPT1.bin", "a:stream", "file.", "file "])
def test_windows_ambiguous_names(name):
    assert "zip_platform_ambiguous_path" in checks(fixture(name))


@pytest.mark.parametrize(
    "names", [("a", "A"), ("café", "cafe\u0301"), ("a/b", "a\\b"), ("a", "./a"), ("a", "a.")]
)
def test_portability_collision_controls(names):
    assert "zip_portability_collision" in checks(fixture(*names))


def test_duplicate_names_and_control_characters_are_aggregate_candidates():
    assert checks(fixture("a", "a")) == {"zip_duplicate_entries"}
    assert checks(fixture("a\nb")) == {"zip_control_filename"}


@pytest.mark.parametrize(
    "names", [(), ("file.txt",), ("nested/", "nested/hello.txt"), ("café.txt", "other.txt")]
)
def test_normal_archives_do_not_imply_vulnerability_or_safety(names):
    result = inspect_binary(fixture(*names))
    assert not checks(fixture(*names))
    assert result.findings[1].check == "zip_metadata"
    assert result.findings[1].status == "unverified"
    assert any("no extraction" in n for n in result.not_checked)


def test_symlink_metadata_does_not_read_destination():
    assert checks(fixture("link", payload=b"PRIVATE", symlink=True)) == {"zip_symlink_entry"}


def test_declared_expansion_and_aggregate_budget(monkeypatch):
    assert checks(
        fixture("a", payload=b"a" * (2 * 1024 * 1024), compression=zipfile.ZIP_DEFLATED)
    ) == {"zip_declared_expansion"}
    import ai_threat_lab.archive_review as module

    monkeypatch.setattr(module, "MAX_DECLARED_BYTES", 5)
    assert "zip_declared_expansion" in checks(fixture("a", payload=b"123456"))


def test_metadata_only_never_opens_extracts_or_checks_payload(monkeypatch):
    raw = fixture("../PRIVATE", compression=zipfile.ZIP_DEFLATED)

    def forbidden(*args, **kwargs):
        pytest.fail("ZIP members must not be opened or decompressed")

    for method in ("open", "read", "extract", "extractall", "testzip"):
        monkeypatch.setattr(zipfile.ZipFile, method, forbidden)
    assert "zip_path_escape" in checks(raw)


def test_encryption_flag_is_metadata_not_password_validation():
    raw = fixture("a")
    central = raw.index(b"PK\x01\x02")
    raw = mutated(mutated(raw, 6, "<H", 1), central + 8, "<H", 1)
    result = inspect_binary(raw)
    assert not checks(raw)
    assert "encrypted entries=1" in result.findings[1].evidence


@pytest.mark.parametrize(
    "offset,fmt,value",
    [
        (0, "<I", 0),
        (6, "<H", 1),
        (8, "<H", 99),
        (14, "<I", 99),
        (18, "<I", 999),
        (22, "<I", 999),
        (26, "<H", 999),
        (28, "<H", 999),
        (30, "B", ord("z")),
    ],
)
def test_inconsistent_local_metadata_suppresses_all_candidates(offset, fmt, value):
    raw = mutated(fixture("../PRIVATE"), offset, fmt, value)
    assert not checks(raw)
    # Corrupting the signature can make the format unknown, never a partial candidate.
    assert "PRIVATE" not in str(inspect_binary(raw))


@pytest.mark.parametrize(
    "offset,fmt,value",
    [
        (4, "<H", 1),
        (6, "<H", 1),
        (8, "<H", 999),
        (10, "<H", 65535),
        (12, "<I", 0xFFFFFFFF),
        (16, "<I", 0xFFFFFFFF),
        (20, "<H", 100),
    ],
)
def test_bad_end_records_suppress_candidates(offset, fmt, value):
    raw = fixture("../PRIVATE")
    raw = mutated(raw, len(raw) - 22 + offset, fmt, value)
    assert not checks(raw)
    assert inspect_binary(raw).findings[-1].check == "binary_structure_unavailable"


def test_directory_limits_apply_before_zipfile_allocates(monkeypatch):
    raw = fixture("a")
    end = len(raw) - 22
    raw = mutated(mutated(raw, end + 8, "<H", 1001), end + 10, "<H", 1001)
    monkeypatch.setattr(zipfile, "ZipFile", lambda *a, **k: pytest.fail("preflight first"))
    with pytest.raises(ArchiveFormatError, match="limit"):
        zip_metadata(raw)


def test_all_truncated_prefixes_and_trailing_bytes_are_not_partial_findings():
    raw = fixture("../PRIVATE")
    for length in range(len(raw)):
        assert not checks(raw[:length])
    assert not checks(raw + b"trailing")


def test_oversized_and_nonbytes_metadata_input_rejected():
    for raw in (None, "text", bytearray(), b"x" * (16 * 1024 * 1024 + 1)):
        with pytest.raises(ArchiveFormatError):
            zip_metadata(raw)


def test_random_zip_markers_never_escape_as_low_level_errors():
    rng = random.Random(38)
    for _ in range(250):
        assert not checks(b"PK\x03\x04" + rng.randbytes(rng.randrange(512)))


def test_zip_cli_audit_and_verified_scan_bundle(tmp_path):
    path = tmp_path / "archive próbne.zip"
    path.write_bytes(fixture("../PRIVATE"))
    result = run_cli("audit", path)
    assert result.returncode == 0, result.stderr
    assert "zip_path_escape" in {f["check"] for f in json.loads(result.stdout)["findings"]}
    result = run_cli("scan", path, "--output-dir", tmp_path / "bundle", "--fail-on-findings")
    assert result.returncode == 1, result.stderr
    read_bundle(tmp_path / "bundle")
    assert "zip_path_escape" in (tmp_path / "bundle" / "report.html").read_text()
