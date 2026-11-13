"""Build a bounded Linux site-packages inventory without executing wheel code."""

import base64
import csv
import io
import stat
from email import message_from_bytes
from hashlib import sha256
from zipfile import BadZipFile, ZipFile

from .bandit_runtime_review import bandit_reference_lock, capture_locked_bandit_wheels
from .models import ValidationError
from .scanner_objects import CapturedEntry, ScannerSnapshot

_MAX_BYTES = 32 * 1024**2
_MAX_ENTRIES = 4000
_OMITTED_SETUPTOOLS = {
    "distutils-precedence.pth",
    "pkg_resources/tests/data/my-test-package-zip/my-test-package.zip",
    "pkg_resources/tests/data/my-test-package_zipped-egg/my_test_package-1.0-py3.7.egg",
}


def _safe_path(path):
    return (
        path and len(path) <= 512 and "\\" not in path and ":" not in path
        and not any(ord(char) < 32 for char in path)
        and all(part not in {"", ".", ".."} for part in path.split("/"))
        and not path.split("/")[0].endswith(".data")
    )


def _wheel_files(raw, artifact, remaining, entries_left):
    with ZipFile(io.BytesIO(raw)) as archive:
        files = {}
        seen = set()
        for info in archive.infolist():
            path = info.filename.removesuffix("/") if info.is_dir() else info.filename
            kind = stat.S_IFMT(info.external_attr >> 16)
            expected_type = stat.S_IFDIR if info.is_dir() else stat.S_IFREG
            if (
                not _safe_path(path) or path in seen or kind not in (0, expected_type)
                or info.orig_filename != info.filename
            ):
                raise ValidationError("Unsafe or duplicate wheel member")
            if len(seen) >= entries_left or info.file_size > remaining:
                raise ValidationError("Wheel expansion limit exceeded")
            seen.add(path)
            if not info.is_dir():
                files[path] = archive.read(info)
                remaining -= len(files[path])
    root = artifact["filename"].split("-", 2)
    prefix = f"{root[0]}-{root[1]}.dist-info/"
    metadata = message_from_bytes(files[prefix + "METADATA"])
    wheel = message_from_bytes(files[prefix + "WHEEL"])
    if (
        metadata["Name"].lower().replace("_", "-") != artifact["name"]
        or metadata["Version"] != artifact["version"]
        or wheel.get_all("Tag") != artifact["tags"]
    ):
        raise ValidationError("Wheel metadata differs from the reference lock")
    record = prefix + "RECORD"
    pending = set(files)
    for row in csv.reader(io.StringIO(files[record].decode("utf-8"), newline=""), strict=True):
        if len(row) != 3 or row[0] not in pending:
            raise ValidationError("Invalid wheel RECORD membership")
        path, fingerprint, size = row
        pending.remove(path)
        if path == record:
            if fingerprint or size:
                raise ValidationError("Invalid wheel RECORD self entry")
        else:
            payload = files[path]
            expected = base64.urlsafe_b64encode(sha256(payload).digest()).decode().rstrip("=")
            if fingerprint != "sha256=" + expected or size != str(len(payload)):
                raise ValidationError("Invalid wheel RECORD digest or size")
    if pending:
        raise ValidationError("Incomplete wheel RECORD")
    return files


def materialize_bandit_packages(directory):
    """Return immutable package bytes and identify omitted startup artifacts."""
    artifacts = bandit_reference_lock()["artifacts"]
    entries = {}
    omitted = []
    remaining = _MAX_BYTES
    try:
        captured = capture_locked_bandit_wheels(directory)
        for artifact, (_, raw) in zip(artifacts, captured, strict=True):
            files = _wheel_files(raw, artifact, remaining, _MAX_ENTRIES - len(entries))
            for path, data in files.items():
                leaf = path.rsplit("/", 1)[-1].lower()
                if path in _OMITTED_SETUPTOOLS and artifact["name"] == "setuptools":
                    omitted.append(path)
                    continue
                if leaf.endswith((".pth", ".pyc", ".pyz", ".egg", ".zip")) or leaf in {
                    "sitecustomize.py", "usercustomize.py",
                }:
                    raise ValidationError("Unexpected Python startup or archive member")
                if path in entries:
                    raise ValidationError("Wheel installation would overwrite a file")
                entries[path] = CapturedEntry(path, "file", 0o444, data)
                remaining -= len(data)
    except (BadZipFile, KeyError, AttributeError, UnicodeError, csv.Error):
        raise ValidationError("Invalid reference wheel metadata or archive") from None
    for path in entries:
        parent = path.rpartition("/")[0]
        while parent:
            if parent in entries:
                raise ValidationError("Wheel file conflicts with an installation directory")
            parent = parent.rpartition("/")[0]
    snapshot = ScannerSnapshot("site-packages", tuple(entries[p] for p in sorted(entries)))
    return snapshot, tuple(sorted(omitted))
