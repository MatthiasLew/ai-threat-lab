import os
from email import message_from_bytes
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile, ZipInfo

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from ai_threat_lab.bandit_runtime_review import bandit_reference_lock, capture_locked_bandit_wheels
from ai_threat_lab.bandit_wheel_tree import _wheel_files, materialize_bandit_packages
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scanner_staging import sealed_scanner_file


@pytest.mark.parametrize("name", ["../outside", "/absolute", "folder\\file", "x.data/file"])
def test_wheel_rejects_unsafe_member(name):
    raw = BytesIO()
    with ZipFile(raw, "w") as archive:
        archive.writestr(name.replace("\\", "/"), b"x")
    payload = raw.getvalue().replace(b"folder/file", b"folder\\file")
    with pytest.raises(ValidationError, match="Unsafe"):
        _wheel_files(payload, {}, 100, 10)


def test_wheel_rejects_symlink_and_expansion_limit():
    raw = BytesIO()
    with ZipFile(raw, "w") as archive:
        info = ZipInfo("link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        archive.writestr(info, b"target")
    with pytest.raises(ValidationError, match="Unsafe"):
        _wheel_files(raw.getvalue(), {}, 100, 10)
    raw = BytesIO()
    with ZipFile(raw, "w") as archive:
        archive.writestr("payload", b"oversized")
    with pytest.raises(ValidationError, match="expansion"):
        _wheel_files(raw.getvalue(), {}, 1, 10)


def test_wheel_rejects_record_with_wrong_hash():
    raw = BytesIO()
    with ZipFile(raw, "w") as archive:
        archive.writestr("demo-1.dist-info/METADATA", "Name: demo\nVersion: 1\n")
        archive.writestr("demo-1.dist-info/WHEEL", "Tag: py3-none-any\n")
        archive.writestr("demo-1.dist-info/RECORD", "demo.py,sha256=invalid,1\n")
        archive.writestr("demo.py", "x")
    artifact = {
        "filename": "demo-1-py3-none-any.whl", "name": "demo",
        "version": "1", "tags": ["py3-none-any"],
    }
    with pytest.raises(ValidationError, match="digest or size"):
        _wheel_files(raw.getvalue(), artifact, 1024, 10)


def test_locked_wheel_directory_rejects_incomplete_extra_and_modified_files(tmp_path):
    names = [row["filename"] for row in bandit_reference_lock()["artifacts"]]
    with pytest.raises(ValidationError, match="incomplete"):
        capture_locked_bandit_wheels(tmp_path)
    extra = tmp_path / "extra"
    extra.touch()
    with pytest.raises(ValidationError, match="Unexpected artifact"):
        capture_locked_bandit_wheels(tmp_path)
    extra.unlink()
    for name in names:
        (tmp_path / name).write_bytes(b"changed")
    with pytest.raises(ValidationError, match="digest mismatch"):
        capture_locked_bandit_wheels(tmp_path)
    original = tmp_path.parent / "outside-wheel"
    original.touch()
    (tmp_path / names[0]).unlink()
    os.link(original, tmp_path / names[0])
    with pytest.raises(ValidationError, match="single link"):
        capture_locked_bandit_wheels(tmp_path)


@pytest.mark.skipif(not hasattr(os, "memfd_create"), reason="Linux immutable descriptors")
def test_reference_wheels_are_captured_and_sealed(tmp_path):
    import shutil

    configured = os.environ.get("THREAT_LAB_REFERENCE_WHEELS")
    if not configured:
        pytest.skip("Reference wheel cache not supplied")
    for row in bandit_reference_lock()["artifacts"]:
        shutil.copyfile(Path(configured) / row["filename"], tmp_path / row["filename"])
    captured = capture_locked_bandit_wheels(tmp_path)
    packages, omitted = materialize_bandit_packages(tmp_path)
    assert len(omitted) == 3 and "distutils-precedence.pth" in omitted
    paths = {entry.path for entry in packages.entries}
    assert {"bandit/__init__.py", "sarif_om/__init__.py", "yaml/__init__.py"} <= paths
    assert any(path.startswith("yaml/_yaml.") and path.endswith(".so") for path in paths)
    assert not any(path.endswith(".pth") for path in paths)
    artifacts = bandit_reference_lock()["artifacts"]
    versions = {row["name"]: row["version"] for row in artifacts}
    for row, (name, raw) in zip(artifacts, captured, strict=True):
        with ZipFile(BytesIO(raw)) as archive:
            metadata_path, = [
                p for p in archive.namelist()
                if p.count("/") == 1 and p.endswith(".dist-info/METADATA")
            ]
            metadata = message_from_bytes(archive.read(metadata_path))
            wheel_path = metadata_path.removesuffix("METADATA") + "WHEEL"
            tags = message_from_bytes(archive.read(wheel_path))
        assert canonicalize_name(metadata["Name"]) == row["name"]
        assert metadata["Version"] == row["version"]
        assert tags.get_all("Tag") == row["tags"]
        environment = {
            "platform_system": "Linux", "sys_platform": "linux", "platform_machine": "x86_64",
            "python_version": "3.12", "python_full_version": "3.12.0",
            "implementation_name": "cpython", "platform_python_implementation": "CPython",
            "extra": "sarif" if row["name"] == "bandit" else "",
        }
        active = []
        for declaration in metadata.get_all("Requires-Dist", []):
            requirement = Requirement(declaration)
            if requirement.marker is None or requirement.marker.evaluate(environment):
                assert requirement.specifier.contains(versions[canonicalize_name(requirement.name)])
                active.append(str(requirement))
        assert sorted(active) == row["requires"]
        (tmp_path / name).write_bytes(b"substituted after capture")
        with sealed_scanner_file(raw, row["sha256"]) as fd:
            assert sha256(os.read(fd, len(raw))).hexdigest() == row["sha256"]
