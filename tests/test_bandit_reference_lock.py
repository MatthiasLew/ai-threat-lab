import os
from email import message_from_bytes
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from ai_threat_lab.bandit_runtime_review import bandit_reference_lock, capture_locked_bandit_wheels
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scanner_staging import sealed_scanner_file


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
