"""Deterministic opened-object controls, without executing target source."""

import os

import pytest

from ai_threat_lab import agent_fs
from ai_threat_lab.models import ValidationError


def test_change_during_read_is_rejected_and_unchanged_file_is_readable(tmp_path):
    path = tmp_path / "file.txt"
    path.write_bytes(b"before")
    assert agent_fs.read_scoped(path) == b"before"
    with path.open("rb") as source:
        class ChangingStream:
            def fileno(self):
                return source.fileno()

            def read(self, size):
                value = source.read(size)
                path.write_bytes(b"changed to a different size")
                return value

        with pytest.raises(ValidationError, match="changed"):
            agent_fs._read(ChangingStream(), 1024)


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative no-follow race")
def test_replacement_between_path_check_and_open_cannot_return_outside_bytes(tmp_path, monkeypatch):
    root = tmp_path / "approved"
    root.mkdir()
    target, outside = root / "file.txt", tmp_path / "outside.txt"
    target.write_bytes(b"approved")
    outside.write_bytes(b"OUTSIDE_INERT_MARKER")
    approved = agent_fs.scoped_path(root, "file.txt")
    original = os.open

    def replace_before_open(path, flags, *args, **kwargs):
        if path == "file.txt":
            target.unlink()
            target.symlink_to(outside)
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", replace_before_open)
    with pytest.raises(OSError):
        agent_fs.read_scoped(approved)
