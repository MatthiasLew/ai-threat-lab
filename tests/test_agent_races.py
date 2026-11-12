"""Deterministic opened-object controls, without executing target source."""

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from ai_threat_lab import agent_fs
from ai_threat_lab.agent_service import AgentService
from ai_threat_lab.models import ValidationError
from ai_threat_lab.report_io import read_regular
from ai_threat_lab.scan_engine import ScanOptions, ScanService


def test_root_must_pass_opened_directory_validation(tmp_path, monkeypatch):
    assert AgentService(tmp_path).root == tmp_path.resolve()

    def unavailable(_path):
        raise OSError("Directory cannot be pinned")

    monkeypatch.setattr(agent_fs, "pinned_directory", unavailable)
    with pytest.raises(ValidationError, match="accessible directory"):
        AgentService(tmp_path)


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


@pytest.mark.skipif(os.name != "nt", reason="Windows opened-handle attributes")
def test_opened_directory_rejects_junction(tmp_path):
    import _winapi

    folder = tmp_path / "fixture"
    folder.mkdir()
    junction = tmp_path / "junction"
    _winapi.CreateJunction(str(folder), str(junction))
    with pytest.raises(ValidationError, match="Reparse points"):
        with agent_fs.pinned_directory(junction):
            pytest.fail("Accepted a reparse point")
    sample = folder / "sample.py"
    sample.write_text("pass\n")
    with pytest.raises(ValidationError, match="Reparse points"):
        ScanOptions(str(junction / sample.name))
    with pytest.raises(ValidationError, match="Reparse points"):
        read_regular(junction / sample.name, 1024)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink and directory descriptor semantics")
def test_ordinary_project_reads_stay_with_opened_directory(tmp_path):
    root, moved = tmp_path / "project", tmp_path / "moved"
    root.mkdir()
    source = root / "sample.py"
    source.write_bytes(b"# selected content")
    with agent_fs.pinned_read_scope(root):
        root.rename(moved)
        root.mkdir()
        source.write_bytes(b"# new directory content")
        assert read_regular(source, 1024) == b"# selected content"
    assert read_regular(source, 1024) == b"# new directory content"


def test_scan_requires_same_selected_project_directory(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    options = ScanOptions(str(root))
    root.rename(tmp_path / "moved")
    root.mkdir()
    service = ScanService(lambda _: pytest.fail("Collector ran on a replacement directory"))
    with pytest.raises(ValidationError, match="changed since selection"):
        service.run(options, tmp_path / "report")
    assert not (tmp_path / "report").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows share-delete semantics")
def test_pinned_directory_blocks_rename_until_release(tmp_path):
    folder = tmp_path / "fixture"
    moved = tmp_path / "moved"
    folder.mkdir()
    with agent_fs.pinned_directory(folder):
        with pytest.raises(PermissionError):
            folder.rename(moved)
    folder.rename(moved)
    assert moved.is_dir()


def test_parallel_first_scans_publish_distinct_bundles(tmp_path, monkeypatch):
    (tmp_path / "fixture.py").write_text("pass\n", encoding="utf-8")
    service = AgentService(tmp_path)
    original = os.mkdir
    gate = Barrier(2, timeout=10)

    def mkdir(path, *args, **kwargs):
        if str(path).endswith(".ai-threat-lab"):
            gate.wait()
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "mkdir", mkdir)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(service.call, "scan", {"target": "fixture.py"}) for _ in range(2)]
        results = [future.result(timeout=30) for future in futures]
    assert len({result["run"] for result in results}) == 2
    for result in results:
        saved = service.call("status", {"run": result["run"]})
        assert saved["integrity"] == "verified_local_consistency"


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
