import json
from pathlib import Path

import pytest

from ai_threat_lab.models import ValidationError
from ai_threat_lab.scan_bundle import (
    digest,
    document,
    encoded,
    publish_bundle,
    read_bundle,
    scope_digest,
    validate_manifest,
    validate_modules,
)
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService


@pytest.fixture
def bundle(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("eval(data)\n")
    folder = tmp_path / "scan"
    ScanService(assessor).run(ScanOptions(str(target)), folder)
    return folder


def manifest(folder):
    return json.loads((folder / "manifest.json").read_text())


def write_manifest(folder, value):
    (folder / "manifest.json").write_bytes(encoded(value))


def reindex(folder, filename, value):
    raw = encoded(value)
    (folder / filename).write_bytes(raw)
    metadata = manifest(folder)
    metadata["files"][filename] = {"bytes": len(raw), "sha256": digest(raw)}
    write_manifest(folder, metadata)


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"run_id": "bad"},
        {"created_at": "not-time"},
        {"created_at": "2026-01-01T00:00:00"},
        {"scope_digest": "wrong"},
        {"files": {}},
        {"extra": "unknown"},
    ],
)
def test_invalid_manifest_fields(bundle, change):
    value = manifest(bundle)
    value.update(change)
    with pytest.raises(ValidationError):
        validate_manifest(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("engine", "unknown"),
        ("network", 1),
        ("share_packages", 0),
        ("advisory_cache", 1),
        ("target", None),
        ("target_kind", ""),
        ("allowed_hosts", "example.com"),
        ("allowed_hosts", [None]),
        ("max_files", True),
        ("max_files", 10001),
        ("max_pages", 0),
        ("max_pages", True),
        ("dkim_selector", 1),
    ],
)
def test_invalid_scope_fields(bundle, field, value):
    data = manifest(bundle)
    data["scope"][field] = value
    data["scope_digest"] = scope_digest(data["scope"])
    with pytest.raises(ValidationError):
        validate_manifest(data)


@pytest.mark.parametrize(
    "metadata",
    [
        {"bytes": -1, "sha256": "a" * 64},
        {"bytes": True, "sha256": "a" * 64},
        {"bytes": 8 * 1024 * 1024 + 1, "sha256": "a" * 64},
        {"bytes": 10, "sha256": "bad"},
        {"bytes": 10, "sha256": None},
    ],
)
def test_artifact_bounds(bundle, metadata):
    data = manifest(bundle)
    data["files"]["report.json"] = metadata
    with pytest.raises(ValidationError):
        validate_manifest(data)


def test_total_bundle_bound_and_filename_traversal(bundle):
    data = manifest(bundle)
    for value in data["files"].values():
        value["bytes"] = 8 * 1024 * 1024
    with pytest.raises(ValidationError, match="total"):
        validate_manifest(data)
    data = manifest(bundle)
    data["files"]["../../outside"] = {"bytes": 0, "sha256": digest(b"")}
    with pytest.raises(ValidationError):
        validate_manifest(data)


@pytest.mark.parametrize("raw", [b"[]", b"not json", b"\xff", b'{"x":1,"x":2}', b'{"x":NaN}'])
def test_json_contract_is_strict(raw):
    with pytest.raises(ValidationError):
        document(raw)


def test_missing_manifest_and_oversized_manifest(bundle, tmp_path):
    with pytest.raises(ValidationError):
        read_bundle(tmp_path / "missing")
    (bundle / "manifest.json").unlink()
    with pytest.raises(ValidationError, match="incomplete"):
        read_bundle(bundle)
    (bundle / "manifest.json").write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(ValidationError, match="1 MiB"):
        read_bundle(bundle)


@pytest.mark.parametrize("damage", ["changed", "missing", "extra"])
def test_corrupt_bundle_artifacts_are_rejected(bundle, damage):
    if damage == "changed":
        (bundle / "report.json").write_bytes(b"{}")
    elif damage == "missing":
        (bundle / "report.html").unlink()
    else:
        (bundle / "unindexed.txt").write_text("not part of bundle")
    with pytest.raises(ValidationError):
        read_bundle(bundle)


def test_rehashed_but_inconsistent_derived_report_is_rejected(bundle):
    report = json.loads((bundle / "report.json").read_text())
    report["findings"] = []
    reindex(bundle, "report.json", report)
    with pytest.raises(ValidationError, match="does not match"):
        read_bundle(bundle)


def test_scope_target_must_match_assessment_even_when_hashes_recomputed(bundle):
    data = manifest(bundle)
    data["scope"]["target"] = "different-target"
    data["scope_digest"] = scope_digest(data["scope"])
    write_manifest(bundle, data)
    with pytest.raises(ValidationError, match="target scope"):
        read_bundle(bundle)


@pytest.mark.parametrize("status", ["secure", [], None])
def test_bad_module_status_types(bundle, status):
    value = json.loads((bundle / "modules.json").read_text())
    value["target_assessment"]["status"] = status
    with pytest.raises(ValidationError):
        validate_modules(value)
    reindex(bundle, "modules.json", value)
    with pytest.raises(ValidationError):
        read_bundle(bundle)


def test_modules_notice_and_missing_fields(bundle):
    value = json.loads((bundle / "modules.json").read_text())
    value["target_assessment"]["notice"] = ""
    with pytest.raises(ValidationError):
        validate_modules(value)
    with pytest.raises(ValidationError):
        validate_modules({})


@pytest.mark.parametrize("part", ["folder", "manifest.json", "report.json"])
def test_symlinks_rejected(bundle, tmp_path, part):
    try:
        if part == "folder":
            link = tmp_path / "linked"
            link.symlink_to(bundle, target_is_directory=True)
            with pytest.raises(ValidationError):
                read_bundle(link)
        else:
            saved = tmp_path / "saved"
            (bundle / part).rename(saved)
            (bundle / part).symlink_to(saved)
            with pytest.raises(ValidationError):
                read_bundle(bundle)
    except OSError:
        pytest.skip("Symlinks unavailable")


def publication(bundle):
    value = manifest(bundle)
    artifacts = {name: (bundle / name).read_bytes() for name in value["files"]}
    metadata = {key: item for key, item in value.items() if key not in ("files", "schema_version")}
    return artifacts, metadata


def test_publish_existing_empty_folder_is_never_overwritten(bundle, tmp_path):
    artifacts, metadata = publication(bundle)
    destination = tmp_path / "existing"
    destination.mkdir()
    with pytest.raises(FileExistsError):
        publish_bundle(destination, artifacts, metadata)
    assert list(destination.iterdir()) == []
    with pytest.raises(ValidationError):
        publish_bundle(tmp_path / "bad", {}, metadata)


@pytest.mark.parametrize("error", [OSError("disk full"), KeyboardInterrupt()])
def test_failed_publication_cleans_only_its_files_and_no_manifest(
    bundle, tmp_path, monkeypatch, error
):
    artifacts, metadata = publication(bundle)
    destination = tmp_path / "failed"
    original = Path.open

    def failing(path, *args, **kwargs):
        if path == destination / "report.html" and args and args[0] == "xb":
            raise error
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing)
    with pytest.raises(type(error)):
        publish_bundle(destination, artifacts, metadata)
    assert not destination.exists()
    assert not list(tmp_path.glob(".ai-threat-scan-*"))


def test_cleanup_never_deletes_unrelated_files(bundle, tmp_path, monkeypatch):
    artifacts, metadata = publication(bundle)
    destination = tmp_path / "failed"
    original = Path.open

    def failing(path, *args, **kwargs):
        if path == destination / "report.html" and args and args[0] == "xb":
            (destination / "operator-note.txt").write_text("keep this")
            raise OSError("disk problem")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing)
    with pytest.raises(OSError):
        publish_bundle(destination, artifacts, metadata)
    assert (destination / "operator-note.txt").read_text() == "keep this"
    assert not (destination / "manifest.json").exists()
    with pytest.raises(ValidationError, match="incomplete"):
        read_bundle(destination)


def test_racing_directory_claim_preserves_the_other_actor_files(bundle, tmp_path, monkeypatch):
    artifacts, metadata = publication(bundle)
    destination = tmp_path / "race"
    original = Path.mkdir

    def race(path, *args, **kwargs):
        if path == destination and not destination.exists():
            original(path)
            (path / "keep.txt").write_text("other actor")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", race)
    with pytest.raises(FileExistsError):
        publish_bundle(destination, artifacts, metadata)
    assert (destination / "keep.txt").read_text() == "other actor"
