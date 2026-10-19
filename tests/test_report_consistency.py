"""Saved-report invariants, including rehashed HTML, scope and typed-count regressions."""

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from ai_threat_lab.audit_report import merge_reports, render_html
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scan_bundle import digest, encoded, publish_bundle, read_bundle, scope_digest
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService


def make_scan(tmp_path, name="scan", *, baseline=None):
    target = tmp_path / "source.py"
    target.write_text("eval(untrusted)\n")
    folder = tmp_path / name
    ScanService(assessor).run(ScanOptions(str(target)), folder, baseline=baseline)
    return folder


def reindex(folder, name, raw):
    (folder / name).write_bytes(raw)
    manifest = json.loads((folder / "manifest.json").read_bytes())
    manifest["files"][name] = {"bytes": len(raw), "sha256": digest(raw)}
    (folder / "manifest.json").write_bytes(encoded(manifest))


def test_rehashed_html_must_match_saved_assessment_not_just_its_digest(tmp_path):
    folder = make_scan(tmp_path)
    reindex(folder, "report.html", b"<script>PRIVATE</script>")
    with pytest.raises(ValidationError):
        read_bundle(folder)


def test_boolean_count_cannot_impersonate_an_integer_when_json_and_html_rehashed(tmp_path):
    folder = make_scan(tmp_path)
    report = json.loads((folder / "report.json").read_bytes())
    assert report["summary"]["unique_findings"] == 1
    report["summary"]["unique_findings"] = True
    reindex(folder, "report.json", encoded(report))
    reindex(folder, "report.html", render_html(report).encode())
    with pytest.raises(ValidationError):
        read_bundle(folder)


def test_target_kind_scope_must_match_assessment(tmp_path):
    folder = make_scan(tmp_path)
    manifest = json.loads((folder / "manifest.json").read_bytes())
    manifest["scope"]["target_kind"] = "mail_message"
    manifest["scope_digest"] = scope_digest(manifest["scope"])
    (folder / "manifest.json").write_bytes(encoded(manifest))
    with pytest.raises(ValidationError):
        read_bundle(folder)


def test_dependency_target_must_match_even_with_self_consistent_reports(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    folder = tmp_path / "scan"
    ScanService(assessor).run(ScanOptions(str(project)), folder)
    dependency = json.loads((folder / "dependencies.json").read_bytes())
    dependency["target"] = "PRIVATE-OTHER-TARGET"
    reindex(folder, "dependencies.json", encoded(dependency))
    assessment = json.loads((folder / "assessment.json").read_bytes())
    report = merge_reports([assessment, dependency])
    reindex(folder, "report.json", encoded(report))
    reindex(folder, "report.html", render_html(report).encode())
    with pytest.raises(ValidationError):
        read_bundle(folder)


def test_saved_comparison_cannot_lie_about_counts_after_rehash(tmp_path):
    before = make_scan(tmp_path, "before")
    after = make_scan(tmp_path, "after", baseline=before)
    comparison = json.loads((after / "comparison.json").read_bytes())
    comparison["counts"]["still_observed"] = 999
    reindex(after, "comparison.json", encoded(comparison))
    with pytest.raises(ValidationError):
        read_bundle(after)


def test_publication_cleanup_preserves_replacement_of_its_earlier_file(tmp_path, monkeypatch):
    folder = make_scan(tmp_path)
    manifest = json.loads((folder / "manifest.json").read_bytes())
    artifacts = {name: (folder / name).read_bytes() for name in manifest["files"]}
    metadata = {k: v for k, v in manifest.items() if k not in ("files", "schema_version")}
    destination = tmp_path / "failed"
    original = Path.open

    def failing(path, *args, **kwargs):
        if path == destination / "report.html" and args and args[0] == "xb":
            saved = destination / "assessment.json"
            saved.rename(tmp_path / "our-original.json")
            saved.write_text("KEEP OTHER ACTOR")
            raise OSError("Injected failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing)
    with pytest.raises(OSError):
        publish_bundle(destination, artifacts, metadata)
    assert (destination / "assessment.json").read_text() == "KEEP OTHER ACTOR"
    assert not (destination / "manifest.json").exists()


@pytest.mark.parametrize(
    "mutation",
    [
        {"schema_version": True},
        {"previous_run_id": "bad"},
        {"current_run_id": "a" * 32},
        {"comparable": 1},
        {"coverage_notices_changed": 1},
        {"notice": ""},
        {"counts": None},
        {"still_observed": {}},
        {"reason": "unknown"},
        {"comparable": False},
        {"new_observations": [None]},
    ],
)
def test_malformed_comparison_schema_cannot_be_reported_as_verified(tmp_path, mutation):
    before = make_scan(tmp_path, "before")
    after = make_scan(tmp_path, "after", baseline=before)
    value = json.loads((after / "comparison.json").read_bytes())
    value.update(mutation)
    reindex(after, "comparison.json", encoded(value))
    with pytest.raises(ValidationError):
        read_bundle(after)


@pytest.mark.parametrize(
    "mutation",
    [
        {"id": "bad"},
        {"target": "PRIVATE-other"},
        {"triage_priority": "P1"},
        {"sources": [True]},
        {"sources": []},
        {"sources": [1, 1]},
    ],
)
def test_comparison_finding_identity_provenance_and_current_membership(tmp_path, mutation):
    before = make_scan(tmp_path, "before")
    after = make_scan(tmp_path, "after", baseline=before)
    value = json.loads((after / "comparison.json").read_bytes())
    value["still_observed"][0].update(mutation)
    reindex(after, "comparison.json", encoded(value))
    with pytest.raises(ValidationError):
        read_bundle(after)


def test_valid_noncomparable_and_disappearing_findings_remain_readable(tmp_path):
    before = make_scan(tmp_path, "before")
    target = tmp_path / "source.py"
    target.write_text("safe = 1\n")
    after = tmp_path / "after"
    ScanService(assessor).run(ScanOptions(str(target)), after, baseline=before)
    value = read_bundle(after)["documents"]["comparison.json"]
    assert len(value["no_longer_observed"]) == 1 and value["comparable"]
    changed = tmp_path / "changed"
    ScanService(assessor).run(ScanOptions(str(target), max_files=1), changed, baseline=before)
    assert not read_bundle(changed)["documents"]["comparison.json"]["comparable"]


def test_manifest_special_file_is_rejected_without_blocking(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unsupported")
    folder = tmp_path / "scan"
    folder.mkdir()
    os.mkfifo(folder / "manifest.json")
    with pytest.raises(ValidationError):
        read_bundle(folder)


def test_shared_reader_closes_descriptor_on_type_race_and_stream_failure(tmp_path, monkeypatch):
    import ai_threat_lab.report_io as io

    path = tmp_path / "report"
    path.write_bytes(b"inert")
    original_close, original_stat = io.os.close, io.os.fstat
    closed = []

    def closing(fd):
        closed.append(fd)
        original_close(fd)

    monkeypatch.setattr(io.os, "close", closing)
    monkeypatch.setattr(io.os, "fstat", lambda _: SimpleNamespace(st_mode=stat.S_IFIFO))
    with pytest.raises(ValidationError):
        io.read_regular(path, 10)
    assert len(closed) == 1
    monkeypatch.setattr(io.os, "fstat", original_stat)

    def fail(*a, **k):
        raise OSError("PRIVATE")

    monkeypatch.setattr(io.os, "fdopen", fail)
    with pytest.raises(OSError):
        io.read_regular(path, 10)
    assert len(closed) == 2


def test_html_escapes_summary_labels_and_values_for_python_callers(tmp_path):
    folder = make_scan(tmp_path)
    report = json.loads((folder / "report.json").read_bytes())
    report["summary"]["triage_counts"] = {"<script>PRIVATE</script>": "<img src=PRIVATE>"}
    html = render_html(report)
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html and "&lt;img" in html
