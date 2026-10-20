"""Static sibling-module linking with bounded collection and cross-file evidence."""

import json
import socket
from dataclasses import asdict

import pytest
from test_cli_process import run_cli
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.assessment import AssessmentService
from ai_threat_lab.code_review import read_python_source, review_file
from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.models import ValidationError
from ai_threat_lab.python_project_flow import project_flows
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, read_bundle, scope_digest
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService

HELPER = "import os, sqlite3\ndef run(value):\n    os.system(value)\n"
CALLER = "from flask import request\nfrom helpers import run\nrun(request.args['PRIVATE_KEY'])\n"


@pytest.mark.parametrize(
    "imports,call",
    [
        ("from helpers import run", "run(request.args['q'])"),
        ("from helpers import run as execute", "execute(request.args['q'])"),
        ("import helpers", "helpers.run(request.args['q'])"),
        ("import helpers as h", "h.run(request.args['q'])"),
        ("import helpers, os", "helpers.run(request.args['q'])"),
        ("import os, helpers as h", "h.run(request.args['q'])"),
    ],
)
def test_direct_and_module_import_aliases(imports, call):
    caller = "from flask import request\n" + imports + "\n" + call
    findings, _ = project_flows([("app.py", caller), ("helpers.py", HELPER)])
    assert len(findings) == 1 and findings[0].check == "PY013"
    assert "helpers.py:3:5" in findings[0].evidence
    assert "HTTP source(s): app.py:3" in findings[0].evidence
    assert "helper definition(s): helpers.py:2" in findings[0].evidence


def test_returned_text_keeps_foreign_helper_evidence_at_caller_sink():
    caller = "from flask import request\nimport os\nfrom helpers import prepare\n"
    caller += "os.system(prepare(request.args['q']))"
    helper = "def prepare(value):\n    return 'prefix '+value"
    findings, _ = project_flows([("app.py", caller), ("helpers.py", helper)])
    assert len(findings) == 1 and "app.py:4:" in findings[0].evidence
    assert "helpers.py:1" in findings[0].evidence


def test_returned_sqlite_identity_keeps_foreign_helper_evidence():
    caller = "from flask import request\nfrom helpers import connect\n"
    caller += "connection=connect()\nconnection.execute(request.args['q'])"
    helper = "import sqlite3\ndef connect():\n    return sqlite3.connect(':memory:')"
    findings, _ = project_flows([("app.py", caller), ("helpers.py", helper)])
    assert [f.check for f in findings] == ["PY014"]
    assert "helpers.py:2" in findings[0].evidence


def test_sqlite_parameters_do_not_become_query_text_flow():
    caller = "from flask import request\nimport sqlite3\nfrom helpers import run\n"
    caller += "run(sqlite3.connect(':memory:'), request.args['q'])"
    helper = "def run(connection, value):\n    connection.execute('SELECT ?', (value,))"
    assert project_flows([("app.py", caller), ("helpers.py", helper)])[0] == ()


def test_multiple_modules_and_lazy_import_inside_function():
    caller = "from flask import request\ndef endpoint():\n    import helpers\n"
    caller += "    helpers.run(request.args['q'])"
    helper = "from operations import sink\ndef run(value):\n    sink(value)"
    findings, _ = project_flows(
        [
            ("app.py", caller),
            ("helpers.py", helper),
            ("operations.py", HELPER.replace("run", "sink")),
        ]
    )
    assert len(findings) == 1 and "operations.py:3" in findings[0].evidence
    assert "app.py:4" in findings[0].evidence


@pytest.mark.parametrize(
    "imports,call",
    [
        ("from .helpers import run", "run(request.args['q'])"),
        ("from helpers import *", "run(request.args['q'])"),
        ("from helpers import missing", "missing(request.args['q'])"),
        ("import helpers", "helpers.missing(request.args['q'])"),
        ("from helpers import run", "run=unknown\nrun(request.args['q'])"),
        ("import helpers", "helpers=unknown\nhelpers.run(request.args['q'])"),
        ("import helpers", "if flag:\n    helpers=unknown\nhelpers.run(request.args['q'])"),
        ("from helpers import run", "if flag:\n    run=unknown\nrun(request.args['q'])"),
    ],
)
def test_unresolved_or_ambiguous_imports_are_not_guessed(imports, call):
    caller = "from flask import request\n" + imports + "\n" + call
    findings, notices = project_flows([("app.py", caller), ("helpers.py", HELPER)])
    assert not findings and any("unchecked" in n or "unresolved" in n for n in notices)


@pytest.mark.parametrize(
    "helper",
    [
        "@decorator\ndef run(value):\n    os.system(value)",
        "async def run(value):\n    os.system(value)",
        "def run(*value):\n    os.system(value)",
        "def run(value):\n    yield value\n    os.system(value)",
        "run=unknown",
        "def run(value):\n    os.system(value)\nrun=unknown",
    ],
)
def test_unsupported_exports_and_signatures_keep_gaps(helper):
    findings, notices = project_flows([("app.py", CALLER), ("helpers.py", "import os\n" + helper)])
    assert not findings and any("unchecked" in n for n in notices)


def test_local_api_name_shadowing_is_not_labeled_as_third_party_flask():
    findings, notices = project_flows(
        [("app.py", CALLER), ("helpers.py", HELPER), ("flask.py", "request=unknown")]
    )
    assert not findings and any("not a definite function" in n for n in notices)


def test_missing_selected_shadow_module_does_not_fall_back_to_library(monkeypatch):
    import ai_threat_lab.python_project_flow as module

    monkeypatch.setattr(module, "MAX_FILES", 1)
    findings, notices = project_flows([("app.py", CALLER), ("helpers.py", HELPER)])
    assert not findings
    assert any("local module unavailable" in n for n in notices)


def test_cycles_are_bounded_and_have_explicit_gaps():
    sources = [
        ("app.py", "from flask import request\nimport helpers\nhelpers.run(request.args['q'])"),
        ("helpers.py", "import app\n" + HELPER),
    ]
    findings, notices = project_flows(sources)
    assert len(findings) == 1
    assert any("cyclic project imports" in n for n in notices)


def test_no_duplicate_addition_for_entirely_same_file_paths():
    source = "from flask import request\nimport os\ndef run(value):\n    os.system(value)\n"
    source += "run(request.args['q'])"
    assert not project_flows([("app.py", source), ("unrelated.py", "value=1")])[0]


def test_sorting_is_deterministic_and_file_line_spaces_do_not_collide():
    sources = [("app.py", CALLER), ("helpers.py", HELPER)]
    first = project_flows(sources)
    assert first == project_flows(list(reversed(sources)))
    assert "PRIVATE_KEY" not in str(first)
    assert "100000" not in str(first)


@pytest.mark.parametrize(
    "sources",
    [
        None,
        {},
        [1],
        [("app.py",)],
        [(3, "")],
        [("app.py", b"bytes")],
        [("app.py", ""), ("app.py", "")],
    ],
)
def test_invalid_or_duplicate_input_fails_without_echoing_source(sources):
    with pytest.raises(ValidationError):
        project_flows(sources)


@pytest.mark.parametrize(
    "name,supported",
    [
        ("src/helpers.py", True),
        ("pkg/__init__.py", True),
        ("__init__.py", False),
        ("../helpers.py", False),
        ("/tmp/helpers.py", False),
        ("a-b.py", False),
        ("café.py", False),
    ],
)
def test_module_layout_selection_reports_scope(name, supported):
    findings, notices = project_flows([(name, HELPER)])
    assert not findings
    if supported:
        assert any("inspected 1 modules" in n for n in notices)
    else:
        assert any("unsupported module paths/layouts" in n for n in notices)


def test_input_and_byte_bounds(monkeypatch):
    import ai_threat_lab.python_project_flow as module

    with pytest.raises(ValidationError, match="100"):
        project_flows([(f"m{i}.py", "") for i in range(101)])
    monkeypatch.setattr(module, "MAX_FILE_BYTES", 4)
    assert any("oversized" in n for n in project_flows([("app.py", "value=1")])[1])
    monkeypatch.setattr(module, "MAX_TOTAL_BYTES", 2)
    assert any("total-byte" in n for n in project_flows([("app.py", "x=1")])[1])


def test_unparseable_modules_consume_attempt_and_byte_budgets(monkeypatch):
    import ai_threat_lab.python_project_flow as module

    monkeypatch.setattr(module, "MAX_FILES", 1)
    result = project_flows([("a.py", "("), ("b.py", "value=1")])
    assert any("unparsable" in n for n in result[1])
    assert any("file/total-byte" in n for n in result[1])
    assert any("from 1 attempts (1 UTF-8 bytes)" in n for n in result[1])


def test_surrogate_text_is_skipped_without_encoding_error_details():
    result = project_flows([("app.py", "\ud800")])
    assert any("invalid source encoding" in n for n in result[1])


def test_reader_preserves_declared_encoding_and_rejects_non_files(tmp_path):
    source = tmp_path / "source.py"
    source.write_bytes(b"# coding: latin-1\nvalue='\xe9'\neval(data)\n")
    assert "é" in read_python_source(source)
    assert review_file(source).findings[0].rule_id == "PY001"
    with pytest.raises(ValidationError, match="regular file"):
        read_python_source(tmp_path / "absent.py")


def test_local_cli_and_scan_add_cross_file_candidates_without_execution(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("project analysis attempted network access")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    project = tmp_path / "project"
    project.mkdir()
    marker = tmp_path / "must-not-exist"
    (project / "app.py").write_text(CALLER)
    (project / "helpers.py").write_text(HELPER + f'\nopen({str(marker)!r}, "w").write("ran")')
    for result in (AssessmentService().assess(str(project)), local_inventory(str(project))):
        assert {f.check for f in result.findings} == {"PY005", "PY013"}
        assert any(
            "helpers.py:3" in f.evidence and "app.py:3" in f.evidence for f in result.findings
        )
    process = run_cli("audit", project)
    assert process.returncode == 0 and not process.stderr
    assert len(json.loads(process.stdout)["findings"]) == 2
    report = tmp_path / "audit.json"
    assert run_cli("audit", project, "--output", report).returncode == 0
    assert run_cli("audit", project, "--output", report).returncode == 2
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "bundle")
    result = read_bundle(tmp_path / "bundle")
    assert len(result["documents"]["assessment.json"]["findings"]) == 2
    assert "PRIVATE_KEY" not in (tmp_path / "bundle" / "report.html").read_text()
    assert not marker.exists()


def test_pinned_github_uses_collected_blobs_without_additional_fetches():
    first, first_blob = blob(CALLER)
    first["path"] = "app.py"
    second, second_blob = blob(HELPER)
    second["path"] = "helpers.py"
    client = QueueHTTP(*repository(first, second), first_blob, second_blob)
    snapshot = GithubAudit(client).collect("https://github.com/owner/repo")
    assert len(client.calls) == 5
    assert {f.check for f in snapshot.assessment.findings} == {"PY005", "PY013"}
    assert any(
        "helpers.py:3" in f.evidence and "app.py:3" in f.evidence
        for f in snapshot.assessment.findings
    )


def test_project_only_results_remain_assessment_report_compatible():
    from ai_threat_lab.assessment import AssessmentResult
    from ai_threat_lab.audit_report import merge_reports, render_html

    findings, notices = project_flows([("app.py", CALLER), ("helpers.py", HELPER)])
    result = asdict(AssessmentResult("fixture", "local_project", "partial", findings, notices))
    result["findings"] = list(result["findings"])
    rendered = render_html(merge_reports([result]))
    assert "cross-file" in rendered and "PRIVATE_KEY" not in rendered


def test_engine_fourteen_reading_without_cross_engine_comparison(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(CALLER)
    (project / "helpers.py").write_text(HELPER)
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    assert current["manifest"]["scope"]["engine"] == "read-only-pipeline-28"
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-14"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    comparison = compare_bundles(read_bundle(tmp_path / "old"), current)
    assert comparison["comparable"] is False and comparison["counts"] is None


def test_noncompleting_module_pass_does_not_export_earlier_function():
    findings, notices = project_flows(
        [("app.py", CALLER), ("helpers.py", HELPER + "raise Error\n")]
    )
    assert not findings
    assert any("module pass did not complete" in n for n in notices)


def test_oversized_local_shadow_is_not_treated_as_installed_flask(monkeypatch):
    import ai_threat_lab.python_project_flow as module

    monkeypatch.setattr(module, "MAX_FILE_BYTES", 200)
    findings, notices = project_flows(
        [("app.py", CALLER), ("helpers.py", HELPER), ("flask.py", "#" * 201)]
    )
    assert not findings
    assert any("oversized" in n for n in notices)
    assert any("local module unavailable" in n for n in notices)


def test_helper_definition_evidence_is_bounded_across_contexts():
    operations = "".join(f"def cb{i}(value):\n    return value\n" for i in range(10))
    caller = "from flask import request\nimport os\nfrom helpers import run\n"
    caller += "from operations import " + ", ".join(f"cb{i}" for i in range(10)) + "\n"
    caller += "".join(f"os.system(run(cb{i}, request.args['q']))\n" for i in range(10))
    helper = "def run(callback, value):\n    return callback(value)"
    findings, notices = project_flows(
        [("app.py", caller), ("helpers.py", helper), ("operations.py", operations)]
    )
    assert len(findings) == 10
    assert any("helper-definition evidence limit" in n for n in notices)
    for finding in findings:
        definitions = finding.evidence.split("helper definition(s): ")[1].split(". Possible")[0]
        assert len(definitions.split(", ")) <= 8


def test_missing_cross_file_evidence_prevents_demo_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as module
    from ai_threat_lab.assessment import AssessmentResult

    original = module.assessor

    def missing(options):
        if options.target.endswith("python-project-fixture"):
            return AssessmentResult(options.target, "local_project", "partial", (), ("Fixture",))
        return original(options)

    monkeypatch.setattr(module, "assessor", missing)
    with pytest.raises(ValidationError, match="project-flow acceptance"):
        module.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo" / "demo-result.json").exists()


def test_unreadable_local_shadow_labels_are_not_assumed_to_be_library_imports(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(CALLER)
    (project / "helpers.py").write_text(HELPER)
    (project / "flask.py").write_bytes(b"\xff")
    result = local_inventory(str(project))
    assert {f.check for f in result.findings} == {"PY005"}
    assert any("local module unavailable" in n for n in result.not_checked)


def test_unparseable_local_shadow_is_included_in_project_module_index(tmp_path):
    (tmp_path / "app.py").write_text(CALLER)
    (tmp_path / "helpers.py").write_text(HELPER)
    (tmp_path / "flask.py").write_text("(")
    result = local_inventory(str(tmp_path))
    assert {f.check for f in result.findings} == {"PY005"}
    assert any("unparsable module" in n for n in result.not_checked)


@pytest.mark.parametrize("unavailable", [None, "flask.py", [1], ["m.py"] * 101])
def test_unavailable_label_boundary_is_validated(unavailable):
    with pytest.raises(ValidationError):
        project_flows([], unavailable=unavailable)
