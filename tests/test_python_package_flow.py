"""Regular-package, src-root and lexical relative-import static resolution."""

import json
import socket

import pytest
from test_cli_process import run_cli
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.models import ValidationError
from ai_threat_lab.python_project_flow import project_flows
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, read_bundle, scope_digest
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService

HELPER = "import os\ndef run(value):\n    os.system(value)\n"
SOURCE = "from flask import request\n"


def package_sources(caller, *, prefix="", initializer="", helper=HELPER):
    return [
        ("app.py", SOURCE + caller),
        (prefix + "pkg/__init__.py", initializer),
        (prefix + "pkg/helpers.py", helper),
    ]


@pytest.mark.parametrize("prefix", ["", "src/"])
@pytest.mark.parametrize(
    "imports,call",
    [
        ("from pkg.helpers import run", "run(request.args['PRIVATE_KEY'])"),
        ("from pkg.helpers import run as execute", "execute(request.args['PRIVATE_KEY'])"),
        ("import pkg.helpers", "pkg.helpers.run(request.args['PRIVATE_KEY'])"),
        ("import pkg.helpers as h", "h.run(request.args['PRIVATE_KEY'])"),
        ("from pkg import helpers", "helpers.run(request.args['PRIVATE_KEY'])"),
        ("from pkg import helpers as h", "h.run(request.args['PRIVATE_KEY'])"),
    ],
)
def test_selected_absolute_package_imports(prefix, imports, call):
    findings, _ = project_flows(package_sources(imports + "\n" + call, prefix=prefix))
    assert len(findings) == 1 and findings[0].check == "PY013"
    assert prefix + "pkg/helpers.py:3" in findings[0].evidence
    assert "app.py:3" in findings[0].evidence and "PRIVATE_KEY" not in str(findings)


@pytest.mark.parametrize("prefix", ["", "src/"])
@pytest.mark.parametrize(
    "imports,call",
    [
        ("from .helpers import run", "run(request.args['q'])"),
        ("from .helpers import run as execute", "execute(request.args['q'])"),
        ("from . import helpers", "helpers.run(request.args['q'])"),
        ("from . import helpers as h", "h.run(request.args['q'])"),
    ],
)
def test_sibling_relative_imports(prefix, imports, call):
    sources = [
        (prefix + "pkg/__init__.py", ""),
        (prefix + "pkg/helpers.py", HELPER),
        (prefix + "pkg/views.py", SOURCE + imports + "\n" + call),
    ]
    findings, notices = project_flows(sources)
    assert len(findings) == 1
    assert prefix + "pkg/views.py:3" in findings[0].evidence
    assert not any("relative local import unresolved" in n for n in notices)


@pytest.mark.parametrize(
    "imports,call",
    [
        ("from ..helpers import run", "run(request.args['q'])"),
        ("from .. import helpers", "helpers.run(request.args['q'])"),
    ],
)
def test_parent_relative_imports(imports, call):
    sources = [
        ("pkg/__init__.py", ""),
        ("pkg/sub/__init__.py", ""),
        ("pkg/helpers.py", HELPER),
        ("pkg/sub/views.py", SOURCE + imports + "\n" + call),
    ]
    assert len(project_flows(sources)[0]) == 1


@pytest.mark.parametrize("imports", ["from ...helpers import run", "from .... import run"])
def test_relative_import_cannot_escape_top_package(imports):
    sources = [
        ("pkg/__init__.py", ""),
        ("pkg/helpers.py", HELPER),
        ("pkg/views.py", SOURCE + imports + "\nrun(request.args['q'])"),
    ]
    findings, notices = project_flows(sources)
    assert not findings and any("relative local import unresolved" in n for n in notices)


def test_import_inside_called_function_uses_definition_package():
    sources = package_sources("from pkg.proxy import forward\nforward(request.args['q'])")
    sources.append(
        ("pkg/proxy.py", "def forward(value):\n    from .helpers import run\n    run(value)")
    )
    findings, _ = project_flows(sources)
    assert len(findings) == 1 and "pkg/helpers.py:3" in findings[0].evidence
    assert "pkg/proxy.py:3" in findings[0].evidence


@pytest.mark.parametrize(
    "initializer,caller",
    [
        ("from .helpers import run", "from pkg import run\nrun(request.args['q'])"),
        ("from . import helpers", "import pkg\npkg.helpers.run(request.args['q'])"),
        (
            "from . import helpers as h\ndef run(value):\n    h.run(value)",
            "from pkg import run\nrun(request.args['q'])",
        ),
        (
            "def run(value):\n    from .helpers import run as sink\n    sink(value)",
            "from pkg import run\nrun(request.args['q'])",
        ),
    ],
)
def test_selected_initializer_reexports_and_local_helpers(initializer, caller):
    findings, notices = project_flows(package_sources(caller, initializer=initializer))
    assert len(findings) == 1
    assert not any("cyclic project imports" in n for n in notices)


def test_src_with_initializer_is_named_package_not_automatic_source_root():
    sources = package_sources(
        "from src.pkg.helpers import run\nrun(request.args['q'])", prefix="src/"
    )
    sources.append(("src/__init__.py", ""))
    assert len(project_flows(sources)[0]) == 1
    sources[0] = ("app.py", SOURCE + "from pkg.helpers import run\nrun(request.args['q'])")
    assert not project_flows(sources)[0]


def test_src_flat_module_is_linked_without_package_markers():
    sources = [
        ("app.py", SOURCE + "from helpers import run\nrun(request.args['q'])"),
        ("src/helpers.py", HELPER),
    ]
    assert len(project_flows(sources)[0]) == 1


@pytest.mark.parametrize(
    "sources",
    [
        [("helpers.py", HELPER), ("src/helpers.py", HELPER)],
        [("pkg.py", HELPER), ("pkg/__init__.py", ""), ("pkg/helpers.py", HELPER)],
        [("pkg/__init__.py", ""), ("src/pkg/__init__.py", ""), ("pkg/helpers.py", HELPER)],
    ],
)
def test_ambiguous_roots_or_file_package_choices_are_not_guessed(sources):
    target = "helpers" if sources[0][0] == "helpers.py" else "pkg.helpers"
    sources = [("app.py", SOURCE + f"from {target} import run\nrun(request.args['q'])"), *sources]
    findings, notices = project_flows(sources)
    assert not findings
    assert any("ambiguous module/root/package" in n for n in notices)


@pytest.mark.parametrize("marker", ["(", "raise Error", "from .helpers import run\nraise Error"])
def test_invalid_or_noncompleting_initializer_does_not_expose_cached_child(marker):
    findings, notices = project_flows(
        package_sources("from pkg.helpers import run\nrun(request.args['q'])", initializer=marker)
    )
    assert not findings
    assert any("parent unavailable" in n or "initializer pass incomplete" in n for n in notices)


def test_unavailable_initializer_labels_block_child_binding():
    sources = [
        ("app.py", SOURCE + "from pkg.helpers import run\nrun(request.args['q'])"),
        ("pkg/helpers.py", HELPER),
    ]
    findings, notices = project_flows(sources, unavailable=["pkg/__init__.py"])
    assert not findings and any("package parent unavailable" in n for n in notices)


def test_missing_marker_is_not_treated_as_supported_namespace_package():
    sources = [
        ("app.py", SOURCE + "from pkg.helpers import run\nrun(request.args['q'])"),
        ("pkg/helpers.py", HELPER),
    ]
    findings, notices = project_flows(sources)
    assert not findings and any("namespace/missing-marker" in n for n in notices)


def test_oversized_initializer_does_not_fall_back_to_third_party(monkeypatch):
    import ai_threat_lab.python_project_flow as module

    monkeypatch.setattr(module, "MAX_FILE_BYTES", 200)
    findings, notices = project_flows(
        package_sources(
            "from pkg.helpers import run\nrun(request.args['q'])", initializer="#" * 201
        )
    )
    assert not findings and any("package parent unavailable" in n for n in notices)


def test_cyclic_package_imports_are_bounded_and_visible():
    sources = package_sources(
        "from pkg import run\nrun(request.args['q'])",
        initializer="from .helpers import run",
        helper="import pkg\n" + HELPER,
    )
    findings, notices = project_flows(sources)
    assert len(findings) == 1
    assert any("cyclic project imports" in n for n in notices)


def test_conflicting_function_and_child_module_are_not_guessed():
    sources = [
        ("app.py", SOURCE + "from pkg import run\nrun(request.args['q'])"),
        ("pkg/__init__.py", HELPER),
        ("pkg/run.py", HELPER),
    ]
    findings, notices = project_flows(sources)
    assert not findings and any("ambiguous function/module export" in n for n in notices)


def test_package_depth_limit_is_explicit(monkeypatch):
    import ai_threat_lab.python_module_index as module

    monkeypatch.setattr(module, "MAX_PACKAGE_DEPTH", 1)
    sources = [
        ("app.py", SOURCE + "from pkg.sub.helpers import run\nrun(request.args['q'])"),
        ("pkg/__init__.py", ""),
        ("pkg/sub/__init__.py", ""),
        ("pkg/sub/helpers.py", HELPER),
    ]
    findings, notices = project_flows(sources)
    assert not findings and any("package-depth limit" in n for n in notices)


def test_markers_consume_attempt_budget(monkeypatch):
    import ai_threat_lab.python_project_flow as module

    monkeypatch.setattr(module, "MAX_FILES", 2)
    findings, notices = project_flows(
        package_sources("from pkg.helpers import run\nrun(request.args['q'])")
    )
    assert not findings and any("file/total-byte limit" in n for n in notices)


@pytest.mark.parametrize(
    "path",
    [
        "pkg//helpers.py",
        "pkg/../helpers.py",
        "pkg/./helpers.py",
        "pkg\\helpers.py",
        "/pkg/helpers.py",
        "pkg:secret/helpers.py",
    ],
)
def test_nonportable_or_traversing_labels_do_not_create_module_bindings(path):
    findings, notices = project_flows([(path, HELPER)])
    assert not findings and any("unsupported module paths/layouts" in n for n in notices)


def test_layout_selection_is_deterministic():
    sources = package_sources("from pkg.helpers import run\nrun(request.args['q'])", prefix="src/")
    assert project_flows(sources) == project_flows(list(reversed(sources)))


def test_existing_local_cli_and_bundle_use_package_links_without_execution(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("package analysis attempted network access")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    project = tmp_path / "project"
    project.mkdir()
    marker = tmp_path / "must-not-exist"
    sources = package_sources(
        "from pkg.helpers import run\nrun(request.args['q'])",
        prefix="src/",
        initializer=f'open({str(marker)!r}, "w").write("ran")',
    )
    for name, source in sources:
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    result = local_inventory(str(project))
    assert {f.check for f in result.findings} == {"PY005", "PY013"}
    assert any("src/pkg/helpers.py:3" in f.evidence for f in result.findings)
    report = tmp_path / "assessment.json"
    assert run_cli("audit", project, "--output", report).returncode == 0
    assert len(json.loads(report.read_text())["findings"]) == 2
    before = report.read_bytes()
    assert run_cli("audit", project, "--output", report).returncode == 2
    assert report.read_bytes() == before
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "bundle")
    assert len(read_bundle(tmp_path / "bundle")["documents"]["assessment.json"]["findings"]) == 2
    assert not marker.exists()


def test_pinned_github_reuses_selected_package_blobs():
    sources = package_sources("from pkg.helpers import run\nrun(request.args['q'])", prefix="src/")
    entries, documents = [], []
    for name, source in sources:
        entry, document = blob(source)
        entry["path"] = name
        entries.append(entry)
        documents.append(document)
    client = QueueHTTP(*repository(*entries), *documents)
    snapshot = GithubAudit(client).collect("https://github.com/owner/repo")
    assert len(client.calls) == 6
    assert {f.check for f in snapshot.assessment.findings} == {"PY005", "PY013"}
    assert any("src/pkg/helpers.py:3" in f.evidence for f in snapshot.assessment.findings)


def test_unreadable_local_marker_retains_unavailable_package_identity(tmp_path):
    for name, source in package_sources("from pkg.helpers import run\nrun(request.args['q'])"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    (tmp_path / "pkg/__init__.py").write_bytes(b"\xff")
    result = local_inventory(str(tmp_path))
    assert {f.check for f in result.findings} == {"PY005"}
    assert any("package parent unavailable" in n for n in result.not_checked)


def test_engine_fifteen_reading_without_cross_engine_deltas(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    for name, source in package_sources("from pkg.helpers import run\nrun(request.args['q'])"):
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    assert current["manifest"]["scope"]["engine"] == "read-only-pipeline-26"
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-15"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    comparison = compare_bundles(read_bundle(tmp_path / "old"), current)
    assert comparison["comparable"] is False and comparison["counts"] is None


def test_missing_package_demo_evidence_prevents_completion(tmp_path, monkeypatch):
    from ai_threat_lab import offline_cli
    from ai_threat_lab.assessment import AssessmentResult

    original = offline_cli.assessor

    def missing_package(target):
        if target.target.endswith("python-package-fixture"):
            return AssessmentResult(target.target, "local_project", "partial", (), ())
        return original(target)

    monkeypatch.setattr(offline_cli, "assessor", missing_package)
    with pytest.raises(ValidationError, match="package-flow acceptance failed"):
        offline_cli.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo/demo-result.json").exists()
