"""Literal importlib labels and project integration; target code is never loaded."""

import ast
import json
import socket

import pytest
from test_cli_process import run_cli
from test_python_package_flow import HELPER, SOURCE, package_sources
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.code_review import review_source
from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.python_import_calls import literal_import_target
from ai_threat_lab.python_project_flow import project_flows
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, read_bundle, scope_digest
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService


@pytest.mark.parametrize(
    "arguments,target",
    [
        ("'helpers'", "helpers"),
        ("'pkg.helpers'", "pkg.helpers"),
        ("name='pkg.helpers'", "pkg.helpers"),
        ("'pkg.helpers', None", "pkg.helpers"),
        ("'pkg.helpers', package='unused'", "pkg.helpers"),
        ("'.helpers', 'pkg'", "pkg.helpers"),
        ("'..helpers', 'pkg.sub'", "pkg.helpers"),
        ("package='pkg.sub', name='..helpers'", "pkg.helpers"),
        ("'.', 'pkg'", "pkg"),
        ("'..', 'pkg.sub'", "pkg"),
        ("'helpers' '2'", "helpers2"),
    ],
)
def test_literal_call_decoding(arguments, target):
    assert literal_import_target(ast.parse("load(" + arguments + ")", mode="eval").body) == target


@pytest.mark.parametrize(
    "arguments",
    [
        "",
        "''",
        "42",
        "None",
        "b'helpers'",
        "chosen",
        "'pkg.' + 'helpers'",
        "f'helpers'",
        "'helpers', anchor",
        "'helpers', *values",
        "**values",
        "'helpers', name='other'",
        "name='helpers', name='other'",
        "'helpers', 'pkg', package='pkg'",
        "'helpers', other='pkg'",
        "'helpers', None, None",
        "'.helpers'",
        "'.helpers', None",
        "'..helpers', 'pkg'",
        "'...helpers', 'pkg.sub'",
        "'.helpers', 4",
        "'.helpers', ''",
        "'.helpers', '.pkg'",
        "'pkg..helpers'",
        "'/tmp/helpers'",
        "'pkg/helpers'",
        "'pkg.hello-world'",
        "'café'",
        "'pkg\\x00helpers'",
    ],
)
def test_unsupported_or_invalid_arguments_are_not_resolved(arguments):
    assert literal_import_target(ast.parse("load(" + arguments + ")", mode="eval").body) is None


@pytest.mark.parametrize("literal", ["a" * 1025, "a" * 256, "a." * 511 + "aaa"])
def test_literal_name_length_bounds(literal):
    call = ast.parse("load(" + repr(literal) + ")", mode="eval").body
    assert literal_import_target(call) is None


@pytest.mark.parametrize("prefix", ["", "src/"])
@pytest.mark.parametrize(
    "setup,call",
    [
        ("import importlib", "importlib.import_module('pkg.helpers')"),
        ("import importlib as lib", "lib.import_module(name='pkg.helpers')"),
        ("from importlib import import_module", "import_module('pkg.helpers')"),
        ("from importlib import import_module as load", "load('pkg.helpers')"),
        ("from importlib import import_module\nload = import_module", "load('pkg.helpers')"),
        ("import importlib\nload = importlib.import_module", "load('pkg.helpers')"),
    ],
)
def test_imported_loader_aliases_and_dotted_module_result(prefix, setup, call):
    findings, notices = project_flows(
        package_sources(setup + "\nh = " + call + "\nh.run(request.args['PRIVATE'])", prefix=prefix)
    )
    assert len(findings) == 1 and findings[0].check == "PY013"
    assert prefix + "pkg/helpers.py:3" in findings[0].evidence
    assert "PRIVATE" not in str(findings)
    assert not any("importlib call has unsupported" in n for n in notices)


@pytest.mark.parametrize(
    "call",
    [
        "load('.helpers', 'pkg')",
        "load(name='.helpers', package='pkg')",
        "load('..helpers', 'pkg.sub')",
    ],
)
def test_explicit_relative_anchor_uses_literal_not_caller_package(call):
    sources = package_sources(
        "from importlib import import_module as load\nh = " + call + "\nh.run(request.args['q'])"
    )
    assert len(project_flows(sources)[0]) == 1


def test_loader_returned_module_reaches_final_helper_with_sink_evidence():
    sources = package_sources(
        "from proxy import get_module\nh = get_module()\nh.run(request.args['q'])"
    )
    sources.append(
        (
            "proxy.py",
            "from importlib import import_module as load\n"
            "def get_module():\n    return load('pkg.helpers')",
        )
    )
    findings, _ = project_flows(sources)
    assert len(findings) == 1
    assert "app.py:4" in findings[0].evidence
    assert "pkg/helpers.py:2" in findings[0].evidence


def test_inline_loader_attribute_call_and_sqlite_identity():
    sources = package_sources(
        "import importlib\nimport sqlite3\n"
        "importlib.import_module('pkg.helpers').run("
        "sqlite3.connect(':memory:'), request.args['q'])",
        helper="def run(connection, value):\n    connection.execute(value)",
    )
    findings, _ = project_flows(sources)
    assert len(findings) == 1 and findings[0].check == "PY014"


@pytest.mark.parametrize(
    "setup,call",
    [
        ("load = unknown", "load('pkg.helpers')"),
        ("from importlib import import_module as load\nload = unknown", "load('pkg.helpers')"),
        ("import importlib\nimportlib = unknown", "importlib.import_module('pkg.helpers')"),
        ("from other import import_module", "import_module('pkg.helpers')"),
        ("", "__import__('pkg.helpers')"),
        ("from importlib import import_module as load\nname = 'pkg.helpers'", "load(name)"),
    ],
)
def test_unknown_rebound_and_computed_loaders_do_not_get_module_identity(setup, call):
    findings, _ = project_flows(
        package_sources(setup + "\nh = " + call + "\nh.run(request.args['q'])")
    )
    assert not findings


@pytest.mark.parametrize(
    "shadow", ["", "def import_module(name):\n    return None", "raise Exception()"]
)
def test_local_importlib_shadow_never_falls_back_to_installed_library(shadow):
    sources = package_sources(
        "import importlib\nh = importlib.import_module('pkg.helpers')\nh.run(request.args['q'])"
    )
    sources.append(("importlib.py", shadow))
    assert not project_flows(sources)[0]


@pytest.mark.parametrize(
    "marker",
    ["def broken(", "raise Exception()", "x" * (256 * 1024 + 1)],
    ids=["syntax", "termination", "oversize"],
)
def test_unusable_parent_rejects_dynamic_result(marker):
    sources = package_sources(
        "from importlib import import_module as load\n"
        "h = load('pkg.helpers')\nh.run(request.args['q'])",
        initializer=marker,
    )
    findings, notices = project_flows(sources)
    assert not findings
    assert any("importlib target pass unavailable/incomplete" in n for n in notices)


@pytest.mark.parametrize("target", ["uncollected", "pkg.missing", "os", "pkg..helpers"])
def test_uncollected_targets_have_explicit_gaps_without_library_fallback(target):
    sources = package_sources(
        "from importlib import import_module as load\nh = load("
        + repr(target)
        + ")\nh.run(request.args['q'])"
    )
    findings, notices = project_flows(sources)
    assert not findings and any("importlib call has unsupported" in n for n in notices)


def test_dynamic_import_cycle_stops_without_unbounded_recursion():
    sources = package_sources(
        "from importlib import import_module as load\nh = load('pkg.helpers')\n"
        "h.run(request.args['q'])",
        helper="from importlib import import_module as load\nload('app')\n" + HELPER,
    )
    findings, notices = project_flows(sources)
    assert len(findings) == 1
    assert any("cyclic project imports" in n for n in notices)
    assert any("importlib target pass unavailable/incomplete" in n for n in notices)


def test_single_file_review_does_not_claim_project_import_support():
    source = SOURCE + "from importlib import import_module as load\nh = load('helpers')\n"
    source += "h.run(request.args['q'])"
    assert not review_source(source, "app.py").findings


def test_local_cli_bundle_and_nonexecution(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("analysis attempted a network connection")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    project = tmp_path / "project"
    project.mkdir()
    marker = tmp_path / "must-not-exist"
    sources = package_sources(
        "from importlib import import_module as load\nh = load('pkg.helpers')\n"
        "h.run(request.args['PRIVATE'])",
        prefix="src/",
        initializer=f'open({str(marker)!r}, "w").write("ran")',
    )
    for name, source in sources:
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    result = local_inventory(str(project))
    assert {f.check for f in result.findings} == {"PY005", "PY013"}
    output = tmp_path / "assessment.json"
    assert run_cli("audit", project, "--output", output).returncode == 0
    assert len(json.loads(output.read_text())["findings"]) == 2
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "bundle")
    assert len(read_bundle(tmp_path / "bundle")["documents"]["assessment.json"]["findings"]) == 2
    assert not marker.exists()


def test_pinned_github_reuses_blobs_for_literal_loader():
    sources = package_sources(
        "from importlib import import_module as load\nh = load('pkg.helpers')\n"
        "h.run(request.args['q'])",
        prefix="src/",
    )
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


def test_engine_sixteen_readable_without_cross_engine_comparison(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("eval(user_value)")
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    assert current["manifest"]["scope"]["engine"] == "read-only-pipeline-27"
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-16"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    assert not compare_bundles(read_bundle(tmp_path / "old"), current)["comparable"]


def test_missing_importlib_demo_evidence_prevents_completion(tmp_path, monkeypatch):
    from ai_threat_lab import offline_cli
    from ai_threat_lab.assessment import AssessmentResult
    from ai_threat_lab.models import ValidationError

    original = offline_cli.assessor

    def missing_importlib(options):
        if options.target.endswith("python-importlib-fixture"):
            return AssessmentResult(options.target, "local_project", "partial", (), ())
        return original(options)

    monkeypatch.setattr(offline_cli, "assessor", missing_importlib)
    with pytest.raises(ValidationError, match="importlib-flow acceptance failed"):
        offline_cli.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo/demo-result.json").exists()


def test_loader_callable_parameter_and_returned_function():
    sources = package_sources(
        "from importlib import import_module as load\n"
        "def get_function(loader):\n    return loader('pkg.helpers').run\n"
        "sink = get_function(load)\nsink(request.args['q'])"
    )
    findings, _ = project_flows(sources)
    assert len(findings) == 1 and "pkg/helpers.py:3" in findings[0].evidence


def test_same_module_join_retains_identity_but_conflicting_join_drops_it():
    base = "from importlib import import_module as load\n"
    body = (
        "if condition:\n    h = load('pkg.helpers')\n"
        "else:\n    h = load('TARGET')\nh.run(request.args['q'])"
    )
    same = package_sources(base + body.replace("TARGET", "pkg.helpers"))
    assert len(project_flows(same)[0]) == 1
    different = package_sources(base + body.replace("TARGET", "other"))
    different.append(("other.py", HELPER))
    findings, notices = project_flows(different)
    assert not findings and any("join lost ambiguous" in n for n in notices)


def test_namespace_and_ambiguous_roots_still_block_literal_loaders():
    caller = SOURCE + "from importlib import import_module as load\n"
    caller += "h = load('pkg.helpers')\nh.run(request.args['q'])"
    sources = [("app.py", caller), ("pkg/helpers.py", HELPER)]
    findings, notices = project_flows(sources)
    assert not findings and any("namespace/missing-marker" in n for n in notices)
    sources.extend(
        [("pkg/__init__.py", ""), ("src/pkg/__init__.py", ""), ("src/pkg/helpers.py", HELPER)]
    )
    findings, notices = project_flows(sources)
    assert not findings and any("ambiguous module/root/package" in n for n in notices)


def test_unavailable_target_retains_local_identity():
    sources = [
        (
            "app.py",
            SOURCE + "from importlib import import_module as load\n"
            "h = load('helpers')\nh.run(request.args['q'])",
        )
    ]
    findings, notices = project_flows(sources, unavailable=("helpers.py",))
    assert not findings and any(
        "importlib target pass unavailable/incomplete" in n for n in notices
    )
