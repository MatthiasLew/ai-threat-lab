"""Bounded HTTP input dependencies, conservative barriers and source-free evidence."""

import json
import socket

import pytest
from test_cli_process import run_cli
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.acceptance_samples import synthetic_python_flow
from ai_threat_lab.assessment import AssessmentService
from ai_threat_lab.code_review import render_code_review, review_source
from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.models import ValidationError
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, read_bundle, scope_digest
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService

PREFIX = "from flask import request\nimport os, sqlite3, subprocess\n"


def flows(source):
    return [f for f in review_source(source).findings if f.rule_id in ("PY013", "PY014")]


@pytest.mark.parametrize(
    "expression",
    [
        "request.args['q']",
        "request.args.get('q')",
        "request.form.get('q')",
        "request.values.getlist('q')",
        "request.cookies['q']",
        "request.headers.get('q')",
        "request.json['q']",
        "request.get_json()['q']",
        "request.data",
        "request.query_string",
        "request.get_data(as_text=True)",
    ],
)
def test_selected_sources_have_line_only_origin(expression):
    result = flows(PREFIX + f"value = {expression}\nos.system(value)\n")
    assert len(result) == 1 and result[0].rule_id == "PY013"
    assert result[0].line == 4 and "line(s): 3." in result[0].rationale
    assert expression not in result[0].rationale


@pytest.mark.parametrize(
    "expression",
    [
        "value",
        "'prefix ' + value",
        "'prefix %s' % value",
        "f'prefix {value}'",
        "'prefix {}'.format(value)",
        "' '.join([value, 'suffix'])",
        "str(value)",
        "value.strip().lower()",
        "value.replace('a', 'b')",
        "value.encode().decode()",
    ],
)
def test_selected_propagation_preserves_original_source_line(expression):
    result = flows(
        PREFIX + "value = request.args['private-key']\n"
        f"command = {expression}\nos.system(command)\n"
    )
    assert len(result) == 1 and "line(s): 3." in result[0].rationale


@pytest.mark.parametrize(
    "sink",
    [
        "os.system(value)",
        "os.popen(value)",
        "subprocess.run(value, shell=True)",
        "subprocess.Popen(args=value, shell=True)",
        "subprocess.call(value, shell=True)",
        "subprocess.check_call(value, shell=True)",
        "subprocess.check_output(value, shell=True)",
    ],
)
def test_shell_sinks_require_selected_input(sink):
    assert len(flows(PREFIX + "value=request.args['q']\n" + sink)) == 1


@pytest.mark.parametrize(
    "sink",
    [
        "connection.execute(query)",
        "connection.executemany(query, [])",
        "connection.executescript(query)",
        "connection.cursor().execute(query)",
        "cursor.execute(query)",
        "cursor.executemany(query, [])",
        "cursor.executescript(query)",
        "sqlite3.connect(':memory:').execute(query)",
    ],
)
def test_sqlite_connection_and_cursor_identities(sink):
    source = PREFIX + "value=request.args['q']\nquery='SELECT ' + value\n"
    source += "connection=sqlite3.connect(':memory:')\ncursor=connection.cursor()\n" + sink
    result = flows(source)
    assert len(result) == 1 and result[0].rule_id == "PY014"


@pytest.mark.parametrize(
    "source",
    [
        "value='constant'\nos.system(value)",
        "value=request.args['q']\nvalue='fixed'\nos.system(value)",
        "value=request.args['q']\ndel value\nos.system(value)",
        "value=request.args['q']\nsubprocess.run([value], shell=False)",
        "value=request.args['q']\nsubprocess.run(value, shell=policy)",
        "value=request.args['q']\nsubprocess.run(value)",
        "value=request.endpoint\nos.system(value)",
        "value=request.args['q']\nconnection=sqlite3.connect(':memory:')\n"
        "connection.execute('SELECT ? ', (value,))",
        "value=request.args['q']\nother.execute(value)",
        "value=request.args['q']\nconnection=sqlite3.connect(':memory:')\n"
        "connection=other\nconnection.execute(value)",
        "request=other\nos.system(request.args['q'])",
        "os=other\nos.system(request.args['q'])",
        "value=request.args['q']\ncommand=unknown_wrapper(value)\nos.system(command)",
        "def run(request):\n    os.system(request.args['q'])",
        "def run(*request):\n    os.system(request.args['q'])",
        "def run(**request):\n    os.system(request.args['q'])",
        "def run(*, request):\n    os.system(request.args['q'])",
        "def run(request, /):\n    os.system(request.args['q'])",
        "def run():\n    return\n    os.system(request.args['q'])",
        "def run():\n    raise Error\n    os.system(request.args['q'])",
        "value=request.args['q']\nstr=other\ncommand=str(value)\nos.system(command)",
        "value=request.args['q']\na, b=(value, value)\nos.system(a)",
        "value=request.args['q']\nvalue*=2\nos.system(value)",
    ],
)
def test_unselected_overwritten_unknown_or_out_of_scope_values(source):
    assert not flows(PREFIX + source)


def test_import_aliases_and_request_object_aliases():
    source = "import flask as f\nfrom os import system as shell\n"
    source += "from sqlite3 import connect as open_db\nreq=f.request\n"
    source += "def endpoint():\n    value=req.args.get('q')\n    shell(value)\n"
    source += "    db=open_db(':memory:')\n    copied=db\n    copied.execute(value)\n"
    assert [f.rule_id for f in flows(source)] == ["PY013", "PY014"]


def test_chained_annotated_and_augmented_assignments():
    source = PREFIX + "value=request.args['q']\na=b=value\ncommand: str = a\n"
    source += "command += b\nos.system(command)\n"
    assert len(flows(source)) == 1


@pytest.mark.parametrize(
    "barrier",
    [
        "with resource:\n    pass",
        "try:\n    pass\nexcept Error:\n    pass",
        "class Example:\n    pass",
        "match value:\n    case 1:\n        pass",
        "global value",
    ],
)
def test_control_flow_barriers_reset_tracking_with_explicit_gap(barrier):
    result = review_source(PREFIX + "value=request.args['q']\n" + barrier + "\nos.system(value)")
    assert not [f for f in result.findings if f.rule_id == "PY013"]
    assert any("tracking reset" in n for n in result.limitations)


def test_independent_function_environments_and_explicit_caller_argument_inference():
    source = PREFIX + "def first():\n    value=request.args['q']\n    os.system(value)\n"
    source += "def second(value):\n    os.system(value)\nsecond(request.args['q'])\n"
    assert len(flows(source)) == 2


def test_nested_receiver_call_is_not_evaluated_twice():
    assert len(flows(PREFIX + "os.system(request.args['q']).strip()")) == 1


def test_original_source_lines_merge_with_bounded_origin_evidence():
    source = PREFIX + "".join(f"v{i}=request.args['q']\n" for i in range(9))
    source += "os.system(" + " + ".join(f"v{i}" for i in range(9)) + ")"
    result = review_source(source)
    flow = [f for f in result.findings if f.rule_id == "PY013"][0]
    assert "line(s): 3, 4, 5, 6, 7, 8, 9, 10." in flow.rationale
    assert any("source-origin limit" in n for n in result.limitations)


@pytest.mark.parametrize("limit", ["MAX_STEPS", "MAX_DEPTH", "MAX_SCOPES", "MAX_FINDINGS"])
def test_resource_limits_have_visible_gaps(limit, monkeypatch):
    import ai_threat_lab.python_flow as module

    monkeypatch.setattr(module, limit, 1)
    source = PREFIX + "def endpoint():\n    os.system(request.args['q'])\n"
    source += "os.system(request.args['q'])\nos.system(request.args['q'])\n"
    result = review_source(source)
    assert any("limit reached" in n for n in result.limitations)


@pytest.mark.parametrize("format", ["txt", "json", "sarif"])
def test_source_free_reports_and_line_locations(format):
    source = synthetic_python_flow().replace("fixture", "PRIVATE_TOKEN")
    rendered = render_code_review(review_source(source, "source.py"), format)
    assert "PRIVATE_TOKEN" not in rendered
    assert "PY013" in rendered and "PY014" in rendered and "line(s): 4." in rendered
    if format == "sarif":
        results = json.loads(rendered)["runs"][0]["results"]
        assert [r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results] == [
            6,
            6,
            9,
        ]
        assert all(r["properties"]["candidateOnly"] for r in results)


def test_no_import_execution_or_network(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("flow review attempted network access")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    marker = tmp_path / "must-not-exist"
    source = synthetic_python_flow() + f'\nopen({str(marker)!r}, "w").write("ran")\n'
    assert len(flows(source)) == 2 and not marker.exists()


def test_local_scan_reports_keep_origin_and_gap_evidence(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    source = synthetic_python_flow() + "\nwith resource:\n    pass\n"
    (project / "source.py").write_text(source)
    for result in (AssessmentService().assess(str(project)), local_inventory(str(project))):
        assert len(result.findings) == 3
        assert any("line(s): 4." in f.evidence for f in result.findings)
        assert any("tracking reset" in n for n in result.not_checked)
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "bundle")
    bundle = read_bundle(tmp_path / "bundle")
    assert len(bundle["documents"]["assessment.json"]["findings"]) == 3


def test_immutable_github_keeps_origin_and_gap_evidence():
    item, data = blob(synthetic_python_flow() + "\nwith resource:\n    pass\n")
    client = QueueHTTP(*repository(item), data)
    snapshot = GithubAudit(client).collect("https://github.com/owner/repo")
    assert len(client.calls) == 4
    assert {f.check for f in snapshot.assessment.findings} == {"PY005", "PY013", "PY014"}
    assert any("line(s): 4." in f.evidence for f in snapshot.assessment.findings)
    assert any("tracking reset" in n for n in snapshot.assessment.not_checked)


def test_real_cli_json_sarif_exit_and_no_overwrite(tmp_path):
    source = tmp_path / "source.py"
    source.write_text(synthetic_python_flow())
    output = tmp_path / "source.sarif"
    process = run_cli(
        "review-code", source, "--format", "sarif", "--output", output, "--fail-on-findings"
    )
    assert process.returncode == 1 and not process.stderr
    assert len(json.loads(output.read_text())["runs"][0]["results"]) == 3
    before = output.read_bytes()
    assert run_cli("review-code", source, "--output", output).returncode == 2
    assert output.read_bytes() == before


def test_engine_eleven_reading_without_cross_engine_comparison(tmp_path):
    source = tmp_path / "source.py"
    source.write_text(synthetic_python_flow())
    ScanService(assessor).run(ScanOptions(str(source)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    assert current["manifest"]["scope"]["engine"] == "read-only-pipeline-24"
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-11"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    comparison = compare_bundles(read_bundle(tmp_path / "old"), current)
    assert comparison["comparable"] is False and comparison["counts"] is None


def test_missing_flow_demo_evidence_prevents_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as module
    from ai_threat_lab.assessment import AssessmentResult

    original = module.assessor

    def missing(options):
        if options.target.endswith("python-flow.py"):
            return AssessmentResult(options.target, "python_source", "partial", (), ("Fixture",))
        return original(options)

    monkeypatch.setattr(module, "assessor", missing)
    with pytest.raises(ValidationError, match="Python flow acceptance"):
        module.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo" / "demo-result.json").exists()


@pytest.mark.parametrize(
    "source",
    [
        "os.system(request.args['q'])",
        "from other import request\nimport os\nos.system(request.args['q'])",
        "from flask import request\nimport os\nfrom .other import request\n"
        "os.system(request.args['q'])",
        "from flask import request\nimport os\nfrom unknown import *\nos.system(request.args['q'])",
    ],
)
def test_sources_require_supported_unshadowed_import_bindings(source):
    assert not flows(source)


def test_scope_and_expression_gaps_are_retained():
    result = review_source(
        PREFIX + "value=request.args['q']\n"
        "pair=(value, value)\nleft, right=pair\n"
        "object.value=value\ncommand=unknown(value)\n"
        "from .relative import name\n"
    )
    assert any("writes are not modeled" in n for n in result.limitations)
    assert any("unknown call results" in n for n in result.limitations)
    assert any("relative/star imports" in n for n in result.limitations)


def test_captured_request_collections_are_not_propagated_into_function_scopes():
    source = PREFIX + "captured=request.args\ndef endpoint():\n"
    source += "    os.system(captured.get('q'))\n"
    assert not flows(source)
