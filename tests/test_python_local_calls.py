"""Bounded same-file helper arguments, returns and privacy-preserving evidence."""

import json
import socket

import pytest
from test_cli_process import run_cli
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.code_review import render_code_review, review_source
from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.models import ValidationError
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, read_bundle, scope_digest
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService

PREFIX = "from flask import request\nimport os, sqlite3\n"


def flows(source):
    return [f for f in review_source(source).findings if f.rule_id in ("PY013", "PY014")]


@pytest.mark.parametrize(
    "signature,call",
    [
        ("value", "helper(request.args['q'])"),
        ("value", "helper(value=request.args['q'])"),
        ("value, /", "helper(request.args['q'])"),
        ("*, value", "helper(value=request.args['q'])"),
        ("value, extra='fixed'", "helper(request.args['q'])"),
        ("prefix, value", "helper('fixed', value=request.args['q'])"),
        ("value='fixed'", "helper(value=request.args['q'])"),
        ("value, *, extra='fixed'", "helper(request.args['q'])"),
    ],
)
def test_supported_parameter_binding(signature, call):
    source = PREFIX + f"def helper({signature}):\n    os.system(value)\n" + call
    result = flows(source)
    assert len(result) == 1
    assert result[0].rule_id == "PY013" and "Local call-site line(s):" in result[0].rationale


@pytest.mark.parametrize(
    "body",
    [
        "return value",
        "return 'prefix '+value",
        "return f'prefix {value}'",
        "if flag:\n    return value\nelse:\n    return 'fixed'",
        "if flag:\n    return value",
        "return value.strip()",
    ],
)
def test_selected_return_values_propagate_with_call_site_evidence(body):
    indented = "\n".join("    " + line for line in body.splitlines())
    source = PREFIX + "def helper(value):\n" + indented
    source += "\nresult=helper(request.args['q'])\nos.system(result)"
    result = flows(source)
    assert len(result) == 1 and "Local call-site line(s):" in result[0].rationale


def test_helper_can_return_selected_http_source_without_caller_input():
    source = PREFIX + "def helper():\n    return request.args['q']\nos.system(helper())"
    result = flows(source)
    assert len(result) == 1 and "line(s): 4." in result[0].rationale
    assert "Local call-site line(s): 5." in result[0].rationale


@pytest.mark.parametrize(
    "source",
    [
        "def helper(value):\n    return 'fixed'\nos.system(helper(request.args['q']))",
        "def helper(value):\n    pass\nos.system(helper(request.args['q']))",
        "def helper(value):\n    value='fixed'\n    os.system(value)\nhelper(request.args['q'])",
        "def helper(value='fixed'):\n    os.system(value)\nhelper()",
        "def helper(*, value='fixed'):\n    os.system(value)\nhelper()",
        "def helper(value):\n    os.system(value)\nhelper('fixed')",
        "def helper(value):\n    os.system(value)\nhelper=unknown\nhelper(request.args['q'])",
        "def helper(value):\n    os.system(value)\nif flag:\n    helper=unknown\n"
        "helper(request.args['q'])",
        "from another_module import helper\nhelper(request.args['q'])",
    ],
)
def test_nonmatching_returns_overwrites_and_unknown_bindings(source):
    assert not flows(PREFIX + source)


@pytest.mark.parametrize(
    "signature,call",
    [
        ("value", "helper()"),
        ("value, value", "helper(request.args['q'], 'fixed')"),
        ("value", "helper(request.args['q'], 'extra')"),
        ("value", "helper(unexpected=request.args['q'])"),
        ("value", "helper(request.args['q'], value=request.args['q'])"),
        ("value", "helper(value=request.args['q'], value=request.args['q'])"),
        ("value, /", "helper(value=request.args['q'])"),
        ("*, value", "helper(request.args['q'])"),
        ("*, value", "helper()"),
        ("value", "helper(*[request.args['q']])"),
        ("value", "helper(**{'value': request.args['q']})"),
        ("*value", "helper(request.args['q'])"),
        ("**value", "helper(value=request.args['q'])"),
        ("value=dynamic()", "helper(request.args['q'])"),
        ("*, value=dynamic()", "helper(value=request.args['q'])"),
    ],
)
def test_unsupported_or_invalid_binding_keeps_gap_without_guessing(signature, call):
    source = PREFIX + f"def helper({signature}):\n    os.system(value)\n" + call
    result = review_source(source)
    assert not [f for f in result.findings if f.rule_id == "PY013"]
    assert any("signature or argument binding" in n for n in result.limitations)


@pytest.mark.parametrize(
    "definition",
    [
        "@decorator\ndef helper(value):\n    os.system(value)",
        "async def helper(value):\n    os.system(value)",
        "def helper(value):\n    yield value\n    os.system(value)",
        "def helper(value):\n    yield from value\n    os.system(value)",
    ],
)
def test_decorated_async_and_generator_calls_are_not_executed_abstractly(definition):
    result = review_source(PREFIX + definition + "\nhelper(request.args['q'])")
    assert not [f for f in result.findings if f.rule_id == "PY013"]
    assert any("signature or argument binding" in n for n in result.limitations)


def test_sqlite_and_request_object_arguments_are_propagated():
    source = PREFIX + "def helper(connection, req):\n    connection.execute(req.args['q'])\n"
    source += "helper(sqlite3.connect(':memory:'), request)"
    assert [f.rule_id for f in flows(source)] == ["PY014"]


def test_sqlite_connection_return_keeps_selected_identity():
    source = PREFIX + "def connect():\n    return sqlite3.connect(':memory:')\n"
    source += "db=connect()\ndb.execute(request.args['q'])"
    assert [f.rule_id for f in flows(source)] == ["PY014"]


def test_callable_aliases_and_parameter_forwarding():
    source = PREFIX + "def sink(value):\n    os.system(value)\n"
    source += "def helper(callback, value):\n    callback(value)\n"
    source += "alias=sink\nhelper(alias, request.args['q'])"
    assert len(flows(source)) == 1


def test_chained_helpers_preserve_call_lines_through_return():
    source = PREFIX + "def first(value):\n    return value\n"
    source += "def second(value):\n    return first(value)\n"
    source += "os.system(second(request.args['q']))"
    result = flows(source)
    assert len(result) == 1 and "Local call-site line(s): 6, 7." in result[0].rationale


def test_multiple_calls_merge_same_sink_and_source_line_evidence():
    source = PREFIX + "def helper(value):\n    os.system(value)\n"
    source += "helper(request.args['q'])\nhelper(request.form['q'])"
    result = flows(source)
    assert len(result) == 1 and "line(s): 5, 6." in result[0].rationale
    assert "Local call-site line(s): 5, 6." in result[0].rationale


def test_local_parameter_state_does_not_leak_to_next_call():
    source = PREFIX + "def helper(value):\n    os.system(value)\n"
    source += "helper(request.args['q'])\nhelper('fixed')"
    result = flows(source)
    assert len(result) == 1 and "Local call-site line(s): 5." in result[0].rationale


def test_recursion_is_skipped_with_gap_without_missing_prior_sink():
    source = PREFIX + "def helper(value):\n    os.system(value)\n    helper(value)\n"
    result = review_source(source + "helper(request.args['q'])")
    assert len([f for f in result.findings if f.rule_id == "PY013"]) == 1
    assert any("recursive local call skipped" in n for n in result.limitations)


def test_forward_and_nested_helper_calls_remain_unresolved():
    source = PREFIX + "def endpoint():\n    helper(request.args['q'])\n"
    source += "def helper(value):\n    os.system(value)\nendpoint()"
    result = review_source(source)
    assert not [f for f in result.findings if f.rule_id == "PY013"]
    assert any("unknown call results" in n for n in result.limitations)
    nested = PREFIX + "def endpoint():\n    def helper(value):\n        os.system(value)\n"
    nested += "    helper(request.args['q'])"
    assert not flows(nested)


@pytest.mark.parametrize("limit", ["MAX_CALLS", "MAX_CALL_DEPTH", "MAX_FUNCTIONS"])
def test_limits_keep_explicit_gaps(limit, monkeypatch):
    import ai_threat_lab.python_flow as module

    monkeypatch.setattr(module, limit, 1)
    source = PREFIX + "def first(value):\n    os.system(value)\n"
    source += "def second(value):\n    first(value)\n"
    source += "second(request.args['q'])\nsecond(request.form['q'])"
    result = review_source(source)
    assert any("limit" in n for n in result.limitations)


def test_parameter_limit_has_binding_gap(monkeypatch):
    import ai_threat_lab.python_call_binding as module

    monkeypatch.setattr(module, "MAX_PARAMETERS", 1)
    source = PREFIX + "def helper(value, extra):\n    os.system(value)\n"
    result = review_source(source + "helper(request.args['q'], 'fixed')")
    assert not [f for f in result.findings if f.rule_id == "PY013"]
    assert any("signature or argument binding" in n for n in result.limitations)


def test_evidence_limits_are_explicit_for_multiple_contexts():
    source = PREFIX + "def helper(value):\n    os.system(value)\n"
    source += "\n".join("helper(request.args['q'])" for _ in range(12))
    result = review_source(source)
    assert len([f for f in result.findings if f.rule_id == "PY013"]) == 1
    assert any("evidence limit" in n for n in result.limitations)


SAMPLE = PREFIX + "def helper(connection, value):\n    os.system(value)\n"
SAMPLE += "    connection.execute('SELECT '+value)\n"
SAMPLE += "helper(sqlite3.connect(':memory:'), request.args['PRIVATE_KEY'])\n"


@pytest.mark.parametrize("format", ["txt", "json", "sarif"])
def test_reports_include_call_lines_but_no_source_values(format):
    report = render_code_review(review_source(SAMPLE, "source.py"), format)
    assert "PRIVATE_KEY" not in report
    assert "Local call-site line(s): 6." in report
    if format == "sarif":
        results = json.loads(report)["runs"][0]["results"]
        assert len(results) == 3 and all(r["properties"]["candidateOnly"] for r in results)


def test_analysis_never_imports_executes_or_connects(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("local-call analysis attempted network access")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    marker = tmp_path / "must-not-exist"
    source = SAMPLE + f'\nopen({str(marker)!r}, "w").write("ran")'
    assert len(flows(source)) == 2 and not marker.exists()


def test_local_github_and_bundle_preserve_call_evidence(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "source.py").write_text(SAMPLE)
    result = local_inventory(str(project))
    assert {f.check for f in result.findings} == {"PY005", "PY013", "PY014"}
    assert any("Local call-site line(s): 6." in f.evidence for f in result.findings)
    item, data = blob(SAMPLE)
    snapshot = GithubAudit(QueueHTTP(*repository(item), data)).collect(
        "https://github.com/owner/repo"
    )
    assert any("Local call-site line(s): 6." in f.evidence for f in snapshot.assessment.findings)
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "bundle")
    assert len(read_bundle(tmp_path / "bundle")["documents"]["assessment.json"]["findings"]) == 3


def test_real_cli_exit_and_no_overwrite(tmp_path):
    source = tmp_path / "source.py"
    source.write_text(SAMPLE)
    report = tmp_path / "report.sarif"
    result = run_cli(
        "review-code", source, "--format", "sarif", "--output", report, "--fail-on-findings"
    )
    assert result.returncode == 1 and not result.stderr
    before = report.read_bytes()
    assert run_cli("review-code", source, "--output", report).returncode == 2
    assert report.read_bytes() == before


def test_engine_thirteen_reading_without_cross_engine_deltas(tmp_path):
    source = tmp_path / "source.py"
    source.write_text(SAMPLE)
    ScanService(assessor).run(ScanOptions(str(source)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    assert current["manifest"]["scope"]["engine"] == "read-only-pipeline-17"
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-13"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    comparison = compare_bundles(read_bundle(tmp_path / "old"), current)
    assert comparison["comparable"] is False and comparison["counts"] is None


def test_returned_call_evidence_has_explicit_line_cap():
    source = PREFIX + "def helper(value):\n    return value\nvalue=request.args['q']\n"
    source += "value=helper(value)\n" * 12 + "os.system(value)"
    result = review_source(source)
    assert len([f for f in result.findings if f.rule_id == "PY013"]) == 1
    assert any("call-site evidence limit" in n for n in result.limitations)


def test_missing_local_call_evidence_prevents_demo_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as module
    from ai_threat_lab.assessment import AssessmentResult

    original = module.assessor

    def missing(options):
        if options.target.endswith("python-local-calls.py"):
            return AssessmentResult(options.target, "python_source", "partial", (), ("Fixture",))
        return original(options)

    monkeypatch.setattr(module, "assessor", missing)
    with pytest.raises(ValidationError, match="local-call acceptance"):
        module.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo" / "demo-result.json").exists()
