"""Bounded possible-path joins, loop abstraction and explicit coverage gaps."""

import json

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
    "body",
    [
        "if flag:\n    value=request.args['q']\nelse:\n    value='fixed'",
        "value='fixed'\nif flag:\n    value=request.args['q']",
        "if flag:\n    value='fixed'\nelse:\n    value=request.args['q']",
        (
            "if first:\n    value='fixed'\nelif second:\n    value=requ"
            "est.args['q']\nelse:\n    value='fixed'"
        ),
        (
            "if flag:\n    if second:\n        value=request.args['q']"
            "\n    else:\n        value='fixed'\nelse:\n    value='fixed"
            "'"
        ),
        "value=request.args['q'] if flag else 'fixed'",
        "value='fixed' if flag else request.args['q']",
        "value=request.args.get('q') or 'fixed'",
        "value=flag and request.args['q']",
    ],
)
def test_possible_branch_data_survives_join(body):
    assert len(flows(PREFIX + body + "\nos.system(value)")) == 1


def test_two_source_origins_are_merged_into_one_sink_observation():
    source = PREFIX + (
        "if flag:\n    value=request.args['q']\nelse:\n    value=re"
        "quest.form['q']\nos.system(value)"
    )
    result = flows(source)
    assert len(result) == 1 and "line(s): 4, 6." in result[0].rationale


@pytest.mark.parametrize(
    "body",
    [
        "value=request.args['q']\nif flag:\n    value='a'\nelse:\n    value='b'",
        "if False:\n    value=request.args['q']\nelse:\n    value='fixed'",
        "if True:\n    value='fixed'\nelse:\n    value=request.args['q']",
        "value=request.args['q'] if False else 'fixed'",
        "value='fixed' if True else request.args['q']",
        "value=False and request.args['q']",
        "value=True or request.args['q']",
        "value=not request.args['q']",
        "value=request.args['q'] == 'fixed'",
        "if request.args['q']:\n    value='a'\nelse:\n    value='b'",
    ],
)
def test_no_implicit_condition_dependency_and_literal_safe_branches(body):
    assert not flows(PREFIX + body + "\nos.system(value)")


@pytest.mark.parametrize(
    "condition",
    [
        "os.system(request.args['q'])",
        "os.system(request.args['q']) == 0",
        "not os.system(request.args['q'])",
    ],
)
def test_nested_condition_sink_is_inspected_once(condition):
    assert len(flows(PREFIX + f"if {condition}:\n    pass")) == 1


@pytest.mark.parametrize("terminator", ["return", "raise Error"])
def test_terminated_branch_does_not_taint_successor(terminator):
    source = PREFIX + "def endpoint():\n    if flag:\n        value=request.args['q']\n"
    source += f"        {terminator}\n    else:\n        value='fixed'\n    os.system(value)"
    assert not flows(source)


def test_both_branches_terminate_and_unreachable_flow_is_skipped():
    source = (
        PREFIX + "def endpoint():\n    if flag:\n        return\n    else:\n        raise Error\n"
    )
    source += "    os.system(request.args['q'])"
    assert not flows(source)


def test_reachable_branch_after_other_branch_return_keeps_input():
    source = PREFIX + "def endpoint():\n    if flag:\n        return\n"
    source += "    else:\n        value=request.args['q']\n    os.system(value)"
    assert len(flows(source)) == 1


@pytest.mark.parametrize(
    "body",
    [
        (
            "if flag:\n    connection=sqlite3.connect(':memory:')\nels"
            "e:\n    connection=sqlite3.connect(':memory:')"
        ),
        (
            "connection=sqlite3.connect(':memory:')\nif flag:\n    con"
            "nection=sqlite3.connect(':memory:')"
        ),
    ],
)
def test_definite_sqlite_identity_is_preserved_across_branches(body):
    assert [
        f.rule_id for f in flows(PREFIX + body + "\nconnection.execute(request.args['q'])")
    ] == ["PY014"]


@pytest.mark.parametrize(
    "body,sink",
    [
        (
            "if flag:\n    connection=sqlite3.connect(':memory:')",
            "connection.execute(request.args['q'])",
        ),
        (
            "connection=sqlite3.connect(':memory:')\nif flag:\n    connection=other",
            "connection.execute(request.args['q'])",
        ),
        ("if flag:\n    os=other", "os.system(request.args['q'])"),
        ("if flag:\n    request=other", "os.system(request.args['q'])"),
    ],
)
def test_ambiguous_api_bindings_are_omitted_with_gap(body, sink):
    result = review_source(PREFIX + body + "\n" + sink)
    assert not [f for f in result.findings if f.rule_id in ("PY013", "PY014")]
    assert any("ambiguous API/object" in n for n in result.limitations)


@pytest.mark.parametrize(
    "expression",
    [
        "request.args.getlist('q')",
        "request.data.split()",
        "request.data.rsplit()",
        "request.data.splitlines()",
    ],
)
def test_loop_target_preserves_input_origins(expression):
    result = review_source(PREFIX + f"for value in {expression}:\n    os.system(value)")
    assert [f.rule_id for f in result.findings if f.rule_id == "PY013"] == ["PY013"]
    assert any("loop-carried" in n for n in result.limitations)


@pytest.mark.parametrize(
    "body",
    [
        "value='fixed'\nfor item in items:\n    value=request.args['q']",
        "value='fixed'\nwhile condition:\n    value=request.args['q']",
        "value=request.args['q']\nfor item in items:\n    value='fixed'",
        "value=request.args['q']\nwhile condition:\n    value='fixed'",
    ],
)
def test_loop_join_preserves_zero_or_one_iteration_possibilities(body):
    assert len(flows(PREFIX + body + "\nos.system(value)")) == 1


@pytest.mark.parametrize(
    "body",
    [
        "while False:\n    os.system(request.args['q'])",
        "while True:\n    pass\nos.system(request.args['q'])",
        "while True:\n    pass\nelse:\n    os.system(request.args['q'])",
        "for value in ['fixed']:\n    os.system(value)",
        "value='fixed'\nfor item in items:\n    os.system(value)\n    value=request.args['q']",
    ],
)
def test_unreachable_literal_while_or_untracked_later_iteration_paths(body):
    assert not flows(PREFIX + body)


def test_literal_infinite_loop_body_is_inspected():
    assert len(flows(PREFIX + "while True:\n    os.system(request.args['q'])")) == 1


@pytest.mark.parametrize("loop", ["for item in items:", "while flag:"])
def test_loop_else_is_processed_after_join(loop):
    source = (
        PREFIX
        + "value='fixed'\n"
        + loop
        + "\n    pass\nelse:\n    value=request.args['q']\nos.system(value)"
    )
    assert len(flows(source)) == 1


@pytest.mark.parametrize("keyword", ["break", "continue"])
def test_unsupported_loop_exits_reset_tracking_without_scanning_dead_tails(keyword):
    source = PREFIX + "value=request.args['q']\nfor item in items:\n    " + keyword
    source += "\n    os.system(value)\nos.system(value)"
    result = review_source(source)
    assert not [f for f in result.findings if f.rule_id == "PY013"]
    assert any("break/continue skipped" in n for n in result.limitations)


def test_return_in_loop_body_does_not_create_a_fallthrough_state():
    source = PREFIX + "def endpoint():\n    value='fixed'\n    for item in items:\n"
    source += "        value=request.args['q']\n        return\n    os.system(value)"
    assert not flows(source)


def test_block_depth_limit_keeps_coverage_gap(monkeypatch):
    import ai_threat_lab.python_flow as module

    monkeypatch.setattr(module, "MAX_BLOCK_DEPTH", 1)
    source = PREFIX + "if first:\n    if second:\n        os.system(request.args['q'])"
    result = review_source(source)
    assert not [f for f in result.findings if f.rule_id == "PY013"]
    assert any("nesting limit" in n for n in result.limitations)


def test_branches_do_not_consume_function_scope_budget(monkeypatch):
    import ai_threat_lab.python_flow as module

    monkeypatch.setattr(module, "MAX_SCOPES", 1)
    source = PREFIX + "if first:\n    if second:\n        os.system(request.args['q'])"
    assert len(flows(source)) == 1


def test_joins_do_not_exponentially_enumerate_paths():
    source = PREFIX + "value=request.args['q']\n" + "if flag:\n    value=value + 'x'\n" * 100
    assert len(flows(source + "os.system(value)")) == 1


SAMPLE = PREFIX + (
    "def endpoint():\n    value='fixed'\n    if flag:\n        value=request.args['PRIVATE_KEY']\n"
)
SAMPLE += "    os.system(value)\n    connection=sqlite3.connect(':memory:')\n"
SAMPLE += (
    "    for term in request.args.getlist('PRIVATE_KEY'):\n  "
    "      connection.execute('SELECT '+term)\n"
)


@pytest.mark.parametrize("format", ["txt", "json", "sarif"])
def test_reports_keep_possible_flow_lines_without_values(format):
    report = render_code_review(review_source(SAMPLE, "source.py"), format)
    assert "PRIVATE_KEY" not in report
    assert "PY013" in report and "PY014" in report
    if format == "sarif":
        results = json.loads(report)["runs"][0]["results"]
        assert len(results) == 3 and all(r["properties"]["candidateOnly"] for r in results)


def test_local_github_and_bundle_use_same_possible_flow_rules(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "source.py").write_text(SAMPLE)
    result = local_inventory(str(project))
    assert {f.check for f in result.findings} == {"PY005", "PY013", "PY014"}
    assert any("loop-carried" in n for n in result.not_checked)
    item, data = blob(SAMPLE)
    remote = GithubAudit(QueueHTTP(*repository(item), data)).collect(
        "https://github.com/owner/repo"
    )
    assert {f.check for f in remote.assessment.findings} == {"PY005", "PY013", "PY014"}
    assert any("loop-carried" in n for n in remote.assessment.not_checked)
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "bundle")
    assert len(read_bundle(tmp_path / "bundle")["documents"]["assessment.json"]["findings"]) == 3


def test_real_cli_exit_policy_and_no_overwrite(tmp_path):
    source = tmp_path / "source.py"
    source.write_text(SAMPLE)
    report = tmp_path / "report.sarif"
    process = run_cli(
        "review-code", source, "--format", "sarif", "--output", report, "--fail-on-findings"
    )
    assert process.returncode == 1 and not process.stderr
    before = report.read_bytes()
    assert run_cli("review-code", source, "--output", report).returncode == 2
    assert report.read_bytes() == before


def test_engine_twelve_remains_readable_without_comparison(tmp_path):
    source = tmp_path / "source.py"
    source.write_text(SAMPLE)
    ScanService(assessor).run(ScanOptions(str(source)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    assert current["manifest"]["scope"]["engine"] == "read-only-pipeline-18"
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-12"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    comparison = compare_bundles(read_bundle(tmp_path / "old"), current)
    assert comparison["comparable"] is False and comparison["counts"] is None


def test_missing_control_flow_demo_evidence_prevents_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as module
    from ai_threat_lab.assessment import AssessmentResult

    original = module.assessor

    def missing(options):
        if options.target.endswith("python-control-flow.py"):
            return AssessmentResult(options.target, "python_source", "partial", (), ("Fixture",))
        return original(options)

    monkeypatch.setattr(module, "assessor", missing)
    with pytest.raises(ValidationError, match="control-flow acceptance"):
        module.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo" / "demo-result.json").exists()
