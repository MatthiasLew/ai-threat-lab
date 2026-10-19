"""Bounded SQLite contexts: public observations, flow barriers and no target execution."""

import json
import socket
import sqlite3

import pytest
from test_cli_process import run_cli
from test_python_local_calls import PREFIX, flows
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.code_review import render_code_review, review_source
from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.python_project_flow import project_flows
from ai_threat_lab.remote_audit import GithubAudit
from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, read_bundle, scope_digest
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService


@pytest.mark.parametrize(
    "setup,manager",
    [
        ("", "sqlite3.connect(':memory:')"),
        ("", "sqlite3.connect(database=':memory:')"),
        ("import sqlite3 as db\n", "db.connect(':memory:')"),
        ("from sqlite3 import connect as open_db\n", "open_db(':memory:')"),
        ("open_db = sqlite3.connect\n", "open_db(':memory:')"),
        ("connection = sqlite3.connect(':memory:')\n", "connection"),
        ("connection = sqlite3.connect(':memory:')\nalias = connection\n", "alias"),
        ("def get_db():\n    return sqlite3.connect(':memory:')\n", "get_db()"),
    ],
)
def test_selected_connection_contexts_preserve_query_candidates(setup, manager):
    source = (
        PREFIX + setup + "with " + manager + " as con:\n    con.execute(request.args['PRIVATE'])"
    )
    result = flows(source)
    assert len(result) == 1 and result[0].rule_id == "PY014"
    assert "PRIVATE" not in result[0].rationale


@pytest.mark.parametrize(
    "option",
    [
        "timeout=2",
        "detect_types=0",
        "isolation_level=None",
        "check_same_thread=False",
        "cached_statements=4",
        "uri=False",
        "autocommit=True",
    ],
)
def test_selected_keyword_options_do_not_erase_default_connection_kind(option):
    source = PREFIX + "with sqlite3.connect(':memory:', " + option + ") as con:\n"
    assert len(flows(source + "    con.execute(request.args['q'])")) == 1


@pytest.mark.parametrize(
    "manager",
    [
        "unknown()",
        "sqlite3.connect(':memory:').cursor()",
        "sqlite3.connect(':memory:').execute('SELECT 1')",
        "sqlite3.Connection(':memory:')",
        "sqlite3.connect()",
        "sqlite3.connect(':memory:', 2)",
        "sqlite3.connect(*args)",
        "sqlite3.connect(**options)",
        "sqlite3.connect(':memory:', **options)",
        "sqlite3.connect(':memory:', database='other')",
        "sqlite3.connect(':memory:', factory=custom)",
        "sqlite3.connect(':memory:', factory=sqlite3.Connection)",
        "sqlite3.connect(':memory:', unknown=True)",
        "sqlite3.connect(':memory:', timeout=1, timeout=2)",
        "closing(sqlite3.connect(':memory:'))",
    ],
)
def test_unsupported_managers_and_connection_forms_remain_barriers(manager):
    source = PREFIX + "from contextlib import closing\nvalue = request.args['q']\n"
    source += "with " + manager + " as con:\n    os.system(value)\nos.system(value)"
    result = review_source(source)
    assert not flows(source)
    assert any("unsupported context manager/target" in n for n in result.limitations)


@pytest.mark.parametrize("target", ["first, second", "object.attr", "items[0]"])
def test_non_name_context_targets_are_not_guessed(target):
    source = PREFIX + "with sqlite3.connect(':memory:') as " + target + ":\n"
    result = review_source(source + "    os.system(request.args['q'])")
    assert not [f for f in result.findings if f.rule_id == "PY013"]
    assert any("unsupported context manager/target" in n for n in result.limitations)


def test_context_without_as_keeps_existing_connection_and_values_after_exit():
    source = PREFIX + "con = sqlite3.connect(':memory:')\nwith con:\n"
    source += "    query = request.args['q']\ncon.execute(query)"
    assert len(flows(source)) == 1


def test_as_name_survives_context_and_preserves_cursor_and_shell_flows():
    source = PREFIX + "with sqlite3.connect(':memory:') as con:\n    value = request.args['q']\n"
    source += "con.cursor().execute(value)\nos.system(value)"
    assert {f.rule_id for f in flows(source)} == {"PY013", "PY014"}


def test_multiple_items_enter_left_to_right_and_preserve_prior_aliases():
    source = PREFIX + "with sqlite3.connect(':memory:') as con, con as alias:\n"
    source += "    alias.execute(request.args['q'])"
    assert len(flows(source)) == 1


def test_eight_context_items_supported_ninth_skips_body():
    item = "sqlite3.connect(':memory:') as c"
    body = "\n    c.execute(request.args['q'])"
    assert len(flows(PREFIX + "with " + ", ".join([item] * 8) + ":" + body)) == 1
    result = review_source(PREFIX + "with " + ", ".join([item] * 9) + ":" + body)
    assert not [f for f in result.findings if f.rule_id == "PY014"]
    assert any("context-item limit" in n for n in result.limitations)


def test_unknown_later_manager_does_not_analyze_body_or_keep_partial_state():
    source = PREFIX + "with sqlite3.connect(':memory:') as con, unknown():\n"
    source += "    os.system(request.args['q'])\ncon.execute(request.args['q'])"
    assert not flows(source)


def test_manager_expression_is_analyzed_before_unknown_enter_barrier():
    result = flows(PREFIX + "with os.system(request.args['q']):\n    pass")
    assert len(result) == 1 and result[0].rule_id == "PY013"


def test_nested_contexts_and_branch_values_reach_selected_sinks():
    source = PREFIX + "with sqlite3.connect(':memory:') as first:\n"
    source += "    with first as second:\n        if flag:\n"
    source += "            value = request.args['q']\n        else:\n            value = 'fixed'\n"
    source += "        second.execute(value)"
    assert len(flows(source)) == 1


@pytest.mark.parametrize("other", ["sqlite3.connect(':memory:').cursor()", "unknown()"])
def test_joined_connection_and_other_kind_cannot_enter_supported_context(other):
    source = PREFIX + "if flag:\n    con = sqlite3.connect(':memory:')\nelse:\n"
    source += "    con = " + other + "\nwith con:\n    os.system(request.args['q'])"
    result = review_source(source)
    assert not flows(source)
    assert any("join lost ambiguous" in n for n in result.limitations)


def test_join_of_two_connections_keeps_selected_context_kind():
    source = PREFIX + "if flag:\n    con = sqlite3.connect(':memory:')\nelse:\n"
    source += "    con = sqlite3.connect('fixture.db')\nwith con:\n"
    assert len(flows(source + "    con.execute(request.args['q'])")) == 1


@pytest.mark.parametrize("statement", ["return", "raise Exception()"])
def test_terminated_context_body_does_not_reach_successor(statement):
    source = PREFIX + "def endpoint():\n    with sqlite3.connect(':memory:') as con:\n"
    source += "        value = request.args['q']\n        " + statement
    source += "\n    os.system(value)"
    assert not flows(source)


def test_return_from_context_reaches_caller_without_database_execution():
    source = PREFIX + "def get_value():\n    with sqlite3.connect(':memory:'):\n"
    source += "        return request.args['q']\nos.system(get_value())"
    result = flows(source)
    assert len(result) == 1 and "Local call-site line(s):" in result[0].rationale


def test_connection_argument_and_return_keep_context_kind():
    source = PREFIX + "def identity(value):\n    return value\n"
    source += "with identity(sqlite3.connect(':memory:')) as con:\n"
    assert len(flows(source + "    con.execute(request.args['q'])")) == 1


def test_parameterized_query_values_are_not_query_text_candidates():
    source = PREFIX + "with sqlite3.connect(':memory:') as con:\n"
    source += "    con.execute('SELECT ?', (request.args['q'],))"
    assert not flows(source)


def test_async_context_remains_unsupported():
    source = PREFIX + "async def endpoint():\n    async with sqlite3.connect(':memory:') as con:\n"
    source += "        con.execute(request.args['q'])"
    assert not flows(source)


def test_rebound_sqlite_import_does_not_create_connection_descriptor():
    source = PREFIX + "sqlite3 = unknown\nwith sqlite3.connect(':memory:') as con:\n"
    assert not flows(source + "    con.execute(request.args['q'])")


def test_context_nesting_keeps_existing_depth_limit():
    source = PREFIX + "def endpoint():\n"
    for level in range(34):
        source += "    " * (level + 1) + "with sqlite3.connect(':memory:'):\n"
    source += "    " * 35 + "os.system(request.args['q'])"
    result = review_source(source)
    assert not flows(source)
    assert any("control-flow nesting limit" in n for n in result.limitations)


def cross_file_sources():
    return [
        (
            "app.py",
            "from flask import request\nfrom helpers import open_database, run\n"
            "with open_database() as con:\n    run(con, request.args['PRIVATE'])",
        ),
        (
            "helpers.py",
            "import sqlite3\ndef open_database():\n"
            "    return sqlite3.connect(':memory:')\ndef run(con, value):\n    con.execute(value)",
        ),
    ]


def test_project_pass_keeps_returned_connection_and_cross_file_evidence():
    findings, _ = project_flows(cross_file_sources())
    assert len(findings) == 1 and findings[0].check == "PY014"
    assert "helpers.py:5" in findings[0].evidence and "app.py:4" in findings[0].evidence
    assert "PRIVATE" not in str(findings)


def test_cli_json_sarif_bundle_without_database_or_network(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("source analysis executed a database or network operation")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    project = tmp_path / "project"
    project.mkdir()
    for name, source in cross_file_sources():
        (project / name).write_text(source)
    assert {f.check for f in local_inventory(str(project)).findings} == {"PY014"}
    process = run_cli("audit", project)
    assert process.returncode == 0
    assert {f["check"] for f in json.loads(process.stdout)["findings"]} == {"PY014"}
    source = PREFIX + "with sqlite3.connect('DO_NOT_OPEN.db') as con:\n"
    source += "    con.execute(request.args['PRIVATE'])"
    review = review_source(source)
    sarif = json.loads(render_code_review(review, "sarif"))
    assert sarif["runs"][0]["results"][0]["ruleId"] == "PY014"
    assert "PRIVATE" not in json.dumps(sarif)
    standalone = project / "standalone.py"
    standalone.write_text(source)
    output = tmp_path / "review.sarif"
    assert (
        run_cli(
            "review-code", standalone, "--format", "sarif", "--output", output, cwd=project
        ).returncode
        == 0
    )
    assert not (project / "DO_NOT_OPEN.db").exists()
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "bundle")
    assert len(read_bundle(tmp_path / "bundle")["documents"]["assessment.json"]["findings"]) == 2


def test_pinned_github_uses_existing_verified_blobs_for_context_pass():
    entries, documents = [], []
    for name, source in cross_file_sources():
        entry, document = blob(source)
        entry["path"] = name
        entries.append(entry)
        documents.append(document)
    client = QueueHTTP(*repository(*entries), *documents)
    snapshot = GithubAudit(client).collect("https://github.com/owner/repo")
    assert len(client.calls) == 5
    assert {f.check for f in snapshot.assessment.findings} == {"PY014"}


def test_engine_seventeen_readable_without_comparing_expanded_context_scope(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("eval(user_value)")
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    assert current["manifest"]["scope"]["engine"] == "read-only-pipeline-18"
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-17"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    assert not compare_bundles(read_bundle(tmp_path / "old"), current)["comparable"]


def test_missing_sqlite_context_demo_evidence_prevents_completion(tmp_path, monkeypatch):
    from ai_threat_lab import offline_cli
    from ai_threat_lab.assessment import AssessmentResult
    from ai_threat_lab.models import ValidationError

    original = offline_cli.assessor

    def missing_context(options):
        if options.target.endswith("python-sqlite-context.py"):
            return AssessmentResult(options.target, "python_source", "partial", (), ())
        return original(options)

    monkeypatch.setattr(offline_cli, "assessor", missing_context)
    with pytest.raises(ValidationError, match="SQLite-context acceptance failed"):
        offline_cli.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo/demo-result.json").exists()
