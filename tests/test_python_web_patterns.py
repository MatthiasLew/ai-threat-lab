"""Web API candidate observations across AST, CLI, SARIF and scan boundaries."""

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

SAMPLE = """import jinja2, jwt
from django.utils.safestring import mark_safe
jinja2.Environment(autoescape=False)
mark_safe(private_customer_html)
jwt.decode(private_token, options={"verify_signature": False})
"""


@pytest.mark.parametrize(
    "source,rule",
    [
        ("import jinja2\njinja2.Environment(autoescape=False)", "PY010"),
        ("import jinja2 as j\nj.Environment(autoescape=False)", "PY010"),
        ("from jinja2 import Environment as Env\nEnv(autoescape=False)", "PY010"),
        ("import django.utils.safestring\ndjango.utils.safestring.mark_safe(data)", "PY011"),
        ("from django.utils.safestring import mark_safe\nmark_safe(data)", "PY011"),
        ("from django.utils import safestring as safe\nsafe.mark_safe(data)", "PY011"),
        ("import markupsafe as m\nm.Markup(data)", "PY011"),
        ("from markupsafe import Markup as Safe\nSafe(data)", "PY011"),
        ('import jwt\njwt.decode(token, options={"verify_signature": False})', "PY012"),
        ('import jwt as j\nj.decode_complete(token, options={"verify_signature": False})', "PY012"),
        (
            'from jwt import decode as read\nread(token, options={"verify_signature": False})',
            "PY012",
        ),
        ('jwt.decode(token, options={"verify_signature": False, "verify_exp": True})', "PY012"),
    ],
)
def test_simple_calls_aliases_and_fixed_source_free_descriptors(source, rule):
    result = review_source(source)
    assert [item.rule_id for item in result.findings] == [rule]
    assert result.engine == "python-ast-1.8"
    assert result.findings[0].rationale and result.findings[0].recommendation


@pytest.mark.parametrize(
    "source",
    [
        "jinja2.Environment(autoescape=True)",
        "jinja2.Environment(autoescape=0)",
        "jinja2.Environment(autoescape=None)",
        "jinja2.Environment(autoescape=policy)",
        "jinja2.Environment(autoescape=select_autoescape())",
        "jinja2.Environment()",
        "jinja2.Environment(**options)",
        "jinja2.Environment(False)",
        "another.Environment(autoescape=False)",
        "markupsafe.escape(data)",
        "markupsafe.Markup.escape(data)",
        "from another import Markup\nMarkup(data)",
        "from another import mark_safe\nmark_safe(data)",
        "mark_safe(data)",
        "jwt.encode(data, key)",
        "jwt.decode(token, verify=False)",
        "jwt.decode(token)",
        "jwt.decode(token, options=policy)",
        'jwt.decode(token, options={"verify_signature": True})',
        'jwt.decode(token, options={"verify_signature": 0})',
        'jwt.decode(token, options={"verify_signature": None})',
        'jwt.decode(token, options={"verify_signature": flag})',
        'jwt.decode(token, options={"verify_exp": False})',
        "jwt.decode(token, options=dict(verify_signature=False))",
        'jwt.decode(token, options={"verify_signature": False, **extra})',
        'jwt.decode(token, options={**extra, "verify_signature": False})',
        'jwt.decode(token, options={key: True, "verify_signature": False})',
        'jwt.decode(token, options={"verify_signature": True, "verify_signature": False})',
        'jwt.decode(token, options={"verify_signature": False, "verify_signature": True})',
        'jwt.decode(token, options={1: True, "verify_signature": False})',
        "jwt.decode(token, options={})",
        'other.decode(token, options={"verify_signature": False})',
        '# jinja2.Environment(autoescape=False)\ntext="markupsafe.Markup(data)"',
    ],
)
def test_unselected_unknown_and_ambiguous_patterns_are_not_guessed(source):
    assert not review_source(source).findings


def test_trusted_static_markup_still_requires_context_review():
    result = review_source('from markupsafe import Markup\nMarkup("<b>Trusted</b>")')
    assert result.findings[0].rule_id == "PY011"
    assert "intentional" in result.findings[0].rationale


@pytest.mark.parametrize("format", ["txt", "json", "sarif"])
def test_reports_omit_html_token_and_source_values(format):
    report = render_code_review(review_source(SAMPLE, "web.py"), format)
    assert "private_customer_html" not in report and "private_token" not in report
    assert all(rule in report for rule in ("PY010", "PY011", "PY012"))
    if format == "sarif":
        run = json.loads(report)["runs"][0]
        assert run["properties"]["engine"] == "python-ast-1.8"
        assert [
            r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in run["results"]
        ] == [3, 4, 5]
        assert all(r["properties"]["candidateOnly"] for r in run["results"])


def test_no_framework_import_execution_or_network(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("AST review attempted a network connection")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    marker = tmp_path / "not-executed"
    source = SAMPLE + f'\nopen({str(marker)!r}, "w").write("executed")\n'
    assert len(review_source(source).findings) == 3
    assert not marker.exists()


def test_local_project_and_bundle_merge(tmp_path):
    project = tmp_path / "source"
    project.mkdir()
    (project / "web.py").write_text(SAMPLE)
    result = local_inventory(str(project))
    assert {f.check for f in result.findings} == {"PY010", "PY011", "PY012"}
    ScanService(assessor).run(ScanOptions(str(project)), tmp_path / "bundle")
    result = read_bundle(tmp_path / "bundle")
    assert len(result["documents"]["assessment.json"]["findings"]) == 3
    assert "private_token" not in (tmp_path / "bundle" / "report.html").read_text()


def test_immutable_github_uses_same_rules():
    item, data = blob(SAMPLE)
    item["path"] = "web.py"
    client = QueueHTTP(*repository(item), data)
    snapshot = GithubAudit(client).collect("https://github.com/owner/repo")
    assert len(client.calls) == 4
    assert {f.check for f in snapshot.assessment.findings} == {"PY010", "PY011", "PY012"}


def test_cli_outputs_exit_policy_and_no_overwrite(tmp_path):
    path = tmp_path / "web.py"
    path.write_text(SAMPLE)
    output = tmp_path / "web.sarif"
    result = run_cli(
        "review-code", path, "--format", "sarif", "--output", output, "--fail-on-findings"
    )
    assert result.returncode == 1 and not result.stderr
    assert len(json.loads(output.read_text())["runs"][0]["results"]) == 3
    before = output.read_bytes()
    assert run_cli("review-code", path, "--output", output).returncode == 2
    assert output.read_bytes() == before
    path.write_text("jinja2.Environment(autoescape=True)")
    assert run_cli("review-code", path, "--fail-on-findings").returncode == 0


def test_engine_ten_readable_without_cross_engine_deltas(tmp_path):
    path = tmp_path / "web.py"
    path.write_text(SAMPLE)
    ScanService(assessor).run(ScanOptions(str(path)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    assert current["manifest"]["scope"]["engine"] == "read-only-pipeline-19"
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-10"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    comparison = compare_bundles(read_bundle(tmp_path / "old"), current)
    assert comparison["comparable"] is False and comparison["counts"] is None


def test_missing_new_demo_rules_prevents_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as module
    from ai_threat_lab.assessment import AssessmentResult

    original = module.assessor

    def missing(options):
        if options.target.endswith("python-patterns.py"):
            return AssessmentResult(options.target, "python_source", "partial", (), ("Fixture",))
        return original(options)

    monkeypatch.setattr(module, "assessor", missing)
    with pytest.raises(ValidationError, match="Python pattern acceptance"):
        module.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo" / "demo-result.json").exists()
