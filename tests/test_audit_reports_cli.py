import json
import subprocess
import sys

import pytest

import ai_threat_lab.integration_cli as cli
from ai_threat_lab.assessment import AssessmentService
from ai_threat_lab.audit_report import merge_reports, render_html
from ai_threat_lab.cli import main
from ai_threat_lab.models import ValidationError


def assessment(target="fixture", check="possible_secret"):
    return {
        "target": target,
        "target_kind": "local_project",
        "status": "partial",
        "findings": [
            {
                "check": check,
                "status": "candidate",
                "evidence": "Value redacted",
                "recommendation": "Review and remediate",
            }
        ],
        "not_checked": ["Partial analysis"],
    }


def test_merge_prioritizes_deduplicates_and_preserves_provenance():
    first = assessment()
    first["findings"] *= 2
    result = merge_reports(
        [
            first,
            assessment(),
            assessment("other", "missing_header"),
            assessment("deps", "known_dependency_advisory"),
        ]
    )
    assert result["summary"]["unique_findings"] == 3
    assert result["summary"]["triage_counts"] == {"P1": 1, "P2": 1, "P3": 1}
    assert result["findings"][0]["sources"] == [1, 2]
    assert len(result["not_checked"]) == 4 and len(result["assessments"]) == 4
    assert result["status"] == "partial" and "not CVSS" in result["notice"]
    assert merge_reports([first, assessment()]) == merge_reports([first, assessment()])


def test_empty_not_configured_reports_preserve_gaps():
    empty = assessment()
    empty.update(findings=[], status="not_configured")
    result = merge_reports([empty])
    assert not result["findings"] and result["not_checked"]
    assert result["status"] == "partial" and "complete security" in result["notice"]


@pytest.mark.parametrize(
    "documents",
    [
        [],
        [{}],
        [assessment()] * 21,
        [dict(assessment(), findings="bad")],
        [dict(assessment(), findings=[{}])],
        [dict(assessment(), status="secure")],
        [dict(assessment(), unexpected="value")],
        [dict(assessment(), findings=assessment()["findings"] * 2001)],
    ],
)
def test_invalid_merge_inputs(documents):
    with pytest.raises(ValidationError):
        merge_reports(documents)


def test_html_escapes_all_untrusted_content_and_has_no_external_assets():
    malicious = '<script>alert("x")</script><img src="https://private.example">'
    source = assessment(malicious, malicious)
    source["findings"][0].update(evidence=malicious, recommendation=malicious)
    source["not_checked"] = [malicious]
    html = render_html(merge_reports([source]))
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html
    assert "default-src 'none'" in html and "form-action 'none'" in html
    assert "<iframe" not in html and "<link" not in html


def test_dependency_cli_offline_optin_and_network_contract(tmp_path, monkeypatch, capsys):
    from test_dependencies import HTTP

    path = tmp_path / "requirements.txt"
    path.write_text("fixture==1.0")
    assert main(["audit-deps", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["packages"][0]["name"] == "fixture"
    for extra in (
        ["--network"],
        ["--share-packages"],
        ["--advisory-cache", str(tmp_path / "cache.sqlite")],
    ):
        assert main(["audit-deps", str(path), *extra]) == 2
        capsys.readouterr()
    client = HTTP({"results": [{"vulns": [{"id": "OSV-FIXTURE-1"}]}]})
    monkeypatch.setattr(cli, "PublicHTTPS", lambda *a, **k: client)
    output = tmp_path / "dependencies.json"
    assert (
        main(
            [
                "audit-deps",
                str(path),
                "--network",
                "--share-packages",
                "--advisory-cache",
                str(tmp_path / "cache.sqlite"),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(output.read_text())["findings"][0]["check"] == "known_dependency_advisory"
    capsys.readouterr()
    assert (
        main(
            [
                "audit-deps",
                str(path),
                "--network",
                "--share-packages",
                "--advisory-cache",
                str(tmp_path / "cache.sqlite"),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["dependency_audit"]["cache_hits"] == 1


def test_report_cli_json_html_and_overwrite(tmp_path, capsys):
    source = tmp_path / "assessment.json"
    source.write_text(json.dumps(assessment()))
    assert main(["audit-report", str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["unique_findings"] == 1
    assert main(["audit-report", str(source), "--format", "html"]) == 0
    assert "<!doctype html>" in capsys.readouterr().out
    output = tmp_path / "report.html"
    assert main(["audit-report", str(source), "--format", "html", "--output", str(output)]) == 0
    assert "Review and remediate" in output.read_text(encoding="utf-8")
    assert main(["audit-report", str(source), "--format", "html", "--output", str(output)]) == 2
    capsys.readouterr()


def test_actual_cli_dependency_and_report_flow(tmp_path):
    (tmp_path / "requirements.txt").write_text("fixture==1.0")
    source = tmp_path / "assessment.json"
    source.write_text(json.dumps(assessment()))
    for args in (
        ["audit-deps", str(tmp_path)],
        ["audit-report", str(source)],
        ["audit-report", str(source), "--format", "html"],
    ):
        result = subprocess.run(
            [sys.executable, "-m", "ai_threat_lab", *args],
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert result.returncode == 0, result.stderr


def test_python_directory_and_entry_traversal_are_bounded(tmp_path, monkeypatch):
    import os

    def directories(*args, **kwargs):
        for _ in range(1002):
            yield str(tmp_path), [], []

    monkeypatch.setattr(os, "walk", directories)
    result = AssessmentService().assess(str(tmp_path))
    assert any("traversal stopped" in n for n in result.not_checked)
    monkeypatch.setattr(
        os, "walk", lambda *a, **k: [(str(tmp_path), [], [f"{i}.txt" for i in range(10002)])]
    )
    result = AssessmentService().assess(str(tmp_path))
    assert any("traversal stopped" in n for n in result.not_checked)


@pytest.mark.parametrize("target", ["https://github.com/../repo", "https://github.com/user/.."])
def test_github_path_components_rejected_without_network(target):
    from test_remote_audit import QueueHTTP

    from ai_threat_lab.remote_audit import GithubAudit

    with pytest.raises(ValidationError):
        GithubAudit(QueueHTTP()).assess(target)
