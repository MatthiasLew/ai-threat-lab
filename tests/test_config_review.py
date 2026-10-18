import json

import pytest
from test_remote_audit import QueueHTTP, blob, repository

from ai_threat_lab.config_review import configuration_file, inspect_configuration
from ai_threat_lab.local_inventory import inspect_text, local_inventory
from ai_threat_lab.remote_audit import GithubAudit


@pytest.mark.parametrize("filename", ["Dockerfile", "Dockerfile.dev", "worker.Dockerfile"])
def test_selected_container_names(filename):
    assert configuration_file(filename)
    assert len(inspect_configuration(filename, "FROM python:latest\nUSER root\n")) == 2


@pytest.mark.parametrize(
    "source,checks",
    [
        ("USER root", {"container_explicit_root"}),
        ("user 0:app # comment", {"container_explicit_root"}),
        ("FROM python:3.13", {"container_mutable_base"}),
        ("ADD https://example.invalid/file /file", {"container_remote_add"}),
        ("ADD --chown=app http://example.invalid/file /file", {"container_remote_add"}),
        ("FROM scratch\nUSER app", set()),
        ("FROM python@sha256:" + "a" * 64 + "\nUSER 1000", set()),
        ("FROM ${BASE}\nUSER ${USER}", set()),
        ("# FROM python:latest\n# USER root", set()),
        ("FROM scratch AS builder\nFROM builder", set()),
        ("FROM scratch AS build\nFROM BUILD\nFROM 0", set()),
        ("ADD local.txt /file\nRUN echo safe", set()),
        ("FROM --platform=linux/amd64 python:latest", set()),
    ],
)
def test_container_literal_rules(source, checks):
    findings = inspect_configuration("Dockerfile", source)
    assert {f.check for f in findings} == checks
    assert all(f.status == "candidate" for f in findings)


@pytest.mark.parametrize(
    "source,checks",
    [
        ("permissions: write-all", {"workflow_write_all"}),
        ("  permissions: 'write-all' # note", {"workflow_write_all"}),
        ("  - uses: actions/checkout@v4", {"workflow_mutable_action"}),
        ('  - uses: "owner/repo/subdir@main" # note', {"workflow_mutable_action"}),
        ("- uses: actions/checkout@" + "a" * 40, set()),
        ("- uses: ./local-action", set()),
        ("permissions: read-all", set()),
        ("# permissions: write-all\n# - uses: owner/repo@v1", set()),
        ("- uses: ${{ inputs.action }}", set()),
    ],
)
def test_workflow_literal_rules(source, checks):
    assert {f.check for f in inspect_configuration(".github/workflows/ci.yml", source)} == checks


def test_no_rules_outside_configuration_scope_and_no_value_leak():
    source = "permissions: write-all\n- uses: owner/repo@main\nUSER root"
    assert not inspect_configuration("notes.txt", source)
    findings = inspect_text(".github/workflows/ci.yml", source)
    assert len(findings) == 2
    assert "owner/repo" not in json.dumps([f.evidence for f in findings])
    assert ":2:" in findings[1].evidence


def test_local_inventory_includes_dockerfiles_and_workflows(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:latest\nUSER root\n", encoding="utf-8")
    folder = tmp_path / ".github" / "workflows"
    folder.mkdir(parents=True)
    (folder / "ci.yml").write_text("permissions: write-all\n", encoding="utf-8")
    result = local_inventory(str(tmp_path))
    assert len(result.findings) == 3
    assert any("literal lines" in n for n in result.not_checked)


def test_github_includes_dockerfile_without_extension():
    item, data = blob("USER root\n")
    item["path"] = "Dockerfile"
    result = GithubAudit(QueueHTTP(*repository(item), data)).assess("https://github.com/o/r")
    assert result.findings[0].check == "container_explicit_root"
    assert any("literal lines" in n for n in result.not_checked)
