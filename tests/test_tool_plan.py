"""Plan selection is deterministic and cannot grant permission or run a tool."""

import json
import socket

import pytest

from ai_threat_lab.cli import main
from ai_threat_lab.models import ValidationError
from ai_threat_lab.tool_plan import plan_target


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Planning/local inspection must not use a socket")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


@pytest.mark.parametrize(
    "name,kind,tool",
    [
        ("code.py", "python_source", "python_review"),
        ("message.eml", "mail_message", "saved_mail_review"),
        ("page.html", "html_document", "saved_html_review"),
        ("saved.auth.jsonl", "authentication_log", "authentication_patterns"),
        ("saved.ssh.jsonl", "ssh_journal", "openssh_journal_review"),
        ("program.exe", "program_file", "binary_archive_review"),
    ],
)
def test_local_routes_are_selected_without_reading_target(tmp_path, name, kind, tool):
    path = tmp_path / name
    path.write_bytes(b"not parsed while planning")
    result = plan_target(str(path))
    assert result["target_kind"] == kind
    assert result["tools"][0]["id"] == tool
    assert result["collection_permitted"] is True
    assert result["network_destinations"] == []
    assert result["ai_calls"] == 0


@pytest.mark.parametrize(
    "target,host,destination",
    [
        ("https://github.com/owner/repo", "github.com", "api.github.com"),
        ("https://example.invalid/path", "example.invalid", "example.invalid"),
        ("mail-domain:example.invalid", "example.invalid", "cloudflare-dns.com"),
        ("mailbox:user@example.invalid", "gmail.googleapis.com", "gmail.googleapis.com"),
    ],
)
def test_remote_plans_show_actual_destinations_and_require_permission(target, host, destination):
    result = plan_target(target)
    assert result["collection_permitted"] is False
    assert len(result["permission_requirements"]) == 2
    assert result["network_destinations"] == [destination]
    assert result["data_disclosure"]
    assert result["network_called"] is False
    assert result["credentials_inspected"] is False
    approved = plan_target(target, network=True, allowed_hosts=[host.upper()])
    assert approved["collection_permitted"] is True
    assert approved["network_called"] is False


def test_osv_is_optional_explicit_disclosure(tmp_path):
    offline = plan_target(str(tmp_path))
    assert [t["id"] for t in offline["tools"]] == [
        "local_inventory",
        "dependency_inventory",
        "verified_report_bundle",
    ]
    proposal = plan_target(str(tmp_path), share_packages=True)
    assert proposal["collection_permitted"] is False
    assert proposal["network_destinations"] == ["api.osv.dev"]
    assert "exact versions" in proposal["data_disclosure"][0]
    assert plan_target(str(tmp_path), network=True, share_packages=True)["collection_permitted"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"network": "yes"},
        {"allowed_hosts": "example.invalid"},
        {"allowed_hosts": ["*"]},
        {"allowed_hosts": [1]},
        {"max_files": True},
        {"max_files": 10001},
        {"recursive_dependencies": "yes"},
        {"max_pages": 0},
        {"share_packages": "yes"},
        {"dkim_selector": "invalid"},
    ],
)
def test_plan_rejects_invalid_options_like_execution(tmp_path, kwargs):
    with pytest.raises(ValidationError):
        plan_target(str(tmp_path), **kwargs)


def test_https_and_target_boundary_rejections():
    for target in (
        "http://example.invalid",
        "https://user:pass@example.invalid",
        "https://example.invalid:444",
        "https://example.invalid/#fragment",
        "ftp://example.invalid",
    ):
        with pytest.raises(ValidationError):
            plan_target(target)


def test_inspect_saves_readable_evidence_and_can_fail_on_findings(tmp_path, capsys):
    target = tmp_path / "source.py"
    target.write_text("eval(input())\n")
    output = tmp_path / "run"
    assert main(["inspect", str(target), "--output-dir", str(output), "--fail-on-findings"]) == 1
    text = capsys.readouterr().out
    assert "PY001" in text and "Saved run:" in text
    assert (output / "manifest.json").is_file()
    assert main(["scan-check", str(output)]) == 0
    capsys.readouterr()
    before = (output / "manifest.json").read_bytes()
    assert main(["inspect", str(target), "--output-dir", str(output)]) == 2
    assert (output / "manifest.json").read_bytes() == before


def test_remote_inspect_cannot_use_planning_as_consent(tmp_path):
    assert plan_target("https://example.invalid")["collection_permitted"] is False
    assert main(["inspect", "https://example.invalid", "--output-dir", str(tmp_path / "run")]) == 2
    assert not (tmp_path / "run").exists()


def test_plan_cli_and_inspect_json(tmp_path, capsys):
    target = tmp_path / "source.py"
    target.write_text("value = 1\n")
    assert main(["plan", str(target)]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "prepared_tool_plan"
    assert (
        main(["inspect", str(target), "--output-dir", str(tmp_path / "run"), "--format", "json"])
        == 0
    )
    assert json.loads(capsys.readouterr().out)["ai_calls"] == 0
