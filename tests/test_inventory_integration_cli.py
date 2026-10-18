import json
import subprocess
import sys

import pytest

import ai_threat_lab.integration_cli as integration
from ai_threat_lab.ai_costs import AIConfig, CostLedger
from ai_threat_lab.cli import main
from ai_threat_lab.local_inventory import inspect_text, local_inventory
from ai_threat_lab.models import ValidationError


def write(path, document):
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def sample(tmp_path):
    configuration = write(
        tmp_path / "ai.json",
        {
            "schema_version": 1,
            "model": "fixture-model",
            "input_usd_per_million": "2",
            "output_usd_per_million": "8",
            "cache_ttl_seconds": 60,
        },
    )
    report = write(
        tmp_path / "assessment.json",
        {
            "target_kind": "website",
            "status": "partial",
            "findings": [
                {
                    "check": "missing_header",
                    "status": "candidate",
                    "evidence": "Missing",
                    "recommendation": "Review configuration",
                }
            ],
            "not_checked": ["Partial audit"],
        },
    )
    return configuration, report


def test_inventory_secrets_redacted_manifests_and_python(tmp_path):
    key = "AKIA" + "A" * 16
    (tmp_path / ".env").write_text("TOKEN=" + key)
    (tmp_path / "sample.py").write_text("eval(untrusted)\n")
    (tmp_path / "package.json").write_text('{"dependencies":{"fixture":"latest"}}')
    result = local_inventory(str(tmp_path))
    assert {"possible_secret", "floating_dependency", "PY001"} <= {f.check for f in result.findings}
    assert key not in str(result)
    assert result.status == "partial" and any("advisory" in x for x in result.not_checked)


@pytest.mark.parametrize("source", ["{", '{"dependencies":[]}', "[1]"])
def test_invalid_manifest_is_explicit(source):
    assert inspect_text("package.json", source)[0].check == "invalid_manifest"


def test_inventory_skips_symlinks_dependencies_badtext_and_large_files(tmp_path):
    child = tmp_path / "node_modules"
    child.mkdir()
    (child / "bad.py").write_text("eval(x)")
    (tmp_path / "bad.js").write_bytes(b"\xff")
    (tmp_path / "large.js").write_text("x" * (256 * 1024 + 1))
    result = local_inventory(str(tmp_path))
    assert not result.findings
    assert any("oversized" in x for x in result.not_checked)
    assert any("Could not read" in x for x in result.not_checked)
    link = tmp_path / "link"
    try:
        link.symlink_to(child, target_is_directory=True)
    except OSError:
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ValidationError):
        local_inventory(str(link))


def test_inventory_file_limit(tmp_path):
    for index in range(101):
        (tmp_path / f"{index:03}.js").write_text("console.log('ok')")
    assert any("limit" in item for item in local_inventory(str(tmp_path)).not_checked)


@pytest.mark.parametrize(
    "magic,expected", [(b"MZ", "PE"), (b"\x7fELF", "ELF"), (b"other", "unknown")]
)
def test_binary_metadata_without_execution(tmp_path, magic, expected):
    path = tmp_path / "program.bin"
    path.write_bytes(magic)
    result = local_inventory(str(path))
    assert f"Format={expected}" in result.findings[0].evidence
    assert "sha256=" in result.findings[0].evidence
    assert result.findings[0].status == "unverified"


def test_binary_size_limit(tmp_path):
    path = tmp_path / "large.bin"
    with path.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    with pytest.raises(ValidationError):
        local_inventory(str(path))


def test_local_python_and_message_inventory(tmp_path):
    path = tmp_path / "code.py"
    path.write_text("eval(data)")
    assert local_inventory(str(path)).findings[0].check == "PY001"
    path = tmp_path / "mail.eml"
    path.write_text("From: sender@example.com\n\nHello\n")
    assert local_inventory(str(path)).target_kind == "mail_message"


def test_audit_cli_local_report_and_refuses_overwrite(tmp_path, capsys):
    path = tmp_path / "script.py"
    path.write_text("eval(input())")
    output = tmp_path / "out.json"
    assert main(["audit", str(path), "--output", str(output)]) == 0
    assert json.loads(output.read_text())["findings"]
    assert main(["audit", str(path), "--output", str(output)]) == 2
    assert "exists" in capsys.readouterr().err


@pytest.mark.parametrize(
    "args",
    [
        ["audit", "https://example.com"],
        ["audit", "https://example.com", "--network"],
        ["audit", "https://example.com", "--network", "--allow-host", "other.com"],
    ],
)
def test_remote_network_optin_and_exact_scope(args, capsys, monkeypatch):
    monkeypatch.setattr(
        integration, "PublicHTTPS", lambda *a, **k: pytest.fail("No client creation")
    )
    assert main(args) == 2
    error = capsys.readouterr().err
    assert "scope" in error or "requires" in error


def test_all_remote_cli_routes_use_real_adapters_with_fixture_http(monkeypatch, capsys):
    from test_remote_audit import DNS, QueueHTTP, blob, repository

    from ai_threat_lab.http_client import HttpResponse

    item, data = blob("eval(x)")
    cases = [
        (
            "https://github.com/o/r",
            "github.com",
            QueueHTTP(*repository(item), data),
            "github_repository",
        ),
        ("https://example.com", "example.com", QueueHTTP(HttpResponse(200, {}, b"")), "website"),
        ("mail-domain:example.com", "example.com", DNS(), "mail_domain"),
        (
            "mailbox:user@example.com",
            "gmail.googleapis.com",
            QueueHTTP({"emailAddress": "user@example.com"}, {"enabled": False}, {}),
            "mailbox_account",
        ),
    ]
    monkeypatch.setenv("GMAIL_ACCESS_TOKEN", "fixture-token")
    for target, host, client, kind in cases:
        monkeypatch.setattr(integration, "PublicHTTPS", lambda *a, **k: client)
        assert main(["audit", target, "--network", "--allow-host", host]) == 0
        assert json.loads(capsys.readouterr().out)["target_kind"] == kind


def test_malformed_remote_response_is_redacted(monkeypatch, capsys):
    from test_remote_audit import QueueHTTP

    monkeypatch.setattr(
        integration,
        "PublicHTTPS",
        lambda *a, **k: QueueHTTP(
            {"default_branch": "main"}, {"sha": "a" * 40}, {"tree": ["BAD_SECRET_RESPONSE"]}
        ),
    )
    assert main(["audit", "https://github.com/o/r", "--network", "--allow-host", "github.com"]) == 3
    captured = capsys.readouterr()
    assert "SECRET" not in captured.err and "Traceback" not in captured.err


def test_ai_cli_dryrun_consent_and_missing_key(tmp_path, monkeypatch, capsys):
    config, report = sample(tmp_path)
    ledger = tmp_path / "cost.sqlite"
    base = ["ai-explain", str(report), "--ai-config", str(config), "--ledger", str(ledger)]
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert main(base) == 2
    assert "send-evidence" in capsys.readouterr().err
    assert main(base + ["--send-evidence"]) == 3
    assert "missing" in capsys.readouterr().err and not ledger.exists()
    assert main(base + ["--dry-run"]) == 0
    assert json.loads(capsys.readouterr().out)["network_called"] is False
    assert not CostLedger(ledger).report()["days"]


def test_ai_cli_real_wire_with_fake_transport_cache_and_cost_report(tmp_path, monkeypatch, capsys):
    from test_ai_costs import API

    config, report = sample(tmp_path)
    ledger = tmp_path / "cost.sqlite"
    api = API()
    monkeypatch.setenv("OPENAI_API_KEY", "fixture-only")
    monkeypatch.setattr(integration, "PublicHTTPS", lambda *a, **k: api)
    base = [
        "ai-explain",
        str(report),
        "--ai-config",
        str(config),
        "--ledger",
        str(ledger),
        "--send-evidence",
    ]
    assert main(base) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "generated"
    assert main(base) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "cached"
    assert len(api.calls) == 1
    assert main(["api-costs", "--ledger", str(ledger)]) == 0
    assert json.loads(capsys.readouterr().out)["days"][0]["cache_hits"] == 1


def test_ai_cli_skip_empty_findings_and_reconcile(tmp_path, capsys):
    config, report = sample(tmp_path)
    write(report, {"findings": [], "not_checked": ["Not a complete audit"]})
    ledger = tmp_path / "cost.sqlite"
    assert (
        main(
            [
                "ai-explain",
                str(report),
                "--ai-config",
                str(config),
                "--ledger",
                str(ledger),
                "--dry-run",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "skipped_no_findings"
    assert not ledger.exists()
    cost = CostLedger(ledger)
    identifier, _ = cost.reserve("fixture", AIConfig("fixture", "2", "8"), 1000, 100)
    assert main(["api-reconcile", identifier, "--actual-usd", "0", "--ledger", str(ledger)]) == 0
    assert not json.loads(capsys.readouterr().out)["unconfirmed"]


def test_new_cli_commands_as_actual_processes(tmp_path):
    config, report = sample(tmp_path)
    commands = [
        [
            "ai-explain",
            str(report),
            "--ai-config",
            str(config),
            "--ledger",
            str(tmp_path / "cost.sqlite"),
            "--dry-run",
        ],
        ["api-costs", "--ledger", str(tmp_path / "cost.sqlite")],
        ["audit", str(report)],
    ]
    for command in commands:
        result = subprocess.run(
            [sys.executable, "-m", "ai_threat_lab", *command],
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert result.returncode == 0, result.stderr
        assert isinstance(json.loads(result.stdout), dict)


def test_corrupt_cost_ledger_is_readable_error(tmp_path, capsys):
    database = tmp_path / "broken.sqlite"
    database.write_bytes(b"not a database" * 100)
    assert main(["api-costs", "--ledger", str(database)]) == 3
    assert "Storage error" in capsys.readouterr().err


def test_ai_report_requires_findings_array(tmp_path, capsys):
    config, report = sample(tmp_path)
    write(report, {})
    assert (
        main(
            [
                "ai-explain",
                str(report),
                "--ai-config",
                str(config),
                "--ledger",
                str(tmp_path / "cost.sqlite"),
                "--dry-run",
            ]
        )
        == 2
    )
    assert "findings array" in capsys.readouterr().err
