import hashlib
import json
import os
import socket
from dataclasses import replace
from datetime import timedelta
from email import policy
from email.parser import BytesParser

import pytest
from test_cli_process import run_cli
from test_training_lab import NOW, approved

import ai_threat_lab.offline_cli as offline_cli
from ai_threat_lab.campaigns import ContentApproval
from ai_threat_lab.cli import main
from ai_threat_lab.contracts import approval_to_document, plan_to_document
from ai_threat_lab.exercise_export import export_exercise
from ai_threat_lab.models import ValidationError
from ai_threat_lab.readiness import readiness
from ai_threat_lab.scan_bundle import read_bundle


def no_network(*args, **kwargs):
    pytest.fail("Offline workflow attempted networking")


@pytest.mark.parametrize(
    "channel,asset",
    [
        ("email", "preview.eml"),
        ("voice", "voice-script.json"),
        ("video", "video-storyboard.json"),
    ],
)
def test_approved_pack_has_exact_preview_and_verified_index(tmp_path, monkeypatch, channel, asset):
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    plan, approval = approved(channel)
    output = tmp_path / "pack"
    result = export_exercise(plan, approval, output, now=NOW)
    assert asset in result["files"]
    document = json.loads((output / "exercise.json").read_text(encoding="utf-8"))
    assert document["preview"] == {"subject": plan.content.subject, "body": plan.content.body}
    assert document["plan_digest"] == plan.digest
    assert plan.recipients[0] not in json.dumps(document)
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert set(result["files"]) == {*manifest["files"], "manifest.json"}
    for name, metadata in manifest["files"].items():
        raw = (output / name).read_bytes()
        assert metadata == {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    if channel == "email":
        message = BytesParser(policy=policy.default).parsebytes((output / asset).read_bytes())
        assert str(message["To"]).endswith("<participant@example.invalid>")
        assert message["X-AI-Threat-Lab-Mode"] == "local-rehearsal-only"
        assert "LOCAL TRAINING SIMULATION" in message.get_content()
        assert not list(message.iter_attachments())
    if os.name != "nt":
        assert output.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("failure", ["digest", "expired", "future"])
def test_pack_bad_approval_before_any_output(tmp_path, failure):
    plan, approval = approved("email")
    if failure == "digest":
        approval = replace(approval, plan_digest="wrong")
    elif failure == "future":
        approval = replace(approval, approved_at=NOW + timedelta(minutes=1))
    current = NOW + timedelta(hours=2) if failure == "expired" else NOW
    with pytest.raises(ValidationError):
        export_exercise(plan, approval, tmp_path / "pack", now=current)
    assert not (tmp_path / "pack").exists()


def test_pack_escapes_preview_and_omits_media_reference(tmp_path):
    plan, _ = approved("video")
    content = replace(
        plan.content,
        subject="<script>alert(1)</script>",
        body="<img src=x>",
        media_reference="file:///not-opened-training-media",
        media_sha256="b" * 64,
    )
    plan = replace(plan, content=content)
    approval = ContentApproval(plan.digest, "reviewer", NOW)
    export_exercise(plan, approval, tmp_path / "pack", now=NOW)
    page = (tmp_path / "pack" / "preview.html").read_text(encoding="utf-8")
    assert "<script>" not in page and "<img" not in page
    assert "&lt;script&gt;" in page and "Content-Security-Policy" in page
    assert plan.content.media_reference not in page


def test_pack_large_preview_and_existing_destination(tmp_path):
    plan, approval = approved("email")
    output = tmp_path / "existing"
    output.mkdir()
    (output / "keep").write_text("keep")
    with pytest.raises(FileExistsError):
        export_exercise(plan, approval, output, now=NOW)
    assert (output / "keep").read_text() == "keep"
    plan = replace(plan, content=replace(plan.content, body="x" * (65 * 1024)))
    with pytest.raises(ValidationError):
        export_exercise(
            plan, ContentApproval(plan.digest, "reviewer", NOW), tmp_path / "large", now=NOW
        )
    assert not (tmp_path / "large").exists()


def test_symlink_destination_is_not_followed(tmp_path):
    link = tmp_path / "link"
    try:
        link.symlink_to(tmp_path / "missing", target_is_directory=True)
    except OSError:
        pytest.skip("Symlinks unavailable")
    plan, approval = approved("email")
    with pytest.raises(FileExistsError):
        export_exercise(plan, approval, link, now=NOW)
    assert not (tmp_path / "missing").exists()


def test_readiness_is_static_and_honest(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", no_network)
    result = readiness()
    assert not result["network_called"] and not result["credentials_inspected"]
    assert not result["complete_product"] and not result["api_key_alone_sufficient"]
    items = {c["id"]: c for c in result["capabilities"]}
    assert len(items) == len(result["capabilities"])
    assert items["dependencies"]["local_status"] == "offline_complete"
    assert items["mail_domain"]["local_status"] == "offline_complete"
    assert items["mail_domain"]["external_status"] == "integration_validation_required"
    assert items["mailbox"]["local_status"] == "offline_complete"
    assert items["binary"]["local_status"] == "static_headers_partial"
    assert items["training"]["external_status"] == "implementation_required"
    # A caller cannot mutate the next invocation's inventory.
    result["capabilities"].clear()
    assert readiness()["capabilities"]


def test_complete_offline_demo_never_networks_or_executes_source(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(subprocess, "run", no_network)
    root = tmp_path / "synthetic demo"
    summary = offline_cli.offline_demo(root, now=NOW)
    assert summary["before_findings"] == 3 and summary["after_findings"] == 0
    assert summary["comparison"]["counts"]["no_longer_observed"] == 3
    assert summary["comparison"]["comparable"]
    assert not summary["network_called"] and summary["ai_calls"] == 0
    read_bundle(root / "scan-before")
    read_bundle(root / "scan-after")
    report = json.loads((root / "training-report.json").read_text(encoding="utf-8"))
    assert len(report["sessions"]) == 3
    assert {s["channel"] for s in report["sessions"]} == {"email", "voice", "video"}
    assert all(s["status"] == "completed" for s in report["sessions"])
    assert (root / "index.html").is_file()
    assert json.loads((root / "demo-result.json").read_text(encoding="utf-8")) == summary
    with pytest.raises(FileExistsError):
        offline_cli.offline_demo(root, now=NOW)


def test_demo_invalid_time_and_failure_do_not_claim_completion(tmp_path, monkeypatch):
    with pytest.raises(ValidationError):
        offline_cli.offline_demo(tmp_path / "naive", now=NOW.replace(tzinfo=None))
    assert not (tmp_path / "naive").exists()

    def broken(*args, **kwargs):
        raise OSError("fixture write failure")

    monkeypatch.setattr(offline_cli, "export_exercise", broken)
    with pytest.raises(OSError):
        offline_cli.offline_demo(tmp_path / "interrupted", now=NOW)
    assert not (tmp_path / "interrupted" / "demo-result.json").exists()


def test_readiness_and_export_cli_json_file_outputs(tmp_path, capsys):
    output = tmp_path / "ready.json"
    assert main(["readiness", "--output", str(output)]) == 0
    assert "Report saved" in capsys.readouterr().out
    assert not json.loads(output.read_text(encoding="utf-8"))["complete_product"]
    assert main(["readiness", "--output", str(output)]) == 2
    assert "exists" in capsys.readouterr().err
    # Use the current clock so the command validates a real current approval window.
    from ai_threat_lab.providers import ProviderConfig, ProviderRegistry
    from ai_threat_lab.workflows import approve_campaign, example_request, prepare_campaign

    document = prepare_campaign(
        example_request("email_training"), ProviderRegistry(), ProviderConfig()
    )
    approved_document = approval_to_document(approve_campaign(document, "reviewer"))
    plan = tmp_path / "plan.json"
    approval = tmp_path / "approval.json"
    plan.write_text(json.dumps(document), encoding="utf-8")
    approval.write_text(json.dumps(approved_document), encoding="utf-8")
    assert (
        main(
            [
                "exercise-export",
                str(plan),
                "--approval",
                str(approval),
                "--output-dir",
                str(tmp_path / "pack"),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["channel"] == "email"


def test_real_cli_demo_help_outputs_and_exit_codes(tmp_path):
    for command in ("readiness", "offline-demo", "exercise-export"):
        assert run_cli(command, "--help").returncode == 0
    assert run_cli("offline-demo").returncode == 2
    result = run_cli("offline-demo", "--output-dir", tmp_path / "demo space")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["before_findings"] == 3
    assert run_cli("offline-demo", "--output-dir", tmp_path / "demo space").returncode == 2
    inventory = run_cli("readiness")
    assert inventory.returncode == 0
    assert not json.loads(inventory.stdout)["api_key_alone_sufficient"]


def test_expired_export_cli_no_pack(tmp_path, capsys):
    plan, approval = approved("email")
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan_to_document(plan)), encoding="utf-8")
    approval_path = tmp_path / "approval.json"
    # A mismatched approval always fails regardless of wall clock.
    approval_path.write_text(
        json.dumps(approval_to_document(replace(approval, plan_digest="f" * 64))), encoding="utf-8"
    )
    assert (
        main(
            [
                "exercise-export",
                str(path),
                "--approval",
                str(approval_path),
                "--output-dir",
                str(tmp_path / "pack"),
            ]
        )
        == 2
    )
    assert "Error:" in capsys.readouterr().err
    assert not (tmp_path / "pack").exists()


def test_demo_collector_failure_is_not_success(tmp_path, monkeypatch):
    def unavailable(options):
        raise OSError("collector failed")

    monkeypatch.setattr(offline_cli, "assessor", unavailable)
    with pytest.raises(ValidationError, match="acceptance failed"):
        offline_cli.offline_demo(tmp_path / "failure", now=NOW)
    assert not (tmp_path / "failure" / "demo-result.json").exists()
