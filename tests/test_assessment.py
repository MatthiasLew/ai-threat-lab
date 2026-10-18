import json

import pytest

from ai_threat_lab.assessment import AssessmentService, identify_target
from ai_threat_lab.cli import main
from ai_threat_lab.models import ValidationError


def test_remote_targets_are_not_falsely_marked_secure():
    service = AssessmentService()
    for target, kind in (
        ("https://github.com/example/repo", "github_repository"),
        ("https://example.invalid", "website"),
    ):
        result = service.assess(target)
        assert result.target_kind == kind
        assert result.status == "not_configured"
        assert result.not_checked and not result.findings
    with pytest.raises(ValidationError):
        identify_target("https://user:password@example.invalid")
    with pytest.raises(ValidationError):
        identify_target("https://github.com/example/repo/blob/main/code.py")


def test_project_review_excludes_dependencies_and_limits_sources(tmp_path):
    (tmp_path / "app.py").write_text("eval(data)")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "ignore.py").write_text("eval(data)")
    (tmp_path / "bad.py").write_text("broken = (")
    result = AssessmentService().assess(str(tmp_path))
    assert result.status == "partial"
    assert len(result.findings) == 1
    assert "app.py:1:" in result.findings[0].evidence
    assert any("Skipped" in text for text in result.not_checked)
    for i in range(105):
        (tmp_path / f"source{i:03}.py").write_text("value = 1")
    result = AssessmentService().assess(str(tmp_path))
    assert any("100-file limit" in text for text in result.not_checked)


def test_mail_headers_are_unverified_observations(tmp_path):
    path = tmp_path / "message.eml"
    path.write_text(
        "From: sender@example.invalid\nReply-To: other@example.invalid\n"
        "Authentication-Results: untrusted; dmarc=fail\n\nTraining content"
    )
    result = AssessmentService().assess(str(path))
    assert result.status == "partial"
    assert {f.check for f in result.findings} == {
        "different_reply_to",
        "reported_authentication_failure",
    }
    assert all(f.status == "candidate" for f in result.findings)
    assert any("cryptographic" in item for item in result.not_checked)


def test_cli_campaign_and_assessment_commands(capsys, tmp_path):
    assert main(["campaigns"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 3
    assert main(["campaign-demo", "voice_training"]) == 0
    assert json.loads(capsys.readouterr().out)["receipts"][0]["status"] == "simulated"
    assert main(["campaign-demo", "missing"]) == 2
    assert "Unknown" in capsys.readouterr().err
    assert main(["assess", "https://example.invalid"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "not_configured"
    events = tmp_path / "events.json"
    events.write_text('{"schema_version":1,"events":[]}')
    assert main(["campaign-report", str(events)]) == 0
    assert json.loads(capsys.readouterr().out)["unique_participants"] == 0


@pytest.mark.parametrize(
    "target,kind",
    [
        ("mailbox:person@example.invalid", "mailbox_account"),
        ("mail-domain:example.invalid", "mail_domain"),
    ],
)
def test_mail_provider_targets_need_real_adapters(target, kind):
    result = AssessmentService().assess(target)
    assert result.target_kind == kind
    assert result.status == "not_configured"
    assert result.not_checked


@pytest.mark.parametrize("target", ["https://[invalid", "https://example.invalid:bad"])
def test_invalid_urls_fail_readably(target):
    with pytest.raises(ValidationError, match="Invalid target URL"):
        identify_target(target)
