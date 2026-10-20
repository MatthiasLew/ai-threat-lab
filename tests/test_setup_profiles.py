import json
import socket

import pytest

from ai_threat_lab.cli import main
from ai_threat_lab.models import ValidationError
from ai_threat_lab.setup_check import setup_check


def settings(tmp_path):
    smtp, speech = tmp_path / "smtp.json", tmp_path / "speech.json"
    smtp.write_text(json.dumps({
        "schema_version": 1, "host": "mail.example.invalid", "sender": "PRIVATE@example.invalid",
        "mode": "starttls", "timeout": 15,
    }))
    speech.write_text(json.dumps({
        "schema_version": 1, "region": "westeurope", "voice": "en-US-JennyNeural",
        "usd_per_million_characters": "20", "max_request_usd": "0.1",
    }))
    return smtp, speech


def test_optional_profiles_validate_without_network_or_secret_output(tmp_path, monkeypatch):
    smtp, speech = settings(tmp_path)
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("network"))
    monkeypatch.setenv("AI_THREAT_SMTP_PASSWORD", "PRIVATE-PASSWORD")
    monkeypatch.setenv("AI_THREAT_SPEECH_KEY", "PRIVATE-KEY")
    result = setup_check(smtp_path=smtp, speech_path=speech)
    assert result["status"] == "configuration_needed"  # AI model was not selected.
    assert not result["credentials_inspected"] and not result["network_called"]
    selected = [row for row in result["integrations"] if row["id"] != "avatar"]
    assert all(row["status"] == "local_configuration_valid" for row in selected)
    assert all(not row["live_ready"] for row in selected)
    assert "PRIVATE" not in json.dumps(result)


def test_unselected_profiles_are_optional():
    result = setup_check()
    assert all(row["status"] == "not_selected" for row in result["integrations"])


def test_unknown_secret_field_rejected_without_echo(tmp_path):
    smtp, speech = settings(tmp_path)
    value = json.loads(smtp.read_text())
    value["password"] = "PRIVATE-PASSWORD"
    smtp.write_text(json.dumps(value))
    with pytest.raises(ValidationError) as error:
        setup_check(smtp_path=smtp, speech_path=speech)
    assert "PRIVATE" not in str(error.value)


def test_cli_configuration_check(tmp_path, capsys):
    smtp, speech = settings(tmp_path)
    assert main(["setup-check", "--smtp-config", str(smtp),
                 "--speech-config", str(speech)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert [row["id"] for row in result["integrations"]] == ["smtp", "speech", "avatar"]
