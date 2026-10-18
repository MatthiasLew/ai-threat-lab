import json
import subprocess
import sys

import pytest

from ai_threat_lab import (
    AnalysisRequest,
    TargetProfile,
    ThreatAnalyzer,
    ValidationError,
    export_report,
)
from ai_threat_lab.cli import main
from ai_threat_lab.reports import render_json, render_text


@pytest.fixture
def result():
    return ThreatAnalyzer().analyze(
        AnalysisRequest(
            "voice_deepfake",
            TargetProfile("Przykład Łódź", "Księgowość"),
            proposed_control_ids=("callback", "independent_approval"),
        )
    )


def test_report_roundtrip_and_metadata(result, tmp_path):
    path = export_report(result, tmp_path / "analysis.json", "json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["analysis"]["model_version"] == result.model_version
    assert data["analysis"]["baseline"]["score"] == 20
    assert data["analysis"]["residual"]["score"] == 10
    assert data["analysis"]["target"]["organization"] == "Przykład Łódź"
    assert data["generated_at"].endswith("+00:00")
    text = render_text(result)
    for expected in ("Przykład Łódź", "20/25", "10/25", "ASSUMPTIONS", "callback"):
        assert expected in text
    assert json.loads(render_json(result))["analysis"]["stages"]


def test_export_refuses_overwrite_and_invalid_destinations(result, tmp_path):
    path = tmp_path / "report.txt"
    path.write_text("preserve me")
    with pytest.raises(FileExistsError):
        export_report(result, path)
    assert path.read_text() == "preserve me"
    with pytest.raises(OSError):
        export_report(result, tmp_path / "missing" / "report.txt")
    with pytest.raises(ValidationError):
        export_report(result, tmp_path / "report.pdf", "pdf")


@pytest.mark.parametrize(
    "scenario",
    [
        "ai_phishing",
        "voice_deepfake",
        "video_deepfake",
        "brute_force",
        "credential_stuffing",
        "insecure_generated_code",
    ],
)
def test_cli_end_to_end(scenario, tmp_path):
    path = tmp_path / "report.json"
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "ai_threat_lab",
            "analyze",
            scenario,
            "--proposed",
            "callback",
            "--format",
            "json",
            "--output",
            str(path),
        ],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stderr
    report = json.loads(path.read_text())
    assert report["analysis"]["scenario_id"] == scenario
    assert report["analysis"]["residual"]["score"] <= report["analysis"]["baseline"]["score"]


def test_cli_lists_and_errors(capsys, tmp_path):
    assert main(["scenarios"]) == 0
    assert "video_deepfake" in capsys.readouterr().out
    assert main(["controls"]) == 0
    assert "callback" in capsys.readouterr().out
    assert main(["analyze", "missing"]) == 2
    assert "Unknown scenario" in capsys.readouterr().err
    assert main(["analyze", "ai_phishing", "--proposed", "missing"]) == 2
    assert "Unknown controls" in capsys.readouterr().err
    assert main(["analyze", "ai_phishing", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["schema_version"] == 1
    assert main(["analyze", "ai_phishing", "--output", str(tmp_path)]) == 2
    assert "Error:" in capsys.readouterr().err


def test_interactive_workflow(monkeypatch, capsys):
    responses = iter(["voice_deepfake", "", "", "", "", "", "callback independent_approval"])
    monkeypatch.setattr("builtins.input", lambda _: next(responses))
    assert main(["interactive"]) == 0
    assert "10/25" in capsys.readouterr().out


def test_interactive_eof_is_readable(monkeypatch, capsys):
    def eof(_):
        raise EOFError("Input ended")

    monkeypatch.setattr("builtins.input", eof)
    assert main(["interactive"]) == 2
    assert "Traceback" not in capsys.readouterr().err
