"""Exercise the offline Bandit handoff with pinned SARIF and synthetic failures."""

import json
import subprocess
from pathlib import Path

import pytest

from ai_threat_lab.cli import main
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scanner_report import save_bandit_report

FIXTURE = Path(__file__).parent / "fixtures" / "external_sarif" / "bandit.sarif"


def test_publish_reports_via_cli_without_running_scanner(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: pytest.fail("unexpected process"))
    output = tmp_path / "report.json"
    args = ["scanner", "import", "bandit", str(FIXTURE), "--output", str(output)]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["reported_results"] == 1
    original = output.read_bytes()
    result = json.loads(original)
    assert result["observations"][0]["rule_id"] == "B101"
    assert result["observations"][0]["status"] == "unverified"
    assert main(args) == 2
    assert output.read_bytes() == original


@pytest.mark.parametrize("change,diagnostic", [
    ("empty", None), ("failed", "complete successful"), ("missing", "complete successful"),
    ("version", "supported Bandit"), ("large", "publication result limit"),
])
def test_publish_only_complete_supported_documents(tmp_path, change, diagnostic):
    document = json.loads(FIXTURE.read_bytes())
    run = document["runs"][0]
    if change == "empty":
        run["results"] = []
    elif change == "failed":
        run["invocations"][0]["executionSuccessful"] = False
    elif change == "missing":
        del run["invocations"]
    elif change == "version":
        run["tool"]["driver"]["version"] = "99"
    else:
        run["results"] *= 201
    source = tmp_path / "synthetic.sarif"
    source.write_text(json.dumps(document), encoding="utf-8")
    output = tmp_path / "report.json"
    if diagnostic:
        with pytest.raises(ValidationError, match=diagnostic):
            save_bandit_report(source, output)
        assert not output.exists()
    else:
        assert save_bandit_report(source, output)["total_results"] == 0
        assert output.is_file()


def test_report_network_path_rejected_before_read(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ai_threat_lab.scanner_report.import_sarif",
        lambda source: pytest.fail("unexpected report read"),
    )
    with pytest.raises(ValidationError, match="Network"):
        save_bandit_report("//remote.invalid/report.sarif", tmp_path / "output.json")
