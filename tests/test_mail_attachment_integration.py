"""The ordinary mail scan must use the same decoded-attachment tools as the dedicated CLI."""

import io
import json
import zipfile
from email.message import EmailMessage

import pytest

from ai_threat_lab.assessment import audit_message
from ai_threat_lab.scan_bundle import read_bundle
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService
from ai_threat_lab.tool_plan import plan_target


def message_path(tmp_path):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("../PRIVATE", b"PRIVATE")
    message = EmailMessage()
    message["From"] = "fixture@example.invalid"
    message["To"] = "fixture@example.invalid"
    message.set_content("fixture")
    message.add_attachment(archive.getvalue(), maintype="application", subtype="zip",
                           filename="PRIVATE.zip")
    path = tmp_path / "message.eml"
    path.write_bytes(message.as_bytes())
    return path


def test_standard_mail_assessment_reuses_parsed_message(tmp_path, monkeypatch):
    import ai_threat_lab.attachment_review as attachment
    path = message_path(tmp_path)
    monkeypatch.setattr(attachment, "BytesParser",
                        lambda *a, **kw: pytest.fail("MIME message reparsed"))
    result = audit_message(path)
    finding = next(f for f in result.findings if f.check == "zip_path_escape")
    assert "Attachment 0001" in finding.evidence
    assert "PRIVATE" not in repr(result)
    assert any("malware" in gap for gap in result.not_checked)


def test_tool_plan_scan_and_source_independent_bundle(tmp_path):
    path = message_path(tmp_path)
    plan = plan_target(str(path))
    assert "mail_attachment_structures" in [tool["id"] for tool in plan["tools"]]
    destination = tmp_path / "scan"
    result = ScanService(assessor).run(ScanOptions(str(path)), destination)
    assert not result["failed_modules"] and result["ai_calls"] == 0
    path.unlink()
    bundle = read_bundle(destination)
    assert "zip_path_escape" in json.dumps(bundle["documents"]["report.json"])
    assert "PRIVATE" not in json.dumps(bundle["documents"]["report.json"])


def test_bad_attachment_does_not_erase_message_header_evidence(tmp_path):
    path = tmp_path / "malformed.eml"
    path.write_bytes(
        b"From: fixture@example.invalid\nReply-To: other@example.invalid\n"
        b"MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n"
        b"--x\nContent-Type: application/octet-stream\n"
        b"Content-Disposition: attachment; filename=PRIVATE\n"
        b"Content-Transfer-Encoding: base64\n\n%%%%\n--x--\n")
    result = audit_message(path)
    assert any(f.check == "different_reply_to" for f in result.findings)
    assert any("Attachment sub-review failures: 1" in gap for gap in result.not_checked)
    assert "PRIVATE" not in repr(result)
