"""Local-only exported mail candidates with privacy, MIME bounds and CLI acceptance."""

import json
import socket
from dataclasses import asdict
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

import pytest
from test_cli_process import run_cli

from ai_threat_lab.assessment import AssessmentService, audit_message
from ai_threat_lab.cli import main
from ai_threat_lab.mail_review import inspect_message_content
from ai_threat_lab.models import ValidationError
from ai_threat_lab.scan_bundle import read_bundle
from ai_threat_lab.scan_cli import assessor
from ai_threat_lab.scan_engine import ScanOptions, ScanService


def message(body="Ordinary text", *, html=False):
    mail = EmailMessage()
    mail["From"] = "Fictional Sender <sender@example.invalid>"
    mail["To"] = "recipient@example.invalid"
    mail["Subject"] = "Private subject must not be exported"
    mail.set_content(body, subtype="html" if html else "plain")
    return mail


def inspect(mail):
    findings, notices = inspect_message_content(
        BytesParser(policy=policy.default).parsebytes(mail.as_bytes())
    )
    return {item.check for item in findings}, findings, notices


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://example.invalid/private-token", {"message_link_cleartext"}),
        ("https://192.0.2.1/private-token", {"message_link_ip_address"}),
        ("https://[2001:db8::1]/private-token", {"message_link_ip_address"}),
        ("https://[2001:db8::1]", {"message_link_ip_address"}),
        ("https://user:password@example.invalid/private-token", {"message_link_credentials"}),
        (
            "http://user:password@192.0.2.1/",
            {"message_link_cleartext", "message_link_credentials", "message_link_ip_address"},
        ),
        ("https://example.invalid/private-token", set()),
    ],
)
def test_plain_links_detect_only_selected_properties(url, expected):
    checks, findings, _ = inspect(message(url))
    assert checks == expected
    assert all(f.status == "candidate" for f in findings)
    assert "private-token" not in str(findings) and "password@" not in str(findings)


@pytest.mark.parametrize(
    "html,expected",
    [
        (
            '<a href="https://other.invalid/secret">https://trusted.invalid/</a>',
            {"message_link_display_mismatch"},
        ),
        ('<a href="https://same.invalid/private">https://SAME.invalid.</a>', set()),
        ('<a href="https://same.invalid/private">Read more</a>', set()),
        (
            '<a href="//other.invalid/">https://trusted.invalid/</a>',
            {"message_link_display_mismatch"},
        ),
        (
            '<a href="https://other.invalid/">https://trusted.invalid/<b></b></a>',
            {"message_link_display_mismatch"},
        ),
        ('<a href="javascript:privateCode()">open</a>', {"message_link_active_scheme"}),
        ('<a href="data:text/html,privateData">open</a>', {"message_link_active_scheme"}),
        ('<a href="vbscript:privateCode()">open</a>', {"message_link_active_scheme"}),
        ('<a href="http://example.invalid/?x=1&amp;y=2">open', {"message_link_cleartext"}),
        ('<script>fetch("http://192.0.2.1/private")</script>', set()),
        ('<img src="http://192.0.2.1/private">', set()),
        ('<a href="https://[broken/">https://trusted.invalid</a>', set()),
        ('<a href="https://example.invalid:bad/">open</a>', set()),
        ('<a href="https://other.invalid/">https://trusted.invalid some text</a>', set()),
    ],
)
def test_html_anchors_are_syntax_candidates_not_rendering_or_reputation(html, expected):
    checks, _, _ = inspect(message(html, html=True))
    assert checks == expected


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("private.exe", {"message_attachment_active_type"}),
        (
            "private.PDF.EXE",
            {"message_attachment_active_type", "message_attachment_double_extension"},
        ),
        ("private.docm", {"message_attachment_active_type"}),
        (
            "private.txt.ps1",
            {"message_attachment_active_type", "message_attachment_double_extension"},
        ),
        ("private.zip", set()),
        ("private.pdf", set()),
        ("private.txt", set()),
    ],
)
def test_attachment_metadata_is_reviewed_without_opening_payload(filename, expected):
    mail = message()
    mail.add_attachment(
        b"PRIVATE_PAYLOAD_NEVER_EXECUTE",
        maintype="application",
        subtype="octet-stream",
        filename=filename,
    )
    checks, findings, notices = inspect(mail)
    assert checks == expected and any("not opened" in n for n in notices)
    assert "private." not in str(findings) and "PRIVATE_PAYLOAD" not in str(findings)


def test_mime_type_without_filename_still_observed_for_declared_attachment():
    mail = message()
    mail.add_attachment(b"inert", maintype="application", subtype="x-msdownload")
    assert "message_attachment_active_type" in inspect(mail)[0]


def test_html_attachment_is_not_parsed_as_visible_message_body():
    mail = message()
    mail.add_attachment(
        '<a href="http://192.0.2.1">open</a>', subtype="html", filename="private.html"
    )
    assert not inspect(mail)[0]


def test_aggregate_counts_are_stable_and_omit_sensitive_material():
    mail = message("http://example.invalid/secret http://example.invalid/secret")
    _, findings, _ = inspect(mail)
    assert len(findings) == 1 and findings[0].evidence.startswith("2 ")
    assert "secret" not in str(findings) and "example.invalid" not in str(findings)


def test_no_network_and_shared_audit_scan_routes(tmp_path, monkeypatch):
    def reject(*args, **kwargs):
        raise AssertionError("No network is permitted during mail analysis")

    monkeypatch.setattr(socket, "create_connection", reject)
    path = tmp_path / "private-message.eml"
    path.write_bytes(message("http://user:private-token@192.0.2.1/").as_bytes())
    expected = {"message_link_cleartext", "message_link_credentials", "message_link_ip_address"}
    result = AssessmentService().assess(str(path))
    assert {f.check for f in result.findings} == expected
    serialized = json.dumps(asdict(result))
    assert "private-token" not in serialized and "Private subject" not in serialized
    assert "sender@example.invalid" not in serialized
    summary = ScanService(assessor).run(ScanOptions(str(path)), tmp_path / "scan")
    assert summary["ai_calls"] == 0 and not summary["failed_modules"]
    report = read_bundle(tmp_path / "scan")["documents"]["report.json"]
    assert {f["check"] for f in report["findings"]} == expected
    assert "private-token" not in json.dumps(report)


def test_all_authentication_results_headers_are_considered(tmp_path):
    path = tmp_path / "message.eml"
    path.write_text(
        "Authentication-Results: untrusted; dmarc=pass\n"
        "Authentication-Results: also-untrusted; dkim=fail\n\nOrdinary body"
    )
    assert "reported_authentication_failure" in {f.check for f in audit_message(path).findings}


def test_limits_links_text_bytes_parts_depth_and_text_part_count(monkeypatch):
    import ai_threat_lab.mail_review as module

    monkeypatch.setattr(module, "MAX_LINKS", 2)
    checks, findings, notices = inspect(message("http://example.invalid " * 5))
    assert checks == {"message_link_cleartext"} and findings[0].evidence.startswith("2 ")
    assert any("link" in n and "limit" in n for n in notices)
    monkeypatch.setattr(module, "MAX_TEXT_BYTES", 10)
    assert any("byte limit" in n for n in inspect(message("x" * 100))[2])
    monkeypatch.setattr(module, "MAX_TEXT_BYTES", 256 * 1024)
    mail = message()
    mail.add_alternative("<p>plain html</p>", subtype="html")
    monkeypatch.setattr(module, "MAX_TEXT_PARTS", 1)
    assert any("text-part limit" in n for n in inspect(mail)[2])
    monkeypatch.setattr(module, "MAX_PARTS", 1)
    assert any("part limit" in n for n in inspect(mail)[2])
    monkeypatch.setattr(module, "MAX_PARTS", 100)
    monkeypatch.setattr(module, "MAX_DEPTH", 0)
    assert any("depth limit" in n for n in inspect(mail)[2])


def test_unknown_charset_and_oversized_url_are_explicit_gaps():
    mail = message("http://example.invalid/" + "x" * 4100)
    assert any("Oversized" in n for n in inspect(mail)[2])
    raw = b'Content-Type: text/plain; charset="unknown-private-charset"\n\nhttp://example.invalid/'
    findings, notices = inspect_message_content(BytesParser(policy=policy.default).parsebytes(raw))
    assert not findings and any("interpret" in n for n in notices)
    assert "unknown-private-charset" not in str(notices)


def test_embedded_messages_and_non_text_body_are_not_opened():
    mail = message()
    mail.add_attachment(message("http://192.0.2.1/private"))
    assert not inspect(mail)[0]
    raw = b"Content-Type: application/octet-stream\n\nhttp://192.0.2.1/private"
    findings, notices = inspect_message_content(BytesParser(policy=policy.default).parsebytes(raw))
    assert not findings and any("Non-text" in n for n in notices)


def test_oversized_and_linked_message_files_fail(tmp_path):
    path = tmp_path / "large.eml"
    path.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(ValidationError, match="1 MiB"):
        audit_message(path)
    with pytest.raises(ValidationError, match="regular"):
        audit_message(tmp_path)
    linked = tmp_path / "link.eml"
    try:
        linked.symlink_to(path)
    except (OSError, NotImplementedError):
        return
    with pytest.raises(ValidationError, match="regular"):
        audit_message(linked)


def test_parse_recursion_failure_has_redacted_error(tmp_path, monkeypatch):
    path = tmp_path / "mail.eml"
    path.write_bytes(b"Private source")

    def fail(*args, **kwargs):
        raise RecursionError("Private source")

    monkeypatch.setattr(BytesParser, "parsebytes", fail)
    with pytest.raises(ValidationError, match="structural limits") as error:
        audit_message(path)
    assert "Private source" not in str(error.value)


def test_cli_audit_and_scan_exit_policy_no_overwrite(tmp_path, capsys):
    path = tmp_path / "mail.eml"
    path.write_bytes(message("http://192.0.2.1/private").as_bytes())
    report = tmp_path / "mail.json"
    assert main(["audit", str(path), "--output", str(report)]) == 0
    original = report.read_bytes()
    assert main(["audit", str(path), "--output", str(report)]) == 2
    assert report.read_bytes() == original
    capsys.readouterr()
    process = run_cli("scan", path, "--output-dir", tmp_path / "bundle", "--fail-on-findings")
    assert process.returncode == 1 and not process.stderr
    assert json.loads(process.stdout)["unique_findings"] == 2
    assert "private" not in (tmp_path / "bundle" / "assessment.json").read_text()


def test_malformed_base64_and_mime_boundary_remain_explicit_gaps():
    malformed = BytesParser(policy=policy.default).parsebytes(
        b"Content-Type: text/plain\nContent-Transfer-Encoding: base64\n\na"
    )
    _, notices = inspect_message_content(malformed)
    assert any("defects" in n for n in notices)
    bad_multipart = BytesParser(policy=policy.default).parsebytes(
        b'Content-Type: multipart/mixed; boundary="missing"\n\nordinary body'
    )
    _, notices = inspect_message_content(bad_multipart)
    assert any("defects" in n for n in notices)


def test_link_limit_across_html_and_plain_parts(monkeypatch):
    import ai_threat_lab.mail_review as module

    monkeypatch.setattr(module, "MAX_LINKS", 2)
    mail = message("http://example.invalid")
    mail.add_alternative('<a href="http://example.invalid">open</a>' * 5, subtype="html")
    _, findings, notices = inspect(mail)
    assert findings[0].evidence.startswith("2 ")
    assert any("link limit" in n for n in notices)


def test_attached_message_is_not_inspected_for_nested_links_or_payloads():
    mail = message()
    mail.make_mixed()
    embedded = EmailMessage()
    embedded.set_type("message/rfc822")
    embedded.set_payload([message("http://192.0.2.1/private")])
    mail.attach(embedded)
    checks, _, notices = inspect(mail)
    assert not checks and any("Embedded" in n for n in notices)


def test_deterministic_arbitrary_message_bytes_have_bounded_redacted_results(tmp_path):
    import random

    generator = random.Random(1234)
    path = tmp_path / "fuzz.eml"
    for _ in range(50):
        path.write_bytes(generator.randbytes(generator.randrange(0, 1500)))
        result = audit_message(path)
        assert result.status == "partial" and len(result.findings) <= 10
        assert len(result.not_checked) < 20


def test_synthetic_demo_covers_new_routes_and_missing_mail_evidence_fails(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as module
    from ai_threat_lab.assessment import AssessmentResult

    original = module.assessor

    def no_mail_evidence(options):
        if options.target.endswith(".eml"):
            return AssessmentResult(
                options.target, "mail_message", "partial", (), ("Fixture only",)
            )
        return original(options)

    monkeypatch.setattr(module, "assessor", no_mail_evidence)
    with pytest.raises(ValidationError, match="mail acceptance"):
        module.offline_demo(tmp_path / "incomplete")
    assert not (tmp_path / "incomplete" / "demo-result.json").exists()
