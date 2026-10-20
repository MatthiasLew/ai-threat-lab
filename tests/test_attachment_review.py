import io
import json
import socket
import zipfile
from email.message import EmailMessage
from email.parser import BytesParser

import pytest

from ai_threat_lab.attachment_review import decoded_attachment, review_attachments, selected_parts
from ai_threat_lab.models import ValidationError


def saved(tmp_path, payloads):
    message = EmailMessage()
    message["From"] = "private@example.invalid"
    message["Subject"] = "PRIVATE-SUBJECT"
    message.set_content("PRIVATE-BODY")
    for payload in payloads:
        message.add_attachment(payload, maintype="application", subtype="octet-stream",
                               filename="PRIVATE-NAME.bin")
    path = tmp_path / "message.eml"
    path.write_bytes(message.as_bytes())
    return path


def test_zip_bytes_are_reviewed_without_extracting_or_network(tmp_path, monkeypatch):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("../PRIVATE-MEMBER", b"PRIVATE-PAYLOAD")
    path = saved(tmp_path, [stream.getvalue()])
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("network"))
    monkeypatch.setattr(zipfile.ZipFile, "open", lambda *a, **k: pytest.fail("extraction"))
    before = list(tmp_path.iterdir())
    report, failures = review_attachments(path)
    assert failures == 0
    text = json.dumps(report)
    assert "zip_path_escape" in text
    assert "binary_metadata" in text
    assert "PRIVATE" not in text and "private@" not in text
    assert list(tmp_path.iterdir()) == before


def test_pagination_retains_attachment_indexes_and_limits(tmp_path):
    path = saved(tmp_path, [b"one", b"two", b"MZbad"])
    report, failures = review_attachments(path, start=2, max_entries=2)
    text = json.dumps(report)
    assert failures == 0
    assert "Attachment 0002" in text and "Attachment 0003" in text
    assert "Attachment 0001" not in text
    assert "binary_structure_unavailable" in text
    assert "2..3 of 3" in text


@pytest.mark.parametrize("options", [
    {"start": 0}, {"start": True}, {"start": 3}, {"max_entries": 0},
    {"max_entries": 21}, {"max_entries": True},
])
def test_invalid_selection(tmp_path, options):
    with pytest.raises(ValidationError):
        review_attachments(saved(tmp_path, [b"one"]), **options)


def test_no_attachments_is_explicit_and_source_independent(tmp_path):
    path = saved(tmp_path, [])
    report, failures = review_attachments(path)
    assert not failures
    assert "No eligible attachment" in json.dumps(report)
    with pytest.raises(ValidationError):
        review_attachments(path, start=2)


@pytest.mark.parametrize("encoding,payload", [
    ("base64", "%%%="), ("base64", "a"), ("quoted-printable", "bad=ZZ"),
    ("quoted-printable", "bad="), ("x-unsupported", "abc"), ("7bit", "\u00e9"),
])
def test_malformed_encoding_is_not_invented_bytes(encoding, payload):
    part = EmailMessage()
    part["Content-Transfer-Encoding"] = encoding
    part.set_payload(payload)
    with pytest.raises(ValidationError):
        decoded_attachment(part)


def test_duplicate_encoding_and_decoded_limit():
    part = BytesParser().parsebytes(
        b"Content-Transfer-Encoding: 7bit\nContent-Transfer-Encoding: base64\n\nabc")
    with pytest.raises(ValidationError):
        decoded_attachment(part)
    large = EmailMessage()
    large.set_payload("a" * (1024 * 1024 + 1))
    with pytest.raises(ValidationError, match="Decoded"):
        decoded_attachment(large)
    large.set_payload("a" * (2 * 1024 * 1024 + 1))
    with pytest.raises(ValidationError, match="Encoded"):
        decoded_attachment(large)


def test_failed_attachment_preserves_other_results(tmp_path):
    path = saved(tmp_path, [b"a" * (1024 * 1024 + 1), b"valid"])
    report, failures = review_attachments(path)
    assert failures == 1
    assert "binary_metadata" in json.dumps(report)
    assert "1 MiB" in json.dumps(report)


def test_total_budget(tmp_path):
    report, failures = review_attachments(saved(tmp_path, [b"x" * 900000] * 5))
    assert failures == 1
    assert "4 MiB" in json.dumps(report)


def test_nested_messages_not_traversed():
    outer = EmailMessage()
    outer.set_content("body")
    inner = EmailMessage()
    inner.set_content("inner")
    inner.add_attachment(b"MZbad", maintype="application", subtype="octet-stream")
    outer.add_attachment(inner)
    parts, gaps = selected_parts(outer)
    assert parts == []
    assert any("Encapsulated" in gap for gap in gaps)


def test_depth_and_part_bounds():
    outer = EmailMessage()
    current = outer
    for _ in range(10):
        current.make_mixed()
        child = EmailMessage()
        current.attach(child)
        current = child
    parts, gaps = selected_parts(outer)
    assert not parts and any("depth limit" in gap for gap in gaps)
    broad = EmailMessage()
    broad.make_mixed()
    for _ in range(105):
        child = EmailMessage()
        child.set_content("x")
        broad.attach(child)
    parts, gaps = selected_parts(broad)
    assert not parts and any("part limit" in gap for gap in gaps)
    assert any("child limit" in gap for gap in gaps)


def test_cli_report_can_feed_evidence_summary(tmp_path, capsys):
    from ai_threat_lab.cli import main
    path = saved(tmp_path, [b"unknown"])
    output = tmp_path / "attachments.json"
    assert main(["review-attachments", str(path), "--output", str(output)]) == 0
    assert main(["brief", str(output)]) == 0
    assert "binary_metadata" in capsys.readouterr().out
    original = output.read_bytes()
    assert main(["review-attachments", str(path), "--output", str(output)]) == 2
    assert output.read_bytes() == original


def test_console_attachment_review(tmp_path, monkeypatch):
    from ai_threat_lab.cli import main
    path = saved(tmp_path, [b"unknown"])
    output = tmp_path / "console-attachments.json"
    answers = iter(map(str, ["12", path, output, "0"]))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert main(["console"]) == 0
    assert "binary_metadata" in output.read_text()
