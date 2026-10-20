"""Captured authenticated browser traffic is analyzed locally, never replayed."""

import base64
import copy
import json

import pytest

from ai_threat_lab.cli import main
from ai_threat_lab.evidence import load_evidence
from ai_threat_lab.har_review import response_body, review_har
from ai_threat_lab.models import ValidationError

HTML = '<form><input type="password" name="PRIVATE"></form>'


def entry():
    return {
        "request": {
            "method": "POST", "url": "https://local.example/PRIVATE?token=PRIVATE",
            "headers": [{"name": "Authorization", "value": "Bearer PRIVATE"}],
            "cookies": [{"name": "session", "value": "PRIVATE"}],
            "postData": {"text": "password=PRIVATE"},
        },
        "response": {
            "status": 200,
            "headers": [
                {"name": "content-type", "value": "text/html"},
                {"name": "set-cookie", "value": "session=PRIVATE; SameSite=None"},
            ],
            "content": {"size": len(HTML.encode()), "mimeType": "text/html", "text": HTML},
        },
    }


def save(tmp_path, entries, version="1.2"):
    path = tmp_path / "capture.har"
    path.write_text(json.dumps({"log": {"version": version, "entries": entries}}),
                    encoding="utf-8")
    return path


def test_captured_post_analysis_redacts_all_values(tmp_path, monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("HAR review attempted a connection")

    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    report, failures = review_har(save(tmp_path, [entry()]))
    assert failures == 0
    checks = {row["check"] for row in report["findings"]}
    assert {"html_password_form_get", "cookie_none_without_secure"} <= checks
    assert "PRIVATE" not in json.dumps(report)
    assert "local.example" not in json.dumps(report)
    output = tmp_path / "report.json"
    output.write_text(json.dumps(report), encoding="utf-8")
    assert load_evidence(output)["report"] == report


def test_base64_and_missing_body_preserve_headers(tmp_path):
    first, second = entry(), entry()
    content = first["response"]["content"]
    content["text"] = base64.b64encode(HTML.encode()).decode()
    content["encoding"] = "base64"
    del second["response"]["content"]["text"]
    report, failures = review_har(save(tmp_path, [first, second]))
    assert failures == 0
    html_sources = [row["sources"] for row in report["findings"]
                    if row["check"] == "html_password_form_get"]
    assert html_sources == [[1]]
    assert any(row["notice"] == "HAR response body was not captured."
               for row in report["not_checked"])


@pytest.mark.parametrize("change", [
    lambda e: e.update(request=None),
    lambda e: e.update(response=[]),
    lambda e: e["request"].update(url="http://local.example/"),
    lambda e: e["request"].update(url="https://a:b@local.example/"),
    lambda e: e["response"].update(status=0),
    lambda e: e["response"].update(status=True),
    lambda e: e["response"].update(headers=[None]),
    lambda e: e["response"].update(headers=[{"name": "X", "value": "PRIVATE\n"}]),
    lambda e: e["response"].update(headers=[{"name": "X", "value": "v"}] * 101),
])
def test_malformed_entry_preserves_other_results(tmp_path, change):
    broken = entry()
    change(broken)
    report, failures = review_har(save(tmp_path, [broken, entry()]))
    assert failures == 1
    assert report["assessments"][0]["status"] == "not_configured"
    assert report["assessments"][1]["finding_count"] > 0
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("content", [
    None, {}, {"text": "x", "size": 0}, {"text": "x", "size": True},
    {"text": "x", "size": 1, "encoding": "gzip"},
    {"text": "!!!!", "size": 3, "encoding": "base64"},
    {"text": "\ud800", "size": 1},
    {"text": "x" * (512 * 1024 + 1), "size": 1},
    {"text": "x" * (256 * 1024 + 1), "size": 256 * 1024 + 1},
])
def test_unsupported_body_has_explicit_gap(content):
    body, gap = response_body(content)
    assert body is None and gap


def test_paging_preserves_original_entry_numbers(tmp_path):
    path = save(tmp_path, [copy.deepcopy(entry()) for _ in range(22)])
    report, failures = review_har(path, start=21)
    assert failures == 0
    assert [row["target"] for row in report["assessments"]] == [
        "HAR entry 0021", "HAR entry 0022",
    ]
    assert any("21..22 of 22" in row["notice"] for row in report["not_checked"])


@pytest.mark.parametrize("start,maximum", [(0, 1), (True, 1), (1, 0), (1, 21), (1, True)])
def test_options_validate_before_read(tmp_path, start, maximum):
    with pytest.raises(ValidationError):
        review_har(tmp_path / "absent", start=start, max_entries=maximum)


def test_invalid_capture_rejected(tmp_path):
    for entries, version in [([], "1.2"), ([entry()] * 201, "1.2"), ([entry()], "1.1")]:
        with pytest.raises(ValidationError):
            review_har(save(tmp_path, entries, version))
    with pytest.raises(ValidationError):
        review_har(save(tmp_path, [entry()]), start=2)
    path = tmp_path / "duplicate.har"
    path.write_text('{"log":{},"log":{}}', encoding="utf-8")
    with pytest.raises(ValidationError):
        review_har(path)


def test_cli_output_and_no_overwrite(tmp_path):
    source, output = save(tmp_path, [entry()]), tmp_path / "report.json"
    args = ["review-har", str(source), "--output", str(output)]
    assert main(args + ["--fail-on-findings"]) == 1
    assert load_evidence(output)["report"]["assessments"][0]["target"] == "HAR entry 0001"
    assert main(args) == 2


def test_console_capture_route(monkeypatch):
    from ai_threat_lab.console import run_console

    inputs = iter(["10", "capture.har", "report.json", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    calls = []
    assert run_console(lambda args: calls.append(args) or 0) == 0
    assert calls == [["review-har", "capture.har", "--output", "report.json"]]


def test_non_200_and_malformed_cli_status(tmp_path, capsys):
    item = entry()
    item["response"]["status"] = 302
    report, failures = review_har(save(tmp_path, [item]))
    assert failures == 0
    assert not any(f["check"] == "html_password_form_get" for f in report["findings"])
    source = save(tmp_path, [None])
    assert main(["review-har", str(source)]) == 2
    assert json.loads(capsys.readouterr().out)["assessments"][0]["status"] == "not_configured"
