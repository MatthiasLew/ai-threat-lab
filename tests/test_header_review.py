"""Redacted cookie/CSP observations over bounded captures and duplicate HTTPS fields."""

import json
import socket
from dataclasses import asdict

import pytest
from test_cli_process import run_cli
from test_remote_audit import QueueHTTP

from ai_threat_lab.audit_report import merge_reports
from ai_threat_lab.cli import main
from ai_threat_lab.header_review import audit_header_capture, inspect_response_headers
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError
from ai_threat_lab.remote_audit import WebsiteAudit

SAFE = [
    ["Strict-Transport-Security", "max-age=31536000"],
    ["Content-Security-Policy", "default-src 'self'"],
    ["X-Content-Type-Options", "nosniff"],
    ["Referrer-Policy", "no-referrer"],
]


def checks(headers, status=200):
    return {f.check for f in inspect_response_headers(status, headers)[0]}


def capture(path, headers=SAFE, **changes):
    value = {
        "schema_version": 1,
        "url": "https://private.example.invalid/?token=PRIVATE_URL",
        "status": 200,
        "headers": headers,
    }
    value.update(changes)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "cookie,expected",
    [
        ("private=value; Secure; HttpOnly; SameSite=Strict", set()),
        ("private=value; secure; httponly; samesite=lax;", set()),
        ('private="value"; Secure; HttpOnly; SameSite=None', set()),
        ("private=; Secure; HttpOnly; SameSite=Lax; Max-Age=0", set()),
        (
            "private=value",
            {"cookie_missing_secure", "cookie_missing_httponly", "cookie_missing_samesite"},
        ),
        (
            "private=value; HttpOnly; SameSite=None",
            {"cookie_missing_secure", "cookie_none_without_secure"},
        ),
        ("private=value; Secure; SameSite=Lax", {"cookie_missing_httponly"}),
        ("private=value; Secure; HttpOnly; SameSite=unknown", {"cookie_invalid_samesite"}),
        (
            "__Secure-private=value; HttpOnly; SameSite=Lax",
            {"cookie_missing_secure", "cookie_prefix_constraints"},
        ),
        ("__Host-private=value; Secure; HttpOnly; SameSite=Lax; Path=/", set()),
        (
            "__Host-private=value; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=private.invalid",
            {"cookie_prefix_constraints"},
        ),
        ("__Host-private=value; Secure; HttpOnly; SameSite=Lax", {"cookie_prefix_constraints"}),
        (
            "__Host-private=value; Secure; HttpOnly; SameSite=Lax; Path=/private",
            {"cookie_prefix_constraints"},
        ),
        ("private=value; Secure; Secure", {"cookie_ambiguous_attributes"}),
        ("private=value; malformed attribute", {"cookie_ambiguous_attributes"}),
        ("private=value, second=another", {"cookie_unparsed"}),
        ("private without equals", {"cookie_unparsed"}),
        ('private="unterminated', {"cookie_unparsed"}),
        (
            "private=value; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax",
            set(),
        ),
    ],
)
def test_cookie_attributes_and_prefixes_are_metadata_candidates(cookie, expected):
    findings, notices = inspect_response_headers(200, SAFE + [["Set-Cookie", cookie]])
    assert {f.check for f in findings} == expected
    assert all(f.status == "candidate" for f in findings)
    assert "value" not in " ".join(f.evidence.replace("values omitted", "") for f in findings)
    assert any("Preference and deletion" in n for n in notices)


@pytest.mark.parametrize(
    "policy,expected",
    [
        ("script-src 'self'", set()),
        ("default-src 'self' 'unsafe-eval'", {"csp_script_unsafe_eval"}),
        ("script-src 'unsafe-eval'", {"csp_script_unsafe_eval"}),
        ("script-src 'unsafe-inline'", {"csp_script_unsafe_inline"}),
        ("script-src *", {"csp_script_wildcard"}),
        (
            "script-src * 'unsafe-inline' 'unsafe-eval'",
            {"csp_script_wildcard", "csp_script_unsafe_inline", "csp_script_unsafe_eval"},
        ),
        ("script-src 'unsafe-inline' 'nonce-cHJpdmF0ZQ=='", set()),
        ("script-src 'unsafe-inline' 'sha256-cHJpdmF0ZQ=='", set()),
        ("script-src * 'nonce-cHJpdmF0ZQ==' 'strict-dynamic'", set()),
        ("script-src * 'strict-dynamic'", {"csp_script_wildcard"}),
        ("default-src *; script-src 'none'", set()),
        ("script-src 'none'; script-src 'unsafe-inline'", set()),
        ("script-src 'unsafe-inline'; script-src-elem 'none'", set()),
        ("style-src 'unsafe-inline'; script-src 'self'", set()),
        ("script-src 'self', script-src 'unsafe-inline'", set()),
        ("script-src-elem 'unsafe-eval'; script-src 'self'", set()),
    ],
)
def test_csp_selected_script_patterns_do_not_claim_browser_execution(policy, expected):
    headers = [row for row in SAFE if row[0] != "Content-Security-Policy"]
    findings, notices = inspect_response_headers(
        200, headers + [["Content-Security-Policy", policy]]
    )
    assert {f.check for f in findings} == expected
    assert "cHJpdmF0ZQ" not in str(findings) and "nonce-" not in str(findings)
    assert any("intersection" in n for n in notices)


def test_duplicate_cookie_fields_aggregate_without_merging_expires_or_secret_values():
    headers = SAFE + [["Set-Cookie", "private1=SECRET1"], ["Set-Cookie", "private2=SECRET2"]]
    findings, _ = inspect_response_headers(200, headers)
    assert len(findings) == 3 and all(f.evidence.startswith("2 ") for f in findings)
    assert "SECRET" not in str(findings) and "private1" not in str(findings)
    assert "duplicate_security_header" not in {f.check for f in findings}


def test_report_only_and_duplicate_policies_have_explicit_limits():
    headers = [row for row in SAFE if row[0] != "Content-Security-Policy"]
    assert "missing_content-security-policy" in checks(
        headers + [["Content-Security-Policy-Report-Only", "script-src 'none'"]]
    )
    findings, notices = inspect_response_headers(
        200, SAFE + [["Content-Security-Policy", "script-src 'unsafe-eval'"]]
    )
    assert {f.check for f in findings} == {"csp_script_unsafe_eval"}
    assert any("Multiple enforcing" in n for n in notices)
    assert "duplicate_security_header" in checks(
        SAFE + [["X-Content-Type-Options", "private-value"]]
    )


@pytest.mark.parametrize("status", [True, 0, 600, "200"])
def test_invalid_status_is_not_coerced(status):
    with pytest.raises(ValidationError):
        inspect_response_headers(status, SAFE)


@pytest.mark.parametrize(
    "headers",
    [
        None,
        {},
        [["a"]],
        [[None, "PRIVATE"]],
        [["bad name", "PRIVATE"]],
        [["X-Test", None]],
        [["X-Test", "PRIVATE\r\nOther: value"]],
        [["X-Test", "PRIVATE\x7f"]],
        [["X-Test", "\ud800"]],
    ],
)
def test_invalid_pairs_and_controls_fail_without_values(headers):
    with pytest.raises(ValidationError) as error:
        inspect_response_headers(200, headers)
    assert "PRIVATE" not in str(error.value)


def test_exact_header_resource_limits_and_no_truncation():
    assert inspect_response_headers(200, [["x", "a" * 16384]])[0]
    for headers in ([["x", "a"]] * 101, [["x", "a" * 16385]], [["x", "a" * 16384]] * 4):
        with pytest.raises(ValidationError, match="100|limit"):
            inspect_response_headers(200, headers)


@pytest.mark.parametrize("status", [201, 301, 401, 500])
def test_non_200_is_unchecked_not_an_all_clear(status):
    findings, notices = inspect_response_headers(status, [["Set-Cookie", "private=SECRET"]])
    assert not findings and any("not performed" in n for n in notices)


def test_offline_capture_never_contacts_url_and_reports_are_redacted(tmp_path, monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("No network during offline header review")

    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    path = capture(
        tmp_path / "capture.json",
        SAFE
        + [
            ["Set-Cookie", "private=SECRET_COOKIE"],
            ["Authorization", "PRIVATE_AUTH"],
            ["X-Trace", "PRIVATE_TRACE"],
        ],
    )
    result = audit_header_capture(path)
    assert result.target_kind == "http_response_headers" and result.status == "partial"
    assert len(result.findings) == 3
    report = json.dumps(asdict(result))
    for secret in (
        "SECRET_COOKIE",
        "PRIVATE_URL",
        "PRIVATE_AUTH",
        "PRIVATE_TRACE",
        "private.example.invalid",
    ):
        assert secret not in report
    assert merge_reports([json.loads(report)])["summary"]["unique_findings"] == 3


@pytest.mark.parametrize(
    "url",
    [
        "http://example.invalid",
        "https://user:SECRET@example.invalid",
        "https://@example.invalid",
        "https://example.invalid:bad/",
        "https://example.invalid/#fragment",
        "https://example.invalid/\nPRIVATE",
        None,
    ],
)
def test_offline_url_is_only_a_validated_declaration(tmp_path, url):
    path = capture(tmp_path / "capture.json", url=url)
    with pytest.raises(ValidationError) as error:
        audit_header_capture(path)
    assert "SECRET" not in str(error.value) and "PRIVATE" not in str(error.value)


def test_capture_schema_encoding_limits_and_root_links(tmp_path):
    path = capture(tmp_path / "capture.json", schema_version=True)
    with pytest.raises(ValidationError):
        audit_header_capture(path)
    path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValidationError):
        audit_header_capture(path)
    path.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(ValidationError, match="1 MiB"):
        audit_header_capture(path)
    capture(path)
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(path)
    except (OSError, NotImplementedError):
        return
    with pytest.raises(ValidationError, match="without links"):
        audit_header_capture(link)


def test_live_adapter_preserves_duplicate_cookies_and_uses_same_engine():
    pairs = SAFE + [["Set-Cookie", "first=PRIVATE1"], ["Set-Cookie", "second=PRIVATE2"]]
    response = HttpResponse(
        200, dict((k.lower(), v) for k, v in pairs), b"PRIVATE_BODY", tuple(pairs)
    )
    client = QueueHTTP(response)
    result = WebsiteAudit(client).assess("https://example.invalid/")
    assert len(client.calls) == 1 and len(result.findings) == 3
    assert all(f.evidence.startswith("2 ") for f in result.findings)
    assert result.findings == inspect_response_headers(200, pairs)[0]
    assert "PRIVATE" not in json.dumps(asdict(result))


def test_live_header_errors_remain_redacted_provider_failures():
    response = HttpResponse(200, {"x-private": "PRIVATE\r\nvalue"}, b"")
    with pytest.raises(ProviderError) as error:
        WebsiteAudit(QueueHTTP(response)).assess("https://example.invalid")
    assert "PRIVATE" not in str(error.value)


def test_transport_keeps_all_wire_header_pairs(monkeypatch):
    from test_http_client import Connection

    import ai_threat_lab.http_client as module

    monkeypatch.setattr(module, "public_address", lambda _: "8.8.8.8")
    monkeypatch.setattr(module, "_PinnedHTTPS", Connection)
    monkeypatch.setattr(
        Connection,
        "getheaders",
        lambda _: [("Set-Cookie", "a=PRIVATE1"), ("Set-Cookie", "b=PRIVATE2")],
    )
    response = module.PublicHTTPS(["example.invalid"]).request("https://example.invalid/")
    assert response.header_items == (("set-cookie", "a=PRIVATE1"), ("set-cookie", "b=PRIVATE2"))
    assert response.headers["set-cookie"] == "b=PRIVATE2"  # Legacy mapping remains compatible.


def test_cli_json_html_exit_codes_and_no_overwrite(tmp_path, capsys):
    path = capture(tmp_path / "capture.json", SAFE + [["Set-Cookie", "private=SECRET_COOKIE"]])
    assert main(["review-headers", str(path), "--fail-on-findings"]) == 1
    assert len(json.loads(capsys.readouterr().out)["findings"]) == 3
    output = tmp_path / "report.html"
    assert main(["review-headers", str(path), "--format", "html", "--output", str(output)]) == 0
    original = output.read_bytes()
    assert b"SECRET_COOKIE" not in original and b"PRIVATE_URL" not in original
    assert main(["review-headers", str(path), "--output", str(output)]) == 2
    assert output.read_bytes() == original
    capture(path)
    result = run_cli("review-headers", path, "--fail-on-findings")
    assert result.returncode == 0 and not result.stderr
    assert json.loads(result.stdout)["findings"] == []
    assert run_cli("review-headers", path, "--network").returncode == 2


def test_demo_missing_header_evidence_cannot_publish_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as module
    from ai_threat_lab.assessment import AssessmentResult

    monkeypatch.setattr(
        module,
        "audit_header_capture",
        lambda path: AssessmentResult(
            str(path), "http_response_headers", "partial", (), ("No fixture evidence",)
        ),
    )
    with pytest.raises(ValidationError, match="header acceptance"):
        module.offline_demo(tmp_path / "incomplete")
    assert not (tmp_path / "incomplete" / "demo-result.json").exists()


def test_engine_seven_bundle_remains_readable_without_cross_engine_deltas(tmp_path):
    from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, read_bundle, scope_digest
    from ai_threat_lab.scan_cli import assessor
    from ai_threat_lab.scan_engine import ScanOptions, ScanService

    source = tmp_path / "source.py"
    source.write_text("eval(data)")
    ScanService(assessor).run(ScanOptions(str(source)), tmp_path / "current")
    current = read_bundle(tmp_path / "current")
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-7"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "current" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    comparison = compare_bundles(read_bundle(tmp_path / "old"), current)
    assert comparison["comparable"] is False and comparison["counts"] is None


def test_invalid_capture_never_creates_output_and_does_not_echo_header_text(tmp_path, capsys):
    source = tmp_path / "broken.json"
    source.write_text('{"headers": "PRIVATE_INVALID')
    output = tmp_path / "absent.html"
    assert main(["review-headers", str(source), "--format", "html", "--output", str(output)]) == 2
    assert not output.exists()
    assert "PRIVATE_INVALID" not in capsys.readouterr().err


def test_legacy_header_mapping_is_supported_with_duplicate_coverage_notice():
    headers = {key.lower(): value for key, value in SAFE}
    headers["set-cookie"] = "private=value"
    result = WebsiteAudit(QueueHTTP(HttpResponse(200, headers, b""))).assess(
        "https://example.invalid"
    )
    assert len(result.findings) == 3
    assert any("duplicate fields may be missing" in n for n in result.not_checked)
