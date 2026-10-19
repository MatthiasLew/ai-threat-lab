"""Source-free saved-page/form checks with conservative browser-semantics gaps."""

import json
import socket
from dataclasses import asdict

import pytest

from ai_threat_lab.html_review import inspect_html, review_html_file
from ai_threat_lab.models import ValidationError

PAGE = "https://site.example/login?PRIVATE=TOKEN"
PASSWORD = "<input type=password name=PRIVATE value=SECRET>"


def checks(source, url=PAGE):
    findings, _ = inspect_html(source, document_url=url)
    assert "SECRET" not in str(findings) and "PRIVATE" not in str(findings)
    return {f.check for f in findings}


@pytest.mark.parametrize("action", ["http://site.example/login", "http://other.example/"])
def test_named_password_get_and_http_form_candidates(action):
    result = checks('<form action="' + action + '">' + PASSWORD + "</form>")
    assert {"html_password_form_get", "html_password_form_http"} <= result
    assert "html_password_form_cross_origin" in result


@pytest.mark.parametrize("method", ["", "get", "GET"])
def test_missing_method_and_explicit_get_use_selected_query_pattern(method):
    assert checks('<form method="' + method + '">' + PASSWORD + "</form>") == {
        "html_password_form_get"
    }


@pytest.mark.parametrize("method", ["post", "POST", "dialog", "invalid"])
def test_post_dialog_and_unresolved_method_do_not_claim_get_or_http(method):
    assert not checks('<form method="' + method + '">' + PASSWORD + "</form>")


@pytest.mark.parametrize(
    "field",
    [
        "<input type=password>",
        '<input type=password name="">',
        "<input type=password name=p disabled>",
        "<input type=text name=p>",
    ],
)
def test_only_named_enabled_password_controls_enter_form_checks(field):
    assert not checks('<form action="http://other.example/">' + field + "</form>")


def test_empty_action_uses_document_not_http_base():
    result = checks('<base href="http://other.example/"><form action="">' + PASSWORD + "</form>")
    assert result == {"html_password_form_get"}


def test_relative_action_uses_first_base_href():
    result = checks(
        '<base href="http://other.example/a/"><base href="https://site.example/">'
        '<form action="next" method=post>' + PASSWORD + "</form>"
    )
    assert result == {"html_password_form_http", "html_password_form_cross_origin"}


@pytest.mark.parametrize(
    "base", ["javascript:PRIVATE", "https://exa<mple/", "http://[broken", "\\host"]
)
def test_invalid_first_base_leaves_relative_form_unchecked(base):
    result, notices = inspect_html(
        '<base href="' + base + '"><form action=next>' + PASSWORD + "</form>", document_url=PAGE
    )
    assert not result and any("base URL unsupported" in n for n in notices)
    assert "PRIVATE" not in str(notices)


def test_relative_urls_without_document_context_are_not_guessed():
    assert not checks(
        "<form action=next>" + PASSWORD + '</form><script src="//other.example/x"></script>', None
    )


def test_absolute_http_form_can_be_observed_without_document_url():
    assert checks('<form action="http://other.example/">' + PASSWORD + "</form>", None) == {
        "html_password_form_get",
        "html_password_form_http",
    }


@pytest.mark.parametrize(
    "source",
    [
        "<form><fieldset>" + PASSWORD + "</fieldset></form>",
        "<form>" + PASSWORD + '<button formaction="http://other.example/">Go</button></form>',
        "<form>" + PASSWORD + "<input type=submit formmethod=get></form>",
        "<form>" + PASSWORD + "</form><input name=x form=elsewhere>",
        "<form><form>" + PASSWORD + "</form></form>",
        "<form>" + PASSWORD,
        "<form method=post method=get>" + PASSWORD + "</form>",
        "<form><input type=password type=text name=x></form>",
    ],
)
def test_ambiguous_form_structure_association_and_overrides_have_no_candidates(source):
    findings, notices = inspect_html(source, document_url=PAGE)
    assert not findings and len(notices) > 2


@pytest.mark.parametrize("container", ["template", "svg", "math", "noscript"])
def test_unmodeled_subtrees_do_not_turn_hidden_markup_into_active_elements(container):
    assert not checks(
        "<" + container + "><form>" + PASSWORD + "</form>"
        '<script src="http://other.example/x"></script></' + container + ">"
    )


@pytest.mark.parametrize(
    "resource",
    [
        '<script src="http://other.example/x"></script>',
        '<iframe src="http://other.example/"></iframe>',
        '<link rel=stylesheet href="http://other.example/x">',
    ],
)
def test_selected_active_resources_expose_http_authoring_on_https(resource):
    assert "html_mixed_active_content" in checks(resource)
    assert not checks(resource, "http://other.example/page")


def test_srcdoc_overrides_iframe_src_and_is_not_parsed_recursively():
    assert not checks(
        '<iframe src="http://other.example/" '
        'srcdoc="&lt;script&gt;PRIVATE&lt;/script&gt;"></iframe>'
    )


@pytest.mark.parametrize(
    "kind", ["application/json", "application/ld+json", "importmap", "text/plain"]
)
def test_non_javascript_script_blocks_are_not_active_resource_candidates(kind):
    assert not checks('<script type="' + kind + '" src="http://other.example/x"></script>')


@pytest.mark.parametrize("kind", ["", "module", "text/javascript", "application/javascript"])
def test_cross_origin_script_without_declared_integrity_is_a_candidate(kind):
    assert checks('<script type="' + kind + '" src="https://other.example/x"></script>') == {
        "html_external_script_without_integrity"
    }


def test_nonempty_integrity_marker_is_not_validated_as_a_hash():
    result, notices = inspect_html(
        '<script src="https://other.example/x" integrity="invalid-marker"></script>',
        document_url=PAGE,
    )
    assert not result and any("integrity values" in n for n in notices)


@pytest.mark.parametrize("url", ["https://site.example:443/x", "//site.example/x", "/x"])
def test_same_origin_script_spellings_do_not_trigger_third_party_rule(url):
    assert not checks('<script src="' + url + '"></script>')


def test_explicit_port_zero_is_not_conflated_with_default_port():
    assert checks('<script src="https://site.example:0/x"></script>') == {
        "html_external_script_without_integrity"
    }


@pytest.mark.parametrize(
    "url", ["https://u:p@other.example/x", "https://other.example/x?PRIVATE=SECRET"]
)
def test_destination_values_never_enter_evidence(url):
    findings, notices = inspect_html('<script src="' + url + '"></script>', document_url=PAGE)
    assert findings
    assert "SECRET" not in str(findings) + str(notices)
    assert "u:p" not in str(findings) + str(notices)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:SECRET@site.example/",
        "https://exa<mple/",
        "ftp://site.example/",
        "http://[broken",
        "https://café.example/",
        "https://site.example/\nPRIVATE",
        "https://site.example/\\PRIVATE",
    ],
)
def test_invalid_declared_url_is_rejected_without_value_echo(url):
    with pytest.raises(ValidationError) as error:
        inspect_html("", document_url=url)
    assert "SECRET" not in str(error.value) and "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("source", ["x" * (256 * 1024 + 1), "\ud800"], ids=["oversize", "encoding"])
def test_source_size_and_encoding_bounds(source):
    with pytest.raises(ValidationError):
        inspect_html(source)


@pytest.mark.parametrize(
    "source",
    [
        "<p></p>" * 5001,
        "<template/>" * 5001,
        "<form></form>" * 101,
        "<input " + " ".join("a" + str(i) + "=x" for i in range(101)) + ">",
    ],
    ids=["elements", "containers", "forms", "attributes"],
)
def test_structural_limits_return_gap_without_partial_candidates(source):
    findings, notices = inspect_html(source, document_url=PAGE)
    assert not findings and any("candidates omitted" in n for n in notices)


def test_source_file_is_not_executed_and_document_url_is_not_fetched(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("HTML analysis attempted network access")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    path = tmp_path / "page.html"
    path.write_text(
        '<script>throw "PRIVATE"</script><form action="http://other.example/">'
        + PASSWORD
        + "</form>",
        encoding="utf-8",
    )
    result = review_html_file(path, document_url=PAGE)
    assert result.target_kind == "html_document"
    assert len(result.findings) == 3
    assert "PRIVATE" not in json.dumps(asdict(result))


def test_file_rejects_directory_invalid_text_and_link(tmp_path):
    with pytest.raises(ValidationError):
        review_html_file(tmp_path)
    path = tmp_path / "bad.html"
    path.write_bytes(b"\xff")
    with pytest.raises(ValidationError):
        review_html_file(path)
    link = tmp_path / "link.html"
    try:
        link.symlink_to(path)
    except OSError:
        return
    with pytest.raises(ValidationError):
        review_html_file(link)


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [("Content-Type", "application/xhtml+xml")],
        [("Content-Type", "text/html"), ("content-type", "text/html")],
        [("Content-Type", "text/html; charset=iso-8859-1")],
        [("Content-Type", "text/html; charset=utf-8; charset=utf-8")],
        [("Content-Type", "text/html"), ("Content-Encoding", "gzip")],
        [
            ("Content-Type", "text/html"),
            ("Content-Encoding", "identity"),
            ("content-encoding", "identity"),
        ],
    ],
)
def test_response_requires_unambiguous_utf8_html(headers):
    from ai_threat_lab.html_review import inspect_html_response

    findings, missing = inspect_html_response(
        ('<form action="http://other.example/">' + PASSWORD + "</form>").encode(),
        headers,
        document_url=PAGE,
    )
    assert not findings and any("unchecked" in n for n in missing)


@pytest.mark.parametrize(
    "body",
    [b"\xff", b"x" * (256 * 1024 + 1), "text"],
    ids=["invalid-utf8", "oversized", "notbytes"],
)
def test_bad_body_keeps_header_assessment(body):
    from test_remote_audit import QueueHTTP

    from ai_threat_lab.http_client import HttpResponse
    from ai_threat_lab.remote_audit import WebsiteAudit

    client = QueueHTTP(HttpResponse(200, {"content-type": "text/html"}, body))
    result = WebsiteAudit(client).assess("https://site.example/")
    assert len(client.calls) == 1
    assert "missing_strict-transport-security" in {f.check for f in result.findings}
    assert not any(f.check.startswith("html_") for f in result.findings)


@pytest.mark.parametrize("status", [200, 302, 403, 500])
def test_website_uses_only_existing_success_response_no_resource_requests(status):
    from test_remote_audit import QueueHTTP

    from ai_threat_lab.http_client import HttpResponse
    from ai_threat_lab.remote_audit import WebsiteAudit

    source = '<form action="http://other.example/">' + PASSWORD + "</form>"
    client = QueueHTTP(
        HttpResponse(status, {"Content-Type": 'text/html; charset="UTF-8"'}, source.encode())
    )
    result = WebsiteAudit(client).assess("https://site.example/")
    assert len(client.calls) == 1
    html = {f.check for f in result.findings if f.check.startswith("html_")}
    assert html == (
        {"html_password_form_get", "html_password_form_http", "html_password_form_cross_origin"}
        if status == 200
        else set()
    )


def test_local_and_github_selected_html_share_parser_and_verified_blob(tmp_path):
    from test_remote_audit import QueueHTTP, blob, repository

    from ai_threat_lab.local_inventory import local_inventory
    from ai_threat_lab.remote_audit import GithubAudit

    source = '<form action="http://other.example/">' + PASSWORD + "</form>"
    (tmp_path / "page.HTML").write_text(source)
    local = local_inventory(str(tmp_path))
    entry, content = blob(source)
    entry["path"] = "page.HTML"
    client = QueueHTTP(*repository(entry), content)
    remote = GithubAudit(client).assess("https://github.com/owner/repo")
    expected = {"html_password_form_get", "html_password_form_http"}
    assert {f.check for f in local.findings if f.check.startswith("html_")} == expected
    assert {f.check for f in remote.findings if f.check.startswith("html_")} == expected
    assert len(client.calls) == 4
    assert "SECRET" not in str(local.findings) + str(remote.findings)


def test_message_html_form_candidates_are_scoped_and_source_free():
    from email import policy
    from email.parser import BytesParser

    from ai_threat_lab.mail_review import inspect_message_content

    source = '<form action="http://other.example/">' + PASSWORD + "</form>"
    raw = b"Content-Type: text/html; charset=utf-8\r\n\r\n" + source.encode()
    findings, missing = inspect_message_content(BytesParser(policy=policy.default).parsebytes(raw))
    assert {f.check for f in findings} == {
        "message_html_password_form_get",
        "message_html_password_form_http",
    }
    assert "SECRET" not in str(findings) and "PRIVATE" not in str(findings)
    assert any("Static HTML subset" in n for n in missing)


def test_saved_html_cli_scan_and_batch_contracts(tmp_path):
    from test_cli_process import run_cli

    from ai_threat_lab.scan_bundle import read_bundle

    path = tmp_path / "saved próbna.html"
    path.write_text('<form action="http://other.example/">' + PASSWORD + "</form>")
    result = run_cli("review-html", path, "--document-url", PAGE, "--fail-on-findings")
    assert result.returncode == 1, result.stderr
    assert len(json.loads(result.stdout)["findings"]) == 3
    report = tmp_path / "review.html"
    result = run_cli("review-html", path, "--format", "html", "--output", report)
    assert result.returncode == 0, result.stderr
    assert "html_password_form_http" in report.read_text()
    result = run_cli("review-html", path, "--output", report)
    assert result.returncode == 2 and report.read_text().startswith("<!doctype html>")
    result = run_cli("review-html", path, "--document-url", "javascript:PRIVATE")
    assert result.returncode == 2 and "PRIVATE" not in result.stderr
    result = run_cli("scan", path, "--output-dir", tmp_path / "bundle")
    assert result.returncode == 0, result.stderr
    read_bundle(tmp_path / "bundle")


def test_html_finding_cap_and_mime_cap_are_visible():
    from email.message import EmailMessage

    from ai_threat_lab.mail_review import inspect_message_content

    source = "\n".join(
        '<form action="http://other.example/">' + PASSWORD + "</form>" for _ in range(100)
    )
    findings, notices = inspect_html(source, document_url=PAGE)
    assert len(findings) == 200 and any("finding limit" in n for n in notices)
    message = EmailMessage()
    message.make_mixed()
    for _ in range(2):
        part = EmailMessage()
        part.set_content(source, subtype="html")
        message.attach(part)
    findings, notices = inspect_message_content(message)
    assert len(findings) == 200
    assert any("HTML" in n and "limit" in n for n in notices)


def test_batch_accepts_saved_html_alongside_zip(tmp_path):
    from test_archive_review import fixture
    from test_cli_process import run_cli

    path = tmp_path / "page.html"
    path.write_text('<form action="http://other.example/">' + PASSWORD + "</form>")
    archive = tmp_path / "data.zip"
    archive.write_bytes(fixture("../example.txt"))
    result = run_cli("scan-batch", path, archive, "--output-dir", tmp_path / "batch")
    assert result.returncode == 0, result.stderr
    checked = run_cli("batch-check", tmp_path / "batch")
    assert checked.returncode == 0, checked.stderr


def test_engine_nineteen_remains_readable_but_not_comparable(tmp_path):
    from ai_threat_lab.scan_bundle import compare_bundles, publish_bundle, read_bundle, scope_digest
    from ai_threat_lab.scan_cli import assessor
    from ai_threat_lab.scan_engine import ScanOptions, ScanService

    path = tmp_path / "page.html"
    path.write_text("<p>example</p>")
    ScanService(assessor).run(ScanOptions(str(path)), tmp_path / "new")
    current = read_bundle(tmp_path / "new")
    metadata = dict(current["manifest"])
    metadata["scope"] = {**metadata["scope"], "engine": "read-only-pipeline-19"}
    metadata["scope_digest"] = scope_digest(metadata["scope"])
    artifacts = {name: (tmp_path / "new" / name).read_bytes() for name in metadata["files"]}
    publish_bundle(tmp_path / "old", artifacts, metadata)
    assert not compare_bundles(read_bundle(tmp_path / "old"), current)["comparable"]


@pytest.mark.parametrize("tag", ["textarea", "title", "xmp", "iframe", "noembed", "noframes"])
def test_non_markup_text_and_frame_fallback_do_not_create_forms(tag):
    source = (
        "<" + tag + '><form action="http://other.example/">' + PASSWORD + "</form></" + tag + ">"
    )
    assert not checks(source)


def test_plaintext_never_reenters_markup_after_fake_close():
    assert not checks(
        '<plaintext></plaintext><form action="http://other.example/">' + PASSWORD + "</form>"
    )


@pytest.mark.parametrize("tag", ["table", "select"])
def test_tree_repair_contexts_suppress_form_assumptions(tag):
    assert not checks(
        "<" + tag + '><form action="http://other.example/">' + PASSWORD + "</form></" + tag + ">"
    )


def test_new_demo_missing_html_candidate_blocks_completion(tmp_path, monkeypatch):
    import ai_threat_lab.offline_cli as offline

    monkeypatch.setattr(offline, "synthetic_html", lambda **kwargs: "<p>inert</p>")
    with pytest.raises(ValidationError, match="HTML acceptance"):
        offline.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo" / "demo-result.json").exists()


def test_new_demo_missing_zip_candidate_blocks_completion(tmp_path, monkeypatch):
    from test_archive_review import fixture

    import ai_threat_lab.offline_cli as offline

    monkeypatch.setattr(offline, "synthetic_zip", lambda: fixture("normal.txt"))
    with pytest.raises(ValidationError, match="ZIP acceptance"):
        offline.offline_demo(tmp_path / "demo")
    assert not (tmp_path / "demo" / "demo-result.json").exists()


@pytest.mark.parametrize(
    "tag",
    [
        "template",
        "noscript",
        "svg",
        "math",
        "form",
        "table",
        "select",
        "textarea",
        "title",
        "iframe",
        "xmp",
        "script",
        "style",
        "noembed",
        "noframes",
    ],
)
def test_self_closing_nonvoid_syntax_does_not_create_fake_form_candidates(tag):
    assert not checks("<" + tag + '/><form action="http://other.example/">' + PASSWORD + "</form>")
