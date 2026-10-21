import base64
import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError
from ai_threat_lab.remote_audit import GithubAudit, GmailAudit, MailDomainAudit, WebsiteAudit


class QueueHTTP:
    def __init__(self, *documents):
        self.documents = list(documents)
        self.calls = []

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        response = self.documents.pop(0)
        return (
            response
            if isinstance(response, HttpResponse)
            else HttpResponse(200, {}, json.dumps(response).encode())
        )


def test_website_absent_and_valid_headers():
    result = WebsiteAudit(QueueHTTP(HttpResponse(200, {}, b""))).assess("https://example.com")
    assert len(result.findings) == 4 and result.status == "partial"
    headers = {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    }
    result = WebsiteAudit(QueueHTTP(HttpResponse(200, headers, b""))).assess("https://example.com")
    assert not result.findings and result.not_checked


@pytest.mark.parametrize("status", [301, 302, 401, 403, 404, 429, 500])
def test_website_errors_not_treated_as_audit(status):
    client = QueueHTTP(HttpResponse(status, {"location": "https://private.example"}, b""))
    result = WebsiteAudit(client).assess("https://example.com")
    assert not result.findings and any(str(status) in x for x in result.not_checked)
    assert len(client.calls) == 1


@pytest.mark.parametrize("url", ["http://example.com", "https://github.com/owner/repo"])
def test_website_invalid_targets(url):
    with pytest.raises(ValidationError):
        WebsiteAudit(QueueHTTP()).assess(url)


def test_website_invalid_header_values():
    result = WebsiteAudit(
        QueueHTTP(
            HttpResponse(
                200,
                {"strict-transport-security": "max-age=0", "x-content-type-options": "wrong"},
                b"",
            )
        )
    ).assess("https://example.com")
    assert {"weak_hsts", "invalid_nosniff"} <= {f.check for f in result.findings}


def blob(source):
    raw = source.encode()
    digest = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return {"path": "code.py", "mode": "100644", "type": "blob", "size": len(raw), "sha": digest}, {
        "encoding": "base64",
        "content": base64.b64encode(raw).decode(),
    }


def repository(*entries, truncated=False):
    return [
        {"default_branch": "main"},
        {"sha": "a" * 40},
        {"tree": list(entries), "truncated": truncated},
    ]


def test_github_immutable_review_no_execution(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "fixture-token")
    item, data = blob("eval(untrusted)\n")
    client = QueueHTTP(*repository(item), data)
    result = GithubAudit(client).assess("https://github.com/owner/repo.git")
    assert result.findings[0].check == "PY001"
    assert "a" * 40 in result.not_checked[0]
    assert all("api.github.com/repos/owner/repo" in url for url, _ in client.calls)
    assert all(
        call[1]["headers"]["Authorization"] == "Bearer fixture-token" for call in client.calls
    )
    assert not data.get("executed")


def test_github_filters_paths_limits_and_truncation():
    item, data = blob("x=1\n")
    skipped = [
        dict(item, path="/outside.py"),
        dict(item, path="../outside.py"),
        dict(item, path="node_modules/unsafe.py"),
        dict(item, mode="120000"),
        dict(item, path="large.py", size=300000),
        dict(item, path="readme.md"),
    ]
    client = QueueHTTP(
        *repository(*skipped, item, dict(item, path="other.py"), truncated=True), data
    )
    result = GithubAudit(client, max_files=1).assess("https://github.com/o/r")
    assert len(client.calls) == 4
    assert any("truncated" in x for x in result.not_checked)
    assert any("limit" in x for x in result.not_checked)
    assert any("oversized" in x for x in result.not_checked)


@pytest.mark.parametrize("response", [{}, {"default_branch": ""}])
def test_github_missing_branch(response):
    with pytest.raises(ProviderError):
        GithubAudit(QueueHTTP(response)).assess("https://github.com/o/r")


@pytest.mark.parametrize("size", [0, 10001])
def test_github_file_limit_validation(size):
    with pytest.raises(ValidationError):
        GithubAudit(QueueHTTP(), max_files=size)


@pytest.mark.parametrize(
    "responses",
    [
        [{"default_branch": "main"}, {"sha": "bad"}],
        [{"default_branch": "main"}, {"sha": "a" * 40}, {}],
    ],
)
def test_github_bad_commit_tree(responses):
    with pytest.raises(ProviderError):
        GithubAudit(QueueHTTP(*responses)).assess("https://github.com/o/r")


@pytest.mark.parametrize(
    "change",
    [
        {"encoding": "raw"},
        {"content": "!bad!"},
        {"content": base64.b64encode(b"wrong").decode()},
        {"content": None},
    ],
)
def test_github_bad_blob(change):
    item, data = blob("eval(x)")
    data.update(change)
    with pytest.raises(ProviderError):
        GithubAudit(QueueHTTP(*repository(item), data)).assess("https://github.com/o/r")


def test_github_bad_sha_and_invalid_python():
    item, data = blob("def broken(")
    result = GithubAudit(QueueHTTP(*repository(item), data)).assess("https://github.com/o/r")
    assert any("parse" in x for x in result.not_checked)
    item["sha"] = "bad"
    with pytest.raises(ProviderError):
        GithubAudit(QueueHTTP(*repository(item))).assess("https://github.com/o/r")


def test_github_nonutf8_blob():
    raw = b"\xff"
    sha = hashlib.sha1(b"blob 1\0" + raw).hexdigest()
    item = {"path": "code.py", "mode": "100644", "type": "blob", "size": 1, "sha": sha}
    client = QueueHTTP(*repository(item), {"encoding": "base64", "content": "/w=="})
    assert any(
        "non-UTF-8" in s for s in GithubAudit(client).assess("https://github.com/o/r").not_checked
    )


class DNS:
    def __init__(self, records=None, status=0):
        self.records, self.status = records or {}, status
        self.calls = []

    def request(self, url, **kwargs):
        name = parse_qs(urlsplit(url).query)["name"][0]
        self.calls.append(name)
        return HttpResponse(
            200,
            {},
            json.dumps(
                {
                    "Status": self.status,
                    "Answer": [
                        {"name": name + ".", "type": 16, "data": value}
                        for value in self.records.get(name, [])
                    ],
                }
            ).encode(),
        )


def test_dns_good_and_weak_policies():
    good = DNS(
        {
            "example.com": ['"v=spf1 -all"'],
            "_dmarc.example.com": ['"v=DMARC1; p=reject"'],
            "sel._domainkey.example.com": ['"v=DKIM1; p=abc"'],
        }
    )
    result = MailDomainAudit(good, selector="sel").assess("mail-domain:example.com")
    assert not result.findings and len(good.calls) == 3
    weak = DNS({"example.com": ['"v=spf1 +all"'], "_dmarc.example.com": ['"v=DMARC1; p=none"']})
    result = MailDomainAudit(weak).assess("mail-domain:example.com")
    assert {f.check for f in result.findings} == {"weak_spf", "monitoring_dmarc"}
    assert any("not checked" in x for x in result.not_checked)


def test_dns_missing_duplicate_and_empty_dkim():
    result = MailDomainAudit(DNS(), selector="sel").assess("mail-domain:example.com")
    assert len(result.findings) == 3
    result = MailDomainAudit(DNS({"example.com": ['"v=spf1 -all"'] * 2})).assess(
        "mail-domain:example.com"
    )
    assert result.findings[0].check == "spf_record_count"


@pytest.mark.parametrize("status", [1, 2, 5, None])
def test_dns_failure_is_not_missing_policy(status):
    with pytest.raises(ProviderError):
        MailDomainAudit(DNS(status=status)).assess("mail-domain:example.com")


@pytest.mark.parametrize("selector", ["bad.name", "../evil", "x" * 64, ""])
def test_selector_validation(selector):
    with pytest.raises(ValidationError):
        MailDomainAudit(DNS(), selector=selector)


def test_dns_ignores_other_names_and_catches_malformed_txt():
    client = QueueHTTP(
        {"Status": 0, "Answer": [{"name": "other.example", "type": 16, "data": '"x"'}]},
        {"Status": 3},
    )
    assert len(MailDomainAudit(client).assess("mail-domain:example.com").findings) == 2
    client = QueueHTTP(
        {"Status": 0, "Answer": [{"name": "example.com", "type": 16, "data": '"unterminated'}]}
    )
    with pytest.raises(ProviderError):
        MailDomainAudit(client).assess("mail-domain:example.com")


def test_gmail_account_binding_and_settings(monkeypatch):
    monkeypatch.setenv("GMAIL_ACCESS_TOKEN", "fake-token")
    client = QueueHTTP(
        {"emailAddress": "user@example.com"},
        {"enabled": True},
        {"filter": [{"action": {"forward": "PRIVATE_ADDRESS"}}]},
    )
    result = GmailAudit(client).assess("mailbox:user@example.com")
    assert {f.check for f in result.findings} == {
        "mailbox_auto_forwarding",
        "mailbox_filter_forwarding",
    }
    assert "PRIVATE_ADDRESS" not in str(result)
    assert len(client.calls) == 3
    client = QueueHTTP({"emailAddress": "someone@example.com"})
    with pytest.raises(ProviderError, match="does not match"):
        GmailAudit(client).assess("mailbox:user@example.com")
    assert len(client.calls) == 1


def test_gmail_empty_and_invalid_settings(monkeypatch):
    monkeypatch.setenv("GMAIL_ACCESS_TOKEN", "fixture")
    client = QueueHTTP({"emailAddress": "user@example.com"}, {"enabled": False}, {})
    assert not GmailAudit(client).assess("mailbox:user@example.com").findings
    client = QueueHTTP({"emailAddress": "user@example.com"}, {}, {})
    with pytest.raises(ProviderError):
        GmailAudit(client).assess("mailbox:user@example.com")
    monkeypatch.delenv("GMAIL_ACCESS_TOKEN")
    with pytest.raises(ProviderError, match="missing"):
        GmailAudit(QueueHTTP()).assess("mailbox:user@example.com")


@pytest.mark.parametrize(
    "adapter,target",
    [
        (GithubAudit, "https://example.com"),
        (GithubAudit, "https://github.com/o%2fr/r"),
        (MailDomainAudit, "https://example.com"),
        (GmailAudit, "https://example.com"),
    ],
)
def test_adapter_target_validation(adapter, target):
    with pytest.raises(ValidationError):
        adapter(QueueHTTP()).assess(target)
