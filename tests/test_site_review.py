"""Passive multi-page acceptance: exact scope, bounded discovery and evidence reuse."""

import json

import pytest

import ai_threat_lab.http_client as http
from ai_threat_lab.cli import main
from ai_threat_lab.evidence import load_evidence
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError
from ai_threat_lab.site_review import SiteReview, canonical_url

ROOT = "https://site.example/app/"


def page(body="", *, status=200, body_status="complete", headers=None):
    items = headers or (("content-type", "text/html; charset=utf-8"),)
    return HttpResponse(status, dict(items), body.encode(), items, body_status)


class Wire:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def request(self, url):
        self.calls.append(url)
        value = self.pages[url]
        if isinstance(value, Exception):
            raise value
        return value


def notices(report):
    return " ".join(row["notice"] for row in report["not_checked"])


def test_breadth_first_same_scope_dedup_and_finding_provenance(tmp_path):
    wire = Wire({
        ROOT: page('<a href="one">1</a><a href="two#fragment">2</a>'
                   '<a href="one">again</a><a href="/outside">x</a>'
                   '<a href="https://other.example/app/">external</a>'
                   '<a href="secret?token=PRIVATE">query</a>'),
        ROOT + "one": page('<a href="./">root</a><form><input name="p" type="password"></form>'),
        ROOT + "two": page('<script src="http://other.example/script.js"></script>'),
    })
    report, failures = SiteReview(wire).run(ROOT, path_prefix="/app/")
    assert failures == 0
    assert wire.calls == [ROOT, ROOT + "one", ROOT + "two"]
    assert any(row["check"] == "html_password_form_get"
               and row["target"] == ROOT + "one" for row in report["findings"])
    assert "PRIVATE" not in json.dumps(report)
    path = tmp_path / "site.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    assert len(load_evidence(path)["report"]["assessments"]) == 3


@pytest.mark.parametrize("value", [
    "http://site.example/", "https://user:password@site.example/",
    "https://site.example:8443/", "https://site.example/?x=1",
    "https://site.example/%2e%2e/", "https://site.example/a/../b",
    "https://site.example/a\\b", "https://site.example/a\nb",
    "https://site.example//x", "https://site.example/ż", "",
])
def test_invalid_start(value):
    with pytest.raises(ValidationError):
        canonical_url(value)


@pytest.mark.parametrize("prefix", ["app/", "/app", "/other/", "/app/?x=1", "/app/#x", "//evil/"])
def test_scope_rejected_before_io(prefix):
    wire = Wire({})
    with pytest.raises(ValidationError):
        SiteReview(wire).run(ROOT, path_prefix=prefix)
    assert not wire.calls


@pytest.mark.parametrize("pages,depth", [(0, 1), (21, 1), (True, 1), (1, -1), (1, 6), (1, True)])
def test_invalid_budgets(pages, depth):
    with pytest.raises(ValidationError):
        SiteReview(None, max_pages=pages, max_depth=depth)


def test_page_and_depth_bounds_are_visible():
    body = '<a href="one">1</a><a href="two">2</a>'
    wire = Wire({ROOT: page(body), ROOT + "one": page(body)})
    report, _ = SiteReview(wire, max_pages=2).run(ROOT)
    assert wire.calls == [ROOT, ROOT + "one"]
    assert "Page limit reached" in notices(report)
    wire = Wire({ROOT: page(body)})
    report, _ = SiteReview(wire, max_depth=0).run(ROOT)
    assert wire.calls == [ROOT]
    assert "depth limit reached" in notices(report)


@pytest.mark.parametrize("response", [
    page('<a href="one">1</a>', status=302),
    page('<a href="one">1</a>', body_status="size_limit"),
    page('<a href="one">1</a>', headers=(("content-type", "text/plain"),)),
    page('<base href="/"><a href="one">1</a>'),
    page('<template><a href="one">1</a></template>'),
    page('<script>const t = \'<a href="one">1</a>\';</script>'),
    page('<a href="one" href="two">1</a>'),
    page('<a href="one" download>download</a>'),
    page('<a href="one\n">1</a>'),
    page('<plaintext><a href="one">1</a>'),
])
def test_unfollowed_documents_and_elements(response):
    wire = Wire({ROOT: response})
    SiteReview(wire).run(ROOT)
    assert wire.calls == [ROOT]


def test_partial_failure_keeps_other_evidence_and_redacts_error():
    wire = Wire({
        ROOT: page('<a href="one">1</a><a href="two">2</a>'),
        ROOT + "one": ProviderError("PRIVATE transport failure"),
        ROOT + "two": page(),
    })
    report, failures = SiteReview(wire).run(ROOT)
    assert failures == 1
    assert len(report["assessments"]) == 3
    assert report["assessments"][1]["status"] == "not_configured"
    assert "PRIVATE" not in json.dumps(report)
    assert "collection failed" in notices(report)


def test_cli_requires_scope_preserves_output_and_emits_usable_report(tmp_path, monkeypatch):
    wire = Wire({ROOT: page()})
    monkeypatch.setattr(http, "PublicHTTPS", lambda *a, **kw: wire)
    output = tmp_path / "report.json"
    base = ["review-site", ROOT, "--output", str(output)]
    assert main(base) == 2
    assert not wire.calls
    allowed = base + ["--network", "--allow-host", "site.example"]
    assert main(allowed + ["--fail-on-findings"]) == 1
    assert load_evidence(output)["report"]["assessments"][0]["target"] == ROOT
    assert main(allowed) == 2
    assert wire.calls == [ROOT]


def test_link_and_element_limits_are_bounded():
    wire = Wire({ROOT: page('<a href="one">1</a>' * 501)})
    report, _ = SiteReview(wire, max_pages=1).run(ROOT)
    assert "500-element bound" in notices(report)
    wire = Wire({ROOT: page('<b></b>' * 5001)})
    report, _ = SiteReview(wire).run(ROOT)
    assert "parser bounds" in notices(report)


@pytest.mark.parametrize("consent", ["y", "n"])
def test_console_site_consent(monkeypatch, consent):
    from ai_threat_lab.console import run_console

    inputs = iter(["9", ROOT, "/app/", "site.json", consent, "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    calls = []
    assert run_console(lambda args: calls.append(args) or 0) == 0
    assert calls == ([["review-site", ROOT, "--network", "--allow-host", "site.example",
                      "--path-prefix", "/app/", "--output", "site.json"]]
                     if consent == "y" else [])


def test_cli_failed_page_has_nonzero_status(monkeypatch, capsys):
    wire = Wire({ROOT: ProviderError("PRIVATE")})
    monkeypatch.setattr(http, "PublicHTTPS", lambda *a, **kw: wire)
    assert main(["review-site", ROOT, "--network", "--allow-host", "site.example"]) == 2
    assert json.loads(capsys.readouterr().out)["assessments"][0]["status"] == "not_configured"
