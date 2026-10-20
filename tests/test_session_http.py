import json
from datetime import datetime, timedelta, timezone

import pytest

from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError
from ai_threat_lab.session_http import ScopedSession
from ai_threat_lab.site_review import SiteReview

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


def saved(tmp_path, **changes):
    value = {
        "schema_version": 1, "host": "app.example", "path_prefix": "/app/",
        "expires_at": (NOW + timedelta(hours=1)).isoformat(),
        "headers": {"Authorization": "Bearer PRIVATE-TOKEN", "Cookie": "session=PRIVATE-COOKIE"},
        **changes,
    }
    path = tmp_path / "session.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


class Wire:
    def __init__(self, status=200):
        self.calls = []
        self.status = status

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        body = (b'<a href="/app/next">next</a><a href="/outside">outside</a>'
                b'<a href="https://other.example/app/">other</a>'
                b'<a href="https://app.example.evil/app/">suffix</a>')
        return HttpResponse(self.status, {"content-type": "text/html"}, body)


def load(path, wire, **changes):
    return ScopedSession.from_file(path, wire, target="https://app.example/app/",
                                   path_prefix="/app/", clock=lambda: NOW, **changes)


def test_session_scope_and_report_redaction(tmp_path):
    wire = Wire()
    session = load(saved(tmp_path), wire)
    report, failures = SiteReview(session, session_supplied=True).run(
        "https://app.example/app/", path_prefix="/app/")
    assert failures == 0 and len(wire.calls) == 2
    assert all(url.startswith("https://app.example/app/") for url, _ in wire.calls)
    assert all(kwargs["headers"]["Cookie"] == "session=PRIVATE-COOKIE"
               for _, kwargs in wire.calls)
    text = json.dumps(report)
    assert "PRIVATE" not in text
    assert "Operator-supplied static session" in text
    assert "no login, cookies" not in text


@pytest.mark.parametrize("change", [
    {"schema_version": True}, {"host": "other.example"}, {"path_prefix": "/"},
    {"headers": {}}, {"headers": []}, {"headers": {"Host": "other.example"}},
    {"headers": {"Cookie": "ok\r\nHost: other.example"}},
    {"headers": {"Authorization": "token\tvalue"}}, {"headers": {"Cookie": " "}},
    {"headers": {"Cookie": "\u00e9"}}, {"headers": {"Cookie": "a" * 8193}},
    {"expires_at": "not-a-date"}, {"expires_at": "2030-01-01T01:00:00"},
    {"expires_at": NOW.isoformat()},
    {"expires_at": (NOW + timedelta(hours=25)).isoformat()},
])
def test_invalid_session_never_calls_or_echoes_values(tmp_path, change):
    wire = Wire()
    with pytest.raises(ValidationError) as error:
        load(saved(tmp_path, **change), wire)
    assert not wire.calls and "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("target", [
    "https://other.example/app/", "https://app.example/outside",
    "https://app.example/appx/", "https://app.example/app/../outside",
    "https://app.example/app/?secret=PRIVATE", "http://app.example/app/",
])
def test_transport_independently_rejects_scope_escape(tmp_path, target):
    wire = Wire()
    session = load(saved(tmp_path), wire)
    with pytest.raises((ValidationError, ProviderError)):
        session.request(target)
    assert not wire.calls


def test_expiry_rechecked_before_each_request(tmp_path):
    wire = Wire()
    clock = [NOW]
    session = ScopedSession.from_file(saved(tmp_path), wire, target="https://app.example/app/",
                                      path_prefix="/app/", clock=lambda: clock[0])
    session.request("https://app.example/app/")
    clock[0] += timedelta(hours=1)
    with pytest.raises(ProviderError):
        session.request("https://app.example/app/next")
    assert len(wire.calls) == 1


@pytest.mark.parametrize("status", [401, 403])
def test_access_denial_stops_further_requests(tmp_path, status):
    wire = Wire(status)
    session = load(saved(tmp_path), wire)
    for _ in range(2):
        with pytest.raises(ProviderError):
            session.request("https://app.example/app/")
    assert len(wire.calls) == 1


def test_cli_requires_network_and_exact_host(tmp_path, monkeypatch, capsys):
    import ai_threat_lab.http_client as http
    from ai_threat_lab.cli import main
    path = saved(tmp_path, expires_at=(
        datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
    wire = Wire()
    monkeypatch.setattr(http, "PublicHTTPS", lambda *a, **k: wire)
    args = ["review-site", "https://app.example/app/", "--path-prefix", "/app/",
            "--session-file", str(path)]
    assert main(args) == 2
    assert not wire.calls
    assert main([*args, "--network", "--allow-host", "app.example"]) == 0
    assert len(wire.calls) == 2
    assert "PRIVATE" not in capsys.readouterr().out


def test_session_file_byte_bound(tmp_path):
    path = tmp_path / "large.json"
    path.write_bytes(b"x" * (16 * 1024 + 1))
    with pytest.raises(ValidationError):
        load(path, Wire())


def test_denied_session_is_explicit_in_report(tmp_path):
    session = load(saved(tmp_path), Wire(401))
    report, failures = SiteReview(session, session_supplied=True).run(
        "https://app.example/app/", path_prefix="/app/")
    assert failures == 1
    assert "HTTP 401/403" in json.dumps(report)
    assert "PRIVATE" not in json.dumps(report)


def test_console_session_refusal_without_opening_credentials(monkeypatch):
    from ai_threat_lab.cli import main
    answers = iter(["14", "https://app.example/app/", "/app/",
                    "missing.session.json", "new-report.json", "new.paths.private.json", "n", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert main(["console"]) == 0


def test_reflected_secret_url_stays_only_in_explicit_private_map(tmp_path, monkeypatch, capsys):
    import ai_threat_lab.http_client as http
    from ai_threat_lab.cli import main
    from ai_threat_lab.evidence import load_evidence

    path = saved(tmp_path, expires_at=(
        datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
    wire = Wire()
    monkeypatch.setattr(http, "PublicHTTPS", lambda *a, **k: wire)
    output, mapping = tmp_path / "report.json", tmp_path / "pages.paths.private.json"
    args = ["review-site", "https://app.example/app/PRIVATE-TOKEN", "--path-prefix", "/app/",
            "--session-file", str(path), "--network", "--allow-host", "app.example",
            "--private-path-map", str(mapping), "--output", str(output)]
    assert main(args) == 0
    assert "PRIVATE" not in output.read_text() and "app.example" not in output.read_text()
    assert "PRIVATE-TOKEN" in mapping.read_text()
    assert "PRIVATE" not in json.dumps(load_evidence(output))
    with pytest.raises(ValidationError):
        load_evidence(mapping)
    assert "PRIVATE" not in capsys.readouterr().out
    count = len(wire.calls)
    output.unlink()
    assert main(args) == 2  # Existing private map is rejected before another request.
    assert len(wire.calls) == count
