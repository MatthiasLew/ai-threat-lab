"""Hash-only reputation contract and privacy controls using a synthetic wire."""

import copy
import json
from datetime import datetime, timezone

import pytest

from ai_threat_lab.file_reputation import HOST, STATS, capture, preview, review
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError

NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)
RAW = b"inert PRIVATE fixture"
DIGEST = preview(RAW)["sha256"]


def document():
    return {"data": {"type": "file", "id": DIGEST, "attributes": {
        "sha256": DIGEST, "size": len(RAW), "last_analysis_date": int(NOW.timestamp()) - 300,
        "last_analysis_stats": {key: int(key == "undetected") for key in STATS},
        "names": ["PRIVATE"], "last_analysis_results": {"PRIVATE": "PRIVATE"},
    }}}


class Wire:
    def __init__(self, doc=None, status=200):
        self.doc = document() if doc is None else doc
        self.status, self.calls = status, []

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return HttpResponse(self.status, {}, json.dumps(self.doc).encode())


def run(monkeypatch, wire, **kwargs):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "PRIVATE")
    options = dict(expected_sha256=DIGEST, network=True, share_hash=True,
                   allowed_host=HOST, client=wire, now=NOW)
    options.update(kwargs)
    return review(RAW, **options)


def test_exact_wire_and_minimal_historical_evidence(monkeypatch):
    wire = Wire()
    result, failed = run(monkeypatch, wire)
    assert not failed and result.status == "partial"
    assert wire.calls == [(f"https://{HOST}/api/v3/files/{DIGEST}",
                           {"headers": {"x-apikey": "PRIVATE"}})]
    assert "PRIVATE" not in repr(result)
    finding = result.findings[-1]
    assert finding.check == "file_reputation_counts" and finding.status == "unverified"
    assert "undetected=1" in finding.evidence and "last_analysis_utc=" in finding.evidence
    assert any("does not establish safety" in gap for gap in result.not_checked)


@pytest.mark.parametrize("options", [
    {"network": False}, {"network": 1}, {"share_hash": False},
    {"allowed_host": "other.invalid"}, {"expected_sha256": "a" * 64},
    {"expected_sha256": DIGEST.upper()}, {"expected_sha256": None},
    {"now": NOW.replace(tzinfo=None)}, {"now": "PRIVATE"},
])
def test_preflight_before_key_and_wire(monkeypatch, options):
    wire = Wire()
    with pytest.raises(ValidationError):
        run(monkeypatch, wire, **options)
    assert not wire.calls


@pytest.mark.parametrize("key", ["", "PRIVATE\n", "x" * 513, "á", "a b"])
def test_missing_or_invalid_key_no_request(monkeypatch, key):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", key)
    wire = Wire()
    with pytest.raises(ProviderError, match="no request"):
        review(RAW, expected_sha256=DIGEST, network=True, share_hash=True,
               allowed_host=HOST, client=wire, now=NOW)
    assert not wire.calls


@pytest.mark.parametrize("status", [301, 401, 403, 429, 500])
def test_failure_preserves_local_without_provider_echo_or_retry(monkeypatch, status):
    wire = Wire({"PRIVATE": "PRIVATE"}, status)
    result, failed = run(monkeypatch, wire)
    assert failed and len(wire.calls) == 1
    assert result.findings[0].check == "binary_metadata"
    assert "PRIVATE" not in repr(result)


def test_missing_record_is_unknown_not_clean(monkeypatch):
    result, failed = run(monkeypatch, Wire(status=404))
    assert not failed and result.status == "partial"
    assert not any(f.check == "file_reputation_counts" for f in result.findings)
    assert any("reputation unknown" in gap for gap in result.not_checked)


@pytest.mark.parametrize("field,value", [
    ("sha256", "a" * 64), ("size", True), ("size", 0),
    ("last_analysis_date", True), ("last_analysis_date", 0),
    ("last_analysis_date", int(NOW.timestamp()) + 301),
    ("last_analysis_stats", {}), ("last_analysis_stats", []),
    ("last_analysis_stats", {key: False for key in STATS}),
    ("last_analysis_stats", {key: 10001 for key in STATS}),
    ("last_analysis_stats", {key: 0 for key in STATS}),
])
def test_mismatched_or_invalid_provider_metadata_is_not_a_result(monkeypatch, field, value):
    doc = document()
    doc["data"]["attributes"][field] = value
    result, failed = run(monkeypatch, Wire(doc))
    assert failed and len(result.findings) == 1


@pytest.mark.parametrize("doc", [{}, {"data": None}, {"data": []}, {"data": {"type": "url"}}])
def test_malformed_envelope(monkeypatch, doc):
    assert run(monkeypatch, Wire(copy.deepcopy(doc)))[1]


def test_capture_bound_preview_offline(tmp_path, monkeypatch):
    path = tmp_path / "PRIVATE.bin"
    path.write_bytes(RAW)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    value = preview(capture(path))
    assert not value["network_called"] and not value["credentials_inspected"]
    assert "PRIVATE" not in json.dumps(value)
    with pytest.raises(ValidationError):
        preview("PRIVATE")
    path.write_bytes(b"x" * (16 * 1024 * 1024 + 1))
    with pytest.raises(ValidationError, match="16 MiB"):
        capture(path)


def test_transport_and_json_failure_are_redacted(monkeypatch):
    class Broken:
        def request(self, *args, **kwargs):
            raise ProviderError("PRIVATE")
    assert run(monkeypatch, Broken())[1]
    class BadJSON:
        def request(self, *args, **kwargs):
            return HttpResponse(200, {}, b"PRIVATE")
    result, failed = run(monkeypatch, BadJSON())
    assert failed and "PRIVATE" not in repr(result)


def test_cli_saved_report_survives_source_and_no_paid_call_on_occupied_output(
    tmp_path, monkeypatch, capsys,
):
    from ai_threat_lab import reputation_cli
    from ai_threat_lab.cli import main
    from ai_threat_lab.evidence import load_evidence

    source, output = tmp_path / "PRIVATE.bin", tmp_path / "report.json"
    source.write_bytes(RAW)
    wire = Wire()
    monkeypatch.setattr(reputation_cli, "PublicHTTPS", lambda *a, **kw: wire)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "PRIVATE")
    assert main(["reputation-preview", str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["sha256"] == DIGEST
    args = ["review-reputation", str(source), "--output", str(output),
            "--network", "--share-hash", "--allow-host", HOST, "--sha256", DIGEST]
    assert main(args) == 0 and len(wire.calls) == 1
    assert main(args) == 2 and len(wire.calls) == 1
    source.unlink()
    evidence = load_evidence(output)
    assert any(f["check"] == "file_reputation_counts" for f in evidence["report"]["findings"])
    assert "PRIVATE" not in output.read_text()


def test_cli_preflight_and_missing_key_cleanup(tmp_path, monkeypatch, capsys):
    from ai_threat_lab import reputation_cli
    from ai_threat_lab.cli import main

    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    source, output = tmp_path / "file", tmp_path / "report.json"
    source.write_bytes(RAW)
    wire = Wire()
    monkeypatch.setattr(reputation_cli, "PublicHTTPS", lambda *a, **kw: wire)
    args = ["review-reputation", str(source), "--output", str(output),
            "--allow-host", HOST, "--sha256", DIGEST]
    assert main(args) == 2
    assert main([*args, "--network", "--share-hash"]) != 0
    assert not output.exists() and not wire.calls
    assert "PRIVATE" not in capsys.readouterr().err


@pytest.mark.parametrize("answers,command", [
    (["0"], None), (["9"], None),
    (["1", "file.bin", "preview.json"], "reputation-preview"),
    (["2", "file.bin", "result.json", DIGEST, "n"], None),
    (["2", "file.bin", "result.json", DIGEST, "y"], "review-reputation"),
])
def test_menu_consent_and_exact_arguments(answers, command):
    from ai_threat_lab.reputation_cli import reputation_menu

    responses, calls = iter(answers), []
    assert reputation_menu(lambda args: calls.append(args) or 0,
                           lambda *a, **kw: next(responses)) == 0
    if command is None:
        assert not calls
    else:
        assert calls[0][0] == command
        if command == "review-reputation":
            assert calls[0] == [
                command, "file.bin", "--output", "result.json", "--sha256", DIGEST,
                "--network", "--share-hash", "--allow-host", HOST,
            ]


def test_claim_cleanup_on_failed_write(tmp_path):
    from ai_threat_lab.reputation_cli import claimed_output

    output = tmp_path / "new.json"
    with pytest.raises(RuntimeError):
        with claimed_output(output) as stream:
            stream.write("partial")
            raise RuntimeError("fixture failure")
    assert not output.exists()


@pytest.mark.parametrize("field,value", [("type", "url"), ("id", "a" * 64)])
def test_provider_identity_must_match(monkeypatch, field, value):
    doc = document()
    doc["data"][field] = value
    assert run(monkeypatch, Wire(doc))[1]
