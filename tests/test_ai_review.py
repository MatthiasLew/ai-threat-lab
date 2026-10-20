"""Model advice must reference supplied evidence and never become executable work."""

import copy
import json
import sqlite3
from contextlib import closing
from dataclasses import asdict

import pytest

import ai_threat_lab.integration_cli as integration
from ai_threat_lab.ai_costs import AIConfig, CostLedger
from ai_threat_lab.ai_review import TEXT_FORMAT, review_result, validate_review
from ai_threat_lab.audit_report import merge_reports
from ai_threat_lab.cli import main
from ai_threat_lab.contracts import write_document
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError


def report():
    return merge_reports([{
        "target": "private/source.py", "target_kind": "python_source", "status": "partial",
        "findings": [{"check": "PY001", "status": "candidate", "evidence": "line 1",
                      "recommendation": "Review inputs"}], "not_checked": ["No execution"],
    }])


def reply(identifier):
    return {"summary": "Review the reported candidate.", "observations": [{
        "evidence_id": identifier, "explanation": "Dynamic evaluation was observed.",
        "what_to_review": "Check the source and trust boundary.",
        "suggested_remediation": "Prefer a parser for the required input format.",
    }], "uncertainty": "Input provenance and runtime behavior remain unverified."}


class Wire:
    def __init__(self, alter=None, status="completed"):
        self.calls = []
        self.alter, self.status = alter, status

    def request(self, url, **kwargs):
        payload = json.loads(kwargs["body"])
        self.calls.append((url, payload))
        evidence = json.loads(payload["input"])
        response = reply(evidence["findings"][0]["evidence_id"])
        if self.alter:
            self.alter(response)
        body = {"status": self.status, "output": [{"type": "message", "content": [
            {"type": "output_text", "text": json.dumps(response)}]}],
            "usage": {"input_tokens": 100, "output_tokens": 200}}
        return HttpResponse(200, {}, json.dumps(body).encode())


def config():
    return AIConfig("fixture-model", "2", "8", cache_ttl_seconds=60)


def test_structured_wire_and_cache_are_separate_from_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-key")
    original = report()
    before = copy.deepcopy(original)
    ledger = CostLedger(tmp_path / "cost.sqlite")
    wire = Wire()
    result = review_result(config(), ledger, wire, original)
    assert original == before
    observed = result["interpretation"]["observations"][0]["evidence_id"]
    assert observed == original["findings"][0]["id"]
    assert result["not_checked"] == original["not_checked"]
    assert "unverified" in result["notice"]
    url, payload = wire.calls[0]
    assert url == "https://api.openai.com/v1/responses"
    assert payload["tools"] == [] and payload["store"] is False
    assert payload["text"]["format"] == TEXT_FORMAT
    assert "private/source.py" not in payload["input"]
    assert review_result(config(), ledger, wire, original)["status"] == "cached"
    assert len(wire.calls) == 1


@pytest.mark.parametrize("alter", [
    lambda r: r.update(commands=["anything"]),
    lambda r: r.update(summary=""),
    lambda r: r.update(uncertainty=False),
    lambda r: r.update(observations=[]),
    lambda r: r["observations"].append(copy.deepcopy(r["observations"][0])),
    lambda r: r["observations"][0].update(evidence_id="a" * 64),
    lambda r: r["observations"][0].update(suggested_remediation=""),
    lambda r: r["observations"][0].update(explanation="x" * 8001),
])
def test_invalid_advice_records_cost_without_caching_or_retry(tmp_path, monkeypatch, alter):
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-key")
    ledger = CostLedger(tmp_path / "cost.sqlite")
    wire = Wire(alter)
    with pytest.raises(ProviderError, match="usage recorded, cache disabled"):
        review_result(config(), ledger, wire, report())
    assert len(wire.calls) == 1
    with closing(sqlite3.connect(ledger.path)) as db:
        row = db.execute("SELECT state,input_tokens,output_tokens,response FROM calls").fetchone()
    assert row == ("completed", 100, 200, None)


def test_incomplete_provider_response_preserves_pending_reservation(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-key")
    ledger = CostLedger(tmp_path / "cost.sqlite")
    wire = Wire(status="incomplete")
    with pytest.raises(ProviderError, match="reservation retained"):
        review_result(config(), ledger, wire, report())
    assert len(wire.calls) == 1
    with closing(sqlite3.connect(ledger.path)) as db:
        assert db.execute("SELECT state FROM calls").fetchone() == ("pending",)


def test_dry_run_needs_no_key_client_or_database(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = review_result(config(), None, None, report(), dry_run=True)
    assert result["status"] == "estimate_only"
    assert result["network_called"] is False


@pytest.mark.parametrize("text", ['[]', '{"summary":1,"summary":2}', '{}', 'null', 'x' * 131073],
                         ids=["array", "duplicate", "empty", "null", "oversize"])
def test_invalid_response_boundaries(text):
    with pytest.raises(ValidationError):
        validate_review(text, {"a" * 64})


def test_duplicate_reference_in_correct_length_response_is_rejected():
    value = reply("a" * 64)
    value["observations"].append(copy.deepcopy(value["observations"][0]))
    with pytest.raises(ValidationError, match="repeated"):
        validate_review(json.dumps(value), {"a" * 64, "b" * 64})


def test_cli_dry_run_preflight_and_output_claim(tmp_path, monkeypatch, capsys):
    source, settings = tmp_path / "report.json", tmp_path / "config.json"
    output, ledger = tmp_path / "review.json", tmp_path / "cost.sqlite"
    write_document(report(), source)
    write_document({"schema_version": 1, **asdict(config())}, settings)
    args = ["ai-review", str(source), "--ai-config", str(settings), "--ledger", str(ledger)]
    assert main(args) == 2
    assert not ledger.exists()
    assert main(args + ["--dry-run"]) == 0
    estimate = json.loads(capsys.readouterr().out)
    assert estimate["status"] == "estimate_only" and not ledger.exists()
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert main(args + ["--send-evidence"]) == 3
    assert not ledger.exists()
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-key")
    wire = Wire()
    monkeypatch.setattr(integration, "PublicHTTPS", lambda *a, **kw: wire)
    assert main(args + ["--send-evidence", "--output", str(output)]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["mode"] == "advisory_interpretation"
    assert main(args + ["--send-evidence", "--output", str(output)]) == 2
    assert len(wire.calls) == 1
