import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from ai_threat_lab.ai_costs import (
    AIConfig,
    BudgetedAI,
    CostLedger,
    OpenAIResponses,
    compact_evidence,
    money,
)
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderError


@pytest.fixture
def config():
    # Deliberately synthetic prices, not a provider price list.
    return AIConfig("fixture-model", "2", "8", cache_ttl_seconds=60)


@pytest.fixture
def evidence():
    return {
        "target": "/private/target",
        "target_kind": "website",
        "status": "partial",
        "findings": [
            {
                "check": "missing_header",
                "status": "candidate",
                "evidence": "Absent",
                "recommendation": "Review configuration",
            }
        ],
        "not_checked": ["No authenticated audit"],
        "raw_source": "DO_NOT_UPLOAD",
    }


class Provider:
    calls = 0

    def respond(self, model, instructions, prompt, maximum):
        self.calls += 1
        assert model == "fixture-model"
        assert "untrusted" in instructions and "not_checked" in prompt
        assert maximum == 600
        assert "DO_NOT_UPLOAD" not in prompt and "/private/target" not in prompt
        return "Review this candidate; partial audit only.", 100, 20


@pytest.mark.parametrize(
    "value", [None, 1, True, "NaN", "Infinity", "-1", "0", "1e100", "0.0000000001", "garbage"]
)
def test_money_rejects_invalid_or_unbounded_values(value):
    with pytest.raises(ValidationError):
        money(value)


def test_money_and_rounding(config):
    assert money("0.01") == 10_000_000
    assert config.charge(100, 20) == 360_000
    assert replace(config, input_usd_per_million="0.000001").charge(1, 0) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"model": ""},
        {"namespace": ""},
        {"max_input_bytes": True},
        {"max_input_bytes": 255},
        {"max_input_bytes": 100001},
        {"max_output_tokens": 0},
        {"max_output_tokens": 4097},
        {"max_calls_per_day": 0},
        {"cache_ttl_seconds": -1},
        {"cache_ttl_seconds": 30 * 86400 + 1},
        {"input_usd_per_million": "0"},
        {"daily_budget_usd": "nope"},
    ],
)
def test_config_bounds(config, change):
    with pytest.raises(ValidationError):
        replace(config, **change)


@pytest.mark.parametrize(
    "document",
    [
        None,
        [],
        {},
        {"schema_version": True},
        {"schema_version": 2},
        {"schema_version": 1, "key": "SECRET"},
    ],
)
def test_config_schema(document):
    with pytest.raises(ValidationError):
        AIConfig.from_document(document)


def test_config_document_and_compaction(config, evidence):
    doc = {
        "schema_version": 1,
        "model": "fixture-model",
        "input_usd_per_million": "2",
        "output_usd_per_million": "8",
    }
    assert AIConfig.from_document(doc).model == config.model
    evidence["findings"] *= 3
    text = compact_evidence(evidence, 12000)
    assert len(json.loads(text)["findings"]) == 1
    assert "not_checked" in text and "DO_NOT_UPLOAD" not in text


@pytest.mark.parametrize("document", [None, {}, {"findings": [1]}, {"findings": "oops"}])
def test_compaction_invalid(document):
    with pytest.raises(ValidationError):
        compact_evidence(document, 100)


def test_input_limit_fails_without_truncating_limits(evidence):
    with pytest.raises(ValidationError, match="split"):
        compact_evidence(evidence, 10)


def test_dryrun_cache_restart_and_usage(config, evidence, tmp_path):
    db = tmp_path / "costs.sqlite"
    ledger, provider = CostLedger(db), Provider()
    ai = BudgetedAI(config, ledger, provider, clock=lambda: 1000)
    estimate = ai.explain(evidence, dry_run=True)
    assert estimate["network_called"] is False and provider.calls == 0
    assert ledger.report()["days"] == []
    first = ai.explain(evidence)
    assert first["status"] == "generated" and first["estimated_usd"] == "0.000360000"
    second = BudgetedAI(config, CostLedger(db), provider, clock=lambda: 1001).explain(evidence)
    assert second["status"] == "cached" and second["request_id"] == first["request_id"]
    assert provider.calls == 1
    report = ledger.report()["days"][0]
    assert report["cache_hits"] == 1 and report["calls"] == 1
    assert not ledger.report()["unconfirmed"]
    if os.name != "nt":
        assert db.stat().st_mode & 0o777 == 0o600
    db.unlink()  # All connections must be closed, including on Windows.


def test_cache_expiry_namespace_and_disabled_cache(config, evidence, tmp_path):
    ledger, provider = CostLedger(tmp_path / "cost.sqlite"), Provider()
    ai = BudgetedAI(config, ledger, provider, clock=lambda: 100)
    ai.explain(evidence)
    assert (
        BudgetedAI(config, ledger, provider, clock=lambda: 161).explain(evidence)["status"]
        == "generated"
    )
    BudgetedAI(replace(config, namespace="other"), ledger, provider).explain(evidence)
    plain = BudgetedAI(replace(config, cache_ttl_seconds=0), ledger, provider)
    plain.explain(evidence)
    plain.explain(evidence)
    assert provider.calls == 5
    with sqlite3.connect(ledger.path) as db:
        assert (
            db.execute("SELECT response FROM calls ORDER BY rowid DESC LIMIT 1").fetchone()[0]
            is None
        )


@pytest.mark.parametrize("change", [{"daily_budget_usd": "0.000001"}, {"max_calls_per_day": 1}])
def test_budget_prevents_provider_call(config, evidence, tmp_path, change):
    ledger, provider = CostLedger(tmp_path / "cost.sqlite"), Provider()
    config = replace(config, cache_ttl_seconds=0, **change)
    ai = BudgetedAI(config, ledger, provider)
    if config.max_calls_per_day == 1:
        ai.explain(evidence)
    previous = provider.calls
    with pytest.raises(ProviderError, match="budget"):
        ai.explain(evidence)
    assert provider.calls == previous


@pytest.mark.parametrize(
    "result",
    [
        TimeoutError("PRIVATE_KEY"),
        None,
        ("", 1, 1),
        ("x", True, 1),
        ("x", -1, 1),
        ("x", 1, "2"),
        ("x" * 131073, 1, 1),
    ],
)
def test_failures_retain_reservation_and_block_retries(config, evidence, tmp_path, result):
    class Broken:
        calls = 0

        def respond(self, *args):
            self.calls += 1
            if isinstance(result, Exception):
                raise result
            return result

    provider, ledger = Broken(), CostLedger(tmp_path / "cost.sqlite")
    ai = BudgetedAI(config, ledger, provider)
    with pytest.raises(ProviderError, match="reservation retained") as error:
        ai.explain(evidence)
    assert "PRIVATE_KEY" not in str(error.value)
    assert ledger.report()["days"][0]["unconfirmed_calls"] == 1
    with pytest.raises(ProviderError, match="pending"):
        ai.explain(evidence)
    assert provider.calls == 1
    identifier = ledger.report()["unconfirmed"][0]["id"]
    ledger.reconcile(identifier, "0")
    assert ledger.report()["days"][0]["charged_or_reserved_usd"] == "0.000000000"
    with pytest.raises(ValidationError):
        ledger.reconcile(identifier, "0")


def test_concurrent_reservations_are_atomic(config, tmp_path):
    ledger = CostLedger(tmp_path / "cost.sqlite")

    def reserve(index):
        try:
            return ledger.reserve("one-key", config, 1, 100)[0]
        except ProviderError:
            return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(reserve, range(8)))
    assert sum(item is not None for item in results) == 1
    assert ledger.report()["days"][0]["calls"] == 1


def test_excess_usage_recorded_before_error(config, evidence, tmp_path):
    class Excess:
        def respond(self, *args):
            return "Partial answer", 100, 601

    ledger = CostLedger(tmp_path / "cost.sqlite")
    with pytest.raises(ProviderError, match="exceeded"):
        BudgetedAI(config, ledger, Excess()).explain(evidence)
    assert ledger.report()["days"][0]["unconfirmed_calls"] == 0
    with pytest.raises(ProviderError):
        ledger.complete("missing", config, "text", 1, 1, 0)


def test_reconcile_positive_charge(config, tmp_path):
    ledger = CostLedger(tmp_path / "cost.sqlite")
    identifier, _ = ledger.reserve("a", config, 10000, 100)
    ledger.reconcile(identifier, "0.000001")
    assert ledger.report()["days"][0]["charged_or_reserved_usd"] == "0.000001000"


def test_symlink_ledger_rejected(tmp_path):
    target = tmp_path / "real"
    target.touch()
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ValidationError):
        CostLedger(link)


class API:
    def __init__(self, status=200, document=None):
        self.status = status
        self.document = document or {
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "Defensive summary"}],
                }
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        self.calls = []

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return HttpResponse(self.status, {}, json.dumps(self.document).encode())


def test_openai_wire_contract(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fake-key")
    api = API()
    assert OpenAIResponses(api).respond("fixture-model", "instructions", "evidence", 600) == (
        "Defensive summary",
        10,
        5,
    )
    url, request = api.calls[0]
    body = json.loads(request["body"])
    assert url == "https://api.openai.com/v1/responses" and request["method"] == "POST"
    assert body["store"] is False and body["tools"] == [] and body["max_output_tokens"] == 600
    assert body["truncation"] == "disabled" and "previous_response_id" not in body


@pytest.mark.parametrize(
    "status,document",
    [
        (401, {}),
        (429, {}),
        (500, {}),
        (200, {"status": "incomplete"}),
        (200, {"status": "completed", "output": []}),
    ],
)
def test_openai_failure_responses(monkeypatch, status, document):
    monkeypatch.setenv("OPENAI_API_KEY", "SECRET")
    with pytest.raises(ProviderError):
        OpenAIResponses(API(status, document)).respond("m", "i", "p", 50)


def test_missing_key_does_not_call_network(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    api = API()
    with pytest.raises(ProviderError, match="missing"):
        OpenAIResponses(api).respond("m", "i", "p", 50)
    assert not api.calls
