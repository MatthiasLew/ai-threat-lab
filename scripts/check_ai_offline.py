"""Installed-package AI cost acceptance with a synthetic transport and blocked sockets."""

import json
import os
import socket
from dataclasses import asdict
from pathlib import Path

from ai_threat_lab.ai_costs import AIConfig, BudgetedAI, CostLedger, OpenAIResponses
from ai_threat_lab.http_client import HttpResponse
from ai_threat_lab.providers import ProviderError


def blocked(*args, **kwargs):
    raise AssertionError("Offline acceptance must not contact a provider")


def main():
    socket.create_connection = blocked
    socket.getaddrinfo = blocked
    # Only an in-memory synthetic credential is used by the fake transport below.
    os.environ["OPENAI_API_KEY"] = "offline-fixture-not-a-real-key"
    config = AIConfig("offline-fixture", "2", "8", cache_ttl_seconds=60)
    document = {
        "target": "PRIVATE-TARGET",
        "target_kind": "website",
        "status": "partial",
        "findings": [
            {
                "check": "fixture",
                "status": "candidate",
                "evidence": "Absent",
                "recommendation": "Review the controlled fixture",
            }
        ],
        "not_checked": ["Synthetic acceptance only"],
        "raw_source": "PRIVATE-SOURCE",
    }

    class Transport:
        calls = 0
        fail = False

        def request(self, url, **kwargs):
            self.calls += 1
            if self.fail:
                raise TimeoutError("PRIVATE-ERROR")
            request = json.loads(kwargs["body"])
            assert url == "https://api.openai.com/v1/responses"
            assert request["store"] is False and request["tools"] == []
            assert "PRIVATE" not in request["input"]
            return HttpResponse(
                200,
                {},
                json.dumps(
                    {
                        "status": "completed",
                        "output": [
                            {
                                "type": "message",
                                "content": [
                                    {"type": "output_text", "text": "Partial synthetic explanation"}
                                ],
                            }
                        ],
                        "usage": {"input_tokens": 100, "output_tokens": 20},
                    }
                ).encode(),
            )

    transport, clock = Transport(), [100]
    ledger = CostLedger(Path("installed AI costs.sqlite"))
    ai = BudgetedAI(config, ledger, OpenAIResponses(transport), clock=lambda: clock[0])
    assert ai.explain(document, dry_run=True)["network_called"] is False
    assert transport.calls == 0 and not ledger.report()["days"]
    assert ai.explain(document)["status"] == "generated"
    assert ai.explain(document)["status"] == "cached" and transport.calls == 1
    before = ledger.report()["days"][0]["charged_or_reserved_usd"]
    clock[0] = 160
    assert ledger.prune_cache(clock=lambda: clock[0])["cleared_responses"] == 1
    assert ledger.report()["days"][0]["charged_or_reserved_usd"] == before
    transport.fail = True
    try:
        ai.explain(document)
    except ProviderError:
        pass
    else:
        raise AssertionError("Uncertain response must fail")
    identifier = ledger.report()["unconfirmed"][0]["id"]
    calls = transport.calls
    try:
        ai.explain(document)
    except ProviderError:
        pass
    else:
        raise AssertionError("Pending request must block retry")
    assert transport.calls == calls
    ledger.reconcile(identifier, "0")
    transport.fail = False
    assert ai.explain(document)["status"] == "generated"
    assert ledger.prune_cache(all_entries=True)["cleared_responses"] == 1
    assert not ledger.report()["unconfirmed"]
    Path("installed-ai-config.json").write_text(json.dumps({"schema_version": 1, **asdict(config)}))
    Path("installed-ai-costs-result.json").write_text(json.dumps(ledger.report()))
    print("Installed offline AI: estimate/cache/expiry/unknown/reconcile/accounting passed.")


if __name__ == "__main__":
    main()
