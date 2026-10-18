import json

import pytest

from ai_threat_lab.assessment import AssessmentFinding, AssessmentResult
from ai_threat_lab.campaigns import CampaignService, TrainingContent
from ai_threat_lab.cli import main
from ai_threat_lab.contracts import request_from_document, write_document
from ai_threat_lab.models import ValidationError
from ai_threat_lab.providers import ProviderConfig, ProviderError, ProviderRegistry
from ai_threat_lab.workflows import example_request


class FakeTarget:
    def assess(self, target):
        return AssessmentResult(
            target,
            "website",
            "partial",
            (AssessmentFinding("fixture", "candidate", "Synthetic evidence", "Review fixture"),),
            ("No network request performed",),
        )


class FakeContent:
    def prepare(self, scenario, approved_facts, identity_reference):
        assert identity_reference.startswith("fictional:")
        return TrainingContent("Fixture exercise", "Synthetic information only")


def test_registered_adapters_are_usable_without_changing_core_or_cli(tmp_path, capsys):
    registry = ProviderRegistry()
    registry.register_target("website", "fixture", FakeTarget())
    registry.register_content("fixture", FakeContent())
    config = ProviderConfig("fixture", (("website", "fixture"),))
    result = registry.assessment_service(config).assess("https://example.invalid")
    assert result.findings[0].check == "fixture"
    request = request_from_document(example_request("email_training"))
    plan = CampaignService(registry.content("fixture")).prepare(**request)
    assert plan.content.subject == "Fixture exercise"
    path = tmp_path / "providers.json"
    write_document(
        {"schema_version": 1, "content": "fixture", "assessment": {"website": "fixture"}}, path
    )
    assert (
        main(["--config", str(path), "assess", "https://example.invalid"], registry=registry) == 0
    )
    assert json.loads(capsys.readouterr().out)["findings"][0]["status"] == "candidate"
    assert main(["--config", str(path), "doctor"], registry=registry) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ready_offline"


@pytest.mark.parametrize(
    "failure",
    [TimeoutError("SECRET-TOKEN"), RuntimeError("SECRET-TOKEN"), ValueError("SECRET-TOKEN")],
)
def test_provider_failures_are_redacted_and_never_retried(failure, tmp_path, capsys):
    class Broken:
        calls = 0

        def assess(self, target):
            self.calls += 1
            raise failure

    provider = Broken()
    registry = ProviderRegistry()
    registry.register_target("website", "broken", provider)
    config = tmp_path / "config.json"
    write_document({"schema_version": 1, "assessment": {"website": "broken"}}, config)
    assert (
        main(["--config", str(config), "assess", "https://example.invalid"], registry=registry) == 3
    )
    output = capsys.readouterr()
    assert "SECRET-TOKEN" not in output.out + output.err
    assert "Traceback" not in output.err
    assert provider.calls == 1


@pytest.mark.parametrize(
    "result",
    [
        None,
        {},
        "bad",
        AssessmentResult("https://different.invalid", "website", "partial", (), ("Not checked",)),
    ],
)
def test_invalid_target_provider_results_are_rejected(result):
    class BadResult:
        def assess(self, target):
            return result

    registry = ProviderRegistry()
    registry.register_target("website", "bad", BadResult())
    with pytest.raises(ProviderError):
        registry.assessment_service(ProviderConfig(assessment=(("website", "bad"),))).assess(
            "https://example.invalid"
        )


@pytest.mark.parametrize("result", [None, "plain text", {"body": "text"}])
def test_unstructured_content_provider_output_is_rejected(result):
    class BadContent:
        def prepare(self, *args):
            return result

    registry = ProviderRegistry()
    registry.register_content("bad", BadContent())
    with pytest.raises(ProviderError):
        CampaignService(registry.content("bad")).prepare(
            **request_from_document(example_request("email_training"))
        )


def test_content_provider_errors_are_redacted():
    class BrokenContent:
        def prepare(self, *args):
            raise TimeoutError("API_SECRET")

    registry = ProviderRegistry()
    registry.register_content("bad", BrokenContent())
    with pytest.raises(ProviderError) as error:
        CampaignService(registry.content("bad")).prepare(
            **request_from_document(example_request("email_training"))
        )
    assert "API_SECRET" not in str(error.value)
    assert error.value.__suppress_context__


def test_missing_adapters_report_diagnostics_without_network():
    registry = ProviderRegistry()
    config = ProviderConfig("unavailable", (("website", "unavailable"),))
    assert registry.diagnose(config)["missing"] == ["content", "assessment:website"]
    with pytest.raises(ProviderError):
        registry.content(config.content)
    with pytest.raises(ProviderError):
        registry.assessment_service(config)


def test_registry_rejects_duplicate_and_non_callable_adapters():
    registry = ProviderRegistry()
    with pytest.raises(ValidationError):
        registry.register_content("template", FakeContent())
    with pytest.raises(ValidationError):
        registry.register_content("bad", object())
    with pytest.raises(ValidationError):
        registry.register_target("unknown", "fixture", FakeTarget())
    with pytest.raises(ValidationError):
        registry.register_target("website", "bad", object())
    registry.register_target("website", "fixture", FakeTarget())
    with pytest.raises(ValidationError):
        registry.register_target("website", "fixture", FakeTarget())


def test_provider_registration_does_not_claim_remote_health():
    registry = ProviderRegistry()
    assert registry.diagnose(ProviderConfig())["network_checked"] is False
    assert registry.describe(ProviderConfig())["live_transport"] == "not_bundled"


@pytest.mark.parametrize("invalid", [None, "bad", {"status": "accepted"}])
def test_invalid_transport_result_is_redacted_and_attempt_is_not_replayed(invalid):
    from datetime import datetime, timezone

    from ai_threat_lab.campaigns import ContentApproval

    class InvalidTransport:
        channel = "email"
        calls = 0

        def deliver(self, *args):
            self.calls += 1
            return invalid

    instance = InvalidTransport()
    registry = ProviderRegistry()
    registry.register_transport("email", "fixture", instance)
    service = CampaignService()
    plan = service.prepare(**request_from_document(example_request("email_training")))
    approval = ContentApproval(plan.digest, "Reviewer", datetime.now(timezone.utc))
    transport = registry.transport("email", "fixture")
    with pytest.raises(ProviderError):
        service.execute(plan, approval, transport)
    with pytest.raises(ValidationError, match="already attempted"):
        service.execute(plan, approval, transport)
    assert instance.calls == 1


def test_transport_contract_registration_and_builtin_demo():
    from datetime import datetime, timezone

    from ai_threat_lab.campaigns import ContentApproval

    registry = ProviderRegistry()
    with pytest.raises(ValidationError):
        registry.register_transport("email", "demo", object())
    with pytest.raises(ValidationError):
        registry.register_transport("unknown", "bad", object())
    with pytest.raises(ProviderError):
        registry.transport("email", "missing")
    service = CampaignService()
    plan = service.prepare(**request_from_document(example_request("email_training")))
    receipts = service.execute(
        plan,
        ContentApproval(plan.digest, "Reviewer", datetime.now(timezone.utc)),
        registry.transport("email", "demo"),
    )
    assert receipts[0].status == "simulated"


def test_transport_timeout_is_redacted_and_remains_unconfirmed():
    class TimeoutTransport:
        channel = "voice"
        calls = 0

        def deliver(self, plan, recipient):
            self.calls += 1
            raise TimeoutError("SECRET_PROVIDER_CREDENTIAL")

    transport = TimeoutTransport()
    registry = ProviderRegistry()
    registry.register_transport("voice", "timeout", transport)
    with pytest.raises(ProviderError, match="unconfirmed") as error:
        registry.transport("voice", "timeout").deliver(None, "+12025550100")
    assert "SECRET_PROVIDER_CREDENTIAL" not in str(error.value)
    assert error.value.__suppress_context__
    assert transport.calls == 1


def test_provider_acceptance_does_not_claim_delivery_or_participant_action():
    from ai_threat_lab.campaigns import DeliveryReceipt

    class AcceptingTransport:
        channel = "email"

        def deliver(self, plan, recipient):
            return DeliveryReceipt(recipient, "accepted", "synthetic-provider-reference")

    registry = ProviderRegistry()
    registry.register_transport("email", "fixture", AcceptingTransport())
    receipt = registry.transport("email", "fixture").deliver(None, "participant@example.invalid")
    assert receipt.status == "accepted"
    with pytest.raises(ValidationError):
        DeliveryReceipt(receipt.recipient, "compromised", receipt.reference)
