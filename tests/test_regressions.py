import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from importlib.resources import files

import pytest

from ai_threat_lab import AnalysisRequest, TargetProfile, ThreatAnalyzer, ValidationError
from ai_threat_lab.assessment import (
    AssessmentFinding,
    AssessmentResult,
    AssessmentService,
    identify_target,
)
from ai_threat_lab.campaigns import CampaignPlan, CampaignScope, CampaignService, TrainingContent
from ai_threat_lab.catalog import load_catalog
from ai_threat_lab.cli import main
from ai_threat_lab.contracts import write_document
from ai_threat_lab.delivery_ledger import MemoryLedger, SQLiteLedger
from ai_threat_lab.providers import ProviderRegistry
from ai_threat_lab.workflows import example_request


@pytest.mark.parametrize(
    "mutation",
    [
        "controls_not_array",
        "scenarios_not_array",
        "duplicate_control",
        "duplicate_rule",
        "rules_not_array",
        "stages_not_array",
        "consequences_not_array",
        "empty_consequences",
        "missing_field",
        "blank_title",
        "reduction_negative",
        "reduction_three",
        "reduction_bool",
        "reduction_float",
        "schema_bool",
        "invalid_json",
    ],
)
def test_catalog_malformed_data_is_never_silently_accepted(tmp_path, mutation):
    raw = json.loads(files("ai_threat_lab").joinpath("data/catalog.json").read_text())
    scenario = raw["scenarios"][0]
    if mutation == "controls_not_array":
        raw["controls"] = {}
    elif mutation == "scenarios_not_array":
        raw["scenarios"] = {}
    elif mutation == "duplicate_control":
        raw["controls"].append(raw["controls"][0])
    elif mutation == "duplicate_rule":
        scenario["rules"].append(scenario["rules"][0])
    elif mutation.endswith("_not_array"):
        scenario[mutation.removesuffix("_not_array")] = {}
    elif mutation == "empty_consequences":
        scenario["consequences"] = []
    elif mutation == "missing_field":
        del scenario["id"]
    elif mutation == "blank_title":
        scenario["title"] = " "
    elif mutation.startswith("reduction_"):
        scenario["rules"][0]["likelihood_reduction"] = {
            "reduction_negative": -1,
            "reduction_three": 3,
            "reduction_bool": True,
            "reduction_float": 1.5,
        }[mutation]
    elif mutation == "schema_bool":
        raw["schema_version"] = True
    path = tmp_path / "catalog.json"
    path.write_text("{" if mutation == "invalid_json" else json.dumps(raw))
    with pytest.raises(ValidationError):
        load_catalog(path)


@pytest.mark.parametrize(
    "target",
    [
        "mail-domain:a..example",
        "mail-domain:-bad.example",
        "mail-domain:bad-.example",
        "mail-domain:localhost",
        "mail-domain:" + "a" * 64 + ".example",
        "mailbox:no-at-symbol",
        "ftp://example.invalid",
        "https://github.com/owner",
    ],
)
def test_target_routing_rejects_unsupported_or_malformed_inputs(target):
    with pytest.raises(ValidationError):
        identify_target(target)


@pytest.mark.parametrize(
    "name", ["mail-domain:example.invalid", "mail-domain:sub-domain.example.invalid"]
)
def test_valid_mail_domain_is_recognized_without_dns(name):
    assert AssessmentService().assess(name).status == "not_configured"


def test_empty_projects_binary_files_and_untrusted_mail_headers(tmp_path):
    service = AssessmentService()
    result = service.assess(str(tmp_path))
    assert any("No Python" in item for item in result.not_checked)
    binary = tmp_path / "program.exe"
    binary.write_bytes(b"not executable")
    assert service.assess(str(binary)).status == "not_configured"
    message = tmp_path / "mail.eml"
    message.write_text(
        "From: sender@example.invalid\nAuthentication-Results: attacker; dmarc=pass\n\nHello"
    )
    result = service.assess(str(message))
    assert result.findings[0].status == "unverified"
    assert result.status == "partial"
    message.write_bytes(b"X" * (1024 * 1024 + 1))
    with pytest.raises(ValidationError, match="limit"):
        service.assess(str(message))


@pytest.mark.parametrize("ledger_type", [MemoryLedger, SQLiteLedger])
def test_concurrent_delivery_claims_have_one_winner(ledger_type, tmp_path):
    ledger = (
        ledger_type(tmp_path / "claims.sqlite") if ledger_type is SQLiteLedger else ledger_type()
    )
    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(ledger.claim, ["same-attempt"] * 32))
    assert sum(outcomes) == 1


def test_corrupt_ledger_and_missing_parent_produce_validation_errors(tmp_path):
    broken = tmp_path / "broken.sqlite"
    broken.write_bytes(b"NOT A SQLITE DATABASE" * 20)
    with pytest.raises(ValidationError, match="ledger"):
        SQLiteLedger(broken)
    with pytest.raises(ValidationError):
        SQLiteLedger(tmp_path / "missing" / "ledger.sqlite")
    ledger = SQLiteLedger(tmp_path / "claims.sqlite")
    ledger.path.write_bytes(b"NOT A DATABASE" * 100)
    with pytest.raises(ValidationError, match="ledger"):
        ledger.claim("attempt")


@pytest.mark.parametrize(
    "scope,recipients",
    [
        (None, ()),
        (None, []),
        ("bad", ["a"]),
    ],
)
def test_campaign_api_invalid_scope_never_calls_provider(scope, recipients):
    with pytest.raises(ValidationError, match="scope"):
        CampaignService().prepare("email_training", scope, recipients)


def test_campaign_models_reject_mutable_or_wrong_type_inputs():
    now = datetime.now(timezone.utc)
    scope = CampaignScope("test", "Reviewer", ["a@example.invalid"], now + timedelta(hours=1))
    with pytest.raises(ValidationError, match="recipients"):
        CampaignService().prepare("email_training", scope, "a@example.invalid")
    with pytest.raises(ValidationError):
        CampaignService().prepare("email_training", scope, [None])
    with pytest.raises(ValidationError):
        CampaignPlan("email_training", "unknown", scope, (), (), TrainingContent("a", "b"))
    with pytest.raises(ValidationError):
        CampaignPlan("email_training", "email", scope, "bad", (), TrainingContent("a", "b"))
    with pytest.raises(ValidationError):
        CampaignPlan("email_training", "email", None, (), (), TrainingContent("a", "b"))
    with pytest.raises(ValidationError):
        TrainingContent("multiline\nsubject", "text")
    with pytest.raises(ValidationError):
        TrainingContent("subject", "text", media_sha256="a" * 64)


@pytest.mark.parametrize("bad", ["secure", "success", "", None])
def test_assessment_cannot_claim_unsupported_status(bad):
    with pytest.raises(ValidationError):
        AssessmentResult("target", "website", bad, (), ())
    with pytest.raises(ValidationError):
        AssessmentFinding("check", bad, "evidence", "recommendation")


def test_immutable_result_boundary_rejects_invalid_lists():
    with pytest.raises(ValidationError):
        AssessmentResult("target", "website", "partial", ["not finding"], ())
    with pytest.raises(ValidationError):
        AssessmentResult("target", "website", "partial", (), "not array")
    with pytest.raises(ValidationError):
        AssessmentResult("target", "website", "partial", (), [None])
    result = AssessmentResult("target", "website", "partial", [], ["Not checked"])
    assert result.findings == () and result.not_checked == ("Not checked",)


def test_cli_complete_workflow_in_process_and_no_state_change_on_existing_output(tmp_path, capsys):
    request, plan, approval = [
        tmp_path / f"{name}.json" for name in ("request", "plan", "approval")
    ]
    write_document(example_request("voice_training"), request)
    assert main(["campaign-prepare", str(request), "--output", str(plan)]) == 0
    assert (
        main(["campaign-approve", str(plan), "--reviewer", "Reviewer", "--output", str(approval)])
        == 0
    )
    ledger = tmp_path / "ledger.sqlite"
    result = tmp_path / "result.json"
    result.write_text("preserve")
    capsys.readouterr()
    assert (
        main(
            [
                "campaign-simulate",
                str(plan),
                "--approval",
                str(approval),
                "--ledger",
                str(ledger),
                "--output",
                str(result),
            ]
        )
        == 2
    )
    assert not ledger.exists()
    assert result.read_text() == "preserve"
    assert (
        main(["campaign-simulate", str(plan), "--approval", str(approval), "--ledger", str(ledger)])
        == 0
    )
    assert json.loads(capsys.readouterr().out)["mode"] == "offline_simulation"
    assert main(["campaign-example", "email_training"]) == 0
    assert json.loads(capsys.readouterr().out)["schema_version"] == 1


def test_cli_cancel_and_unknown_interactive_selection(monkeypatch, capsys):
    class InterruptingRegistry(ProviderRegistry):
        def diagnose(self, config):
            raise KeyboardInterrupt

    assert main(["doctor"], registry=InterruptingRegistry()) == 130
    assert "Cancelled" in capsys.readouterr().err
    monkeypatch.setattr("builtins.input", lambda _: "unknown")
    assert main(["interactive"]) == 2
    assert "Unknown" in capsys.readouterr().err


def test_invalid_public_analyzer_requests_are_rejected():
    with pytest.raises(ValidationError):
        ThreatAnalyzer().analyze(None)
    with pytest.raises(ValidationError):
        AnalysisRequest("ai_phishing", "invalid target")
    with pytest.raises(ValidationError):
        replace(
            AnalysisRequest("ai_phishing", TargetProfile("Example", "Employee")), scenario_id=""
        )
