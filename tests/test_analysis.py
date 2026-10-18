import json
from dataclasses import FrozenInstanceError
from itertools import product

import pytest

from ai_threat_lab import AnalysisRequest, TargetProfile, ThreatAnalyzer, ValidationError
from ai_threat_lab.catalog import load_catalog
from ai_threat_lab.models import Level
from ai_threat_lab.risk import calculate_risk, risk_level


@pytest.fixture
def analyzer():
    return ThreatAnalyzer()


def request(scenario="voice_deepfake", existing=(), proposed=(), access="medium", urgency="normal"):
    return AnalysisRequest(
        scenario, TargetProfile("Example Company", "Employee", access, urgency), existing, proposed
    )


@pytest.mark.parametrize("likelihood,impact", list(product(range(1, 6), repeat=2)))
def test_matrix(likelihood, impact):
    assert calculate_risk(likelihood, impact) == likelihood * impact


@pytest.mark.parametrize(
    "score,level",
    [
        (1, Level.LOW),
        (4, Level.LOW),
        (5, Level.MODERATE),
        (9, Level.MODERATE),
        (10, Level.HIGH),
        (14, Level.HIGH),
        (15, Level.VERY_HIGH),
        (19, Level.VERY_HIGH),
        (20, Level.CRITICAL),
        (25, Level.CRITICAL),
    ],
)
def test_level_boundaries(score, level):
    assert risk_level(score) == level


@pytest.mark.parametrize("value", [True, False, 0, 6, -1, 1.5, "4", None])
def test_reject_invalid_ratings(value):
    with pytest.raises(ValidationError):
        calculate_risk(value, 5)
    with pytest.raises(ValidationError):
        calculate_risk(5, value)


def test_voice_worked_example(analyzer):
    result = analyzer.analyze(request(proposed=("callback", "independent_approval")))
    assert (result.baseline.likelihood, result.baseline.impact, result.baseline.score) == (4, 5, 20)
    assert (result.residual.likelihood, result.residual.impact, result.residual.score) == (2, 5, 10)
    assert result.residual.level == Level.HIGH
    assert any("callback" in line for line in result.residual.explanations)


def test_controls_are_deduplicated_and_existing_not_reapplied(analyzer):
    single = analyzer.analyze(request(existing=("callback",)))
    duplicate = analyzer.analyze(request(existing=["callback", "callback"], proposed=["callback"]))
    assert single == duplicate
    assert duplicate.baseline == duplicate.residual
    assert duplicate.proposed_control_ids == ()


def test_related_controls_do_not_stack(analyzer):
    single = analyzer.analyze(request(proposed=("callback",)))
    overlap = analyzer.analyze(request(proposed=("callback", "source_verification")))
    assert single.residual.score == overlap.residual.score == 15


def test_irrelevant_authentication_does_not_reduce_payment_risk(analyzer):
    result = analyzer.analyze(request(proposed=("phishing_resistant_auth",)))
    assert result.baseline.score == result.residual.score == 20
    assert any("not applicable" in line for line in result.residual.explanations)


def test_reduction_caps_and_target_effects(analyzer):
    all_ids = tuple(c.id for c in analyzer.list_controls())
    for scenario, access, urgency in product(
        analyzer.list_scenarios(), ("low", "medium", "high"), ("low", "normal", "high")
    ):
        result = analyzer.analyze(
            request(scenario.id, proposed=all_ids, access=access, urgency=urgency)
        )
        assert 1 <= result.residual.likelihood <= result.baseline.likelihood <= 5
        assert 1 <= result.residual.impact <= result.baseline.impact <= 5
        assert result.baseline.likelihood - result.residual.likelihood <= 2
        assert result.baseline.impact - result.residual.impact <= 2
    low = analyzer.analyze(request(access="low", urgency="low"))
    assert (low.baseline.likelihood, low.baseline.impact) == (3, 4)


def test_result_deterministic_and_immutable(analyzer):
    first = analyzer.analyze(request(proposed=("independent_approval", "callback")))
    second = analyzer.analyze(request(proposed=("callback", "independent_approval")))
    assert first == second
    with pytest.raises(FrozenInstanceError):
        first.model_version = "changed"


@pytest.mark.parametrize(
    "kwargs", [dict(scenario="unknown"), dict(proposed=("missing",)), dict(existing=("missing",))]
)
def test_unknown_ids_rejected(analyzer, kwargs):
    with pytest.raises(ValidationError, match="Unknown"):
        analyzer.analyze(request(**kwargs))


@pytest.mark.parametrize(
    "organization,role,access,urgency",
    [
        (" ", "Employee", "medium", "normal"),
        ("Test", "", "medium", "normal"),
        ("Test", "Employee", "admin", "normal"),
        ("Test", "Employee", "medium", "urgent"),
    ],
)
def test_profile_validation(organization, role, access, urgency):
    with pytest.raises(ValidationError):
        TargetProfile(organization, role, access, urgency)


def test_request_rejects_string_control_collection():
    with pytest.raises(ValidationError):
        request(existing="callback")


@pytest.mark.parametrize("mutation", ["schema", "rating", "unknown_rule", "duplicate", "empty"])
def test_catalog_validation(tmp_path, mutation):
    from importlib.resources import files

    raw = json.loads(files("ai_threat_lab").joinpath("data/catalog.json").read_text())
    if mutation == "schema":
        raw["schema_version"] = 99
    elif mutation == "rating":
        raw["scenarios"][0]["impact"] = True
    elif mutation == "unknown_rule":
        raw["scenarios"][0]["rules"][0]["control_id"] = "missing"
    elif mutation == "duplicate":
        raw["scenarios"].append(raw["scenarios"][0])
    else:
        raw["scenarios"][0]["stages"] = []
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(raw))
    with pytest.raises(ValidationError, match="Invalid scenario catalog"):
        load_catalog(path)


def test_unreadable_catalog(tmp_path):
    with pytest.raises(ValidationError):
        load_catalog(tmp_path / "missing.json")


@pytest.mark.parametrize(
    "scenario_id,control_id",
    [
        ("brute_force", "rate_limiting"),
        ("credential_stuffing", "unique_passwords"),
        ("insecure_generated_code", "code_review"),
    ],
)
def test_extended_offline_scenarios(analyzer, scenario_id, control_id):
    result = analyzer.analyze(request(scenario_id, proposed=(control_id,)))
    assert result.residual.score < result.baseline.score
    assert result.stages and result.consequences
    assert any(control_id in e for e in result.residual.explanations)


def test_brute_force_attempt_controls_overlap(analyzer):
    single = analyzer.analyze(request("brute_force", proposed=("rate_limiting",)))
    both = analyzer.analyze(request("brute_force", proposed=("rate_limiting", "account_lockout")))
    assert single.residual.score == both.residual.score
