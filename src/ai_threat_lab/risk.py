"""Deterministic educational rules, not empirical probabilities."""

from .models import Level, RiskAssessment, Scenario, TargetProfile, require_rating


def risk_level(score: int) -> Level:
    if type(score) is not int or not 1 <= score <= 25:
        from .models import ValidationError

        raise ValidationError("score must be an integer between 1 and 25")
    for upper, level in (
        (4, Level.LOW),
        (9, Level.MODERATE),
        (14, Level.HIGH),
        (19, Level.VERY_HIGH),
        (25, Level.CRITICAL),
    ):
        if score <= upper:
            return level
    raise AssertionError("Unreachable score")


def calculate_risk(likelihood: int, impact: int) -> int:
    require_rating(likelihood, "likelihood")
    require_rating(impact, "impact")
    return likelihood * impact


def assess(scenario: Scenario, target: TargetProfile, controls: tuple[str, ...]) -> RiskAssessment:
    likelihood = scenario.likelihood
    impact = scenario.impact
    explanations = [f"Scenario starting ratings: {likelihood} × {impact}. {scenario.rationale}"]
    urgency_adjustment = {"low": -1, "normal": 0, "high": 1}[target.urgency]
    likelihood = max(1, min(5, likelihood + urgency_adjustment))
    explanations.append(
        f"Urgency {target.urgency}: likelihood adjustment {urgency_adjustment:+d}, "
        f"bounded to 1–5; resulting likelihood {likelihood}."
    )
    access_adjustment = {"low": -1, "medium": 0, "high": 1}[target.access]
    impact = max(1, min(5, impact + access_adjustment))
    explanations.append(
        f"Access {target.access}: impact adjustment {access_adjustment:+d}, "
        f"bounded to 1–5; resulting impact {impact}."
    )
    rules = {rule.control_id: rule for rule in scenario.rules}
    groups: dict[str, tuple[int, int]] = {}
    for control_id in controls:
        rule = rules.get(control_id)
        if rule is None:
            explanations.append(f"{control_id}: not applicable to this scenario; no reduction.")
            continue
        previous = groups.get(rule.group, (0, 0))
        groups[rule.group] = (
            max(previous[0], rule.likelihood_reduction),
            max(previous[1], rule.impact_reduction),
        )
        explanations.append(
            f"{control_id} (group {rule.group}): candidate reductions "
            f"L={rule.likelihood_reduction}, I={rule.impact_reduction}. "
            f"{rule.rationale}"
        )
    reduction_l = min(2, sum(value[0] for value in groups.values()))
    reduction_i = min(2, sum(value[1] for value in groups.values()))
    explanations.append(
        "Controls use the maximum reduction per group and dimension, "
        "then sum groups with a cap of 2 per dimension; ratings have a floor of 1."
    )
    adjusted_l = max(1, likelihood - reduction_l)
    adjusted_i = max(1, impact - reduction_i)
    explanations.append(
        f"Effective control reductions: L={likelihood - adjusted_l}, I={impact - adjusted_i}."
    )
    score = calculate_risk(adjusted_l, adjusted_i)
    return RiskAssessment(adjusted_l, adjusted_i, score, risk_level(score), tuple(explanations))
