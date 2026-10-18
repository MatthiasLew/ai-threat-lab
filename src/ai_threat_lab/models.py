"""Validated, immutable data shared by the CLI and future GUI."""

from dataclasses import dataclass
from enum import StrEnum


class ValidationError(ValueError):
    """A request or scenario catalog violates the public contract."""


class Level(StrEnum):
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"
    VERY_HIGH = "Very high"
    CRITICAL = "Critical"


def require_text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")


def require_rating(value: object, field: str) -> None:
    if type(value) is not int or not 1 <= value <= 5:
        raise ValidationError(f"{field} must be an integer between 1 and 5")


@dataclass(frozen=True)
class TargetProfile:
    organization: str
    role: str
    access: str = "medium"
    urgency: str = "normal"

    def __post_init__(self) -> None:
        require_text(self.organization, "organization")
        require_text(self.role, "role")
        if self.access not in ("low", "medium", "high"):
            raise ValidationError("access must be low, medium or high")
        if self.urgency not in ("low", "normal", "high"):
            raise ValidationError("urgency must be low, normal or high")


@dataclass(frozen=True)
class AnalysisRequest:
    scenario_id: str
    target: TargetProfile
    existing_control_ids: tuple[str, ...] = ()
    proposed_control_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_text(self.scenario_id, "scenario_id")
        if not isinstance(self.target, TargetProfile):
            raise ValidationError("target must be a TargetProfile")
        for field in ("existing_control_ids", "proposed_control_ids"):
            values = getattr(self, field)
            if not isinstance(values, (list, tuple)):
                raise ValidationError(f"{field} must be a list or tuple of IDs")
            for value in values:
                require_text(value, field)
            object.__setattr__(self, field, tuple(sorted(set(values))))


@dataclass(frozen=True)
class CampaignStage:
    title: str
    narrative: str
    warning_sign: str
    intervention: str


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    description: str


@dataclass(frozen=True)
class ControlRule:
    control_id: str
    group: str
    likelihood_reduction: int
    impact_reduction: int
    rationale: str


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    description: str
    default_role: str
    likelihood: int
    impact: int
    rationale: str
    stages: tuple[CampaignStage, ...]
    consequences: tuple[str, ...]
    rules: tuple[ControlRule, ...]


@dataclass(frozen=True)
class RiskAssessment:
    likelihood: int
    impact: int
    score: int
    level: Level
    explanations: tuple[str, ...]


@dataclass(frozen=True)
class AnalysisResult:
    scenario_id: str
    scenario_title: str
    target: TargetProfile
    stages: tuple[CampaignStage, ...]
    consequences: tuple[str, ...]
    existing_control_ids: tuple[str, ...]
    proposed_control_ids: tuple[str, ...]
    recommended_controls: tuple[Control, ...]
    baseline: RiskAssessment
    residual: RiskAssessment
    assumptions: tuple[str, ...]
    model_version: str = "educational-1.0"
