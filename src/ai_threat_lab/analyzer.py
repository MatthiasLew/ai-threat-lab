"""Public service for both interfaces; no terminal, Qt or file-write dependencies."""

from pathlib import Path

from .catalog import load_catalog
from .models import AnalysisRequest, AnalysisResult, Control, Scenario, ValidationError
from .risk import assess

ASSUMPTIONS = (
    "Fictional, local narrative simulation; no messages or synthetic media are generated or sent.",
    "Ordinal teaching model: scores are not probabilities or financial forecasts.",
    "Scenario rules and profile adjustments are provisional, not empirically calibrated.",
    "Controls are assumed implemented and followed; residual risk is not guaranteed protection.",
)


class ThreatAnalyzer:
    def __init__(self, catalog_path: Path | None = None) -> None:
        self._scenarios, self._controls = load_catalog(catalog_path)

    def list_scenarios(self) -> tuple[Scenario, ...]:
        return self._scenarios

    def list_controls(self) -> tuple[Control, ...]:
        return self._controls

    def analyze(self, request: AnalysisRequest) -> AnalysisResult:
        if not isinstance(request, AnalysisRequest):
            raise ValidationError("request must be an AnalysisRequest")
        scenario = next((s for s in self._scenarios if s.id == request.scenario_id), None)
        if scenario is None:
            raise ValidationError(f"Unknown scenario: {request.scenario_id}")
        known_ids = {c.id for c in self._controls}
        selected = set(request.existing_control_ids) | set(request.proposed_control_ids)
        unknown = selected - known_ids
        if unknown:
            raise ValidationError(f"Unknown controls: {', '.join(sorted(unknown))}")
        # Existing controls are evaluated once; additions never compound a prior assessment.
        proposed = tuple(
            sorted(set(request.proposed_control_ids) - set(request.existing_control_ids))
        )
        return AnalysisResult(
            scenario_id=scenario.id,
            scenario_title=scenario.title,
            target=request.target,
            stages=scenario.stages,
            consequences=scenario.consequences,
            existing_control_ids=request.existing_control_ids,
            proposed_control_ids=proposed,
            recommended_controls=tuple(
                c
                for c in self._controls
                if c.id not in selected and c.id in {r.control_id for r in scenario.rules}
            ),
            baseline=assess(scenario, request.target, request.existing_control_ids),
            residual=assess(scenario, request.target, tuple(sorted(selected))),
            assumptions=ASSUMPTIONS,
        )
