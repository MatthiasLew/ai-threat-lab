# GUI handoff

## Division of work

Mateusz: shared models, scenario catalog, risk engine, CLI, exporters, and core verification. GUI contributor: PySide6 screens, navigation, presentation, and service integration.

## Planned screens

1. Scenario selection with description.
2. Fictional target profile and existing controls.
3. Campaign stages, warning signs, and consequences.
4. Baseline assessment with rationale.
5. Proposed controls and baseline/residual comparison.
6. Report export with destination selection.

## Integration rules

Call the shared service directly; never parse CLI text or duplicate scoring in widgets. Treat structured results as the source of truth. Keep Qt objects outside domain models. Handle validation errors and file-write failures visibly. Recompute from the full request whenever selections change.

The service and CLI now provide real results for all three MVP scenarios. Use the example below to begin GUI integration.

## Acceptance

Identical inputs in CLI and GUI must produce identical scores, labels, consequences, and control explanations. Exported content must match the displayed analysis.

## Working integration example (0.1.0)

```python
from pathlib import Path
from ai_threat_lab import AnalysisRequest, TargetProfile, ThreatAnalyzer, export_report

analyzer = ThreatAnalyzer()
result = analyzer.analyze(AnalysisRequest(
    scenario_id="voice_deepfake",
    target=TargetProfile("Example Company", "Accounting employee"),
    proposed_control_ids=("callback", "independent_approval"),
))
assert result.baseline.score == 20
assert result.residual.score == 10
# Widgets can read result.residual.level and result.residual.explanations directly.
# Explicit save action; the destination must be new:
export_report(result, Path("analysis.json"), "json")
```

`ValidationError` covers invalid requests; `OSError` covers file failures. `list_scenarios()` returns full immutable scenarios and `list_controls()` returns control IDs, titles, and descriptions. `recommended_controls` contains applicable defenses not already selected.
