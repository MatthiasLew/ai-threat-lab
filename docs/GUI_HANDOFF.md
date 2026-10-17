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

The core contributor will provide one sample request/result for each MVP scenario after the contract is implemented. GUI work can begin with clearly marked mock results meanwhile.

## Acceptance

Identical inputs in CLI and GUI must produce identical scores, labels, consequences, and control explanations. Exported content must match the displayed analysis.
