# Roadmap

All implementation tasks below are planned, not completed.

## Milestone 0 — Documentation

- [x] Describe the project and its limits.
- [x] Define initial scope, architecture, and GUI handoff.
- [ ] Confirm scope with the team and course instructor.

## Milestone 1 — Domain and data

- [ ] Set up the Python package and development dependencies.
- [ ] Implement validated domain models and catalog loading.
- [ ] Add three fictional scenarios and associated controls.

Acceptance: valid data loads; malformed data produces actionable validation errors.

## Milestone 2 — Analysis engine

- [ ] Implement the risk matrix and explained scenario rules.
- [ ] Add baseline and residual assessments.
- [ ] Cover control applicability, duplicate controls, and rating bounds.

Acceptance: repeatable input produces the same result; every adjustment is traceable.

## Milestone 3 — CLI and exports

- [ ] Add scenario selection and profile configuration.
- [ ] Display stages, consequences, defenses, and comparison.
- [ ] Export TXT and JSON with model version and assumptions.

Acceptance: all three scenarios can be demonstrated end to end without network access.

## Milestone 4 — GUI

- [ ] Agree and freeze the initial service contract.
- [ ] Build scenario, profile, analysis, defense, and export screens.
- [ ] Confirm CLI and GUI show equivalent results for identical requests.

## Milestone 5 — Presentation

- [ ] Prepare sample reports and a repeatable demonstration.
- [ ] Document remaining limitations.
- [ ] Consider PDF and extra scenarios if time permits.
