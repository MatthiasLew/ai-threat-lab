# Roadmap

Milestones 1–3 are implemented in the CLI foundation. Team review, GUI, and presentation remain open.

## Milestone 0 — Documentation

- [x] Describe the project and its limits.
- [x] Define initial scope, architecture, and GUI handoff.
- [ ] Confirm scope with the team and course instructor.

## Milestone 1 — Domain and data

- [x] Set up the Python package and development dependencies.
- [x] Implement validated domain models and catalog loading.
- [x] Add initial three fictional scenarios and associated controls.

Acceptance: valid data loads; malformed data produces actionable validation errors.

## Milestone 2 — Analysis engine

- [x] Implement the risk matrix and explained scenario rules.
- [x] Add baseline and residual assessments.
- [x] Cover control applicability, duplicate controls, and rating bounds.

Acceptance: repeatable input produces the same result; every adjustment is traceable.

## Milestone 3 — CLI and exports

- [x] Add scenario selection and profile configuration.
- [x] Display stages, consequences, defenses, and comparison.
- [x] Export TXT and JSON with model version and assumptions.

Acceptance: all three scenarios can be demonstrated end to end without network access.

## Milestone 4 — GUI

- [ ] Agree and freeze the initial service contract.
- [ ] Build scenario, profile, analysis, defense, and export screens.
- [ ] Confirm CLI and GUI show equivalent results for identical requests.

## Milestone 5 — Presentation

- [ ] Prepare sample reports and a repeatable demonstration.
- [ ] Document remaining limitations.
- [ ] Consider PDF and extra scenarios if time permits.

## Additional offline modules

- [x] Brute-force and credential-stuffing teaching scenarios.
- [x] Insecure AI-generated code scenario.
- [x] Local Python AST checks, findings and remediation guidance.
- [x] Extension documentation without API coupling.
- [ ] More languages, data-flow analysis and additional rule families, only if needed.
- [ ] Optional AI integration after access, budget and source-sharing decisions.

## Assessment/campaign integration foundation — implemented

- [x] Target classification and partial/not-configured result contract.
- [x] Limited local project and exported-mail checks.
- [x] Email, vishing and synthetic-video exercise templates.
- [x] Content/transport interfaces, exact preview approvals and recipient scope.
- [x] Cancellation checks, attempted-delivery claims and persistent ledger option.
- [x] Event aggregation with automated-event exclusion.
- [ ] Actual GitHub, HTTP/TLS, DNS and mailbox adapters.
- [ ] Live email/voice/media provider adapters and integration validation.
