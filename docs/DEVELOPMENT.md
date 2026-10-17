# Development plan

## Current checkout

Only documentation is present. Clone the repository and read PROJECT_PLAN.md and ARCHITECTURE.md before adding code. Packaging and runnable commands will be documented once implemented.

## Contribution workflow

Use a focused branch for each milestone. Keep changes small enough to review. Update documentation when the implemented service contract differs from the proposal. Do not label planned functionality as available.

## Planned meaningful checks

- Rating validation, including invalid types and out-of-range inputs.
- Risk-label boundaries and reachable matrix scores.
- Unknown scenario and control identifiers.
- Duplicate controls and irrelevant controls.
- Existing defenses are not counted twice.
- Deterministic baseline/residual results and explained adjustments.
- UTF-8 report output and JSON schema/model versions.
- Clear failures for unwritable destinations.
- All three CLI scenarios work end to end offline.
- CLI/GUI parity once the desktop adapter exists.

CI should be added together with runnable implementation and tests. The documentation bootstrap does not claim a passing application test suite.
