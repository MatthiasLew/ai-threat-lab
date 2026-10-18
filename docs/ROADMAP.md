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
- [x] Optional OpenAI explanation adapter, budget reservations, cache and source-sharing opt-in.
- [ ] Controlled live validation against the selected model/account.

## Assessment/campaign integration foundation — implemented

- [x] Target classification and partial/not-configured result contract.
- [x] Limited local project and exported-mail checks.
- [x] Email, vishing and synthetic-video exercise templates.
- [x] Content/transport interfaces, exact preview approvals and recipient scope.
- [x] Cancellation checks, attempted-delivery claims and persistent ledger option.
- [x] Event aggregation with automated-event exclusion.
- [x] Concrete read-only GitHub, passive HTTPS, basic DNS and selected Gmail settings adapters.
- [ ] Live-account/provider validation and broader assessment rules.
- [ ] Live email/voice/media provider adapters and integration validation.

## Cost-aware read-only integrations — 0.4.0

- [x] Fixed service endpoints, exact host approval, pinned public DNS, verified TLS, bounded reads and no redirects/retries.
- [x] Immutable GitHub blob verification and explicit skipped-file limits.
- [x] Local secret-pattern redaction and basic dependency-version observations.
- [x] AI payload minimization, deduplication, context/output caps and dry-run.
- [x] Persistent daily/request budgets, concurrency claims, optional TTL cache and usage reconciliation.
- [x] CLI, wire-contract, malformed-response, concurrency and packaging tests.
- [ ] Real provider/account integration evidence; no paid calls performed during development.
- [ ] Active assessments, comprehensive binary/dependency analysis, live communications and media remain separate product work.

## Dependency checks and reports — 0.5.0

- [x] Exact-version inventory from requirements/npm/uv/Poetry lockfiles.
- [x] Explicit OSV package-sharing consent, bounded batches/pages and optional advisory cache.
- [x] Combined JSON/HTML remediation reports, target-scoped deduplication and provenance.
- [x] Preserve incomplete queries, skipped inputs and assessment limitations.
- [x] Bounded legacy Python traversal and tighter repository identity validation.
- [ ] More manifest ecosystems, advisory detail/severity/fix retrieval and reachability analysis.
