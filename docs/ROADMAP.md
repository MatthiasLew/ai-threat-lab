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
- [x] Nine local Python AST rule families, findings and remediation guidance.
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

## Local training lab — 0.6.0

- [x] Approved, durable text-rehearsal sessions for all three training channels.
- [x] Structured actions, restart/replay protection and transactional concurrent updates.
- [x] Stop, scope expiry, bounded voice dialogue and permanent local plan cancellation.
- [x] JSON/HTML selected-outcome reports and follow-up practice guidance.
- [x] Explicit separation from live telemetry and personnel judgments.
- [ ] Real speech/phone/media and live campaign integrations remain absent.

## Scan workflow — 0.7.0

- [x] One-command target checks plus automatic local-project dependency inventory.
- [x] Explicit module status, partial-failure results and optional finding-based exit code.
- [x] Private no-overwrite bundles with manifest-last publication and integrity/consistency checks.
- [x] Baseline comparison with scope/module gates and observation-only change labels.
- [x] Invalid/tampered bundle, interrupted write, path/symlink and installed CLI tests.

## Shared GitHub inventory — 0.8.0

- [x] Root requirements/npm/uv/Poetry inventory from the same immutable commit as source checks.
- [x] Shared bounded retrieval with distinct-blob reuse, manifest priority and explicit skipped coverage.
- [x] Opt-in remote-inventory OSV lookup, existing advisory cache and module failure preservation.
- [x] In-memory parsing with no repository materialization, archive extraction or execution.
- [x] Opt-in nested/monorepo discovery with preserved origins and global limits (0.10.0).
- [ ] Additional ecosystems and dependency reachability.
- [ ] Authenticated history storage and active assessment modules remain future work.


## Offline acceptance and configuration — 0.9.0

- [x] Literal Dockerfile and GitHub Actions observations in local/GitHub scans.
- [x] Approved inert exercise exports for email, voice scripts and video storyboards.
- [x] Repeatable synthetic before/after scan plus all training channels in one CLI command.
- [x] Static readiness inventory that distinguishes credentials, validation and missing modules.
- [x] No-network, approval/expiry, escaping, no-overwrite, CLI process and installed-wheel coverage.
- [ ] External communications/media and authenticated observed-event intake remain separate implementation work, not just API-key setup.

See [DELIVERY_STATUS.md](DELIVERY_STATUS.md) for each requested input type and the remaining implementation/validation order.


## Bounded monorepo inventory — 0.10.0

- [x] Explicit nested-manifest selection for local and shared-commit GitHub scans.
- [x] Portable source paths, cross-subproject exact identity deduplication and global parser bounds.
- [x] Local breadth-first traversal, entry/directory/depth bounds and link/junction exclusions.
- [x] Recursive scope recording, old-bundle reading and conservative comparison gates.
- [x] Expanded synthetic demo, CLI, malformed-path, resource and installed-package checks.
- [ ] Workspace dependency graph resolution, additional ecosystems and runtime reachability.


## Static program-file observations — 0.11.0

- [x] Bounded PE32/PE32+ and ELF32/ELF64 structures, both ELF byte orders.
- [x] Candidate header/permission observations with explicit runtime/trust gaps.
- [x] Metadata preservation and no partial mitigation claims for malformed structures.
- [x] Inert binary demo descriptors, report bundles, truncation/fuzz/resource/CLI tests and installed verification.
- [ ] Cryptographic signature trust, broader formats, disassembly, malware detection and dynamic analysis.

## Local report interchange — 0.13.0

- [x] Source-free SARIF export for standalone Python review, with line-level candidate locations.
- [x] Explicit root-relative paths, URI encoding, no-overwrite and CLI/package tests.
- [ ] Combined multi-target SARIF, upload integrations and consumer-specific acceptance remain separate work.

## Expanded offline assessment milestone — 0.14.0

- [x] Cargo.lock v3/v4 crates.io exact-version inventory, nested origins and shared GitHub snapshots.
- [x] Bounded offline EML link/attachment metadata, redacted aggregate findings and explicit MIME gaps.
- [x] Synthetic multi-ecosystem/mail demo, integrity-checkable reports, failure markers and installed CLI gates.
- [ ] Other dependency ecosystems, data-flow/reachability, trusted mail authenticity and attachment-content analysis remain separate engineering work.

## Multi-target offline workflow — 0.15.0

- [x] Explicit local target lists, sequential collection, combined reports and isolated module failure evidence.
- [x] Strict no-overwrite scope checks, bounded report/index publication and child/report consistency verification.
- [x] Resource, tampering, cancellation, deleted-source, CLI and installed-package acceptance.
- [ ] Remote batch targets, scheduling, resume/retry, shared history services and authenticated signatures are outside this bounded workflow.

## Offline/shared HTTP header observations — 0.16.0

- [x] Strict saved HTTPS header captures, source-free candidate evidence and JSON/HTML CLI output.
- [x] Duplicate-preserving transport, individual cookie metadata and selected CSP script patterns shared with WebsiteAudit.
- [x] No-network, privacy, malformed/resource, CLI, prior-bundle and installed-package tests; six-observation offline demo.
- [ ] Effective browser policy, session/cookie-purpose evaluation, redirects/crawling and authenticated application checks remain outside this collector.

## Structured Kubernetes JSON observations — 0.17.0

- [x] Ten explicit candidate families across supported Pod/workload templates and nested Lists.
- [x] Standalone JSON/HTML CLI, shared local/GitHub project analysis and existing scan/batch reports.
- [x] Parser/selection bounds, source-free JSON pointers, type/OS/resource gaps and synthetic installed-package acceptance.
- [ ] YAML/Helm, admission/default/inheritance evaluation, cluster/RBAC/network/runtime/image analysis, Windows Pod controls and standards conformance remain separate work.

## Go checksum-record inventory — 0.18.0

Implemented bounded `go.sum` module-content identities through local/GitHub dependency routes, synthetic OSV payload validation and installed offline demo acceptance. See [GO.md](GO.md). Next dependency work should resolve the selected build graph and replacements before making applicability claims; other languages and application data flow remain separate work. API setup remains deferred.

## Python web API candidates — 0.19.0

Implemented explicit Jinja autoescape, Django/MarkupSafe trust-marker and literal PyJWT-style signature-option observations in the shared AST reviewer. See [CODE_REVIEW.md](CODE_REVIEW.md). Next depth work requires scoped symbol/data-flow analysis and framework/runtime applicability, rather than interpreting these syntactic candidates as confirmed vulnerabilities. API setup remains deferred.

## Bounded Python input flow — 0.20.0

Implemented selected straight-line Flask request origins, string/assignment propagation and shell/recognized SQLite sinks with line-only evidence and explicit gap notices. See [PYTHON_FLOW.md](PYTHON_FLOW.md). Broader stacks, control-flow graphs, cross-function propagation, heap effects, framework binding and real applicability validation remain separate work; this stage does not complete general data-flow analysis. API setup remains deferred.

## Local branch joins and loop abstraction — 0.21.0

Implemented possible-origin joins for selected if/else/elif, conditional/boolean expressions and one-pass for/while abstraction, preserving definite API identities and excluding terminated branches. See [PYTHON_FLOW.md](PYTHON_FLOW.md). Full control-flow graphs, feasibility/condition correlation, loop fixed points, break/continue, exceptions and interprocedural propagation remain future work. API setup remains deferred.

## Bounded same-file function contexts — 0.22.0

Implemented prior-defined module-level helper argument/return propagation with strict binding, known callable/SQLite descriptors, bounded contexts, recursion stopping and source/call-site line evidence. See [PYTHON_FLOW.md](PYTHON_FLOW.md). This is not general interprocedural analysis: forward or imported helpers, nested closures, methods/decorators, variadics, runtime global effects and callee exception propagation remain unresolved. API setup remains deferred.

## Selected root Python modules — 0.23.0

Implemented a bounded supplementary pass over collected flat root modules, resolving selected absolute sibling imports and function descriptors without execution. See [PYTHON_PROJECT_FLOW.md](PYTHON_PROJECT_FLOW.md). General package/src/relative/dynamic resolution, runtime import selection and initializer/global effects remain unresolved; this is not whole-program correctness or vulnerability validation. API setup remains deferred.
