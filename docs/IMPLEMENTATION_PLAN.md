# Implementation and verification order

## Active workflow

1. Use `ai-dev-cli-tools` to map the repository, plan the change and check its configured gates. Report problems in that tool as issues in `MatthiasLew/ai-dev-cli-tools`; do not create unsolicited PRs there.
2. Reproduce a confirmed defect before changing production code. Keep positive controls so a fix cannot simply disable a feature.
3. Inspect adjacent cases and affected entrypoints. Prefer independent language/protocol behavior over assertions copied from the implementation.
4. Implement the smallest coherent correction with explicit limits and failure evidence.
5. Run focused tests, then `python scripts/verify.py` for the release. Preserve old report reading and suppress comparisons if observation semantics change.
6. Update scope, acceptance fixtures and delivery documentation. Publish directly on the project's main branch and verify the six CI jobs at that exact commit.

The finite acceptance checklist is [OFFLINE_RELEASE_CRITERIA.md](OFFLINE_RELEASE_CRITERIA.md). Feature expansion is paused while confirmed defects or required acceptance gaps remain.

## Current implementation

| Area | Current state | Completion boundary |
| --- | --- | --- |
| Domain/catalog | Validated immutable contracts and teaching scenarios | Scores are explanatory models, not measured defense effectiveness |
| Target assessment | Bounded local checks and fixture-tested read-only collectors | Actual account validation and deeper application/binary analysis remain separate |
| Python analysis | Selected syntax/flows, package/importlib links and SQLite contexts | Candidate evidence with explicit semantic/resource gaps |
| Reporting | Text/JSON/HTML, standalone Python SARIF, scan/batch bundles and comparison | Local evidence consistency, not source authenticity or confirmed vulnerabilities |
| Local training | Three text rehearsal channels, exact approvals and durable actions | Scripted local choices, no live delivery/media or observed employee telemetry |
| AI costs | Budgeted explanation adapter, dry-run/cache/reservations | API setup and live billing/quality validation deferred |
| Packaging | Full tests, coverage, clean-wheel workflow and Linux/Windows CI | Evidence is tied to the tested commit |

## Review without API setup

```bash
python -m ai_threat_lab --help
python -m ai_threat_lab doctor
python -m ai_threat_lab readiness
python -m ai_threat_lab offline-demo --output-dir demo-review
```

Inspect `demo-review/index.html` and its generated report links. Verify the completed demo summary and bundle checks, not only terminal success. Existing output paths must be rejected instead of replaced. Use a new directory for each run.

Automated verification is documented in [TESTING.md](TESTING.md). The demo uses synthetic fixtures and local rehearsal storage; target sources are parsed, never imported or executed by the scanner.

## Decisions for later deployment

The next full-product work needs a chosen repository/framework, owned web test application, mailbox provider or consented training environment and its acceptance criteria. These choices do not prevent the existing offline acceptance work. They do prevent claiming complete real-world coverage from an unspecified target.

The agreed ordering is CLI first, API/account work later, GUI later. Follow [ROADMAP.md](ROADMAP.md) for the separately scoped expansion tracks and [DELIVERY_STATUS.md](DELIVERY_STATUS.md) for current implementation limits.
