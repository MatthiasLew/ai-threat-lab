# Implementation plan and review checklist

## Order of work

| Step | Deliverable | Status |
| --- | --- | --- |
| 1 | Typed immutable request/result contract and validation | Implemented |
| 2 | Six scenario narratives and versioned control rules | Implemented; rules provisional |
| 3 | Deterministic baseline/residual risk engine | Implemented |
| 4 | CLI commands, guided input and TXT/JSON reports | Implemented |
| 5 | Tests, CI, packaging and ai-dev check configuration | Implemented |
| 6 | Mateusz reviews behavior and agrees product choices | Next |
| 7 | PySide6 screens calling the shared service | Planned |
| 8 | GUI parity checks, presentation and optional PDF | Planned |

## What Mateusz should verify first

1. Run `python -m ai_threat_lab interactive` and try all three scenarios.
2. Compare voice-deepfake analysis with no controls and with callback plus independent approval: 20 → 10 at medium access and normal urgency.
3. Add phishing-resistant authentication to the voice scenario: the payment-risk score should remain unchanged, with an explanation.
4. Save a JSON report; verify that saving again to the same filename fails without replacing it.
5. Check whether stages, warning signs, consequences, and recommended defenses fit the course assignment.

## Product decisions to confirm

- Application language: English is implemented; should the CLI/GUI also support Polish?
- Deadline and minimum presentation scope: CLI alone first, or GUI required for the first review?
- GUI ownership: who integrates PySide6 and when?
- Scoring: accept provisional ordinal rules for the class demo, or refine the rubric before GUI work?
- Reports: are TXT/JSON enough for MVP, or is PDF required for submission?

These decisions do not block review of the current foundation. Do not claim empirical defense effectiveness; calibration is separate future work.

## Offline extension delivery

Brute-force, credential-stuffing and insecure-generated-code narratives are implemented in the catalog. The Python AST reviewer is implemented independently of scenario scoring. The next work remains product review, then GUI integration; future API access does not block either. Candidate future rules and the adapter boundary are documented in EXTENDING_SCENARIOS.md.

## Revised product direction and integration foundation

The project now separates real target assessment from teaching scenarios. The implemented local checks and campaign orchestration are described in ASSESSMENT.md/CAMPAIGNS.md; INTEGRATIONS.md lists exactly which remote/provider capabilities remain absent. Next work is a concrete provider adapter plus its integration tests, rather than more narrative-only scenarios.

Existing project PRs #1 and #2 were merged. Subsequent project work is committed to main per the user's workflow. Problems found in ai-dev are reported as issues going forward.

## Integration-ready offline core (0.3.0)

The named adapter registry, strict versioned artifacts and full offline CLI lifecycle are implemented. The expanded behavioral/subprocess suite and installed-wheel verification are release gates. The next implementation step remains selecting and writing concrete external adapters, followed by their controlled integration tests; no live provider has been silently configured.

## Concrete read-only integrations and cost controls (0.4.0)

GitHub, passive HTTPS, basic DNS and selected Gmail settings collectors are implemented, together with program metadata, local secret/manifest observations and a concrete OpenAI Responses explanation adapter. Budget reservations, request caps, optional caching, concurrent deduplication and reconciliation are implemented and fixture-tested. See LIVE_SETUP.md and API_COSTS.md; these supersede older next-adapter notes above. Real-account validation and unimplemented live training services must not be described as complete.
