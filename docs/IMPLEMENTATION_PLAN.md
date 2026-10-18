# Implementation plan and review checklist

## Order of work

| Step | Deliverable | Status |
| --- | --- | --- |
| 1 | Typed immutable request/result contract and validation | Implemented |
| 2 | Three scenario narratives and versioned control rules | Implemented; rules provisional |
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
