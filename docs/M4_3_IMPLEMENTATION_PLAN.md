# M4.3 implementation plan

- Capture bounded project and runtime trees using existing pinned reads.
  Keep immutable bytes in memory and reject incomplete captures.
- Bind those objects, declared runtime roles and parameters to the existing plan.
- Verify a detached owner approval and durably consume it for offline review.
  Require independent custody of the signing key and ledger.
- Test real filesystem substitutions and concurrent SQLite consumption.
- Keep the scanner execution gate closed pending backend handoff.
