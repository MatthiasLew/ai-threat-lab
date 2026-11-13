# M4.3 acceptance

- Capture either returns a complete bounded manifest or fails. Links, special
  files, changed entries and oversized trees are rejected.
- Source replacement cannot change captured bytes. Changes to any runtime role,
  sandbox policy, scope, output or resource limit invalidate approval.
- A signed approval expires and at most one consumer can redeem it. A rollback
  before commit leaves it unused. A crash after commit requires a new approval.
- The offline broker has no launch method. CLI and nine MCP tools stay compatible.
- Both coverage metrics must reach 90% in all six platform/interpreter jobs.
