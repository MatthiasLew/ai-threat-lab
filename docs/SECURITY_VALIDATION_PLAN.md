# Security validation — current iteration

## Gates

- Focused engine/API/CLI/MCP lifecycle and file-boundary regressions.
- Existing #7–#11 regressions in tests/test_regressions.py and report/menu suites.
- Ruff, full pytest under branch coverage >=90%, wheel/sdist build, clean installed
  wheel acceptance, real STDIO MCP. No paid AI or live-account calls.
- Existing CI matrix: Windows/Linux × Python 3.12/3.13/3.14, unchanged coverage gate.
- Existing synthetic analyzer quality corpus and agent response-size benchmark;
  do not claim real-world recall from this corpus or coverage percentage.

## Boundaries and risks

Source, manifests and imported reports are hostile data. Review path traversal,
symlink/junction/hardlink handling, changed inputs, output exclusivity, corrupted
bundles, malformed/oversized requests, process exits and timeouts. Preserve failed
module and skipped-check notices in every consumer. In-process cancellation is
cooperative; killed processes cannot acknowledge cancellation. Source snapshots
are bounded non-atomic copies, not a filesystem transaction.

AI Dev 1.3.1: --version/help, scan, plan and context build completed. Upstream #126
is closed as completed (checked 2026-11-10); do not assume the installed 1.3.1 has
the fix. Use an absolute project interpreter for authoritative tests. Optional
AI Dev failure must not become an application runtime dependency.

Results, exact counts, coverage and CI links are added after execution, never
inferred from historical runs. The security review has a separate managed Codex
Security artifact; unresolved scope there must remain explicit.
