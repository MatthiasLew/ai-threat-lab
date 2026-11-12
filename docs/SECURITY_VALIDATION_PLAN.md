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

## Executed results

[CI42812389626](https://github.com/MatthiasLew/ai-threat-lab/actions/runs/42812389626)
passed6/6 on4882faa: Windows/Linux × Python3.12/3.13/3.14, including Ruff, full
coverage, wheel/sdist and clean installed CLI/MCP acceptance. Windows3.14:
3714 passed,7 skipped,92.4%; Linux3.14:3718 passed,3 skipped,92.3%. Threshold90%
unchanged. The earlier Linux SARIF diagnostic failure was corrected without
weakening/skipping its existing test. Local AI Dev affected tests passed54/3.

The [implementation report](SECURITY_ENGINE_REPORT.md) records exact local runs,
regression IDs and measured synthetic outputs. The separate managed static
security artifact has partial coverage and flags its original-checkout revision
drift; it does not certify the final branch. Remaining race/resource/corpus work
stays explicit in IMPLEMENTATION_TODO.md. No paid AI/live-provider call was made.

See [M2 acceptance](M2_ACCEPTANCE.md) for post-M1 evidence and open boundaries.
