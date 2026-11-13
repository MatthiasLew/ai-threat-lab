# Implementation TODO and historical acceptance

Status vocabulary: TODO, IN_PROGRESS, DONE, BLOCKED. No direct merge to main.

| ID / status | Goal / priority | Modules | Dependencies | Regression risk | Required tests / completion criterion |
| --- | --- | --- | --- | --- | --- |
| A0 DONE | Inspect AI Dev, PR12, issues 7–11 / P0 | upstream metadata, engine, agent, CLI, docs | none | low | PR12 inspected and subsequently merged; AI Dev help/context/plan actually run |
| A1 DONE | Review existing safety boundaries / P0 | agent_*, scan_bundle, PDF, providers, tests | A0 | high: hostile inputs | independent static boundary review and adversarial/privacy tests; security coverage explicitly partial, not every file audited |
| A2 DONE | Correct proven defects / P0 | assessment, local_inventory, code_review, agent_mcp | A1 | local traversal, transport compatibility | Windows junction reproduced failing before fix; positive control passes; regular reads reject special files; MCP JSON mirror parity |
| L1 DONE | Versioned events and cooperative cancellation / P1 | scan_lifecycle, scan_engine, gui_api | A0 | medium: collector/publication flow | test_scan_lifecycle: order/version/failure/cross-thread/parallel/commit interruption; old calls pass |
| C1 DONE | Human progress and JSON-safe CLI / P1 | scan_cli, interactive_menu | L1 | medium: output contracts | real process stderr events/pure JSON stdout, code130, bilingual workflow regression passes |
| C2 DONE | Real history/details/compare/diagnostics / P1 | audit_console, interactive_menu, existing facade | A0 | medium: prompts | bilingual summary/detail/compare, corrupt entry rejection and escaped terminal controls |
| M1 DONE | Agent parity and measured payloads / P1 | agent_service, existing agent scripts/docs | A1,L1 | medium: schemas | nine tools, measured bytes/parity and installed real STDIO pass locally and across six CI jobs |
| H1 DONE | Document compatible GUI service contract / P1 | gui_api, GUI_API_HANDOFF | L1 | medium: public API | GUI-free contract tests, progress/cancel Python example, thread/lifecycle limits and corrected result fields |
| V1 DONE | Full validation and tested PR / P0 | tests, scripts, CI, docs | all above | high: platform differences | Ruff, full coverage, build and clean installed acceptance pass; CI42812389626 green6/6 on4882faa; PR12 later merged |
| Q1 TODO | Broader corpus and performance / P2 | existing benchmark tests/scripts | V1 | low | synthetic1/100-file timing/memory and30-candidate payloads measured; broader per-rule/category/large-file/RSS methodology still pending |
| F1 TODO | Immediate in-module cancellation / later | collectors | L1 | high: deep propagation | explicit future scope; current contract cancels between modules |
| F2 TODO | Asynchronous MCP cancellation / later | agent_mcp/protocol | M1 | high: protocol lifecycle | needs versioned async contract; existing server is synchronous |
| R1 TODO | Extend race/resource validation / P2 | agent_fs, worker, local readers | A1 | platform-specific | deterministic Windows replacement races, terminal closure, adversarial OS-RSS and hard quotas; POSIX replacement and changed-read controls already added |

Validation evidence: [six-job CI](https://github.com/MatthiasLew/ai-threat-lab/actions/runs/42812389626)
and [PR #12](https://github.com/MatthiasLew/ai-threat-lab/pull/12).
Windows/Python3.14:3714 passed,7 skipped,92.4%; Linux/Python3.14:3718 passed,
3 skipped,92.3%. This source-pinned run includes wheel/sdist and installed offline
CLI/MCP acceptance in every job. Later documentation-only commit checks are shown
on the PR. F1/F2/Q1/R1 are real future work, not production-readiness claims.

See [M4 tasks](M4_TODO.md) for current scanner gates and the [release audit](OFFLINE_RELEASE_AUDIT_0_41_4.md) for current verification.

## M2 follow-up — 2026-11-12

Final M1 commit `cda9c80` passed all six jobs in
[CI 42813384348](https://github.com/MatthiasLew/ai-threat-lab/actions/runs/42813384348).
The earlier result above remains tied to `4882faa`. The PR #12 correction at
`6f8eed9` passed [CI 43205191400](https://github.com/MatthiasLew/ai-threat-lab/actions/runs/43205191400).

- DONE — PR #12 review and approved-root correction.
- DONE — Worker output limits, native memory policy, timeout and supervised cleanup.
- DONE — Cooperative cancellation at selected file and manifest boundaries.
- DONE — Retain per-file findings above the project flow input limit.
- DONE — Opened-handle reads for local collectors, with project identity bound for ScanService.
- DONE — Atomic manifest commit and forced exit checks before and after the commit point.
- DONE — STDIO disconnect checks, including committed scan after connection loss.
- IN_PROGRESS — Filesystem edge cases, interruption and abrupt supervisor exit coverage.
- IN_PROGRESS — Representative application corpus beyond the initial Flaskr negative controls.
- TODO — Async client probing and executable contracts (separate lifecycle work).

See [M2 acceptance](M2_ACCEPTANCE.md) for the validation matrix.
