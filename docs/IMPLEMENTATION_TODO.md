# Implementation TODO — 2026-11-10

Status vocabulary: TODO, IN_PROGRESS, DONE, BLOCKED. No direct merge to main.

| ID / status | Goal / priority | Modules | Dependencies | Regression risk | Required tests / completion criterion |
| --- | --- | --- | --- | --- | --- |
| A0 DONE | Inspect AI Dev, PR12, issues 7–11 / P0 | upstream metadata, engine, agent, CLI, docs | none | low | PR12 open, reusable on current main; AI Dev help/context/plan actually run |
| A1 DONE | Review existing safety boundaries / P0 | agent_*, scan_bundle, PDF, providers, tests | A0 | high: hostile inputs | independent static boundary review and adversarial/privacy tests; security coverage explicitly partial, not every file audited |
| A2 DONE | Correct proven defects / P0 | assessment, local_inventory, code_review, agent_mcp | A1 | local traversal, transport compatibility | Windows junction reproduced failing before fix; positive control passes; regular reads reject special files; MCP JSON mirror parity |
| L1 DONE | Versioned events and cooperative cancellation / P1 | scan_lifecycle, scan_engine, gui_api | A0 | medium: collector/publication flow | test_scan_lifecycle: order/version/failure/cross-thread/parallel/commit interruption; old calls pass |
| C1 DONE | Human progress and JSON-safe CLI / P1 | scan_cli, interactive_menu | L1 | medium: output contracts | real process stderr events/pure JSON stdout, code130, bilingual workflow regression passes |
| C2 DONE | Real history/details/compare/diagnostics / P1 | audit_console, interactive_menu, existing facade | A0 | medium: prompts | bilingual summary/detail/compare, corrupt entry rejection and escaped terminal controls |
| M1 IN_PROGRESS | Agent parity and measured payloads / P1 | agent_service, existing agent scripts/docs | A1,L1 | medium: schemas | nine-tool source tests and measured bytes/parity pass; final installed acceptance pending |
| H1 DONE | Document compatible GUI service contract / P1 | gui_api, GUI_API_HANDOFF | L1 | medium: public API | GUI-free contract tests, progress/cancel Python example, thread/lifecycle limits and corrected result fields |
| V1 IN_PROGRESS | Full validation and tested PR / P0 | tests, scripts, CI, docs | all above | high: platform differences | Ruff green; full local3690/26 plus final20/2 focused pass, coverage92.3%; final build/install and six CI jobs pending |
| Q1 TODO | Broader corpus and performance / P2 | existing benchmark tests/scripts | V1 | low | synthetic1/100-file timing/memory and30-candidate payloads measured; broader per-rule/category/large-file/RSS methodology still pending |
| F1 TODO | Immediate in-module cancellation / later | collectors | L1 | high: deep propagation | explicit future scope; current contract cancels between modules |
| F2 TODO | Asynchronous MCP cancellation / later | agent_mcp/protocol | M1 | high: protocol lifecycle | needs versioned async contract; existing server is synchronous |
| R1 TODO | Extend race/resource validation / P2 | agent_fs, worker, local readers | A1 | platform-specific | deterministic Windows replacement races, terminal closure, adversarial OS-RSS and hard quotas; POSIX replacement and changed-read controls already added |
