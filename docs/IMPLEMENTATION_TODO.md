# Implementation TODO — 2026-11-10

Status vocabulary: TODO, IN_PROGRESS, DONE, BLOCKED. No direct merge to main.

| ID / status | Goal / priority | Modules | Dependencies | Regression risk | Required tests / completion criterion |
| --- | --- | --- | --- | --- | --- |
| A0 DONE | Inspect AI Dev, PR12, issues 7–11 / P0 | upstream metadata, engine, agent, CLI, docs | none | low | PR12 open, reusable on current main; AI Dev help/context/plan actually run |
| A1 IN_PROGRESS | Validate existing safety boundaries / P0 | agent_*, scan_bundle, PDF, providers, tests | A0 | high: hostile inputs | source-backed review, existing adversarial and privacy regressions; record limits |
| A2 TODO | Correct proven defects / P0 | only owning modules | A1 | depends on finding | reproducer before fix plus positive control, focused suite green |
| L1 TODO | Versioned events and cooperative cancellation / P1 | scan_lifecycle, scan_engine, gui_api | A0 | medium: collector/publication flow | order/version/failure/cancel/race/API tests; old call signatures work |
| C1 TODO | Human progress and JSON-safe CLI / P1 | scan_cli, interactive_menu | L1 | medium: output contracts | stderr events, pure JSON stdout, cancellation code, bilingual journey |
| C2 TODO | Real history/details/compare/diagnostics / P1 | interactive_menu, existing facade | A0 | medium: prompts | bilingual simulated history/detail/compare and corruption checks |
| M1 TODO | Agent parity and measured payloads / P1 | agent_service, existing agent scripts/docs | A1,L1 | medium: schemas | nine tools, clean installed STDIO and measured bytes with parity |
| H1 TODO | Document compatible GUI service contract / P1 | gui_api, GUI_API_HANDOFF | L1 | medium: public API | GUI-free contract test, progress/cancel Python examples, thread/lifecycle limits |
| V1 TODO | Full validation and tested PR / P0 | tests, scripts, CI, docs | all above | high: platform differences | Ruff, pytest/coverage >=90%, build, clean install, six CI jobs; PR without merge |
| Q1 TODO | Quantify corpus and performance / P2 | existing benchmark tests/scripts | V1 | low | measured synthetic metrics/timing/memory, methodology and limits |
| F1 TODO | Immediate in-module cancellation / later | collectors | L1 | high: deep propagation | explicit future scope; current contract cancels between modules |
| F2 TODO | Asynchronous MCP cancellation / later | agent_mcp/protocol | M1 | high: protocol lifecycle | needs versioned async contract; existing server is synchronous |
