# Engine, CLI and Agent Mode stabilization — 2026-11-10

## Outcome and scope

This work continues [PR #12](https://github.com/MatthiasLew/ai-threat-lab/pull/12)
on current upstream main c90d8b9, reusing its ae953a1 Agent implementation. It
does not merge main, implement GUI, add analyzer families or call paid AI.

The original local checkout fbcc28e lacked the later privacy/consent fixes and
Agent Mode. Those changes were already available upstream and were reused.
Issues #7–#11 are closed; their regressions remain in
`tests/test_audit_regressions.py`, not replaced by this work.

## Source- and test-backed audit

| Component | Established behavior / reuse | Gap or residual risk | Evidence |
| --- | --- | --- | --- |
| ScanOptions / ScanService | One pipeline, explicit network/host/sharing options, independent module failures, new output directory, optional baseline | In-process collectors do not have universal hard deadlines | scan_engine.py; test_scan_workflow.py |
| Assessment / source / configuration | AST/data inspection, no target imports; existing budgets and rule meanings retained | Ordinary Windows traversal entered directory junctions; reproduced and fixed. Ordinary ancestor replacement races are not fully isolated | assessment.py, local_inventory.py, code_review.py; test_local_input_boundaries.py |
| Dependencies / remote audit | Existing exact-version inventory, explicit OSV sharing and host-gated collectors retained | Version matches do not prove reachable vulnerabilities; live account validation excluded | test_dependencies.py, test_github_scan.py, test_remote_audit.py |
| Bundle / history / comparison | Manifest-last new-path publication; hashes and derived reports checked; coverage/failure mismatches suppress definitive deltas | Hashes are local consistency, not authenticity; interrupted/killed processes require verification | scan_bundle.py, local_history.py; test_scan_bundles.py, test_report_consistency.py |
| Finding details | Existing IDs/status/priorities/evidence and deterministic guidance retained | Candidates are not confirmed vulnerabilities; absence does not prove remediation | finding_details.py; test_agent_mode.py |
| PDF / AI / exports | Saved-report exports remain source-independent; redaction, context root, packet/digest binding and exact AI preview gates retained | Pattern redaction cannot anonymize arbitrary content; live prices/model quality are not tested | test_audit_regressions.py, test_ai_costs_closure.py |
| Guided menu / CLI | Existing profiles/consent/destination/export flows reused; new stages/history/details/compare/diagnostics connected | Legacy console remains available; not every diagnostic label/evidence sentence is translated | interactive_menu.py, audit_console.py; test_audit_console.py and stage5 suites |
| Agent CLI / MCP | Same nine tools, strict schema1.0, local approved root, bounded snapshots, private verified reads, fixed worker/deadline | Synchronous calls; status verifies committed runs; no OS memory quota or downstream-model injection enforcement | agent_*.py; test_agent_mode.py, test_agent_races.py |
| GUI API | Existing signatures/results preserved; optional keyword-only events/control, PDF capability corrected | Consumers own their worker thread/queue, callback behavior and collector thread safety | gui_api.py; test_scan_lifecycle.py; GUI_API_HANDOFF.md |
| CI / installation | Existing six Windows/Linux Python3.12–3.14 jobs and >=90% branch-coverage gate retained | Offline tests do not establish production readiness or live-provider correctness | .github/workflows/ci.yml, check_installed_package.py |

Independent static security reviews of the important input, transport, parser,
report and agent boundaries did not establish a new reportable vulnerability.
This was **partial source security coverage**, not an exhaustive review of every
file. Deterministic POSIX replacement and changed-read tests supplement static
reasoning; Windows replacement races, terminal closure and adversarial peak RSS
remain explicit follow-ups. The managed security artifact was started on the
original fbcc28e checkout and flags revision drift; it is not a certification of
the final branch SHA. The functional regression results below are the evidence
for this implementation.

## Implemented changes and regression controls

- `scan_lifecycle.py`: immutable version1 events, per-operation ID/sequence,
  callback isolation and single-use thread-safe ScanControl.
- `scan_engine.py`: module start/completion/failure/skips, cancellation checkpoints,
  final publication gate, explicit interrupted-publication state; no second engine.
- `gui_api.py`: optional on_event/control and public ScanEvent/ScanControl/
  ScanCancelled; PDF in capabilities. Existing bundle/result fields unchanged.
- `scan_cli.py`: opt-in --progress JSONL on stderr, pure JSON stdout and code130;
  publication interruption does not falsely claim no committed output.
- `audit_console.py` / `interactive_menu.py`: bilingual stage labels, verified
  history, one-finding details, comparison, diagnostics and terminal-control escaping.
- `assessment.py` / `local_inventory.py`: reuse junction-aware exclusion;
  `code_review.py` / text inventory reuse bounded regular-file reads.
- `agent_mcp.py`: complete serialized JSON text mirror for clients that do not
  consume structuredContent; schema1.0 and nine tool names retained.

Specific new regressions:

| Test | What it establishes |
| --- | --- |
| test_ordinary_collectors_do_not_follow_directory_junction | Failed before fix on Windows; outside.py via junction disappears while inside.py remains |
| test_text_fifo_does_not_block_inventory | POSIX FIFO in a recognized text extension cannot hang the CLI process |
| test_python_link_rejection_keeps_scope_diagnostic | Preserve the scope diagnostic when source links are rejected before SARIF rendering; covers the Linux CI regression |
| test_gui_free_event_contract_and_existing_report_compatibility | Ordered/versioned service events and readable existing bundle contract |
| test_cancel_before_publication_preserves_previous_run | Cancellation at multiple boundaries creates no new committed run and preserves prior data |
| test_cross_thread_cancel_does_not_cancel_parallel_operation | Separate control/output lifetimes under concurrent scans |
| test_interrupt_during_publication_is_not_claimed_uncommitted | Ctrl+C after the commit gate requires verification rather than a false rollback claim |
| test_real_cli_progress_keeps_stdout_json | Real process, Unicode/spaces, stderr stage JSON and no ANSI |
| test_history_summary_detail_compare_and_corrupt_run | Both languages use verified services and reject corrupt runs |
| test_history_names_and_saved_strings_cannot_emit_terminal_controls | Saved strings cannot emit raw terminal escape commands in the new history view |
| test_change_during_read_is_rejected_and_unchanged_file_is_readable | Changed-read rejection with a positive readable control |
| test_replacement_between_path_check_and_open_cannot_return_outside_bytes | POSIX no-follow opened-object control defeats a deterministic link replacement |
| test_mcp_all_tools_use_shared_services | All nine tools, strict inputs and text/structured JSON parity |

## Executed validation

Windows / Python3.14: full branch-coverage suite **3690 passed,26 skipped** in
566.93s. Final focused coverage pass after adding the last controls:
**20 passed,2 platform-specific skips**. Combined coverage **92.3%**, gate90%
unchanged. The extra tests are not presented as a second full run.

AI Dev1.3.1: version/help, project scan, plan, bounded context, fast uncached Ruff,
git inspect and affected-tests execution all completed. The affected selection
used its Python3.13 interpreter and passed **54 tests,3 skips**. Upstream
[AI Dev#126](https://github.com/MatthiasLew/ai-dev-cli-tools/issues/126) is closed
as completed; the installed1.3.1 predates the fix. No new reproducible AI Dev defect
was found, and AI Dev is not an application dependency.

Wheel/sdist build and final installed-wheel acceptance succeeded locally.
[CI42812389626](https://github.com/MatthiasLew/ai-threat-lab/actions/runs/42812389626)
on4882faa passed all six Windows/Linux × Python3.12/3.13/3.14 jobs, each including
Ruff, full coverage, wheel/sdist and clean installed acceptance.
Windows/Python3.14: **3714 passed,7 skipped,92.4%**;
Linux/Python3.14: **3718 passed,3 skipped,92.3%**. The CI90% gate is unchanged.
The PR carries subsequent final-documentation checks. Installation acceptance uses
an isolated venv, no-index /
no-deps wheel installation, module/executable entrypoints, offline workflows,
Unicode/spaces and real MCP initialize/discovery/calls/EOF.

The first Linux CI pass exposed a diagnostic regression in the existing
`test_resolved_symlink_escape_is_rejected`: earlier link rejection used the
generic report-reader message instead of the expected scope message. Source
link rejection now retains the scope diagnostic; the existing test was not
weakened or skipped. All six jobs were rerun successfully on the correction.

## Measurements and interpretation

Raw outputs: [engine benchmark](benchmarks/2026-11-10-engine.json),
[Agent benchmark](benchmarks/2026-11-10-agent.json). Reproduce with
`scripts/benchmark_security_engine.py` and `scripts/benchmark_agent_mode.py`.
Measured on Windows/Python3.14 during local validation; fixture source/options are
in those scripts, with no target code execution, network or models.

| Fixture / operation | Measured result |
| --- | --- |
| 1-file scan, two repeats | 0.101–0.246s with tracemalloc; ~0.40MB traced Python peak |
| 100-file scan, two repeats | 0.420–0.907s with tracemalloc; ~1.20MB traced Python peak |
| 100-file saved verification | 0.100–0.109s |
| 100-file report JSON serialization | 0.00052–0.00104s,29745B |
| 100-file PDF export | 0.182–0.231s |
| 30-candidate raw report / full Python facade | 18638B / 372864B |
| Agent summary | 748B |
| All references/limitations plus one detail | 16015B |
| Selective MCP responses with framing and JSON text mirror | 34057B, excluding requests/discovery |

These are local synthetic observations, not universal speed/savings claims.
Tracemalloc changes timing and omits native/child allocations; it is not OS RSS.
No cache or security-check removal was introduced. The Agent benchmark asserts
ID/rule/status/priority, limitation and failure-count parity; summary alone is
not equivalent to complete results. No tokenizer was used.

The pre-existing synthetic analyzer corpus test checks19 positive,18 negative and
3 explicitly unsupported cases. Its green assertion is not representative
real-world precision/recall. Broader per-rule/category evaluation and adversarial
large-input/RSS benchmarks remain Q1/R1 in the TODO.

## What can be used now and what remains

The tested offline CLI, guided history/review/export flows, Agent CLI/MCP and
Python event/cancellation contracts are available for bounded local workflows.
The caller still reviews candidates, failures and limitations. Network and paid
AI integrations retain explicit consent and have not received live validation.

Cooperative cancellation waits for a collector to return; hard process death may
produce no final event. MCP has no async job/cancel API; the worker has a deadline,
not an OS memory sandbox. Broader race/resource and effectiveness validation must
precede stronger production-readiness claims. No merge to main was performed.
