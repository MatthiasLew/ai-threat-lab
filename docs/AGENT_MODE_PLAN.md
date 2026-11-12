# Agent Mode integration

Reuse all nine tools from PR #12: security_capabilities, security_plan,
security_scan, security_status, security_summary, security_findings,
security_finding_detail, security_compare, security_limitations. Keep schema 1.0.
The CLI and MCP share AgentService, the fixed worker and ScanService. No shell,
repository edit, model, network or communication operation is exposed.

Review strict schemas, fixed startup root, snapshots, link/race handling,
request/response/file/entry/depth budgets, worker exit/deadline behavior and
manifest-last publication. Treat source/report strings as untrusted data and
redact secrets; a prompt-injection warning is not a model-side enforcement claim.
Report unsupported target types honestly; do not advertise all nonnetwork
analyzers as available if Agent Mode cannot route their target kind.

Re-run existing adversarial tests and installed STDIO negotiation/discovery/calls.
Measure scripts/benchmark_agent_mode.py, retaining reference/status/limitation
parity. Bytes are not token counts. No hidden watcher: explicit CLI/MCP scan and
compare support the before/after workflow documented in AGENT_INTEGRATION.md.

Cancellation of an active MCP call is not currently asynchronous: the synchronous
server dispatches one call at a time, bounded by the fixed worker deadline. Any
future asynchronous jobs require a separately versioned contract; do not pretend
security_status polls a running job (it verifies committed bundles).
