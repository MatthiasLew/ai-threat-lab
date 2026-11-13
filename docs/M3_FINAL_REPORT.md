# M3 offline integration report

The stack is [#14](https://github.com/MatthiasLew/ai-threat-lab/pull/14),
[#15](https://github.com/MatthiasLew/ai-threat-lab/pull/15) and
[#17](https://github.com/MatthiasLew/ai-threat-lab/pull/17). Its base is
`f1c3bf30b4cfeacb05216c3de7540b26a5680679`, including the Gemini fixture fix.
Review in stack order and check the base and current CI before each merge.

The candidate extends clean wheel acceptance with a guided local audit,
PL/EN menu, Unicode paths, compatible and structured SARIF, empty, malformed
and incomplete reports, secret redaction and all Bandit subcommands. Existing
installed tests cover history, comparison, export and real STDIO MCP.
See [the checklist](M3_OFFLINE_RELEASE_CHECKLIST.md) and the PR checks for
platform and interpreter results.

The pinned Trivy source tree contains one SARIF golden file, for an image.
The checked-in derivative of an upstream Semgrep dataflow snapshot verifies
that import retains the finding while omitting code-flow details. Authentic
Trivy filesystem and configuration samples remain open. Synthetic regressions
cover selected boundaries without claiming producer conformance.

Execution remains blocked pending [platform isolation](M3_BANDIT_PLANNING.md).
The owner still needs to verify or remediate Secret Scanning alert #2.
