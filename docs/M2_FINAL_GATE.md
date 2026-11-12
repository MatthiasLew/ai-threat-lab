# M2 final gate

| Priority | Criterion | Initial status | Evidence and completion condition |
| --- | --- | --- | --- |
| P0 | Representative detector corpus | IN_PROGRESS | DONE. [Pinned corpus](benchmarks/m2-final-representative.json) has a positive literal configuration observation, parameter-bound SQL negatives, a multi-file slice and an unsupported case. Broader vulnerability recall is a separate research task. |
| P1 | Performance regression | IN_PROGRESS | DONE. [Same-host phase measurements](benchmarks/m2-final-ab.json) record repeated timings, allocation peaks and identical assessment digests. |
| P0 | MCP process behaviour | IN_PROGRESS | Real backpressure and supervisor exit regressions in `tests/test_mcp_stdio_disconnect.py`. Complete when they pass on both target platforms. The [final report](M2_FINAL_REPORT.md) records the dispatch contract. |
| P0 | Publication | IN_PROGRESS | Integrity, exclusive publication, I/O failure and process interruption tests in `tests/test_scan_bundles.py` and `tests/test_scan_lifecycle.py` pass locally. The matrix confirms both platforms. |
| P0 | Release verification | IN_PROGRESS | Complete when [PR #13 checks](https://github.com/MatthiasLew/ai-threat-lab/pull/13/checks) pass all six jobs, including branch coverage at 90% or above, distribution builds and clean installation. |
| P2 | Power loss and full snapshot isolation | DEFERRED | Architectural limits outside offline M2. |
| P2 | Descendant RSS and asynchronous MCP | DEFERRED | Separate research and implementation milestones. |
