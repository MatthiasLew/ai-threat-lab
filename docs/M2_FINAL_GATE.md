# M2 final gate

| Priority | Criterion | Initial status | Completion evidence |
| --- | --- | --- | --- |
| P0 | Representative detector corpus | IN_PROGRESS | Pinned, independently labelled in-scope positive, close negative, multiple files, configuration, and an unsupported case with per-input hashes and outcomes |
| P1 | Performance regression | IN_PROGRESS | Same-host A/B with warmed repetitions, equivalent findings and phase timings with and without tracemalloc |
| P0 | MCP process behaviour | IN_PROGRESS | Real pipes and isolated process termination on Windows and Linux, with bounded responses and a recorded decision on synchronous dispatch |
| P0 | Publication | IN_PROGRESS | Existing integrity, no-overwrite, I/O failure and commit-boundary regression tests pass |
| P0 | Release verification | IN_PROGRESS | Six platform/interpreter jobs pass, including branch coverage at 90% or above, distribution builds and clean installation |
| P2 | Power loss and full snapshot isolation | DEFERRED | Document as architectural limits outside offline M2 |
| P2 | Descendant RSS and asynchronous MCP | DEFERRED | Separate research and implementation milestones |
