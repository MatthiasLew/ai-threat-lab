# M4 roadmap

| Order | Proposed PR | Acceptance |
| --- | --- | --- |
| 1 | Prove platform confinement | Inert fixtures confirm filesystem and network policy on Windows and Linux, including descendants, denied setup and cleanup. |
| 2 | Bind authorization and runtime identity | Approval covers the target snapshot, launcher, interpreter and dependencies. Reject substitution and incompatible platform policy. |
| 3 | Expand analyzer validation | Score pinned, independently labelled projects by rule. Record scope, errors and false negatives. |
| 4 | Prototype asynchronous MCP | Specify and test deadlines, cancellation, disconnect and cleanup with a separate contract. |
| 5 | Improve performance | Compare repeated same-host runs with equivalent findings. |
| 6 | Extend CLI integrations | Review each report format, fixtures and privacy policy independently. |

The first two PRs use the [Bandit isolation gates](M3_BANDIT_PLANNING.md).
