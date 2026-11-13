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

The M4.3 offline slice implements captured review objects and one-time
redemption. The next integration must close runtime resolution and hand off
the same objects to the backend without reopening mutable source paths.

M4.4 exercises a fixed Linux fixture through offline approval, sealed file
handoff and SARIF publication. Continue with production runtime closure,
Windows sealed object handoff and integrated aggregate limits before
considering any scanner execution.

M4.5 exercises the fixed Linux handoff with delegated memory and task limits,
bounded supervision and safe result publication. External crash reconciliation
and production runtime closure remain open.

Next Linux work covers block-I/O validation and registry crash-window recovery.
