# M2 acceptance

Use `python scripts/verify.py` and the existing six-job Windows/Linux CI matrix.
Record revision, platform, test results and skipped or unverified cases here.
Track production validation separately from offline tests.

| Area | Implemented | Offline checks | Production validation |
| --- | --- | --- | --- |
| Worker | Native memory policy, bounded response, timeout and scratch cleanup | Synthetic worker allocation denial, exit, timeout and malformed or oversized output | Pending |
| Filesystem | Pinned roots, Windows reparse metadata and concurrent store creation | Opened-handle, changed-read and parallel publication tests | Pending |
| Cancellation | File and manifest checkpoints | Lifecycle and multi-file regression tests | Pending |
| Benchmarks | Per-rule and per-category scores, three workload sizes and STDIO timing | Versioned local results | Pending representative applications |
| Async MCP | Proposed lifecycle and acceptance cases | Client probing and executable contracts pending | Pending |

Remaining coverage includes ordinary CLI ancestor replacement protection, same-size
changes that preserve metadata, forced termination during publication and transport
closure during synchronous dispatch. Parent cleanup covers supervised exits.

Clean-wheel CI on Windows 3.12 exposed a worker launch failure inside a venv.
The worker now starts the trusted base interpreter with CPython's venv marker,
allowing the supervisor to attach the interpreter itself to its single-process
Job Object. The regression test checks launch and doctor output from a fresh
venv with spaces in its path. The full installed-wheel workflow validates the
same path without a source import override.
