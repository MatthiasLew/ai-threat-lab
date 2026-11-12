# M2 acceptance

Use `python scripts/verify.py` and the existing six-job Windows/Linux CI matrix.
Record revision, platform, test results and skipped or unverified cases here.
Track production validation separately from offline tests.

| Area | Implemented | Offline checks | Production validation |
| --- | --- | --- | --- |
| Worker | Native memory policy, bounded response, timeout and scratch cleanup | Synthetic worker allocation denial, exit, timeout and malformed or oversized output | Pending |
| Filesystem | Pinned project identity and opened-handle reads in local scan collectors and saved reports | Directory identity, junction, changed-read and parallel publication tests | Pending filesystem variants and metadata-preserving writes |
| Cancellation | File and manifest checkpoints | Lifecycle and multi-file regression tests | Pending |
| Benchmarks | Per-rule and per-category synthetic scores; Flaskr negative controls | Versioned results by corpus | Pending broader labelled positives and negatives |
| Synchronous MCP | Quiet exit on closed output; in-flight dispatch may still commit | Real STDIO closure and actual worker publication | Abrupt supervisor death and unconsumed output remain open |
| Publication | Complete manifest made visible in one no-overwrite operation | Forced exit before directory claim, mid-artifact and before/after marker | Power loss and complete interruption matrix not covered |

On Linux the worker limit is 512 MiB of virtual address space and at most 128
open descriptors. On Windows it is 512 MiB of aggregate committed memory for
a Job Object with one active process, assigned before sending input. Neither
measures resident memory. Parent cleanup covers supervised exits. A client
disconnect is not a cancellation signal during synchronous dispatch.

Clean-wheel CI on Windows 3.12 exposed a worker launch failure inside a venv.
The worker now starts the trusted base interpreter with CPython's venv marker,
allowing the supervisor to attach the interpreter itself to its single-process
Job Object. The regression test checks launch and doctor output from a fresh
venv with spaces in its path. The full installed-wheel workflow validates the
same path without a source import override.
