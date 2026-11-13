# M4 acceptance

| Control | Pass criterion |
| --- | --- |
| Linux backend setup | Required namespaces and mounts succeed, or the test reports setup unavailable without running on the host. |
| Linux filesystem | Fixture reads the Unicode input and writes private scratch. Host canary, symlink, input and root writes fail. The source remains intact. |
| Linux network | Positive host controls reach synthetic IPv4 and IPv6 TCP and UDP listeners. The isolated fixture cannot reach any of them or send a synthetic DNS query. |
| Linux inheritance | Child repeats denied accesses, inherited environment marker and descriptors are absent. |
| Linux lifecycle | Timed out and orphaned test payloads close the readiness pipe. The per-process memory limit and scratch capacity reject larger allocations. A second launch sees fresh scratch. |
| Windows | Native APIs are inventoried. The trusted worker rejects an extra process, dies with the supervisor and passes resource and timeout tests. AppContainer confinement remains required for launch. |
| Approval | Changing any plan field changes its fingerprint. Replacing the executable, interpreter or dependency fixture invalidates the fingerprint on reread. No code grants launch authority. |
| Production | Run exits 2 on both platforms. Existing SARIF, offline CLI and all nine MCP contracts pass. |

Production acceptance additionally requires a pinned immutable snapshot and
runtime, race-safe path handling including symlink/junction substitution,
filesystem and network denial for descendants, atomic process-tree resource
limits, cancellation, supervisor death, scratch and result cleanup, and
bounded SARIF publication after successful execution. Any missing critical
control keeps execution blocked on the platform.

To require the real Linux probes, run
`THREAT_LAB_REQUIRE_BWRAP_PROBE=1 python -m pytest -q -rs tests/test_scanner_sandbox.py`.
Without that flag the suite reports missing prerequisites and denied namespace
creation as skips. A failed probe after setup is a test failure in either mode.

Hosted Ubuntu requires actual Bubblewrap probes and fails if the dependencies,
namespace setup or ready-time seccomp control are unavailable. The combined
and branch-only coverage checks each require at least 90% before acceptance.
