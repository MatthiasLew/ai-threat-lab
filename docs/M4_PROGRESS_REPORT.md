# M4 progress after integration

The integrated baseline is main at ce063f8. The M3/M4 changes from PRs
#14, #15 and #17–#27 are merged. PR #16 separately remediated test credentials.
See [baseline CI](https://github.com/MatthiasLew/ai-threat-lab/actions/runs/43451494387).

## Offline product scope

The CLI supports Polish and English guided audits, local scans, report export,
verified saved history, Agent Mode and nine synchronous STDIO MCP tools.
External SARIF import preserves producer claims as unverified observations.
Bandit discovery, planning and completed saved SARIF import are available.
The production scanner run command returns exit 2.

## Test infrastructure

Linux probes cover Bubblewrap/seccomp filesystem, socket and process
boundaries, sealed file handoff and synthetic SARIF publication. Delegated
WSL2 tests cover aggregate memory and task limits, CPU throttling and
recorded-group recovery. Hosted CI does not establish cgroup delegation.
The separate Linux reference job runs a diagnostic with pinned CPython
3.12.12 files. It checks selected stdlib and native imports, scratch access,
network refusal and read-only runtime. The 13 pinned wheels are validated
and materialized as data in memory. The diagnostic does not load them.

Windows AppContainer and Job Object probes cover synthetic ACL boundaries,
junction denial, IPv4/IPv6 loopback and process lifetime. This evidence
does not cover Windows runtime handoff or external network isolation.
Offline HMAC and SQLite tests verify plan-bound one-time redemption. The
owner prompt is demonstrative and cannot issue launch authority.

## Production gates

Require exact CPython and package handoff with ELF and import/plugin closure,
controlled real Bandit execution and safe SARIF outcome handling. Require an
independent authenticated owner channel and protected key and ledger,
delegated block I/O validation, crash-window and host recovery, and equivalent
Windows staging, scratch quotas and external network controls. See
[M4 roadmap](M4_ROADMAP.md) and [release audit](OFFLINE_RELEASE_AUDIT_0_41_4.md).

M4.11 adds pinned package imports and plugin diagnostics. See [runtime evidence](M4_11_RUNTIME_EVIDENCE.md).
