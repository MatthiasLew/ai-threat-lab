# M4 progress report

## Integration

Main is at `f1c3bf3`. The open stack is
[#14](https://github.com/MatthiasLew/ai-threat-lab/pull/14),
[#15](https://github.com/MatthiasLew/ai-threat-lab/pull/15),
[#17](https://github.com/MatthiasLew/ai-threat-lab/pull/17),
[#18](https://github.com/MatthiasLew/ai-threat-lab/pull/18),
and [#19](https://github.com/MatthiasLew/ai-threat-lab/pull/19).
The first three PRs passed the six-job matrix on their reviewed heads.

## Coverage and Linux

Before hardening, combined coverage was 91.9% on Linux and 92.2–92.3% on
Windows. Branch-only coverage was 88.98% and 89.13–89.16%, respectively.
The expanded regression suite reached 92.7–92.8% combined and 90.07%
branch-only on Ubuntu. Windows Python 3.14 reached 92.9% combined and
90.20% branch-only. The final CI workflow enforces both thresholds using
unrounded counters. See the checks on #18 and #19 for the final commit matrix.

Ubuntu CI requires real Bubblewrap and seccomp probes. They cover the
pre-execution filter, filesystem and scratch, descendants, environment
and descriptors, loopback TCP/UDP, timeout and supervisor death. No
unsandboxed fallback is available.

In WSL2 a transient user systemd service enforced a four-task limit and
64 MiB aggregate memory limit. Separate synthetic workers triggered
an OOM event, and a transient control group terminated its remaining child
after its main process received SIGKILL. These checks used the existing
user service manager and left global cgroup settings intact. Scanner
integration, delegated CI coverage, atomic placement and direct cgroup.kill
remain unverified.

## Windows and authorization

Four local native tests covered the capability-free AppContainer token,
read-only input, private canary and junction denial, scratch writes,
handle exclusion, local IPv4/IPv6 TCP and UDP delivery, Job Object
assignment, child denial, timeout, supervisor death and pinned-scope
directory substitution. The symlink case runs when host policy permits
creating it. Tests own their temporary profile and fixtures. See
[probe details](M4_WINDOWS_APPCONTAINER.md).

The review fingerprint and substitution tests cover the review record.
A production launcher needs owner-issued, expiring, single-use consent
and a broker that keeps the same immutable input and complete runtime
objects from review through launch. The current code grants no launch
authority.

## Conditions for Bandit execution

Require platform-specific filesystem and network acceptance, pinned
immutable input and runtime with complete dependency/configuration identity,
single-use owner approval, aggregate process budgets, cancellation and
crash cleanup, and bounded publication through the existing SARIF importer.
Also require production tests for Windows reparse-point races and scratch
limits and Linux aggregate budgets integrated with Bubblewrap. The scanner
command remains blocked on both platforms.

## M4.3

Bounded project and runtime captures, manifest binding and durable one-time
offline approval are implemented. Production owner interaction, runtime
resolution and direct backend handoff remain launch gates.
See [M4.3 acceptance](M4_3_ACCEPTANCE.md).

M4.6 verified delegated CPU throttling and recorded-group recovery after SIGTERM and SIGKILL on WSL2. Block-device I/O remains unverified.

The open stack extends from #19 through #20 (offline approval), #21 (sealed
Linux test handoff), #22 (delegated supervision) and #23 (CPU and recovery).
The Linux cgroup evidence comes from delegated WSL2, while hosted CI runs
the mandatory namespace and synthetic handoff tests. M4.7 verifies the
upstream Bandit wheel identity and reviews captured inventory offline.

M4.8 pins thirteen reference wheels and exercises memfd staging of captured artifacts. Real Bandit execution remains blocked.

M4.9 builds a validated package tree from the locked wheels. The CPython OCI candidate is pinned; real Bandit remains blocked.
