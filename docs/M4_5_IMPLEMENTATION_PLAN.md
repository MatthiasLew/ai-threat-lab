# M4.5 implementation plan

Reuse the fixed Bubblewrap and seccomp fixture and its sealed inputs. Bound both
output streams and supervise with a monotonic deadline. On delegated hosts,
configure a private cgroup before releasing a trusted gate into Bubblewrap.
Run the delegated tests separately from hosted namespace checks. Production
execution stays blocked pending platform and runtime acceptance.

## Verification and recovery

Hosted Ubuntu runs the existing mandatory namespace tests plus bounded
supervision and SARIF failure cases. It does not claim delegated coverage.
Set THREAT_LAB_DELEGATED_CGROUP to a private delegated cgroup v2 parent with
memory and pids enabled, and set THREAT_LAB_REQUIRE_CGROUP=1 alongside
THREAT_LAB_REQUIRE_BWRAP_PROBE=1. Start pytest within the same delegated
subtree. The trusted isolated gate waits for a byte before exec and the
supervisor confirms membership first. No global controllers are changed.
See [kernel delegation and kill semantics](https://docs.kernel.org/admin-guide/cgroup-v2.html).

Normal exits and handled failures kill and drain the private group and remove
it. Bubblewrap parent-death probes cover descendants after launch. SIGKILL
of the supervisor can leave an empty cgroup directory. External crash
reconciliation and separately enforced CPU and I/O budgets are still open.

## Windows follow-up

1. Verify immutable staging and direct handle handoff into AppContainer.
2. Exercise atomic Job Object assignment and aggregate tree limits.
3. Verify scratch quotas and external network denial independently.
4. Test profile recovery after supervisor death, then integrate bounded SARIF.
5. Review runtime closure and production authorization separately.
