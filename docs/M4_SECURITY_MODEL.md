# M4 security model

The scanner, its runtime, input tree and output are separate trust boundaries.
A plan fingerprint binds fields for review. It proves neither provenance nor
approval. A future launcher must consume the same immutable objects that the
owner approved, rather than reopen mutable paths after hashing.

## Linux

Bubblewrap creates a mount namespace with an explicit mount list. User
namespaces permit unprivileged setup where allowed by the kernel and host LSM.
Private network, PID and IPC namespaces address host networking and process
visibility. The test uses a minimal static payload, a read-only synthetic
input and a size-limited tmpfs. It requires an administrator-installed,
non-setuid Bubblewrap at a standard system path, permission to create the
required namespaces, GCC with static libc and libseccomp for the test.
The test filters socket creation and io_uring setup. A private network
namespace alone still permits UDP to its own loopback. No public server
receives probe traffic. There is no unsandboxed fallback.

Landlock can add inherited access restrictions. Supported operations depend
on the kernel ABI, so probe the required rights. Seccomp can limit syscalls
and further restrict socket creation and exposed kernel interfaces. cgroups
v2 with delegated memory and PID controllers are candidates for aggregate
limits and cleanup. A container is another option if its runtime enforces
equivalent mount, network, credential and resource policies. Namespace
availability alone gives no assurance about those policies.

Sources: [Bubblewrap](https://github.com/containers/bubblewrap),
[Landlock](https://docs.kernel.org/userspace-api/landlock.html),
[seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html),
[cgroups v2](https://docs.kernel.org/admin-guide/cgroup-v2.html).

## Windows

Evaluate an AppContainer or LPAC token with no network capabilities, no
loopback exemptions, explicit read-only snapshot/runtime ACLs and writable
scratch. Check effective access, reparse points and inherited handles.
Restricted tokens and ACLs alone need a separate network policy. A Job
Object is a process and resource control. The existing worker uses one
for its trusted child, while scanner launch would need assignment before
untrusted code runs and aggregate accounting for the full tree. Windows
Sandbox can provide a separate VM with networking disabled and explicit
folder mappings, but depends on host features and a validated lifecycle
and report transport. No host features or firewall rules are provisioned.

Sources: [AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer),
[loopback policy](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/troubleshooting-uwp-firewall),
[Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file).

## Authorization and object identity

The review record is input to a future owner-only approval flow. A trusted
broker should hold a private staged snapshot and runtime through review and
launch. A complete manifest must bind paths, types and content of the input,
interpreter, imports, native libraries and scanner configuration. Reject links,
unexpected entries and partial snapshots. Compute the digests on the same
objects passed to the backend and retain the handles or mount the private
immutable objects. Reopening the original path after a matching digest permits
a second replacement. The existing pinned-scope regression covers directory
replacement before access, while the fingerprint tests cover changed runtime
files on reread.

Approval must be issued by the owner for a single plan and launch, expire, and
be consumed atomically with the backend and runtime identity check. No agent
operation issues approval. The current fingerprint records review intent only.

M4.3 adds bounded immutable review objects and an offline approval ledger.
See the [authorization API](M4_3_AUTHORIZATION_API.md) for key custody,
rollback semantics and remaining loader and sandbox handoff requirements.

## M4.4 test handoff

A Linux acceptance test redeems a synthetic owner's approval, stages the
captured static fixture, seccomp filter and approved input in sealed memfds,
and supplies only those file bytes to Bubblewrap. It imports the fixture's
bounded SARIF output after successful exit and publishes exclusively. The
test uses the existing namespace probe. Existing timeout and parent-death
probes cover descendant termination separately.

Ledger checks reject linked ancestors, hardlinks and unsafe SQLite sidecars.
These checks assume exclusive custody of the parent directory. They do not
prevent races with a writer to that directory or detect rollback to a copy
with the same ledger identity. An unconsumed approval can become valid again
after clock rollback. A consumed nonce stays spent in the intact ledger.
Symmetric key holders can issue approvals. Production issuance requires an
independently authenticated owner channel and isolated key custody.

M4.6 tests quota throttling and explicit recovery of recorded groups.
See [M4.6 plan](M4_6_IMPLEMENTATION_PLAN.md) for the trusted registry boundary,
the pre-recording crash window and the unverified block-I/O control.

M4.7 adds an offline pinned inventory and an owner-review demonstration.
Runtime resolution and production owner authentication remain blocked.
See [M4.7 evidence](M4_7_IMPLEMENTATION_PLAN.md).

M4.8 verifies the locked wheel set as data. Interpreter and loader closure remain unverified.
