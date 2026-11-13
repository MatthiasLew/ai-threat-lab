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
