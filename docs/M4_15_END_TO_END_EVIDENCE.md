# M4.15 combined owner and Bandit acceptance

## Trust and ownership

A root test coordinator prepares the existing pinned OCI projection and
locked 13-wheel installation as data. It validates ELF closure, creates
ScannerReview with every file digest and seals each file in a memfd using
the existing staging implementation. A sealed, bounded metadata descriptor
identifies the exact entries, roles, resource limits, policy and output.

The broker and launcher receive the same descriptors through explicit
Popen pass_fds before confirmation. They independently check seals, sizes,
content digests and the resulting review fingerprint. Reads use pread, so
neither process changes the other's descriptor offset. The broker closes
these descriptors after building its immutable review and generates its
signing key afterward. The launcher retains them through execution. The
coordinator releases its copies after both subprocesses finish.

Broker UID 62001, owner UID 62002, launcher UID 62003 and agent UID 62004
are distinct unprivileged identities. The coordinator controls code and
directory ancestors. Copied code is root-owned and explicitly mode 0644
with mode 0755 directories, including when the source checkout is on DrvFS.
The broker ledger is private. Agent checks cover ledger access, broker
memory and attempts to open trusted code for writing.

## Authorization and execution

The existing owner client reads the complete record through authenticated
SO_PEERCRED IPC, displays escaped JSON on its controlling PTY and requires
the explicit operation phrase. The coordinator supplies keystrokes to that
PTY in the automated test. This verifies the real confirmation channel
and account boundary, with a synthetic owner decision.

The full review is framed into bounded packets when it exceeds 32 KiB.
The client enforces a 2 MiB total bound and validates the full operation
digest before asking for confirmation. Signing and ledger behavior remain
in the existing broker.

The launcher submits its own capture fingerprint and the operation ID.
It opens the existing supervisor gate only after durable redemption and
a positive authenticated reply. It passes the retained sealed bytes to
Bubblewrap, with the approved seccomp filter as stdin. The scanner receives
no key, original input paths, broker socket or private ledger.

Rootfs and scratch are private tmpfs. Rootfs, input and packages are read-only.
Scratch is limited to 1 MiB. The existing payload checks host canary denial,
socket denial, descriptor closure, imports, plugins and library origins.
The delegated supervisor requires CPU, memory and pids controllers, sets
cpu.max to 20000 100000, memory.max to 128 MiB, swap to zero and pids.max to 8.
The plan records a 60-second timeout and bounded combined output.

Block-device io.max remains BLOCKED. This test exception is confined to
the existing tmpfs-only layout with no writable persistent host mounts.
It provides no production block-I/O assurance.

## Failure injection

Actual Bandit emits a test marker at its analysis-manager entry. Timeout,
cancellation and supervisor-kill tests stop the real sandbox processes with
SIGSTOP after that marker. They then use the existing timeout/cancellation
or recovery mechanisms. They do not replace Bandit with a sleeper.

The SIGKILL case uses the existing private recovery registry and a new
launcher-UID recovery process. The test checks that the registered group
and recorded processes disappear and that redemption stays spent.

Report-size enforcement uses the actual scanner's output. A separate
transport-corruption case truncates the actual returned SARIF before
passing it to the existing importer. Exclusive publication is checked by
attempting a second publication and comparing the original bytes.

## Verification record

Verification of the final revision is pending. Hosted CI reports combined
acceptance as BLOCKED when dedicated cgroup delegation is unavailable.
The separate host command requires root coordination and explicit caches
and delegation through THREAT_LAB_OWNER_E2E_CGROUP,
THREAT_LAB_CPYTHON_OCI and THREAT_LAB_REFERENCE_WHEELS.
