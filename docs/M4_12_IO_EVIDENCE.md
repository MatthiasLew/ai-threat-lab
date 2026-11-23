# M4.12 block I/O evidence

Status: BLOCKED on the available WSL2 host. The delegated subtree exposes
cpu, memory and pids. No approved disposable block filesystem was supplied.
No read/write rate or io.stat result is claimed.

On an authorized disposable filesystem, set THREAT_LAB_IO_SCRATCH and
THREAT_LAB_IO_DEVICE (major:minor) and run test_delegated_block_io inside the
delegated subtree. The fixture checks the filesystem device and controller,
uses bounded direct I/O on a private temporary file, and requires both
kernel accounting and a slowdown against an unrestricted baseline. It runs
only a trusted dd fixture. Shared-bandwidth and cancellation during block
I/O still require validation.
