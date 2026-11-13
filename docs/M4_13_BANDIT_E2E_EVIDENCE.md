# M4.13 evidence

Delegated WSL2 ran Bandit 1.7.8 under pinned CPython 3.12.12. The sealed
OCI and wheel files were copied into Bubblewrap's private tmpfs root before
the payload was launched. The probe checks tmpfs for root and scratch,
read-only root, scratch capacity, no device/proc/sys mounts, network
denial, hidden host canary, read-only input and closed staging descriptors.
No persistent host directory is mounted. CPU, memory and task limits
are applied by the delegated supervisor. Block I/O remains unverified.

The B101-only configuration scans one repository-owned Python file as
data. The clean fixture exits 0 with no observations. The assert fixture
exits 1 with one LOW/HIGH B101 observation. Both successful producer
reports pass the saved Bandit SARIF importer. Invalid YAML exits 2 and
produces no publishable report.

Hosted CI runs the pinned import diagnostic and existing containment and
failure probes. The real scanner cases require delegated cgroups and are
reported as blocked on runners without them. Existing synthetic probes
cover timeout, cancellation, output overflow, OOM and supervisor death.
These failure modes are not all injected into the actual scanner.
