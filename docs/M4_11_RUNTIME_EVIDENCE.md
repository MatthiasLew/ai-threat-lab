# M4.11 runtime evidence

The test-only runtime mounts files from the pinned CPython OCI image and the
13 RECORD-validated wheels. Static readelf checks x86-64 ELF objects and
resolves transitive DT_NEEDED from the projected image. It accepts the
reference loader and the pinned ORIGIN-relative library path. Tk is omitted
because the reference image lacks its native dependency.

In Bubblewrap, CPython 3.12.12 loads stdlib from /usr/local/lib/python3.12 and
Bandit, PyYAML with its native extension, Stevedore, Rich and SARIF modules
from /packages. The diagnostic records the finder list, module paths,
plugin names and ELF dependency map. It checks that the observed module
paths are present in the mounted tree. It denies sockets, host canary
reads, runtime writes and inherited staging descriptors.

The delegated WSL2 suite passed 29 tests with one Windows-only skip.
The import probe has CPU, memory and task limits there. Hosted CI does
not claim delegation. Static dependencies and observed imports do not
establish closure for arbitrary dlopen, every plugin path or scanner inputs.
A real Bandit scan remains blocked, pending block I/O, crash recovery and
controlled scan/report acceptance. Production also requires owner IPC,
key and ledger custody, and Windows handoff.
