# M4.8 implementation and acceptance

Lock the Linux x86-64 CPython 3.12 wheel set with SHA-256, then verify bytes
and metadata offline. Reject missing, extra and modified artifacts. Reuse
captured bytes and memfd for bounded test handoff. A verified wheel set does
not attest CPython, its loader or OS resources. Keep the real execution gate
closed until those controls and owner IPC are verified.

The JSON lock records thirteen wheels for Linux x86_64 CPython 3.12 with
the SARIF extra. Ubuntu 3.12 CI downloads those exact artifacts, checks
hashes, validates distribution metadata and active dependency constraints,
and tests sealed descriptors after replacement of the original files.
The wheel archives are not installed or imported by the test.

Runtime status remains UNVERIFIED. CPython, stdlib, ELF interpreter, shared
libraries, import roots, plugin resolution and system resources still need a
pinned platform image and isolated verification. Other configurations are
outside the reference lock. Sealed wheel descriptors prove artifact handoff
only. The real Bandit E2E is BLOCKED and the existing synthetic SARIF path
remains the execution test. The owner prompt remains a demonstration.
Authenticated owner IPC, io.max validation and crash recovery are separate work.
