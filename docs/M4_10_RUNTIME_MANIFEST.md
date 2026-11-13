# M4.10 reference projection
Docker Official Image python:3.12.12-slim-bookworm, linux/amd64, OCI manifest
sha256:2986c55feb36e6cae00fa1fefb454283e4b33f35e75ff8bdd123b134130be301.
The probe verifies configuration and four layer digests, sizes and diff IDs.
It selects CPython, libpython, the ELF linker, selected glibc and zlib files,
stdlib sources and the zlib and _socket extensions. It rejects whiteouts
instead of implementing general OCI overlay reconstruction. No archive
members are extracted onto the host filesystem. The linker and libz aliases
are materialized from the same verified bytes.

The read-only projection starts Python with -I -S -B. Observed sys.path
contains /usr/local/lib/python312.zip (absent), /usr/local/lib/python3.12
and /usr/local/lib/python3.12/lib-dynload. The probe checks loaded module
locations. Full DT_NEEDED and RPATH/RUNPATH closure, site-packages handoff,
Bandit plugins and delegated limits for this interpreter remain unverified.
