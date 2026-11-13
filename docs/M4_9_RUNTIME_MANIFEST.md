# M4.9 reference manifest

The candidate is Docker Official Image python:3.12.12-slim-bookworm for
linux/amd64, pinned to OCI manifest
sha256:2986c55feb36e6cae00fa1fefb454283e4b33f35e75ff8bdd123b134130be301.
The registry manifest bytes matched this digest. The source revision is
90e9ca41dc404ee7d22c09b894823e8925227c17 in docker-library/python.
The OCI digest authenticates the downloaded manifest bytes against the pin.
It does not verify a selectively extracted runtime or its loader behavior.

The package tree is derived from the 13 pinned wheels and validated against
their RECORD hashes. The deterministic snapshot records each retained file
path, mode, size and SHA-256. It omits the known setuptools startup hook and
two nested test archives after verifying their RECORD entries. The snapshot
does not include CPython, glibc, the ELF interpreter, the stdlib or system
resources. Those entries and runtime import traces remain UNVERIFIED.
