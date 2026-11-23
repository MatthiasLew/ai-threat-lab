# M4.11 acceptance

Require OCI and wheel digest validation, transitive ELF checks and a real
read-only package import inside Bubblewrap. Reject missing libc, unexpected
RUNPATH and incompatible ABI. Verify Stevedore plugin loading, observed file
origins, network denial and descriptor cleanup. Record delegation separately.
Production scanner run remains blocked.
