# M4.10 acceptance
The reference CI job must fetch only pinned OCI bytes and run the fixed
diagnostic inside Bubblewrap with seccomp. Verify version, stdlib and native
imports, read-only runtime, private scratch, host canary and network denial.
Production Bandit remains blocked pending complete native and package
closure, delegated supervision and owner authentication.
