# M4 roadmap

1. Verify the Linux CPython and site-packages handoff, ELF dependency closure
   and isolated import/plugin diagnostics.
2. Validate delegated block-device I/O and recovery across registration and
   host failures. Keep these tests separate from hosted CI.
3. Authenticate owner IPC and protect the approval key and ledger.
4. Verify Windows pinned runtime handoff, network, scratch and crash recovery.
5. Run controlled Bandit acceptance and review production launch separately.
6. Evaluate asynchronous MCP and further integrations under separate contracts.

See [integrated evidence](M4_PROGRESS_REPORT.md) and [launch gates](M4_ACCEPTANCE.md).

After M4.11, verify block I/O and run controlled Bandit scan/report acceptance separately.

M4.12 adds durable intent records and a dedicated block I/O acceptance probe.

M4.13 verifies fixed Linux scanner fixtures. Production work still requires owner IPC, block I/O, recovery and Windows acceptance.
