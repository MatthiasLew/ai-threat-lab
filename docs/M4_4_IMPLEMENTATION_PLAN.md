# M4.4 implementation plan

1. Audit the trust boundary and harden local ledger path checks.
2. Bind a fixed fixture to approved bytes and pass sealed Linux descriptors
   into Bubblewrap. Exercise native execution, refusal and cleanup.
3. Accept completed bounded test results through the existing SARIF importer.
4. Keep production issuance and launch blocked. Document Windows handoff,
   loader closure and aggregate controls that still require evidence.

## Remaining gates

The M4.4 Linux test stages individual fixed files. It does not establish
general directory staging or runtime closure for Bandit 1.7.8. The Windows
AppContainer fixture remains a separate platform probe. Windows sealed
staging, native loader closure, scratch quota, external network denial and
crash recovery are open. Linux cgroups are not integrated in this handoff.
The existing CLI and MCP expose no owner confirmation or launch route.
