# M4 implementation plan

Base this PR on M3 report handoff (#17). Retarget after the stack lands and
verify the new base before merge.

1. Add a read-only sandbox diagnostic to scanner doctor and define the scope
   and approval contract. Keep production execution blocked.
2. Exercise Bubblewrap with a fixed, statically linked test fixture and
   synthetic inputs. Record successful and unavailable environments separately.
3. Evaluate Windows native prerequisites and exercise the existing trusted
   worker supervisor. Prototype AppContainer separately.
4. Run the existing offline CI and build/install checks.

## Hardening follow-up

1. Require native Linux probes in CI and cover failure paths in scanner
   diagnostics, SARIF and worker validation. Measure both coverage metrics
   before enabling the second threshold.
2. Prototype Windows AppContainer using synthetic files, a unique profile and
   a suspended process assigned to a Job Object. Verify the token and access
   controls before treating any probe result as evidence.
3. Keep launch blocked until runtime pinning, owner approval, aggregate limits
   and the complete platform acceptance matrix are available.
