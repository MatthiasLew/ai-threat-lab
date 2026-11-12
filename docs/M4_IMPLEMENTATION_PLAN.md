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
