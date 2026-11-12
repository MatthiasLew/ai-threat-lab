# Security engine stabilization — 2026-11-10

## Current-state audit and decisions

Base: upstream main c90d8b9; reuse PR #12 ae953a1, not another agent engine.
`ScanService.run` already coordinates assessment, inventory, optional advisories,
bundle publication and comparison. Collector exceptions become explicit failed
modules; outputs are new paths, hashes verify consistency rather than authenticity.
`ScanOptions` retains explicit network/host/package-sharing gates. The engine never
imports target code. Existing parser/file budgets remain unchanged.

The local main checkout fbcc28e predates the fixes in c90d8b9. Issues #7–#11 are
closed; regression checks must exercise source-snippet redaction/root confinement,
AI preview/request agreement, documentation commands and PDF evidence binding.
Green historical CI is not current validation.

Confirmed functional gaps: no service event contract/cancellation checkpoints;
interactive history option is a placeholder; facade capabilities omit PDF even
though export supports it. Existing JSON CLI, history, finding-detail, comparison
and export services can be reused. Baseline tests and security review results
will be recorded in SECURITY_VALIDATION_PLAN.md and DELIVERY_STATUS.md.

## Design

Add optional typed lifecycle control to the existing ScanService. Events identify
one operation with a monotonic sequence and version 1, use fixed module IDs and
contain no raw source or exception details. Clients choose how to display them.
Cancellation is cooperative at module and pre-publication boundaries; Ctrl+C
propagates as cancellation. No cancelled scan is published as a verified bundle.
No new scanner, arbitrary command runner, network path or GUI dependency.

Compatibility: existing positional arguments and result/bundle schemas remain;
new keyword-only controls are optional. Existing reports stay readable. Parallel
audits use separate controls and output paths. Caller-owned custom collectors and
callbacks must be thread-safe; the service does not make them so automatically.

Hard process termination cannot emit a terminal event; manifest-last publication
keeps interrupted directories invalid. There is no promise of forcibly stopping
an in-process collector. Agent workers retain their independent hard deadline.

See IMPLEMENTATION_TODO.md for ordered work and acceptance gates.
