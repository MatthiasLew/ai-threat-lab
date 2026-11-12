# M2 closure plan

| Remaining work | Dependency | Acceptance evidence |
| --- | --- | --- |
| Harden ordinary scan reads | Share opened-handle primitives; review collectors individually | Native Windows/Linux checks of legitimate reads and deterministic link, identity and concurrent-change regressions; document snapshot limits |
| Make manifest publication atomic | Stage manifest on the same filesystem as the bundle | Terminate a real writer before and after publication; verify incomplete and previously committed bundles |
| Verify synchronous STDIO disconnects | Preserve the nine tools and the worker supervisor | Real pipes, EOF, broken output and worker cleanup; record where disconnect cannot cancel dispatch |
| Validate against representative source | Pin licensed source and label it independently before scanning | Record per-corpus confusion matrix, unsupported cases and elapsed time |
| Verify resource limits | Native Windows/Linux CI | Exercise limits, clean venv and worker termination; distinguish address space, commit and RSS |
| Prepare M3 handoff | Inspect the existing importer and producer fixtures | Document offline interoperability first and defer optional execution to a separate review |

Refresh the acceptance matrix and existing TODO. Keep PR #13 in Draft until the
remaining gates and six-job CI, build and clean installation checks pass.
