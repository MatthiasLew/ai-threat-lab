# AI explanation and cost-control offline completion — 0.32.0

This is the finite completion contract for the existing explanation module. Work on unrelated analyzers, reports/history services, new providers, model routing and GUI is outside this milestone. No credentials are provisioned and no live API requests are required.

The module is accepted offline only after all of these gates pass:

1. Strict bounded configuration, minimal structured evidence, deterministic deduplication, rejection rather than truncation of excess input, empty-finding skip and credential-free estimation.
2. Shared SQLite reservation before dispatch, global per-ledger UTC daily money/request limits, identical pending-request refusal and exact namespace/config/evidence cache identity. Clock sampling for BudgetedAI reservations and cache expiry occurs after acquiring the writer lock.
3. Existing compatible legacy ledgers remain usable without erasing history; malformed/incompatible schema and linked/special/missing operational files fail without initialization or silent replacement. Read-only status does not modify database contents.
4. Success reconciles usage exactly once. Failures/uncertain outcomes keep a discoverable reservation with no automatic retry; explicit operator reconciliation never claims a refund. Usage overruns are recorded and cannot populate a reusable cache.
5. Operators can clear expired/all cached response columns without deleting calls, costs, pending reservations or cache-hit accounting. Cleanup is transactional and repeatable; logical deletion is not forensic secure erasure.
6. An AI output path is claimed exclusively before any possible provider dispatch. Existing-output refusal cannot spend a request. Failure releases the claimed file; successful output uses no-overwrite publication. Storage failures after dispatch cannot guarantee zero charges.
7. Unit/concurrency/fault-injection tests, actual CLI processes, fake-transport adapter workflows, clean installed-wheel checks, all local release gates and the six-job Linux/Windows CI matrix pass. Documentation names the residual external checks honestly.

After these gates pass, status is **offline complete in this scope**, not production acceptance. The remaining external gate is choosing/validating a real account/model/prices and controlled live checks of authentication, quotas, timeout/uncertain outcomes, model parameter support, usage, output quality and actual billing. No key alone establishes those facts. Automatic provider retention/deletion, distributed budgets across separate ledgers, encryption, authenticated multi-user accounting, billing synchronization, Batch API and automatic model routing are outside this local contract.
