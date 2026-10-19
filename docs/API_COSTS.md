# AI integration and cost controls — 0.32.0

The `ai-explain` command has a concrete OpenAI Responses adapter, not just an interface. It explains an existing partial assessment. It does not run tools, execute source, generate campaigns, collect personal information or control other adapters. No API calls are made by the default assessment commands or by `--dry-run`.

The finite [offline completion contract](AI_OFFLINE_ACCEPTANCE.md) is the acceptance boundary for version 0.32.0. It covers local accounting, request/cache safety, CLI and fixture-backed adapter behavior. Choosing and validating a real account/model/prices remains deferred. Completion does not claim provider billing guarantees or live output quality.

## Configuration and first run

Copy `examples/ai-budget.json` to your own configuration. Replace the model and both prices with your actual available model and current **USD per million tokens** rates. The example model is intentionally a placeholder; its prices are **synthetic examples, not current prices or a free-tier promise**. No model is silently chosen and no paid fallback is used.

Run a local audit, then estimate the explanation cost:

```bash
ai-threat-lab audit path/to/project --output assessment.json
ai-threat-lab ai-explain assessment.json --ai-config examples/ai-budget.json --ledger costs.sqlite --dry-run
ai-threat-lab api-costs --ledger costs.sqlite
```

Dry-run needs no key. It estimates the reservation, not available provider quota. Live setup is a separate deferred acceptance stage. When it resumes, configure `OPENAI_API_KEY` through your preferred secure environment mechanism, review the evidence, and explicitly permit transmission:

```bash
ai-threat-lab ai-explain assessment.json --ai-config my-ai-budget.json --ledger costs.sqlite --send-evidence --output explanation.json
```

The application reads the environment; it does not load `.env` files, provision keys, print credentials or require you to put secrets into JSON. Configure a dedicated provider project and billing controls. All machines/workers sharing a local budget must use the **same SQLite file**. Separate files cannot enforce an account-wide budget. The ledger also counts different namespaces toward the same daily budget.

## Controls

| Control | Behavior |
| --- | --- |
| Rules first | Audits run without a model. An empty finding list skips the model; limitations still apply |
| Minimal context | Only selected structured finding fields, status, target kind and limitations are transmitted; raw source/body/attachments and top-level target are excluded |
| Deduplication | Identical structured findings appear once in context |
| Input limit | UTF-8 byte limit; oversized reports are rejected rather than silently losing findings/limitations |
| Output limit | Explicit `max_output_tokens` sent to the provider |
| Local cache | Optional exact-match cache, disabled by default; explicit TTL up to 30 days |
| Cache identity | Includes namespace, model, instructions, configuration and exact compact evidence; changes invalidate it |
| Concurrent calls | SQLite transaction reserves money before the call; identical pending requests are blocked across processes. BudgetedAI samples the clock after the writer lock, including cache TTL and UTC day checks |
| Daily controls | Both a USD reservation limit and request-count limit; days are UTC |
| Unknown outcome | Timeout, malformed response, incomplete response or other error retains the reservation; no automatic retry |
| Usage accounting | Successful input/output usage reconciles the reservation at configured rates; cache discounts are deliberately not assumed |
| Usage overrun | Unexpected usage beyond the planning bound is recorded and reported as an error; its text is never cached/reused. Legacy cached entries are also checked against caller token limits |
| No hidden charges | No tools, automatic escalation, automatic retries, conversation history or streaming reconnection |
| Privacy | `store: false` in the request; this does not override all provider retention policies |

A byte-count-plus-framing allowance is a conservative **planning estimate**, not an exact tokenizer or a remote billing guarantee. Incorrect prices, provider changes, other applications, media charges, taxes and different ledgers can defeat a local estimate. There are no measured savings percentages without real workloads. Caching removes a call only when its identity and TTL match; reducing context helps only when it reduces billed tokens.

Choose an appropriate economical model explicitly. Automatic model routing and Batch API are not implemented. This avoids introducing a hidden second paid call during early integration.

## Cache and data handling

When enabled, cache stores generated explanations in plaintext SQLite, not input prompts or API keys. Evidence can contain sensitive filenames, domains or user-authored text; minimization is **not** a guarantee of anonymization. Review reports before transmission. Use a private directory/OS permissions, separate tenant/project namespaces and appropriate retention. New POSIX database files are created with mode `0600`; Windows inherits directory ACLs. The application does not encrypt the cache or run automatic deletion. Expired entries are no longer reused; use the cache cleanup command below to clear response columns while preserving accounting. Do not delete a ledger with unresolved reservations merely to retry calls.

## Local ledger lifecycle and cache cleanup

```bash
# Clear only cached text whose TTL has expired:
ai-threat-lab api-cache-prune --ledger costs.sqlite
# Clear all cached text, including unexpired responses:
ai-threat-lab api-cache-prune --ledger costs.sqlite --all
```

Cleanup is one transaction and retains every call, charge, pending reservation and cache-hit counter. It never releases budget or retries requests. Repeat cleanup is idempotent. It is logical column clearing, not forensic secure deletion: SQLite free pages, journal/WAL files, copies and backups can retain prior plaintext. No VACUUM or accounting-row deletion is performed. The command reports counts, never the removed text. Changing cache contents does not change provider retention.

`api-costs`, `api-reconcile` and `api-cache-prune` require an existing compatible ledger. Missing files are not silently initialized by operational commands. `ai-explain --dry-run` may initialize an empty ledger but never reserves a call, writes a cache hit or contacts a provider. With no findings it skips even ledger initialization and returns the supplied limitations. Invalid structured evidence/configuration fails before reservation.

New ledgers use schema revision 1. Compatible revision-0 ledgers remain readable/writable without rebuilding tables, resetting charges or clearing pending claims. Their header is not rewritten merely by opening/reporting. Unexpected revision/tables/column types/request primary key or selected malformed accounting state is rejected. The same schema is checked on each transaction; opening a removed/replaced empty file does not reinitialize an existing CostLedger instance. File owners can still tamper with the ledger: this is not authenticated billing evidence.

Operational files must be regular and not preflight links/junctions, and must not exceed 128 MiB. URI-safe opening supports spaces, `#`, percent signs and Unicode paths, with explicit existing-only read/write modes. Parent directories must remain private/trusted against replacement races. `api-costs` opens read-only and reports stored data without clearing cache or expiring rows. SQLite failures leave history in place and require investigation; deleting a ledger is not a safe retry strategy.

Each daily report distinguishes `recorded_usage_or_reconciled_usd` from `reserved_unconfirmed_usd`; `charged_or_reserved_usd` remains their sum. These are locally estimated/declared amounts, not independently verified invoice totals. UTC accounting stays on the reservation's day even when completion occurs after midnight. Day selection and validation use whole-second flooring so subsecond rounding cannot move a pre-midnight reservation to the next day. All configurations/namespaces sharing that file contribute to its totals, subject to the limits supplied by the caller; configuration is trusted operator policy, not a central account-wide policy service.

Cost arithmetic uses integer nanodollars and one upward rounding per completed request. Prices are positive USD decimal strings of at most 32 characters, representing whole nanodollars up to USD 1,000,000; zero/free rates are not inferred. Model/namespace strings are nonempty valid UTF-8, at most 128 characters and contain no ASCII controls. The process-wide Decimal precision cannot round a fractional nanodollar into an accepted price or change token-charge arithmetic.

## Output safety

For `ai-explain --output`, the destination is claimed exclusively with private new-file permissions before any provider dispatch. An existing file or a concurrent winner is refused without spending a request. The destination must not alias the ledger or its standard SQLite sidecars. On a failed command the owned claim is removed; replacement by another file is not removed. A successful command writes only its claimed file. The parent directory must be trusted; this is not a filesystem transaction with provider billing. A crash may leave an incomplete output file, and storage failure after dispatch can still incur charges. Consult the ledger before retrying.

## Unconfirmed requests

```bash
ai-threat-lab api-costs --ledger costs.sqlite
# Only after checking actual provider usage/billing:
ai-threat-lab api-reconcile REQUEST_ID --actual-usd 0.00123 --ledger costs.sqlite
```

Use `--actual-usd 0` only after confirming the request was not billed. Reconciliation records an operator-observed local amount; it does not refund provider charges. A process crash also leaves its claim pending. This is intentional: retrying an unconfirmed request could double the cost.

## Tested boundary

Tests also reproduce pre-0.32 defects in cached overruns, lock-time TTL/day accounting, malformed-schema augmentation, Decimal precision and output-path races. SQL failure/rollback and concurrent distinct/identical reservations are covered. The installed-wheel offline acceptance blocks sockets and exercises the estimate/cache/expiry/timeout/reconciliation lifecycle with a synthetic credential/transport only.

Tests exercise request payloads and responses through the real adapter with a fake HTTP boundary. They cover cache/restart/TTL, namespace changes, persistent concurrency, budget refusal before calls, corrupted databases, missing credentials, unknown outcomes and cost reconciliation. No key, paid call, live model quality or real account quota was tested in this release.

References: [Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create) and [API pricing](https://openai.com/api/pricing/). Check current model access, supported parameters and prices before live validation.
