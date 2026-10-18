# AI integration and cost controls — 0.4.0

The `ai-explain` command has a concrete OpenAI Responses adapter, not just an interface. It explains an existing partial assessment. It does not run tools, execute source, generate campaigns, collect personal information or control other adapters. No API calls are made by the default assessment commands or by `--dry-run`.

## Configuration and first run

Copy `examples/ai-budget.json` to your own configuration. Replace the model and both prices with your actual available model and current **USD per million tokens** rates. The example model is intentionally a placeholder; its prices are **synthetic examples, not current prices or a free-tier promise**. No model is silently chosen and no paid fallback is used.

Run a local audit, then estimate the explanation cost:

```bash
ai-threat-lab audit path/to/project --output assessment.json
ai-threat-lab ai-explain assessment.json --ai-config examples/ai-budget.json --ledger costs.sqlite --dry-run
ai-threat-lab api-costs --ledger costs.sqlite
```

Dry-run needs no key. It estimates the reservation, not available provider quota. For a live call, configure `OPENAI_API_KEY` through your preferred secure environment mechanism, review the evidence, and explicitly permit transmission:

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
| Concurrent calls | SQLite transaction reserves money before the call; identical pending requests are blocked across processes |
| Daily controls | Both a USD reservation limit and request-count limit; days are UTC |
| Unknown outcome | Timeout, malformed response, incomplete response or other error retains the reservation; no automatic retry |
| Usage accounting | Successful input/output usage reconciles the reservation at configured rates; cache discounts are deliberately not assumed |
| Usage overrun | Unexpected usage beyond the planning bound is recorded and reported as an error |
| No hidden charges | No tools, automatic escalation, automatic retries, conversation history or streaming reconnection |
| Privacy | `store: false` in the request; this does not override all provider retention policies |

A byte-count-plus-framing allowance is a conservative **planning estimate**, not an exact tokenizer or a remote billing guarantee. Incorrect prices, provider changes, other applications, media charges, taxes and different ledgers can defeat a local estimate. There are no measured savings percentages without real workloads. Caching removes a call only when its identity and TTL match; reducing context helps only when it reduces billed tokens.

Choose an appropriate economical model explicitly. Automatic model routing and Batch API are not implemented. This avoids introducing a hidden second paid call during early integration.

## Cache and data handling

When enabled, cache stores generated explanations in plaintext SQLite, not input prompts or API keys. Evidence can contain sensitive filenames, domains or user-authored text; minimization is **not** a guarantee of anonymization. Review reports before transmission. Use a private directory/OS permissions, separate tenant/project namespaces and appropriate retention. New POSIX database files are created with mode `0600`; Windows inherits directory ACLs. The application does not encrypt the cache or run automatic deletion; expired entries are no longer reused but remain on disk until the operator removes the database. Do not delete a ledger with unresolved reservations merely to retry calls.

## Unconfirmed requests

```bash
ai-threat-lab api-costs --ledger costs.sqlite
# Only after checking actual provider usage/billing:
ai-threat-lab api-reconcile REQUEST_ID --actual-usd 0.00123 --ledger costs.sqlite
```

Use `--actual-usd 0` only after confirming the request was not billed. Reconciliation records an operator-observed local amount; it does not refund provider charges. A process crash also leaves its claim pending. This is intentional: retrying an unconfirmed request could double the cost.

## Tested boundary

Tests exercise request payloads and responses through the real adapter with a fake HTTP boundary. They cover cache/restart/TTL, namespace changes, persistent concurrency, budget refusal before calls, corrupted databases, missing credentials, unknown outcomes and cost reconciliation. No key, paid call, live model quality or real account quota was tested in this release.

References: [Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create) and [API pricing](https://openai.com/api/pricing/). Check current model access, supported parameters and prices before live validation.
