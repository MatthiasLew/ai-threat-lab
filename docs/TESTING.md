# Test strategy and integration readiness — 0.8.0

The offline suite contains 698 test cases at this revision. Coverage includes statements and branches and is enforced at a minimum of 90%. The current local result is 98.5%; child-process CLI tests are additional behavioral evidence and are not counted as subprocess coverage. This does not establish the correctness or availability of any real external API.

## Run the gates

```bash
python -m pip install -e ".[dev]"
python scripts/verify.py
```

This runs Ruff, pytest under coverage, the coverage gate, package build, a clean installed-wheel workflow, and Git whitespace checks. Each command stops on a failure. To inspect only tests:

```bash
python -m pytest -q
python -m coverage run -m pytest -q
python -m coverage report
```

## Evidence covered

| Area | Behavioral checks |
| --- | --- |
| Risk engine | All matrix values, category boundaries, profile adjustments, relevant/irrelevant controls, overlap, deduplication and reduction caps |
| Catalog | Malformed JSON, invalid versions/types, missing fields, empty data, duplicate IDs and invalid rule reductions |
| Code review | Risk patterns, import aliases, safer code, no source execution, encoding and size bounds, source-free reports |
| Assessment | Target routing, missing adapters, malformed URLs/domains, partial results, project bounds and untrusted mail headers |
| Campaigns | Scope validation before provider calls, exact preview approval, expiry, changed content/recipients/facts, media requirement, stop/cancellation handling |
| Delivery | No automatic retry after ambiguous failures, duplicate rejection across service restarts, corrupt databases and concurrent claims |
| JSON contracts | Roundtrips, duplicate keys, unsupported/secret fields, non-finite values, nesting/size limits, timestamp timezone and digest tampering |
| Provider adapters | Registration, missing providers, structured output validation, redacted errors, timeout behavior and CLI injection |
| CLI processes | Every command's help, parser failures, Unicode, spaces in paths, streams, exit codes and full saved-artifact workflows |
| Concrete HTTP adapters | Pinned GitHub commit/blob verification, truncated/skipped files, passive header checks, DNS response policy checks and authenticated Gmail account binding |
| Network scope | Opt-in and exact hosts, forbidden mutations/redirects, public-address pinning, private/mixed DNS rejection, TLS hostname, size/time/request bounds and response-body redaction |
| AI cost controls | Real Responses wire contract with fake transport, input/output limits, synthetic rates, atomic budgets, cache TTL/restarts/namespaces, unknown outcomes, reconciliation and no automatic retries |
| Dependency inventories/advisories | Exact pins, normalization, unsupported/secret-bearing sources, package/manifest limits, real OSV batch wire contract, pagination/order validation, cache expiry and partial-result gaps |
| Shared GitHub scan | Same commit for code/manifests, verified distinct-blob reuse, root format/priority bounds, shared file/byte limits, isolated parsing/advisory failures, no raw-source artifacts, explicit OSV wire and old-engine compatibility |
| Combined reports | Per-target deduplication, provenance, triage rules, empty/not-configured results, invalid documents and escaped offline HTML |
| Local training lab | Exact approval/scope, alias/recipient uniqueness, structured action policy, bounded voice turns, concurrency/replay, expiry and permanent plan revocation |
| Interactive training | Numbered choices, invalid input redaction, EOF/Ctrl+C stop, terminal-control escaping, all command help and actual persisted CLI workflows |
| Training reports | Selected-action provenance, no false verification/employee judgments, preview omission from aggregates, escaped offline HTML and follow-up practice |
| Scan orchestration | One-command routing, automatic dependency inventory, explicit sharing, module-failure isolation/redaction, partial report preservation, scope/options gates and exit codes |
| Scan bundles/history | Manifest/schema/hash/size validation, derived-report consistency, symlinks, no overwrite, racing directory claims, interrupted writes, unrelated-file preservation and observation-only deltas |
| Packaging | Wheel installed without dependencies/index access into a clean venv outside the checkout, installed console entrypoint and bundled catalog |

No real targets, recipients, mailbox accounts or paid APIs are contacted. Fixtures use synthetic data and reserved demonstration domains/numbers.

## CI

Linux and Windows with Python 3.12, 3.13 and 3.14 run lint, coverage/tests, build and the isolated-wheel verifier. A passing offline suite verifies the concrete adapters against synthetic wire responses, not proof that a remote service/account works.

## When real credentials are added

Use the concrete read-only/AI adapters described in LIVE_SETUP.md and API_COSTS.md, then run provider-specific integration tests against a controlled environment. Missing live communications/media adapters still require implementation. Verify authentication failures, quotas, timeouts, cancellation, event authenticity, source-sharing behavior, scope, media integrity and provider-side idempotency. Keep these tests separate from deterministic offline CI and require explicit credentials/environment selection.
