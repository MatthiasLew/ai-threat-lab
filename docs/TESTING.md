# Test strategy and integration readiness — 0.3.0

The offline suite contains 277 test cases at this revision. Coverage includes statements and branches and is enforced at a minimum of 90%. The current local result is 96.7%; child-process CLI tests are additional behavioral evidence and are not counted as subprocess coverage. This does not establish the correctness or availability of any real external API.

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
| Packaging | Wheel installed without dependencies/index access into a clean venv outside the checkout, installed console entrypoint and bundled catalog |

No real targets, recipients, mailbox accounts or paid APIs are contacted. Fixtures use synthetic data and reserved demonstration domains/numbers.

## CI

Linux and Windows with Python 3.12, 3.13 and 3.14 run lint, coverage/tests, build and the isolated-wheel verifier. A passing offline suite is a prerequisite for introducing a concrete adapter, not proof that a remote service works.

## When a real API is added

Implement the matching provider protocol, register it explicitly, then run these tests plus provider-specific integration tests against a controlled environment. Verify authentication failures, quotas, timeouts, cancellation, event authenticity, source-sharing behavior, scope, media integrity and provider-side idempotency. Keep these tests separate from deterministic offline CI and require explicit credentials/environment selection.
