# Gmail settings collector — offline completion contract

Version 0.38.0 closes the bounded local implementation and fixture acceptance below. Credential setup, OAuth consent and real-account validation remain deferred. No existing account credentials are needed to run the acceptance suite.

## Supported workflow

After separate authorized account/token setup, the implemented routes are:

```bash
ai-threat-lab audit mailbox:owner@example.com --network --allow-host gmail.googleapis.com
ai-threat-lab scan mailbox:owner@example.com --network --allow-host gmail.googleapis.com \
  --output-dir mailbox-review
ai-threat-lab scan-check mailbox-review
```

The collector reads `GMAIL_ACCESS_TOKEN` only after validating the mailbox target. Missing credentials fail before any request. Tokens must contain 1–4096 printable ASCII characters without whitespace. Errors and saved findings never contain the token. The CLI requires network opt-in and exact approval of `gmail.googleapis.com` before constructing the remote client.

Exactly three sequential GET requests are supported, using the same Bearer token:

| Endpoint under `https://gmail.googleapis.com/gmail/v1/users/me` | Used data |
| --- | --- |
| `/profile` | String `emailAddress` must match the requested mailbox, case-insensitively; mismatch/invalid data stops before settings |
| `/settings/autoForwarding` | `enabled` must be a literal boolean; true creates a configuration-review candidate |
| `/settings/filters` | Optional `filter` array; up to 1000 entries, each with an optional object `action`; nonempty string `forward` creates one aggregate candidate |

There are no message/thread downloads, outgoing messages, writes, token refreshes or retries. The built-in transport is restricted to the fixed Gmail host and three requests, with strict complete JSON bodies, the default 1 MiB response bound and existing public-address/TLS checks. There is no whole-job timeout guarantee. Unused profile counts, filter IDs/criteria, label actions and automatic forwarding destinations are not interpreted or retained as findings.

## Failure and uncertainty

Every filter is validated, including entries after a forwarding observation. Invalid rule/action types or forwarding values cause a provider failure, rather than a clean result or partial positive finding. A supplied forwarding value must be a string of at most 1024 printable ASCII characters without whitespace; empty/omitted means no forwarding observation. This checks supported metadata representation, not address validity, deliverability or ownership. A missing filter array is accepted as empty; explicit null/object/scalar arrays are invalid. Unknown response fields are ignored, except a nonempty or incorrectly typed `nextPageToken` is rejected as unsupported/incomplete pagination. The documented filters-list endpoint has no pagination contract used by this collector.

Identity, forwarding and filter validation occurs at each stage before the next request. Any HTTP or document failure stops without retry. `audit` returns 3. `scan` returns 3 and preserves a verified failed-module bundle with an assessment marked `not_configured`, no target findings and an explicit no-conclusion notice. Earlier responses do not become a completed assessment after a later failure.

Successful results remain **partial**, even when no candidates are found. Forwarding may be legitimate. The collector does not determine whether it is malicious, approved, external, effective or currently delivering messages. MFA, sessions, delegated access, SMTP/POP/IMAP, other mailbox providers, linked applications, messages, attachments, authentication, delivery and compromise remain unchecked. Account consent, token scope compatibility/refresh and real provider behavior require separate integration acceptance. An AI key does not implement those capabilities.

## Required evidence

- `tests/test_gmail_boundary.py`: profile binding/type errors, token rejection before network, literal boolean checks, rule/action/forwarding shapes, all-entry validation, 1000-entry boundary, fixed URLs/headers, redaction and HTTP failures at every stage.
- Existing remote/CLI tests and the previous-engine bundle compatibility controls remain required.
- `scripts/check_gmail_offline.py`: runs CLI services with synthetic credentials and sockets/DNS blocked. Six successful fixture requests, three scope rejections and eight negative controls cover verified scan bundles, safe failures and zero live/AI calls.
- `scripts/check_installed_package.py`: invokes this acceptance from the fresh installed wheel outside the checkout, along with all previous workflows.
- Ruff, pytest/coverage, wheel/sdist build and Linux/Windows Python 3.12–3.14 CI must pass.

Engine `read-only-pipeline-25` records changed acceptance/interpretation of malformed settings. Prior engines remain readable, while comparisons across engines remain rejected. This completion contract concerns the implemented offline collector, not full mailbox security or account readiness.

Primary provider references: [profile](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users/getProfile), [automatic forwarding](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.settings/getAutoForwarding), [forwarding representation](https://developers.google.com/workspace/gmail/api/reference/rest/v1/AutoForwarding), [filters list](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.settings.filters/list), [filter actions](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.settings.filters).
