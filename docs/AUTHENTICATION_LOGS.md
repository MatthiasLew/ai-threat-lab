# Offline authentication-event review — 0.28.0

The authentication-log module reviews a saved, normalized JSON Lines export. It detects selected sequences consistent with repeated authentication failures, password spraying, distributed failures and success after failures. It does not perform login attempts, access accounts, contact a service, generate passwords or confirm an attack/compromise. All findings are candidates and the result is partial.

## Console workflow

```bash
ai-threat-lab review-auth-log logins.auth.jsonl
ai-threat-lab review-auth-log logins.auth.jsonl --window-seconds 300 --min-failures 5 --min-accounts 5 --min-sources 3
ai-threat-lab review-auth-log logins.auth.jsonl --format html --output login-review.html
ai-threat-lab review-auth-log logins.auth.jsonl --fail-on-findings
ai-threat-lab scan logins.auth.jsonl --output-dir scans/logins-01
ai-threat-lab scan-batch saved-page.html logins.auth.jsonl --output-dir scans/local-01
```

Standalone `review-auth-log` accepts any filename. Automatic `assess`, `audit`, `scan` and `scan-batch` routing requires the `.auth.jsonl` filename ending, case-insensitively. Project-directory/GitHub source walks do not ingest authentication logs. Pass each export explicitly. Scan/batch use the default policy; custom thresholds apply to standalone review and are recorded in its notices and finding evidence. The target filename remains visible in reports.

Exit codes: 0 for a completed partial review, 1 when `--fail-on-findings` finds candidates, 2 for invalid input/policy or an output conflict. JSON and escaped HTML output never overwrite an existing file. Invalid records reject the entire review; they are not silently treated as normal logins.

## Normalized input contract

One object per nonblank physical line, exactly these five fields:

```json
{"timestamp":"2026-01-01T00:00:00Z","account":"account-001","source":"source-001","outcome":"failure","method":"password"}
```

| Field | Accepted value |
| --- | --- |
| `timestamp` | Valid UTC date/time from year 1970 through 9999; `YYYY-MM-DDTHH:MM:SS`, optional 1–6 fractional digits, followed by `Z` or `+00:00` |
| `account` | Exact 1–128 printable ASCII characters without spaces; use a stable pseudonymous identifier |
| `source` | Same identifier contract; use the same value for the same declared source within an export |
| `outcome` | `failure` or `success` |
| `method` | `password`, `public_key`, `mfa` or `unknown` |

The schema has no fields for passwords, tokens, raw messages or device metadata, and extra properties are rejected. Do not put secrets into account/source identifiers. Do not invent outcomes for missing records. Provider-native Windows/SSH/identity-provider log conversion is not implemented: prepare a normalized export from a trusted source. A later collector must map its actual provider semantics into this contract and validate permissions/completeness; adding a credential alone does not implement that mapping.

The parser rejects duplicate keys, non-finite JSON, malformed structure, invalid dates/identifiers and unsupported fields. UTF-8 files, optional BOM, CRLF and blank lines are supported. Exact normalized duplicates, including equivalent UTC timestamp spellings, are collapsed with a notice; distinct genuine attempts identical in all five fields may therefore be undercounted. No event-ID or export replay authenticity is inferred.

## Selected patterns

| Candidate | Default selected condition within an inclusive 300-second window |
| --- | --- |
| `auth_repeated_failures` | At least 5 failures for the same exact account/source pair |
| `auth_password_spray_pattern` | At least 5 **password** failures at one source spanning at least 5 accounts |
| `auth_distributed_failures` | At least 5 failures at one account spanning at least 3 sources |
| `auth_success_after_failures` | A declared success preceded by at least 5 strictly earlier failures at the same account/source pair |

General failures may use any supported method; password-spray candidates require `password`. Events are sorted by declared UTC time, retaining original line references. Reordering is disclosed. Equal timestamps do not establish that a failure preceded a success. Any success resets that pair's failure segment; distributed/spray windows still describe failures across the export and do not reset with individual pair successes.

Findings aggregate by rule and account/source group, retaining the largest observed qualifying count and its closing event's line. Evidence contains line numbers, capture-local group ordinals, counts and policy values. It omits account/source values and exact timestamps. Ordinals identify groups only within that capture and are assigned by first unique-event input appearance; they are not stable identities across exports. The operator can use line references to examine the original privately. No raw export is copied into a scan bundle.

## Resource and interpretation limits

4 MiB input, 10,000 physical lines, 4,096 characters per line and 200 finding groups. A final newline terminates the last line; blank lines count toward the physical-line limit. Structural/input limits reject the capture. Once the finding cap is reached, additional groups are omitted with a notice while retained groups can still update. File descriptors are checked for regular-file type; preflight links/junctions and special files are rejected, with no-follow/nonblocking flags where available. Concurrent filesystem changes are not an atomic snapshot guarantee.

Policy bounds: window 1–3,600 seconds; minimum failures 3–100; distinct account/source minima 2–100. Thresholds are heuristics, not compliance requirements. Empty input or zero candidates does not establish secure accounts, complete logging or absence of attacks.

Stale credentials, monitoring, shared/NAT sources and clock skew can create similar patterns. Exact identifiers are case-sensitive and are not canonicalized into users, devices, IP addresses or actors. The module does not verify log authenticity, trusted collection, timezone conversion, password reuse, MFA/lockout effectiveness, geolocation, token/session correlation or compromise. No personnel score is calculated.

## Acceptance evidence

The generated offline demo requires all four candidate families plus a time-separated negative control with zero candidates. CLI/installed-wheel checks exercise JSON/HTML, exit policy, invalid thresholds, no overwrite and bundle verification. Boundary tests cover duplicate/reordered events, equal timestamps, reset/expiry rules, invalid structures, privacy, file/resource limits and a finding cap. Fifteen deterministic generated timelines are compared with an independent prefix-window oracle. API configuration remains deferred.
