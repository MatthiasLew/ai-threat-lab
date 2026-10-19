# Saved OpenSSH journal review — 0.31.0

Review selected authentication outcomes in a single-host saved journal JSON Lines export. This offline adapter maps selected OpenSSH messages into the existing bounded authentication-pattern engine. It never reads a live journal, starts a subprocess, resolves an address, connects to SSH or attempts a login. API configuration remains deferred.

## Export and review

On a machine you administer, export a bounded interval using your normal journal permissions. For example, this selects the two supported process names (journalctl combines matches for the same field):

```sh
journalctl _COMM=sshd _COMM=sshd-session --since '2026-01-01 00:00:00 UTC' --until '2026-01-01 00:05:00 UTC' --output=json --no-pager > logins.ssh.jsonl
ai-threat-lab review-ssh-journal logins.ssh.jsonl
ai-threat-lab review-ssh-journal logins.ssh.jsonl --min-failures 6 --window-seconds 600
ai-threat-lab review-ssh-journal logins.ssh.jsonl --format html --output ssh-review.html
ai-threat-lab review-ssh-journal logins.ssh.jsonl --fail-on-findings
ai-threat-lab scan logins.ssh.jsonl --output-dir scans/ssh-01
ai-threat-lab scan-batch logins.ssh.jsonl saved-page.html --output-dir scans/batch-01
```

The program does not run the export command. Retain the original export privately; it contains identities and potentially sensitive metadata. The example is a collection recipe, not evidence that a deployment logs every outcome. Use the actual process names/logging arrangement on the controlled machine. Other names, relay arrangements and native `/var/log/auth.log`, Windows events, binary journal files, pretty-printed JSON and JSON sequences are not supported.

Standalone review accepts any filename. Automatic `assess`/`audit`/`scan`/`scan-batch` routing requires the case-insensitive `.ssh.jsonl` ending. Project-directory and GitHub source walks do not ingest these exports. Pass each file explicitly. Standalone thresholds have the same bounds as [normalized authentication review](AUTHENTICATION_LOGS.md); scans use the default policy. Exit codes are 0 for completed partial review, 1 for requested `--fail-on-findings` with candidates, and 2 for invalid input/policy or output conflict. Reports never overwrite an existing file.

## Selected record contract

Every nonblank physical line must be a JSON object. Additional native fields are allowed, but duplicate keys, non-finite numbers and malformed JSON reject the entire file. Selected records use scalar strings for:

| Field | Required meaning/format |
| --- | --- |
| `_COMM` | Exactly `sshd` or `sshd-session`; `SYSLOG_IDENTIFIER` alone cannot select a row |
| `_MACHINE_ID` | Exactly 32 lowercase hexadecimal digits, identical across every selected SSH row, including nonterminal messages |
| `__REALTIME_TIMESTAMP` | 1–18 ASCII decimal digits representing journal reception time in integer microseconds since the UTC epoch; must fit year 1970–9999 |
| `MESSAGE` | Printable ASCII text with the supported terminal-outcome structure below |

Binary, null or multivalued representations of required selected fields are rejected. A missing/null `_COMM` or another scalar process name is omitted and counted; a nonscalar `_COMM` is rejected because selection is ambiguous. Other-process rows need not contain the selected SSH fields. Their messages are never parsed as logins. Native metadata is not cryptographically authenticated merely because its field name begins with an underscore.

Supported terminal messages have this structure:

```text
Accepted METHOD for ACCOUNT from IP port PORT ssh2
Failed METHOD for ACCOUNT from IP port PORT ssh2
Failed METHOD for invalid user ACCOUNT from IP port PORT ssh2
```

`METHOD` is a lowercase token of at most 32 characters, optionally followed by `/` and another such token. Tokens start with a letter and contain letters, digits or hyphens. `password` maps to password; `publickey` maps to public_key. Other syntactically supported methods, including `keyboard-interactive/pam`, map to unknown. They never imply MFA. A terminal accepted outcome of any supported method resets that account/source pair's preceding failure segment.

Account tokens contain 1–99 printable ASCII nonspace characters, compared exactly and case-sensitively. OpenSSH's message formatter limits user text to 100 characters; this adapter rejects a 100-character token because truncation cannot be excluded. A logged invalid-user token is an attempted account name, not proof the account exists.

The source must be an IPv4 or IPv6 literal without a zone identifier; ports are decimal 1–65535. IP spellings are canonicalized without DNS. IPv4-mapped IPv6 stays distinct from IPv4; no NAT, actor or device identity is inferred. Optional `: ` metadata up to 1,024 printable ASCII characters is discarded without validating a key/certificate. A trailing ` [preauth]` is allowed only for failures. Accepted invalid-user/preauth outcomes are rejected.

A selected message beginning with `Accepted ` or `Failed ` that does not fit this subset rejects the entire capture, rather than silently dropping a terminal outcome. Other selected messages, including `Partial`, `Postponed`, PAM diagnostics and disconnect notices, are omitted and counted. Partial authentication is not successful authentication and is not a terminal failure. Omission counts remain visible even when there are no candidates.

## Evidence and limits

The four existing candidate families are repeated failures, password spraying, distributed failures and success after failures. They retain the normalized engine's inclusive windows, strict-before-success rule, success reset, thresholds and 200-group finding cap. See [AUTHENTICATION_LOGS.md](AUTHENTICATION_LOGS.md). All results remain partial and require investigation.

Evidence uses original physical line numbers and capture-local account/source group ordinals. Reports omit account names, addresses, ports, host IDs, cursors, exact timestamps and key metadata. The input filename remains visible. The raw export is never copied into scan bundles. Identical mapped events collapse even if ports/cursors/extra metadata differ; distinct attempts can be undercounted. Sorting uses declared journal reception time, which may differ from authentication time. Clock skew, missing records and shared sources can distort patterns.

The shared file reader accepts UTF-8 with optional BOM, CRLF and blank lines. Limits are 4 MiB, 10,000 physical lines and 4,096 characters per line. Special files, preflight symlinks/junctions and oversized captures are rejected; descriptor regular-file checks and no-follow/nonblocking flags are used where available. Parent-directory replacement races are not an atomic snapshot guarantee. Structural errors reject the entire capture; they never produce a clean result for an unread remainder.

The collector does not validate logging configuration, process identity, source integrity, cursor uniqueness, export completeness, account validity, session correlation, password reuse, lockout/MFA effectiveness or compromise. A matching process label or machine ID in an editable export is not authenticated evidence. Zero candidates is not a security all-clear.

## Acceptance and compatibility

Unit and real-process tests exercise native mapping, independent expected normalized timelines, method/reset behavior, microsecond boundaries, host separation, malformed/ambiguous outcomes, privacy, resource limits, no-network behavior and bundle routing. The generated demo requires all four candidate families plus a time-separated negative control before writing completion; the installed-wheel gate repeats the workflow. These synthetic fixtures do not establish compatibility with every OpenSSH/systemd version or real deployment.

Scan engine 22 recognizes the new explicit target. Engine-21 and older supported bundles remain readable; cross-engine observation comparisons are disabled. Python analysis engines are unchanged.

Protocol references: [OpenSSH auth_log formatter](https://github.com/openssh/openssh-portable/blob/master/auth.c), [systemd Journal JSON format](https://systemd.io/JOURNAL_EXPORT_FORMATS/#journal-json-format), [journal fields](https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html), and [journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html). This is a deliberately restricted parser, not a claim to implement every format those projects support.
