# Target-based assessment

```bash
python -m ai_threat_lab assess path/to/project
python -m ai_threat_lab assess path/to/module.py
python -m ai_threat_lab assess path/to/export.eml
python -m ai_threat_lab assess https://github.com/example/repository
python -m ai_threat_lab assess https://example.invalid
python -m ai_threat_lab assess mail-domain:example.invalid
python -m ai_threat_lab assess mailbox:person@example.invalid
```

The router identifies a target and selects an implemented module or returns `not_configured` with the missing adapter. No credentials may be embedded in URLs. Provide a repository root URL for GitHub; direct file/issue URLs are not accepted as repository targets.

## Local Python project

Reviews up to 100 `.py` files in deterministic directory order. Dependency/build folders and directory/file symlinks are skipped. Each file has the reviewer's 256 KiB input limit. Unsupported files, skipped parse/read failures, file-limit omissions and analysis limitations appear in `not_checked`. The overall result remains `partial`, including when no candidates are found. Other languages, dependencies and program execution are not inspected.

## Exported mail

Reads a single `.eml` file up to 1 MiB. It reports Authentication-Results failures as unverified candidates and differing Reply-To/From headers as a possible warning. These are not definitive phishing detections: headers can be forged and reply routing can legitimately differ. No links or attachments are opened. Mailbox MFA, forwarding, account permissions, DNS policies and cryptographic verification remain unchecked.

## Legacy router for remote and binary targets

GitHub URLs, website URLs, mail domains, mailbox accounts and executable files are recognized. Without registered TargetAdapter implementations, their checks return `not_configured`. They do not trigger attacks, port scans, login attempts, mail access or network calls. A future provider requires explicit scope and the relevant technical integration; an AI key alone does not implement those checks.

## Result contract

`AssessmentResult` includes target, target_kind, status, findings and not_checked. Each finding names the check, its status, concise evidence and recommended action. Distinguish candidates from confirmed vulnerabilities and never interpret a partial/not-configured result as an all-clear.

## Concrete collectors in 0.4.0

Use `audit` for local inventory/metadata or explicitly opted-in GitHub, HTTPS, DNS and Gmail read-only collectors. `assess` keeps its original no-network behavior. [LIVE_SETUP.md](LIVE_SETUP.md) provides exact commands, limits and account requirements. None of these collectors claims a comprehensive audit; network errors and omitted checks are not an all-clear.

## Dependency advisory checks and combined reporting (0.5.0)

The separate `audit-deps` workflow supports exact recorded Python/npm versions and opt-in OSV queries. `audit-report` combines existing assessments, preserves source/target/gaps, and provides JSON or escaped standalone HTML. See [DEPENDENCIES_AND_REPORTS.md](DEPENDENCIES_AND_REPORTS.md). The original Python traversal now also stops at 1000 directories or 10000 entries, with an explicit notice.
