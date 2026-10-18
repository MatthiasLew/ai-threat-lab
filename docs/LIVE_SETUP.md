# Integration setup and readiness — 0.5.0

These are concrete **read-only** integrations, tested with fixture responses. Live authentication, account availability and provider behavior still need controlled validation. An API key cannot guarantee a full vulnerability audit.

## Commands and access

| Input | Command | Credentials/configuration | Implemented checks |
| --- | --- | --- | --- |
| Local project | `ai-threat-lab audit path/to/project` | None | Selected Python AST patterns, credential patterns, floating npm versions |
| Exported email | `ai-threat-lab audit path/to/export.eml` | None | Bounded header/link/attachment-metadata candidates; no visits, payload execution or authenticity verdict |
| Program file | `ai-threat-lab audit path/to/program.exe` | None | Bounded PE/ELF headers/flags, size and SHA-256; no execution/disassembly/signature trust |
| GitHub repository | `ai-threat-lab audit https://github.com/owner/repo --network --allow-host github.com` | Public: no key needed. Private: scoped `GITHUB_TOKEN` | Default branch pinned to immutable commit, selected text blobs, digest verification, Python and secret/manifest rules |
| Website | `ai-threat-lab audit https://your-domain.example --network --allow-host your-domain.example` | Approved exact host and public HTTPS on port 443 | One response; selected CSP/HSTS/MIME/referrer header checks |
| Mail domain | `ai-threat-lab audit mail-domain:your-domain.example --network --allow-host your-domain.example --dkim-selector actual-selector` | No key; Cloudflare DoH resolver gets queried domain/selector | SPF/DMARC presence and basic policy checks; supplied DKIM TXT presence |
| Gmail mailbox | `ai-threat-lab audit mailbox:owner@example.com --network --allow-host gmail.googleapis.com` | `GMAIL_ACCESS_TOKEN`, enabled Gmail API and suitable OAuth/admin permissions | Authenticated profile must match target; automatic forwarding and forwarding filters |
| AI explanation | See [API_COSTS.md](API_COSTS.md) | `OPENAI_API_KEY`, available model, explicit prices/budget and evidence-sharing opt-in | Explain the existing findings and their limitations |

Add `--output new-report.json` to save a report. Existing files are never overwritten. Normal `assess` remains the legacy offline router; `audit` is the explicit new collector workflow. No automatic network fallback occurs.

### Gmail permissions

An API key is insufficient for mailbox settings. Supply an **OAuth access token**, not a password, and handle consent/refresh externally. The profile endpoint and settings endpoints need appropriate OAuth scopes (`gmail.metadata` or another profile-compatible grant, plus `gmail.settings.basic` and `gmail.settings.sharing` as applicable). Settings-sharing access may require Google Workspace administration/service-account delegation; it is not guaranteed for an ordinary personal Gmail account. Missing/expired/restricted grants fail without a security conclusion. No OAuth wizard, token refresh, Microsoft 365 adapter or MFA/account-session audit is bundled.

The adapter never downloads message bodies and omits forwarding destinations from findings. It reads three endpoints at most, after account identity checking.

## Network boundaries

- Explicit `--network` and exact `--allow-host` approval; no wildcard/subdomain expansion.
- Public HTTPS only; no plaintext HTTP, alternate ports, embedded credentials, proxies or redirect following.
- DNS resolution rejects private, loopback, link-local, reserved or mixed public/private answer sets. The verified public IP is pinned for the socket while the original hostname is retained for TLS certificate checks.
- GitHub, OpenAI, Gmail and DNS service hosts are fixed by their integrations. A repository-supplied URL cannot choose a new credential destination.
- No source installation, hooks, execution, extracted archives or submodules.
- Request, response-byte and per-socket timeout bounds; no automatic retries. OS DNS resolution uses the system resolver and is not governed by the socket timeout. Timeouts are not a whole-job wall-clock deadline.
- Website results skip header conclusions on non-200 responses; redirect/error pages do not become a successful audit.
- Provider failures omit response bodies and credentials.

## Collection limits

GitHub: at most 50 selected files by default (`--max-files 1..100`), 256 KiB/file, 4 MiB decoded text and 110 HTTP requests. A single JSON response is capped at 8 MiB. Truncated trees, oversized/non-UTF-8/unparseable files and limits are explicit in `not_checked`. Symlinks, submodules and dependency/build directories are skipped. No arbitrary branch selection in this release.

Local inventory: up to 100 selected text files, 256 KiB/file and 1000 traversed directories for the additional secret/manifest pass. The Python pass has a 100-file result cap plus traversal caps of 1000 directories and 10000 entries. Program-file header inspection reads at most 16 MiB with selected record-count/range bounds. This is not a malware scanner or full secret scanner. Dependency versions are inspected for selected floating npm declarations; the separate `audit-deps --network --share-packages` workflow can query OSV for exact pinned versions. See DEPENDENCIES_AND_REPORTS.md.

Mail domain: two DNS queries, or three with a selector. No SPF include traversal, organizational-domain DMARC inheritance, cryptographic DKIM validation or selector discovery. Missing records and weak-policy observations are candidates, not proof of spoofing or exploitability.

## Remaining product work

These modules do **not** implement active exploitation, password guessing, live phishing dispatch, deepfake generation, real phone calls, speech understanding, tracking-link services or a webhook backend. Training continues to use fictional/consented identities, synthetic data, exact preview approval and demo transports. Adding a model key does not implement those services. A production training integration would additionally need selected vendors, verified sender/caller identities, approved recipients, media-consent controls, event authenticity, cancellation and retention policies.

Before production use, validate your actual provider account, network policy, OAuth scopes, rate limits, costs, output quality, account mismatch, expired credentials, errors and limits against resources you control.

References: [GitHub trees](https://docs.github.com/en/rest/git/trees), [Git blobs](https://docs.github.com/en/rest/git/blobs), [Gmail profile](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users/getProfile), [Gmail settings](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.settings), [Cloudflare DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/).

## Dependency and merged-report workflows (0.5.0)

`audit-deps` produces an offline inventory by default. Adding both `--network --share-packages` enables fixed-endpoint OSV advisory queries, optionally with a TTL cache. `audit-report` merges assessment reports to JSON or standalone HTML. Neither command uses an AI model. See [DEPENDENCIES_AND_REPORTS.md](DEPENDENCIES_AND_REPORTS.md) for formats, scope, limits and interpretation.

The HTTPS client additionally permits POST only to `https://api.osv.dev/v1/querybatch`. This is a read-only database query carrying names/versions, never an installation, package publication or arbitrary target request.

## Local training sessions (0.6.0)

The `training-*` commands provide persistent, approved **local text rehearsals** without any provider key or network. They add structured selections, stop/expiry/cancellation and JSON/HTML practice reports. They do not add live email/phone/media transports, actual tracking or speech understanding. See [TRAINING_LAB.md](TRAINING_LAB.md).

## Combined scan workflow (0.8.0)

`scan TARGET --output-dir NEW_DIRECTORY` orchestrates the same built-in read-only collectors. Existing network/host/OAuth requirements still apply. Local-project and GitHub root dependency inventory is automatic, but OSV package sharing stays explicit. GitHub uses the same immutable commit/shared retrieval for source and manifests. Its combined `scan` additionally allows root manifests up to 2 MiB each, with a shared 4 MiB/file-count budget; ordinary source remains limited to 256 KiB each. No AI API is called by `scan`. See [SCAN_WORKFLOW.md](SCAN_WORKFLOW.md) for bundles, partial failures and comparison.

## Optional monorepo scope (0.10.0)

`audit-deps` and local/GitHub `scan` now accept `--recursive-dependencies` for bounded nested-manifest selection. Root-only stays the default; GitHub still uses one immutable commit/shared retrieval. No AI call, package sharing or external account configuration is enabled by this flag. See [MONOREPOS.md](MONOREPOS.md) for global limits, relative origins and explicit gaps.

## Offline PE/ELF program paths (0.11.0)

`audit PATH_TO_PROGRAM` and `scan PATH_TO_PROGRAM --output-dir NEW_DIR` now perform selected bounded PE/ELF structure/flag checks. No account, API, subprocess or execution is used. Malformed/unsupported structures preserve hash/size and explicit gaps. See [BINARY_AUDIT.md](BINARY_AUDIT.md).
