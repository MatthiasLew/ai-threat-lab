# GitHub collector offline completion — 0.35.0

This accepts the existing bounded read-only GitHub collector using synthetic HTTP responses. It does not validate a real GitHub account or private repository, and it adds no language/analyzer coverage. AI API setup and controlled live-account acceptance remain deferred.

| Contract | Acceptance evidence |
| --- | --- |
| Explicit routing | A repository root URL requires the CLI network flag and exact approved `github.com` host. Local/legacy assessment does not silently start requests. |
| Immutable selection | Resolve the default branch once, retain its 40-character lowercase commit SHA, and fetch the recursive tree and selected blobs through immutable identities. No checkout, package install or target execution occurs. |
| Bounded input | Existing selected-file, byte, manifest, response, request and traversal bounds plus per-socket timeout remain in force. Exclusions, skipped input and tree truncation remain report gaps. |
| Verified blob bytes | Validate base64, length and Git blob digest before analysis. Distinct paths can reuse verified bytes from one blob request; a conflicting size/path is rejected. |
| Shared inventory | Scan source and root/opt-in nested manifests use one snapshot and shared budgets. OSV requests need separate explicit package-sharing permission. |
| Error contract | Invalid commit/blob SHA types, unusable branch strings, malformed truncation metadata, invalid dependency-selection types and provider JSON beyond 64 container levels become controlled errors. Failed HTTP responses are not retried; response bodies and credentials are not copied into diagnostics. |
| Credential boundary | Existing `GITHUB_TOKEN` remains optional; when supplied, reject unsupported length/characters before any request without echoing its value. This is local header validation, not an account or permission check. |
| Report behavior | Findings remain candidates, assessment remains partial, skipped checks stay visible, saved bundles verify and contain no collected source bodies. A failed collector produces explicit failed scan modules. |
| Installed acceptance | A clean wheel runs a synthetic end-to-end GitHub scan with sockets blocked; assert the exact five-request snapshot/blob reuse wire, verified saved inventory and malformed/denied/rate-limit negative controls. |

The release gate is `python scripts/verify.py`, including full tests, branch coverage, package build, fresh installed workflows and Linux/Windows Python 3.12–3.14 CI at the release commit. Existing GitHub controls span the remote-audit, shared-scan, monorepo and project-flow suites. The added boundary regressions and installed fixture are `tests/test_github_boundary.py` and `scripts/check_github_offline.py`.

No claim is made about real private-repository authorization, current rate-limit quotas, organizational SSO, GitHub Enterprise, arbitrary refs/PRs/submodules/LFS, full repository semantics or absence of vulnerabilities. See [collector usage and limits](GITHUB_COLLECTION.md) and [remaining work](DELIVERY_STATUS.md).
