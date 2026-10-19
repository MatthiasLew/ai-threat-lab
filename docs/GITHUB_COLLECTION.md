# Read-only GitHub collection

The collector reviews a bounded selection of files from one default-branch commit. It never clones or executes the repository, installs its dependencies, retrieves submodules or opens collected HTML in a browser. API credentials for AI explanations are unrelated to this collector.

```bash
ai-threat-lab scan https://github.com/owner/repository --network --allow-host github.com --output-dir "scan results/github-01"
ai-threat-lab scan-check "scan results/github-01"
ai-threat-lab report-export "scan results/github-01" --format html --output github-report.html
```

Use a repository root URL; direct file/issue/PR URLs are unsupported. The optional `.git` suffix is accepted. `assess` is the legacy no-network router; `audit` performs selected read-only target assessment, while `scan` additionally retains a verified report bundle and shared dependency inventory.

## Snapshot and request scope

The current adapter requests repository metadata, resolves the returned default branch to one immutable commit, reads its recursive tree, and fetches selected blobs by SHA. Blob contents must pass base64, byte-length and Git blob SHA-1 checks. This checks agreement with the supplied object identity; it is not a signed-commit or publisher-trust verification.

Only the fixed public GitHub API host is used. The application HTTP layer enforces HTTPS, exact approved host scope, public-address DNS pinning, an 8 MiB response limit, a 110-request limit, a 15-second socket timeout and no redirects or automatic retries. There is no whole-command deadline or resumable collection. A moved repository, denied access, rate limit, malformed response or unavailable network produces a controlled failure; no fallback to unpinned raw source occurs.

Public repositories need no token. Existing private-repository access uses `GITHUB_TOKEN` from the process environment. Do not put credentials in target URLs or command arguments. Local validation accepts at most 4096 visible ASCII characters without whitespace; empty/missing values use anonymous access. Token permissions, account access and organization SSO remain unvalidated until a separately controlled live check. The program does not create or change tokens.

## Selection and limits

Provider JSON objects/arrays have at most 64 nested container levels, counting the root object. Excessive depth and decoder recursion failures become controlled provider errors. This limit is independent of the interpreter’s JSON recursion threshold.

- Default: at most 50 selected files; `--max-files` accepts 1–100. Source/config text is limited to 256 KiB per file; selected dependency manifests can use their documented 2 MiB parser limit. All selected files share the 4 MiB total byte budget.
- Supported root manifests take priority in `scan`; up to 20 are retained. `--recursive-dependencies` opts into supported nested manifests, with portable path/depth and 10,000-entry inspection bounds. It does not add broader source-language analysis.
- Only regular executable/non-executable blobs are eligible. Symlinks, submodules, excluded dependency/build folders, absolute/traversal paths and unsupported formats are not fetched. Repeated blob identities reuse verified bytes; paths still count toward selected-file/byte budgets.
- GitHub tree truncation, oversize/unknown sizes, UTF-8 failures, parser limitations and exhausted budgets remain explicit gaps. Source-language analysis is the shared bounded implementation documented in the Python/config guides.

Dependency inventory is offline after collection. OSV advisory lookup additionally requires `--share-packages` and `--network`; without those flags, no package identities are sent to OSV. No AI request is made by the collector or `scan` itself.

## Interpreting results

A partial result with no findings is not an all-clear. Candidate observations do not prove exploitability. The saved bundle retains summaries, evidence references, inventory and gaps, not raw downloaded source bodies. Paths, package names and evidence can still reveal project structure; review the report before sharing it.

Provider errors do not authorize retries against another branch/host. After correcting access, invalid local token text or connectivity, run a new explicit scan in a new output directory. Historical bundles remain readable without the source repository. Comparing different commits is still subject to the existing target/scope/engine compatibility checks.

Fixtures validate the wire and failure handling without contacting GitHub. They do not establish live-account readiness. See [offline acceptance](GITHUB_OFFLINE_ACCEPTANCE.md), [scan workflow](SCAN_WORKFLOW.md), [manifest scope](MONOREPOS.md) and [implementation limits](DELIVERY_STATUS.md).
