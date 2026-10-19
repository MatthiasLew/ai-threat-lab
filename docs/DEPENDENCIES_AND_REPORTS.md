# Dependency advisories and remediation reports — 0.14.0

These workflows use local parsing and a vulnerability database, without an AI model. They do not install packages, execute hooks, guess passwords, exploit findings or patch dependencies automatically.

## 1. Inventory exact versions offline

```bash
ai-threat-lab audit-deps path/to/project --output inventory.json
ai-threat-lab audit-deps path/to/requirements.txt
```

| Input | Parsed | Gaps |
| --- | --- | --- |
| `requirements*.txt` | Exact `name==version` lines, extras, basic markers/comments | Ranges, wildcard pins, includes, URLs, editable/VCS references and hash/continuation syntax skipped |
| npm `package-lock.json` v2/v3 | Recorded `packages` entries, transitive/scoped packages and version differences | v1, Yarn/pnpm formats and linked workspaces unsupported |
| `uv.lock` / `poetry.lock` | Versioned registry package records | Local/editable/git sources skipped; no dependency solving |
| `Cargo.lock` v3/v4 | Exact crates.io name/version records | Local/git/alternate registry sources skipped; no checksum/feature/graph/installed-state validation; see [CARGO.md](CARGO.md) |

| `go.sum` | Supported module-content checksum records with exact Go versions | Metadata-only records omitted; no hash/build-list/workspace verification; historical/unused versions may be included; see [GO.md](GO.md) |

By default, only supported root manifests are read. Add `--recursive-dependencies` for bounded nested discovery, or select a subproject directly. Root symlinks/junctions are rejected; child links/non-regular manifests are skipped. Global limits: 20 manifests, 2 MiB each, 4 MiB aggregate bytes and 500 unique package/ecosystem/version tuples. File/package overflow fails before any OSV request; aggregate-byte/traversal stops preserve explicit unchecked notices. Parser warnings have a detailed-notice cap and omitted count; discovery notices have a separate bounded prefix. See [MONOREPOS.md](MONOREPOS.md) for exact selection semantics.

Names are normalized for PyPI. Identical names/versions are deduplicated and source locations preserved; different versions remain separate queries. All recorded development/optional/platform groups are included. Environment markers and runtime installation are not evaluated. Custom registry provenance is not verified; a public database may describe a different package sharing the name/version.

The offline inventory is **not an assessment result** and cannot be merged as if an advisory query happened. Unsupported lines are described without echoing secret-bearing URLs or source text.

## 2. Query OSV explicitly

```bash
ai-threat-lab audit-deps path/to/project --network --share-packages --output dependencies.json
# Optional one-hour cache:
ai-threat-lab audit-deps path/to/project --network --share-packages --advisory-cache advisories.sqlite --output dependencies-cached.json
```

Both flags are required. Review the inventory before sharing: package names/versions may reveal private projects. Only ecosystem, normalized name, exact version and pagination tokens go to the fixed `https://api.osv.dev/v1/querybatch` endpoint; no local paths, source, credentials or manifest URLs are submitted. OSV requires no model key. Public HTTPS/DNS pinning, response limits, no redirects and no automatic retries apply.

Queries use batches of at most 100. Response order/length must match the request. Pagination is bounded by `--max-pages` (default 10, maximum 20); results remain partial when this limit is reached. At most 1000 package/advisory matches are accepted. HTTP/auth/rate errors and malformed responses fail rather than returning a clean assessment. Invalid or repeated pagination tokens are rejected.

OSV's batch endpoint returns IDs, not full advisory details. This release does not fetch severity, aliases, fixed releases or reachability. A finding is a **candidate version/advisory match**, not a demonstrated vulnerability. Review the referenced advisory, runtime usage and upgrade compatibility. Absence of matches is not proof of security.

## Cache behavior

The cache stores hashes of ecosystem/name/version queries, matched advisory IDs and expiry, in plaintext SQLite. A valid cached empty result is distinct from an uncached result. Stale results are not reused and incomplete pages are never cached as complete. Complete earlier package results may remain cached if a later request fails. A one-hour cache can miss an advisory published after its last successful lookup; omit the cache for a fresh query.

Protect the database directory. New POSIX files use `0600`; Windows inherits directory ACLs. Expired entries remain on disk until the database is removed; there is no encryption or automatic disk cleanup. Corrupt cache entries fail visibly. Package matches are not merged by CVE aliases, so multiple advisory IDs may describe the same underlying vulnerability.

## 3. Merge assessments and prioritize review

```bash
ai-threat-lab audit path/to/project --output source.json
ai-threat-lab audit-report source.json dependencies.json --output combined.json
ai-threat-lab audit-report source.json dependencies.json --format html --output report.html
```

Accepted inputs are structured `audit`/`assess`/online `audit-deps` result documents, not offline package inventories or combined reports. Between 1 and 20 inputs, each within the standard 1 MiB JSON input limit, can be merged. At most 2000 findings per input. Very large exports may require a smaller scope before reuse in another bounded input workflow.

Duplicate findings are identified by exact target and finding fields. The report preserves source indices, each assessment's status and all `not_checked` notices. The same finding on different targets is kept separate. Input order establishes source indices. The combined result always remains `partial`, including with empty or not-configured inputs.

| Review priority | Rule | Meaning |
| --- | --- | --- |
| P1 | Possible exposed credential pattern | Review promptly; verify and rotate if exposure is real |
| P2 | Dependency advisory, selected risky Python patterns, forwarding configuration and selected mail content candidates | Investigate applicability and approved configuration |
| P3 | Other observations | Review remaining configuration/metadata candidates |

These values order human review. They are not CVSS scores, verified severity, deadlines or evidence that an exploit exists. Candidate status is retained. Unknown rule IDs default to P3.

HTML is a standalone, escaped document with no JavaScript, remote assets, forms or clickable provider-supplied links. Its CSP blocks active/external content. It can be opened locally or printed from a browser. JSON retains stable IDs and provenance for further tooling. Reports may contain sensitive target names and evidence; protect them like the source assessments. Existing output files are never overwritten.

## Verification

Deterministic tests cover parsing, skipped/secret-bearing input, duplicates/versions, wire payloads, request ordering, pagination and caps, cache restart/expiry, malformed responses, per-target report deduplication, HTML escaping and actual CLI processes. The installed-wheel verifier checks inventory and merged JSON/HTML outside the checkout. No real OSV package submission or paid AI call was used to produce this test evidence.

Primary reference: [OSV batch API and pagination](https://google.github.io/osv.dev/post-v1-querybatch/).

## GitHub inventories in combined scans — 0.8.0

Use `scan GITHUB_URL --network --allow-host github.com --output-dir NEW_DIR` for source and supported root manifests from one pinned commit. Add `--share-packages` to query OSV; no model is called. The shared 4 MiB/file-count budget, 20-manifest limit, provenance, module failures and old-bundle compatibility are described in [SCAN_WORKFLOW.md](SCAN_WORKFLOW.md). Standalone `audit-deps` continues to accept local paths only.


## Nested projects — 0.14.0

Add `--recursive-dependencies` to `audit-deps` or `scan` for bounded monorepo discovery. This preserves paths/line origins and deduplicates exact identities globally without interpreting workspace graphs or installing packages. Root-only selection remains the default. Local discovery in both modes now has a global 4 MiB raw-byte cap with explicit unchecked notices. See [MONOREPOS.md](MONOREPOS.md) for all bounds, exclusions and comparison semantics.

The 0.39.0 [offline completion contract](DEPENDENCIES_OFFLINE_ACCEPTANCE.md) adds strict cache clock/expiry/row validation, per-access file guards, validated writes and full pagination-cycle detection, with installed socket-blocked CLI acceptance.
