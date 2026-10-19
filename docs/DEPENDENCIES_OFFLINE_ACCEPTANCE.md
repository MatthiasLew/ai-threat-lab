# Dependency inventory / OSV / cache — offline completion contract

Version 0.39.0 closes the existing bounded dependency workflow, rather than adding more ecosystems or full dependency-graph analysis. It includes local/root or opted-in nested manifest inventory, pinned GitHub parity, opt-in OSV version/ID matching and a local advisory cache. API/account setup and controlled live acceptance remain deferred.

## Scope and usage

See [inventory formats, reports and usage](DEPENDENCIES_AND_REPORTS.md), [nested discovery](MONOREPOS.md), [Cargo](CARGO.md), [Go checksum records](GO.md) and [GitHub snapshot collection](GITHUB_COLLECTION.md). Existing file/count/byte/discovery and parsing limits remain unchanged. No package manager, package installation or target execution is introduced.

```bash
ai-threat-lab audit-deps ./project
ai-threat-lab audit-deps ./project --recursive-dependencies
ai-threat-lab audit-deps ./project --network --share-packages \
  --advisory-cache ./advisories.sqlite
```

The first two commands stay offline. Online routes require explicit sharing consent: only ecosystem, name, exact recorded version and optional opaque page token are sent to the fixed OSV batch endpoint. Neither manifest source contents nor source paths are sent in the request body. The built-in OSV client allows up to 20 requests and 2 MiB per response. OSV batches are at most 100 packages; the selected request limit is 1–20, default 10. Existing coverage notices, unmatched packages and incomplete pages remain visible.

OSV response position must match query position and length. Advisory IDs and token types/lengths are checked. Repeated nonempty pagination tokens are now detected across the entire per-package traversal, including multi-step cycles. The same opaque token for different packages is allowed. Exceeding the request limit leaves explicit incomplete results; incomplete package results are not cached as complete. Successfully completed earlier packages may remain cached if a later package or request fails.

## Cache contract

| Boundary | Implemented behavior |
| --- | --- |
| File lifecycle | Create on explicit construction, with POSIX mode 0600; regular-file/link/junction checks before every connection; missing files are not silently recreated by an existing cache object |
| File size | Reject files over 128 MiB before opening; no automatic eviction or compaction |
| Clock | Integer/float, finite, nonnegative, at most `10**12` seconds; booleans and unsupported values fail before reuse/write |
| Stored expiry | Numeric finite timestamp within `0..10**12 + 86400`; malformed expiry is an explicit validation failure |
| Freshness | Expiry equal to or before the current clock is a miss; valid cached `[]` is a hit; stale rows are not reused |
| Row materialization | SQL returns response text only when its encoded size is at most 262,144 bytes; unsupported/oversized live rows fail before Python JSON parsing |
| Identity values | At most 1000 bounded advisory-ID strings per entry; validated writes, canonical deduplication/order and validation on read |
| Failure | Invalid writes preserve the previous valid row; malformed live entries fail visibly, without fallback to a clean assessment |

Expired entries remain on disk. Cache directories must be protected; files are plaintext, and Windows inherits directory ACLs. Checks are not a race-free filesystem snapshot, hard-link defense or proof against replacement by a process that can modify the directory. There is no encryption, authentic advisory provenance, monotonic-clock continuity guarantee, automatic repair, disk cleanup or whole-job deadline. Clock rollback and changes in the external advisory database can affect cache freshness; omit the cache for a fresh query. The size check is an access guard, not a disk quota for concurrent writers.

Legacy cache rows with the existing `advisories(key, expires, response)` schema and valid values remain readable. No destructive migration or removal of user databases occurs. Metadata corruption is a validation error; SQLite structural/locking failures remain explicit storage failures. They do not establish a clean result.

## Required evidence

- Existing dependency/manifest/Cargo/Go/nested-discovery/GitHub tests remain required.
- `tests/test_advisory_cache_boundary.py` checks timestamp and JSON corruption, response/file limits, clock types, invalid-write rollback, empty-result semantics, expiry, legacy entries, removed/replaced paths, cached aggregate limits and multi-step/per-package pagination behavior.
- `scripts/check_dependencies_offline.py` uses fake OSV responses, real SQLite and blocked sockets/DNS through CLI services. It checks two successful requests, two cache-only workflows, four negative controls and a verified scan bundle; no live or AI calls occur.
- The installed-wheel verifier invokes this acceptance outside the checkout. Ruff, pytest/coverage, package build and all six Linux/Windows Python 3.12–3.14 CI configurations must pass.

Engine `read-only-pipeline-26` records changed cache/pagination acceptance. Earlier bundles remain readable and cross-engine observation comparison remains unavailable.

## Remaining integration and analytical limits

Real OSV behavior/availability and account/network environments are not established by fixtures. No severity, fix-version, alias grouping, runtime reachability, build-selected dependency resolution, installation state or exploitability is inferred. Existing Python/npm/Cargo/Go input subsets remain bounded; broader ecosystems and workspace graphs require separate engineering. A lack of advisory matches does not mean a package or project is secure.
