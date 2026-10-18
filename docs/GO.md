# Go checksum-record inventory — 0.18.0

Go projects can use the existing offline dependency workflow without a Go toolchain or API key:

```bash
ai-threat-lab audit-deps path/to/go.sum --output go-inventory.json
ai-threat-lab audit-deps path/to/project --recursive-dependencies
ai-threat-lab scan path/to/project --recursive-dependencies --output-dir scan-results/go-01
```

## Recorded identities and coverage

The parser reads three whitespace-separated fields per nonempty line: module path, version and checksum. Only module-content records are included. Versions ending in `/go.mod` describe module metadata and are omitted with a notice, even when their hash syntax is supported. Repeated identities merge their manifest origins; different versions remain separate. Module paths retain their case and Go versions retain their `v` prefix.

This is a conservative recorded-identity inventory. A `go.sum` file may contain historical or unused versions. It does not establish the selected build list, installed modules or exploitable application dependencies. `go.mod`, `go.work`, replacement/exclusion directives, vendoring, toolchain/standard-library versions, target conditions and runtime reachability are not resolved. Module major-suffix consistency and pseudo-version timestamps/revisions are not validated.

Supported paths are a bounded ASCII subset: up to 512 characters, a lowercase domain-like first component containing a dot, followed by optional nonempty components containing letters, digits, `.`, `_`, `~` or `-`. Dot-prefixed/dot-suffixed components, traversal, URL schemes, backslashes, escaped proxy spellings (`!`), Unicode and unsupported identities are skipped. This is not a full implementation of Go's path validator.

Versions are at most 128 characters: `vMAJOR.MINOR.PATCH`, optional SemVer prerelease identifiers and optional `+incompatible`. Leading-zero core numbers and numeric prerelease identifiers are rejected. Common pseudo-version spellings pass the syntax check; their source provenance is unchecked. Other build metadata, incomplete versions and branch names are omitted.

Only `h1:` followed by canonical Base64 for 32 bytes is accepted. **No checksum is verified** against module content, a proxy or the checksum database. A forged record or two conflicting hash fields do not become trusted by passing this format check. Hashes and rejected input values are omitted from output. Accepted module identities remain visible in the inventory and can disclose private module names.

## Bounds and shared integration

The parser enforces 20,000 lines per file plus the shared 2 MiB per manifest, 4 MiB aggregate, 20 manifest and 500 unique identity limits. Line/package/individual-byte overflow fails visibly. Detailed inventory notices are capped with an omitted count. Existing recursive discovery and immutable GitHub request/blob budgets remain in force. Invalid UTF-8 fails; unsupported individual records are skipped with explicit coverage notices. Empty input is not proof of security.

The existing optional advisory adapter uses ecosystem `Go`, recorded module path and exact recorded version. Both `--network` and `--share-packages` remain required to contact OSV; default scans do not submit package identities. Wire compatibility is checked with synthetic responses, without live advisory submission. A database match is a candidate for applicability review. API/account setup remains deferred.

The synthetic demo includes `example.invalid/fixture-module` and a deliberately fictional checksum field. It is never fetched, built or verified. See [offline acceptance](OFFLINE_ACCEPTANCE.md), [dependency reports](DEPENDENCIES_AND_REPORTS.md) and [monorepo bounds](MONOREPOS.md).

Primary references: [Go module and go.sum format](https://go.dev/ref/mod#go-sum-files), [Go versions](https://go.dev/ref/mod#versions), [OSV package ecosystem schema](https://ossf.github.io/osv-schema/#affectedpackage-field).
