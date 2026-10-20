# Composer and NuGet recorded dependency inventory

The existing dependency workflow now recognizes `composer.lock` and
`packages.lock.json` in local projects and pinned GitHub snapshots. No PHP,
Composer, .NET or NuGet installation is required; no restore, build or project hook runs.

```bash
ai-threat-lab audit-deps project/composer.lock
ai-threat-lab audit-deps project/packages.lock.json
ai-threat-lab audit-deps project --recursive-dependencies
ai-threat-lab scan project --recursive-dependencies --output-dir results/dependencies
```

## Recorded identities

Composer reads `packages` and optional `packages-dev`. Supported numeric release
tags, including a leading `v` and prerelease/build labels, are preserved verbatim.
Development branches, wildcard/range versions and local path distributions are skipped
with redacted notices. At most 2,000 recorded rows are examined. Platform requirements,
plugins, aliases and dependency solving are not evaluated.

NuGet reads lock versions 1 and 2, at most 64 framework/runtime maps and 5,000
recorded rows. `Direct` and `Transitive` records use `resolved`, never the requested
range. Project references and unsupported record kinds are skipped. Numeric
two-to-four-component versions with optional prerelease/build labels are supported.
Only the default `packages.lock.json` basename is discovered; custom lock filenames
are not selected automatically.

Names and recorded versions remain case-preserved. Identical ecosystem/name/version
tuples merge across files and target maps, retaining relative manifest origins.
The common limits still apply: 20 manifests, 2 MiB each, 4 MiB total and 500 unique
package identities. Duplicate JSON keys and malformed containers fail visibly.
Omitted warnings are counted, while provenance limitations remain visible.

## Advisory lookup and evidence

With explicit `--network --share-packages`, the same OSV/cache path queries
`Packagist` and `NuGet` identities. Paths, lock contents and source/distribution URLs
are not sent. Offline inventory alone never claims an advisory lookup occurred.
Installed-package acceptance checks both formats without sockets; fixture transports
check the exact OSV request identities.

Registry/feed provenance and content hashes are unverified. In particular, Composer
may use custom registries and NuGet may use private feeds. A matching public-database
identity can refer to different bytes. Review applicability before acting on an advisory.
All recorded groups/frameworks are included; installed state, selected runtime,
reachability and exploitability remain unchecked.

Scan engine 27 records the expanded discovery semantics. Earlier bundles remain
readable, but cross-engine comparisons do not produce finding deltas.

The formats follow [Composer's lockfile workflow](https://getcomposer.org/doc/01-basic-usage.md#installing-dependencies)
and [NuGet's recorded dependency structure](https://github.com/NuGet/Home/wiki/Repeatable-build-using-lock-file-implementation).
Advisory identities use the [OSV ecosystem definitions](https://ossf.github.io/osv-schema/#affectedpackage-field).
