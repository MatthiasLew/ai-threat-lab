# Cargo dependency inventory — 0.14.0

Rust projects can use the existing offline dependency workflow. No Rust toolchain, package installation, compiler, build script, Cargo command or model/API key is required.

```bash
ai-threat-lab audit-deps path/to/Cargo.lock --output rust-inventory.json
ai-threat-lab audit-deps path/to/workspace --recursive-dependencies
ai-threat-lab scan path/to/workspace --recursive-dependencies --output-dir scan-results/rust-01
```

## Exact selection

Only a TOML `Cargo.lock` with integer lock version 3 or 4 and a `package` array is supported. A supported record has a valid bounded crate name, exact selected SemVer form, and source exactly `registry+https://github.com/rust-lang/crates.io-index`. Its ecosystem is `crates.io`. Numeric core/prerelease leading-zero violations, incomplete/ranged versions and malformed versions are skipped with values omitted. Build metadata and prerelease identifiers are retained. General version length and identity limits still apply.

A missing source (typically a local/workspace package), git URL, alternate/private registry or unrecognized sparse spelling is skipped. This prevents labeling a different source as a public crates.io dependency. A lockfile can itself be forged: the recorded source does not authenticate a package. Checksums are not verified. Local/git records do not become crates.io matches by name coincidence.

Root-only discovery remains the default. `--recursive-dependencies` discovers nested Cargo.lock files within the shared depth/directory/entry/manifest budgets. Local and pinned GitHub scans reuse the existing parser, preserve relative origins and deduplicate ecosystem/name/version tuples. Different versions remain distinct. Crate spelling is preserved; PyPI normalization is not applied to crates.io.

All recorded selected crates are included. Dependency edges, feature activation, workspace resolution, target/platform conditions, installed artifacts and runtime reachability are not evaluated. A clean or empty inventory does not establish a secure Rust application. `Cargo.toml` and lockfile versions 1/2 are not resolved automatically. Unsupported or malformed lockfiles fail visibly; skipped identities retain explicit notices.

## Bounds and optional advisory lookup

The existing shared limits remain: 20 manifests, 2 MiB each, 4 MiB aggregate bytes and 500 unique package identities. These include manifests from other supported ecosystems. Nested traversal and GitHub request/path/blob limits also remain. No additional fetch occurs to resolve an unknown source.

OSV lookup remains a separate explicit operation requiring both network permission and package-sharing consent:

```bash
ai-threat-lab audit-deps path/to/Cargo.lock --network --share-packages --output rust-advisories.json
```

The existing OSV batch body uses `package.ecosystem: "crates.io"`, the recorded name and exact version. Existing pagination/cache/budget rules apply. A version/advisory match is a candidate for applicability review, not proof of exploitability. No real crate submission was used as release acceptance evidence; wire tests are synthetic. API/account setup remains deferred.

Primary format references: [Cargo registry index](https://doc.rust-lang.org/cargo/reference/registry-index.html), the Rust project's [Cargo.lock](https://github.com/rust-lang/rust/blob/main/Cargo.lock), and [OSV-Scanner ecosystem output examples](https://google.github.io/osv-scanner/output/). See [dependency workflow](DEPENDENCIES_AND_REPORTS.md) and [monorepo bounds](MONOREPOS.md).
