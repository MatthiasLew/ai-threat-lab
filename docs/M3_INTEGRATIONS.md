# M3 proposal: import external analysis results

Start with the existing SARIF import contract and require explicit input selection.
Preserve producer, version, rule ID, severity, scope and provenance. Apply input size
limits and secret redaction before report storage. Inspect generated SARIF fixtures
for path normalization, duplicate observations, malformed records and secret handling.

| Tool | Project license | Installation and runtime | Result formats to evaluate |
| --- | --- | --- | --- |
| Bandit | Apache-2.0 | Isolated Python environment, pip package and SARIF extra | JSON, SARIF. [Upstream installation](https://github.com/PyCQA/bandit/blob/main/doc/source/start.rst) [Package metadata](https://pypi.org/project/bandit/) |
| Semgrep CLI | LGPL-2.1 | Pinned CLI from uv or an isolated container, with local rules. Review each rule pack's terms independently. | JSON, SARIF. [Upstream repository](https://github.com/semgrep/semgrep) [CLI documentation](https://semgrep.dev/docs/cli-reference) |
| Gitleaks | MIT | Pinned platform binary or container, reviewed configuration and redaction | JSON, CSV, JUnit, SARIF. [Upstream repository](https://github.com/gitleaks/gitleaks) |
| Trivy | Apache-2.0 | Pinned binary or container plus versioned advisory databases. Record freshness and stage databases before an offline run. | JSON, SARIF. [Upstream repository](https://github.com/aquasecurity/trivy) [Reporting](https://trivy.dev/latest/docs/configuration/reporting/) |

Defer execution adapters until explicit authorization and isolation design review.
Prefer fixed command arguments, an approved local snapshot, read-only input and
supervised resource limits for any later opt-in execution. Pin and review licenses
for the exact versions, rules and databases before distribution.

## M3.1: offline SARIF interoperability

The current `review-sarif` command and `review_sarif(path, start, max_entries)`
Python function accept a local SARIF 2.1.0 file up to 8 MiB, at most 20 runs,
and at most 200 selected observations per page. The importer reads inline
message text, driver name, rule ID or driver rule index, direct or indexed
physical locations, result level/kind, baseline and suppression statuses. It
keeps these as unverified external evidence and reports incomplete invocations
and unsupported rows separately. It does not persist structured producer
version, rule precision or suppression kind.

Valid message references without inline text, logical-only locations, tool
component rule references and runs without an inline results array are not
handled. URI bases are displayed but not resolved. External property files
are deliberately not opened. Code flows, snippets, fixes, raw fingerprints
and related locations are outside the current projection.

| Order | Producer | Expected current coverage and first fixture |
| --- | --- | --- |
| 1 | Bandit | The [documented 1.7.8 example](https://bandit.readthedocs.io/en/latest/formatters/sarif.html) fits the current inline message, indexed rule, URI and invocation shape. Add a pinned empty and non-empty report fixture; preserve version and Bandit's issue confidence separately from severity. |
| 2 | Semgrep | Inline-text results with physical locations and driver rules can use the generic importer. Verify a pinned [Semgrep CLI](https://semgrep.dev/docs/cli-reference) fixture for OSS rules, multiple findings, code-flow omission and producer diagnostics before claiming version-specific compatibility. |
| 3 | Trivy | The [official SARIF output](https://trivy.dev/docs/latest/configuration/reporting/) supports several scanners. Validate each separately: file-based findings and package/image locations have different identity and scope. Preserve package and target provenance without interpreting a package location as a local path. |
| 4 | Gitleaks | The [upstream writer](https://github.com/gitleaks/gitleaks/blob/master/report/sarif.go) emits compatible inline text and physical locations, but embeds raw secret snippets and private commit metadata. Require a redaction gate and verify a fixture before offering producer-specific support. |

Implement in this order:

1. Add checked-in, inert fixtures with provenance, pinned producer version,
   license and hashes. Test the existing reader against them before changing
   normalization. No executable or live scanner is needed in the core suite.
2. Add a versioned external observation model carrying producer name and both
   reported version fields, original rule ID and optional component ID, raw
   classification, independently mapped severity and optional reported
   confidence, baseline, suppression kind/status and invocation outcome.
   Unknown values stay unknown. Missing invocations or omitted rows must never
   imply a successful clean scan.
3. Accept safe inline aliases and index references with explicit limits,
   including direct/indexed path and driver/extension rule identity.
   Keep locations as inert labels. Normalize relative URI syntax for
   comparison only; do not dereference files, URLs, base IDs or external
   catalogs. Strip raw snippets, fix content, private metadata and credentials
   before persistence, rendering or logging. Cover absolute paths, traversal,
   URI credentials, control characters and synthetic secret canaries.
4. Derive a bounded duplicate key from producer/component/rule and canonical
   location plus result identity where available. Retain provenance and
   occurrence counts. Do not merge different producers automatically or use
   arbitrary producer fingerprint text as an identifier exposed to users.
5. Project structured observations into the existing CLI and Python result
   shapes by default. Add an opt-in versioned structured export. Keep imports
   visibly separate from native audit bundles. Leave the nine MCP contracts
   intact; any later MCP import needs explicit path selection, a pinned local
   read, redacted output, an output cap and separate contract tests.

## M3.2: optional scanner execution

Review one adapter at a time after M3.1. Require an independently approved
executable/version, rule and database licenses, explicit execution and data
permissions, no shell, read-only snapshot inputs, bounded time/memory/output,
isolated scratch, and separate handling for finding exits versus scanner
errors. Review Windows/Linux containment and offline behavior before enabling
an adapter. Keep scanner packages and databases optional.
