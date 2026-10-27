# Offline CLI release criteria — 0.41.4 source

This is the finite acceptance scope for the existing offline CLI. It supersedes open-ended feature expansion as the current engineering priority. Passing it accepts this scoped delivery; it does not complete the original product or establish real-provider readiness. API credentials/live validation and GUI implementation remain deferred.

## Scope freeze

Keep the currently documented Python, manifest/configuration, dependency, PE/ELF, exported-mail, reporting, cost-control and local training subsets. Fix defects and missing acceptance coverage before adding another language, framework, attack capability or provider. Unsupported semantics must stay visible as gaps rather than being guessed. New functionality requires a separately bounded milestone with positive/negative controls and an observable completion criterion.

## Bounded addition — 0.27.0

The new milestone adds saved HTML, shared EML/response HTML authoring checks and explicit ZIP metadata targets. Acceptance requires selected positive/negative parser controls, no rendering/member-read checks, preserved header results when a body is unavailable, local/GitHub parity, CLI/single/batch bundle routing, engine-19 compatibility, demo failure controls and clean installed-wheel execution. Limits are documented in [HTML_REVIEW.md](HTML_REVIEW.md) and [ARCHIVE_REVIEW.md](ARCHIVE_REVIEW.md). This does not expand the live-provider scope.

## Bounded authentication-log addition — 0.28.0

Acceptance requires strict normalized JSONL parsing, bounded windows/thresholds, duplicate/order/reset controls, source-free evidence, explicit file-only routing, no account/network calls, independent prefix-window oracle checks, paired demo failure controls and clean installed-wheel CLI/bundle validation. Limits and unresolved native provider conversion are documented in [AUTHENTICATION_LOGS.md](AUTHENTICATION_LOGS.md).

## Bounded signed-claim journal addition — 0.29.0

Require exact-plan/alias/key binding, strict envelope/time validation, independent HMAC vector, atomic duplicate/conflict/stop behavior, writer-lock scope rechecks, cancellation persistence and simulation/automation/adapter separation. The three-channel demo must reject altered signatures and post-cancellation claims before completion; installed-wheel CLI key/register/import/replay/report/cancel paths must pass. Native provider telemetry remains outside this local contract. See [SIGNED_TRAINING_EVENTS.md](SIGNED_TRAINING_EVENTS.md).

## Required acceptance evidence

| Gate | Completion criterion | Evidence |
| --- | --- | --- |
| Installation and CLI | Supported commands work from an installed wheel outside the source checkout, including paths with spaces; error/help/exit-code contracts pass | `scripts/check_installed_package.py`, `tests/test_cli_process.py`, CI on Linux/Windows and Python 3.12/3.13/3.14 |
| Assessment routing | Local files/directories, exported mail and fixture-backed GitHub/web/domain/mailbox routes retain their documented scope and partial/error results | Assessment, local/remote audit, header, DNS/Gmail and CLI tests |
| Analyzer correctness | All confirmed defects have a failing pre-fix reproduction and passing regression control; unsupported bindings retain gaps | Python flow/package/shadowing tests plus config, dependency, binary and mail fixtures |
| Network boundary | No automatic target-source execution; remote checks require documented opt-ins and host/address/request limits | HTTP-client and integration tests, fixture transports and nonexecution checks |
| Report integrity | JSON/HTML/SARIF and single/batch bundles retain evidence, escaping, no-overwrite behavior and consistency checks | Report, SARIF, scan/batch/bundle tests and the installed-wheel gate |
| Scope compatibility | Old supported bundles remain readable; changed observation semantics cannot be compared across engines | Engine compatibility and comparison tests |
| Cost controls | Dry-run, budget reservations, input/output caps, cache isolation, concurrent deduplication and uncertain-outcome policy pass without live model calls | AI adapter/cost/cache tests and installed CLI workflows |
| Local training | Three text rehearsal channels preserve scope, exact approval, cancellation, restart/replay and outcome provenance | Campaign, lab, CLI and offline-demo tests |
| Positive and negative demo | `offline-demo` verifies expected observations and rejection controls before writing completion; every generated bundle verifies | Demo acceptance tests and clean installed-wheel execution |
| Quality and packaging | Ruff, full coverage suite (minimum 90%), source/wheel build and installed-wheel checks pass at the exact release commit | `python scripts/verify.py` and six CI jobs |
| Documentation | README, capability inventory, current scope and remaining engineering agree; no claim that API keys alone complete the product | `DELIVERY_STATUS.md`, `readiness`, analyzer scope documents and this checklist |

Counts and coverage measurements belong to the tested commit. A larger test count alone does not satisfy any correctness gate. A known defect blocks acceptance even if CI is green. A source-visible defect requires a fix, a regression test and rerunning the relevant release gates.

## Package-binding defect closure

The 0.26.1 correction distinguishes a package's assigned attribute from an absent attribute, and an import operation from ordinary attribute access. The paired demo requires three observations for a package with an importable absent child and one API-pattern observation when an assigned attribute blocks that child. It must not interpret the count difference as a confirmed vulnerability or a real remediation result.

Namespace uncertainty from skipped module-level barriers is retained. Explicit dotted imports retain bounded loaded-child facts through aliases and supported helper returns; branch joins keep only common facts. An initializer's selected top-level imports can establish child attributes without restoring a cached child after a later reassignment. Conditional initializer import effects remain explicit gaps. Test-authored inert import-oracle fixtures independently compare selected bindings against Python; analyzed target sources are never imported. Dynamic attribute mutation and process-wide module state remain outside the abstraction.

## Work outside this release

These are separate engineering tracks, not hidden conditions that can be satisfied by adding an API key:

1. Broader code/framework/language and dependency-graph analysis, selected for a concrete deployment.
2. Controlled web-application assessment with authentication, navigation and business-logic criteria.
3. More mailbox providers, account validation and message-authenticity/delivery evidence.
4. Deeper binary/signature/platform analysis in an explicitly chosen environment.
5. Consented training delivery/media integrations and authenticated observed participant events.
6. Real-environment acceptance, deployment/retention policy and operational support.

Each track needs its own target environment, bounded requirements and acceptance evidence. GUI remains a later client of the same application services. Live brute-force/login attempts, live phishing dispatch, impersonation calls and media generation are not implemented by this offline release.

## Local recovery/control addition (0.30.0)

Require historical signed receipt queries without writes or approval renewal; combined cancellation rollback/idempotency/concurrency; explicit partial-state diagnostics; existing-only bounded distinct DELETE-mode files in one private directory. Demo completion independently checks stored cancellation, stopped session and matching historical receipt. Installed-wheel receipt/status/cancel workflows must pass. External provider control is excluded. See [LOCAL_TRAINING_CONTROL.md](LOCAL_TRAINING_CONTROL.md).

## Bounded OpenSSH journal addition (0.31.0)

Require the restricted single-host JSONL contract, integer reception time, exact process/machine checks, supported terminal outcome mapping, unknown-method handling without MFA inference, original physical line evidence, privacy/resource/file limits and visible omissions. Independent mapping controls, paired demo, CLI and installed-wheel workflows must pass. No native journal collection, live attempts or arbitrary provider parsing is included. See [SSH_JOURNAL_REVIEW.md](SSH_JOURNAL_REVIEW.md).

## AI/cost closure gate (0.32.0)

Require every finite [AI_OFFLINE_ACCEPTANCE.md](AI_OFFLINE_ACCEPTANCE.md) condition: exact local money arithmetic, writer-lock clock/TTL checks, validated legacy storage, service-level skip, no overrun cache reuse, safe cleanup preserving budget history, uncertain-outcome accounting and exclusive output ownership. The socket-blocked installed-wheel lifecycle and all six CI jobs must pass. Acceptance closes this offline module; live account/model/pricing/billing validation is explicitly deferred.

## Reports/local history closure gate (0.33.0)

Require every [REPORTS_OFFLINE_ACCEPTANCE.md](REPORTS_OFFLINE_ACCEPTANCE.md) condition, including typed JSON/HTML derivation, target scope, comparison current-side validation, safe regular bounded readers/cleanup, a bounded read-only catalog with visible invalid entries and verified source-independent export. Deleted-source demo and clean-wheel CLI evidence must pass along with all six CI jobs. No remote account, analyzer expansion or new format is required.

## CLI and installation closure (0.34.0)

The finite [CLI/install contract](CLI_OFFLINE_ACCEPTANCE.md) covers exact option names, one release identity, UTF-8 process streams, quiet closed-pipe exit, local installation diagnostics and wheel/sdist resource/metadata parity. Fresh offline wheel installation exercises every command help and existing functional workflows outside the checkout. Linux/Windows Python 3.12–3.14 CI provides platform evidence. See [installation instructions](CLI_INSTALLATION.md). API setup/live validation remain deferred; broader collector/product work is separate.

## GitHub collector offline closure (0.35.0)

The existing bounded collector is covered by the finite [offline acceptance contract](GITHUB_OFFLINE_ACCEPTANCE.md): immutable shared source/manifest selection, verified blob reuse, strict provider metadata and local header boundaries, controlled failures without retries and a socket-blocked synthetic scan from the installed wheel. This closes the offline collector implementation/testing scope; public/private account and organization access remain deferred integration validation. Source-language coverage and assessment engines are unchanged. See [usage and exact limits](GITHUB_COLLECTION.md).

## Passive HTTPS offline closure (0.36.0)

The finite [passive HTTPS contract](WEBSITE_OFFLINE_ACCEPTANCE.md) covers exact scope/preflight, one GET, duplicate-preserving header review, complete-body-only HTML, retained headers with explicit body gaps, strict JSON/API defaults, native short-read regressions and socket-blocked installed workflows. Engine 23 records changed collection coverage; prior bundles remain readable without cross-engine deltas. Real target/configuration acceptance and authenticated/browser/business-logic assessment remain separate. See [usage and limits](WEBSITE_AUDIT.md).

## Mail-domain DNS offline closure (0.37.0)

The finite [mail-domain collector contract](MAIL_DOMAIN_AUDIT.md) closes typed provider responses, exact-owner TXT collection, optional question binding, truncation/alias/contradiction failures, bounded DNS quoted-string decoding, SPF version selection and visible DMARC tag ambiguity. The socket-blocked installed CLI acceptance checks scope, query count, redaction and saved failure bundles without live or AI calls. Engine 24 preserves prior bundles as readable but prevents cross-engine observation deltas. Full policy/DNSSEC/delivery evaluation and real-domain validation remain deferred; Gmail account integration is separately fixture-tested.

## Gmail settings offline closure (0.38.0)

The bounded [Gmail collector contract](GMAIL_AUDIT.md) closes identity matching, local token preflight, strict forwarding/filter metadata, all-rule validation and finite response limits. The socket-blocked installed CLI gate checks exact endpoint/header scope, no credential or destination disclosure, verified saved success/failure bundles and zero live/AI calls. Engine 25 preserves older bundles without cross-engine comparisons. Credential/OAuth setup, actual account validation and broader mailbox security remain deferred.

## Dependency workflow offline closure (0.39.0)

The finite [dependency acceptance contract](DEPENDENCIES_OFFLINE_ACCEPTANCE.md) covers existing manifest/inventory/OSV behavior, bounded cache files and response rows, finite clock/expiry metadata, validated writes/legacy reads and full per-package pagination-cycle detection. Socket-blocked installed CLI evidence covers pagination, cache-only reports/scans, disclosure consent and corrupt-cache failure without a clean conclusion. Engine 26 preserves historical bundles while rejecting cross-engine deltas. Broader ecosystems, dependency graphs, reachability and controlled live OSV validation remain separate.

### Cache clock ordering correction (0.39.1)

Expiry is rechecked after database reads, and new TTLs start after acquiring the SQLite writer lock. Independent SQL trace controls advance time during the database operation and reproduce both stale-read and shortened-TTL regressions. Invalid post-lock clocks roll back without replacing the previous cache row. Engine 26 and the existing cache schema remain unchanged.
