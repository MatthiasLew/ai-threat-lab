# Test strategy and integration readiness — 0.39.1

The required release evidence is defined in [Offline CLI release criteria](OFFLINE_RELEASE_CRITERIA.md). Exact test counts and coverage measurements belong to the tested commit and its CI run; coverage includes statements and branches and is enforced at a minimum of 90%. Child-process CLI tests add behavioral evidence without being counted as subprocess coverage. Fixtures do not establish real-provider correctness or availability.

## Run the gates

```bash
python -m pip install -e ".[dev]"
python scripts/verify.py
```

This runs Ruff, pytest under coverage, the coverage gate, package build, a clean installed-wheel workflow, and Git whitespace checks. Each command stops on a failure. To inspect only tests:

```bash
python -m pytest -q
python -m coverage run -m pytest -q
python -m coverage report
```

Package-binding regression tests also compare selected source-level outcomes against a fresh Python process importing only test-authored inert fixtures. This oracle checks binding semantics independently; it never imports analyzed target sources.

## Evidence covered

| Area | Behavioral checks |
| --- | --- |
| Risk engine | All matrix values, category boundaries, profile adjustments, relevant/irrelevant controls, overlap, deduplication and reduction caps |
| Catalog | Malformed JSON, invalid versions/types, missing fields, empty data, duplicate IDs and invalid rule reductions |
| Code review | Fourteen AST rule families, bounded Flask flows, selected module/package/importlib linking and SQLite contexts, explicit YAML loaders, hash exemptions, TLS-helper limitations, local/GitHub/CLI parity, risk patterns, import aliases, safer code, no source execution, encoding and size bounds, source-free reports |
| Assessment | Target routing, missing adapters, malformed URLs/domains, partial results, project bounds and untrusted mail headers |
| Campaigns | Scope validation before provider calls, exact preview approval, expiry, changed content/recipients/facts, media requirement, stop/cancellation handling |
| Delivery | No automatic retry after ambiguous failures, duplicate rejection across service restarts, corrupt databases and concurrent claims |
| JSON contracts | Roundtrips, duplicate keys, unsupported/secret fields, non-finite values, nesting/size limits, timestamp timezone and digest tampering |
| Provider adapters | Registration, missing providers, structured output validation, redacted errors, timeout behavior and CLI injection |
| CLI processes | Every command's help, parser failures, Unicode, spaces in paths, streams, exit codes and full saved-artifact workflows |
| Concrete HTTP adapters | Pinned GitHub commit/blob verification, truncated/skipped files, passive header checks, DNS response policy checks and authenticated Gmail account binding |
| Network scope | Opt-in and exact hosts, forbidden mutations/redirects, public-address pinning, private/mixed DNS rejection, TLS hostname, size/time/request bounds and response-body redaction |
| AI cost controls | Real Responses wire contract with fake transport, input/output limits, synthetic rates, atomic budgets, cache TTL/restarts/namespaces, unknown outcomes, reconciliation and no automatic retries |
| Dependency inventories/advisories | Exact pins, normalization, unsupported/secret-bearing sources, package/manifest limits, real OSV batch wire contract, pagination/order validation, cache expiry and partial-result gaps |
| Shared GitHub scan | Same commit for code/manifests, verified distinct-blob reuse, root format/priority bounds, shared file/byte limits, isolated parsing/advisory failures, no raw-source artifacts, explicit OSV wire and old-engine compatibility |
| Static binary observations | Independent PE/ELF fixtures, endian/class variants, truncated prefixes, bounded counters/ranges/alignment, certificate presence limits, random inputs, descriptor cleanup, non-regular files, no execution/network, CLI reports and inert demo |
| Monorepo inventory | Root-default/recursive opt-in, relative origins, same/different-version deduplication, global traversal/parser bounds, exclusions, links/junction guard, Unicode CLI paths, shared GitHub/OSV wire, scope mismatches and legacy/current engine compatibility |
| Combined reports | Per-target deduplication, provenance, triage rules, empty/not-configured results, invalid documents and escaped offline HTML |
| Local training lab | Exact approval/scope, alias/recipient uniqueness, structured action policy, bounded voice turns, concurrency/replay, expiry and permanent plan revocation |
| Interactive training | Numbered choices, invalid input redaction, EOF/Ctrl+C stop, terminal-control escaping, all command help and actual persisted CLI workflows |
| Training reports | Selected-action provenance, no false verification/employee judgments, preview omission from aggregates, escaped offline HTML and follow-up practice |
| Scan orchestration | One-command routing, automatic dependency inventory, explicit sharing, module-failure isolation/redaction, partial report preservation, scope/options gates and exit codes |
| Scan bundles/history | Manifest/schema/hash/size validation, derived-report consistency, symlinks, no overwrite, racing directory claims, interrupted writes, unrelated-file preservation and observation-only deltas |
| Configuration rules | Literal positive/negative patterns, comments, pinned refs, build-stage aliases, local/GitHub inclusion and generic evidence |
| Offline acceptance/exports | Network/process execution denied, exact preview approval, expiry, inert email headers, media-reference omission, HTML escaping, no overwrite, completion marker, static readiness and installed demo |
| Packaging | Wheel installed without dependencies/index access into a clean venv outside the checkout, installed console entrypoint and bundled catalog |

No real targets, recipients, mailbox accounts or paid APIs are contacted. Fixtures use synthetic data and reserved demonstration domains/numbers.

## Portable test identities

Large binary fixture inputs have explicit short parameter IDs. Collection rejects any test ID longer than 4096 characters to avoid oversized `PYTEST_CURRENT_TEST` environment values and unusable reports. The binary-size fixture previously generated a 16 MiB ID; input bytes remain unchanged, but are never used as its case name. CI jobs have a 10-minute bound.

## CI

Linux and Windows with Python 3.12, 3.13 and 3.14 run lint, coverage/tests, build and the isolated-wheel verifier. A passing offline suite verifies the concrete adapters against synthetic wire responses, not proof that a remote service/account works.

## When real credentials are added

Use the concrete read-only/AI adapters described in LIVE_SETUP.md and API_COSTS.md, then run provider-specific integration tests against a controlled environment. Missing live communications/media adapters still require implementation. Verify authentication failures, quotas, timeouts, cancellation, event authenticity, source-sharing behavior, scope, media integrity and provider-side idempotency. Keep these tests separate from deterministic offline CI and require explicit credentials/environment selection.

## SARIF export (0.13.0)

Regression and real-process CLI tests cover all nine rule IDs, repeated observations, empty runs, rule indexes, line locations, Unicode/URI encoding, source-free output, basename privacy, relative roots, out-of-root paths, symlink escapes (where supported), validation errors, no overwrite and finding-based exits. The installed-wheel gate also exercises SARIF from a clean environment. Eight representative documents (empty, clean, Unicode and all-rule inputs with basename/root-relative paths) were separately validated against the official OASIS SARIF 2.1.0 schema with URI format checks. The validator is not a runtime dependency or a live-service integration test.

## Cargo and EML offline milestone (0.14.0)

Cargo tests cover supported lock versions, exact SemVer, malformed/duplicate TOML, source filtering/redaction, identity deduplication, nested origins, package limits, shared GitHub retrieval, synthetic OSV wire payloads and real CLI/local scan routes. Mail tests cover plain/HTML/Unicode/entity/IPv4/IPv6 link properties, metadata-only attachments, duplicate authentication headers, MIME decoding/charset/structure errors, resource bounds, deterministic arbitrary input, no-network behavior, redaction, reports, exit policy and no overwrite. The installed-wheel gate runs both additions through generated offline fixtures. No real mailbox, recipient, crate submission or provider account was used.

## Local multi-target batches (0.15.0)

Tests cover multiple target routes and source-free combined findings, no-network defaults, invalid/remote/duplicate/overlapping scopes, exact-ten/over-limit selection, output placement, per-target recursive selection, isolated module failures, exit-code precedence, cancellation, no overwrite, tampered/missing/unindexed artifacts, report regeneration after hash recomputation, scope tampering, byte budgets, symlink rejection, deleted-source verification, real processes and clean installed-wheel acceptance. CLI help covers both new commands.

## Response-header review (0.16.0)

Tests cover legacy mapping compatibility and duplicate-preserving transport/WebsiteAudit fields, separate cookies with Expires commas, selected cookie flags/prefixes/SameSite, malformed/duplicate attributes, CSP fallback/directive ordering/nonce/hash/split/multiple policies, report-only exclusion, non-200 omissions, strict schema/control/encoding/status/resource limits, no-network captures, declared-URL/header/cookie/nonce redaction, JSON/HTML merging, CLI exit/no-overwrite behavior, failed demo completion, prior-engine reading and installed-wheel acceptance. HTTPS responses are fixtures; no real website, cookie or provider account was used.

## Kubernetes JSON review (0.17.0)

Tests cover ten explicit rule families, three container groups, all supported workload paths and nested Lists; absent/restrictive settings; Pod/container context distinction; invalid types and unsupported versions/kinds/OS; fixed pointer/value redaction; JSON byte/depth/escaping/duplicate/non-finite boundaries; global selection/finding/notice caps; UTF-8/BOM/files/links; no network or subprocess execution; local/GitHub/scan/batch parity; HTML/JSON and real CLI exit/no-overwrite behavior; failed demo completion; prior-engine reading and installed-wheel acceptance. No cluster, kubectl, Helm, real deployment or provider account was used.

## Go checksum records (0.18.0)

56 new cases cover exact/prerelease/pseudo/incompatible version spellings, case-sensitive module identities, unsupported paths, malformed/canonical hash fields, metadata-only records, redaction, byte/line/package/notice bounds, deduplication and nested origins. Fixture-backed GitHub collection and OSV payloads, real CLI/local scans and engine-9 compatibility are covered. The clean installed-wheel gate requires Go, Python and Cargo identities in the generated offline demo. No Go toolchain or live advisory submission is required.

## Python web API patterns (0.19.0)

61 new cases cover direct/aliased Jinja autoescape opt-out, Django/MarkupSafe trust markers, PyJWT-style decode/signature options, nonmatching and ambiguous syntax, duplicate/computed/unpacked dictionary keys, static trusted-markup caveats and source-free text/JSON/SARIF. Integration checks cover local projects, immutable GitHub blobs, real CLI exit/no-overwrite behavior, no source execution/network, engine-10 bundle compatibility and incomplete-demo publication. The installed-wheel gate requires eight inert PY005–PY012 observations without importing web frameworks. Findings remain unvalidated candidates.

## Bounded Python flows (0.20.0)

92 new cases cover explicit Flask request sources, import aliases, request/SQLite object aliases, assignments/reassignments, annotations, concatenation/interpolation, selected string transformations, shell and SQLite sinks, parameterized SQL negatives, function isolation/argument shadowing and return/raise termination. Barrier/import/unknown-result gaps, source-line merging, source/step/depth/scope/finding bounds, source-free JSON/text/SARIF, local/GitHub reports, real CLI no-overwrite/exit behavior, engine-11 compatibility and incomplete-demo publication are exercised. The installed-wheel gate verifies the inert flow fixture without importing Flask or executing SQL/commands. These tests establish the documented static behavior, not real-environment exploitability.

## Local control-flow abstraction (0.21.0)

62 new cases exercise possible-path if/else/elif and conditional/boolean expression joins, source-origin merging, literal boolean pruning, no implicit condition taint, terminated branches, definite/ambiguous API identities, loop targets, zero/one iteration joins, loop else, literal while behavior, skipped break/continue and loop-carried gaps. They cover block-depth and function-scope budgets, sequential joins without path enumeration, source-free reports, local/GitHub/bundle/real-CLI behavior, engine-12 compatibility and incomplete-demo publication. The clean installed-wheel gate requires the separate three-observation branch/loop fixture. Feasible paths, loop convergence and real exploitability remain unvalidated.

## Bounded same-file calls (0.22.0)

65 new cases cover positional/keyword/positional-only/keyword-only binding, literal defaults, invalid/missing/duplicate/excess arguments, unsupported signatures and unpacking, argument and return propagation, SQLite/request/callable descriptors, aliases, independent caller state, merged source/call-site evidence, recursion and parameter/table/call/evidence bounds. Source-free text/JSON/SARIF, no execution/network, local/GitHub/bundle/real-CLI behavior, engine-13 compatibility and incomplete-demo publication are included. The clean installed-wheel gate verifies a separate three-observation local-helper fixture. These checks validate the documented static abstraction, not real execution paths or exploitability.

## Root Python project linking (0.23.0)

61 new cases cover direct/from/module import aliases, lazy/multi-module links, returned text and SQLite identity, parameterized SQL negatives, ambiguous/rebound/non-function/unsupported exports, API-name shadows, unavailable selected modules, cycles and noncompleting module passes. They verify deterministic file-qualified evidence, same-file suppression, unsupported layouts, type/duplicate/encoding/parse/file/byte/attempt/evidence bounds, shared source decoding, no execution/network, existing CLI/report/bundle/immutable GitHub behavior, engine-14 compatibility and incomplete-demo publication. The clean installed-wheel gate requires the separate three-observation two-module fixture. No actual target import or additional network retrieval is used.

## HTML, EML forms and ZIP milestone (0.27.0)

The demo creates a saved HTML page, a safer negative control, an HTML-form email and a ZIP metadata fixture. It requires five declared-origin HTML observations, two context-free HTML scan observations, two EML form observations and the exact path-escape/reserved-name ZIP candidates before completion. Generated bundles are verified; the installed-wheel gate repeats review-html, no-overwrite and audit/scan-check routes. Unit/integration controls cover parser bounds, raw-text elements, unsupported browser semantics, response encodings, local/GitHub parity, malformed ZIP metadata and forbidden member-read/extract calls. See [HTML_REVIEW.md](HTML_REVIEW.md) and [ARCHIVE_REVIEW.md](ARCHIVE_REVIEW.md).

## Normalized authentication events (0.28.0)

The demo now requires all four selected failure/spray/distributed/success-after-failure rule families, a zero-candidate time-separated control and verified bundles. CLI/wheel checks cover review-auth-log, invalid policy, output conflicts and redacted reports. Boundary tests and an independent generated prefix-window oracle validate selected temporal semantics. No real logins or API calls occur. See [AUTHENTICATION_LOGS.md](AUTHENTICATION_LOGS.md).

## Signed local event claims (0.29.0)

The demo creates a fresh private signing key and separate event journal for all three fictional channels. Each must record one simulation action, exclude one automated event, reject changed signatures, handle identical retry without another write and reject post-cancellation claims. It exports escaped per-channel reports without claiming adapter telemetry or verified behavior. The installed-wheel gate repeats the complete CLI workflow. The demo directory contains a private fixture key and should not be published. See [SIGNED_TRAINING_EVENTS.md](SIGNED_TRAINING_EVENTS.md).

## Historical receipt and combined-control gates (0.30.0)

Test unchanged database bytes for receipt/status reads; signature/binding failures; expired/cancelled receipt lookup; missing/conflicting IDs; no implicit creation; malformed schemas, links, hardlinks, URI escaping, size limits and WAL rejection. Inject SQL failures into each database and require rollback of both; concurrent status/cancellation must expose no half-commit. Preserve unrelated and completed sessions. Real CLI and installed-wheel checks cover recovery, idempotency, no overwrite and stopping both local ledgers. SQL fault/concurrency tests do not simulate physical power loss.

## OpenSSH journal mapping (0.31.0)

Require independent native records and expected normalized timelines, all four pattern controls, nonterminal and alternate-method success resets, exact source-line evidence, host/process isolation, microsecond epoch/year boundaries, canonical-IP grouping, strict JSON/field/message limits and identity-free output. Cover invalid selected outcomes, nonscalar/binary metadata, no-network/subprocess, file guards, CLI thresholds/HTML/no-overwrite and scan/batch integrity. Demo positive/negative failures must block completion; installed wheel must repeat both controls. Engine-21 reading remains supported; cross-engine comparisons remain disabled.

## AI/cost closure (0.32.0)

Require pre-fix failure/current success for overruns reused from cache, clock sampling before the SQLite writer lock, incompatible-ledger augmentation, price precision and the CLI output-path race. Retain exact legacy data, reject invalid state without reset, preserve reservations after completion failures, and verify cache cleanup rollback/idempotency/concurrency without deleting accounting. Test byte limits and service-level empty-findings skip. The clean-wheel verifier runs `scripts/check_ai_offline.py` using the installed package, synthetic HTTP/credential data and blocked DNS/sockets, then repeats operational CLI reads/cleanup. Live account correctness is excluded. See [AI_OFFLINE_ACCEPTANCE.md](AI_OFFLINE_ACCEPTANCE.md).

## Reports/local history closure (0.33.0)

Require pre-fix failure/current success for rehashed inconsistent HTML, Boolean counts, assessment/dependency scope mismatches, false comparison counts, replacement-file cleanup and summary escaping. Cover original-source deletion, single/batch catalog/export, failed versus invalid runs, strict comparison metadata, root/run/read/output budgets, no network, file links/types/descriptor closure, no overwrite and write failures. Demo completion independently checks catalog counts and regenerated exports; installed-wheel CLI repeats both after the demo source was removed. No new report formats or analysis engines are part of this gate.

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
