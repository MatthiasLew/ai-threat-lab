# Changelog

## 0.26.0

- Traverse selected synchronous default-factory SQLite connection contexts with simple as names, ordered items (at most eight), nested bodies and normal-body successor/termination handling.
- Carry connection kind through supported aliases, arguments, returns and definite joins; distinguish cursors/execute results for context selection. Keep unknown managers, custom factories, unsupported call/target forms and item/depth limits as explicit barriers.
- Preserve query-value versus query-text separation, source-free evidence and existing runtime/transaction/exception limitations. No target execution or database opening.
- Add context regression, CLI/SARIF, verified-GitHub and bundle tests, an inert offline fixture and installed-wheel acceptance checks.
- Advance Python AST engine to 1.8, project pass to python-project-modules-1.3 and scan engine to 18. Retain older bundle reading and suppress cross-engine comparisons. API setup remains deferred.

## 0.25.0

- Resolve selected imported/aliased importlib.import_module calls with literal absolute names or literal relative names and explicit package anchors over already collected sources.
- Enforce strict bounded argument/name decoding; retain gaps for computed/uncollected targets, missing or noncompleting modules, cycles and ambiguous mappings. Respect local importlib shadowing without target execution or additional network retrieval.
- Add positive/negative, CLI, verified-GitHub and bundle regression cases, an inert importlib demo and installed-wheel acceptance checks. Document the limited subset and incomplete construction-site history.
- Advance the project pass to python-project-modules-1.2 and scan engine to 17; retain Python AST engine 1.7 and old bundle reading with cross-engine comparisons disabled. API setup remains deferred.

## 0.24.0

- Extend supplementary Python linking to collected regular packages, conventional src layouts, absolute dotted imports, lexical relative imports and definite module/helper re-exports.
- Require collected package markers; expose ambiguous mappings, missing/unavailable or noncompleting parents, import cycles and package-depth limits. Reuse bounded source text without executing initializers or fetching imports.
- Add package-layout regression, CLI and pinned GitHub tests plus a three-file offline fixture and installed-wheel acceptance gate.
- Advance Python AST engine to 1.7, project pass to python-project-modules-1.1 and scan engine to 16. Retain older bundle reading, with cross-engine comparisons disabled. API setup remains deferred.

## 0.23.0

- Add a supplementary static pass linking selected flat root Python modules through absolute local imports, aliases, argument/return propagation and SQLite identities.
- Preserve file-qualified source/sink/call/helper evidence and report only supplementary cross-file flow observations. Reuse already-collected local/GitHub source text; perform no target import, installation, execution or additional fetch.
- Bound input count, selected file attempts/bytes and helper-definition evidence alongside shared flow budgets. Preserve cycle, unavailable/non-function export, unsupported layout, parse/encoding and noncompleting-module gaps; do not fall back to library bindings for known unavailable local modules.
- Share local source decoding between per-file and project passes; reject non-file Python sources before opening. Single-file review/SARIF remains single-file.
- Add a two-module inert demo and installed-wheel gate, 61 regression/integration/CLI cases, and scope/usage documentation. API setup remains deferred.
- Advance Python engine to python-ast-1.6 and scan engine to 15; identify the project pass as python-root-modules-1.0. Retain old bundle reading and suppress cross-engine comparisons.

## 0.22.0

- Extend PY013/PY014 to selected previously defined module-level same-file helpers, with strict positional/keyword/default binding and argument/return propagation.
- Carry selected HTTP origins, SQLite identities and known callable aliases across bounded contexts. Preserve call-site line evidence through returned values and merge repeated contexts by sink without source values.
- Stop recursion and enforce table/call/depth/parameter/evidence budgets alongside existing flow limits. Unsupported/invalid signatures, defaults, unpacking, decorators, generators, async/nested/forward/imported helpers retain gaps.
- Keep runtime globals, object effects, callee exceptions/termination, cross-file resolution and exploitability outside the abstraction. No Python target execution or imports.
- Add a separate inert same-file helper demo, installed-wheel acceptance and 65 regression/integration/CLI cases with updated documentation.
- Advance Python engine to python-ast-1.5 and scan engine to 14; retain earlier bundle reading and suppress cross-engine comparisons. API setup remains deferred.

## 0.21.0

- Extend PY013/PY014 with possible-origin if/else/elif joins, conditional/boolean expressions and nested condition operands. Exclude terminated branches from successor states and prune direct literal boolean choices.
- Preserve API/SQLite identity only when all reaching states agree; expose ambiguous-binding gaps rather than guessing runtime objects. No path-feasibility, correlated-condition or implicit-flow proof.
- Inspect selected for/while bodies once with zero/one-iteration joins and loop else; retain explicit loop-carried/convergence gaps. Skip loops containing break/continue as barriers.
- Add control-flow nesting bounds and keep function-scope/step/depth/origin/finding limits. No execution, framework import, database or network access.
- Add a separate inert branch/loop demo and installed-wheel checks, plus 62 control-flow regression/integration/CLI cases and documentation.
- Advance Python engine to python-ast-1.4 and scan engine to 13; retain earlier bundle reading and suppress cross-engine comparisons. API setup remains deferred.

## 0.20.0

- Add PY013/PY014: bounded straight-line dependencies from explicitly imported Flask request sources to selected shell command and recognized SQLite query APIs.
- Track simple assignments, aliases, selected string operations and imported SQLite connection/cursor identities; preserve source/sink lines without input values.
- Keep parameterized query values separate from query-text observations. Reset tracking at unsupported control-flow barriers; expose unknown-call, import, write and resource-limit gaps.
- Bound flow expression steps/depth, scopes, source origins and findings. No framework imports, source execution, HTTP calls, database opening or exploit validation.
- Reuse observations and coverage notices in standalone JSON/text/SARIF, local/GitHub assessments and reports. Add an inert flow demo plus installed-wheel gate and 92 regression/integration/CLI cases.
- Advance Python engine to python-ast-1.3 and scan engine to 12; retain older bundle reading and suppress cross-engine comparisons. API setup remains deferred.

## 0.19.0

- Extend Python review to twelve rule families: explicit Jinja autoescape=False, Django/MarkupSafe safe-HTML markers and PyJWT-style literal verify_signature=False options.
- Keep source-free candidate evidence and simple alias handling; do not infer HTML context, sanitizer correctness, installed library identity or authorization use. Leave ambiguous JWT dictionaries unchecked.
- Reuse the rules in standalone text/JSON/SARIF, local and immutable GitHub scans. No framework imports, template rendering, token handling, runtime execution or network calls.
- Extend offline demo and installed-wheel acceptance to eight PY005–PY012 observations. Add 55 tests and detailed rule/scope documentation.
- Advance Python engine to python-ast-1.2 and scan engine to 11; retain older bundle reading and disable cross-engine deltas. API setup remains deferred.

## 0.18.0

- Add bounded Go `go.sum` module-content inventory to existing local, recursive and pinned GitHub routes. Keep case-sensitive paths, exact v-prefixed versions and merged origins; omit metadata-only and unsupported records with redacted notices.
- Check supported h1 field syntax/canonical encoding without verifying checksums or resolving build selection, replacements, workspaces, pseudo-version provenance or reachability. Historical/unused versions may be included.
- Apply shared manifest/byte/package budgets plus a 20,000-line bound. No Go command, fetch or package installation.
- Extend offline demo and clean installed-wheel checks with a fictional Go identity; add 56 regression/integration/CLI cases and documentation. OSV requests are fixture-tested only.
- Advance scan scope to engine 10, retaining old bundle reading and suppressing cross-engine deltas. API setup remains deferred.

## 0.17.0

- Add bounded offline Kubernetes JSON review for Pod, selected apps/v1 and batch/v1 workload templates, v1 ReplicationController and nested v1 List resources.
- Observe ten explicit field families: host namespaces, privileged/escalation/root identity, non-root opt-out, writable root filesystem, selected added capabilities, unconfined seccomp, hostPath volumes and host ports. Do not infer defaults or effective runtime state.
- Add `review-kubernetes` with JSON/escaped HTML, no overwrite and finding-based exit behavior. Reuse the same checker in bounded local/GitHub project collection and existing scan/batch reports.
- Emit fixed-field JSON pointer evidence without names, namespaces, images, host paths or input values. Preserve malformed-selected-field, unsupported-resource, explicit non-Linux and resource-limit coverage notices.
- Enforce source bytes and lexical JSON depth before decoding; bound resources, List depth, containers, volumes, ports, findings and notices. No YAML/Helm rendering, kubectl, cluster/network access or admission/conformance validation.
- Extend synthetic demo and clean installed-wheel gates with ten Kubernetes observations. Advance scan scope to engine 9; retain prior bundle reading and suppress cross-engine deltas.
- Add positive/negative/workload/type/resource/privacy/no-execution/CLI/local/GitHub/batch/error/compatibility tests. API setup remains deferred.

## 0.16.0

- Add `review-headers` for bounded caller-supplied HTTPS response-header captures, JSON/HTML output, finding-based exits and no-overwrite files; never fetch the declared URL.
- Share selected HSTS/nosniff/header presence, cookie metadata and CSP script-pattern checks with the existing passive WebsiteAudit collector.
- Preserve duplicate wire headers in HttpResponse while retaining the legacy mapping; inspect every individual Set-Cookie without comma folding and report missing duplicate coverage for mapping-only adapters.
- Aggregate cookie observations with names/values omitted; cover selected flags, SameSite and Secure/Host prefixes, while treating malformed/ambiguous entries as unassessed candidates.
- Observe selected script CSP patterns with explicit nonce/hash, strict-dynamic, split-directive, duplicate and multiple-policy limitations. Do not claim effective browser enforcement.
- Enforce strict capture/schema/status/header controls and count/byte bounds; omit declared capture URL, unknown header values, tokens, cookies and policy values from new reports.
- Extend synthetic offline demo and clean installed-wheel acceptance with six header observations. Add no-network/privacy/duplicate/limit/error/CLI tests.
- Advance scan engine to 8; retain old bundle reading and suppress cross-engine deltas. No API/account setup or live target validation.

## 0.15.0

- Add `scan-batch` for 1–10 explicit distinct local targets, sequentially using built-in offline collectors; reject remote targets, links, overlapping sources and output inside scanned projects before claiming the destination.
- Publish each existing scan bundle independently, then combined JSON/HTML and `batch.json` last. Preserve per-target module failures and other useful results; no automatic retry/resume or network/model call.
- Add `batch-check`: bounded schema/path/index checks, child manifest hashes, child integrity/scope validation, combined report regeneration and summary consistency. Checks do not reread source files.
- Preserve no-overwrite and cancellation semantics; bound child artifact totals and combined-report sizes. Completion means publication, never security or authenticity.
- Extend synthetic offline demo and clean installed-wheel acceptance with two-target batches; add CLI exit-policy, malformed/tampered/missing output, privacy, resource, symlink and partial-failure tests. APIs remain deferred.

## 0.14.0

- Add Cargo.lock v3/v4 exact crates.io inventory through local, opted-in nested and shared immutable GitHub routes; preserve global parser/byte/package limits and source origins.
- Skip local/git/alternate registry sources with redacted notices; validate selected SemVer forms and use the existing opt-in OSV batch/cache contract for crates.io. Never call Cargo or install dependencies.
- Expand exported EML review with bounded plain/HTML link and attachment metadata candidates, aggregate source-free evidence, no network or payload execution.
- Report cleartext/IP/userinfo/active-scheme/display-host link patterns and executable/script/macro or document-plus-active attachment extensions as human-review candidates.
- Bound input, selected MIME depth/parts, decoded text, text parts and links; preserve explicit decoding, parser and omitted-coverage notices. Catch structural parser failures and reject linked/non-regular EML targets.
- Consider all Authentication-Results headers without trusting their provenance; retain explicit authenticity/reputation/cryptographic gaps.
- Extend offline demo with Python + Rust inventories, five-observation inert EML fixture and separate report bundle; acceptance failure cannot publish the completion marker.
- Advance scan scope to engine 7, keep older bundle reading and suppress cross-engine deltas. Add exported-mail readiness, CLI/package tests and updated capability docs. No API setup or live integrations.

## 0.13.0

- Add offline SARIF 2.1.0 export for the nine Python pattern rule families through `review-code --format sarif` and the existing renderer API.
- Keep candidate-only warnings, source-free evidence, line-only regions and explicit original UTF-8 byte-column metadata; avoid inaccurate Unicode highlighting.
- Use URI-encoded basenames by default; optional `--source-root` preserves relative paths and rejects resolved sources outside the root. Do not export absolute roots, source snippets or invocation/environment metadata.
- Preserve no-overwrite reports and existing exit behavior; test rule indexes, empty runs, repeated observations, URI encoding, root escapes, real CLI processes and clean installed wheels.
- Validate representative outputs against the official OASIS schema. No automatic upload, scan-engine change, API setup or live calls.

## 0.12.0

- Expand bounded Python AST review from four to nine rule families: OS shell APIs, non-atomic temporary names, the unverified TLS helper, explicit unsafe YAML loaders and MD5/SHA-1 candidates.
- Share the rules across standalone review, local assessments and immutable GitHub collection; retain source/argument redaction and no execution.
- Document literal-loader/hash exemptions, TLS override limitations and unresolved data-flow/scope semantics.
- Add a separate inert five-pattern offline demo/report, CLI and installed-wheel acceptance checks.
- Advance scan scope to engine 6; preserve reading older bundles and suppress cross-engine deltas. No API setup or live calls added.

## 0.11.0

- Keep large binary fixture test IDs compact, enforce a portable ID length during collection, and bound CI job duration.

- Add bounded static PE32/PE32+ and ELF32/ELF64 header observations to local program-file audits and scans; never execute or upload target bytes.
- Record selected PE hardening bits, section write/execute flags and bounded certificate-table presence without signature/trust claims.
- Add both ELF byte orders, selected program/load/stack flags and RELRO markers with explicit PIE/runtime/full-RELRO limitations.
- Preserve metadata and mark structural checks unavailable on malformed/unsupported input; suppress partially parsed mitigation candidates.
- Reject links/non-regular inputs and close descriptors on errors; cap bytes and record counts.
- Extend synthetic offline demo with inert binary descriptors and reports, scope engine 5, old-bundle reading, malformed/fuzz/CLI/resource tests and installed-package verification.

## 0.10.0

- Add opted-in `--recursive-dependencies` to local `audit-deps` and local/GitHub `scan`; retain root-only defaults.
- Discover nested manifests with global manifest/package/byte/directory/entry/depth bounds, deterministic breadth-first local traversal and explicit partial-coverage notices. Skip links/junctions and excluded directories.
- Preserve portable relative origins across all supported formats; deduplicate exact package identities across subprojects before optional advisory queries.
- Share nested GitHub inventory with the existing pinned commit and bounded blob retrieval; reject snapshot/scope disagreements.
- Add strict recursive scope to engine 4, retain old bundle reading and suppress cross-coverage comparisons.
- Extend synthetic demo, CLI/wire/resource/error tests and clean installed-wheel verification. No live API validation or model calls added.

## 0.9.0

- Add literal Dockerfile and GitHub Actions configuration observations, shared by local and immutable GitHub collection. All remain candidate findings with explicit parser/runtime gaps.
- Add exact-approved inert exercise exports: reserved-address `.eml`, escaped HTML, voice script and video storyboard. No sending, calling, source execution or media generation.
- Add `offline-demo`: generated project before/after scans, integrity checks, three scripted training sessions and linked reports; publish completion only after acceptance checks.
- Add `readiness` static capability inventory, explicit missing-engineering statuses and a complete delivery matrix; no credential inspection or service probes.
- Advance scan scope engine to 3; keep older bundle reading and suppress cross-engine deltas.
- Extend no-network, redaction/escaping, approval/expiry, no-overwrite, CLI and clean installed-wheel verification.

## 0.8.0

- Add GitHub root dependency inventory to combined scans using the same immutable commit and shared bounded retrieval as source checks.
- Parse in-memory requirements/npm/uv/Poetry inputs without saving repository source; reuse verified blobs and prioritize root manifests within shared limits.
- Extend explicit OSV sharing and advisory caching to GitHub scans. Preserve source/inventory evidence when parsing or advisory modules fail.
- Advance scan scope engine to version 2; retain version-1 bundle reading while conservatively disabling cross-engine deltas.
- Add synthetic CLI/wire, shared-budget/digest, malformed-manifest, provenance, redaction and compatibility checks. No live API validation.

## 0.7.0

- Add a one-command read-only `scan` workflow over existing collectors, automatic local-project dependency inventory and explicitly opted-in OSV lookup. No automatic AI calls.
- Preserve module failures and unchecked areas in useful partial reports; fail-on-findings is a separate opt-in exit policy.
- Add private no-overwrite report bundles with staged bytes, manifest-last commit, SHA-256/size indexes and bounded integrity/derived-report checks.
- Add `scan-check`, `scan-compare` and optional baseline comparison, preserving new/still/no-longer-observed labels without claiming remediation. Changed scope/module coverage disables deltas.
- Add malformed bundle, symlink, concurrent directory-claim, interrupted publication, redaction, scope, CLI and installed-package tests.

## 0.6.0

- Add approved local text-training sessions for email/voice/video scenarios, bound to exact preview digests, participant aliases and approved recipient indices.
- Add SQLite state, unique plan/participant/recipient sessions, atomic idempotent actions, expiry and persistent whole-plan cancellation.
- Add numbered interactive rehearsal, stop/EOF/Ctrl+C handling and deterministic voice dialogue with a three-unknown-turn bound. No raw replies, speech, calls, media or link visits.
- Add JSON/escaped standalone HTML session reports with selected outcomes, follow-up practice and explicit limits; do not label selections as observed susceptibility or identity verification.
- Extend CLI subprocess, approval, concurrency, expiry, privacy, cancellation and installed-wheel checks.

## 0.5.0

- Add static exact-version inventory for requirements, npm lockfiles v2/v3, uv and Poetry locks; normalize and deduplicate identities without installation or code execution.
- Add explicitly consented OSV batch queries, bounded pagination, advisory identity checks, partial-result notices and optional one-hour local cache. No AI/model call is needed.
- Add combined JSON/standalone HTML reports with exact finding deduplication, provenance, preserved gaps and explained human-triage priorities. Escape untrusted fields and block active/external content.
- Bound the legacy Python traversal by directories/entries; tighten GitHub repository path validation and keep POST restricted to two fixed query endpoints.
- Expand CLI/contract, cache, malformed-input, paging and installed-package verification.

## 0.4.0

- Add explicit read-only `audit` collectors for immutable GitHub source, passive HTTPS headers, basic mail DNS policy, authenticated Gmail forwarding/filter settings, and local secret/manifest/program inventory.
- Add exact target scope, public DNS pinning with original-host TLS verification, bounded reads and fixed provider endpoints. Do not follow redirects or execute downloaded code.
- Add a concrete optional OpenAI Responses explanation adapter; minimize/deduplicate structured evidence, require transmission opt-in, cap context/output, and offer no-network cost estimates.
- Add SQLite daily/request budget reservations, optional exact-match TTL cache, cross-process pending-request deduplication, conservative unknown-outcome handling and operator billing reconciliation.
- Add `ai-explain`, `api-costs` and `api-reconcile`, setup/cost documentation and a synthetic example configuration.
- Expand fixture, concurrency, CLI subprocess and installed-wheel verification. No paid requests or real mailbox/communications actions were performed.

All audit results remain partial. Training dispatch remains simulated; active exploitation, full dependency/binary audits, live calls, media generation and telemetry collection are not bundled. Account permissions, models/prices and real service behavior require validation before live use.
