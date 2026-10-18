# Changelog

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
